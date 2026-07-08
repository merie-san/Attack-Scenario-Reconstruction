import unittest
from scenario_reconstructor.scenario_reconstructor import FlowExploit, AttackType, StarNetworkAttackGraphBasedScenarioReconstructor, Preconditions, HostAttribute, Host
from scenario_reconstructor.attack_mapper import AttackMapper
from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.reconstruction_manager import ExploitGenerator, ScenarioReconstructionManager
from datetime import datetime
import os


class TestHostAttributeConc(HostAttribute):
    ATT_1 = "att_1"
    ATT_2 = "att_2"
    ATT_3 = "att_3"


class TestExploitGenerator(unittest.TestCase):

    def setUp(self) -> None:
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("attack_1", {Preconditions({
            TestHostAttributeConc.ATT_1}, True)}, {TestHostAttributeConc.ATT_1})
        self.attack2 = AttackType("attack_2", {Preconditions({
            TestHostAttributeConc.ATT_2}, True)}, {TestHostAttributeConc.ATT_2})
        self.zero_day = AttackType(
            "zero_day", set(), {TestHostAttributeConc.ATT_2, TestHostAttributeConc.ATT_1})
        self.mapper = AttackMapper([self.attack1, self.attack2], 0.1)
        self.exploit_generator = ExploitGenerator(
            self.mapper, 0.1, self.zero_day)

    def test_to_exploit_error(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.001,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.4})
        with self.assertRaises(RuntimeError, msg="The flow event cannot considered an anomaly"):
            self.exploit_generator.to_flow_exploit(flow_event)

    def test_to_exploit_normal(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.7,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9})
        exploit = self.exploit_generator.to_flow_exploit(flow_event)
        self.assertEqual(exploit, FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                              datetime(2023, 1, 1, 12),
                                              datetime(2023, 1, 2, 2), 0.7))

    def test_to_exploit_unknown(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.7,
                               attack_scores={"attack_1": 0.01, "attack_2": 0.01})
        exploit = self.exploit_generator.to_flow_exploit(flow_event)
        self.assertEqual(exploit, FlowExploit(self.zero_day, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                              datetime(2023, 1, 1, 12),
                                              datetime(2023, 1, 2, 2), 0.7))


class TestReconstructionManager(unittest.TestCase):

    def setUp(self) -> None:
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("attack_1", {Preconditions({
            TestHostAttributeConc.ATT_1}, True)}, {TestHostAttributeConc.ATT_1})
        self.attack2 = AttackType("attack_2", {Preconditions({
            TestHostAttributeConc.ATT_2}, True)}, {TestHostAttributeConc.ATT_2})
        self.attack3 = AttackType("attack_3", {Preconditions({
            TestHostAttributeConc.ATT_3}, True)}, {TestHostAttributeConc.ATT_2})
        self.zero_day = AttackType(
            "zero_day", set(), {TestHostAttributeConc.ATT_2, TestHostAttributeConc.ATT_1})
        self.scenario_reconstructor = StarNetworkAttackGraphBasedScenarioReconstructor(
            [self.host1, self.host2], {TestHostAttributeConc.ATT_3, TestHostAttributeConc.ATT_2, TestHostAttributeConc.ATT_1}, [self.attack1, self.attack2, self.attack3, self.zero_day], "./exploits.log", "./flow_exploits.log", "./states.log", "./correlations.log")
        self.scenario_reconstructor.seen_external_hosts_dict["10.0.0.3"] = Host(
            "10.0.0.3")
        self.scenario_reconstructor.seen_external_hosts_dict["10.0.0.3"].update_compromise_attributes(
            {TestHostAttributeConc.ATT_3, TestHostAttributeConc.ATT_2, TestHostAttributeConc.ATT_1})
        self.anomaly_threshold = 0.1
        self.exploit_threshold = 0.5
        self.mapper = AttackMapper(
            [self.attack1, self.attack2, self.attack3], self.anomaly_threshold)
        self.exploit_generator = ExploitGenerator(
            self.mapper, 0.1, self.zero_day)
        self.reconstruction_manager = ScenarioReconstructionManager(
            self.scenario_reconstructor, self.mapper, self.anomaly_threshold, self.exploit_threshold, self.zero_day, 100,100, 100)

    def tearDown(self) -> None:
        if os.path.exists("./exploits.log"):
            os.remove("./exploits.log")
        if os.path.exists("./states.log"):
            os.remove("./states.log")

    def test_accept_anomaly_added(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.2,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.suspect_dict), 1)
        self.assertIn(FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                  datetime(2023, 1, 1, 12),
                                  datetime(2023, 1, 2, 2), 0.2), self.reconstruction_manager.suspect_dict["attack_2-10.0.0.1-10.0.0.3"])

    def test_accept_event_discarted(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.001,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.suspect_dict), 0)

    def test_accept_event_compatible(self):
        flow_event = FlowEvent(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        exploit = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(
            len(self.scenario_reconstructor.flow_exploits_dict["attack_2-10.0.0.1-10.0.0.3"]), 1)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(), {
                         TestHostAttributeConc.ATT_2})
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["attack_2-10.0.0.1-10.0.0.3"][-1], exploit)
        self.assertEqual(len(self.scenario_reconstructor.state_sequence), 2)
        self.reconstruction_manager.length_when_log_states = 1
        self.reconstruction_manager.length_when_log_exploits = 1
        exploit = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./exploits.log"))
        self.assertTrue(os.path.exists("./states.log"))
        with open("./exploits.log", "r") as log1, open("./states.log", "r") as log2:
            lines = [str.strip() for str in log1.readlines()]
            self.assertEqual(len(lines), 3)
            lines = [str.strip() for str in log2.readlines()]
            self.assertEqual(len(lines), 2)

    def test_accept_event_incompatible(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.1, "attack_3": 0.99})
        exploit = FlowExploit(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        fps=self.reconstruction_manager.get_fps()
        self.assertEqual(len(fps), 1)
        self.assertTrue(fps[0].unk_eq(exploit,self.zero_day))

    def test_accept_no_anomaly_sat_req_found(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        exploit = FlowExploit(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        fps=self.reconstruction_manager.get_fps()
        self.assertEqual(len(fps), 1)
        self.assertTrue(fps[0].unk_eq(exploit,self.zero_day))

    def test_accept_single_sat_found(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                  datetime(2023, 1, 1, 11),
                                  datetime(2023, 1, 1, 11, 35), 0.2)
        self.reconstruction_manager.suspect_dict[old_exploit.get_flow_exploit_group_id(
        )] = [old_exploit]
        self.reconstruction_manager.accept(flow_event)
        fns = self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 1)
        self.assertIn(old_exploit, fns)

    def test_accept_zero_day(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.9,
                               attack_scores={"attack_1": 0.1, "attack_2": 0.1, "attack_3": 0.1})
        exploit = FlowExploit(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.9)
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(
            len(self.scenario_reconstructor.flow_exploits_dict["zero_day-10.0.0.1-10.0.0.2"]), 1)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(), {
                         TestHostAttributeConc.ATT_2, TestHostAttributeConc.ATT_1})
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["zero_day-10.0.0.1-10.0.0.2"][-1], exploit)
        self.assertEqual(len(self.scenario_reconstructor.state_sequence), 2)

    def test_accept_multiple_sat_found(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11),
                                    datetime(2023, 1, 1, 11, 35), 0.45)
        old_exploit_2 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 36),
                                    datetime(2023, 1, 1, 11, 59, 59), 0.3)
        old_exploit_3 = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                    datetime(2023, 1, 1, 11),
                                    datetime(2023, 1, 1, 11, 59), 0.2)
        old_exploit_4 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11),
                                    datetime(2023, 1, 2), 0.3)
        self.reconstruction_manager.suspect_dict[old_exploit_1.get_flow_exploit_group_id(
        )] = [old_exploit_1]
        self.reconstruction_manager.suspect_dict[old_exploit_2.get_flow_exploit_group_id(
        )].append(old_exploit_2)
        self.reconstruction_manager.suspect_dict[old_exploit_3.get_flow_exploit_group_id(
        )] = [old_exploit_3]
        self.reconstruction_manager.suspect_dict[old_exploit_4.get_flow_exploit_group_id(
        )].append(old_exploit_4)
        self.reconstruction_manager.accept(flow_event)
        fns=self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 1)
        self.assertIn(old_exploit_4, fns)

    def test_accept_clustering_single_attack_type_with_clusters(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 1),
                                    datetime(2023, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 6),
                                    datetime(2023, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 10),
                                    datetime(2023, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 12),
                                    datetime(2023, 1, 1, 12, 5), 0.3)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"] = [
            old_exploit_1]
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_2)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_3)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_4)
        self.reconstruction_manager.accept(flow_event)
        fns = self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 3)
        self.assertIn(old_exploit_1, fns)
        self.assertIn(old_exploit_2, fns)
        self.assertIn(old_exploit_3, fns)

    def test_accept_clustering_single_attack_type_no_clusters(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 13),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2010, 1, 1, 11, 1),
                                    datetime(2015, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2018, 1, 1, 11, 6),
                                    datetime(2019, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2021, 1, 1, 11, 10),
                                    datetime(2022, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowExploit(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2026, 1, 1, 12),
                                    datetime(2027, 1, 1, 12, 5), 0.3)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"] = [
            old_exploit_1]
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_2)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_3)
        self.reconstruction_manager.suspect_dict["attack_1-10.0.0.2-10.0.0.3"].append(
            old_exploit_4)
        self.reconstruction_manager.accept(flow_event)
        fns = self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 1)
        self.assertIn(old_exploit_4, fns)

    def test_accept_clustering_multiple_attack_type(self):
        flow_event = FlowEvent(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 13),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.2, "attack_2": 0.9, "attack_3": 0.3})
        old_exploit_1 = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 1),
                                    datetime(2023, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 6),
                                    datetime(2023, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 10),
                                    datetime(2023, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowExploit(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 12),
                                    datetime(2023, 1, 1, 12, 5), 0.3)

        n_old_exploit_1 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 11, 1),
                                      datetime(2023, 1, 1, 11, 5), 0.45)
        n_old_exploit_2 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 11, 6),
                                      datetime(2023, 1, 1, 11, 9), 0.3)
        n_old_exploit_3 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 10),
                                      datetime(2023, 1, 1, 12, 13), 0.89)
        n_old_exploit_4 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 14),
                                      datetime(2023, 1, 1, 12, 15, 58), 0.7)
        n_old_exploit_5 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 15, 59),
                                      datetime(2023, 1, 1, 12, 16, 30), 0.6)
        n_old_exploit_6 = FlowExploit(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 17),
                                      datetime(2023, 1, 1, 12, 18, 23), 0.8)

        m_old_exploit_1 = FlowExploit(self.attack2, [], "10.0.0.5", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 10, 15),
                                      datetime(2023, 1, 1, 10, 16), 0.1)
        m_old_exploit_2 = FlowExploit(self.attack2, [], "10.0.0.5", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 10, 17),
                                      datetime(2023, 1, 1, 10, 18), 0.1)

        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"] = [
            old_exploit_1]
        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"].append(
            old_exploit_2)
        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"].append(
            old_exploit_3)
        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"].append(
            old_exploit_4)

        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"] = [
            n_old_exploit_1]
        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"].append(
            n_old_exploit_2)
        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"].append(
            n_old_exploit_3)
        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"].append(
            n_old_exploit_4)
        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"].append(
            n_old_exploit_5)
        self.reconstruction_manager.suspect_dict["attack_3-10.0.0.2-10.0.0.3"].append(
            n_old_exploit_6)

        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"] = [
            m_old_exploit_1]
        self.reconstruction_manager.suspect_dict["attack_2-10.0.0.2-10.0.0.3"].append(
            m_old_exploit_2)

        self.reconstruction_manager.accept(flow_event)
        fns = self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 4)
        self.assertIn(n_old_exploit_3, fns)
        self.assertIn(n_old_exploit_4, fns)
        self.assertIn(n_old_exploit_5, fns)
        self.assertIn(n_old_exploit_6, fns)


if __name__ == '__main__':
    unittest.main()
