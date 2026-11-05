from datetime import datetime, timedelta
from math import nextafter
import os
import unittest

from scenario_reconstructor.alerts import AlertFactory
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import AttackType, FlowAlert, Host, HostAttribute, Precondition
from tests.support import EPOCH, ProjectTestCase


class ExampleHostAttribute(HostAttribute):
    ATT_1 = "att_1"
    ATT_2 = "att_2"
    ATT_3 = "att_3"


class TestAlertFactory(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("attack_1", {Precondition({
            ExampleHostAttribute.ATT_1}, True)}, {ExampleHostAttribute.ATT_1})
        self.attack2 = AttackType("attack_2", {Precondition({
            ExampleHostAttribute.ATT_2}, True)}, {ExampleHostAttribute.ATT_2})
        self.zero_day = AttackType(
            "zero_day", set(), {ExampleHostAttribute.ATT_2, ExampleHostAttribute.ATT_1})
        self.mapper = AttackMapper([self.attack1, self.attack2], 0.1)
        self.exploit_generator = AlertFactory(
            self.mapper, 0.1, self.zero_day)

    def test_to_exploit_error(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.001,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.4})
        with self.assertRaises(RuntimeError, msg="The flow event cannot considered an anomaly"):
            self.exploit_generator.to_flow_exploit(flow_event)

    def test_to_exploit_requires_score_strictly_above_suspect_threshold(self):
        event = self.make_event(score=0.1, scores={'attack_1': 1.0, 'attack_2': 0.0})
        with self.assertRaisesRegex(RuntimeError, 'exceed the suspect threshold'):
            self.exploit_generator.to_flow_exploit(event)
        event.anomaly_score = nextafter(0.1, 1.0)
        self.assertEqual(self.exploit_generator.to_flow_exploit(event).attack_type, self.attack1)

    def test_to_exploit_normal(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.7,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9})
        exploit = self.exploit_generator.to_flow_exploit(flow_event)
        self.assertEqual(exploit, FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                              datetime(2023, 1, 1, 12),
                                              datetime(2023, 1, 2, 2), 0.7))

    def test_to_exploit_unknown(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.7,
                               attack_scores={"attack_1": 0.01, "attack_2": 0.01})
        exploit = self.exploit_generator.to_flow_exploit(flow_event)
        self.assertEqual(exploit, FlowAlert(self.zero_day, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                              datetime(2023, 1, 1, 12),
                                              datetime(2023, 1, 2, 2), 0.7))


class TestReconstructionManager(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("attack_1", {Precondition({
            ExampleHostAttribute.ATT_1}, True)}, {ExampleHostAttribute.ATT_1})
        self.attack2 = AttackType("attack_2", {Precondition({
            ExampleHostAttribute.ATT_2}, True)}, {ExampleHostAttribute.ATT_2})
        self.attack3 = AttackType("attack_3", {Precondition({
            ExampleHostAttribute.ATT_3}, True)}, {ExampleHostAttribute.ATT_2})
        self.zero_day = AttackType(
            "zero_day", set(), {ExampleHostAttribute.ATT_2, ExampleHostAttribute.ATT_1})
        self.scenario_reconstructor = self.make_reconstructor(
            attacks=[self.attack1, self.attack2, self.attack3, self.zero_day],
            internal_hosts=[self.host1, self.host2],
            external_host_attributes={ExampleHostAttribute.ATT_3, ExampleHostAttribute.ATT_2, ExampleHostAttribute.ATT_1},
        )
        self.scenario_reconstructor.seen_external_hosts_dict["10.0.0.3"] = Host(
            "10.0.0.3")
        self.scenario_reconstructor.seen_external_hosts_dict["10.0.0.3"].update_compromise_attributes(
            {ExampleHostAttribute.ATT_3, ExampleHostAttribute.ATT_2, ExampleHostAttribute.ATT_1})
        self.anomaly_threshold = 0.1
        self.exploit_threshold = 0.5
        self.mapper = AttackMapper(
            [self.attack1, self.attack2, self.attack3], self.anomaly_threshold)
        self.exploit_generator = AlertFactory(
            self.mapper, 0.1, self.zero_day)
        self.reconstruction_manager = self.make_manager(
            reconstructor=self.scenario_reconstructor,
            mapper=self.mapper,
            suspect_threshold=self.anomaly_threshold,
            anomaly_threshold=self.exploit_threshold,
            unknown_attack=self.zero_day,
            length_when_log_states=100,
            length_when_log_flow_exploits=100,
            suspect_list_max_length=100,
        )

    def test_accept_anomaly_added(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.2,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.suspect_dict), 1)
        self.assertIn(FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                  datetime(2023, 1, 1, 12),
                                  datetime(2023, 1, 2, 2), 0.2), self.reconstruction_manager.suspect_dict["attack_2-10.0.0.1-10.0.0.3"])

    def test_accept_event_discarded(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.001,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.suspect_dict), 0)

    def test_accept_event_compatible(self):
        flow_event = self.make_event(source_ip="10.0.0.3", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0})
        exploit = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(
            len(self.scenario_reconstructor.flow_exploits_dict["attack_2-10.0.0.1-10.0.0.3"]), 1)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(), {
                         ExampleHostAttribute.ATT_2})
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["attack_2-10.0.0.1-10.0.0.3"][-1], exploit)
        self.assertEqual(len(self.scenario_reconstructor.state_sequence), 2)
        self.reconstruction_manager.length_when_log_states = 1
        self.reconstruction_manager.length_when_log_flow_exploits = 1
        exploit = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists(self.log_path('flow_exploits.log')))
        self.assertTrue(os.path.exists(self.log_path('states.log')))
        with open(self.log_path('flow_exploits.log'), "r") as log1, open(self.log_path('states.log'), "r") as log2:
            lines = [str.strip() for str in log1.readlines()]
            self.assertEqual(len(lines), 2)
            lines = [str.strip() for str in log2.readlines()]
            self.assertEqual(len(lines), 2)

    def test_accept_event_incompatible(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.1, "attack_3": 0.99})
        exploit = FlowAlert(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        fps=self.reconstruction_manager.get_fps()
        self.assertEqual(len(fps), 1)
        self.assertTrue(fps[0].unk_eq(exploit,self.zero_day))

    def test_accept_no_anomaly_sat_req_found(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        exploit = FlowAlert(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.6)
        self.reconstruction_manager.accept(flow_event)
        fps=self.reconstruction_manager.get_fps()
        self.assertEqual(len(fps), 1)
        self.assertTrue(fps[0].unk_eq(exploit,self.zero_day))

    def test_accept_single_sat_found(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                  datetime(2023, 1, 1, 11),
                                  datetime(2023, 1, 1, 11, 35), 0.2)
        self.reconstruction_manager.suspect_dict[old_exploit.get_flow_exploit_group_id(
        )] = [old_exploit]
        self.reconstruction_manager.accept(flow_event)
        fns = self.reconstruction_manager.get_fns()
        self.assertEqual(len(fns), 1)
        self.assertIn(old_exploit, fns)

    def test_accept_zero_day(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.9,
                               attack_scores={"attack_1": 0.1, "attack_2": 0.1, "attack_3": 0.1})
        exploit = FlowAlert(self.zero_day, [], "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.9)
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(
            len(self.scenario_reconstructor.flow_exploits_dict["zero_day-10.0.0.1-10.0.0.2"]), 1)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(), {
                         ExampleHostAttribute.ATT_2, ExampleHostAttribute.ATT_1})
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["zero_day-10.0.0.1-10.0.0.2"][-1], exploit)
        self.assertEqual(len(self.scenario_reconstructor.state_sequence), 2)

    def test_accept_multiple_sat_found(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11),
                                    datetime(2023, 1, 1, 11, 35), 0.45)
        old_exploit_2 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 36),
                                    datetime(2023, 1, 1, 11, 59, 59), 0.3)
        old_exploit_3 = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                    datetime(2023, 1, 1, 11),
                                    datetime(2023, 1, 1, 11, 59), 0.2)
        old_exploit_4 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
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
        # The long alert overlaps both shorter alerts in its context.
        self.assertCountEqual(fns, [old_exploit_1, old_exploit_2, old_exploit_4])

    def test_accept_clustering_selects_latest_singleton(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12, 6),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 1),
                                    datetime(2023, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 6),
                                    datetime(2023, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 10),
                                    datetime(2023, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
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
        self.assertEqual(fns, [old_exploit_4])

    def test_accept_clustering_single_attack_type_no_clusters(self):
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2028, 1, 1, 13),
                               end_time=datetime(2028, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3})
        old_exploit_1 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2010, 1, 1, 11, 1),
                                    datetime(2015, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2018, 1, 1, 11, 6),
                                    datetime(2019, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2021, 1, 1, 11, 10),
                                    datetime(2022, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowAlert(self.attack1, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
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
        # Keep the intended four-alert candidate together using a physical-time threshold.
        self.scenario_reconstructor.max_idle_gap = timedelta(seconds=60)
        flow_event = self.make_event(source_ip="10.0.0.2", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 13),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.6,
                               attack_scores={"attack_1": 0.2, "attack_2": 0.9, "attack_3": 0.3})
        old_exploit_1 = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 1),
                                    datetime(2023, 1, 1, 11, 5), 0.45)
        old_exploit_2 = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 6),
                                    datetime(2023, 1, 1, 11, 9, 59), 0.3)
        old_exploit_3 = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 11, 10),
                                    datetime(2023, 1, 1, 11, 13), 0.2)
        old_exploit_4 = FlowAlert(self.attack2, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                    datetime(2023, 1, 1, 12),
                                    datetime(2023, 1, 1, 12, 5), 0.3)

        n_old_exploit_1 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 11, 1),
                                      datetime(2023, 1, 1, 11, 5), 0.45)
        n_old_exploit_2 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 11, 6),
                                      datetime(2023, 1, 1, 11, 9), 0.3)
        n_old_exploit_3 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 10),
                                      datetime(2023, 1, 1, 12, 13), 0.89)
        n_old_exploit_4 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 14),
                                      datetime(2023, 1, 1, 12, 15, 58), 0.7)
        n_old_exploit_5 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 15, 59),
                                      datetime(2023, 1, 1, 12, 16, 30), 0.6)
        n_old_exploit_6 = FlowAlert(self.attack3, [], "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 12, 17),
                                      datetime(2023, 1, 1, 12, 18, 23), 0.8)

        m_old_exploit_1 = FlowAlert(self.attack2, [], "10.0.0.5", "8080", "10.0.0.2", "443", "6",
                                      datetime(2023, 1, 1, 10, 15),
                                      datetime(2023, 1, 1, 10, 16), 0.1)
        m_old_exploit_2 = FlowAlert(self.attack2, [], "10.0.0.5", "8080", "10.0.0.2", "443", "6",
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


class TestBatchManagerResults(ProjectTestCase):

    def test_empty_results_return_dag_and_alert_list(self):
        dag, alerts = self.make_manager().get_results()
        self.assertIsInstance(dag, AttackScenarioDAG)
        self.assertEqual(dag.steps, [])
        self.assertEqual(dag.roots, [])
        self.assertEqual(alerts, [])

    def test_results_cluster_all_groups_and_sort_steps_and_alerts(self):
        manager = self.make_manager()
        # Both discoveries are retained even though only the first changes state.
        manager.accept(self.make_event(second=10, score=0.95))
        manager.accept(self.make_event(second=0, score=0.95))
        manager.accept(self.make_event(second=20, score=0.95, scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        dag, alerts = manager.get_results()

        self.assertIsInstance(dag, AttackScenarioDAG)
        self.assertEqual(len(alerts), 3)
        self.assertEqual([alert.start_time for alert in alerts],
                         sorted(alert.start_time for alert in alerts))
        self.assertEqual([step.start_time for step in dag.steps],
                         [alert.start_time for alert in alerts])
        first, repeat, finish = dag.steps
        self.assertEqual([step.attack_type for step in dag.steps],
                         [self.discover, self.discover, self.finish])
        self.assertEqual(dag.roots, [first, repeat])
        self.assertEqual(dag.parents_map[repeat], [])
        self.assertEqual(dag.clause_parents_map[repeat], [])
        self.assertEqual(dag.parents_map[finish], [first, repeat])
        self.assertEqual(dag.clause_parents_map[finish], [[first, repeat]])
        self.assertEqual(dag.get_adjacent_pairs(), {(first, finish), (repeat, finish)})
        self.assertEqual(dag.get_repetition_pairs(), {(first, repeat)})

    def test_results_include_recovered_fn_as_causal_parent(self):
        manager = self.make_manager()
        manager.accept(self.make_event(second=0, score=0.5))
        before, before_alerts = manager.get_results()
        self.assertEqual(before.steps, [])
        self.assertEqual(before_alerts, [])

        manager.accept(self.make_event(second=10, score=0.95, scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        dag, alerts = manager.get_results()
        self.assertIsInstance(dag, AttackScenarioDAG)
        self.assertEqual(len(manager.get_fns()), 1)
        self.assertEqual(manager.get_fps(), [])
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0], manager.get_fns()[0])
        self.assertEqual(alerts[0].start_time, EPOCH)
        recovered, trigger = dag.steps
        self.assertEqual([step.attack_type for step in dag.steps], [self.discover, self.finish])
        self.assertEqual(dag.roots, [recovered])
        self.assertEqual(dag.parents_map[trigger], [recovered])
        self.assertEqual(dag.clause_parents_map[trigger], [[recovered]])
        self.assertEqual(dag.children_map[recovered], [trigger])
        self.assertEqual(dag.get_causal_pairs(), {(recovered, trigger)})
        self.assertEqual(before.steps, [])

    def test_repeated_results_rebuild_dag_and_reset_clears_it(self):
        manager = self.make_manager()
        manager.accept(self.make_event(score=0.95))
        before, _ = manager.get_results()
        manager.accept(self.make_event(second=10, score=0.95, scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        after, alerts = manager.get_results()
        self.assertIsNot(before, after)
        self.assertEqual(len(before.steps), 1)
        self.assertEqual(before.get_adjacent_pairs(), set())
        self.assertEqual(len(after.steps), 2)
        self.assertEqual(len(alerts), 2)
        again, again_alerts = manager.get_results()
        self.assertEqual(again.steps, after.steps)
        self.assertEqual(again.get_adjacent_pairs(), after.get_adjacent_pairs())
        self.assertEqual(again_alerts, alerts)

        manager.reset({host: set() for host in manager.reconstructor.host_dict.values()})
        cleared, cleared_alerts = manager.get_results()
        self.assertEqual(cleared.steps, [])
        self.assertEqual(cleared.roots, [])
        self.assertEqual(cleared_alerts, [])


if __name__ == '__main__':
    unittest.main()
