import unittest
from scenario_reconstructor.scenario_reconstructor import Exploit, AttackType, StarNetworkAttackGraphBasedScenarioReconstructor, ExploitRequirement, Preconditions, HostAttribute, Host
from scenario_reconstructor.attack_mapper import AttackMapper
from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.exploit_manager import ExploitGenerator, ScenarioReconstructionManager
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
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.001,
            attack_scores={"attack_1": 0.4, "attack_2": 0.4}
        )
        with self.assertRaises(RuntimeError, msg="The flow event cannot considered an anomaly"):
            self.exploit_generator.to_exploit(flow_event)

    def test_to_exploit_normal(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.7,
            attack_scores={"attack_1": 0.4, "attack_2": 0.9}
        )
        exploit = self.exploit_generator.to_exploit(flow_event)
        self.assertEqual(exploit, Exploit(self.attack2, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                          datetime(2023, 1, 1, 12),
                                          datetime(2023, 1, 2, 2), 0.7, 1))

    def test_to_exploit_unknown(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.7,
            attack_scores={"attack_1": 0.01, "attack_2": 0.01}
        )
        exploit = self.exploit_generator.to_exploit(flow_event)
        self.assertEqual(exploit, Exploit(self.zero_day, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                          datetime(2023, 1, 1, 12),
                                          datetime(2023, 1, 2, 2), 0.7, 1))


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
            [self.host1, self.host2], ["10.0.0.3"], TestHostAttributeConc, [self.attack1, self.attack2, self.attack3, self.zero_day], "./exploits.log", "./states.log")
        self.anomaly_threshold = 0.1
        self.exploit_threshold = 0.5
        self.mapper = AttackMapper(
            [self.attack1, self.attack2, self.attack3], self.anomaly_threshold)
        self.exploit_generator = ExploitGenerator(
            self.mapper, 0.1, self.zero_day)
        self.reconstruction_manager = ScenarioReconstructionManager(
            self.scenario_reconstructor, self.mapper, self.anomaly_threshold, self.exploit_threshold, self.zero_day, "./fns.log", "./fps.log")

    def tearDown(self) -> None:
        if os.path.exists("./exploits.log"):
            os.remove("./exploits.log")
        if os.path.exists("./states.log"):
            os.remove("./states.log")
        if os.path.exists("./fps.log"):
            os.remove("./fps.log")
        if os.path.exists("./fns.log"):
            os.remove("./fns.log")

    def test_accept_anomaly_added(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.2,
            attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0}
        )
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.low_sus_anomalies), 1)
        self.assertIn(Exploit(self.attack2, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                              datetime(2023, 1, 1, 12),
                              datetime(2023, 1, 2, 2), 0.2, 1), self.reconstruction_manager.low_sus_anomalies)

    def test_accept_event_discarted(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.001,
            attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0}
        )
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(len(self.reconstruction_manager.low_sus_anomalies), 0)

    def test_accept_event_compatible(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.3",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.6,
            attack_scores={"attack_1": 0.4, "attack_2": 0.9, "attack_3": 0}
        )
        exploit = Exploit(self.attack2, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                          datetime(2023, 1, 1, 12),
                          datetime(2023, 1, 2, 2), 0.6, 1)
        self.reconstruction_manager.accept(flow_event)
        self.assertEqual(
            len(self.scenario_reconstructor.exploits_dict[exploit.get_exploit_id()]), 1)
        self.assertIn(
            exploit, self.scenario_reconstructor.exploits_dict[exploit.get_exploit_id()])
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromission_attributes(), {
                         TestHostAttributeConc.ATT_2})
        self.assertEqual(
            self.scenario_reconstructor.exploit_sequence[-1], exploit)
        self.assertEqual(len(self.scenario_reconstructor.state_sequence), 2)
        self.reconstruction_manager.log_when_size = 1
        exploit = Exploit(self.attack2, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                          datetime(2023, 1, 1, 12),
                          datetime(2023, 1, 2, 2), 0.6, 1)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./exploits.log"))
        self.assertTrue(os.path.exists("./states.log"))
        with open("./exploits.log", "r") as log1, open("./states.log", "r") as log2:
            lines = [str.strip() for str in log1.readlines()]
            self.assertEqual(len(lines), 2)
            lines = [str.strip() for str in log2.readlines()]
            self.assertEqual(len(lines), 5)

    def test_accept_event_incompatible(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.2",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.6,
            attack_scores={"attack_1": 0.4, "attack_2": 0.1, "attack_3": 0.99}
        )
        exploit = Exploit(self.attack3, "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                          datetime(2023, 1, 1, 12),
                          datetime(2023, 1, 2, 2), 0.6, 1)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./fps.log"))
        with open("./fps.log", "r") as fplog:
            lines = [str.strip() for str in fplog.readlines()]
            self.assertEqual(len(lines), 1)
            self.assertIn(str(exploit), lines)

    def test_accept_no_anomaly_sat_req_found(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.2",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.6,
            attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3}
        )
        exploit = Exploit(self.attack1, "10.0.0.2", "8080", "10.0.0.1", "443", "6",
                          datetime(2023, 1, 1, 12),
                          datetime(2023, 1, 2, 2), 0.6, 1)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./fps.log"))
        with open("./fps.log", "r") as fplog:
            lines = [str.strip() for str in fplog.readlines()]
            self.assertEqual(len(lines), 1)
            self.assertIn(str(exploit), lines)

    def test_accept_single_sat_found(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.2",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.6,
            attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3}
        )
        old_exploit = Exploit(self.attack1, "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                              datetime(2023, 1, 1, 11),
                              datetime(2023, 1, 1, 11, 35), 0.2, 1)
        self.reconstruction_manager.low_sus_anomalies.append(old_exploit)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./fns.log"))
        with open("./fns.log", "r") as fnlog:
            lines = [str.strip() for str in fnlog.readlines()]
            self.assertEqual(len(lines), 1)
            self.assertIn(str(old_exploit), lines)

    def test_accept_multiple_sat_found(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="10.0.0.2",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="6",
            start_time=datetime(2023, 1, 1, 12),
            end_time=datetime(2023, 1, 2, 2),
            anomaly_score=0.6,
            attack_scores={"attack_1": 0.6, "attack_2": 0.1, "attack_3": 0.3}
        )
        old_exploit_1 = Exploit(self.attack1, "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                datetime(2023, 1, 1, 11),
                                datetime(2023, 1, 1, 11, 35), 0.45, 1)
        old_exploit_2 = Exploit(self.attack1, "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                datetime(2023, 1, 1, 11 , 36),
                                datetime(2023, 1, 1, 11, 59, 59 ), 0.3, 1)
        old_exploit_3 = Exploit(self.attack2, "10.0.0.3", "8080", "10.0.0.1", "443", "6",
                                datetime(2023, 1, 1, 11 ),
                                datetime(2023, 1, 1, 11, 59), 0.2, 1)
        old_exploit_4 = Exploit(self.attack1, "10.0.0.3", "8080", "10.0.0.2", "443", "6",
                                datetime(2023, 1, 1, 11 ),
                                datetime(2023, 1, 2), 0.3, 1)        
        self.reconstruction_manager.low_sus_anomalies.append(old_exploit_1)
        self.reconstruction_manager.low_sus_anomalies.append(old_exploit_2)
        self.reconstruction_manager.low_sus_anomalies.append(old_exploit_3)
        self.reconstruction_manager.low_sus_anomalies.append(old_exploit_4)
        self.reconstruction_manager.accept(flow_event)
        self.assertTrue(os.path.exists("./fns.log"))
        with open("./fns.log", "r") as fnlog:
            lines = [str.strip() for str in fnlog.readlines()]
            self.assertEqual(len(lines), 1)
            self.assertIn(str(old_exploit_2), lines)
