from datetime import datetime, timedelta, timezone

import numpy as np

from scenario_reconstructor.models import (
    AttackStep,
    AttackType,
    FlowAlert,
    Host,
    NetworkState,
    Precondition,
    RecoveryRequirement,
)
from tests.fixtures import NetworkAttribute
from tests.support import ProjectTestCase


class TestScenarioReconstructor(ProjectTestCase):

    def setUp(self):
        super().setUp()
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("host_discovery", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True)}, {
                                  NetworkAttribute.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Precondition({NetworkAttribute.HOST_DISCOVERED}, False), Precondition(
            {NetworkAttribute.HOST_COMPROMISED}, True)}, {NetworkAttribute.PORT_SCANNED})
        self.attack3 = AttackType("brute_force", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True), Precondition({NetworkAttribute.PORT_SCANNED}, False)}, {
                                  NetworkAttribute.HOST_COMPROMISED})
        self.attack4 = AttackType("vulnerability_exploit", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True), Precondition(
            {NetworkAttribute.PORT_SCANNED}, False), Precondition({NetworkAttribute.HOST_VULNERABLE}, False)}, {NetworkAttribute.HOST_COMPROMISED})
        self.scenario_reconstructor = self.make_reconstructor(
            attacks=[self.attack1, self.attack2, self.attack3, self.attack4],
            internal_hosts=[self.host1, self.host2],
            external_host_attributes={NetworkAttribute.PORT_SCANNED, NetworkAttribute.HOST_VULNERABLE, NetworkAttribute.HOST_DISCOVERED, NetworkAttribute.HOST_COMPROMISED},
        )

    def test_check_preconditions(self):
        exploit = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertTrue(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = FlowAlert(self.attack1, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertFalse(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = FlowAlert(self.attack1, [], "10.0.0.111", "50000", "10.0.0.23", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        with self.assertRaises(ValueError):
            self.scenario_reconstructor.check_preconditions(exploit)

    def test_set_postconditions(self):
        exploit = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.set_postconditions(exploit)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(
        ), exploit.attack_type.postconditions)

    def test_add_exploit(self):
        exploit = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.add_flow_exploit(exploit)
        self.assertIn("host_discovery-10.0.0.1-10.0.0.5",
                      self.scenario_reconstructor.flow_exploits_dict)
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"][-1], exploit)

    def test_alert_group_size(self):
        exploit = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 0)
        self.scenario_reconstructor.add_flow_exploit(exploit)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 1)
        exploit2 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9)
        self.scenario_reconstructor.add_flow_exploit(exploit2)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 2)
        exploit3 = FlowAlert(self.attack2, [], "10.0.0.5", "50001", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9)
        self.scenario_reconstructor.add_flow_exploit(exploit3)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit2), 2)

    def test_check_exploit_requirements_invalid_ips(self):
        exploit1 = FlowAlert(self.attack1, [], "10.0.0.53", "50000", "10.0.0.23", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        with self.assertRaises(ValueError, msg="Precondition defined on two external ips: 10.0.0.53 10.0.0.23"):
            self.scenario_reconstructor.check_preconditions(exploit1)

    def test_compute_requirements_edge_cases(self):
        exploit1 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertEqual(
            self.scenario_reconstructor.compute_requirements(exploit1), set())
        exploit2 = FlowAlert(self.attack1, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit2))
        exploit3 = FlowAlert(self.attack2, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit3))
        exploit4 = FlowAlert(self.attack2, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit4))

    def test_compute_requirements_single(self):
        exploit1 = FlowAlert(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, RecoveryRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"))
        exploit2 = FlowAlert(self.attack1, [], "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.host_dict["10.0.0.2"].compromise_attributes.add(
            NetworkAttribute.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, RecoveryRequirement(
            self.attack3, ["10.0.0.5"], "10.0.0.2"))

    def test_compute_requirements_multiple_blue_hosts(self):
        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.3"].update_compromise_attributes(
            {NetworkAttribute.HOST_COMPROMISED})

        exploit1 = FlowAlert(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(RecoveryRequirement(
            self.attack1, ["10.0.0.5", "10.0.0.3"], "10.0.0.1"), requirements)
        exploit2 = FlowAlert(self.attack1, [], "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.host_dict["10.0.0.2"].compromise_attributes.add(
            NetworkAttribute.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(RecoveryRequirement(
            self.attack3, ["10.0.0.5", "10.0.0.3"], "10.0.0.2"), requirements)

    def test_compute_requirements_multiple_green_attacks(self):
        new_attack = AttackType("metasploit_port_scan", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True)}, {
                                NetworkAttribute.HOST_DISCOVERED, NetworkAttribute.PORT_SCANNED})
        self.scenario_reconstructor.attack_types.append(new_attack)

        exploit1 = FlowAlert(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(RecoveryRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"), requirements)
        self.assertIn(RecoveryRequirement(
            new_attack, ["10.0.0.5"], "10.0.0.1"), requirements)

        exploit2 = FlowAlert(self.attack1, [], "10.0.0.2", "50000", "10.0.0.3", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)

        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromise_attributes(
            {NetworkAttribute.HOST_COMPROMISED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromise_attributes(
            {NetworkAttribute.PORT_SCANNED, NetworkAttribute.HOST_VULNERABLE})

        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(RecoveryRequirement(
            self.attack3, ["10.0.0.5", "10.0.0.1"], "10.0.0.2"), requirements)
        self.assertIn(RecoveryRequirement(
            self.attack4, ["10.0.0.5", "10.0.0.1"], "10.0.0.2"), requirements)

    def test_would_change_state(self):
        exploit1 = FlowAlert(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertTrue(
            self.scenario_reconstructor.would_change_state(exploit1))
        self.host1.update_compromise_attributes(
            {NetworkAttribute.PORT_SCANNED})
        self.assertFalse(
            self.scenario_reconstructor.would_change_state(exploit1))

    def test_update_network_state(self):
        flow_ex = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)
        self.host1.update_compromise_attributes(
            {NetworkAttribute.HOST_DISCOVERED})
        self.scenario_reconstructor.update_network_state(flow_ex)
        self.assertEqual(self.scenario_reconstructor.state_sequence[-1], NetworkState({"10.0.0.1": {
                         NetworkAttribute.HOST_DISCOVERED}, "10.0.0.2": set()}, datetime(2026, 6, 10, 10, 3)))

    def test_update_exploits_empty(self):
        flow_ex = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)
        with self.assertRaises(RuntimeError):
            self.scenario_reconstructor.update_exploits(flow_ex)

    def test_update_exploits(self):
        # This fixture's first four flows have idle gaps of 10 to 30 seconds.
        self.scenario_reconstructor.max_idle_gap = timedelta(seconds=30)
        flow_ex1 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 1, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 1, 40, tzinfo=timezone.utc), 0.7)
        flow_ex2 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 3, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 3, 50, tzinfo=timezone.utc), 0.7)
        flow_ex3 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 2, 10, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 3, tzinfo=timezone.utc), 0.7)
        flow_ex4 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 4, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 4, 55, tzinfo=timezone.utc), 0.7)
        flow_ex5 = FlowAlert(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 33, tzinfo=timezone.utc), 0.7)
        self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            flow_ex1, flow_ex2, flow_ex3, flow_ex4, flow_ex5]
        self.scenario_reconstructor.update_exploits(flow_ex5)
        self.assertEqual(len(
            self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"]), 2)
        self.assertIn(AttackStep(self.attack1, 1, "10.0.0.5", "10.0.0.1", datetime(
            2026, 6, 10, 10, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 33, tzinfo=timezone.utc), -1, -1), self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"])
        self.assertIn(AttackStep(self.attack1, 4, "10.0.0.5", "10.0.0.1", datetime(
            2026, 6, 10, 10, 1, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 4, 55, tzinfo=timezone.utc), np.array([30000, 30000, 10000]).mean(), np.array([30000, 30000, 10000]).std()), self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"])
