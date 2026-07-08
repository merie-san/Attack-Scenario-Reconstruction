import unittest
from scenario_reconstructor.scenario_reconstructor import Host, StarNetworkAttackGraphBasedScenarioReconstructor, HostAttribute, AttackType, FlowExploit, Preconditions, ExploitRequirement, Exploit, NetworkState, StringToExploitConverter, StringToNetworkStateConvertor
from datetime import datetime, timezone
import os
import numpy as np


class TestHostCompromiseAttributeImplementation(HostAttribute):
    HOST_DISCOVERED = "host_discovered"
    PORT_SCANNED = "port_scanned"
    HOST_VULNERABLE = "host_vulnerable"
    HOST_COMPROMISED = "host_compromised"


class TestExploit(unittest.TestCase):

    def setUp(self) -> None:
        self.exploit = Exploit(AttackType("attack_1", set(), set()), 2, "109.0.0.2", "108.8.09.9", datetime(
            2026, 11, 12, 10), datetime(2026, 11, 12, 10, 30), 2, 3)

    def test_get_exploit_group_id(self):
        self.assertEqual(self.exploit.get_exploit_group_id(),
                         "attack_1-108.8.09.9-109.0.0.2")

    def test_to_str(self):
        self.assertEqual(str(self.exploit), "Exploit(attack_type=attack_1, size=2, source_ip=109.0.0.2, destination_ip=108.8.09.9, start_time=2026-11-12T10:00:00, end_time=2026-11-12T10:30:00, mean_ift=2, std_ift=3)")


class TestNetworkState(unittest.TestCase):

    def setUp(self) -> None:
        attribute_dict = {"10.0.0.5": {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}, "10.0.0.6": {
            TestHostCompromiseAttributeImplementation.PORT_SCANNED}}
        self.state = NetworkState(attribute_dict, datetime(2026, 10, 10, 10))

    def test_to_str(self):
        self.assertEqual(str(
            self.state), "NetworkState(state={10.0.0.5={host_discovered}-10.0.0.6={port_scanned}}, time=2026-10-10T10:00:00)")

    def test_from_dict_of_host(self):
        host1 = Host("10.0.0.5")
        host2 = Host("10.0.0.6")
        host1.update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        host2.update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.PORT_SCANNED})
        self.assertEqual(NetworkState.from_dict_of_host(
            {"10.0.0.5": host1, "10.0.0.6": host2}, datetime(2026, 10, 10, 10)), self.state)


class TestStringToNetworkStateConverter(unittest.TestCase):

    def setUp(self) -> None:
        self.converter = StringToNetworkStateConvertor(
            TestHostCompromiseAttributeImplementation)

    def test_from_str_empty_state(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={}, time=2026-10-10T10:00:00)"),
                         NetworkState({}, datetime(2026, 10, 10, 10)))

    def test_from_str_single(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={10.0.0.5={host_discovered}}, time=2026-10-10T10:00:00)"), NetworkState(
            {"10.0.0.5": {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}}, datetime(2026, 10, 10, 10)))

    def test_from_str_multiple(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={10.0.0.5={host_discovered; port_scanned}-10.0.0.6={host_discovered; port_scanned}}, time=2026-10-10T10:00:00)"), NetworkState({"10.0.0.5": {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED,
                         TestHostCompromiseAttributeImplementation.PORT_SCANNED}, "10.0.0.6": {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED, TestHostCompromiseAttributeImplementation.PORT_SCANNED}}, datetime(2026, 10, 10, 10)))


class TestStringToExploitConverter(unittest.TestCase):

    def setUp(self) -> None:
        self.converter = StringToExploitConverter(
            [AttackType("attack_1", set(), set()), AttackType("attack_2", set(), set())])

    def test_str_to_flow_exploit(self):
        self.assertEqual(self.converter.from_str_flow_exploit("FlowExploit(attack_type=attack_1, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5)"), FlowExploit(AttackType("attack_1", set(), set()), [], "10.0.0.1", "50", "10.0.0.2",
                                                                                                                                                                                                                                                                                                 "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5))

    def test_str_to_exploit(self):
        self.assertEqual(self.converter.from_str_exploit("Exploit(attack_type=attack_1, size=2, source_ip=109.0.0.2, destination_ip=108.8.09.9, start_time=2026-11-12T10:00:00, end_time=2026-11-12T10:30:00, mean_ift=2, std_ift=3)"), Exploit(AttackType("attack_1", set(), set()), 2, "109.0.0.2", "108.8.09.9", datetime(
            2026, 11, 12, 10), datetime(2026, 11, 12, 10, 30), 2, 3))


class TestHost(unittest.TestCase):

    def test_update_compromission_attributes(self):
        host = Host("10.0.0.1")
        self.assertEqual(len(host.compromise_attributes), 0)
        host.update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        self.assertIn(TestHostCompromiseAttributeImplementation.HOST_DISCOVERED,
                      host.compromise_attributes)


class TestAttackType(unittest.TestCase):

    def setUp(self):
        self.attack_type = AttackType("nmap_port_scan", set(),
                                      {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})

    def test_eq(self):
        self.assertNotEqual(self.attack_type, AttackType(
            "nmap_port_scan", set(), set()))
        self.assertNotEqual(self.attack_type, AttackType(
            "host_scan", set(), {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}))
        self.assertEqual(self.attack_type, AttackType("nmap_port_scan", set(),
                                                      {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}))

    def test_str(self):
        self.assertEqual(str(self.attack_type), "nmap_port_scan")

    def test_get_preconditions(self):
        src_cond, dst_cond = self.attack_type.get_preconditions()
        self.assertEqual(len(src_cond), 0)
        self.assertEqual(len(dst_cond), 0)
        new_attack = AttackType("nmap_port_scan", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True), Preconditions({TestHostCompromiseAttributeImplementation.PORT_SCANNED}, False)},
                                {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        src_cond, dst_cond = new_attack.get_preconditions()
        self.assertEqual(len(src_cond), 1)
        self.assertIn(Preconditions(
            {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True), src_cond)
        self.assertEqual(len(dst_cond), 1)
        self.assertIn(Preconditions(
            {TestHostCompromiseAttributeImplementation.PORT_SCANNED}, False), dst_cond)


class TestFlowExploit(unittest.TestCase):

    def setUp(self):
        self.exploit = FlowExploit(AttackType("unknown", set(), set()), [], "10.0.0.1", "50", "10.0.0.2",
                                   "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5)

    def test_exploit_id(self):
        self.assertEqual(self.exploit.get_flow_exploit_group_id(),
                         "unknown-10.0.0.2-10.0.0.1")

    def test_str(self):
        self.assertEqual(str(self.exploit), "FlowExploit(attack_type=unknown, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5)")


class TestFlowExploitRequirements(unittest.TestCase):

    def setUp(self) -> None:
        self.attack1 = AttackType("host_discovery", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                  TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}, False), Preconditions(
            {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True)}, {TestHostCompromiseAttributeImplementation.PORT_SCANNED})
        self.requirement1 = ExploitRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1")

    def test_eq(self):
        self.assertEqual(self.requirement1, ExploitRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(
            self.attack2, ["10.0.0.5"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(
            self.attack1, ["10.0.0.3"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.3"))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(
            self.attack2, ["10.0.0.30"], "10.0.0.0"))
        new_requirement = ExploitRequirement(self.attack1, [
                                             "10.0.0.0", "10.0.0.3"], "10.0.0.1")
        self.assertEqual(new_requirement, ExploitRequirement(self.attack1, [
                         "10.0.0.0", "10.0.0.3"], "10.0.0.1"))
        self.assertEqual(new_requirement, ExploitRequirement(self.attack1, [
                         "10.0.0.3", "10.0.0.0"], "10.0.0.1"))
        self.assertNotEqual(new_requirement, ExploitRequirement(self.attack1, [
                            "10.0.0.3", "10.0.0.0", "10.0.0.255"], "10.0.0.1"))

    def test_hash(self):
        self.assertEqual(hash(self.requirement1), hash(
            hash(self.attack1)+hash("10.0.0.5")+hash("10.0.0.1")))


class TestStarNetworkAttackGraphBasedScenarioReconstructor(unittest.TestCase):

    def setUp(self):
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("host_discovery", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                  TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}, False), Preconditions(
            {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True)}, {TestHostCompromiseAttributeImplementation.PORT_SCANNED})
        self.attack3 = AttackType("brute_force", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True), Preconditions({TestHostCompromiseAttributeImplementation.PORT_SCANNED}, False)}, {
                                  TestHostCompromiseAttributeImplementation.HOST_COMPROMISED})
        self.attack4 = AttackType("vulnerability_exploit", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True), Preconditions(
            {TestHostCompromiseAttributeImplementation.PORT_SCANNED}, False), Preconditions({TestHostCompromiseAttributeImplementation.HOST_VULNERABLE}, False)}, {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor = StarNetworkAttackGraphBasedScenarioReconstructor(
            [self.host1, self.host2], {TestHostCompromiseAttributeImplementation.PORT_SCANNED, TestHostCompromiseAttributeImplementation.HOST_VULNERABLE, TestHostCompromiseAttributeImplementation.HOST_DISCOVERED, TestHostCompromiseAttributeImplementation.HOST_COMPROMISED},  [self.attack1, self.attack2, self.attack3, self.attack4], "./exploits.log", "./flow_exploits.log", "./states.log", "./correlations.log")

    def tearDown(self):
        if os.path.exists("./exploits.log"):
            os.remove("./exploits.log")
        if os.path.exists("./flow_exploits.log"):
            os.remove("./flow_exploits.log")
        if os.path.exists("./states.log"):
            os.remove("./states.log")
        if os.path.exists("./correlations.log"):
            os.remove("./correlations.log")

    def test_check_preconditions(self):
        exploit = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertTrue(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = FlowExploit(self.attack1, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertFalse(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = FlowExploit(self.attack1, [], "10.0.0.111", "50000", "10.0.0.23", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        with self.assertRaises(ValueError):
            self.scenario_reconstructor.check_preconditions(exploit)

    def test_set_postconditions(self):
        exploit = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.set_postconditions(exploit)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromise_attributes(
        ), exploit.attack_type.postconditions)

    def test_add_exploit(self):
        exploit = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.add_flow_exploit(exploit)
        self.assertIn("host_discovery-10.0.0.1-10.0.0.5",
                      self.scenario_reconstructor.flow_exploits_dict)
        self.assertEqual(
            self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"][-1], exploit)

    def test_get_flow_expoit_group_size(self):
        exploit = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 0)
        self.scenario_reconstructor.add_flow_exploit(exploit)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 1)
        exploit2 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9)
        self.scenario_reconstructor.add_flow_exploit(exploit2)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit), 2)
        exploit3 = FlowExploit(self.attack2, [], "10.0.0.5", "50001", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9)
        self.scenario_reconstructor.add_flow_exploit(exploit3)
        self.assertEqual(
            self.scenario_reconstructor.get_flow_exploit_group_length(exploit2), 2)

    def test_check_exploit_requirements_invalid_ips(self):
        exploit1 = FlowExploit(self.attack1, [], "10.0.0.53", "50000", "10.0.0.23", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        with self.assertRaises(ValueError, msg="Precondition defined on two external ips: 10.0.0.53 10.0.0.23"):
            self.scenario_reconstructor.check_preconditions(exploit1)

    def test_compute_requirements_edge_cases(self):
        exploit1 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertEqual(
            self.scenario_reconstructor.compute_requirements(exploit1), set())
        exploit2 = FlowExploit(self.attack1, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit2))
        exploit3 = FlowExploit(self.attack2, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit3))
        exploit4 = FlowExploit(self.attack2, [], "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit4))

    def test_compute_requirements_single(self):
        exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"))
        exploit2 = FlowExploit(self.attack1, [], "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.host_dict["10.0.0.2"].compromise_attributes.add(
            TestHostCompromiseAttributeImplementation.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(
            self.attack3, ["10.0.0.5"], "10.0.0.2"))

    def test_compute_requirements_multiple_blue_hosts(self):
        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.3"].update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED})

        exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(ExploitRequirement(
            self.attack1, ["10.0.0.5", "10.0.0.3"], "10.0.0.1"), requirements)
        exploit2 = FlowExploit(self.attack1, [], "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.host_dict["10.0.0.2"].compromise_attributes.add(
            TestHostCompromiseAttributeImplementation.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(ExploitRequirement(
            self.attack3, ["10.0.0.5", "10.0.0.3"], "10.0.0.2"), requirements)

    def test_compute_requirements_multiple_green_attacks(self):
        new_attack = AttackType("metasploit_port_scan", {Preconditions({TestHostCompromiseAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                TestHostCompromiseAttributeImplementation.HOST_DISCOVERED, TestHostCompromiseAttributeImplementation.PORT_SCANNED})
        self.scenario_reconstructor.attack_types.append(new_attack)

        exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(ExploitRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"), requirements)
        self.assertIn(ExploitRequirement(
            new_attack, ["10.0.0.5"], "10.0.0.1"), requirements)

        exploit2 = FlowExploit(self.attack1, [], "10.0.0.2", "50000", "10.0.0.3", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)

        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.PORT_SCANNED, TestHostCompromiseAttributeImplementation.HOST_VULNERABLE})

        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(ExploitRequirement(
            self.attack3, ["10.0.0.5", "10.0.0.1"], "10.0.0.2"), requirements)
        self.assertIn(ExploitRequirement(
            self.attack4, ["10.0.0.5", "10.0.0.1"], "10.0.0.2"), requirements)

    def test_would_change_state(self):
        exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.assertTrue(
            self.scenario_reconstructor.would_change_state(exploit1))
        self.host1.update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.PORT_SCANNED})
        self.assertFalse(
            self.scenario_reconstructor.would_change_state(exploit1))

    def test_add_correlation(self):
        exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.add_correlation(exploit1)
        self.assertEqual(
            self.scenario_reconstructor.correlation_sequence[-1], "port_scanning-10.0.0.1-10.0.0.5-2026-06-10T10:30:00")

    def test_log_empty(self):
        f_exploit1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        self.scenario_reconstructor.flow_exploits_dict["port_scanning-10.0.0.1-10.0.0.5"] = [
            f_exploit1]
        with self.assertRaises(RuntimeError):
            self.scenario_reconstructor.log_exploits(f_exploit1)
        self.scenario_reconstructor.flow_exploits_dict["port_scanning-10.0.0.1-10.0.0.5"] = [
        ]
        exploit = Exploit(self.attack2, 1, "10.0.0.5", "10.0.0.1", datetime(
            2026, 12, 12, 12), datetime(2026, 12, 21, 0), 12, 12)
        self.scenario_reconstructor.exploits_dict["port_scanning-10.0.0.1-10.0.0.5"] = [
            exploit]
        with self.assertRaises(RuntimeError):
            self.scenario_reconstructor.log_exploits(f_exploit1)

    def test_log_exploits(self):
        flow_ex1 = FlowExploit(self.attack2, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)
        flow_ex2 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)

        ex1 = Exploit(self.attack2, 3, "10.0.0.5", "10.0.0.1", datetime(
            2026, 12, 12, 12), datetime(2026, 12, 21, 0), 12, 12)
        ex2 = Exploit(self.attack1, 3, "10.0.0.5", "10.0.0.1", datetime(
            2026, 12, 12, 12), datetime(2026, 12, 21, 0), 12, 12)

        self.scenario_reconstructor.flow_exploits_dict["port_scanning-10.0.0.1-10.0.0.5"] = [
            flow_ex1]
        self.scenario_reconstructor.exploits_dict["port_scanning-10.0.0.1-10.0.0.5"] = [
            ex1]

        self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            flow_ex2]
        self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            ex2]

        self.scenario_reconstructor.log_exploits(flow_ex1)

        self.assertEqual(len(
            self.scenario_reconstructor.flow_exploits_dict["port_scanning-10.0.0.1-10.0.0.5"]), 0)
        self.assertEqual(len(
            self.scenario_reconstructor.exploits_dict["port_scanning-10.0.0.1-10.0.0.5"]), 0)

        self.assertEqual(len(
            self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"]), 1)
        self.assertEqual(len(
            self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"]), 1)

        with open("./flow_exploits.log", "r") as e_l:
            lines = e_l.readlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0], "port_scanning-10.0.0.1-10.0.0.5\n")
            self.assertEqual(lines[1], "FlowExploit(attack_type=port_scanning, source_ip=10.0.0.5, source_port=50000, destination_ip=10.0.0.1, destination_port=40, protocol=6, start_time=2026-06-10T10:30:00, end_time=2026-06-10T10:35:00, anomaly_score=0.8)\n")
            self.assertEqual(lines[2], "\n")

        with open("./exploits.log", "r") as e_l:
            lines = e_l.readlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0], "port_scanning-10.0.0.1-10.0.0.5\n")
            self.assertEqual(
                lines[1], "Exploit(attack_type=port_scanning, size=3, source_ip=10.0.0.5, destination_ip=10.0.0.1, start_time=2026-12-12T12:00:00, end_time=2026-12-21T00:00:00, mean_ift=12, std_ift=12)\n")
            self.assertEqual(lines[2], "\n")

    def test_log_exploits_multiple(self):
        flow_ex2 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)
        ex2 = Exploit(self.attack1, 3, "10.0.0.5", "10.0.0.1", datetime(
            2026, 12, 12, 12), datetime(2026, 12, 21, 0), 12, 12)

        ex_new = Exploit(self.attack1, 4, "10.0.0.5", "10.0.0.1", datetime(
            2026, 12, 12, 12), datetime(2026, 12, 21, 0), 12, 10)
        flow_ex_new = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8)

        self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            flow_ex2, flow_ex_new]
        self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            ex2, ex_new]

        self.scenario_reconstructor.log_exploits(flow_ex2)
        with open("./flow_exploits.log", "r") as e_l:
            lines = e_l.readlines()
            self.assertEqual(len(lines), 4)
            self.assertEqual(lines[0], "host_discovery-10.0.0.1-10.0.0.5\n")
            self.assertEqual(lines[1], "FlowExploit(attack_type=host_discovery, source_ip=10.0.0.5, source_port=50000, destination_ip=10.0.0.1, destination_port=40, protocol=6, start_time=2026-06-10T10:00:00, end_time=2026-06-10T10:03:00, anomaly_score=0.7)\n")
            self.assertEqual(lines[2], "FlowExploit(attack_type=host_discovery, source_ip=10.0.0.5, source_port=50000, destination_ip=10.0.0.1, destination_port=40, protocol=6, start_time=2026-06-10T10:30:00, end_time=2026-06-10T10:35:00, anomaly_score=0.8)\n")
            self.assertEqual(lines[3], "\n")

        with open("./exploits.log", "r") as e_l:
            lines = e_l.readlines()
            self.assertEqual(len(lines), 4)
            self.assertEqual(lines[0], "host_discovery-10.0.0.1-10.0.0.5\n")
            self.assertEqual(
                lines[1], "Exploit(attack_type=host_discovery, size=3, source_ip=10.0.0.5, destination_ip=10.0.0.1, start_time=2026-12-12T12:00:00, end_time=2026-12-21T00:00:00, mean_ift=12, std_ift=12)\n")
            self.assertEqual(
                lines[2], "Exploit(attack_type=host_discovery, size=4, source_ip=10.0.0.5, destination_ip=10.0.0.1, start_time=2026-12-12T12:00:00, end_time=2026-12-21T00:00:00, mean_ift=12, std_ift=10)\n")
            self.assertEqual(lines[3], "\n")

    def test_update_network_state(self):
        flow_ex = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)
        self.host1.update_compromise_attributes(
            {TestHostCompromiseAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.update_network_state(flow_ex)
        self.assertEqual(self.scenario_reconstructor.state_sequence[-1], NetworkState({"10.0.0.1": {
                         TestHostCompromiseAttributeImplementation.HOST_DISCOVERED}, "10.0.0.2": set()}, datetime(2026, 6, 10, 10, 3)))

    def test_update_exploits_empty(self):
        flow_ex = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10), datetime(2026, 6, 10, 10, 3), 0.7)
        with self.assertRaises(RuntimeError):
            self.scenario_reconstructor.update_exploits(flow_ex)

    def test_update_exploits(self):
        flow_ex1 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 1, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 1, 40, tzinfo=timezone.utc), 0.7)
        flow_ex2 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 3, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 3, 50, tzinfo=timezone.utc), 0.7)
        flow_ex3 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 2, 10, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 3, tzinfo=timezone.utc), 0.7)
        flow_ex4 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 4, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 4, 55, tzinfo=timezone.utc), 0.7)
        flow_ex5 = FlowExploit(self.attack1, [], "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 33, tzinfo=timezone.utc), 0.7)
        self.scenario_reconstructor.flow_exploits_dict["host_discovery-10.0.0.1-10.0.0.5"] = [
            flow_ex1, flow_ex2, flow_ex3, flow_ex4, flow_ex5]
        self.scenario_reconstructor.update_exploits(flow_ex5)
        self.assertEqual(len(
            self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"]), 2)
        self.assertIn(Exploit(self.attack1, 1, "10.0.0.5", "10.0.0.1", datetime(
            2026, 6, 10, 10, 30, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 30, tzinfo=timezone.utc), -1, -1), self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"])
        self.assertIn(Exploit(self.attack1, 4, "10.0.0.5", "10.0.0.1", datetime(
            2026, 6, 10, 10, 1, tzinfo=timezone.utc), datetime(2026, 6, 10, 10, 4, tzinfo=timezone.utc), np.array([30, 30, 10]).mean(), np.array([30, 30, 10]).std()), self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-10.0.0.5"])


if __name__ == '__main__':
    unittest.main()
