import unittest
from scenario_reconstructor.scenario_reconstructor import Host, StarNetworkAttackGraphBasedScenarioReconstructor, HostAttribute, AttackType, Exploit, Preconditions, ExploitRequirement
from datetime import datetime
import os


class TestHostCompromissionAttributeImplementation(HostAttribute):
    HOST_DISCOVERED = "host_discovered"
    PORT_SCANNED = "port_scanned"
    HOST_VULNERABLE = "host_vulnerable"
    HOST_COMPROMISED = "host_compromised"


class TestHost(unittest.TestCase):

    def test_update_compromission_attributes(self):
        host = Host("10.0.0.1")
        self.assertEqual(len(host._compromission_attributes), 0)
        host.update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.assertIn(TestHostCompromissionAttributeImplementation.HOST_DISCOVERED,
                      host._compromission_attributes)


class TestAttackType(unittest.TestCase):

    def setUp(self):
        self.attack_type = AttackType("nmap_port_scan", set(), set(
            [TestHostCompromissionAttributeImplementation.HOST_DISCOVERED]))

    def test_eq(self):
        self.assertNotEqual(self.attack_type, AttackType(
            "nmap_port_scan", set(), set()))
        self.assertNotEqual(self.attack_type, AttackType(
            "host_scan", set(), set([TestHostCompromissionAttributeImplementation.HOST_DISCOVERED])))
        self.assertEqual(self.attack_type, AttackType("nmap_port_scan", set(), set(
            [TestHostCompromissionAttributeImplementation.HOST_DISCOVERED])))

    def test_str(self):
        self.assertEqual(str(self.attack_type), "nmap_port_scan")

    def test_get_preconditions(self):
        src_cond, dst_cond = self.attack_type.get_preconditions()
        self.assertEqual(len(src_cond), 0)
        self.assertEqual(len(dst_cond), 0)
        new_attack = AttackType("nmap_port_scan", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True), Preconditions({TestHostCompromissionAttributeImplementation.PORT_SCANNED}, False)}, set(
            [TestHostCompromissionAttributeImplementation.HOST_DISCOVERED]))
        src_cond, dst_cond = new_attack.get_preconditions()
        self.assertEqual(len(src_cond), 1)
        self.assertIn(Preconditions(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True), src_cond)
        self.assertEqual(len(dst_cond), 1)
        self.assertIn(Preconditions(
            {TestHostCompromissionAttributeImplementation.PORT_SCANNED}, False), dst_cond)


class TestExploit(unittest.TestCase):

    def setUp(self):
        self.exploit = Exploit(AttackType("unknown", set(), set()), "10.0.0.1", "50", "10.0.0.2",
                               "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5, 0.5)

    def test_exploit_id(self):
        self.assertEqual(self.exploit.get_exploit_id(),
                         "unknown-10.0.0.2-5000-10.0.0.1-50-6")

    def test_str(self):
        self.assertEqual(str(self.exploit), "Exploit(attack_type=unknown, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5)")

    def test_merge_errors(self):
        new_exploit = Exploit(AttackType("other", set(), set(
        )), "10.0.0.1", "500", "10.0.0.2", "5000", "6", datetime(2026, 6, 6, 18, 30), datetime(2026, 6, 6, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "501", "10.0.0.2", "5000", "6", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.0", "50", "10.0.0.2", "5000", "6", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "50", "10.0.0.3", "5000", "6", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "50", "10.0.0.2", "105", "6", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "50", "10.0.0.2", "5000", "17", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError):
            self.exploit.merge(new_exploit)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "50", "10.0.0.2", "5000", "6", datetime(2026, 6, 8, 18, 30, 10), datetime(2026, 6, 8, 19), 0.5, 1)
        with self.assertRaises(ValueError, msg="exploit flows overlap in time\tobj1 2026-06-08T18:30:00 - 2026-06-08T19:00:00\tobj2 2026-06-08T18:30:10 - 2026-06-08T19:00:10"):
            self.exploit.merge(new_exploit)

    def test_merge(self):
        new_exploit = Exploit(AttackType("unknown", set(), set()), "10.0.0.1", "50", "10.0.0.2",
                              "5000", "6", datetime(2026, 6, 8, 17), datetime(2026, 6, 8, 18), 1, 1)
        merged_exploit = self.exploit.merge(new_exploit)
        self.assertEqual(merged_exploit.attack_type, self.exploit.attack_type)
        self.assertEqual(merged_exploit.source_ip, self.exploit.source_ip)
        self.assertEqual(merged_exploit.source_port, self.exploit.source_port)
        self.assertEqual(merged_exploit.destination_ip,
                         self.exploit.destination_ip)
        self.assertEqual(merged_exploit.destination_port,
                         self.exploit.destination_port)
        self.assertEqual(merged_exploit.protocol, self.exploit.protocol)
        self.assertEqual(merged_exploit.start_time, new_exploit.start_time)
        self.assertEqual(merged_exploit.end_time, self.exploit.end_time)
        self.assertEqual(merged_exploit.density, 0.625)
        self.assertEqual(merged_exploit.anomaly_score, 0.75)
        self.assertEqual(merged_exploit.cardinality, 2)
        new_exploit = Exploit(AttackType("unknown", set(), set(
        )), "10.0.0.1", "50", "10.0.0.2", "5000", "6", datetime(2026, 6, 8, 19), datetime(2026, 6, 8, 21), 1, 1)
        merged_exploit = self.exploit.merge(new_exploit)
        self.assertEqual(merged_exploit.start_time, self.exploit.start_time)
        self.assertEqual(merged_exploit.end_time, new_exploit.end_time)


class TestExploitRequirements(unittest.TestCase):

    def setUp(self) -> None:
        self.attack1 = AttackType("host_discovery", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                  TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_DISCOVERED}, False), Preconditions(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True)}, {TestHostCompromissionAttributeImplementation.PORT_SCANNED})
        self.requirement1 = ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30))

    def test_eq(self):
        self.assertEqual(self.requirement1, ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack2, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack1, ["10.0.0.3"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.3", datetime.min, datetime(
            2026, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime(2025, 12, 1), datetime(
            2026, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2027, 6, 10, 10, 30)))
        self.assertNotEqual(self.requirement1,  ExploitRequirement(self.attack2, ["10.0.0.30"], "10.0.0.0", datetime(2000, 12, 6), datetime(
            2026, 6, 28, 10, 30)))
        new_requirement = ExploitRequirement(self.attack1, [
                                             "10.0.0.0", "10.0.0.3"], "10.0.0.1", datetime.min, datetime(2026, 6, 10, 10, 30))
        self.assertEqual(new_requirement, ExploitRequirement(self.attack1, [
                         "10.0.0.0", "10.0.0.3"], "10.0.0.1", datetime.min, datetime(2026, 6, 10, 10, 30)))
        self.assertEqual(new_requirement, ExploitRequirement(self.attack1, [
                         "10.0.0.3", "10.0.0.0"], "10.0.0.1", datetime.min, datetime(2026, 6, 10, 10, 30)))
        self.assertNotEqual(new_requirement, ExploitRequirement(self.attack1, [
                            "10.0.0.3", "10.0.0.0", "10.0.0.255"], "10.0.0.1", datetime.min, datetime(2026, 6, 10, 10, 30)))

    def test_hash(self):
        self.assertEqual(hash(self.requirement1), hash(hash(self.attack1)+hash("10.0.0.5")+hash("10.0.0.1")+hash(datetime.min)+hash(datetime(
            2026, 6, 10, 10, 30))))


class TestStarNetworkAttackGraphBasedScenarioReconstructor(unittest.TestCase):

    def setUp(self):
        self.host1 = Host("10.0.0.1")
        self.host2 = Host("10.0.0.2")
        self.attack1 = AttackType("host_discovery", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                  TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_DISCOVERED}, False), Preconditions(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True)}, {TestHostCompromissionAttributeImplementation.PORT_SCANNED})
        self.attack3 = AttackType("brute_force", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True), Preconditions({TestHostCompromissionAttributeImplementation.PORT_SCANNED}, False)}, {
                                  TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})
        self.attack4 = AttackType("vulnerability_exploit", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True), Preconditions(
            {TestHostCompromissionAttributeImplementation.PORT_SCANNED}, False), Preconditions({TestHostCompromissionAttributeImplementation.HOST_VULNERABLE}, False)}, {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor = StarNetworkAttackGraphBasedScenarioReconstructor(
            [self.host1, self.host2], ["10.0.0.5"], TestHostCompromissionAttributeImplementation, [self.attack1, self.attack2, self.attack3, self.attack4], "./exploits.log", "./states.log")

    def tearDown(self):
        if os.path.exists("./exploits.log"):
            os.remove("./exploits.log")
        if os.path.exists("./states.log"):
            os.remove("./states.log")

    def test_check_preconditions(self):
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertTrue(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = Exploit(self.attack1, "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertFalse(
            self.scenario_reconstructor.check_preconditions(exploit))
        exploit = Exploit(self.attack1, "10.0.0.111", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        with self.assertRaises(ValueError):
            self.scenario_reconstructor.check_preconditions(exploit)

    def test_set_postconditions(self):
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.scenario_reconstructor.set_postconditions(exploit)
        self.assertEqual(self.scenario_reconstructor.host_dict["10.0.0.1"].get_compromission_attributes(
        ), exploit.attack_type.postconditions)

    def test_add_exploit(self):
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.scenario_reconstructor.add_exploit(exploit)
        self.assertIn("host_discovery-10.0.0.1-40-10.0.0.5-50000-6",
                      self.scenario_reconstructor.exploits_dict)
        self.assertEqual(
            self.scenario_reconstructor.exploits_dict["host_discovery-10.0.0.1-40-10.0.0.5-50000-6"][-1], exploit)

    def test_get_expoit_dict_size(self):
        self.assertEqual(
            self.scenario_reconstructor.get_exploit_dict_size(), 0)
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.scenario_reconstructor.add_exploit(exploit)
        self.assertEqual(
            self.scenario_reconstructor.get_exploit_dict_size(), 1)
        exploit2 = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9, 1)
        self.scenario_reconstructor.add_exploit(exploit2)
        self.assertEqual(
            self.scenario_reconstructor.get_exploit_dict_size(), 2)
        exploit3 = Exploit(self.attack1, "10.0.0.5", "50001", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9, 1)
        self.scenario_reconstructor.add_exploit(exploit3)
        self.assertEqual(
            self.scenario_reconstructor.get_exploit_dict_size(), 3)

    def test_merge_exploits(self):
        exploit1 = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        exploit2 = Exploit(self.attack2, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9, 1)
        exploit3 = Exploit(self.attack1, "10.0.0.5", "50001", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 10, 30), datetime(2026, 6, 11, 10, 35), 0.9, 1)
        exploit4 = Exploit(self.attack1, "10.0.0.5", "50001", "10.0.0.1", "40", "6", datetime(
            2026, 6, 11, 12, 30), datetime(2026, 6, 11, 13, 35), 0.6, 1)
        self.scenario_reconstructor.exploits_dict[exploit1.get_exploit_id()] = [
            exploit1]
        self.scenario_reconstructor.exploits_dict[exploit2.get_exploit_id()] = [
            exploit2]
        self.scenario_reconstructor.exploits_dict[exploit3.get_exploit_id()] = [
            exploit3, exploit4]
        self.scenario_reconstructor.persist_exploits()
        exploit_strs = [str(exploit1), str(exploit2),
                        str(exploit3), str(exploit4)]
        with open("./exploits.log", "r") as f:
            for line in f.readlines():
                self.assertIn(line.strip(), exploit_strs)
        for exploits in self.scenario_reconstructor.exploits_dict.values():
            self.assertEqual(len(exploits), 0)
        self.assertIn(exploit1.get_exploit_id(),
                      self.scenario_reconstructor.aggregated_exploits)
        self.assertIn(exploit2.get_exploit_id(),
                      self.scenario_reconstructor.aggregated_exploits)
        self.assertIn(exploit3.get_exploit_id(),
                      self.scenario_reconstructor.aggregated_exploits)
        self.assertIn(exploit4.get_exploit_id(),
                      self.scenario_reconstructor.aggregated_exploits)

    def test_check_exploit_requirements_invalid_ips(self):
        exploit1 = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.23", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        with self.assertRaises(ValueError, msg="Precondition defined on unknown hosts: 10.0.0.5 10.0.0.23"):
            self.scenario_reconstructor.check_preconditions(exploit1)
        exploit2 = Exploit(self.attack1, "10.0.0.51", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        with self.assertRaises(ValueError, msg="Precondition defined on unknown hosts: 10.0.0.51 10.0.0.2"):
            self.scenario_reconstructor.check_preconditions(exploit2)

    def test_compute_requirements_edge_cases(self):
        exploit1 = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertEqual(
            self.scenario_reconstructor.compute_requirements(exploit1), set())
        exploit2 = Exploit(self.attack1, "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit2))
        exploit3 = Exploit(self.attack2, "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit3))
        exploit4 = Exploit(self.attack2, "10.0.0.1", "50000", "10.0.0.2", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.assertIsNone(
            self.scenario_reconstructor.compute_requirements(exploit4))

    def test_compute_requirements_single(self):
        exploit1 = Exploit(self.attack2, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)))
        exploit2 = Exploit(self.attack1, "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.scenario_reconstructor.host_dict["10.0.0.2"]._compromission_attributes.add(
            TestHostCompromissionAttributeImplementation.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(self.attack3, ["10.0.0.5"], "10.0.0.2", datetime.min, datetime(
            2026, 6, 10, 10, 30)))

    def test_compute_requirements_multiple_blue_hosts(self):
        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.3"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})

        exploit1 = Exploit(self.attack2, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(ExploitRequirement(self.attack1, ["10.0.0.5", "10.0.0.3"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)
        exploit2 = Exploit(self.attack1, "10.0.0.2", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        self.scenario_reconstructor.host_dict["10.0.0.2"]._compromission_attributes.add(
            TestHostCompromissionAttributeImplementation.PORT_SCANNED)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        self.assertIn(ExploitRequirement(self.attack3, ["10.0.0.5", "10.0.0.3"], "10.0.0.2", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)

    def test_compute_requirements_multiple_green_attacks(self):
        new_attack = AttackType("metasploit_port_scan", {Preconditions({TestHostCompromissionAttributeImplementation.HOST_COMPROMISED}, True)}, {
                                TestHostCompromissionAttributeImplementation.HOST_DISCOVERED, TestHostCompromissionAttributeImplementation.PORT_SCANNED})
        self.scenario_reconstructor.attack_types.append(new_attack)

        exploit1 = Exploit(self.attack2, "10.0.0.5", "50000", "10.0.0.1", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit1)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(ExploitRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)
        self.assertIn(ExploitRequirement(new_attack, ["10.0.0.5"], "10.0.0.1", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)

        exploit2 = Exploit(self.attack1, "10.0.0.2", "50000", "10.0.0.3", "40", "6", datetime(
            2026, 6, 10, 10, 30), datetime(2026, 6, 10, 10, 35), 0.8, 1)

        self.scenario_reconstructor.host_dict["10.0.0.3"] = Host("10.0.0.3")
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.PORT_SCANNED, TestHostCompromissionAttributeImplementation.HOST_VULNERABLE})

        requirements = self.scenario_reconstructor.compute_requirements(
            exploit2)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 2)
        self.assertIn(ExploitRequirement(self.attack3, ["10.0.0.5", "10.0.0.1"], "10.0.0.2", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)
        self.assertIn(ExploitRequirement(self.attack4, ["10.0.0.5", "10.0.0.1"], "10.0.0.2", datetime.min, datetime(
            2026, 6, 10, 10, 30)), requirements)

    def test_compute_requirements_destination_time(self):
        exploit = Exploit(self.attack3, "10.0.0.1", "50000", "10.0.0.2", "50", "6", datetime(
            2026, 6, 1, 12), datetime(2026, 6, 1, 13, 30), 0.8, 1)
        old_exploit = Exploit(self.attack1, "10.0.0.5", "5000", "10.0.0.2", "50", "6", datetime(
            2026, 6, 1, 6, 30), datetime(2026, 6, 1, 7), 0.7, 1)
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.exploits_dict[old_exploit.get_exploit_id(
        )] = [old_exploit]
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(self.attack2, [
                         "10.0.0.1", "10.0.0.5"], "10.0.0.2", datetime(2026, 6, 1, 7), datetime(2026, 6, 1, 12)))

    def test_compute_requirements_source_time(self):
        exploit = Exploit(self.attack2, "10.0.0.1", "50000", "10.0.0.2", "50", "6", datetime(
            2026, 6, 1, 12), datetime(2026, 6, 1, 13, 30), 0.8, 1)
        old_exploit = Exploit(self.attack2, "10.0.0.5", "5000", "10.0.0.1", "50", "6", datetime(
            2026, 6, 1, 6, 30), datetime(2026, 6, 1, 7), 0.7, 1)
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.PORT_SCANNED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.exploits_dict[old_exploit.get_exploit_id(
        )] = [old_exploit]
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(self.attack3, [
                         "10.0.0.5"], "10.0.0.1", datetime(2026, 6, 1, 7), datetime(2026, 6, 1, 12)))

    def test_compute_requirements_multiple_sources_time(self):
        exploit = Exploit(self.attack2, "10.0.0.1", "50000", "10.0.0.2", "50", "6", datetime(
            2026, 6, 1, 12), datetime(2026, 6, 1, 13, 30), 0.8, 1)
        old_exploit1 = Exploit(self.attack2, "10.0.0.5", "5000", "10.0.0.1", "50", "6", datetime(
            2026, 6, 1, 6, 30), datetime(2026, 6, 1, 7), 0.7, 1)
        old_exploit2 = Exploit(self.attack2, "10.0.0.3", "5000", "10.0.0.1", "50", "6", datetime(
            2026, 6, 1, 6, 30), datetime(2026, 6, 1, 6, 40), 0.7, 1)
        new_host = Host("10.0.0.3")
        new_host.update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_COMPROMISED})
        self.scenario_reconstructor.host_dict["10.0.0.3"] = new_host
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.PORT_SCANNED})
        self.scenario_reconstructor.host_dict["10.0.0.2"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.exploits_dict[old_exploit1.get_exploit_id(
        )] = [old_exploit1]
        self.scenario_reconstructor.exploits_dict[old_exploit2.get_exploit_id()] = [
            old_exploit2]
        requirements = self.scenario_reconstructor.compute_requirements(
            exploit)
        self.assertIsNotNone(requirements)
        assert requirements is not None
        self.assertEqual(len(requirements), 1)
        req = requirements.pop()
        self.assertEqual(req, ExploitRequirement(self.attack3, [
                         "10.0.0.5", "10.0.0.3"], "10.0.0.1", datetime(2026, 6, 1, 6, 40), datetime(2026, 6, 1, 12)))

    def test_register_network_state(self):
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "50", "6", datetime(
            2026, 6, 1, 12), datetime(2026, 6, 1, 13, 30), 0.8, 1)
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.register_network_state(exploit)
        self.assertEqual(len(self.scenario_reconstructor.exploit_sequence), 1)
        self.assertEqual(
            self.scenario_reconstructor.exploit_sequence[0], exploit)
        self.assertEqual(
            len(self.scenario_reconstructor.state_sequence), 2)
        self.assertEqual(self.scenario_reconstructor.state_sequence[1]["10.0.0.1"], {
                         TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.assertEqual(
            self.scenario_reconstructor.state_sequence[1]["10.0.0.2"], set())

    def test_persist_history(self):
        exploit = Exploit(self.attack1, "10.0.0.5", "50000", "10.0.0.1", "50", "6", datetime(
            2026, 6, 1, 12), datetime(2026, 6, 1, 13, 30), 0.8, 1)
        self.scenario_reconstructor.host_dict["10.0.0.1"].update_compromission_attributes(
            {TestHostCompromissionAttributeImplementation.HOST_DISCOVERED})
        self.scenario_reconstructor.register_network_state(exploit)
        self.scenario_reconstructor.persist_history()
        self.assertEqual(len(self.scenario_reconstructor.state_sequence),0)
        self.assertEqual(len(self.scenario_reconstructor.exploit_sequence),0)
        with open("./states.log", "r") as f:
            lines=f.readlines()
            self.assertEqual(len(lines),3)
            self.assertIn("State(10.0.0.1={}-10.0.0.2={})\n", lines)
            self.assertIn("Exploit(attack_type=host_discovery, source_ip=10.0.0.5, source_port=50000, destination_ip=10.0.0.1, destination_port=50, protocol=6, start_time=2026-06-01T12:00:00, end_time=2026-06-01T13:30:00, anomaly_score=0.8)\n", lines)
            self.assertIn("State(10.0.0.1={host_discovered}-10.0.0.2={})\n", lines)

if __name__ == '__main__':
    unittest.main()
