import unittest
from scenario_reconstructor.scenario_reconstructor import Host, StarNetworkAttackGraphBasedScenarioReconstructor, HostCompromissionAttribute, AttackType, Exploit
from datetime import datetime


class TestHost(unittest.TestCase):

    def test_update_compromission_attributes(self):
        host = Host("10.0.0.1")
        self.assertEqual(len(host._compromission_attributes), 0)
        host.update_compromission_attributes(
            {HostCompromissionAttribute.ENTRY_POINT_SELECTED})
        self.assertIn(HostCompromissionAttribute.ENTRY_POINT_SELECTED,
                      host._compromission_attributes)


class TestAttackType(unittest.TestCase):

    def setUp(self):
        self.attack_type = AttackType("nmap_port_scan", set([]), set(
            [HostCompromissionAttribute.ENTRY_POINT_SELECTED]))

    def test_eq(self):
        self.assertEqual(self.attack_type, AttackType(
            "nmap_port_scan", set(), set()))
        self.assertNotEqual(self.attack_type, AttackType(
            "host_scan", set(), set([HostCompromissionAttribute.ENTRY_POINT_SELECTED])))

    def test_str(self):
        self.assertEqual(str(self.attack_type), "nmap_port_scan")

    def test_hash(self):
        self.assertEqual(self.attack_type.__hash__(), hash("nmap_port_scan"))


class TestExploit(unittest.TestCase):

    def setUp(self):
        self.exploit = Exploit(AttackType("unknown", set(), set()), "10.0.0.1", "50", "10.0.0.2",
                               "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5, 0.5)

    def test_exploit_id(self):
        self.assertEqual(self.exploit.get_exploit_id(),
                         "unknown-10.0.0.2-5000-10.0.0.1-50-6")

    def test_str(self):
        self.assertEqual(str(self.exploit), "Exploit(attack_type=unknown, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5, density=0.5, cardinality=1)")

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
        with self.assertRaises(ValueError, msg="exploit flows overlap in time\tobj1 2026-06-08T18:30:00 - 2026-06-08T19:00:00 \tobj2 2026-06-08T18:30:10 - 2026-06-08T19:00:10"):
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


if __name__ == '__main__':
    unittest.main()
