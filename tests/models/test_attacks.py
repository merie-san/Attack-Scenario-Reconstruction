from scenario_reconstructor.models import AttackType, Precondition, RecoveryRequirement
from tests.fixtures import NetworkAttribute
from tests.support import ProjectTestCase


class TestAttackType(ProjectTestCase):

    def setUp(self):
        super().setUp()
        self.attack_type = AttackType("nmap_port_scan", set(),
                                      {NetworkAttribute.HOST_DISCOVERED})

    def test_eq(self):
        self.assertNotEqual(self.attack_type, AttackType(
            "nmap_port_scan", set(), set()))
        self.assertNotEqual(self.attack_type, AttackType(
            "host_scan", set(), {NetworkAttribute.HOST_DISCOVERED}))
        self.assertEqual(self.attack_type, AttackType("nmap_port_scan", set(),
                                                      {NetworkAttribute.HOST_DISCOVERED}))

    def test_str(self):
        self.assertEqual(str(self.attack_type), "nmap_port_scan")

    def test_get_preconditions(self):
        src_cond, dst_cond = self.attack_type.get_preconditions()
        self.assertEqual(len(src_cond), 0)
        self.assertEqual(len(dst_cond), 0)
        new_attack = AttackType("nmap_port_scan", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True), Precondition({NetworkAttribute.PORT_SCANNED}, False)},
                                {NetworkAttribute.HOST_DISCOVERED})
        src_cond, dst_cond = new_attack.get_preconditions()
        self.assertEqual(len(src_cond), 1)
        self.assertIn(Precondition(
            {NetworkAttribute.HOST_COMPROMISED}, True), src_cond)
        self.assertEqual(len(dst_cond), 1)
        self.assertIn(Precondition(
            {NetworkAttribute.PORT_SCANNED}, False), dst_cond)


class TestRecoveryRequirement(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.attack1 = AttackType("host_discovery", {Precondition({NetworkAttribute.HOST_COMPROMISED}, True)}, {
                                  NetworkAttribute.HOST_DISCOVERED})
        self.attack2 = AttackType("port_scanning", {Precondition({NetworkAttribute.HOST_DISCOVERED}, False), Precondition(
            {NetworkAttribute.HOST_COMPROMISED}, True)}, {NetworkAttribute.PORT_SCANNED})
        self.requirement1 = RecoveryRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1")

    def test_eq(self):
        self.assertEqual(self.requirement1, RecoveryRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  RecoveryRequirement(
            self.attack2, ["10.0.0.5"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  RecoveryRequirement(
            self.attack1, ["10.0.0.3"], "10.0.0.1"))
        self.assertNotEqual(self.requirement1,  RecoveryRequirement(
            self.attack1, ["10.0.0.5"], "10.0.0.3"))
        self.assertNotEqual(self.requirement1,  RecoveryRequirement(
            self.attack2, ["10.0.0.30"], "10.0.0.0"))
        new_requirement = RecoveryRequirement(self.attack1, [
                                             "10.0.0.0", "10.0.0.3"], "10.0.0.1")
        self.assertEqual(new_requirement, RecoveryRequirement(self.attack1, [
                         "10.0.0.0", "10.0.0.3"], "10.0.0.1"))
        self.assertEqual(new_requirement, RecoveryRequirement(self.attack1, [
                         "10.0.0.3", "10.0.0.0"], "10.0.0.1"))
        self.assertNotEqual(new_requirement, RecoveryRequirement(self.attack1, [
                            "10.0.0.3", "10.0.0.0", "10.0.0.255"], "10.0.0.1"))

    def test_hash(self):
        equivalent = RecoveryRequirement(self.attack1, ["10.0.0.5"], "10.0.0.1")
        self.assertEqual(self.requirement1, equivalent)
        self.assertEqual(hash(self.requirement1), hash(equivalent))
        self.assertIn(equivalent, {self.requirement1})
