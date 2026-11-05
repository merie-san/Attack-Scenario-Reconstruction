from datetime import datetime

from scenario_reconstructor.models import AttackStep, AttackType, FlowAlert
from tests.support import ProjectTestCase


class TestAttackStep(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.exploit = AttackStep(AttackType("attack_1", set(), set()), 2, "109.0.0.2", "108.8.09.9", datetime(
            2026, 11, 12, 10), datetime(2026, 11, 12, 10, 30), 2, 3)

    def test_get_exploit_group_id(self):
        self.assertEqual(self.exploit.get_exploit_group_id(),
                         "attack_1-108.8.09.9-109.0.0.2")

    def test_to_str(self):
        self.assertEqual(str(self.exploit), "Exploit(attack_type=attack_1, size=2, source_ip=109.0.0.2, destination_ip=108.8.09.9, start_time=2026-11-12T10:00:00, end_time=2026-11-12T10:30:00, mean_ift=2, std_ift=3)")


class TestFlowAlert(ProjectTestCase):

    def setUp(self):
        super().setUp()
        self.exploit = FlowAlert(AttackType("unknown", set(), set()), [], "10.0.0.1", "50", "10.0.0.2",
                                   "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5)

    def test_exploit_id(self):
        self.assertEqual(self.exploit.get_flow_exploit_group_id(),
                         "unknown-10.0.0.2-10.0.0.1")

    def test_str(self):
        self.assertEqual(str(self.exploit), "FlowExploit(attack_type=unknown, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5)")
