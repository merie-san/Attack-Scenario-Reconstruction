from datetime import datetime

from scenario_reconstructor.models import AttackStep, AttackType, FlowAlert, NetworkState
from scenario_reconstructor.serialization import AlertStepParser, NetworkStateParser
from tests.fixtures import NetworkAttribute
from tests.support import ProjectTestCase


class TestNetworkStateParser(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.converter = NetworkStateParser(
            NetworkAttribute)

    def test_from_str_empty_state(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={}, time=2026-10-10T10:00:00)"),
                         NetworkState({}, datetime(2026, 10, 10, 10)))

    def test_from_str_single(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={10.0.0.5={host_discovered}}, time=2026-10-10T10:00:00)"), NetworkState(
            {"10.0.0.5": {NetworkAttribute.HOST_DISCOVERED}}, datetime(2026, 10, 10, 10)))

    def test_from_str_multiple(self):
        self.assertEqual(self.converter.from_str("NetworkState(state={10.0.0.5={host_discovered; port_scanned}-10.0.0.6={host_discovered; port_scanned}}, time=2026-10-10T10:00:00)"), NetworkState({"10.0.0.5": {NetworkAttribute.HOST_DISCOVERED,
                         NetworkAttribute.PORT_SCANNED}, "10.0.0.6": {NetworkAttribute.HOST_DISCOVERED, NetworkAttribute.PORT_SCANNED}}, datetime(2026, 10, 10, 10)))


class TestAlertStepParser(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.converter = AlertStepParser(
            [AttackType("attack_1", set(), set()), AttackType("attack_2", set(), set())])

    def test_str_to_flow_exploit(self):
        self.assertEqual(self.converter.from_str_flow_exploit("FlowExploit(attack_type=attack_1, source_ip=10.0.0.1, source_port=50, destination_ip=10.0.0.2, destination_port=5000, protocol=6, start_time=2026-06-08T18:30:00, end_time=2026-06-08T19:00:00, anomaly_score=0.5)"), FlowAlert(AttackType("attack_1", set(), set()), [], "10.0.0.1", "50", "10.0.0.2",
                                                                                                                                                                                                                                                                                                 "5000", "6", datetime(2026, 6, 8, 18, 30), datetime(2026, 6, 8, 19), 0.5))

    def test_str_to_exploit(self):
        self.assertEqual(self.converter.from_str_exploit("Exploit(attack_type=attack_1, size=2, source_ip=109.0.0.2, destination_ip=108.8.09.9, start_time=2026-11-12T10:00:00, end_time=2026-11-12T10:30:00, mean_ift=2, std_ift=3)"), AttackStep(AttackType("attack_1", set(), set()), 2, "109.0.0.2", "108.8.09.9", datetime(
            2026, 11, 12, 10), datetime(2026, 11, 12, 10, 30), 2, 3))
