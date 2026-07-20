import unittest
from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.scenario_reconstructor import AttackType
from datetime import datetime

class TestMapper(unittest.TestCase):

    def setUp(self) -> None:
        self.attack1 = AttackType("attack_1", set(), set())
        self.attack2 = AttackType("attack_2", set(), set())
        self.mapper = AttackMapper([self.attack1, self.attack2], 0.1)

    def test_map_nonexisting_attack(self):
        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8,
                               attack_scores={"attack_3": 0.4, "attack_4": 0.4})
        with self.assertRaises(RuntimeError, msg="Found attack not defined in provided types"):
            self.mapper.map(flow_event)

    def test_map_different_attacks_lenghts(self):
        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8, attack_scores={"attack_1": 0.4})
        with self.assertRaises(RuntimeError, msg="provided flow event does not define the same number of attacks"):
            self.mapper.map(flow_event)

        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8,
                               attack_scores={"attack_1": 0.4, "attack_2": 0.4, "attack_3": 0.4})
        with self.assertRaises(RuntimeError, msg="provided flow event does not define the same number of attacks"):
            self.mapper.map(flow_event)

    def test_map_attacks(self):
        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8,
                               attack_scores={"attack_1": 0.02, "attack_2": 0.01})
        self.assertEqual(len(self.mapper.map(flow_event)[1]),0)
        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8,
                               attack_scores={"attack_1": 0.11, "attack_2": 0.01})
        self.assertEqual(self.mapper.map(flow_event)[0], self.attack1)
        flow_event = FlowEvent(source_ip="192.168.1.1", source_port="8080", destination_ip="10.0.0.1",
                               destination_port="443", protocol="6", start_time=datetime(2023, 1, 1, 12),
                               end_time=datetime(2023, 1, 2, 2), anomaly_score=0.8,
                               attack_scores={"attack_1": 0.11, "attack_2": 0.3})
        self.assertEqual(self.mapper.map(flow_event)[0], self.attack2)


if __name__ == '__main__':
    unittest.main()
