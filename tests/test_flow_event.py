import unittest
from event_generator.flow_event import FlowEvent
from datetime import datetime

class TestFlowEventStringFunctions(unittest.TestCase):

    def test_flow_event_to_string_no_other_attributes(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="TCP",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.8
        )
        self.assertEqual(str(flow_event), "[flow_id=12345, source_ip=192.168.1.1, source_port=8080, destination_ip=10.0.0.1, destination_port=443, protocol=TCP, timestamp=2023-01-01 12:00:00, anomaly_score=0.8]")
    
    def test_flow_event_to_string_with_other_attributes(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="TCP",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.8,
            attack_scores={"A": 1, "B": 2}
        )
        self.assertEqual(str(flow_event), "[flow_id=12345, source_ip=192.168.1.1, source_port=8080, destination_ip=10.0.0.1, destination_port=443, protocol=TCP, timestamp=2023-01-01 12:00:00, anomaly_score=0.8, A=1, B=2]")

    def test_string_to_flow_event_no_other_attributes(self):
        string = "[flow_id=12345, source_ip=192.168.1.1, source_port=8080, destination_ip=10.0.0.1, destination_port=443, protocol=TCP, timestamp=2023-01-01 12:00:00, anomaly_score=0.8]"
        flow_event = FlowEvent.from_str(string)
        self.assertEqual(flow_event.flow_id, "12345")
        self.assertEqual(flow_event.source_ip, "192.168.1.1")
        self.assertEqual(flow_event.source_port, 8080)
        self.assertEqual(flow_event.destination_ip, "10.0.0.1")
        self.assertEqual(flow_event.destination_port, 443)
        self.assertEqual(flow_event.protocol, "TCP")
        self.assertEqual(flow_event.timestamp, datetime(2023, 1, 1, 12, 0, 0))
        self.assertEqual(flow_event.anomaly_score, 0.8)
        self.assertEqual(flow_event.attack_scores, {})

    def test_string_to_flow_event_with_other_attributes(self):
        string = "[flow_id=12345, source_ip=192.168.1.1, source_port=8080, destination_ip=10.0.0.1, destination_port=443, protocol=TCP, timestamp=2023-01-01 12:00:00, anomaly_score=0.8, A=1, B=2]"
        flow_event = FlowEvent.from_str(string)
        self.assertEqual(flow_event.flow_id, "12345")
        self.assertEqual(flow_event.source_ip, "192.168.1.1")
        self.assertEqual(flow_event.source_port, 8080)
        self.assertEqual(flow_event.destination_ip, "10.0.0.1")
        self.assertEqual(flow_event.destination_port, 443)
        self.assertEqual(flow_event.protocol, "TCP")
        self.assertEqual(flow_event.timestamp, datetime(2023, 1, 1, 12, 0, 0))
        self.assertEqual(flow_event.anomaly_score, 0.8)
        self.assertEqual(flow_event.attack_scores, {"A": "1", "B": "2"})

class TestFlowEventDictFunctions(unittest.TestCase):

    def test_flow_event_to_dict_with_other_attributes(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="TCP",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.8,
            attack_scores={"A": 1, "B": 2}
        )
        self.assertEqual(flow_event.to_dict(), {
            "flow_id": "12345",
            "source_ip": "192.168.1.1",
            "source_port": 8080,
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": datetime(2023, 1, 1, 12, 0, 0),
            "anomaly_score": 0.8,
            "A": 1,
            "B": 2
        })
    
    def test_flow_event_to_dict_no_other_attributes(self):
        flow_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="443",
            protocol="TCP",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.8,
        )
        self.assertEqual(flow_event.to_dict(), {
            "flow_id": "12345",
            "source_ip": "192.168.1.1",
            "source_port": 8080,
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": datetime(2023, 1, 1, 12, 0, 0),
            "anomaly_score": 0.8,
        })
    
    def test_dict_to_flow_event_no_other_attributes(self):
        data = {
            "flow_id": "12345",
            "source_ip": "192.168.1.1",
            "source_port": 8080,
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": datetime(2023, 1, 1, 12, 0, 0),
            "anomaly_score": 0.8
        }
        flow_event = FlowEvent.from_dict(data)
        self.assertEqual(flow_event.flow_id, "12345")
        self.assertEqual(flow_event.source_ip, "192.168.1.1")
        self.assertEqual(flow_event.source_port, 8080)
        self.assertEqual(flow_event.destination_ip, "10.0.0.1")
        self.assertEqual(flow_event.destination_port, 443)
        self.assertEqual(flow_event.protocol, "TCP")
        self.assertEqual(flow_event.timestamp, datetime(2023, 1, 1, 12, 0, 0))
        self.assertEqual(flow_event.anomaly_score, 0.8)
        self.assertEqual(flow_event.attack_scores, {})
        
    def test_dict_to_flow_event_with_other_attributes(self):
        data = {
            "flow_id": "12345",
            "source_ip": "192.168.1.1",
            "source_port": 8080,
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "timestamp": datetime(2023, 1, 1, 12, 0, 0),
            "anomaly_score": 0.8,
            "A": 1,
            "B": 2
        }
        flow_event = FlowEvent.from_dict(data)
        self.assertEqual(flow_event.flow_id, "12345")
        self.assertEqual(flow_event.source_ip, "192.168.1.1")
        self.assertEqual(flow_event.source_port, 8080)
        self.assertEqual(flow_event.destination_ip, "10.0.0.1")
        self.assertEqual(flow_event.destination_port, 443)
        self.assertEqual(flow_event.protocol, "TCP")
        self.assertEqual(flow_event.timestamp, datetime(2023, 1, 1, 12, 0, 0))
        self.assertEqual(flow_event.anomaly_score, 0.8)
        self.assertEqual(flow_event.attack_scores, {"A": 1, "B": 2})

if __name__ == '__main__':
    unittest.main()