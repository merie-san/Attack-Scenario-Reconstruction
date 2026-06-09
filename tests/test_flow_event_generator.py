import unittest
from event_generator.flow_event_generator import FlowEventGenerator
from event_generator.flow_event import FlowEvent
from datetime import datetime
import pandas as pd
import os

class TestFlowEventGeneratorLogEvents(unittest.TestCase):

    def test_log_events_default_cols(self):
        generator = FlowEventGenerator()

        final_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="80",
            protocol="6",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.5,
            attack_scores={"Port Scan": 0.5, "Brute Force": 0.5}
        )

        test_df = pd.DataFrame(
            {
                "col1": [0],
                "col2": [1],
                "Flow ID": ["12345"],
                "Source IP": ["192.168.1.1"],
                "Source Port": [8080],
                "Destination IP": ["10.0.0.1"],
                "Destination Port": [80],
                "Protocol": [6],
                "Anomaly Score": [0.5],
                "Port Scan":[0.5],
                "Brute Force": [0.5],
                "Timestamp": [datetime(2023, 1, 1, 12, 0, 0)],
            }
        )

        generator.log_events(test_df, "./test.log", attack_score_cols=["Port Scan", "Brute Force"])
        with open("./test.log", "r") as f:
            lines = f.readlines()
        self.assertEqual(lines[0].strip(), str(final_event))

    def test_log_events_custom_cols(self):
        generator = FlowEventGenerator()

        test_df = pd.DataFrame(
            {
                "col1": [0],
                "col2": [1],
                "flow_id": ["12345"],
                "source_ip": ["192.168.1.1"],
                "source_port": [8080],
                "destination_ip": ["10.0.0.1"],
                "destination_port": [80],
                "protocol": [6],
                "timestamp": [datetime(2023, 1, 1, 12, 0, 0)],
                "anomaly_score": [0.5],
            }
        )

        generator.log_events(
            test_df,
            "./test.log",
            flow_id_col="flow_id",
            source_ip_col="source_ip",
            source_port_col="source_port",
            destination_ip_col="destination_ip",
            destination_port_col="destination_port",
            protocol_col="protocol",
            timestamp_col="timestamp",
            anomaly_score_col="anomaly_score",
        )
        final_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="80",
            protocol="6",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=0.5,
            attack_scores={}
        )
        with open("./test.log", "r") as f:
            lines = f.readlines()
        self.assertEqual(lines[0].strip(), str(final_event))

    def tearDown(self):
        if os.path.exists("./test.log"):
            os.remove("./test.log")


if __name__ == "__main__":
    unittest.main()
