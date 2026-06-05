import unittest
from event_generator.flow_event_generator import FlowEventGenerator
from event_generator.flow_event import FlowEvent
from datetime import datetime
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
import os
import pickle
import random


class TestFlowEventGeneratorLogEvents(unittest.TestCase):

    def test_log_events_default_cols(self):
        df_training = pd.DataFrame(
            {
                "col1": [0, 1],
                "col2": [1, 0],
                "Flow ID": ["12345", "67890"],
                "Source IP": ["192.168.1.1", "192.168.1.2"],
                "Source Port": [8080, 8081],
                "Destination IP": ["10.0.0.1", "10.0.0.2"],
                "Destination Port": [80, 80],
                "Protocol": [6, 6],
                "Timestamp": [
                    datetime(2023, 1, 1, 12, 0, 0),
                    datetime(2023, 1, 1, 12, 5, 0),
                ],
                "Label": [0, 1],
            }
        )
        y_train, X_train = df_training["Label"], df_training[["col1", "col2"]]
        cls = RandomForestClassifier()
        cls.fit(X_train, y_train)
        pipeline = Pipeline([("cls", cls)])
        generator = FlowEventGenerator(detector=pipeline, label_col="Label")

        final_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="80",
            protocol="6",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=cls.predict_proba([[0, 1]])[0][1],
            other_attributes={"col1": 0, "col2": 1}
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
                "Timestamp": [datetime(2023, 1, 1, 12, 0, 0)],
            }
        )

        generator.log_events(test_df, "./test.log")
        with open("./test.log", "r") as f:
            lines = f.readlines()
        self.assertEqual(lines[0].strip(), str(final_event))

    def test_log_events_custom_cols(self):
        df_training = pd.DataFrame(
            {
                "col1": [0, 1],
                "col2": [1, 0],
                "flow_id": ["12345", "67890"],
                "source_ip": ["192.168.1.1", "192.168.1.2"],
                "source_port": [8080, 8081],
                "destination_ip": ["10.0.0.1", "10.0.0.2"],
                "destination_port": [80, 80],
                "protocol": [6, 6],
                "timestamp": [
                    datetime(2023, 1, 1, 12, 0, 0),
                    datetime(2023, 1, 1, 12, 5, 0),
                ],
                "Type": [0, 1],
            }
        )
        y_train, X_train = df_training["Type"], df_training[["col1", "col2"]]
        cls = RandomForestClassifier()
        cls.fit(X_train, y_train)
        pipeline = Pipeline([("cls", cls)])
        generator = FlowEventGenerator(detector=pipeline, label_col="Type")

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
        )
        final_event = FlowEvent(
            flow_id="12345",
            source_ip="192.168.1.1",
            source_port="8080",
            destination_ip="10.0.0.1",
            destination_port="80",
            protocol="6",
            timestamp="2023-01-01T12:00:00",
            anomaly_score=cls.predict_proba([[0, 1]])[0][1],
            other_attributes={"col1": 0, "col2": 1}
        )
        with open("./test.log", "r") as f:
            lines = f.readlines()
        self.assertEqual(lines[0].strip(), str(final_event))

    def tearDown(self):
        if os.path.exists("./test.log"):
            os.remove("./test.log")


class TestFlowEventGeneratorInit(unittest.TestCase):

    def setUp(self):
        cls = RandomForestClassifier()
        self.pipeline = Pipeline([(str(random.randint(0, 1000000)), cls)])
        with open("./test_detector.pkl", "wb") as f:
            pickle.dump(self.pipeline, f)

    def test_init_with_detector(self):
        generator = FlowEventGenerator(detector=self.pipeline)
        self.assertEqual(generator.detector, self.pipeline)

    def test_init_with_detector_path(self):
        generator = FlowEventGenerator(detector_path="./test_detector.pkl")
        self.assertEqual(generator.detector.steps[0][0], self.pipeline.steps[0][0])

    def test_init_with_invalid_args(self):
        with self.assertRaises(ValueError):
            FlowEventGenerator()
        with self.assertRaises(ValueError):
            FlowEventGenerator(
                detector=self.pipeline, detector_path="./test_detector.pkl"
            )

    def tearDown(self):
        if os.path.exists("./test_detector.pkl"):
            os.remove("./test_detector.pkl")


if __name__ == "__main__":
    unittest.main()
