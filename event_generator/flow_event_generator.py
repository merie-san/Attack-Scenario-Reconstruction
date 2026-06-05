import pandas as pd
import pickle
from sklearn.pipeline import Pipeline
from event_generator.flow_event import FlowEvent

class FlowEventGenerator:

    def __init__(
        self, detector_path: str | None = None, detector: Pipeline | None = None, label_col: str = "label", timestamp_template: str | None = None
    ):
        if (detector_path and detector) or (not detector_path and not detector):
            raise ValueError(
                "Provided arguments are not valid. Please provide either a path to the detector or the detector itself."
            )
        if detector_path:
            with open(detector_path, "rb") as f:
                self.detector = pickle.load(f)
        elif detector:
            self.detector = detector
        self.label_col = label_col.lower()
        self.timestamp_template = timestamp_template
        
    def log_events(
        self,
        df: pd.DataFrame,
        log_path: str,
        flow_id_col: str = "Flow ID",
        source_ip_col: str = "Source IP",
        source_port_col: str = "Source Port",
        destination_ip_col: str = "Destination IP",
        destination_port_col: str = "Destination Port",
        protocol_col: str = "Protocol",
        timestamp_col: str = "Timestamp",
    ):
        ad_df = df[[col for col in df.columns if col in self.detector.feature_names_in_ and col.lower()!= self.label_col]]
        anomaly_scores = self.detector.predict_proba(ad_df)[:, 1]
        with open(log_path, "a") as f:
            for i in range(len(df)):
                row = df.iloc[i]
                flow_event = FlowEvent(
                    flow_id=row[flow_id_col],
                    source_ip=row[source_ip_col],
                    source_port=row[source_port_col],
                    destination_ip=row[destination_ip_col],
                    destination_port=row[destination_port_col],
                    protocol=row[protocol_col],
                    timestamp=row[timestamp_col],
                    anomaly_score=anomaly_scores[i],
                    timestamp_template=self.timestamp_template,
                    other_attributes={col.strip(): row[col] for col in df.columns if col not in {flow_id_col, source_ip_col, source_port_col, destination_ip_col, destination_port_col, protocol_col, timestamp_col}}
                )
                f.write(str(flow_event) + "\n")
