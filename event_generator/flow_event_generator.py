import pandas as pd
import pickle
from sklearn.pipeline import Pipeline
from event_generator.flow_event import FlowEvent

class FlowEventGenerator:

    def __init__(
        self, timestamp_template: str | None = None
    ):
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
        anomaly_score_col: str = "Anomaly Score",
        attack_score_cols: list | None = None,
    ):
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
                    anomaly_score=row[anomaly_score_col],
                    timestamp_template=self.timestamp_template,
                    attack_scores={col.strip(): row[col] for col in df.columns if col in attack_score_cols} if attack_score_cols else {},
                )
                f.write(str(flow_event) + "\n")
