"""Conversion of scored cAPTure dataframe rows into UTC flow events."""
from datetime import timedelta

import pandas as pd

from .models import FlowEvent


CAPTURE_ATTACK_SCORE_COLUMNS = (
    "nmap_10_T5", "nmap_mqtt", "nmap_banner", "brute_force_malformed", "dollar_char", "scp_inst",
)


class CaptureFlowEventConverter:
    """Adapt cAPTure column names to the dataset-independent flow model."""

    @staticmethod
    def convert(dataframe: pd.DataFrame) -> list[FlowEvent]:
        """Create UTC events without changing input; naive timestamps represent UTC."""
        events = dataframe.copy(deep=True)
        events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
        return [
            FlowEvent(
                source_ip=row.src_ip, source_port=row.src_port,
                destination_ip=row.dst_ip, destination_port=row.dst_port,
                protocol=row.protocol, start_time=row.timestamp,
                end_time=row.timestamp + timedelta(milliseconds=row.duration),
                anomaly_score=row.anomaly_score,
                attack_scores={name: getattr(row, name) for name in CAPTURE_ATTACK_SCORE_COLUMNS},
            )
            for row in events.itertuples(index=False)
        ]
