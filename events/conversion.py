"""Conversion of scored cAPTure dataframe rows into UTC flow events."""
from collections.abc import Iterable
from datetime import timedelta

import pandas as pd

from .models import FlowEvent


CAPTURE_ATTACK_SCORE_COLUMNS = (
    "nmap_10_T5", "nmap_mqtt", "nmap_banner", "brute_force_malformed", "dollar_char", "scp_inst",
)


class CaptureFlowEventConverter:
    """Adapt cAPTure column names to the dataset-independent flow model."""

    @staticmethod
    def convert(dataframe: pd.DataFrame,
                score_columns: Iterable[str] = CAPTURE_ATTACK_SCORE_COLUMNS) -> list[FlowEvent]:
        """Create UTC events without changing input; naive timestamps represent UTC."""
        events = dataframe.copy(deep=True)
        events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
        score_columns = tuple(score_columns)
        if events.empty:
            return []
        for name in score_columns:
            if name not in events.columns:
                raise AttributeError(f"Flow dataset has no attack score column {name!r}")
        score_positions = [(name, events.columns.get_loc(name)) for name in score_columns]
        return [
            FlowEvent(
                source_ip=row.src_ip, source_port=row.src_port,
                destination_ip=row.dst_ip, destination_port=row.dst_port,
                protocol=row.protocol, start_time=row.timestamp,
                end_time=row.timestamp + timedelta(milliseconds=row.duration),
                anomaly_score=row.anomaly_score,
                attack_scores={name: row[position] for name, position in score_positions},
            )
            for row in events.itertuples(index=False)
        ]
