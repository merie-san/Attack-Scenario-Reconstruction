"""Detection evaluation helpers."""

from datetime import datetime, timedelta
from typing import cast

import pandas as pd
from sklearn.metrics import confusion_matrix

from scenario_reconstructor.models import AttackType, FlowAlert
from scenario_reconstructor.time_utils import normalize_timestamp

from .matching import match_alerts


def detection_confusion_matrix(
    scenario_df: pd.DataFrame,
    alert_threshold: float,
) -> tuple[int, int, int, int]:
    y_true = (scenario_df["label"] != "normal").astype(int)
    y_pred = scenario_df["anomaly_score"] > alert_threshold
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return int(tn), int(fp), int(fn), int(tp)


def reconstruction_confusion_matrix(
    scenario_df: pd.DataFrame,
    predicted_alerts: list[FlowAlert],
) -> tuple[int, int, int, int]:
    predicted_flows = {alert.metric_key for alert in predicted_alerts}

    values = []
    for row in scenario_df.itertuples(index=False):
        timestamp = cast(datetime, row.timestamp)
        duration = cast(int, row.duration)
        key = (
            row.src_ip,
            row.src_port,
            row.dst_ip,
            row.dst_port,
            row.protocol,
            normalize_timestamp(timestamp),
            normalize_timestamp(timestamp + timedelta(milliseconds=duration)),
        )
        values.append(int(key in predicted_flows))

    tn, fp, fn, tp = confusion_matrix(
        (scenario_df["label"] != "normal").astype(int),
        values,
        labels=[0, 1],
    ).ravel()
    return int(tn), int(fp), int(fn), int(tp)


def alert_recall(
    predicted_alerts: list[FlowAlert],
    actual_alerts: list[FlowAlert],
    unknown_attack_type: AttackType | None = None,
) -> float:
    if not actual_alerts:
        return 1.0 if not predicted_alerts else 0.0
    matches = match_alerts(
        predicted_alerts, actual_alerts, unknown_attack_type
    )
    return len(matches) / len(actual_alerts)


def alert_precision(
    predicted_alerts: list[FlowAlert],
    actual_alerts: list[FlowAlert],
    unknown_attack_type: AttackType | None = None,
) -> float:
    if not predicted_alerts:
        return 1.0 if not actual_alerts else 0.0
    matches = match_alerts(
        predicted_alerts, actual_alerts, unknown_attack_type
    )
    return len(matches) / len(predicted_alerts)
