"""Stable class API delegating to focused, stateless metric implementations."""

from .aggregation import aggregation_pairs, aggregation_quality, build_aggregation_pairs
from .causal import causal_pairs, causal_quality, scenario_detected
from .detection import (
    alert_precision,
    alert_recall,
    detection_confusion_matrix,
    reconstruction_confusion_matrix,
)
from .matching import ensure_dag_pair, ensure_steps, mapped_causal_pairs, match_alerts, match_steps
from .occurrence import step_precision, step_recall


class MetricsCalculator:
    """Evaluate detection, aggregation, occurrence coverage, and causal recovery."""

    _ensure_steps = staticmethod(ensure_steps)
    _ensure_dag_pair = staticmethod(ensure_dag_pair)
    _match_alerts_one_to_one = staticmethod(match_alerts)
    _match_steps_one_to_one = staticmethod(match_steps)
    _mapped_causal_pairs = staticmethod(mapped_causal_pairs)
    _build_pairs = staticmethod(build_aggregation_pairs)
    _get_aggregation_correlation_pairs = staticmethod(aggregation_pairs)
    _get_causal_correlation_pairs = staticmethod(causal_pairs)
    get_detection_confusion_matrix = staticmethod(detection_confusion_matrix)
    get_reconstruction_confusion_matrix = staticmethod(reconstruction_confusion_matrix)
    get_alert_precision = staticmethod(alert_precision)
    get_alert_recall = staticmethod(alert_recall)
    get_step_soundness_completeness = staticmethod(aggregation_quality)
    get_scenario_step_precision = staticmethod(step_precision)
    get_scenario_step_recall = staticmethod(step_recall)
    get_scenario_soundness_completeness = staticmethod(causal_quality)
    is_scenario_detected = staticmethod(scenario_detected)
