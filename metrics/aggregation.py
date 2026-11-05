"""Aggregation evaluation helpers."""

from collections import defaultdict
from itertools import combinations_with_replacement

from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import AttackStep, AttackType, FlowAlert

from .matching import ensure_steps, match_alerts


def build_aggregation_pairs(
    alerts_by_step: dict[AttackStep, list[tuple[int, FlowAlert]]]
) -> set[tuple[int, int]]:
    pairs: set[tuple[int, int]] = set()
    for alerts in alerts_by_step.values():
        alerts = sorted(alerts, key=lambda x: x[1].start_time)
        alert_ids = [alert_id for alert_id, _ in alerts]
        for a_id, b_id in combinations_with_replacement(alert_ids, 2):
            pairs.add((a_id, b_id))
    return pairs


def aggregation_pairs(
    actual_alerts: list[FlowAlert],
    actual_steps: list[AttackStep],
    predicted_alerts: list[FlowAlert],
    predicted_steps: list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> tuple[set[tuple[int, int]], set[tuple[int, int]], set[tuple[int, int]]]:
    actual_matches_by_group = defaultdict(list)
    predicted_matches_by_group = defaultdict(list)

    for a_idx, p_alert, candidate in match_alerts(
        predicted_alerts, actual_alerts, unknown_attack_type
    ):
        actual_matches_by_group[candidate.get_flow_exploit_group_id()].append((a_idx, candidate))
        predicted_matches_by_group[p_alert.get_flow_exploit_group_id()].append((a_idx, p_alert))

    actual_alerts_by_step = {
        step: [
            (a_idx, a)
            for a_idx, a in actual_matches_by_group[step.get_exploit_group_id()]
            if step.start_time <= a.start_time <= step.end_time
        ]
        for step in actual_steps
    }
    predicted_alerts_by_step = {
        step: [
            (alert_id, p_a)
            for alert_id, p_a in predicted_matches_by_group[step.get_exploit_group_id()]
            if step.start_time <= p_a.start_time <= step.end_time
        ]
        for step in predicted_steps
    }

    predicted_pairs = build_aggregation_pairs(predicted_alerts_by_step)
    actual_pairs = build_aggregation_pairs(actual_alerts_by_step)
    return actual_pairs & predicted_pairs, predicted_pairs, actual_pairs


def aggregation_quality(
    predicted_steps: AttackScenarioDAG | list[AttackStep],
    actual_steps: AttackScenarioDAG | list[AttackStep],
    predicted_alerts: list[FlowAlert],
    actual_alerts: list[FlowAlert],
    unknown_attack_type: AttackType | None = None,
) -> tuple[float, float]:
    p_steps = ensure_steps(predicted_steps)
    a_steps = ensure_steps(actual_steps)
    correctly_correlated, predicted_pairs, actual_pairs = (
        aggregation_pairs(
            actual_alerts, a_steps, predicted_alerts, p_steps, unknown_attack_type
        )
    )
    completeness = len(correctly_correlated) / len(actual_pairs) if actual_pairs else 0.0
    soundness = len(correctly_correlated) / len(predicted_pairs) if predicted_pairs else 0.0
    return soundness, completeness
