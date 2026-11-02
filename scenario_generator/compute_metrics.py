from typing import cast
from collections import defaultdict
import pandas as pd
from scenario_reconstructor.scenario_reconstructor import AttackType, Exploit, FlowExploit
from itertools import combinations_with_replacement
from sklearn.metrics import confusion_matrix
from datetime import timedelta, datetime


class MetricsCalculator:

    @staticmethod
    def _index_steps(steps: list[Exploit]):
        index = defaultdict(list)
        for step in steps:
            index[step.metric_key].append(step)
        return index

    @staticmethod
    def _pair_key(pair: tuple[FlowExploit, FlowExploit]):
        return (pair[0].metric_key, pair[1].metric_key)

    @staticmethod
    def _build_pairs(alerts_by_step: dict[Exploit, list[tuple[int, FlowExploit]]]) -> set[tuple[int, int]]:
        pairs = set()
        for alerts in alerts_by_step.values():
            alerts = sorted(alerts, key=lambda x: x[1].start_time)
            alert_ids = [alert_id for alert_id, _ in alerts]
            for a_id, b_id in combinations_with_replacement(alert_ids, 2):
                pairs.add((a_id, b_id))
        return pairs

    @staticmethod
    def get_step_soundness_completeness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                        predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit],
                                        unknown_attack_type: AttackType | None = None) -> tuple[float, float]:
        correctly_correlated, predicted_pairs, actual_pairs = MetricsCalculator._get_aggregation_correlation_pairs(
            actual_alerts,
            actual_steps,
            predicted_alerts,
            predicted_steps, unknown_attack_type)

        completeness = len(correctly_correlated) / \
                       len(actual_pairs) if actual_pairs else 0.0
        soundness = len(correctly_correlated) / \
                    len(predicted_pairs) if predicted_pairs else 0.0
        return soundness, completeness

    @staticmethod
    def _match_alerts_one_to_one(predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit],
                                 unknown_attack_type: AttackType | None = None) -> list[tuple[int, FlowExploit, FlowExploit]]:
        actual_by_key = defaultdict(list)
        for a_idx, alert in enumerate(actual_alerts):
            actual_by_key[alert.metric_key].append((a_idx, alert))

        used_actual_indices: set[int] = set()
        matches: list[tuple[int, FlowExploit, FlowExploit]] = []

        for p_alert in predicted_alerts:
            for a_idx, candidate in actual_by_key.get(p_alert.metric_key, []):
                if (not unknown_attack_type and p_alert == candidate) or \
                        (unknown_attack_type and candidate.unk_eq(p_alert, unknown_attack_type)):
                    if a_idx not in used_actual_indices:
                        used_actual_indices.add(a_idx)
                        matches.append((a_idx, p_alert, candidate))
                        break
        return matches

    @staticmethod
    def get_alert_recall(predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit],
                         unknown_attack_type: AttackType | None = None) -> float:
        if not actual_alerts:
            return 0.0
        matches = MetricsCalculator._match_alerts_one_to_one(
            predicted_alerts, actual_alerts, unknown_attack_type)
        return len(matches) / len(actual_alerts)

    @staticmethod
    def get_alert_precision(predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit],
                            unknown_attack_type: AttackType | None = None) -> float:
        if not predicted_alerts:
            return 0.0
        matches = MetricsCalculator._match_alerts_one_to_one(
            predicted_alerts, actual_alerts, unknown_attack_type)
        return len(matches) / len(predicted_alerts)

    @staticmethod
    def _get_aggregation_correlation_pairs(actual_alerts: list[FlowExploit], actual_steps: list[Exploit],
                                           predicted_alerts: list[FlowExploit],
                                           predicted_steps: list[Exploit],
                                           unknown_attack_type: AttackType | None = None) -> tuple[
        set[tuple[int, int]], set[tuple[int, int]], set[tuple[int, int]]]:
        actual_matches_by_group = defaultdict(list)
        predicted_matches_by_group = defaultdict(list)

        for a_idx, p_alert, candidate in MetricsCalculator._match_alerts_one_to_one(
                predicted_alerts, actual_alerts, unknown_attack_type):
            actual_matches_by_group[candidate.get_flow_exploit_group_id()].append((a_idx, candidate))
            predicted_matches_by_group[p_alert.get_flow_exploit_group_id()].append((a_idx, p_alert))

        predicted_alerts_by_step = {}
        actual_alerts_by_step = {}

        for step in actual_steps:
            actual_alerts_by_step[step] = [
                (a_idx, a) for a_idx, a in actual_matches_by_group[step.get_exploit_group_id()]
                if step.start_time <= a.start_time <= step.end_time
            ]

        for step in predicted_steps:
            predicted_alerts_by_step[step] = [
                (alert_id, p_a) for alert_id, p_a in predicted_matches_by_group[step.get_exploit_group_id()]
                if step.start_time <= p_a.start_time <= step.end_time
            ]

        predicted_pairs = MetricsCalculator._build_pairs(
            predicted_alerts_by_step)
        actual_pairs = MetricsCalculator._build_pairs(actual_alerts_by_step)

        return actual_pairs & predicted_pairs, predicted_pairs, actual_pairs

    @staticmethod
    def get_detection_confusion_matrix(scenario_df: pd.DataFrame, alert_threshold: float) -> tuple[
        int, int, int, int]:
        y_true = (scenario_df["label"] != "normal").astype(int)
        y_pred = scenario_df["anomaly_score"] > alert_threshold
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel()
        return int(tn), int(fp), int(fn), int(tp)

    @staticmethod
    def get_reconstruction_confusion_matrix(
            scenario_df: pd.DataFrame,
            predicted_alerts: list[FlowExploit],
    ) -> tuple[int, int, int, int]:
        predicted_flows = {
            (
                alert.source_ip,
                alert.source_port,
                alert.destination_ip,
                alert.destination_port,
                alert.protocol,
                alert.start_time,
                alert.end_time,
            )
            for alert in predicted_alerts
        }

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
                timestamp,
                timestamp +
                timedelta(milliseconds=duration),
            )
            values.append(int(key in predicted_flows))

        tn, fp, fn, tp = confusion_matrix(
            (scenario_df["label"] != "normal").astype(int), labels=[0, 1]).ravel()

        return int(tn), int(fp), int(fn), int(tp)

    @staticmethod
    def _match_steps_one_to_one(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                tolerance: int = 0,
                                unknown_attack_type: AttackType | None = None) -> dict[Exploit, Exploit]:
        tol = timedelta(milliseconds=tolerance)
        used_actual: set[int] = set()
        matches: dict[Exploit, Exploit] = {}
        for p_step in predicted_steps:
            for a_idx, a_step in enumerate(actual_steps):
                if a_idx in used_actual:
                    continue
                if a_step.approx_match(p_step, tol, unknown_attack_type):
                    matches[p_step] = a_step
                    used_actual.add(a_idx)
                    break
        return matches

    @staticmethod
    def get_scenario_step_recall(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                 tolerance: int = 0,
                                 unknown_attack_type: AttackType | None = None) -> float:
        if not actual_steps:
            return 0.0
        matches = MetricsCalculator._match_steps_one_to_one(
            predicted_steps, actual_steps, tolerance, unknown_attack_type)
        return len(matches) / len(actual_steps)

    @staticmethod
    def get_scenario_step_precision(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                    tolerance: int = 0,
                                    unknown_attack_type: AttackType | None = None) -> float:
        if not predicted_steps:
            return 0.0
        matches = MetricsCalculator._match_steps_one_to_one(
            predicted_steps, actual_steps, tolerance, unknown_attack_type)
        return len(matches) / len(predicted_steps)

    @staticmethod
    def _get_step_matches(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                          tolerance: int = 0,
                          unknown_attack_type: AttackType | None = None) -> dict[Exploit, Exploit]:
        return MetricsCalculator._match_steps_one_to_one(
            predicted_steps, actual_steps, tolerance, unknown_attack_type)

    @staticmethod
    def _get_causal_correlation_pairs(actual_steps: list[Exploit], predicted_steps: list[Exploit],
                                      unknown_attack_type: AttackType | None = None) -> tuple[
        set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]]]:

        matches = MetricsCalculator._get_step_matches(
            predicted_steps, actual_steps, 0, unknown_attack_type
        )

        actual_steps = sorted(actual_steps, key=lambda x: x.start_time)
        predicted_steps = sorted(predicted_steps, key=lambda x: x.start_time)

        matched_actual_steps = []

        for step in actual_steps:
            if step in matches.values():
                matched_actual_steps.append(step)

        actual_pairs = {(matched_actual_steps[i], matched_actual_steps[j])
                        for i in range(len(matched_actual_steps))
                        for j in range(i + 1, len(matched_actual_steps))}

        matched_predicted_steps = []

        for step in predicted_steps:
            if step in matches.keys():
                matched_predicted_steps.append(matches[step])

        predicted_pairs = {(matched_predicted_steps[i], matched_predicted_steps[j])
                           for i in range(len(matched_predicted_steps))
                           for j in range(i + 1, len(matched_predicted_steps))}

        return actual_pairs, predicted_pairs, predicted_pairs & actual_pairs

    @staticmethod
    def get_scenario_soundness_completeness(
            predicted_steps: list[Exploit],
            actual_steps: list[Exploit],
            unknown_attack_type: AttackType | None = None
    ) -> tuple[float, float]:

        actual_pairs, predicted_pairs, correct_pairs = MetricsCalculator._get_causal_correlation_pairs(
            actual_steps, predicted_steps, unknown_attack_type)

        soundness = (
            len(correct_pairs) / len(predicted_pairs)
            if predicted_pairs
            else 0.0
        )
        completeness = len(correct_pairs) / \
                       len(actual_pairs) if actual_pairs else 0.0
        return soundness, completeness
