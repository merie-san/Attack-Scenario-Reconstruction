from typing import cast
from collections import defaultdict
import pandas as pd
from scenario_reconstructor.scenario_reconstructor import AttackType, Exploit, FlowExploit
from itertools import combinations
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
    def _build_pairs(alerts_by_step: dict[Exploit, list[FlowExploit]]) -> set[tuple[FlowExploit, FlowExploit]]:
        pairs = set()
        for alerts in alerts_by_step.values():
            alerts = sorted(alerts, key=lambda x: x.start_time)
            for a, b in combinations(alerts, 2):
                pairs.add((a, b))
        return pairs

    @staticmethod
    def get_step_soundness_completeness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                        predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit], unknown_attack_type: AttackType | None = None) -> tuple[float, float]:
        correctly_correlated, predicted_pairs, actual_pairs = MetricsCalculator._get_aggregation_correlation_pairs(actual_alerts,
                                                                                                                  actual_steps,
                                                                                                                  predicted_alerts,
                                                                                                                  predicted_steps, unknown_attack_type)

        completeness = len(correctly_correlated) / \
            len(actual_pairs) if actual_pairs else 0.0
        soundness = len(correctly_correlated) / \
            len(predicted_pairs) if predicted_pairs else 0.0
        return soundness, completeness

    @staticmethod
    def _get_aggregation_correlation_pairs(actual_alerts: list[FlowExploit], actual_steps: list[Exploit],
                                          predicted_alerts: list[FlowExploit],
                                          predicted_steps: list[Exploit], unknown_attack_type: AttackType | None = None) -> tuple[
        set[tuple[FlowExploit, FlowExploit]], set[tuple[FlowExploit, FlowExploit]], set[
            tuple[FlowExploit, FlowExploit]]]:
        actual_by_key = defaultdict(list)

        for alert in actual_alerts:
            actual_by_key[alert.metric_key].append(alert)

        matches = {}

        for p_alert in predicted_alerts:
            for candidate in actual_by_key.get(p_alert.metric_key, []):
                if (not unknown_attack_type and p_alert == candidate) or \
                        (unknown_attack_type and candidate.unk_eq(p_alert, unknown_attack_type)):
                    matches[p_alert] = candidate
                    break

        actual_matches_by_group = defaultdict(list)
        predicted_matches_by_group = defaultdict(list)

        for alert in matches.values():
            actual_matches_by_group[
                alert.get_flow_exploit_group_id()
            ].append(alert)

        for alert in matches.keys():
            predicted_matches_by_group[
                alert.get_flow_exploit_group_id()
            ].append(alert)

        predicted_alerts_by_step = {}
        actual_alerts_by_step = {}

        for step in actual_steps:
            actual_alerts_by_step[step] = [
                a for a in actual_matches_by_group[step.get_exploit_group_id()]
                if step.start_time <= a.start_time <= step.end_time
            ]

        for step in predicted_steps:
            predicted_alerts_by_step[step] = [
                matches[a] for a in predicted_matches_by_group[step.get_exploit_group_id()]
                if step.start_time <= a.start_time <= step.end_time
            ]

        predicted_pairs = MetricsCalculator._build_pairs(
            predicted_alerts_by_step)
        actual_pairs = MetricsCalculator._build_pairs(actual_alerts_by_step)

        return actual_pairs & predicted_pairs, predicted_pairs, actual_pairs

    @staticmethod
    def get_detection_confusion_matrix_capture(scenario_df: pd.DataFrame, alert_threshold: float) -> tuple[
            int, int, int, int]:
        y_true = (scenario_df["label"] != "normal").astype(int)
        y_pred = scenario_df["anomaly_score"] >= alert_threshold
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        return int(tn), int(fp), int(fn), int(tp)

    @staticmethod
    def get_reconstruction_confusion_matrix_capture(
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
            (scenario_df["label"] != "normal").astype(int), values).ravel()

        return int(tn), int(fp), int(fn), int(tp)

    @staticmethod
    def get_scenario_step_recall(predicted_steps: list[Exploit], actual_steps: list[Exploit], tolerance: int, unknown_attack_type: AttackType | None = None) -> float:
        matches = 0
        for step in actual_steps:
            for p_step in predicted_steps:
                if step.approx_match(p_step, timedelta(milliseconds=tolerance), unknown_attack_type):
                    matches += 1
                    break
        return matches / len(actual_steps) if actual_steps else 0.0

    @staticmethod
    def get_scenario_step_recall_no_timing(predicted_steps: list[Exploit], actual_steps: list[Exploit], unknown_attack_type: AttackType | None = None) -> float:
        matches = 0
        for step in actual_steps:
            for p_step in predicted_steps:
                if step.approx_match_no_timing(p_step, unknown_attack_type):
                    matches += 1
                    break
        return matches / len(actual_steps) if actual_steps else 0.0

    @staticmethod
    def get_scenario_step_precision(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                    tolerance: int, unknown_attack_type: AttackType | None = None) -> float:
        matches = 0
        for p_step in predicted_steps:
            for step in actual_steps:
                if step.approx_match(p_step, timedelta(milliseconds=tolerance), unknown_attack_type):
                    matches += 1
                    break
        return matches / len(predicted_steps) if predicted_steps else 0.0

    @staticmethod
    def get_scenario_step_precision_no_timing(predicted_steps: list[Exploit], actual_steps: list[Exploit], unknown_attack_type: AttackType | None = None) -> float:
        matches = 0
        for p_step in predicted_steps:
            for step in actual_steps:
                if step.approx_match_no_timing(p_step, unknown_attack_type):
                    matches += 1
                    break
        return matches / len(predicted_steps) if predicted_steps else 0.0

    @staticmethod
    def _get_step_matches(predicted_steps: list[Exploit], actual_steps: list[Exploit], unknown_attack_type: AttackType | None = None):
        matches = {}
        actual_index = MetricsCalculator._index_steps(actual_steps)
        for p in predicted_steps:
            candidates = actual_index[p.metric_key]
            for a in candidates:
                if a.approx_match_no_timing(p, unknown_attack_type):
                    matches[p] = a
                    break
        return matches

    @staticmethod
    def _ordered_pairs(steps: list[Exploit]) -> set[tuple[Exploit, Exploit]]:
        steps = sorted(steps, key=lambda x: x.start_time)
        return {
            (steps[i], steps[j])
            for i in range(len(steps))
            for j in range(i + 1, len(steps))
        }

    @staticmethod
    def _get_causal_correlation_pairs(actual_steps: list[Exploit], predicted_steps: list[Exploit], unknown_attack_type: AttackType | None = None) -> tuple[
            set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]]]:
        actual_pairs = MetricsCalculator._ordered_pairs(actual_steps)

        matches = MetricsCalculator._get_step_matches(
            predicted_steps, actual_steps, unknown_attack_type
        )

        predicted_pairs = set()

        for i in range(len(predicted_steps)):
            for j in range(i + 1, len(predicted_steps)):
                p1 = predicted_steps[i]
                p2 = predicted_steps[j]

                if p1 in matches and p2 in matches and matches[p1]!=matches[p2]:
                    predicted_pairs.add((matches[p1], matches[p2]))

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
