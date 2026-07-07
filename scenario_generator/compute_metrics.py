from typing import cast, Any

import pandas as pd
from scenario_reconstructor.scenario_reconstructor import Exploit, FlowExploit
from itertools import combinations
from sklearn.metrics import confusion_matrix
from datetime import timedelta


class MetricsCalculator:

    @staticmethod
    def _build_pairs(alerts_by_step: dict[Exploit, list[FlowExploit]]) -> set[tuple[FlowExploit, FlowExploit]]:
        pairs = set()
        for alerts in alerts_by_step.values():
            alerts.sort(key=lambda x: x.start_time)
            for a, b in combinations(alerts, 2):
                pairs.add((a, b))
        return pairs

    @staticmethod
    def get_step_completeness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                              predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit]) -> float:
        correctly_correlated, _, actual_pairs = MetricsCalculator.get_aggregation_correlation_pairs(actual_alerts,
                                                                                                    actual_steps,
                                                                                                    predicted_alerts,
                                                                                                    predicted_steps)

        return len(correctly_correlated) / len(actual_pairs) if actual_pairs else 0.0

    @staticmethod
    def get_step_soundness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                           predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit]) -> float:
        correctly_correlated, predicted_pairs, _ = MetricsCalculator.get_aggregation_correlation_pairs(actual_alerts,
                                                                                                       actual_steps,
                                                                                                       predicted_alerts,
                                                                                                       predicted_steps)

        return len(correctly_correlated) / len(predicted_pairs) if predicted_pairs else 0.0

    @staticmethod
    def get_aggregation_correlation_pairs(actual_alerts: list[FlowExploit], actual_steps: list[Exploit],
                                          predicted_alerts: list[FlowExploit],
                                          predicted_steps: list[Exploit]) -> tuple[
        set[tuple[FlowExploit, FlowExploit]], set[tuple[FlowExploit, FlowExploit]], set[
            tuple[FlowExploit, FlowExploit]]]:
        alerts = [alert for alert in predicted_alerts if alert in actual_alerts]
        predicted_alerts_by_step = {}
        actual_alerts_by_step = {}

        for step in predicted_steps:
            predicted_alerts_by_step[step] = [alert for alert in alerts if
                                              alert.get_flow_exploit_group_id() == step.get_exploit_group_id() and step.start_time <= alert.start_time <= step.end_time]

        for step in actual_steps:
            actual_alerts_by_step[step] = [alert for alert in alerts if
                                           alert.get_flow_exploit_group_id() == step.get_exploit_group_id() and step.start_time <= alert.start_time <= step.end_time]

        predicted_pairs = MetricsCalculator._build_pairs(predicted_alerts_by_step)
        actual_pairs = MetricsCalculator._build_pairs(actual_alerts_by_step)

        correctly_correlated = predicted_pairs.intersection(actual_pairs)
        return correctly_correlated, predicted_pairs, actual_pairs

    @staticmethod
    def get_detection_confusion_matrix_capture(scenario_df: pd.DataFrame, alert_threshold: float) -> tuple[
        int, int, int, int]:
        return confusion_matrix((scenario_df["label"] != "normal").astype(int),
                                scenario_df["anomaly_score"] > alert_threshold).ravel()

    @staticmethod
    def get_reconstruction_confusion_matrix_capture(
            scenario_df: pd.DataFrame,
            predicted_alerts: list[FlowExploit],
    ) -> tuple[int, int, int, int]:
        predicted_flows = {
            (
                alert.start_time,
                alert.source_ip,
                alert.destination_ip,
                alert.end_time,
            )
            for alert in predicted_alerts
        }

        values = []

        for row in scenario_df.itertuples(index=False):
            key = (
                row.timestamp,
                row.src_ip,
                row.dst_ip,
                row.timestamp + timedelta(milliseconds=cast(int, row.duration)),
            )
            values.append(int(key in predicted_flows))

        return confusion_matrix((scenario_df["label"] != "normal").astype(int), values).ravel()

    @staticmethod
    def get_scenario_step_recall(predicted_steps: list[Exploit], actual_steps: list[Exploit], tolerance: int) -> float:
        matches = 0
        for step in actual_steps:
            for p_step in predicted_steps:
                if step.approx_match(p_step, timedelta(milliseconds=tolerance)):
                    matches += 1
                    break
        return matches / len(actual_steps) if actual_steps else 0.0

    @staticmethod
    def get_scenario_step_recall_no_timing(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> float:
        matches = 0
        for step in actual_steps:
            for p_step in predicted_steps:
                if step.approx_match_no_timing(p_step):
                    matches += 1
                    break
        return matches / len(actual_steps) if actual_steps else 0.0

    @staticmethod
    def get_scenario_step_precision(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                                    tolerance: int) -> float:
        matches = 0
        for p_step in predicted_steps:
            for step in actual_steps:
                if p_step.approx_match(step, timedelta(milliseconds=tolerance)):
                    matches += 1
                    break
        return matches / len(predicted_steps) if predicted_steps else 0.0

    @staticmethod
    def get_scenario_step_precision_no_timing(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> float:
        matches = 0
        for p_step in predicted_steps:
            for step in actual_steps:
                if p_step.approx_match_no_timing(step):
                    matches += 1
                    break
        return matches / len(predicted_steps) if predicted_steps else 0.0

    @staticmethod
    def _match_predicted_steps(predicted_steps: list[Exploit], actual_steps: list[Exploit]):
        matches = {}
        for p in predicted_steps:
            for a in actual_steps:
                if p.approx_match_no_timing(a):
                    matches[p] = a
                    break
        return matches

    @staticmethod
    def _ordered_pairs(steps: list[Exploit]) -> set[tuple[Exploit, Exploit]]:
        return {
            (steps[i], steps[j])
            for i in range(len(steps))
            for j in range(i + 1, len(steps))
        }

    @staticmethod
    def get_scenario_completeness(
            predicted_steps: list[Exploit],
            actual_steps: list[Exploit],
    ) -> float:

        actual_pairs, predicted_pairs = MetricsCalculator.get_causal_correlation_pairs(actual_steps, predicted_steps)

        return (
            len(actual_pairs & predicted_pairs) / len(actual_pairs)
            if actual_pairs
            else 0.0
        )

    @staticmethod
    def get_causal_correlation_pairs(actual_steps: list[Exploit], predicted_steps: list[Exploit]) -> tuple[
        set[tuple[Exploit, Exploit]], set[Any]]:
        actual_pairs = MetricsCalculator._ordered_pairs(actual_steps)

        matches = MetricsCalculator._match_predicted_steps(
            predicted_steps, actual_steps
        )

        predicted_pairs = set()

        for i in range(len(predicted_steps)):
            for j in range(i + 1, len(predicted_steps)):
                p1 = predicted_steps[i]
                p2 = predicted_steps[j]

                if p1 in matches and p2 in matches:
                    predicted_pairs.add((matches[p1], matches[p2]))
        return actual_pairs, predicted_pairs

    @staticmethod
    def get_scenario_soundness(
            predicted_steps: list[Exploit],
            actual_steps: list[Exploit],
    ) -> float:

        actual_pairs, predicted_pairs = MetricsCalculator.get_causal_correlation_pairs(actual_steps, predicted_steps)

        return (
            len(actual_pairs & predicted_pairs) / len(predicted_pairs)
            if predicted_pairs
            else 0.0
        )
