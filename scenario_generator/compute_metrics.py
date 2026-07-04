from typing import cast

import pandas as pd
from scenario_reconstructor.scenario_reconstructor import Exploit, FlowExploit
from itertools import combinations
from sklearn.metrics import confusion_matrix
from datetime import datetime, timedelta


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
    def get_completeness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                         predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit]) -> float:
        correctly_correlated, _, actual_pairs = MetricsCalculator.get_correlation_pairs(actual_alerts, actual_steps,
                                                                                        predicted_alerts,
                                                                                        predicted_steps)

        return len(correctly_correlated) / len(actual_pairs) if actual_pairs else 0.0

    @staticmethod
    def get_soundness(predicted_steps: list[Exploit], actual_steps: list[Exploit],
                      predicted_alerts: list[FlowExploit], actual_alerts: list[FlowExploit]) -> float:
        correctly_correlated, predicted_pairs, _ = MetricsCalculator.get_correlation_pairs(actual_alerts, actual_steps,
                                                                                           predicted_alerts,
                                                                                           predicted_steps)

        return len(correctly_correlated) / len(predicted_pairs) if predicted_pairs else 0.0

    @staticmethod
    def get_correlation_pairs(actual_alerts: list[FlowExploit], actual_steps: list[Exploit],
                              predicted_alerts: list[FlowExploit],
                              predicted_steps: list[Exploit]) -> tuple[
        set[tuple[FlowExploit, FlowExploit]], set[tuple[FlowExploit, FlowExploit]], set[
            tuple[FlowExploit, FlowExploit]]]:
        alerts = [alert for alert in predicted_alerts if alert in actual_alerts]
        predicted_alerts_by_step = {}
        actual_alerts_by_step = {}

        for step in predicted_steps:
            predicted_alerts_by_step[step] = [alert for alert in alerts if
                                              alert.get_flow_exploit_group_id() == step and step.start_time <= alert.start_time <= step.end_time]

        for step in actual_steps:
            actual_alerts_by_step[step] = [alert for alert in alerts if
                                           alert.get_flow_exploit_group_id() == step and step.start_time <= alert.start_time <= step.end_time]

        predicted_pairs = MetricsCalculator._build_pairs(predicted_alerts_by_step)
        actual_pairs = MetricsCalculator._build_pairs(actual_alerts_by_step)

        correctly_correlated = predicted_pairs.intersection(actual_pairs)
        return correctly_correlated, predicted_pairs, actual_pairs

    @staticmethod
    def get_detection_confusion_matrix_capture(scenario_df: pd.DataFrame, alert_threshold: float):
        return confusion_matrix((scenario_df["label"] != "normal").astype(int),
                                scenario_df["anomaly_score"] > alert_threshold)

    @staticmethod
    def get_reconstruction_confusion_matrix_capture(
            scenario_df: pd.DataFrame,
            predicted_alerts: list[FlowExploit],
    ):
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

        return confusion_matrix((scenario_df["label"] != "normal").astype(int), values)

    @staticmethod
    def scenario_exact_full_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        if len(actual_steps) != len(predicted_steps):
            return False
        for i in range(len(actual_steps)):
            if actual_steps[i] != predicted_steps[i]:
                return False
        return True

    @staticmethod
    def scenario_approx_full_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        if len(actual_steps) != len(predicted_steps):
            return False
        for i in range(len(actual_steps)):
            if not actual_steps[i].approx_match(predicted_steps[i]):
                return False
        return True

    @staticmethod
    def scenario_full_order_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        if len(actual_steps) != len(predicted_steps):
            return False
        for i in range(len(actual_steps)):
            if not actual_steps[i].approx_match_no_timing(predicted_steps[i]):
                return False
        return True

    @staticmethod
    def scenario_unique_order_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        seen = set()
        unique_group_ids = []
        for step in actual_steps:
            gid = step.get_exploit_group_id()
            if gid not in seen:
                seen.add(gid)
                unique_group_ids.append(gid)
        i = 0
        j = 0
        if len(unique_group_ids) == 0:
            return True
        while j < len(unique_group_ids):
            if i >= len(predicted_steps):
                return False
            if unique_group_ids[j] == predicted_steps[i].get_exploit_group_id():
                j += 1
            i += 1
        return True

    @staticmethod
    def scenario_full_box_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        if len(actual_steps) != len(predicted_steps):
            return False
        return all([any([predicted_step.approx_match_no_timing(actual_step) for actual_step in actual_steps]) for
                    predicted_step in predicted_steps])

    @staticmethod
    def scenario_unique_box_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]):
        unique_group_ids = set()
        predicted_group_ids = {step.get_exploit_group_id() for step in predicted_steps}
        for actual_step in actual_steps:
            unique_group_ids.add(actual_step.get_exploit_group_id())
        for group_id in unique_group_ids:
            if group_id not in predicted_group_ids:
                return False
        return True

    @staticmethod
    def scenario_end_match(predicted_steps: list[Exploit], actual_steps: list[Exploit]) -> bool:
        return actual_steps[-1].get_exploit_group_id() == predicted_steps[-1].get_exploit_group_id()
