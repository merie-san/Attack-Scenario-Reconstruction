from collections import defaultdict
from datetime import datetime, timedelta
from itertools import combinations_with_replacement
from typing import cast

import pandas as pd
from sklearn.metrics import confusion_matrix

from scenario_reconstructor.scenario_reconstructor import (
    AttackType, Exploit, FlowExploit, normalize_timestamp,
)


class AttackGoal:
    """Conditions identifying a goal attack step in an AttackScenarioDAG."""

    def __init__(
        self,
        attack_type: AttackType | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> None:
        self.attack_type = attack_type
        self.source_ip = source_ip
        self.destination_ip = destination_ip

    def is_satisfied_by(
        self,
        step: Exploit,
        unknown_attack_type: AttackType | None = None,
    ) -> bool:
        if self.source_ip is not None and step.source_ip != self.source_ip:
            return False
        if self.destination_ip is not None and step.destination_ip != self.destination_ip:
            return False
        if self.attack_type is not None:
            if step.attack_type == self.attack_type:
                return True
            if unknown_attack_type is not None and step.attack_type == unknown_attack_type:
                return True
            return False
        return True


class AttackScenarioDAG:
    """Temporal AND/OR Attack Graph (DAG) representation of an attack scenario.

    Steps are grouped by (attack_type, destination_ip, source_ip) and ordered by
    start_time within each group:
    - Each Exploit step acts as an AND-node over its satisfied precondition clauses
      (stored in `clause_parents_map[step]` as a list of OR-clauses).
    - Each precondition clause acts as an OR-node (`list[Exploit]`) containing the
      latest repetition (occurring before the step) of every prior group that
      satisfied that precondition clause.
    - Repeated steps within the same group are linked sequentially
      (`clause_parents_map[group[i]] = [[group[i-1]]]`).
    """

    def __init__(self, steps: list[Exploit]) -> None:
        self.steps: list[Exploit] = sorted(steps, key=lambda s: normalize_timestamp(s.start_time))
        self.groups: dict[str, list[Exploit]] = defaultdict(list)
        seen_by_group: dict[str, set[Exploit]] = defaultdict(set)
        for step in self.steps:
            gid = step.get_exploit_group_id()
            # Keep duplicate inputs in steps for precision/recall, but only one DAG node per value.
            if step not in seen_by_group[gid]:
                seen_by_group[gid].add(step)
                self.groups[gid].append(step)

        self.clause_parents_map: dict[Exploit, list[list[Exploit]]] = defaultdict(list)
        self.parents_map: dict[Exploit, list[Exploit]] = defaultdict(list)
        self.children_map: dict[Exploit, list[Exploit]] = defaultdict(list)
        self.roots: list[Exploit] = []
        self._build_dag()

    @staticmethod
    def is_causally_correlated(earlier: Exploit, later: Exploit) -> bool:
        if normalize_timestamp(earlier.start_time) >= normalize_timestamp(later.start_time):
            return False

        src_pre, dst_pre = later.attack_type.get_preconditions()
        post = earlier.attack_type.postconditions

        if earlier.destination_ip == later.source_ip:
            for pre in src_pre:
                if post.intersection(pre.compromise_attributes):
                    return True
        if earlier.destination_ip == later.destination_ip:
            for pre in dst_pre:
                if post.intersection(pre.compromise_attributes):
                    return True
        return False

    @staticmethod
    def _latest_repetition_before(group: list[Exploit], target_step: Exploit) -> Exploit:
        target_time = normalize_timestamp(target_step.start_time)
        latest = group[0]
        for step in group:
            if normalize_timestamp(step.start_time) < target_time:
                latest = step
            else:
                break
        return latest

    @staticmethod
    def _find_clause_matching_groups(
        first_step: Exploit,
        prior_groups: list[tuple[str, list[Exploit]]],
    ) -> list[list[str]]:
        if not prior_groups:
            return []

        src_pre, dst_pre = first_step.attack_type.get_preconditions()
        clause_group_ids: list[list[str]] = []

        for pre in src_pre:
            matching_ids = [
                gid for gid, g in prior_groups
                if g[0].destination_ip == first_step.source_ip
                and bool(g[0].attack_type.postconditions.intersection(pre.compromise_attributes))
            ]
            if matching_ids:
                clause_group_ids.append(matching_ids)

        for pre in dst_pre:
            matching_ids = [
                gid for gid, g in prior_groups
                if g[0].destination_ip == first_step.destination_ip
                and bool(g[0].attack_type.postconditions.intersection(pre.compromise_attributes))
            ]
            if matching_ids:
                clause_group_ids.append(matching_ids)

        return clause_group_ids

    def _build_dag(self) -> None:
        self.clause_parents_map = defaultdict(list)
        self.parents_map = defaultdict(list)
        self.children_map = defaultdict(list)
        self.roots = []

        ordered_groups: list[tuple[str, list[Exploit]]] = sorted(
            [(gid, group) for gid, group in self.groups.items() if group],
            key=lambda item: normalize_timestamp(item[1][0].start_time),
        )

        for _, group in ordered_groups:
            for idx in range(1, len(group)):
                prev_step, curr_step = group[idx - 1], group[idx]
                self.clause_parents_map[curr_step] = [[prev_step]]
                self.parents_map[curr_step].append(prev_step)
                self.children_map[prev_step].append(curr_step)

        for g_idx, (_, group) in enumerate(ordered_groups):
            first_step = group[0]
            first_time = normalize_timestamp(first_step.start_time)
            prior_groups = [
                (p_gid, prior_g)
                for p_gid, prior_g in ordered_groups[:g_idx]
                if normalize_timestamp(prior_g[0].start_time) < first_time
            ]
            clause_gids_list = self._find_clause_matching_groups(first_step, prior_groups)

            clause_parents: list[list[Exploit]] = []
            unique_parents: list[Exploit] = []
            for clause_gids in clause_gids_list:
                or_parents = [
                    self._latest_repetition_before(self.groups[p_gid], first_step)
                    for p_gid in clause_gids
                ]
                if or_parents:
                    clause_parents.append(or_parents)
                    for parent in or_parents:
                        if parent not in unique_parents:
                            unique_parents.append(parent)

            self.clause_parents_map[first_step] = clause_parents
            self.parents_map[first_step] = unique_parents

            if not unique_parents:
                self.roots.append(first_step)
            else:
                for parent in unique_parents:
                    self.children_map[parent].append(first_step)

    def get_adjacent_pairs(self) -> set[tuple[Exploit, Exploit]]:
        pairs: set[tuple[Exploit, Exploit]] = set()
        for step in self.steps:
            for parent in self.parents_map.get(step, []):
                pairs.add((parent, step))
        return pairs

    def get_causal_pairs(self) -> set[tuple[Exploit, Exploit]]:
        pairs: set[tuple[Exploit, Exploit]] = set()
        for step in self.steps:
            stack = list(self.parents_map.get(step, []))
            visited = set(stack)
            while stack:
                ancestor = stack.pop()
                pairs.add((ancestor, step))
                for parent in self.parents_map.get(ancestor, []):
                    if parent not in visited:
                        visited.add(parent)
                        stack.append(parent)
        return pairs

    def get_chains(self) -> list[list[Exploit]]:
        if not self.steps:
            return []
        chains: list[list[Exploit]] = []

        for root in self.roots:
            path = [root]
            children = self.children_map.get(root, [])
            if not children:
                chains.append(list(path))
                continue
            stack = [iter(children)]
            while stack:
                child = next(stack[-1], None)
                if child is None:
                    stack.pop()
                    path.pop()
                    continue
                path.append(child)
                children = self.children_map.get(child, [])
                if children:
                    stack.append(iter(children))
                else:
                    chains.append(list(path))
                    path.pop()
        return chains

    def find_goal_steps(
        self,
        attack_goal: AttackGoal,
        unknown_attack_type: AttackType | None = None,
    ) -> list[Exploit]:
        return [
            step for step in self.steps
            if attack_goal.is_satisfied_by(step, unknown_attack_type)
        ]

    def get_path_edges_to_step(self, target_step: Exploit) -> set[tuple[Exploit, Exploit]]:
        edges: set[tuple[Exploit, Exploit]] = set()
        stack = [target_step]
        visited = {target_step}
        while stack:
            curr = stack.pop()
            for parent in self.parents_map.get(curr, []):
                edges.add((parent, curr))
                if parent not in visited:
                    visited.add(parent)
                    stack.append(parent)
        return edges

    def get_goal_clause_recovery(
        self,
        target_step: Exploit,
        predicted_causal_pairs: set[tuple[Exploit, Exploit]],
    ) -> tuple[int, int]:
        """Compute (recovered_clauses, required_clauses) for reaching `target_step` in the AND/OR DAG.

        Each Exploit step is an AND-node over its clauses in `clause_parents_map[step]`,
        and each clause is an OR-node over its candidate parent steps.
        """
        memo_score: dict[Exploit, tuple[int, int]] = {}
        selected_parents: dict[Exploit, list[Exploit]] = {}
        # Evaluate ancestors before their children without depending on Python's recursion limit.
        score_stack = [(target_step, False)]
        while score_stack:
            node, expanded = score_stack.pop()
            if node in memo_score:
                continue
            clauses = self.clause_parents_map.get(node, [])
            if not expanded:
                score_stack.append((node, True))
                score_stack.extend(
                    (parent, False)
                    for or_parents in clauses
                    for parent in or_parents
                    if parent not in memo_score
                )
                continue
            rec_total = 0
            req_total = 0
            selected_parents[node] = []
            for or_parents in clauses:
                best_rec, best_req = 0, 1
                best_key = (-1, -1.0, 0)
                best_parent = None
                for p in or_parents:
                    edge_ok = 1 if (p, node) in predicted_causal_pairs else 0
                    p_rec, p_req = memo_score[p]
                    cand_rec = edge_ok + p_rec
                    cand_req = 1 + p_req
                    cand_ratio = cand_rec / cand_req
                    cand_key = (edge_ok, cand_ratio, -cand_req)
                    if cand_key > best_key:
                        best_key = cand_key
                        best_rec, best_req = cand_rec, cand_req
                        best_parent = p
                rec_total += best_rec
                req_total += best_req
                if best_parent is not None:
                    selected_parents[node].append(best_parent)
            memo_score[node] = (rec_total, req_total)

        recovered_clauses = 0
        required_clauses = 0
        stack = [target_step]
        visited = {target_step}

        while stack:
            curr = stack.pop()
            for best_parent in selected_parents[curr]:
                required_clauses += 1
                if (best_parent, curr) in predicted_causal_pairs:
                    recovered_clauses += 1
                if best_parent not in visited:
                    visited.add(best_parent)
                    stack.append(best_parent)

        return recovered_clauses, required_clauses

    def get_ancestors_of_step(self, target_step: Exploit) -> set[Exploit]:
        ancestors: set[Exploit] = set()
        stack = list(self.parents_map.get(target_step, []))
        visited = set(stack)
        while stack:
            curr = stack.pop()
            ancestors.add(curr)
            for parent in self.parents_map.get(curr, []):
                if parent not in visited:
                    visited.add(parent)
                    stack.append(parent)
        return ancestors


class MetricsCalculator:

    @staticmethod
    def _ensure_dag(scenario: AttackScenarioDAG | list[Exploit]) -> AttackScenarioDAG:
        if isinstance(scenario, AttackScenarioDAG):
            return scenario
        return AttackScenarioDAG(scenario)

    @staticmethod
    def _ensure_steps(scenario: AttackScenarioDAG | list[Exploit]) -> list[Exploit]:
        if isinstance(scenario, AttackScenarioDAG):
            return scenario.steps
        return scenario

    # ------------------------------------------------------------------
    # 1. Flow / Intrusion Detection Confusion Matrices
    # ------------------------------------------------------------------

    @staticmethod
    def get_detection_confusion_matrix(
        scenario_df: pd.DataFrame,
        alert_threshold: float,
    ) -> tuple[int, int, int, int]:
        y_true = (scenario_df["label"] != "normal").astype(int)
        y_pred = scenario_df["anomaly_score"] > alert_threshold
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
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
                timestamp + timedelta(milliseconds=duration),
            )
            values.append(int(key in predicted_flows))

        tn, fp, fn, tp = confusion_matrix(
            (scenario_df["label"] != "normal").astype(int),
            values,
            labels=[0, 1],
        ).ravel()
        return int(tn), int(fp), int(fn), int(tp)

    # ------------------------------------------------------------------
    # 2. Alert-Level Matching, Precision, Recall & Step Aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _match_alerts_one_to_one(
        predicted_alerts: list[FlowExploit],
        actual_alerts: list[FlowExploit],
        unknown_attack_type: AttackType | None = None,
    ) -> list[tuple[int, FlowExploit, FlowExploit]]:
        actual_by_key = defaultdict(list)
        for a_idx, alert in enumerate(actual_alerts):
            actual_by_key[alert.metric_key].append((a_idx, alert))

        used_actual_indices: set[int] = set()
        matches: list[tuple[int, FlowExploit, FlowExploit]] = []

        for p_alert in predicted_alerts:
            for a_idx, candidate in actual_by_key.get(p_alert.metric_key, []):
                if (not unknown_attack_type and p_alert == candidate) or (
                    unknown_attack_type and candidate.unk_eq(p_alert, unknown_attack_type)
                ):
                    if a_idx not in used_actual_indices:
                        used_actual_indices.add(a_idx)
                        matches.append((a_idx, p_alert, candidate))
                        break
        return matches

    @staticmethod
    def get_alert_recall(
        predicted_alerts: list[FlowExploit],
        actual_alerts: list[FlowExploit],
        unknown_attack_type: AttackType | None = None,
    ) -> float:
        if not actual_alerts:
            return 1.0 if not predicted_alerts else 0.0
        matches = MetricsCalculator._match_alerts_one_to_one(
            predicted_alerts, actual_alerts, unknown_attack_type
        )
        return len(matches) / len(actual_alerts)

    @staticmethod
    def get_alert_precision(
        predicted_alerts: list[FlowExploit],
        actual_alerts: list[FlowExploit],
        unknown_attack_type: AttackType | None = None,
    ) -> float:
        if not predicted_alerts:
            return 1.0 if not actual_alerts else 0.0
        matches = MetricsCalculator._match_alerts_one_to_one(
            predicted_alerts, actual_alerts, unknown_attack_type
        )
        return len(matches) / len(predicted_alerts)

    @staticmethod
    def _build_pairs(
        alerts_by_step: dict[Exploit, list[tuple[int, FlowExploit]]]
    ) -> set[tuple[int, int]]:
        pairs: set[tuple[int, int]] = set()
        for alerts in alerts_by_step.values():
            alerts = sorted(alerts, key=lambda x: x[1].start_time)
            alert_ids = [alert_id for alert_id, _ in alerts]
            for a_id, b_id in combinations_with_replacement(alert_ids, 2):
                pairs.add((a_id, b_id))
        return pairs

    @staticmethod
    def _get_aggregation_correlation_pairs(
        actual_alerts: list[FlowExploit],
        actual_steps: list[Exploit],
        predicted_alerts: list[FlowExploit],
        predicted_steps: list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> tuple[set[tuple[int, int]], set[tuple[int, int]], set[tuple[int, int]]]:
        actual_matches_by_group = defaultdict(list)
        predicted_matches_by_group = defaultdict(list)

        for a_idx, p_alert, candidate in MetricsCalculator._match_alerts_one_to_one(
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

        predicted_pairs = MetricsCalculator._build_pairs(predicted_alerts_by_step)
        actual_pairs = MetricsCalculator._build_pairs(actual_alerts_by_step)
        return actual_pairs & predicted_pairs, predicted_pairs, actual_pairs

    @staticmethod
    def get_step_soundness_completeness(
        predicted_steps: AttackScenarioDAG | list[Exploit],
        actual_steps: AttackScenarioDAG | list[Exploit],
        predicted_alerts: list[FlowExploit],
        actual_alerts: list[FlowExploit],
        unknown_attack_type: AttackType | None = None,
    ) -> tuple[float, float]:
        p_steps = MetricsCalculator._ensure_steps(predicted_steps)
        a_steps = MetricsCalculator._ensure_steps(actual_steps)
        correctly_correlated, predicted_pairs, actual_pairs = (
            MetricsCalculator._get_aggregation_correlation_pairs(
                actual_alerts, a_steps, predicted_alerts, p_steps, unknown_attack_type
            )
        )
        completeness = len(correctly_correlated) / len(actual_pairs) if actual_pairs else 0.0
        soundness = len(correctly_correlated) / len(predicted_pairs) if predicted_pairs else 0.0
        return soundness, completeness

    # ------------------------------------------------------------------
    # 3. Step-Level Matching, Precision & Recall
    # ------------------------------------------------------------------

    @staticmethod
    def _match_steps_one_to_one(
        predicted_steps: list[Exploit],
        actual_steps: list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> dict[Exploit, Exploit]:
        used_actual: set[int] = set()
        matches: dict[Exploit, Exploit] = {}
        for p_step in predicted_steps:
            for a_idx, a_step in enumerate(actual_steps):
                if a_idx in used_actual:
                    continue
                if a_step.approx_match(p_step, unknown_attack_type):
                    matches[p_step] = a_step
                    used_actual.add(a_idx)
                    break
        return matches

    @staticmethod
    def get_scenario_step_recall(
        predicted_steps: AttackScenarioDAG | list[Exploit],
        actual_steps: AttackScenarioDAG | list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> float:
        p_steps = MetricsCalculator._ensure_steps(predicted_steps)
        a_steps = MetricsCalculator._ensure_steps(actual_steps)
        if not a_steps:
            return 1.0 if not p_steps else 0.0
        matches = MetricsCalculator._match_steps_one_to_one(
            p_steps, a_steps, unknown_attack_type
        )
        return len(matches) / len(a_steps)

    @staticmethod
    def get_scenario_step_precision(
        predicted_steps: AttackScenarioDAG | list[Exploit],
        actual_steps: AttackScenarioDAG | list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> float:
        p_steps = MetricsCalculator._ensure_steps(predicted_steps)
        a_steps = MetricsCalculator._ensure_steps(actual_steps)
        if not p_steps:
            return 1.0 if not a_steps else 0.0
        matches = MetricsCalculator._match_steps_one_to_one(
            p_steps, a_steps, unknown_attack_type
        )
        return len(matches) / len(p_steps)

    # ------------------------------------------------------------------
    # 4. Scenario-Level DAG Causal Soundness, Completeness & Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _get_causal_correlation_pairs(
        actual_scenario: AttackScenarioDAG | list[Exploit],
        predicted_scenario: AttackScenarioDAG | list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> tuple[set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]], set[tuple[Exploit, Exploit]]]:
        actual_dag = MetricsCalculator._ensure_dag(actual_scenario)
        predicted_dag = MetricsCalculator._ensure_dag(predicted_scenario)

        matches = MetricsCalculator._match_steps_one_to_one(
            predicted_dag.steps, actual_dag.steps, unknown_attack_type
        )
        matched_actual_set = set(matches.values())

        actual_pairs = {
            (u, v)
            for u, v in actual_dag.get_causal_pairs()
            if u in matched_actual_set and v in matched_actual_set
        }
        predicted_pairs = {
            (matches[u], matches[v])
            for u, v in predicted_dag.get_causal_pairs()
            if u in matches and v in matches
        }

        return actual_pairs, predicted_pairs, predicted_pairs & actual_pairs

    @staticmethod
    def get_scenario_soundness_completeness(
        predicted_scenario: AttackScenarioDAG | list[Exploit],
        actual_scenario: AttackScenarioDAG | list[Exploit],
        unknown_attack_type: AttackType | None = None,
    ) -> tuple[float, float]:
        actual_dag = MetricsCalculator._ensure_dag(actual_scenario)
        predicted_dag = MetricsCalculator._ensure_dag(predicted_scenario)

        matches = MetricsCalculator._match_steps_one_to_one(
            predicted_dag.steps, actual_dag.steps, unknown_attack_type
        )
        matched_actual_set = set(matches.values())

        actual_pairs = {
            (u, v)
            for u, v in actual_dag.get_causal_pairs()
            if u in matched_actual_set and v in matched_actual_set
        }
        predicted_pairs = {
            (matches[u], matches[v])
            for u, v in predicted_dag.get_causal_pairs()
            if u in matches and v in matches
        }
        correct_pairs = predicted_pairs & actual_pairs

        if not predicted_pairs:
            soundness = 1.0 if not actual_pairs else 0.0
        else:
            soundness = len(correct_pairs) / len(predicted_pairs)

        required_clauses = 0
        satisfied_clauses = 0
        for step in actual_dag.steps:
            if step not in matched_actual_set:
                continue
            for or_parents in actual_dag.clause_parents_map.get(step, []):
                candidates: set[Exploit] = set()
                stack = list(or_parents)
                visited: set[Exploit] = set()
                while stack:
                    parent = stack.pop()
                    if parent in visited:
                        continue
                    visited.add(parent)
                    if parent in matched_actual_set:
                        candidates.add(parent)
                    else:
                        # Only bypass missing steps: a matched intermediate must satisfy its own edge.
                        stack.extend(actual_dag.parents_map.get(parent, []))
                if candidates:
                    required_clauses += 1
                    if any((u, step) in predicted_pairs for u in candidates):
                        satisfied_clauses += 1

        if required_clauses == 0:
            completeness = 1.0 if not predicted_pairs else 0.0
        else:
            completeness = satisfied_clauses / required_clauses

        return soundness, completeness

    @staticmethod
    def is_scenario_detected(
        predicted_scenario: AttackScenarioDAG | list[Exploit],
        actual_scenario: AttackScenarioDAG | list[Exploit],
        attack_goal: AttackGoal,
        unknown_attack_type: AttackType | None = None,
        edge_recovery_threshold: float = 0.8,
    ) -> bool:
        """Evaluate on a single scenario whether the attack goal and its root-to-goal AND/OR subgraph are recovered."""
        actual_dag = MetricsCalculator._ensure_dag(actual_scenario)
        predicted_dag = MetricsCalculator._ensure_dag(predicted_scenario)

        if not actual_dag.steps or not predicted_dag.steps:
            return False

        actual_goal_steps = actual_dag.find_goal_steps(attack_goal)
        if not actual_goal_steps:
            return False

        matches = MetricsCalculator._match_steps_one_to_one(
            predicted_dag.steps, actual_dag.steps, unknown_attack_type
        )
        matched_actual_set = set(matches.values())

        predicted_causal_pairs = {
            (matches[u], matches[v])
            for u, v in predicted_dag.get_causal_pairs()
            if u in matches and v in matches
        }

        for goal_step in actual_goal_steps:
            if goal_step not in matched_actual_set:
                continue
            recovered_clauses, required_clauses = actual_dag.get_goal_clause_recovery(
                goal_step, predicted_causal_pairs
            )
            if required_clauses == 0:
                return True
            if recovered_clauses / required_clauses >= edge_recovery_threshold:
                return True

        return False
