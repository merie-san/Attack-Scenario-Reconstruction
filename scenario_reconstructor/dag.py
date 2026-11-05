"""Temporal AND/OR dependencies, goal explanations, and separate repetitions."""

from collections import defaultdict
from collections.abc import Iterable

from .models import AttackStep, AttackType
from .time_utils import normalize_timestamp


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
        step: AttackStep,
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
    - Each precondition clause acts as an OR-node (`list[Exploit]`) containing all
      earlier occurrences whose postconditions support it on the relevant host.
      Every occurrence receives its own precondition clauses.
    - Consecutive repetitions are exposed by get_repetition_pairs(), independently
      of the causal maps. Sharing a context alone never establishes causation.
    - When tracked_host_ips is supplied, only effects on those hosts establish
      state dependencies. Repetition pairs remain available for every group.
    """

    def __init__(self, steps: list[AttackStep], *, tracked_host_ips: Iterable[str] | None = None) -> None:
        # None preserves unrestricted inference for standalone DAG callers.
        self.tracked_host_ips = None if tracked_host_ips is None else frozenset(tracked_host_ips)
        self.steps: list[AttackStep] = sorted(steps, key=lambda s: normalize_timestamp(s.start_time))
        self.groups: dict[str, list[AttackStep]] = defaultdict(list)
        seen_by_group: dict[str, set[AttackStep]] = defaultdict(set)
        for step in self.steps:
            gid = step.get_exploit_group_id()
            # Keep duplicate inputs in steps for precision/recall, but only one DAG node per value.
            if step not in seen_by_group[gid]:
                seen_by_group[gid].add(step)
                self.groups[gid].append(step)

        self.clause_parents_map: dict[AttackStep, list[list[AttackStep]]] = defaultdict(list)
        self.parents_map: dict[AttackStep, list[AttackStep]] = defaultdict(list)
        self.children_map: dict[AttackStep, list[AttackStep]] = defaultdict(list)
        self.roots: list[AttackStep] = []
        self._build_dag()

    def _tracks_host(self, ip_address: str) -> bool:
        return self.tracked_host_ips is None or ip_address in self.tracked_host_ips

    def is_causally_correlated(self, earlier: AttackStep, later: AttackStep) -> bool:
        if not self._tracks_host(earlier.destination_ip):
            return False
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

    def _find_clause_parents(self, step: AttackStep, prior_steps: list[AttackStep]) -> list[list[AttackStep]]:
        """Return observed OR-supporters for each supported precondition clause."""
        start = normalize_timestamp(step.start_time)
        eligible = [parent for parent in prior_steps
                    if normalize_timestamp(parent.start_time) < start
                    and self._tracks_host(parent.destination_ip)]
        source_preconditions, destination_preconditions = step.attack_type.get_preconditions()
        clauses = []
        for host_ip, preconditions in ((step.source_ip, source_preconditions),
                                       (step.destination_ip, destination_preconditions)):
            for precondition in preconditions:
                supporters = [parent for parent in eligible
                              if parent.destination_ip == host_ip
                              and parent.attack_type.postconditions.intersection(precondition.compromise_attributes)]
                if supporters:
                    clauses.append(supporters)
        return clauses

    def _build_dag(self) -> None:
        self.clause_parents_map = defaultdict(list)
        self.parents_map = defaultdict(list)
        self.children_map = defaultdict(list)
        self.roots = []

        prior_steps: list[AttackStep] = []
        # Preserve duplicate inputs in self.steps for occurrence metrics, but build
        # graph nodes and dependencies only once per distinct step value.
        for step in dict.fromkeys(self.steps):
            clauses = self._find_clause_parents(step, prior_steps)
            parents = list(dict.fromkeys(parent for clause in clauses for parent in clause))
            self.clause_parents_map[step] = clauses
            self.parents_map[step] = parents
            if not parents:
                self.roots.append(step)
            for parent in parents:
                self.children_map[parent].append(step)
            prior_steps.append(step)

    def get_repetition_pairs(self) -> set[tuple[AttackStep, AttackStep]]:
        """Return consecutive distinct occurrences per context, without causal meaning."""
        return {(previous, current) for group in self.groups.values()
                for previous, current in zip(group, group[1:])}

    def get_adjacent_pairs(self) -> set[tuple[AttackStep, AttackStep]]:
        pairs: set[tuple[AttackStep, AttackStep]] = set()
        for step in self.steps:
            for parent in self.parents_map.get(step, []):
                pairs.add((parent, step))
        return pairs

    def get_causal_pairs(self) -> set[tuple[AttackStep, AttackStep]]:
        """Return reachability through state dependencies, excluding mere repetition."""
        pairs: set[tuple[AttackStep, AttackStep]] = set()
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

    def get_chains(self) -> list[list[AttackStep]]:
        if not self.steps:
            return []
        chains: list[list[AttackStep]] = []

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
    ) -> list[AttackStep]:
        return [
            step for step in self.steps
            if attack_goal.is_satisfied_by(step, unknown_attack_type)
        ]

    def get_path_edges_to_step(self, target_step: AttackStep) -> set[tuple[AttackStep, AttackStep]]:
        edges: set[tuple[AttackStep, AttackStep]] = set()
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
        target_step: AttackStep,
        predicted_causal_pairs: set[tuple[AttackStep, AttackStep]],
    ) -> tuple[int, int]:
        """Compute (recovered_clauses, required_clauses) for reaching `target_step` causally.

        Each Exploit step is an AND-node over its clauses in `clause_parents_map[step]`,
        and each clause is an OR-node over its candidate parent steps.
        Repetition pairs do not create clauses or increase the recovery denominator.
        """
        memo_score: dict[AttackStep, tuple[int, int]] = {}
        selected_parents: dict[AttackStep, list[AttackStep]] = {}
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

    def get_ancestors_of_step(self, target_step: AttackStep) -> set[AttackStep]:
        ancestors: set[AttackStep] = set()
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
