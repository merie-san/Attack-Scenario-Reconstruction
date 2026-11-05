"""Causal evaluation helpers."""

from scenario_reconstructor.dag import AttackGoal, AttackScenarioDAG
from scenario_reconstructor.models import AttackStep, AttackType

from .matching import ensure_dag_pair, mapped_causal_pairs, match_steps


def _correlation_pairs(
    actual_dag: AttackScenarioDAG,
    predicted_dag: AttackScenarioDAG,
    matches: dict[AttackStep, AttackStep],
) -> tuple[set[tuple[AttackStep, AttackStep]], set[tuple[AttackStep, AttackStep]], set[tuple[AttackStep, AttackStep]]]:
    matched_actual_set = set(matches.values())

    actual_pairs = {
        (u, v)
        for u, v in actual_dag.get_causal_pairs()
        if u in matched_actual_set and v in matched_actual_set
    }
    predicted_pairs = mapped_causal_pairs(predicted_dag, matches)

    return actual_pairs, predicted_pairs, predicted_pairs & actual_pairs


def causal_pairs(
    actual_scenario: AttackScenarioDAG | list[AttackStep],
    predicted_scenario: AttackScenarioDAG | list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> tuple[set[tuple[AttackStep, AttackStep]], set[tuple[AttackStep, AttackStep]], set[tuple[AttackStep, AttackStep]]]:
    """Return actual, predicted, and correct dependencies among matched occurrences."""
    actual_dag, predicted_dag = ensure_dag_pair(actual_scenario, predicted_scenario)
    matches = match_steps(predicted_dag.steps, actual_dag.steps, unknown_attack_type)
    return _correlation_pairs(actual_dag, predicted_dag, matches)


def causal_quality(
    predicted_scenario: AttackScenarioDAG | list[AttackStep],
    actual_scenario: AttackScenarioDAG | list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> tuple[float, float]:
    """Score causal reachability and AND/OR clauses; occurrence coverage is separate."""
    actual_dag, predicted_dag = ensure_dag_pair(actual_scenario, predicted_scenario)

    matches = match_steps(
        predicted_dag.steps, actual_dag.steps, unknown_attack_type
    )
    matched_actual_set = set(matches.values())

    actual_pairs, predicted_pairs, correct_pairs = _correlation_pairs(actual_dag, predicted_dag, matches)

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
            candidates: set[AttackStep] = set()
            stack = list(or_parents)
            visited: set[AttackStep] = set()
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


def scenario_detected(
    predicted_scenario: AttackScenarioDAG | list[AttackStep],
    actual_scenario: AttackScenarioDAG | list[AttackStep],
    attack_goal: AttackGoal,
    unknown_attack_type: AttackType | None = None,
    edge_recovery_threshold: float = 0.8,
) -> bool:
    """Evaluate on a single scenario whether the attack goal and its root-to-goal AND/OR subgraph are recovered."""
    actual_dag, predicted_dag = ensure_dag_pair(actual_scenario, predicted_scenario)

    if not actual_dag.steps or not predicted_dag.steps:
        return False

    actual_goal_steps = actual_dag.find_goal_steps(attack_goal)
    if not actual_goal_steps:
        return False

    matches = match_steps(
        predicted_dag.steps, actual_dag.steps, unknown_attack_type
    )
    matched_actual_set = set(matches.values())

    predicted_causal_pairs = mapped_causal_pairs(predicted_dag, matches)

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
