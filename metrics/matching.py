"""Matching evaluation helpers."""

from collections import defaultdict

from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import AttackStep, AttackType, FlowAlert


def ensure_steps(scenario: AttackScenarioDAG | list[AttackStep]) -> list[AttackStep]:
    if isinstance(scenario, AttackScenarioDAG):
        return scenario.steps
    return scenario


def ensure_dag_pair(
    actual_scenario: AttackScenarioDAG | list[AttackStep],
    predicted_scenario: AttackScenarioDAG | list[AttackStep],
) -> tuple[AttackScenarioDAG, AttackScenarioDAG]:
    """Apply an explicit tracking policy to both sides of a metric comparison."""
    policies = [scenario.tracked_host_ips for scenario in (actual_scenario, predicted_scenario)
                if isinstance(scenario, AttackScenarioDAG) and scenario.tracked_host_ips is not None]
    if policies and any(policy != policies[0] for policy in policies):
        raise ValueError('Actual and predicted DAGs must use the same tracked hosts')
    policy = policies[0] if policies else None
    dags = []
    for scenario in (actual_scenario, predicted_scenario):
        if isinstance(scenario, AttackScenarioDAG) and scenario.tracked_host_ips == policy:
            dags.append(scenario)
        else:
            dags.append(AttackScenarioDAG(ensure_steps(scenario), tracked_host_ips=policy))
    return dags[0], dags[1]


def match_alerts(
    predicted_alerts: list[FlowAlert],
    actual_alerts: list[FlowAlert],
    unknown_attack_type: AttackType | None = None,
) -> list[tuple[int, FlowAlert, FlowAlert]]:
    actual_by_key = defaultdict(list)
    for a_idx, alert in enumerate(actual_alerts):
        actual_by_key[alert.metric_key].append((a_idx, alert))

    used_actual_indices: set[int] = set()
    matches: list[tuple[int, FlowAlert, FlowAlert]] = []

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


def match_steps(
    predicted_steps: list[AttackStep],
    actual_steps: list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> dict[AttackStep, AttackStep]:
    used_actual: set[int] = set()
    matches: dict[AttackStep, AttackStep] = {}
    for p_step in predicted_steps:
        for a_idx, a_step in enumerate(actual_steps):
            if a_idx in used_actual:
                continue
            if a_step.approx_match(p_step, unknown_attack_type):
                matches[p_step] = a_step
                used_actual.add(a_idx)
                break
    return matches


def mapped_causal_pairs(
    predicted_dag: AttackScenarioDAG, matches: dict[AttackStep, AttackStep],
) -> set[tuple[AttackStep, AttackStep]]:
    """Project pure dependency reachability into matched actual-step identities."""
    return {(matches[parent], matches[child])
            for parent, child in predicted_dag.get_causal_pairs()
            if parent in matches and child in matches}
