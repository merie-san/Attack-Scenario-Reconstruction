"""Occurrence evaluation helpers."""

from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import AttackStep, AttackType

from .matching import ensure_steps, match_steps


def step_recall(
    predicted_steps: AttackScenarioDAG | list[AttackStep],
    actual_steps: AttackScenarioDAG | list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> float:
    """Measure recovery of individual temporal occurrences, including repetitions."""
    p_steps = ensure_steps(predicted_steps)
    a_steps = ensure_steps(actual_steps)
    if not a_steps:
        return 1.0 if not p_steps else 0.0
    matches = match_steps(
        p_steps, a_steps, unknown_attack_type
    )
    return len(matches) / len(a_steps)


def step_precision(
    predicted_steps: AttackScenarioDAG | list[AttackStep],
    actual_steps: AttackScenarioDAG | list[AttackStep],
    unknown_attack_type: AttackType | None = None,
) -> float:
    """Measure accuracy of individual predicted occurrences, including repetitions."""
    p_steps = ensure_steps(predicted_steps)
    a_steps = ensure_steps(actual_steps)
    if not p_steps:
        return 1.0 if not a_steps else 0.0
    matches = match_steps(
        p_steps, a_steps, unknown_attack_type
    )
    return len(matches) / len(p_steps)
