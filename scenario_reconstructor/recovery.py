"""Explicit proposals exchanged by recovery planning and atomic acceptance."""

from dataclasses import dataclass

from .models import FlowAlert


@dataclass(frozen=True)
class RecoveryPlan:
    """A validated proposal; supporting alerts become recovered FNs upon commit."""

    alert: FlowAlert
    recovered_alerts: tuple[FlowAlert, ...] = ()
    suspect_group_id: str | None = None
    source_suspects: tuple[FlowAlert, ...] = ()


@dataclass(frozen=True)
class RecoveryCandidate:
    """A uniform cluster hypothesis, ranked before full-sequence validation."""

    is_primary: bool
    score: float
    source_group_id: str
    alerts: tuple[FlowAlert, ...]
    source_suspects: tuple[FlowAlert, ...]
