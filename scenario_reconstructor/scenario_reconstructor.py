"""Compatibility imports; new code should use models, dag, engine, and serialization."""

from .dag import AttackGoal, AttackScenarioDAG
from .engine import ScenarioReconstructor
from .models import (
    AttackStep,
    AttackType,
    FlowAlert,
    Host,
    HostAttribute,
    NetworkState,
    Precondition,
    RecoveryRequirement,
)
from .serialization import AlertStepParser, NetworkStateParser
from .time_utils import normalize_timestamp


FlowExploit = FlowAlert
Exploit = AttackStep
Preconditions = Precondition
ExploitRequirement = RecoveryRequirement
StarNetworkAttackGraphBasedScenarioReconstructor = ScenarioReconstructor
StringToExploitConverter = AlertStepParser
StringToNetworkStateConvertor = NetworkStateParser

__all__ = ["AttackGoal", "AttackScenarioDAG", "ScenarioReconstructor", "AttackStep", "AttackType",
           "FlowAlert", "Host", "HostAttribute", "NetworkState", "Precondition", "RecoveryRequirement",
           "AlertStepParser", "NetworkStateParser", "normalize_timestamp", "FlowExploit", "Exploit",
           "Preconditions", "ExploitRequirement", "StarNetworkAttackGraphBasedScenarioReconstructor",
           "StringToExploitConverter", "StringToNetworkStateConvertor"]
