"""Compatibility imports for the reconstruction manager and alert factory."""

from .alerts import AlertFactory
from .manager import ReconstructionManager, RecoveryPlan


ExploitGenerator = AlertFactory
ScenarioReconstructionManager = ReconstructionManager
__all__ = ["AlertFactory", "ReconstructionManager", "RecoveryPlan", "ExploitGenerator", "ScenarioReconstructionManager"]
