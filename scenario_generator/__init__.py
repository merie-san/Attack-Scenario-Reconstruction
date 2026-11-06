"""Scenario generation with explicit search limits and caller-visible failures."""
from .exceptions import NoFeasibleScenarioError, ScenarioGenerationError, ScenarioSearchLimitError
from .generator import ScenarioGenerator

CAPTureScenarioGenerator = ScenarioGenerator
__all__ = ["ScenarioGenerator", "CAPTureScenarioGenerator", "ScenarioGenerationError",
           "NoFeasibleScenarioError", "ScenarioSearchLimitError"]
