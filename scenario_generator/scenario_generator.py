"""Compatibility import for the original cAPTure generator name."""
from .generator import ScenarioGenerator

CAPTureScenarioGenerator = ScenarioGenerator
__all__ = ["ScenarioGenerator", "CAPTureScenarioGenerator"]
