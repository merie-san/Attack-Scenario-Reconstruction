"""Dataset-specific scenario definitions, independent of experiment execution."""
from .loader import ScenarioConfig, load_scenario_config

__all__ = ["ScenarioConfig", "load_scenario_config"]
