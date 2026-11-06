"""Public failures callers can handle when requesting a generated scenario."""


class ScenarioGenerationError(RuntimeError):
    """Base class for an unsuccessful scenario generation request."""


class NoFeasibleScenarioError(ScenarioGenerationError):
    """All available choices were exhausted without reaching an allowed end."""


class ScenarioSearchLimitError(ScenarioGenerationError):
    """Search was bounded; failure does not prove that no valid scenario exists."""

    def __init__(self, limit_name: str, limit: int, attempts: int) -> None:
        self.limit_name = limit_name
        self.limit = limit
        self.attempts = attempts
        super().__init__(f"Scenario search reached {limit_name}={limit} after {attempts} choice attempts")
