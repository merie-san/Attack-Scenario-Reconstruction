"""Feasible hierarchical choices and bounded, iterative scenario backtracking."""
import copy
import random
from dataclasses import dataclass
from collections.abc import Hashable
from .exceptions import NoFeasibleScenarioError, ScenarioSearchLimitError


@dataclass(frozen=True)
class GenerationRules:
    next_attacks: dict[str, list[str]]
    possible_sources: dict[str, list[str]]
    possible_destinations: dict[str, list[str]]
    enables_source_for: dict[str, list[str]]
    enables_destination_for: dict[str, list[str]]
    restricted_destinations: dict[str, list[str]]
    final_attack: str
    enabling_attacks: list[str]


@dataclass
class _SearchFrame:
    sources: dict[str, list[str]]
    destinations: dict[str, list[str]]
    choices: dict[str, dict[str, list[str]]]

    def take_choice(self) -> tuple[str, str, str] | None:
        """Sample hierarchically and remove this exact choice from the frame."""
        attack = random.choice(list(self.choices))
        if attack == "end":
            del self.choices[attack]
            return None
        sources = self.choices[attack]
        source = random.choice(list(sources))
        destination = random.choice(sources[source])
        sources[source].remove(destination)
        if not sources[source]:
            del sources[source]
        if not sources:
            del self.choices[attack]
        return attack, source, destination


class ScenarioSearch:
    """Search using configured rules and per-branch copies of enabled-host state."""

    def __init__(self, rules: GenerationRules, available_attacks: set[Hashable]) -> None:
        self.rules = rules
        self.available_attacks = available_attacks

    def _feasible_choices(
        self, current_attack: str, sources: dict[str, list[str]], destinations: dict[str, list[str]],
    ) -> dict[str, dict[str, list[str]]]:
        choices: dict[str, dict[str, list[str]]] = {}
        final_targets = self.rules.restricted_destinations.get(self.rules.final_attack)
        final_enabled = final_targets is None or any(
            target in destinations.get(self.rules.final_attack, []) for target in final_targets
        )
        for attack in self.rules.next_attacks.get(current_attack, []):
            if attack == "end":
                choices[attack] = {}
                continue
            if attack not in self.available_attacks:
                continue
            restricted_targets = self.rules.restricted_destinations.get(attack)
            by_source = {}
            for source in sources.get(attack, []):
                targets = [
                    target for target in dict.fromkeys(destinations.get(attack, []))
                    if target != source
                    and (restricted_targets is None or target in restricted_targets)
                    and (attack not in self.rules.enabling_attacks or final_enabled or target in (final_targets or []))
                ]
                if targets:
                    by_source[source] = targets
            if by_source:
                choices[attack] = by_source
        return choices

    def find_path(self, max_steps: int, max_search_attempts: int) -> list[tuple[str, str, str]]:
        sources = copy.deepcopy(self.rules.possible_sources)
        destinations = copy.deepcopy(self.rules.possible_destinations)
        frames = [_SearchFrame(sources, destinations, self._feasible_choices("start", sources, destinations))]
        path: list[tuple[str, str, str]] = []
        attempts = 0
        depth_limited = False
        while frames:
            frame = frames[-1]
            if not frame.choices:
                frames.pop()
                if path:
                    path.pop()
                continue
            if attempts >= max_search_attempts:
                raise ScenarioSearchLimitError("max_search_attempts", max_search_attempts, attempts)
            choice = frame.take_choice()
            attempts += 1
            if choice is None:
                return path
            attack, source, destination = choice
            if len(path) >= max_steps:
                depth_limited = True
                continue

            child_sources = copy.deepcopy(frame.sources)
            child_destinations = copy.deepcopy(frame.destinations)
            for mapping, enabled_attacks in (
                (child_sources, self.rules.enables_source_for.get(attack, [])),
                (child_destinations, self.rules.enables_destination_for.get(attack, [])),
            ):
                for enabled_attack in enabled_attacks:
                    hosts = mapping.setdefault(enabled_attack, [])
                    if destination not in hosts:
                        hosts.append(destination)
            path.append((attack, source, destination))
            frames.append(_SearchFrame(
                child_sources, child_destinations,
                self._feasible_choices(attack, child_sources, child_destinations),
            ))

        if depth_limited:
            raise ScenarioSearchLimitError("max_steps", max_steps, attempts)
        raise NoFeasibleScenarioError("No feasible scenario reaches an allowed end with the configured hosts and templates")
