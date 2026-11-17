"""Public scenario generation API coordinating validation, search, and rendering."""
import random
from collections.abc import Hashable, Sequence
from datetime import datetime, timedelta
from numbers import Integral
from typing import cast
import pandas as pd
from scenario_reconstructor.models import AttackStep, AttackType, FlowAlert
from .exceptions import ScenarioGenerationError
from .rendering import RenderedScenario, render_scenario
from .search import GenerationRules, ScenarioSearch
from .validation import validate_templates


class ScenarioGenerator:
    """Generate complete scenarios while retaining the last successful result."""

    def __init__(self, dataframe: pd.DataFrame, next_attack_dict: dict[str, list[str]],
                 enable_src_for: dict[str, list[str]], enable_dst_for: dict[str, list[str]],
                 possible_srcs: dict[str, list[str]], possible_dsts: dict[str, list[str]],
                 dst_restricted_atks: dict[str, list[str]], final_atk: str, enabling_atks: list[str]) -> None:
        templates = validate_templates(dataframe)
        self.data_source: dict[Hashable, dict[Hashable, pd.DataFrame]] = {}
        self.enable_src_for = enable_src_for
        self.enable_dst_for = enable_dst_for
        self.next_attack_dict = next_attack_dict
        self._publish_result(RenderedScenario())
        for (label, step_number), group in templates.groupby(["label", "step_number"]):
            self.data_source.setdefault(label, {})[step_number] = group
        self.possible_srcs = possible_srcs
        self.possible_dsts = possible_dsts
        self.dst_restricted_atks = dst_restricted_atks
        self.final_atk = final_atk
        self.enabling_atks = enabling_atks

    def _publish_result(self, rendered: RenderedScenario) -> None:
        """Expose completed metadata using the established generator attributes."""
        self.attack_names = rendered.attack_names
        self.step_id_list = rendered.step_id_list
        self.attack_times = rendered.attack_times
        self.attack_ips = rendered.attack_ips
        self.sizes = rendered.sizes
        self.ift_mean = rendered.ift_mean
        self.ift_std = rendered.ift_std
        self.result = rendered.result

    def _search_scenario(self, max_steps: int, max_search_attempts: int):
        rules = GenerationRules(
            self.next_attack_dict, self.possible_srcs, self.possible_dsts,
            self.enable_src_for, self.enable_dst_for, self.dst_restricted_atks,
            self.final_atk, self.enabling_atks,
        )
        return ScenarioSearch(rules, set(self.data_source)).find_path(max_steps, max_search_attempts)

    def generate_scenario(self, normal_flow_number_divisor: int = 1, *,
                          max_steps: int = 100, max_search_attempts: int = 10_000,
                          path: Sequence[tuple[str, str, str]] | None = None) -> pd.DataFrame:
        """Render an explicit path or search for one, preserving the last result on failure."""
        if not isinstance(normal_flow_number_divisor, Integral):
            raise TypeError("normal_flow_number_divisor must be an integer")
        if normal_flow_number_divisor <= 0:
            raise ValueError("normal_flow_number_divisor must be positive")
        for name, value in (("max_steps", max_steps), ("max_search_attempts", max_search_attempts)):
            if not isinstance(value, Integral):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if "normal" not in self.data_source or -1 not in self.data_source["normal"]:
            raise ScenarioGenerationError("The dataset must contain normal flows with step_number=-1")
        if path is None:
            path = self._search_scenario(max_steps, max_search_attempts)
        else:
            if isinstance(path, (str, bytes)) or not isinstance(path, Sequence):
                raise TypeError("Explicit scenario path must be a sequence of steps")
            normalized = []
            for step in path:
                if (isinstance(step, (str, bytes)) or not isinstance(step, Sequence)
                        or len(step) != 3 or not all(isinstance(item, str) and item.strip() for item in step)):
                    raise ValueError("Each scenario step must contain three non-empty strings: attack, src_ip, dst_ip")
                attack_name, src_ip, dst_ip = (item.strip() for item in step)
                if src_ip == dst_ip:
                    raise ScenarioGenerationError("Scenario step source and destination IPs must differ")
                if attack_name == "normal" or attack_name not in self.data_source:
                    raise ScenarioGenerationError(f"Unknown or unavailable attack type in path: {attack_name}")
                normalized.append((attack_name, src_ip, dst_ip))
            if not normalized:
                raise ScenarioGenerationError("Explicit scenario path must contain at least one step")
            path = normalized
        rendered = render_scenario(path, self.data_source, normal_flow_number_divisor)
        self._publish_result(rendered)
        return self.result

    @staticmethod
    def choose_dst_src_ips(current_attack, possible_dsts: dict[str, list[str]],
                           possible_srcs: dict[str, list[str]]) -> \
            tuple[list[str], str]:
        possible_srcs_list = possible_srcs.get(current_attack)
        if not possible_srcs_list or len(possible_srcs_list) == 0:
            raise RuntimeError(
                f"No possible source IPs found for {current_attack}")
        src_ip = random.choice(possible_srcs_list)
        possible_dsts_list = possible_dsts.get(current_attack)
        if not possible_dsts_list or len(possible_dsts_list) == 0:
            raise RuntimeError(
                f"No possible destination IPs found for {current_attack}")
        return possible_dsts_list, src_ip

    def export_results(self, attack_types: list[AttackType]) -> tuple[
        list[AttackStep], list[FlowAlert]]:
        attack_steps = []
        alerts = []
        attack_type_dict = {attack.identifier: attack for attack in attack_types}
        for i in range(len(self.attack_names)):
            attack_name = self.attack_names[i]
            start_time, end_time = self.attack_times[i]
            src_ip, dst_ip = self.attack_ips[i]
            size = self.sizes[i]
            ift_mean = self.ift_mean[i]
            ift_std = self.ift_std[i]
            attack = attack_type_dict[attack_name]
            attack_steps.append(
                AttackStep(attack, size, src_ip, dst_ip, start_time, end_time, ift_mean, ift_std))
        alert_flows = self.result[self.result["label"] != "normal"]
        for row in alert_flows.itertuples():
            alerts.append(
                FlowAlert(attack_type_dict[cast(str, row.label)], [], cast(str, row.src_ip), cast(str, row.src_port),
                            cast(str, row.dst_ip), cast(str, row.dst_port), cast(str, row.protocol),
                            cast(datetime, row.timestamp), cast(datetime, row.timestamp) + timedelta(
                        milliseconds=cast(int, row.duration)), cast(float, row.anomaly_score)))
        return attack_steps, alerts
