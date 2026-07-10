from collections.abc import Hashable
from typing import Any, cast

from scenario_reconstructor.reconstruction_manager import Exploit, FlowExploit, AttackType
import random
from datetime import timedelta, datetime
import pandas as pd
import numpy as np
import copy


class CAPTureScenarioGenerator:

    def __init__(self, dataframe: pd.DataFrame, next_attack_dict: dict[str, list[str]],
                 enable_src_for: dict[str, list[str]], enable_dst_for: dict[str, list[str]],
                 possible_srcs: dict[str, list[str]], possible_dsts: dict[str, list[str]],
                 dst_restricted_atks: dict[str, list[str]], final_atk: str, enabling_atks: list[str]) -> None:
        self.data_source: dict[Hashable, dict[Hashable, pd.DataFrame]] = {}
        self.result: pd.DataFrame = pd.DataFrame()
        self.enable_src_for = enable_src_for
        self.enable_dst_for = enable_dst_for
        self.next_attack_dict = next_attack_dict
        self.attack_names: list[str] = []
        self.attack_times: list[tuple[datetime, datetime]] = []
        self.attack_ips: list[tuple[str, str]] = []
        self.step_id_list: list[int] = []
        self.sizes: list[int] = []
        self.ift_mean: list[float] = []
        self.ift_std: list[float] = []
        dataframe["timestamp"] = pd.to_datetime(dataframe["timestamp"])
        for (label, step_number), group in dataframe.groupby(["label", "step_number"]):
            self.data_source.setdefault(label, {})[step_number] = group
        self.possible_srcs = possible_srcs
        self.possible_dsts = possible_dsts
        self.dst_restricted_atks = dst_restricted_atks
        self.final_atk = final_atk
        self.enabling_atks = enabling_atks

    def generate_scenario(self, normal_flow_number_divisor: int = 1) -> pd.DataFrame:
        scenario = []
        src_dst_ips = []
        srt_end_times = []
        current_attack = "start"
        possible_srcs = copy.deepcopy(self.possible_srcs)
        possible_dsts = copy.deepcopy(self.possible_dsts)
        while True:
            next_attacks = self.next_attack_dict.get(current_attack, [])
            if not next_attacks:
                raise RuntimeError(
                    f"No next attacks or end found for {current_attack}")

            current_attack = random.choice(next_attacks)

            if current_attack == "end":
                break
            else:
                possible_dsts_list, src_ip = self.choose_dst_src_ips(current_attack, possible_dsts, possible_srcs)
                finished = False
                while len([dst for dst in possible_dsts_list if
                           dst != src_ip] if current_attack not in self.dst_restricted_atks else [
                    dst for dst in possible_dsts_list if
                    dst != src_ip and dst in self.dst_restricted_atks[current_attack]]) == 0:
                    current_attack = random.choice(next_attacks)
                    if current_attack == "end":
                        finished = True
                        break
                    possible_dsts_list, src_ip = self.choose_dst_src_ips(current_attack, possible_dsts, possible_srcs)

                if finished:
                    break

                while True:
                    dst_ip = random.choice([dst for dst in possible_dsts_list if
                                            dst != src_ip] if current_attack not in self.dst_restricted_atks else [
                        dst for dst in possible_dsts_list if
                        dst != src_ip and dst in self.dst_restricted_atks[current_attack]])
                    if current_attack not in self.enabling_atks or self.final_atk not in self.dst_restricted_atks or dst_ip in \
                            self.dst_restricted_atks[self.final_atk] or any(
                        [rqd_dst_ip in possible_dsts[self.final_atk] for rqd_dst_ip in
                         self.dst_restricted_atks[self.final_atk]]):
                        break

                scenario.append(current_attack)

                if current_attack in self.enable_src_for:
                    for atk in self.enable_src_for[current_attack]:
                        possible_srcs[atk].append(dst_ip)

                if current_attack in self.enable_dst_for:
                    for atk in self.enable_dst_for[current_attack]:
                        possible_dsts[atk].append(dst_ip)
                src_dst_ips.append((src_ip, dst_ip))

        df_list = []
        step_id_list = []
        sizes = []
        ift_mean = []
        ift_std = []
        for i in range(len(scenario)):
            attack_name = scenario[i]
            src_ip, dst_ip = src_dst_ips[i]
            step_id = random.choice(
                list(self.data_source[attack_name].keys()))
            step_id_list.append(step_id)
            df = self.data_source[attack_name][step_id].copy()
            sizes.append(df.shape[0])
            df["src_ip"] = src_ip
            df["dst_ip"] = dst_ip
            df["step_number"] = i
            noise_t = timedelta(seconds=int(np.round(np.random.normal(
                10, 2)).astype(int)) if len(df_list) > 0 else 0)

            if i == 0:
                delta_t = self.data_source["normal"][-1].iloc[0]["timestamp"] - \
                          df.iloc[0]["timestamp"]
            else:
                delta_t = df_list[-1].iloc[-1]["timestamp"] - \
                          df.iloc[0]["timestamp"]

            df["timestamp"] = df["timestamp"] + delta_t + noise_t
            srt_end_times.append((df.iloc[0]["timestamp"], df.iloc[-1]["timestamp"]))
            df_list.append(df)
            if df.shape[0] > 1:
                starts = df["timestamp"].to_numpy()
                ends = (df["timestamp"] + pd.to_timedelta(df["duration"], unit="ms")).to_numpy()
                intervals = starts[1:] - ends[:-1]
                intervals = intervals / np.timedelta64(1, 'ms')
                ift_mean.append(intervals.mean())
                ift_std.append(intervals.std(ddof=0))
            else:
                ift_mean.append(-1)
                ift_std.append(-1)

        self.attack_names = scenario
        self.step_id_list = step_id_list
        self.attack_times = srt_end_times
        self.attack_ips = src_dst_ips
        self.sizes = sizes
        self.ift_mean = ift_mean
        self.ift_std = ift_std
        self.result = pd.concat(
            df_list + [
                self.data_source["normal"][-1][self.data_source["normal"][-1].index % normal_flow_number_divisor == 0]],
            ignore_index=True).sort_values("timestamp").reset_index(drop=True)
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
        list[Exploit], list[FlowExploit]]:
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
                Exploit(attack, size, src_ip, dst_ip, start_time, end_time, ift_mean, ift_std))
        alert_flows = self.result[self.result["label"] != "normal"]
        for row in alert_flows.itertuples():
            alerts.append(
                FlowExploit(attack_type_dict[cast(str, row.label)], [], cast(str, row.src_ip), cast(str, row.src_port),
                            cast(str, row.dst_ip), cast(str, row.dst_port), cast(str, row.protocol),
                            cast(datetime, row.timestamp), cast(datetime, row.timestamp) + timedelta(
                        milliseconds=cast(int, row.duration)), cast(float, row.anomaly_score)))
        return attack_steps, alerts
