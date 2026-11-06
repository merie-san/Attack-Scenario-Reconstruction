"""Temporal placement and export metadata for a completed generation path."""
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import numpy as np
import pandas as pd


@dataclass
class RenderedScenario:
    attack_names: list[str] = field(default_factory=list)
    step_id_list: list[int] = field(default_factory=list)
    attack_times: list[tuple[datetime, datetime]] = field(default_factory=list)
    attack_ips: list[tuple[str, str]] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    ift_mean: list[float] = field(default_factory=list)
    ift_std: list[float] = field(default_factory=list)
    result: pd.DataFrame = field(default_factory=pd.DataFrame)


def render_scenario(path: list[tuple[str, str, str]], templates, normal_flow_number_divisor: int) -> RenderedScenario:
    """Place selected templates in time and construct a complete unpublished result."""
    scenario = [attack for attack, _, _ in path]
    src_dst_ips = [(source, destination) for _, source, destination in path]
    srt_end_times = []

    df_list = []
    step_id_list = []
    sizes = []
    ift_mean = []
    ift_std = []
    for i in range(len(scenario)):
        attack_name = scenario[i]
        src_ip, dst_ip = src_dst_ips[i]
        step_id = random.choice(
            list(templates[attack_name].keys()))
        step_id_list.append(step_id)
        df = templates[attack_name][step_id].sort_values("timestamp", kind="stable").copy()
        sizes.append(df.shape[0])
        df["src_ip"] = src_ip
        df["dst_ip"] = dst_ip
        df["step_number"] = i
        gap_seconds = int(np.round(abs(np.random.normal(10, 2)))) if df_list else 0
        noise_t = timedelta(seconds=gap_seconds)

        if i == 0:
            delta_t = templates["normal"][-1]["timestamp"].min() - \
                      df.iloc[0]["timestamp"]
        else:
            delta_t = df_list[-1].iloc[-1]["timestamp"] - \
                      df.iloc[0]["timestamp"]

        df["timestamp"] = df["timestamp"] + delta_t + noise_t
        flow_ends = df["timestamp"] + pd.to_timedelta(df["duration"], unit="ms")
        srt_end_times.append((df.iloc[0]["timestamp"], flow_ends.max()))
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

    result = pd.concat(
        df_list + [templates["normal"][-1].iloc[::normal_flow_number_divisor]],
        ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    return RenderedScenario(scenario, step_id_list, srt_end_times, src_dst_ips, sizes, ift_mean, ift_std, result)
