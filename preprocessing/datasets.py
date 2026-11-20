"""Dataset directory discovery and labeled flow summary tables."""
from pathlib import Path

import numpy as np
import pandas as pd


def get_subdirs(path) -> list[Path]:
    """Return sorted non-checkpoint subdirectories inside path."""
    return sorted(
        (
            entry
            for entry in Path(path).iterdir()
            if entry.is_dir() and entry.name != ".ipynb_checkpoints"
        ),
        key=lambda entry: entry.name,
    )


def summarize_labeled_flows(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Sort labeled flows chronologically and compute per-step and per-label summaries."""
    sorted_df = df.sort_values("timestamp").reset_index(drop=True)
    timestamps = (
        sorted_df["timestamp"]
        if pd.api.types.is_datetime64_any_dtype(sorted_df["timestamp"])
        else pd.to_datetime(sorted_df["timestamp"], utc=True)
    )
    duration_col = next(
        (col for col in ("bidirectional_duration_ms", "duration") if col in sorted_df.columns),
        None,
    )
    flow_end_time = (
        timestamps + pd.to_timedelta(sorted_df[duration_col], unit="ms")
        if duration_col is not None
        else timestamps
    )
    work = sorted_df.assign(_flow_start_time=timestamps, _flow_end_time=flow_end_time)
    step_summary = (
        work.groupby("step_number", as_index=False)
        .agg(
            label=("label", "first"),
            phase_name=("phase_name", "first"),
            phase_number=("phase_number", "first"),
            num_flws=("timestamp", "size"),
            start_time=("_flow_start_time", "min"),
            end_time=("_flow_end_time", "max"),
        )
        .assign(duration=lambda g: g["end_time"] - g["start_time"])
    )
    step_summary["fps"] = (
        step_summary["num_flws"]
        / step_summary["duration"].dt.total_seconds().replace(0, np.nan)
    )
    label_summary = (
        step_summary.groupby("label", as_index=False)
        .agg(
            avg_num_flws=("num_flws", "mean"),
            median_num_flws=("num_flws", "median"),
            avg_duration=("duration", "mean"),
            median_duration=("duration", "median"),
            total_steps=("step_number", "nunique"),
            total_flws=("num_flws", "sum"),
            avg_fps=("fps", "mean"),
        )
    )
    return sorted_df, step_summary, label_summary
