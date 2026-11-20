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
    step_summary = (
        sorted_df.groupby("step_number", as_index=False)
        .agg(
            label=("label", "first"),
            phase_name=("phase_name", "first"),
            phase_number=("phase_number", "first"),
            num_flws=("timestamp", "size"),
            start_time=("timestamp", "min"),
            end_time=("timestamp", "max"),
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
