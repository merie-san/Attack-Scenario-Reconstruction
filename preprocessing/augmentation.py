"""Constraint-preserving normal-flow augmentation and timestamp compression."""
import numpy as np
import pandas as pd

EXCLUDED_FEATURE_KEYWORDS = ("id", "ip", "mac", "oui", "first_seen", "last_seen", "duration", "fingerprint", "port")

def augment_normal_flows(df, start_time, repetitions, *, excluded_keywords=EXCLUDED_FEATURE_KEYWORDS):
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    df = df.sort_values("bidirectional_first_seen_ms").copy()
    n_df = df.copy()
    origin = df["bidirectional_first_seen_ms"].min()
    jitter = np.random.normal(0, 500, len(df)).round().astype(int)

    # Use one origin, scale, and per-row shift for every timestamp direction.
    time_cols = [col for col in df.columns
                 if col.endswith(("first_seen_ms", "last_seen_ms"))]
    for col in time_cols:
        n_df[col] = ((df[col] - origin) // repetitions + start_time + jitter)
    for direction in ("src2dst", "dst2src"):
        first, last = f"{direction}_first_seen_ms", f"{direction}_last_seen_ms"
        if first not in df or last not in df:
            continue
        packets = f"{direction}_packets"
        absent = (df[packets].eq(0) if packets in df
                  else df[first].eq(0) & df[last].eq(0) & df["bidirectional_first_seen_ms"].ne(0))
        n_df.loc[absent, [first, last]] = 0
        present = ~absent
        n_df.loc[present, first] = n_df.loc[present, first].clip(
            lower=n_df.loc[present, "bidirectional_first_seen_ms"],
            upper=n_df.loc[present, "bidirectional_last_seen_ms"])
        n_df.loc[present, last] = n_df.loc[present, last].clip(
            lower=n_df.loc[present, first],
            upper=n_df.loc[present, "bidirectional_last_seen_ms"])
    for direction in ("bidirectional", "src2dst", "dst2src"):
        first, last = f"{direction}_first_seen_ms", f"{direction}_last_seen_ms"
        if first in n_df and last in n_df:
            n_df[f"{direction}_duration_ms"] = n_df[last] - n_df[first]

    numeric = [col for col in df.columns
               if df[col].nunique() > 2**7
               and pd.api.types.is_numeric_dtype(df[col])
               and not any(keyword in col for keyword in excluded_keywords)]
    for col in numeric:
        noise = np.random.normal(0, 0.1 * df[col].std(), len(df))
        values = df[col] + noise
        if df[col].ge(0).all():
            values = values.clip(lower=0)
        if col.endswith(("_bytes", "_packets")):
            values.loc[df[col].eq(0)] = 0
            values.loc[df[col].gt(0)] = values.loc[df[col].gt(0)].clip(lower=1)
        if pd.api.types.is_integer_dtype(df[col]):
            values = values.round().astype(df[col].dtype)
        n_df[col] = values

    # Draw whole categorical rows so dependent values stay paired. Assign by
    # position, not index label, because filtered input indexes may have gaps.
    categorical = [col for col in df.columns if col not in numeric
                   and not col.endswith(("_bytes", "_packets"))
                   and not any(keyword in col for keyword in excluded_keywords)]
    sampled = np.random.randint(0, len(df), size=len(df))
    n_df[categorical] = df.iloc[sampled][categorical].to_numpy()

    # Recompute dependent totals after perturbing their directional components.
    for quantity in ("bytes", "packets"):
        total, forward, reverse = (f"bidirectional_{quantity}", f"src2dst_{quantity}", f"dst2src_{quantity}")
        if all(col in n_df for col in (total, forward, reverse)):
            n_df[total] = n_df[forward] + n_df[reverse]
    return n_df.sort_values("bidirectional_first_seen_ms")
