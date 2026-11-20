"""Date-safe capture adjustment and absolute UTC flow timestamps."""
from datetime import datetime, timedelta, timezone

import numpy as np


def shift_capture_time(timestamp: datetime, hours: float = -2) -> datetime:
    return timestamp + timedelta(hours=hours)


def load_start_time(npz_path, *, hours: float = -2) -> datetime:
    """Load capture start datetime from an .npz archive and apply the timezone shift."""
    with np.load(npz_path, allow_pickle=True) as data:
        key = "datetime" if "datetime" in data.files else data.files[0]
        raw = data[key]
        timestamp = raw.item() if hasattr(raw, "item") else raw
    return shift_capture_time(timestamp, hours=hours)


def absolute_flow_time(milliseconds, start_time: datetime) -> datetime:
    absolute = start_time + timedelta(milliseconds=float(milliseconds))
    if absolute.tzinfo is None:
        return absolute.replace(tzinfo=timezone.utc)
    return absolute.astimezone(timezone.utc)
