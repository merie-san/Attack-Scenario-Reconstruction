"""Date-safe capture adjustment and absolute UTC flow timestamps."""
from datetime import datetime, timedelta, timezone


def shift_capture_time(timestamp: datetime, hours: float = -2) -> datetime:
    return timestamp + timedelta(hours=hours)


def absolute_flow_time(milliseconds, start_time: datetime) -> datetime:
    absolute = start_time + timedelta(milliseconds=float(milliseconds))
    if absolute.tzinfo is None:
        return absolute.replace(tzinfo=timezone.utc)
    return absolute.astimezone(timezone.utc)
