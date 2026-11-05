"""Timestamp comparisons shared by models, aggregation, and recovery."""

from datetime import datetime, timezone


def normalize_timestamp(timestamp: datetime) -> datetime:
    """Return naive UTC for aware timestamps, preserving naive timestamps as-is."""
    if timestamp.utcoffset() is not None:
        return timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp
