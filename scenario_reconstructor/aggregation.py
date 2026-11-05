"""Aggregation by attack context and configurable temporal idle gap."""

from collections import defaultdict
from datetime import timedelta, timezone
from statistics import mean, pstdev

from .models import AttackStep, FlowAlert
from .time_utils import normalize_timestamp


def group_alerts(alerts: list[FlowAlert], max_idle_gap: timedelta) -> list[list[FlowAlert]]:
    """Group same-context alerts by overlap or an inclusive maximum idle gap.

    Compare each start against the latest end in its current group. Groups
    can grow without a duration limit. Input lists and alerts are not mutated.
    Aware timestamps are compared in UTC; naive timestamps are treated as UTC.
    """
    contexts: dict[str, list[FlowAlert]] = defaultdict(list)
    for alert in alerts:
        contexts[alert.get_flow_exploit_group_id()].append(alert)

    clusters: list[list[FlowAlert]] = []
    for flows in contexts.values():
        ordered = sorted(flows, key=lambda flow: (
            normalize_timestamp(flow.start_time), normalize_timestamp(flow.end_time),
        ))
        current = [ordered[0]]
        latest_end = normalize_timestamp(ordered[0].end_time)
        for flow in ordered[1:]:
            start = normalize_timestamp(flow.start_time)
            end = normalize_timestamp(flow.end_time)
            idle_gap = max(timedelta(0), start - latest_end)
            if idle_gap > max_idle_gap:
                clusters.append(current)
                current = [flow]
                latest_end = end
            else:
                current.append(flow)
                latest_end = max(latest_end, end)
        clusters.append(current)
    return sorted(clusters, key=lambda cluster: normalize_timestamp(cluster[0].start_time))


def aggregate_alerts(alerts: list[FlowAlert], max_idle_gap: timedelta) -> list[AttackStep]:
    """Build temporal step occurrences, preserving each cluster's own context."""
    if not alerts:
        raise RuntimeError("Cannot aggregate an empty alert sequence")
    steps: list[AttackStep] = []
    for group in group_alerts(alerts, max_idle_gap):
        reference = group[0]
        starts = [normalize_timestamp(flow.start_time) for flow in group]
        ends = [normalize_timestamp(flow.end_time) for flow in group]
        # Preserve the existing signed consecutive inter-flow statistics in milliseconds.
        intervals = [(start - end).total_seconds() * 1000 for start, end in zip(starts[1:], ends[:-1])]
        steps.append(AttackStep(
            reference.attack_type, len(group),
            reference.source_ip, reference.destination_ip,
            starts[0].replace(tzinfo=timezone.utc), max(ends).replace(tzinfo=timezone.utc),
            mean(intervals) if intervals else -1,
            pstdev(intervals) if intervals else -1,
        ))
    return steps
