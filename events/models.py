"""Scored network flow events independent of dataset conversion."""
from datetime import datetime


_FLOW_FIELDS = (
    "source_ip", "source_port", "destination_ip", "destination_port", "protocol",
    "start_time", "end_time", "anomaly_score",
)


class FlowEvent:
    """A network flow with anomaly and attack-type scores."""

    def __init__(self, source_ip: str, source_port: str, destination_ip: str,
                 destination_port: str, protocol: str, start_time: datetime,
                 end_time: datetime, anomaly_score: float, attack_scores: dict[str, float]):
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.start_time = start_time
        self.end_time = end_time
        self.anomaly_score = anomaly_score
        self.attack_scores = attack_scores

    def __str__(self) -> str:
        fields = [f"{name}={getattr(self, name)}" for name in _FLOW_FIELDS]
        fields.extend(f"{name}={score}" for name, score in self.attack_scores.items())
        return "[" + ", ".join(fields) + "]"

    def to_dict(self) -> dict:
        return {**{name: getattr(self, name) for name in _FLOW_FIELDS}, **self.attack_scores}

    @staticmethod
    def from_dict(data: dict) -> "FlowEvent":
        return FlowEvent(
            **{name: data[name] for name in _FLOW_FIELDS},
            attack_scores={name: score for name, score in data.items() if name not in _FLOW_FIELDS},
        )

    @staticmethod
    def from_str(string: str) -> "FlowEvent":
        data = dict(part.split("=", 1) for part in string.strip("[]").split(", "))
        for name in ("start_time", "end_time"):
            data[name] = datetime.fromisoformat(data[name])
        for name in (data.keys() - set(_FLOW_FIELDS)) | {"anomaly_score"}:
            data[name] = float(data[name])
        return FlowEvent.from_dict(data)
