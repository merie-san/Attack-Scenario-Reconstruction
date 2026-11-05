"""Flow alerts and aggregated temporal attack-step occurrences."""

from datetime import datetime

from .attacks import AttackType
from ..time_utils import normalize_timestamp


class FlowAlert:
    """Alert value; do not mutate identity fields while used in a set or dictionary."""

    def __init__(self, main_attack_type: AttackType, attack_types_alternatives: list[AttackType], source_ip: str,
                 source_port: str, destination_ip: str,
                 destination_port: str, protocol: str, start_time: datetime, end_time: datetime, anomaly_score: float):
        self.attack_type = main_attack_type
        self.attack_type_alternatives = attack_types_alternatives
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.start_time = start_time
        self.end_time = end_time
        self.anomaly_score = anomaly_score

    def reclassify(self, attack_type: AttackType) -> "FlowAlert":
        """Return an interpreted copy, leaving the observed alert unchanged."""
        return FlowAlert(attack_type, [], self.source_ip, self.source_port, self.destination_ip,
                           self.destination_port, self.protocol, self.start_time, self.end_time, self.anomaly_score)

    mutate = reclassify  # Original API name retained for existing callers.

    @property
    def metric_key(self):
        """Flow identity without classification, for explicit metric matching."""
        return (
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol,
            normalize_timestamp(self.start_time),
            normalize_timestamp(self.end_time),
        )

    @property
    def _identity_key(self):
        return (self.attack_type, *self.metric_key)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, FlowAlert):
            return False
        return self._identity_key == value._identity_key

    def unk_eq(self, value: object, unknown_attack_type: AttackType) -> bool:
        """Match an actual alert to a prediction, allowing an unknown predicted type."""
        if not isinstance(value, FlowAlert):
            return False
        return self.metric_key == value.metric_key and (
            self.attack_type == value.attack_type or value.attack_type == unknown_attack_type
        )

    def get_flow_exploit_group_id(self) -> str:
        return f"{self.attack_type.identifier}-{self.destination_ip}-{self.source_ip}"

    def __str__(self) -> str:
        return f"FlowExploit(attack_type={self.attack_type.identifier}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, anomaly_score={self.anomaly_score})"

    def __hash__(self) -> int:
        return hash(self._identity_key)

    def __repr__(self):
        return str(self)


class AttackStep:
    """Exact step value; use approx_match for evaluation and keep dictionary keys stable."""

    def __init__(self, attack_type: AttackType, size: int, source_ip: str, destination_ip: str, start_time: datetime,
                 end_time: datetime, mean_interflow_time: float = -1, std_interflow_time: float = -1) -> None:
        self.attack_type = attack_type
        self.size = size
        self.destination_ip = destination_ip
        self.source_ip = source_ip
        self.start_time = start_time
        self.end_time = end_time
        self.mean_interflow_time = mean_interflow_time
        self.std_interflow_time = std_interflow_time

    def get_exploit_group_id(self) -> str:
        return f"{self.attack_type.identifier}-{self.destination_ip}-{self.source_ip}"

    @property
    def metric_key(self):
        return (
            self.source_ip,
            self.destination_ip,
        )

    @property
    def _identity_key(self):
        return (
            self.attack_type, self.source_ip, self.destination_ip,
            normalize_timestamp(self.start_time), normalize_timestamp(self.end_time),
            self.size, self.mean_interflow_time, self.std_interflow_time,
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, AttackStep):
            return False
        return self._identity_key == value._identity_key

    def _matches_context(self, value: "AttackStep", unknown_attack_type: AttackType | None = None) -> bool:
        if self.source_ip != value.source_ip or self.destination_ip != value.destination_ip:
            return False
        if self.attack_type == value.attack_type:
            return True
        if unknown_attack_type is not None:
            return self.attack_type == unknown_attack_type or value.attack_type == unknown_attack_type
        return False

    def approx_match(self, value: object,
                     unknown_attack_type: AttackType | None = None) -> bool:
        if not isinstance(value, AttackStep):
            return False
        if not self._matches_context(value, unknown_attack_type):
            return False
        s1, e1 = normalize_timestamp(self.start_time), normalize_timestamp(self.end_time)
        s2, e2 = normalize_timestamp(value.start_time), normalize_timestamp(value.end_time)
        return max(s1, s2) <= min(e1, e2)

    def __str__(self) -> str:
        return f"Exploit(attack_type={self.attack_type.identifier}, size={self.size}, source_ip={self.source_ip}, destination_ip={self.destination_ip}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, mean_ift={self.mean_interflow_time}, std_ift={self.std_interflow_time})"

    def __hash__(self) -> int:
        return hash(self._identity_key)
