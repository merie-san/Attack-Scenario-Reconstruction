"""Readers for established alert, attack-step, and snapshot text formats."""

from datetime import datetime
from typing import Callable

from .models import AttackStep, AttackType, FlowAlert, HostAttribute, NetworkState


def _record_fields(record: str, prefix: str) -> dict[str, str]:
    if not record.startswith(prefix) or not record.endswith(")"):
        raise RuntimeError("Provided string has wrong format")
    return dict(field.split("=", 1) for field in record[len(prefix):-1].split(", "))


class AlertStepParser:
    """Parse existing records using the supplied attack definitions."""

    def __init__(self, attack_type_list: list[AttackType]) -> None:
        self._attack_types = {attack.identifier: attack for attack in attack_type_list}

    def _attack_type(self, identifier: str) -> AttackType:
        attack = self._attack_types.get(identifier)
        if attack is None:
            raise RuntimeError("Found attack type not defined in the provided list")
        return attack

    def parse_alert(self, record: str) -> FlowAlert:
        fields = _record_fields(record, "FlowExploit(")
        return FlowAlert(
            self._attack_type(fields["attack_type"]), [],
            fields["source_ip"], fields["source_port"],
            fields["destination_ip"], fields["destination_port"], fields["protocol"],
            datetime.fromisoformat(fields["start_time"]),
            datetime.fromisoformat(fields["end_time"]), float(fields["anomaly_score"]),
        )

    def parse_step(self, record: str) -> AttackStep:
        fields = _record_fields(record, "Exploit(")
        return AttackStep(
            self._attack_type(fields["attack_type"]), int(fields["size"]),
            fields["source_ip"], fields["destination_ip"],
            datetime.fromisoformat(fields["start_time"]),
            datetime.fromisoformat(fields["end_time"]),
            float(fields["mean_ift"]), float(fields["std_ift"]),
        )

    from_str_flow_exploit = parse_alert
    from_str_exploit = parse_step


class NetworkStateParser:
    """Restore attributes with an enum class or a current-run archive resolver."""

    def __init__(self, attribute_type: type[HostAttribute] | Callable[[str], HostAttribute]) -> None:
        self._attribute_type = attribute_type

    def parse(self, record: str) -> NetworkState:
        if not record.startswith("NetworkState(") or not record.endswith(")"):
            raise RuntimeError("Provided string has wrong format")
        state_field, time_field = record[len("NetworkState("):-1].split(", ")
        if not state_field.startswith("state={") or not state_field.endswith("}"):
            raise RuntimeError("Provided string has wrong format")
        contents = state_field[len("state={"):-1]
        hosts: dict[str, set[HostAttribute]] = {}
        for host_record in contents.split("-") if contents else []:
            ip_address, attributes = host_record.split("=", 1)
            if not attributes.startswith("{") or not attributes.endswith("}"):
                raise RuntimeError("Provided string has wrong format")
            values = attributes[1:-1]
            hosts[ip_address] = {self._attribute_type(value) for value in values.split("; ")} if values else set()
        return NetworkState(hosts, datetime.fromisoformat(time_field.removeprefix("time=")))

    from_str = parse
