"""Tracked hosts, compromise attributes, and independent network snapshots."""

from datetime import datetime
from enum import Enum
from typing import TypeVar


class HostAttribute(Enum):
    pass

T = TypeVar("T", bound=HostAttribute)

class Host:
    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self.compromise_attributes: set[HostAttribute] = set()

    def update_compromise_attributes(self, attributes: set[HostAttribute]):
        self.compromise_attributes.update(attributes)

    def get_compromise_attributes(self) -> set[HostAttribute]:
        return self.compromise_attributes

    def reset_attributes(self):
        self.compromise_attributes = set()


class NetworkState:
    def __init__(self, att_dict: dict[str, set[T]], transition_time: datetime) -> None:
        # A snapshot owns its sets so later updates cannot rewrite recorded state.
        self.state = {ip_address: set(attributes) for ip_address, attributes in att_dict.items()}
        self.transition_time = transition_time

    @classmethod
    def from_dict_of_host(cls, host_dict: dict[str, Host], timestamp: datetime) -> "NetworkState":
        return cls({ip_address: host.compromise_attributes for ip_address, host in host_dict.items()}, timestamp)

    def __str__(self) -> str:
        state = "-".join([f"{ip_addr}={{" + f"{'; '.join([str(att.value) for att in att_set])}" +
                          "}" for ip_addr, att_set in self.state.items()])
        return f"NetworkState(state={{{state}}}, time={self.transition_time.isoformat()})"

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, NetworkState):
            return False
        if value.transition_time != self.transition_time:
            return False
        for ip_addr, att_set in self.state.items():
            if ip_addr not in value.state:
                return False
            if value.state[ip_addr] != att_set:
                return False
        return True
