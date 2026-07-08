from datetime import datetime, timezone, timedelta
from enum import Enum
from functools import cached_property
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import pandas as pd
from typing import TypeVar


class HostAttribute(Enum):
    pass


T = TypeVar("T", bound=HostAttribute)


class Preconditions:

    def __init__(self, compromise_attributes: set[HostAttribute], targets_source: bool):
        self.targets_source = targets_source
        self.compromise_attributes = compromise_attributes

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Preconditions):
            return False
        return self.targets_source == value.targets_source and self.compromise_attributes == value.compromise_attributes

    def __hash__(self) -> int:
        to_hash = 0 if self.targets_source else 1
        for att in self.compromise_attributes:
            to_hash += hash(att)

        return hash(to_hash)


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


class AttackType:

    def __init__(self, identifier: str, preconditions: set[Preconditions], postconditions: set[HostAttribute],
                 description: str = ""):
        self.identifier = identifier
        self.description = description
        self.preconditions = preconditions
        self.postconditions = postconditions

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, AttackType):
            return False
        return self.identifier == value.identifier and self.preconditions == value.preconditions and self.postconditions == value.postconditions

    def __hash__(self) -> int:
        to_hash = hash(self.identifier)
        for precondition in self.postconditions:
            to_hash += hash(precondition)
        for att in self.postconditions:
            to_hash += hash(att)
        return hash(to_hash)

    def __str__(self) -> str:
        return self.identifier

    def get_preconditions(self) -> tuple[set[Preconditions], set[Preconditions]]:
        source_preconditions = set()
        destination_preconditions = set()
        for condition in self.preconditions:
            if condition.targets_source:
                source_preconditions.add(condition)
            else:
                destination_preconditions.add(condition)
        return source_preconditions, destination_preconditions


class FlowExploit:

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

    @cached_property
    def metric_key(self):
        return (
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.protocol,
            self.start_time,
            self.end_time
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, FlowExploit):
            return False
        return self.attack_type == value.attack_type and self.source_ip == value.source_ip and self.source_port == value.source_port and self.destination_ip == value.destination_ip and self.protocol == value.protocol and self.start_time == value.start_time and self.end_time == value.end_time

    def unk_eq(self, value: object, unknown_attack_type: AttackType):
        if not isinstance(value, FlowExploit):
            return False
        return (self.attack_type == value.attack_type or value.attack_type == unknown_attack_type) and self.source_ip == value.source_ip and self.source_port == value.source_port and self.destination_ip == value.destination_ip and self.protocol == value.protocol and self.start_time == value.start_time and self.end_time == value.end_time

    def get_flow_exploit_group_id(self) -> str:
        return f"{self.attack_type.identifier}-{self.destination_ip}-{self.source_ip}"

    def __str__(self) -> str:
        return f"FlowExploit(attack_type={self.attack_type.identifier}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, anomaly_score={self.anomaly_score})"

    def __hash__(self):
        return hash(
            hash(self.attack_type) + hash(self.source_ip) + hash(self.source_port) + hash(self.destination_ip) + hash(
                self.destination_port) + hash(self.protocol) + hash(self.start_time) + hash(self.end_time))


class Exploit:

    def __init__(self, attack_type: AttackType, size: int, source_ip: str, destination_ip: str, start_time: datetime,
                 end_time: datetime, mean_interflow_time: float, std_interflow_time: float) -> None:
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
    
    @cached_property
    def metric_key(self):
        return (
            self.source_ip,
            self.destination_ip,
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Exploit):
            return False
        return self.attack_type == value.attack_type and self.size == value.size and self.source_ip == value.source_ip and self.destination_ip == value.destination_ip and self.start_time == value.start_time and self.end_time == value.end_time and self.mean_interflow_time - 0.0001 <= value.mean_interflow_time <= self.mean_interflow_time + 0.0001 and self.std_interflow_time - 0.0001 <= value.std_interflow_time <= self.std_interflow_time + 0.0001

    def approx_match(self, value: object, tolerance: timedelta, unknown_attack_type: AttackType | None = None) -> bool:
        if not isinstance(value, Exploit):
            return False
        return self.attack_type == value.attack_type and self.source_ip == value.source_ip and self.destination_ip == value.destination_ip and self.start_time - tolerance <= value.start_time <= self.start_time + tolerance and self.end_time - tolerance <= value.end_time <= self.end_time + tolerance if not unknown_attack_type else (self.attack_type == value.attack_type or value.attack_type == unknown_attack_type) and self.source_ip == value.source_ip and self.destination_ip == value.destination_ip and self.start_time - tolerance <= value.start_time <= self.start_time + tolerance and self.end_time - tolerance <= value.end_time <= self.end_time + tolerance

    def approx_match_no_timing(self, value: object, unknown_attack_type: AttackType | None = None) -> bool:
        if not isinstance(value, Exploit):
            return False
        return self.attack_type == value.attack_type and self.source_ip == value.source_ip and self.destination_ip == value.destination_ip if not unknown_attack_type else (self.attack_type == value.attack_type or value.attack_type == unknown_attack_type) and self.source_ip == value.source_ip and self.destination_ip == value.destination_ip

    def __str__(self) -> str:
        return f"Exploit(attack_type={self.attack_type.identifier}, size={self.size}, source_ip={self.source_ip}, destination_ip={self.destination_ip}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, mean_ift={self.mean_interflow_time}, std_ift={self.std_interflow_time})"

    def __hash__(self):
        return hash(hash(self.attack_type) + hash(self.size) + hash(self.destination_ip) + hash(self.source_ip) + hash(
            self.start_time) + hash(self.end_time) + hash(self.mean_interflow_time) + hash(self.std_interflow_time))


class StringToExploitConverter:

    def __init__(self, attack_type_list: list[AttackType]) -> None:
        self.attack_types = attack_type_list

    def from_str_flow_exploit(self, flow_exploit_str: str) -> FlowExploit:
        if not flow_exploit_str.startswith("FlowExploit(") or not flow_exploit_str.endswith(")"):
            raise RuntimeError("Provided string has wrong format")
        flow_exploit_str = flow_exploit_str.removeprefix("FlowExploit(")
        flow_exploit_str = flow_exploit_str.removesuffix(")")
        fields = flow_exploit_str.split(", ")
        flow_exploit_dict = {field.split("=")[0]: field.split("=")[
            1] for field in fields}
        attack_type = None
        for attack in self.attack_types:
            if attack.identifier == flow_exploit_dict["attack_type"]:
                attack_type = attack
        if attack_type == None:
            raise RuntimeError(
                "Found attack type not defined in the provided list")
        return FlowExploit(attack_type, [], flow_exploit_dict["source_ip"], flow_exploit_dict["source_port"],
                           flow_exploit_dict["destination_ip"], flow_exploit_dict["destination_port"],
                           flow_exploit_dict["protocol"], datetime.fromisoformat(
                               flow_exploit_dict["start_time"]),
                           datetime.fromisoformat(
                               flow_exploit_dict["end_time"]),
                           float(flow_exploit_dict["anomaly_score"]))

    def from_str_exploit(self, exploit_str: str) -> Exploit:
        if not exploit_str.startswith("Exploit(") or not exploit_str.endswith(")"):
            raise RuntimeError("Provided string has wrong format")
        exploit_str = exploit_str.removeprefix("Exploit(")
        exploit_str = exploit_str.removesuffix(")")
        fields = exploit_str.split(", ")
        exploit_dict = {field.split("=")[0]: field.split("=")[
            1] for field in fields}
        attack_type = None
        for attack in self.attack_types:
            if attack.identifier == exploit_dict["attack_type"]:
                attack_type = attack
        if attack_type == None:
            raise RuntimeError(
                "Found attack type not defined in the provided list")
        return Exploit(attack_type, int(exploit_dict["size"]), exploit_dict["source_ip"],
                       exploit_dict["destination_ip"], datetime.fromisoformat(
                           exploit_dict["start_time"]),
                       datetime.fromisoformat(exploit_dict["end_time"]), float(
                           exploit_dict["mean_ift"]),
                       float(exploit_dict["std_ift"]))


class ExploitRequirement:

    def __init__(self, attack_type: AttackType, acceptable_source_ips: list[str], acceptable_destination_ip: str):
        self.attack_type = attack_type
        self.acceptable_source_ips = acceptable_source_ips
        self.acceptable_destination_ip = acceptable_destination_ip

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, ExploitRequirement):
            return False
        return self.attack_type == value.attack_type and set(self.acceptable_source_ips) == set(
            value.acceptable_source_ips) and self.acceptable_destination_ip == value.acceptable_destination_ip

    def __hash__(self) -> int:
        src_ips_hash = sum(hash(src_ips)
                           for src_ips in self.acceptable_source_ips)
        return hash(hash(self.attack_type) + src_ips_hash + hash(self.acceptable_destination_ip))


class NetworkState:

    def __init__(self, att_dict: dict[str, set[T]], transition_time: datetime) -> None:
        self.state = att_dict
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


class StringToNetworkStateConvertor:

    def __init__(self, attribute_type: type[HostAttribute]) -> None:
        self.att_type = attribute_type

    def from_str(self, network_state_str: str) -> "NetworkState":
        if not network_state_str.startswith("NetworkState(") or not network_state_str.endswith(")"):
            raise RuntimeError("Provided string has wrong format")
        network_state_str = network_state_str.removeprefix("NetworkState(")
        network_state_str = network_state_str.removesuffix(")")
        split_str = network_state_str.split(", ")
        state_str = split_str[0]
        time_str = split_str[1].removeprefix("time=")
        if not state_str.startswith("state={") or not state_str.endswith("}"):
            raise RuntimeError("Provided string has wrong format")
        state_str = state_str.removeprefix("state={")
        state_str = state_str.removesuffix("}")
        if state_str == "":
            return NetworkState({}, datetime.fromisoformat(time_str))
        host_states_str = state_str.split("-")
        host_dict: dict[str, set[HostAttribute]] = {}
        for host_state_str in host_states_str:
            host_state_str_split = host_state_str.split("=")
            ip_addr = host_state_str_split[0]
            att_set_str = host_state_str_split[1]
            if not att_set_str.startswith("{") or not att_set_str.endswith("}"):
                raise RuntimeError("Provided string has wrong format")
            att_set_str = att_set_str.removeprefix("{")
            att_set_str = att_set_str.removesuffix("}")
            att_set_str_split = att_set_str.split("; ")
            host_dict[ip_addr] = {self.att_type(
                att_str) for att_str in att_set_str_split}
        return NetworkState(host_dict, datetime.fromisoformat(time_str))


class StarNetworkAttackGraphBasedScenarioReconstructor:

    def __init__(self, internal_hosts: list[Host], external_host_attributes: set[HostAttribute],
                 attack_types: list[AttackType], exploit_log_path: str, flow_exploit_log_path: str, state_log_path: str,
                 correlation_log_path: str):
        self.host_dict = {host.ip_address: host for host in internal_hosts}
        self.external_host_attributes = external_host_attributes
        self.seen_external_hosts_dict = {}
        self.attack_types = attack_types
        self.flow_exploits_dict: dict[str, list[FlowExploit]] = {}
        self.flow_exploit_log_path: str = flow_exploit_log_path
        self.exploits_dict: dict[str, list[Exploit]] = {}
        self.exploit_log_path: str = exploit_log_path
        initial_state = NetworkState.from_dict_of_host(
            self.host_dict, datetime.min)
        self.state_sequence = [initial_state]
        self.correlation_sequence: list[str] = []
        self.state_log_path = state_log_path
        self.correlation_log_path = correlation_log_path

    def reset(self, initial_attributes: dict[Host, set[HostAttribute]]) -> None:
        for host in self.host_dict.values():
            host.reset_attributes()
        for host in self.host_dict.values():
            host.update_compromise_attributes(initial_attributes[host])
        self.seen_external_hosts_dict = {}
        self.flow_exploits_dict = {}
        self.exploits_dict = {}
        initial_state = NetworkState.from_dict_of_host(
            self.host_dict, datetime.min)
        self.state_sequence = [initial_state]
        self.correlation_sequence = []

    def change_log_paths(self, exploit_log_path: str, flow_exploit_log_path: str, state_log_path: str,
                         correlation_log_path: str) -> None:
        self.exploit_log_path = exploit_log_path
        self.flow_exploit_log_path = flow_exploit_log_path
        self.state_log_path = state_log_path
        self.correlation_log_path = correlation_log_path

    def check_preconditions(self, flow_exploit: FlowExploit) -> bool:

        source_preconditions, destination_preconditions = flow_exploit.attack_type.get_preconditions()
        source_host, destination_host = self._obtain_hosts(flow_exploit)

        source_attributes = source_host.get_compromise_attributes()
        for precondition in source_preconditions:
            if len(source_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        destination_attributes = destination_host.get_compromise_attributes()
        for precondition in destination_preconditions:
            if len(destination_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        return True

    def _obtain_hosts(self, flow_exploit: FlowExploit):
        source_host = self.host_dict.get(flow_exploit.source_ip)
        destination_host = self.host_dict.get(flow_exploit.destination_ip)

        if not source_host and not destination_host:
            raise ValueError(
                f"Precondition defined on two external ips: {flow_exploit.source_ip} {flow_exploit.destination_ip}")

        if not source_host:
            if flow_exploit.source_ip in self.seen_external_hosts_dict:
                source_host = self.seen_external_hosts_dict[flow_exploit.source_ip]
            else:
                source_host = Host(flow_exploit.source_ip)
                source_host.update_compromise_attributes(
                    self.external_host_attributes)
                self.seen_external_hosts_dict[flow_exploit.source_ip] = source_host

        if not destination_host:
            if flow_exploit.destination_ip in self.seen_external_hosts_dict:
                destination_host = self.seen_external_hosts_dict[flow_exploit.destination_ip]
            else:
                destination_host = Host(flow_exploit.source_ip)
                destination_host.update_compromise_attributes(
                    self.external_host_attributes)
                self.seen_external_hosts_dict[flow_exploit.destination_ip] = destination_host

        return source_host, destination_host

    def compute_requirements(self, flow_exploit: FlowExploit) -> set[ExploitRequirement] | None:

        source_ip = flow_exploit.source_ip
        destination_ip = flow_exploit.destination_ip

        source_host, destination_host = self._obtain_hosts(flow_exploit)

        source_preconditions, destination_preconditions = flow_exploit.attack_type.get_preconditions()

        complete_host_dict = self.host_dict | self.seen_external_hosts_dict

        red_src_conditions = set(source_preconditions)
        red_dst_conditions = set(destination_preconditions)

        source_attributes = source_host.get_compromise_attributes()
        for condition in source_preconditions:
            if len(source_attributes.intersection(condition.compromise_attributes)) > 0:
                red_src_conditions.remove(condition)

        destination_attributes = destination_host.get_compromise_attributes()
        for condition in destination_preconditions:
            if len(destination_attributes.intersection(condition.compromise_attributes)) > 0:
                red_dst_conditions.remove(condition)

        if len(red_dst_conditions) > 0 and len(red_src_conditions) > 0:
            return None

        if len(red_dst_conditions) == 0 and len(red_src_conditions) == 0:
            return set()

        red_ip = ""
        if len(red_src_conditions) > 0:
            red_ip = source_ip
        elif len(red_dst_conditions) > 0:
            red_ip = destination_ip
        red_host = complete_host_dict[red_ip]

        green_attacks = []
        for attack_type in self.attack_types:
            red_conditions = red_dst_conditions.union(red_src_conditions)
            red_cond_copy = set(red_conditions)
            for condition in red_conditions:
                if len(attack_type.postconditions.intersection(condition.compromise_attributes)) > 0:
                    red_cond_copy.remove(condition)
            if len(red_cond_copy) == 0:
                green_attacks.append(attack_type)

        if len(green_attacks) == 0:
            return None

        blue_dict = {addr: []
                     for addr in complete_host_dict.keys()}

        for ip_addr, host in complete_host_dict.items():
            for attack_type in green_attacks:
                not_satisfied = False
                blue_host_conditions, red_host_conditions = attack_type.get_preconditions()
                for precondition in blue_host_conditions:
                    if len(host.get_compromise_attributes().intersection(precondition.compromise_attributes)) == 0:
                        not_satisfied = True
                        break
                if not not_satisfied:
                    for precondition in red_host_conditions:
                        if len(red_host.get_compromise_attributes().intersection(
                                precondition.compromise_attributes)) == 0:
                            not_satisfied = True
                            break
                if not not_satisfied:
                    blue_dict[ip_addr].append(attack_type)

        n = sum(len(final_attacks)
                for final_attacks in blue_dict.values())

        if n == 0:
            return None

        result = set()
        for attack_type in green_attacks:
            blue_ips = []
            for ip_addr, attacks in blue_dict.items():
                if attack_type in attacks:
                    blue_ips.append(ip_addr)

            if len(blue_ips) > 0:
                result.add(ExploitRequirement(attack_type, blue_ips,
                                              red_ip))

        return result

    def set_postconditions(self, flow_exploit: FlowExploit):
        host = self.host_dict.get(flow_exploit.destination_ip)
        if not host:
            raise ValueError(
                f"Postcondition defined on unknown system host: {flow_exploit.destination_ip}")
        host.update_compromise_attributes(
            flow_exploit.attack_type.postconditions)

    def would_change_state(self, flow_exploit: FlowExploit):
        host = self.host_dict.get(flow_exploit.destination_ip)
        if not host:
            raise ValueError(
                f"Postcondition defined on unknown system host: {flow_exploit.destination_ip}")
        if flow_exploit.attack_type.postconditions.issubset(host.compromise_attributes):
            return False
        return True

    def add_flow_exploit(self, flow_exploit: FlowExploit):
        exploit_group_id = flow_exploit.get_flow_exploit_group_id()
        if exploit_group_id not in self.flow_exploits_dict:
            self.flow_exploits_dict[exploit_group_id] = [flow_exploit]
        else:
            self.flow_exploits_dict[exploit_group_id].append(flow_exploit)

    def add_correlation(self, flow_exploit: FlowExploit):
        self.correlation_sequence.append(
            f"{flow_exploit.get_flow_exploit_group_id()}-{flow_exploit.start_time.isoformat()}")

    def log_exploits(self, ref_flow_exploit: FlowExploit):
        if ref_flow_exploit.get_flow_exploit_group_id() not in self.flow_exploits_dict or ref_flow_exploit.get_flow_exploit_group_id() not in self.exploits_dict or len(
            self.exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()]) == 0 or len(
                self.flow_exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()]) == 0:
            raise RuntimeError(
                "Tried to log exploits while not having any exploit")
        with open(self.flow_exploit_log_path, "a") as f_log:
            f_log.write(ref_flow_exploit.get_flow_exploit_group_id() + "\n")
            for exploit in self.flow_exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()]:
                f_log.write(str(exploit) + "\n")
            f_log.write("\n")
            self.flow_exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()] = [
            ]

        with open(self.exploit_log_path, "a") as e_log:
            e_log.write(ref_flow_exploit.get_flow_exploit_group_id() + "\n")
            for exploit in self.exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()]:
                e_log.write(str(exploit) + "\n")
            e_log.write("\n")
            self.exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()] = [
            ]

    def return_exploits(self) -> dict[str, list[Exploit]]:
        return self.exploits_dict

    def return_flow_exploits(self) -> dict[str, list[FlowExploit]]:
        return self.flow_exploits_dict

    def return_states(self) -> list[NetworkState]:
        return self.state_sequence

    def return_correlations(self) -> list[str]:
        return self.correlation_sequence

    def get_flow_exploit_group_length(self, ref_flow_exploit: FlowExploit) -> int:
        return len(self.flow_exploits_dict[
            ref_flow_exploit.get_flow_exploit_group_id()]) if ref_flow_exploit.get_flow_exploit_group_id() in self.flow_exploits_dict else 0

    def get_state_sequence_length(self):
        return len(self.state_sequence)

    def update_network_state(self, flow_exploit: FlowExploit):
        self.state_sequence.append(NetworkState.from_dict_of_host(
            self.host_dict, flow_exploit.end_time))

    def update_exploits(self, ref_flow_exploit: FlowExploit):
        if ref_flow_exploit.get_flow_exploit_group_id() not in self.flow_exploits_dict or len(
                self.flow_exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()]) == 0:
            raise RuntimeError(
                "Tried to build Exploit objects out of an empty flow exploit dict")
        flow_exploits = self.flow_exploits_dict[ref_flow_exploit.get_flow_exploit_group_id(
        )]
        X = pd.DataFrame([(flow_exploit.start_time.timestamp(), flow_exploit.end_time.timestamp(
        )) for flow_exploit in flow_exploits], columns=["start_time", "end_time"])
        scaler = StandardScaler()
        clusterer = DBSCAN(min_samples=2)
        X_scaled = scaler.fit_transform(X)
        X["step_number"] = clusterer.fit_predict(X_scaled)

        clusters = X[X["step_number"] != -1]
        noise = X[X["step_number"] == -1]
        exploits: list[Exploit] = []
        for _, group in clusters.groupby("step_number"):
            group = group.sort_values("start_time")
            starts = group["start_time"].to_numpy()
            ends = group["end_time"].to_numpy()
            intervals = starts[1:] - ends[:-1]
            exploits.append(Exploit(ref_flow_exploit.attack_type,
                                    len(group),
                                    ref_flow_exploit.source_ip,
                                    ref_flow_exploit.destination_ip,
                                    datetime.fromtimestamp(
                                        min(group["start_time"]), timezone.utc),
                                    datetime.fromtimestamp(
                                        max(group["start_time"]), timezone.utc),
                                    intervals.mean(),
                                    intervals.std()))

        for _, flow_exploit in noise.iterrows():
            exploits.append(Exploit(ref_flow_exploit.attack_type, 1, ref_flow_exploit.source_ip,
                                    ref_flow_exploit.destination_ip,
                                    datetime.fromtimestamp(
                                        flow_exploit["start_time"], timezone.utc),
                                    datetime.fromtimestamp(flow_exploit["start_time"], timezone.utc), -1, -1))
        exploits.sort(key=lambda ex: ex.start_time)
        self.exploits_dict[ref_flow_exploit.get_flow_exploit_group_id()
                           ] = exploits

    def update_exploits_all(self):
        for _, flow_exploit_list in self.flow_exploits_dict.items():
            if len(flow_exploit_list) > 0:
                self.update_exploits(flow_exploit_list[-1])

    def log_states(self):
        with open(self.state_log_path, "a") as s_f:
            for network_state in self.state_sequence:
                s_f.write(str(network_state) + "\n")
        self.state_sequence = []
        with open(self.correlation_log_path, "a") as c_f:
            for correlation in self.correlation_sequence:
                c_f.write(correlation + "\n")
