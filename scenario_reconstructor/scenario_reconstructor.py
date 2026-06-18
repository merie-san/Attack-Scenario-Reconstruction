from datetime import datetime
from enum import Enum


class HostAttribute(Enum):
    pass


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
        self._compromise_attributes = set()

    def update_compromise_attributes(self, attributes: set[HostAttribute]):
        self._compromise_attributes.update(attributes)

    def get_compromise_attributes(self) -> set[HostAttribute]:
        return self._compromise_attributes


class AttackType:

    def __init__(self, identifier: str, preconditions: set[Preconditions], postconditions: set[HostAttribute], description: str = ""):
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


class Exploit:

    def __init__(self, attack_type: AttackType, source_ip: str, source_port: str, destination_ip: str, destination_port: str, protocol: str, start_time: datetime, end_time: datetime, anomaly_score: float, density: float):
        self.attack_type = attack_type
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.start_time = start_time
        self.end_time = end_time
        self.density = density
        self.anomaly_score = anomaly_score
        self.cardinality = 1

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Exploit):
            return False
        return self.attack_type == value.attack_type and self.source_ip == value.source_ip and self.source_port == value.source_port and self.destination_ip == value.destination_ip and self.protocol == value.protocol and self.start_time == value.start_time and self.end_time == value.end_time and self.density == value.density and self.anomaly_score == value.anomaly_score and self.cardinality == value.cardinality

    def set_cardinality(self, cardinality: int):
        self.cardinality = cardinality

    def get_exploit_id(self) -> str:
        return f"{self.attack_type.identifier}-{self.destination_ip}-{self.destination_port}-{self.source_ip}-{self.source_port}-{self.protocol}"

    def __str__(self) -> str:
        return f"Exploit(attack_type={self.attack_type.identifier}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, anomaly_score={self.anomaly_score})"

    def merge(self, exploit: "Exploit") -> "Exploit":
        if self.attack_type != exploit.attack_type or self.source_ip != exploit.source_ip or self.source_port != exploit.source_port or self.destination_ip != exploit.destination_ip or self.destination_port != exploit.destination_port or self.protocol != exploit.protocol:
            raise ValueError(
                f"the provided exploit object for merging is incompatible - obj1: {self} obj2: {exploit}")
        if exploit.start_time > self.start_time and exploit.start_time < self.end_time or exploit.end_time > self.start_time and exploit.end_time < self.end_time:
            raise ValueError(
                f"exploit flows overlap in time\tobj1 {self.start_time.isoformat()} - {self.end_time.isoformat()}\tobj2 {exploit.start_time.isoformat()} - {exploit.end_time.isoformat()}")
        new_start_time = self.start_time
        new_end_time = self.end_time
        if exploit.start_time < self.start_time:
            new_start_time = exploit.start_time
        if exploit.end_time > self.end_time:
            new_end_time = exploit.end_time
        new_density = (self.density*(self.end_time-self.start_time).total_seconds()+exploit.density*(
            exploit.end_time-exploit.start_time).total_seconds())/(new_end_time-new_start_time).total_seconds()
        new_anomaly_score = (self.anomaly_score*self.cardinality+exploit.anomaly_score *
                             exploit.cardinality)/(self.cardinality+exploit.cardinality)
        new_cardinality = self.cardinality+exploit.cardinality
        new_exploit = Exploit(self.attack_type, self.source_ip, self.source_port, self.destination_ip,
                              self.destination_port, self.protocol, new_start_time, new_end_time, new_anomaly_score, new_density)
        new_exploit.set_cardinality(new_cardinality)
        return new_exploit


class ExploitRequirement:

    def __init__(self, attack_type: AttackType, acceptable_source_ips: list[str], acceptable_destination_ip: str):
        self.attack_type = attack_type
        self.acceptable_source_ips = acceptable_source_ips
        self.acceptable_destination_ip = acceptable_destination_ip

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, ExploitRequirement):
            return False
        return self.attack_type == value.attack_type and set(self.acceptable_source_ips) == set(value.acceptable_source_ips) and self.acceptable_destination_ip == value.acceptable_destination_ip

    def __hash__(self) -> int:
        src_ips_hash = sum(hash(src_ips)
                           for src_ips in self.acceptable_source_ips)
        return hash(hash(self.attack_type)+src_ips_hash+hash(self.acceptable_destination_ip))


class StarNetworkAttackGraphBasedScenarioReconstructor:

    def __init__(self, internal_hosts: list[Host], external_host_attributes: set[HostAttribute], host_attributes: type[HostAttribute], attack_types: list[AttackType], exploit_log_path: str, state_log_path: str):
        self.host_dict = {host.ip_address: host for host in internal_hosts}
        self.external_host_attributes = external_host_attributes
        self.seen_external_hosts_dict = {}
        self.attack_types = attack_types
        self.exploits_dict = {}
        self.exploit_log_path = exploit_log_path
        self.aggregated_exploits = {}
        initial_state = {ip_addr: set() for ip_addr in self.host_dict}
        self.state_sequence = [initial_state]
        self.exploit_sequence = []
        self.state_log_path = state_log_path

    def check_preconditions(self, exploit: Exploit) -> bool:

        source_preconditions, destination_preconditions = exploit.attack_type.get_preconditions()
        source_host, destination_host = self._obtain_hosts(exploit)

        source_attributes = source_host.get_compromise_attributes()
        for precondition in source_preconditions:
            if len(source_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        destination_attributes = destination_host.get_compromise_attributes()
        for precondition in destination_preconditions:
            if len(destination_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        return True

    def _obtain_hosts(self, exploit: Exploit):
        source_host = self.host_dict.get(exploit.source_ip)
        destination_host = self.host_dict.get(exploit.destination_ip)

        if not source_host and not destination_host:
            raise ValueError(
                f"Precondition defined on two external ips: {exploit.source_ip} {exploit.destination_ip}")

        if not source_host:
            if exploit.source_ip in self.seen_external_hosts_dict:
                source_host = self.seen_external_hosts_dict[exploit.source_ip]
            else:
                source_host = Host(exploit.source_ip)
                source_host.update_compromise_attributes(
                    self.external_host_attributes)
                self.seen_external_hosts_dict[exploit.source_ip] = source_host

        if not destination_host:
            if exploit.destination_ip in self.seen_external_hosts_dict:
                destination_host = self.seen_external_hosts_dict[exploit.destination_ip]
            else:
                destination_host = Host(exploit.source_ip)
                destination_host.update_compromise_attributes(
                    self.external_host_attributes)
                self.seen_external_hosts_dict[exploit.destination_ip] = destination_host

        return source_host, destination_host

    def compute_requirements(self, exploit: Exploit) -> set[ExploitRequirement] | None:

        source_ip = exploit.source_ip
        destination_ip = exploit.destination_ip

        source_host, destination_host = self._obtain_hosts(exploit)

        source_preconditions, destination_preconditions = exploit.attack_type.get_preconditions()

        complete_host_dict=self.host_dict | self.seen_external_hosts_dict

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
                not_statisfied = False
                blue_host_conditions, red_host_conditions = attack_type.get_preconditions()
                for precondition in blue_host_conditions:
                    if len(host.get_compromise_attributes().intersection(precondition.compromise_attributes)) == 0:
                        not_statisfied = True
                        break
                if not not_statisfied:
                    for precondition in red_host_conditions:
                        if len(red_host.get_compromise_attributes().intersection(precondition.compromise_attributes)) == 0:
                            not_statisfied = True
                            break
                if not not_statisfied:
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

    def set_postconditions(self, exploit: Exploit):
        host = self.host_dict.get(exploit.destination_ip)
        if not host:
            raise ValueError(
                f"Postcondition defined on unknown system host: {exploit.destination_ip}")
        host.update_compromise_attributes(
            exploit.attack_type.postconditions)

    def add_exploit(self, exploit: Exploit):
        exploit_id = exploit.get_exploit_id()
        if exploit_id not in self.exploits_dict:
            self.exploits_dict[exploit_id] = [exploit]
        else:
            self.exploits_dict[exploit_id].append(exploit)

    def persist_exploits(self):
        with open(self.exploit_log_path, "a") as log_file:
            results_dict = self.aggregated_exploits
            for exploit_id, exploits in self.exploits_dict.items():
                for exploit in exploits:
                    log_file.write(str(exploit)+"\n")
                    if exploit_id in results_dict:
                        results_dict[exploit_id] = [results_dict[exploit_id].merge(
                            exploit)]
                    else:
                        results_dict[exploit_id] = exploit

            self.exploits_dict = {exploit_id: []
                                  for exploit_id in results_dict}
            self.aggregated_exploits = results_dict

    def get_exploit_dict_size(self):
        res = 0
        for exploits in self.exploits_dict.values():
            res += len(exploits)
        return res

    def get_state_sequence_size(self):
        return len(self.state_sequence)

    def update_network_state(self, exploit: Exploit):
        new_network_state = {}
        for ip_addr, host in self.host_dict.items():
            new_network_state[ip_addr] = host.get_compromise_attributes()
        self.state_sequence.append(new_network_state)
        self.exploit_sequence.append(exploit)

    def persist_history(self):
        with open(self.state_log_path, "a") as f:
            for i in range(len(self.exploit_sequence)):
                str_conv = "-".join([f"{ip_addr}={{"+f"{', '.join([att.value for att in att_set])}" +
                                    "}" for ip_addr, att_set in self.state_sequence[i].items()])
                f.write(f"State({str_conv})"+'\n')
                f.write(str(self.exploit_sequence[i])+'\n')
            str_conv = "-".join([f"{ip_addr}={{"+f"{', '.join([att.value for att in att_set])}" +
                                "}" for ip_addr, att_set in self.state_sequence[-1].items()])
            f.write(f"State({str_conv})"+'\n')
        self.state_sequence = []
        self.exploit_sequence = []
