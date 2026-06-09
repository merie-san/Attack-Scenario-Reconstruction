from datetime import datetime
from enum import Enum


class HostCompromissionAttribute(Enum):
    ENTRY_POINT_SELECTED = "entry_point_selected"
    TARGET_SELECTED = "target_selected"
    HOST_INFECTED = "host_infected"
    GOAL_ACHIEVED = "goal_achieved"


class Preconditions:

    def __init__(self, compromission_attributes: set[HostCompromissionAttribute]):
        self.compromission_attributes = compromission_attributes


class Host:

    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self._compromission_attributes = set()

    def update_compromission_attributes(self, attributes: set[HostCompromissionAttribute]):
        self._compromission_attributes.update(attributes)

    def get_compromission_attributes(self) -> set[HostCompromissionAttribute]:
        return self._compromission_attributes


class AttackType:

    def __init__(self, identifier: str, preconditions: set[Preconditions], postconditions: set[HostCompromissionAttribute], description: str = ""):
        self.identifier = identifier
        self.description = description
        self.preconditions = preconditions
        self.postconditions = postconditions

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, AttackType):
            return False
        return self.identifier == value.identifier

    def __hash__(self) -> int:
        return hash(self.identifier)

    def __str__(self) -> str:
        return self.identifier


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

    def set_cardinality(self, cardinality: int):
        self.cardinality = cardinality

    def get_exploit_id(self) -> str:
        return f"{self.attack_type.identifier}-{self.destination_ip}-{self.destination_port}-{self.source_ip}-{self.source_port}-{self.protocol}"

    def __str__(self) -> str:
        return f"Exploit(attack_type={self.attack_type.identifier}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, start_time={self.start_time.isoformat()}, end_time={self.end_time.isoformat()}, anomaly_score={self.anomaly_score}, density={self.density}, cardinality={self.cardinality})"

    def merge(self, exploit: "Exploit") -> "Exploit":
        if self.attack_type != exploit.attack_type or self.source_ip != exploit.source_ip or self.source_port != exploit.source_port or self.destination_ip != exploit.destination_ip or self.destination_port != exploit.destination_port or self.protocol != exploit.protocol:
            raise ValueError(
                f"the provided exploit object for merging is incompatible - obj1: {self} obj2: {exploit}")
        if exploit.start_time>self.start_time and exploit.start_time<self.end_time or  exploit.end_time>self.start_time and exploit.end_time<self.end_time:
            raise ValueError(f"exploit flows overlap in time\tobj1 {self.start_time.isoformat()} - {self.end_time.isoformat()}\tobj2 {exploit.start_time.isoformat()} - {exploit.end_time.isoformat()}")
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


class ExploitRequirements:

    def __init__(self, attack_type: AttackType, acceptable_source_ips: list[str], acceptable_destination_ip: str, min_start_time: datetime, max_end_time: datetime):
        self.attack_type = attack_type
        self.acceptable_source_ips = acceptable_source_ips
        self.acceptable_destination_ip = acceptable_destination_ip
        self.start_time = min_start_time
        self.end_time = max_end_time


class StarNetworkAttackGraphBasedScenarioReconstructor:

    def __init__(self, hosts: list[Host], attack_types: list[AttackType], log_path: str):
        self.host_dict = {host.ip_address: host for host in hosts}
        self.attack_types = attack_types
        self.exploits_dict = {}
        self.log_path = log_path

    def check_preconditions(self, exploit: Exploit) -> bool:
        host = self.host_dict.get(exploit.source_ip)
        if not host:
            raise ValueError(
                f"Precondition defined on unknown host: {exploit.source_ip}")
        host_attributes = host.get_compromission_attributes()
        for precondition in exploit.attack_type.preconditions:
            if len(host_attributes.intersection(precondition.compromission_attributes)) == 0:
                return False
        return True

    def check_exploit_requirements(self, exploit: Exploit) -> set[ExploitRequirements]:
        host_ip = exploit.source_ip
        red_host = self.host_dict.get(host_ip)
        if not red_host:
            raise ValueError(
                f"Precondition defined on unknown host: {host_ip}")
        red_conditions = set(exploit.attack_type.preconditions)
        for precondition in exploit.attack_type.preconditions:
            if len(red_host.get_compromission_attributes().intersection(precondition.compromission_attributes)) > 0:
                red_conditions.remove(precondition)

        if len(red_conditions) == 0:
            return set()

        green_attacks = []
        for attack_type in self.attack_types:
            not_satisfied = False
            for condition in red_conditions:
                if len(attack_type.postconditions.intersection(condition.compromission_attributes)) == 0:
                    not_satisfied = True
                    break
            if not not_satisfied:
                green_attacks.append(attack_type)

        blue_attacks = {addr: [] for addr in self.host_dict.keys()}

        for ip_addr, host in self.host_dict.items():
            for attack_type in green_attacks:
                not_statisfied = False
                for precondition in attack_type.preconditions:
                    if len(host.get_compromission_attributes().intersection(precondition.compromission_attributes)) == 0:
                        not_statisfied = True
                        break
                if not not_statisfied:
                    blue_attacks[ip_addr].append(attack_type)

        result = set()
        for attack_type in green_attacks:
            acceptable_source_ips = []
            for ip_addr, attacks in blue_attacks.items():
                if attack_type in attacks:
                    acceptable_source_ips.append(ip_addr)

            if len(acceptable_source_ips) > 0:
                last_update_time = datetime.now()
                updated = False
                for ip_addr in acceptable_source_ips:
                    for exploit_id in self.exploits_dict.keys():
                        if ip_addr == exploit_id.split('-')[1] and self.exploits_dict[exploit_id][-1].end_time < last_update_time:
                            last_update_time = self.exploits_dict[exploit_id][-1].end_time
                            updated = True

                if not updated:
                    last_update_time = datetime.min

                result.add(ExploitRequirements(attack_type, acceptable_source_ips,
                           exploit.source_ip, last_update_time, exploit.start_time))

        return result

    def set_postconditions(self, exploit: Exploit):
        host = self.host_dict.get(exploit.destination_ip)
        if not host:
            raise ValueError(
                f"Postcondition defined on unknown host: {exploit.destination_ip}")
        host.update_compromission_attributes(
            exploit.attack_type.postconditions)

    def add_exploit(self, exploit: Exploit):
        if not self.check_preconditions(exploit):
            raise ValueError(
                f"Preconditions not satisfied for exploit: {exploit}")
        exploit_id = exploit.get_exploit_id()
        if exploit_id not in self.exploits_dict:
            self.exploits_dict[exploit_id] = [exploit]
        else:
            self.exploits_dict[exploit_id].append(exploit)
        self.set_postconditions(exploit)

    def merge_exploits(self):

        with open(self.log_path, "a") as log_file:
            results_dict = {}
            for exploit_id, exploits in self.exploits_dict.items():
                for exploit in exploits:
                    if exploit.cardinality == 1:
                        log_file.write(str(exploit)+"\n")
                    if exploit_id in results_dict:
                        results_dict[exploit_id] = results_dict[exploit_id].merge(
                            exploit)
                    else:
                        results_dict[exploit_id] = exploit

            self.exploits_dict = results_dict

    def get_exploit_dict_size(self):
        res = 0
        for exploits in self.exploits_dict.values():
            res += len(exploits)
        return res
