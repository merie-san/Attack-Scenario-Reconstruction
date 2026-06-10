from datetime import datetime
from enum import Enum


class HostCompromissionAttribute(Enum):
    pass


class Preconditions:

    def __init__(self, compromission_attributes: set[HostCompromissionAttribute], targets_source: bool):
        self.targets_source = targets_source
        self.compromission_attributes = compromission_attributes

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Preconditions):
            return False
        return self.targets_source == value.targets_source and self.compromission_attributes == value.compromission_attributes

    def __hash__(self) -> int:
        to_hash = 0 if self.targets_source else 1
        for att in self.compromission_attributes:
            to_hash += hash(att)

        return hash(to_hash)


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

    def __init__(self, attack_type: AttackType, acceptable_source_ips: list[str], acceptable_destination_ip: str, min_start_time: datetime, max_end_time: datetime):
        self.attack_type = attack_type
        self.acceptable_source_ips = acceptable_source_ips
        self.acceptable_destination_ip = acceptable_destination_ip
        self.min_start_time = min_start_time
        self.max_end_time = max_end_time

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, ExploitRequirement):
            return False
        return self.attack_type == value.attack_type and self.acceptable_source_ips == value.acceptable_source_ips and self.acceptable_destination_ip == value.acceptable_destination_ip and self.min_start_time == value.min_start_time and self.max_end_time == value.max_end_time

    def __hash__(self) -> int:
        src_ips_hash = sum(hash(src_ips)
                           for src_ips in self.acceptable_source_ips)
        return hash(hash(self.attack_type)+src_ips_hash+hash(self.acceptable_destination_ip)+hash(self.min_start_time)+hash(self.max_end_time))


class StarNetworkAttackGraphBasedScenarioReconstructor:

    def __init__(self, hosts: list[Host], attack_types: list[AttackType], log_path: str):
        self.host_dict = {host.ip_address: host for host in hosts}
        self.attack_types = attack_types
        self.exploits_dict = {}
        self.log_path = log_path

    def check_preconditions(self, exploit: Exploit) -> bool:

        source_preconditions, destination_preconditions = exploit.attack_type.get_preconditions()
        source_host = self.host_dict.get(exploit.source_ip)
        destination_host = self.host_dict.get(exploit.destination_ip)

        if not source_host or not destination_host:
            raise ValueError(
                f"Precondition defined on unknown hosts: {exploit.source_ip} {exploit.destination_ip}")

        source_attributes = source_host.get_compromission_attributes()
        for precondition in source_preconditions:
            if len(source_attributes.intersection(precondition.compromission_attributes)) == 0:
                return False

        destination_attributes = destination_host.get_compromission_attributes()
        for precondition in destination_preconditions:
            if len(destination_attributes.intersection(precondition.compromission_attributes)) == 0:
                return False

        return True

    def compute_requirements(self, exploit: Exploit) -> set[ExploitRequirement] | None:

        source_ip = exploit.source_ip
        source_host = self.host_dict.get(source_ip)
        destination_ip = exploit.destination_ip
        destination_host = self.host_dict.get(destination_ip)

        if not source_host or not destination_host:
            raise ValueError(
                f"Precondition defined on unknown hosts: {source_ip} {destination_ip}")

        source_preconditions, destination_preconditions = exploit.attack_type.get_preconditions()

        unsat_src_conditions = set(source_preconditions)
        unsat_dst_conditions = set(destination_preconditions)

        source_attributes = source_host.get_compromission_attributes()
        for condition in source_preconditions:
            if len(source_attributes.intersection(condition.compromission_attributes)) > 0:
                unsat_src_conditions.remove(condition)

        destination_attributes = destination_host.get_compromission_attributes()
        for condition in destination_preconditions:
            if len(destination_attributes.intersection(condition.compromission_attributes)) > 0:
                unsat_dst_conditions.remove(condition)

        if len(unsat_dst_conditions) > 0 and len(unsat_src_conditions) > 0:
            return None

        if len(unsat_dst_conditions) == 0 and len(unsat_src_conditions) == 0:
            return set()

        red_ip = ""
        if len(unsat_src_conditions) > 0:
            red_ip = source_ip
        elif len(unsat_dst_conditions) > 0:
            red_ip = destination_ip
        red_host = self.host_dict[red_ip]

        green_attacks = []
        for attack_type in self.attack_types:
            unsat_conditions = unsat_dst_conditions.union(unsat_src_conditions)
            unsat_cond_copy = set(unsat_conditions)
            for condition in unsat_conditions:
                if len(attack_type.postconditions.intersection(condition.compromission_attributes)) > 0:
                    unsat_cond_copy.remove(condition)
            if len(unsat_cond_copy) == 0:
                green_attacks.append(attack_type)

        if len(green_attacks) == 0:
            return None

        blue_ip_green_attack_dict = {addr: []
                                     for addr in self.host_dict.keys()}

        for ip_addr, host in self.host_dict.items():
            for attack_type in green_attacks:
                not_statisfied = False
                blue_host_conditions, red_host_conditions = attack_type.get_preconditions()
                for precondition in blue_host_conditions:
                    if len(host.get_compromission_attributes().intersection(precondition.compromission_attributes)) == 0:
                        not_statisfied = True
                        break
                if not not_statisfied:
                    for precondition in red_host_conditions:
                        if len(red_host.get_compromission_attributes().intersection(precondition.compromission_attributes)) == 0:
                            not_statisfied = True
                            break
                if not not_statisfied:
                    blue_ip_green_attack_dict[ip_addr].append(attack_type)

        n = sum(len(final_attacks)
                for final_attacks in blue_ip_green_attack_dict.values())

        if n == 0:
            return None

        result = set()
        for attack_type in green_attacks:
            acceptable_source_ips = []
            for ip_addr, attacks in blue_ip_green_attack_dict.items():
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

                result.add(ExploitRequirement(attack_type, acceptable_source_ips,
                           red_ip, last_update_time, exploit.start_time))

        return result

    def set_postconditions(self, exploit: Exploit):
        host = self.host_dict.get(exploit.destination_ip)
        if not host:
            raise ValueError(
                f"Postcondition defined on unknown host: {exploit.destination_ip}")
        host.update_compromission_attributes(
            exploit.attack_type.postconditions)

    def add_exploit(self, exploit: Exploit):
        exploit_id = exploit.get_exploit_id()
        if exploit_id not in self.exploits_dict:
            self.exploits_dict[exploit_id] = [exploit]
        else:
            self.exploits_dict[exploit_id].append(exploit)

    def persist_exploits(self):
        with open(self.log_path, "a") as log_file:
            results_dict = {}
            for exploit_id, exploits in self.exploits_dict.items():
                for exploit in exploits:
                    if exploit.cardinality == 1:
                        log_file.write(str(exploit)+"\n")
                    if exploit_id in results_dict:
                        results_dict[exploit_id] = [results_dict[exploit_id][0].merge(
                            exploit)]
                    else:
                        results_dict[exploit_id] = [exploit]

            self.exploits_dict = results_dict

    def get_exploit_dict_size(self):
        res = 0
        for exploits in self.exploits_dict.values():
            res += len(exploits)
        return res
