"""Network-state validation and accepted-evidence lifecycle."""

from datetime import datetime, timedelta

from .aggregation import aggregate_alerts, group_alerts
from .dag import AttackScenarioDAG
from .models import (
    AttackStep,
    AttackType,
    FlowAlert,
    Host,
    HostAttribute,
    NetworkState,
    RecoveryRequirement,
)
from .storage import EvidenceStore


class ScenarioReconstructor(EvidenceStore):
    """Validate alerts against internal network state and aggregate accepted evidence."""

    def __init__(self, internal_hosts: list[Host], external_host_attributes: set[HostAttribute],
                 attack_types: list[AttackType], flow_exploit_log_path: str, state_log_path: str,
                 *, max_idle_gap: timedelta = timedelta(seconds=1)):
        if not isinstance(max_idle_gap, timedelta):
            raise TypeError("max_idle_gap must be a timedelta")
        if max_idle_gap < timedelta(0):
            raise ValueError("max_idle_gap cannot be negative")
        self.max_idle_gap = max_idle_gap
        self.host_dict = {host.ip_address: host for host in internal_hosts}
        self.external_host_attributes = set(external_host_attributes)
        self.seen_external_hosts_dict = {}
        self.attack_types = attack_types
        super().__init__(flow_exploit_log_path, state_log_path)
        self.exploits_dict: dict[str, list[AttackStep]] = {}
        initial_state = NetworkState.from_dict_of_host(
            self.host_dict, datetime.min)
        self.state_sequence = [initial_state]

    def reset(self, initial_attributes: dict[Host, set[HostAttribute]]) -> None:
        for host in self.host_dict.values():
            host.reset_attributes()
        for host in self.host_dict.values():
            host.update_compromise_attributes(initial_attributes[host])
        self.seen_external_hosts_dict = {}
        self._reset_evidence()
        self.exploits_dict = {}
        initial_state = NetworkState.from_dict_of_host(
            self.host_dict, datetime.min)
        self.state_sequence = [initial_state]

    def check_preconditions(self, flow_exploit: FlowAlert) -> bool:

        source_preconditions, destination_preconditions = flow_exploit.attack_type.get_preconditions()
        source_host, destination_host = self._obtain_hosts(flow_exploit)

        source_attributes = self._host_attributes(source_host)
        for precondition in source_preconditions:
            if len(source_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        destination_attributes = self._host_attributes(destination_host)
        for precondition in destination_preconditions:
            if len(destination_attributes.intersection(precondition.compromise_attributes)) == 0:
                return False

        return True

    def _host_attributes(self, host: Host) -> set[HostAttribute]:
        """External addresses provide context, never accumulated compromise state."""
        if host.ip_address not in self.host_dict:
            return self.external_host_attributes
        return host.get_compromise_attributes()

    def _obtain_hosts(self, flow_exploit: FlowAlert):
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
                destination_host = Host(flow_exploit.destination_ip)
                destination_host.update_compromise_attributes(
                    self.external_host_attributes)
                self.seen_external_hosts_dict[flow_exploit.destination_ip] = destination_host

        return source_host, destination_host

    def compute_requirements(self, flow_exploit: FlowAlert) -> set[RecoveryRequirement] | None:
        """Find single-step ways to supply missing attributes on an internal host."""
        source_host, destination_host = self._obtain_hosts(flow_exploit)
        source_conditions, destination_conditions = flow_exploit.attack_type.get_preconditions()
        missing_source = {condition for condition in source_conditions
                          if self._host_attributes(source_host).isdisjoint(condition.compromise_attributes)}
        missing_destination = {condition for condition in destination_conditions
                               if self._host_attributes(destination_host).isdisjoint(condition.compromise_attributes)}
        if missing_source and missing_destination:
            return None
        if not missing_source and not missing_destination:
            return set()

        target_ip = flow_exploit.source_ip if missing_source else flow_exploit.destination_ip
        if target_ip not in self.host_dict:
            return None  # External attributes are baseline assumptions, never learned state.
        target_attributes = self._host_attributes(self.host_dict[target_ip])
        missing_conditions = missing_source | missing_destination
        known_hosts = self.host_dict | self.seen_external_hosts_dict

        requirements = set()
        for attack in self.attack_types:
            if any(attack.postconditions.isdisjoint(condition.compromise_attributes)
                   for condition in missing_conditions):
                continue
            source_requirements, destination_requirements = attack.get_preconditions()
            if any(target_attributes.isdisjoint(condition.compromise_attributes)
                   for condition in destination_requirements):
                continue
            acceptable_sources = [
                ip_address for ip_address, host in known_hosts.items()
                if all(not self._host_attributes(host).isdisjoint(condition.compromise_attributes)
                       for condition in source_requirements)
            ]
            if acceptable_sources:
                requirements.add(RecoveryRequirement(attack, acceptable_sources, target_ip))
        return requirements or None

    def set_postconditions(self, flow_exploit: FlowAlert):
        host = self.host_dict.get(flow_exploit.destination_ip)
        if not host:
            return
        host.update_compromise_attributes(
            flow_exploit.attack_type.postconditions)

    def would_change_state(self, flow_exploit: FlowAlert):
        host = self.host_dict.get(flow_exploit.destination_ip)
        if not host:
            return False
        if flow_exploit.attack_type.postconditions.issubset(host.compromise_attributes):
            return False
        return True

    def return_exploits(self) -> dict[str, list[AttackStep]]:
        return self.exploits_dict

    def return_scenario_dag(self) -> AttackScenarioDAG:
        """Build a batch DAG from the currently clustered exploit steps."""
        steps = [step for group in self.exploits_dict.values() for step in group]
        return AttackScenarioDAG(steps, tracked_host_ips=self.host_dict)

    def update_network_state(self, flow_exploit: FlowAlert):
        self.state_sequence.append(NetworkState.from_dict_of_host(
            self.host_dict, flow_exploit.end_time))

    def update_exploits(self, ref_flow_exploit: FlowAlert):
        """Aggregate a group's archived and active alerts, independently of logging/cleanup."""
        self._aggregate_flow_exploits(self._all_flow_exploits_for_group(ref_flow_exploit.get_flow_exploit_group_id()))

    def group_flow_exploits(self, flow_exploits: list[FlowAlert]) -> list[list[FlowAlert]]:
        """Group active or archived alerts using the configured idle-gap policy."""
        return group_alerts(flow_exploits, self.max_idle_gap)

    def _aggregate_flow_exploits(self, flow_exploits: list[FlowAlert]):
        steps = aggregate_alerts(flow_exploits, self.max_idle_gap)
        self.exploits_dict[flow_exploits[0].get_flow_exploit_group_id()] = steps

    def update_exploits_all(self):
        for flow_exploit_list in self.return_all_flow_exploits().values():
            if flow_exploit_list:
                self._aggregate_flow_exploits(flow_exploit_list)
