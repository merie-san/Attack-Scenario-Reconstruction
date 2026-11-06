"""Stream classification, atomic recovery planning, and acceptance."""

from collections import Counter
from collections.abc import Sequence
from copy import copy, deepcopy

from events.models import FlowEvent

from .alerts import AlertFactory
from .attack_mapper import AttackMapper
from .dag import AttackScenarioDAG
from .engine import ScenarioReconstructor
from .models import AttackType, FlowAlert, Host, HostAttribute, RecoveryRequirement
from .recovery import RecoveryCandidate, RecoveryPlan
from .time_utils import normalize_timestamp


class ReconstructionManager:
    """Classify incoming flows and commit coherent recovery plans atomically."""

    def _find_most_recent_flow_cluster(self, flow_exploit_list: list[FlowAlert]) -> tuple[float, list[FlowAlert]]:
        """Select the latest temporal group using the reconstructor's idle-gap policy."""
        clusters = self.reconstructor.group_flow_exploits(flow_exploit_list)
        if not clusters:
            raise RuntimeError("Empty flow exploit list provided")
        most_recent_flows = max(clusters, key=lambda cluster: max(
            normalize_timestamp(flow.end_time) for flow in cluster
        ))
        mean_anomaly_score = sum(
            recent_flow.anomaly_score for recent_flow in most_recent_flows) / len(most_recent_flows)

        return mean_anomaly_score, most_recent_flows

    def __init__(self, reconstructor: ScenarioReconstructor, mapper: AttackMapper,
                 suspect_threshold: float, anomaly_threshold: float, unknown_attack: AttackType,
                 length_when_log_states: int = -1,
                 length_when_log_flow_exploits: int = -1, suspect_list_max_length: int = -1) -> None:
        if not suspect_threshold < anomaly_threshold:
            raise ValueError("suspect_threshold must be strictly less than anomaly_threshold")
        self.generator = AlertFactory(
            mapper, suspect_threshold, unknown_attack)
        self.anomaly_threshold = anomaly_threshold
        self.suspect_threshold = suspect_threshold
        self.reconstructor = reconstructor
        self.suspect_dict: dict[str, list[FlowAlert]] = {}
        self.length_when_log_states = length_when_log_states
        self.length_when_log_flow_exploits = length_when_log_flow_exploits
        self.suspect_list_max_length = suspect_list_max_length
        self.fps = []
        self.fns = []

    def get_fps(self) -> list[FlowAlert]:
        return self.fps

    def get_fns(self) -> list[FlowAlert]:
        return self.fns

    def accept(self, event: FlowEvent):
        if event.anomaly_score > self.suspect_threshold:
            anomaly = self.generator.from_event(event)
            if anomaly.anomaly_score > self.anomaly_threshold:
                plan = self._plan_alert(anomaly)
                if plan is None:
                    plan = self._try_alternative_types(anomaly)
                if plan is not None:
                    self._commit_recovery(plan)
                else:
                    self.fps.append(anomaly)
            else:
                group_id = anomaly.get_flow_exploit_group_id()
                suspects = self.suspect_dict.setdefault(group_id, [])
                suspects.append(anomaly)
                if len(suspects) > self.suspect_list_max_length != -1:
                    self.suspect_dict[group_id] = suspects[self.suspect_list_max_length // 2:]

    def _validation_network(self) -> ScenarioReconstructor:
        """Copy only hosts for simulation; validation never calls buffer or log writers."""
        trial = copy(self.reconstructor)
        trial.host_dict, trial.seen_external_hosts_dict = deepcopy((
            self.reconstructor.host_dict, self.reconstructor.seen_external_hosts_dict,
        ))
        return trial

    def _validate_plan(self, anomaly: FlowAlert, recovered_alerts: Sequence[FlowAlert],
                       suspect_group_id: str | None = None,
                       source_suspects: Sequence[FlowAlert] | None = None) -> RecoveryPlan | None:
        """Validate the entire sequence without changing accepted evidence or real hosts."""
        sources = recovered_alerts if source_suspects is None else source_suspects
        pairs = sorted(zip(recovered_alerts, sources, strict=True),
                       key=lambda pair: normalize_timestamp(pair[0].start_time))
        ordered = tuple(alert for alert, _ in pairs)
        trigger_start = normalize_timestamp(anomaly.start_time)
        if any(normalize_timestamp(alert.start_time) >= trigger_start for alert in ordered):
            return None
        trial = self._validation_network()
        for alert in (*ordered, anomaly):
            if not trial.check_preconditions(alert):
                return None
            if trial.would_change_state(alert):
                trial.set_postconditions(alert)
        return RecoveryPlan(anomaly, ordered, suspect_group_id, tuple(source for _, source in pairs))

    @staticmethod
    def _support_interpretations(alert: FlowAlert,
                                 requirements: set[RecoveryRequirement]) -> list[FlowAlert]:
        """Try the primary type first, then distinct alternatives matching a requirement."""
        interpretations = []
        seen_types = []
        for attack_type in (alert.attack_type, *alert.attack_type_alternatives):
            if attack_type in seen_types:
                continue
            seen_types.append(attack_type)
            if any(attack_type == requirement.attack_type
                   and alert.destination_ip == requirement.acceptable_destination_ip
                   and alert.source_ip in requirement.acceptable_source_ips
                   for requirement in requirements):
                interpretations.append(alert if attack_type == alert.attack_type else alert.reclassify(attack_type))
        return interpretations

    def _plan_alert(self, anomaly: FlowAlert) -> RecoveryPlan | None:
        trial = self._validation_network()
        if trial.check_preconditions(anomaly):
            return self._validate_plan(anomaly, [])
        requirements = trial.compute_requirements(anomaly)
        if not requirements:
            return None

        investigation_dict = {}
        trigger_start = normalize_timestamp(anomaly.start_time)
        for group_id, suspects in self.suspect_dict.items():
            eligible = [alert for alert in suspects
                        if normalize_timestamp(alert.start_time) < trigger_start]
            if eligible:
                investigation_dict[group_id] = eligible
        return self._recover_fns(anomaly, investigation_dict, requirements)

    def _try_alternative_types(self, anomaly: FlowAlert) -> RecoveryPlan | None:
        for alternative in anomaly.attack_type_alternatives:
            plan = self._plan_alert(anomaly.reclassify(alternative))
            if plan is not None:
                return plan
        return None

    def _recover_fns(self, anomaly: FlowAlert,
                     investigation_dict: dict[str, list[FlowAlert]],
                     requirements: set[RecoveryRequirement]) -> RecoveryPlan | None:
        """Project each bucket to uniform types; try primary clusters before alternatives."""
        candidates: list[RecoveryCandidate] = []
        for group_id, investigation_list in investigation_dict.items():
            projections: dict[str, list[FlowAlert]] = {}
            source_by_id: dict[int, FlowAlert] = {}
            for source in investigation_list:
                for interpreted in self._support_interpretations(source, requirements):
                    target_group_id = interpreted.get_flow_exploit_group_id()
                    projections.setdefault(target_group_id, []).append(interpreted)
                    source_by_id[id(interpreted)] = source
            # Filter and reinterpret before clustering. Original buckets remain separate.
            for projected in projections.values():
                mean_score, alerts = self._find_most_recent_flow_cluster(projected)
                sources = [source_by_id[id(alert)] for alert in alerts]
                primary = all(alert.attack_type == source.attack_type
                              for alert, source in zip(alerts, sources, strict=True))
                score = mean_score * len(alerts)
                if score > 0:
                    candidates.append(RecoveryCandidate(primary, score, group_id, tuple(alerts), tuple(sources)))
        candidates.sort(key=lambda candidate: (candidate.is_primary, candidate.score), reverse=True)
        for candidate in candidates:
            plan = self._validate_plan(anomaly, candidate.alerts, candidate.source_group_id, candidate.source_suspects)
            if plan is not None:
                return plan
        return None

    def _commit_recovery(self, plan: RecoveryPlan) -> list[FlowAlert]:
        """Accept a validated sequence in full before consuming suspects or writing logs.

        Logging errors propagate after acceptance; the complete accepted batch is
        retained in memory so a failed archive write cannot discard evidence.
        """
        batch = (*plan.recovered_alerts, plan.alert)
        rec = self.reconstructor
        original_external_hosts = dict(rec.seen_external_hosts_dict)
        original_attributes = [
            (host, host.compromise_attributes, set(host.compromise_attributes))
            for host in (*rec.host_dict.values(), *rec.seen_external_hosts_dict.values())
        ]
        original_groups = {
            alert.get_flow_exploit_group_id(): rec.flow_exploits_dict.get(alert.get_flow_exploit_group_id())
            for alert in batch
        }
        original_lengths = {group_id: len(flows) if flows is not None else 0
                            for group_id, flows in original_groups.items()}
        original_state_length = len(rec.state_sequence)
        try:
            for alert in batch:
                # Recheck the live state and register external hosts only at commit time.
                if not rec.check_preconditions(alert):
                    raise RuntimeError("Network state no longer satisfies the validated recovery plan")
                self._add_to_reconstructor(alert)
        except Exception:
            # No log writes have occurred yet. Preserve existing host and buffer identities.
            for host, original_set, values in original_attributes:
                original_set.clear()
                original_set.update(values)
                host.compromise_attributes = original_set
            rec.seen_external_hosts_dict.clear()
            rec.seen_external_hosts_dict.update(original_external_hosts)
            for group_id, flows in original_groups.items():
                if flows is None:
                    rec.flow_exploits_dict.pop(group_id, None)
                else:
                    del flows[original_lengths[group_id]:]
                    rec.flow_exploits_dict[group_id] = flows
            del rec.state_sequence[original_state_length:]
            raise
        if plan.suspect_group_id is not None:
            # Consume occurrences, not all equal values: identical alerts can repeat.
            consumed = Counter(id(alert) for alert in (plan.source_suspects or plan.recovered_alerts))
            remaining = []
            for alert in self.suspect_dict[plan.suspect_group_id]:
                if consumed[id(alert)]:
                    consumed[id(alert)] -= 1
                else:
                    remaining.append(alert)
            self.suspect_dict[plan.suspect_group_id] = remaining
        recovered = list(plan.recovered_alerts)
        self.fns.extend(recovered)
        for alert in batch:
            self._check_and_log(alert)
        return recovered

    def _add_to_reconstructor(self, anomaly: FlowAlert):
        self.reconstructor.add_flow_exploit(anomaly)
        if self.reconstructor.would_change_state(anomaly):
            self.reconstructor.set_postconditions(anomaly)
            self.reconstructor.update_network_state(anomaly)

    def _check_and_log(self, anomaly: FlowAlert):
        if self.reconstructor.get_unlogged_flow_exploit_group_length(anomaly) > self.length_when_log_flow_exploits != -1:
            self.reconstructor.log_flow_exploits(anomaly)
        if self.reconstructor.get_unlogged_state_sequence_length() > self.length_when_log_states != -1:
            self.reconstructor.log_states()

    def get_results(self) -> tuple[AttackScenarioDAG, list[FlowAlert]]:
        self.reconstructor.update_exploits_all()
        scenario_dag = self.reconstructor.return_scenario_dag()
        flow_exploits_dict = self.reconstructor.return_all_flow_exploits()
        final_alerts = []
        for _, flow_exploit in flow_exploits_dict.items():
            final_alerts.extend(flow_exploit)
        final_alerts.sort(key=lambda x: normalize_timestamp(x.start_time))
        return scenario_dag, final_alerts

    def reset(self, initial_attributes: dict[Host, set[HostAttribute]]):
        self.reconstructor.reset(initial_attributes)
        self.suspect_dict = {}
        self.fps = []
        self.fns = []
