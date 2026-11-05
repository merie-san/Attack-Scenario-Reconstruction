"""Accepted-evidence buffers, incremental archives, and explicit memory cleanup."""

from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path

from .models import AttackType, FlowAlert, HostAttribute, NetworkState
from .serialization import NetworkStateParser


def append_batch(path: str, payload: bytes, kind: str) -> tuple[str, int, int]:
    """Append a batch, removing an incomplete fragment if write or flush fails."""
    path = str(Path(path).resolve())
    with open(path, 'ab+') as archive:
        archive.seek(0, 2)
        start = archive.tell()
        try:
            if archive.write(payload) != len(payload):
                raise OSError(f'Incomplete {kind.lower()} archive write')
            archive.flush()
        except OSError:
            archive.seek(start)
            archive.truncate()
            raise
    return path, start, len(payload)


def read_batch(batch: tuple[str, int, int], kind: str) -> str:
    """Read exactly one current-run batch, failing rather than losing history."""
    path, start, size = batch
    with open(path, 'rb') as archive:
        archive.seek(start)
        payload = archive.read(size)
    if len(payload) != size:
        raise OSError(f'{kind} archive has been truncated: {path}')
    return payload.decode('utf-8')


class EvidenceStore:
    """Store accepted alerts and snapshots; never aggregate or mutate live hosts."""

    def __init__(self, flow_exploit_log_path: str, state_log_path: str) -> None:
        self.flow_exploit_log_path = flow_exploit_log_path
        self.state_log_path = state_log_path
        self._reset_evidence()

    def _reset_evidence(self) -> None:
        self.flow_exploits_dict: dict[str, list[FlowAlert]] = {}
        self.state_sequence: list[NetworkState] = []
        self._logged_flow_counts: dict[str, int] = {}
        self._flow_archive_batches: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        self._archive_attack_types: dict[str, AttackType] = {}
        self._logged_state_count = 0
        self._state_archive_batches: list[tuple[str, int, int]] = []
        self._archive_state_attributes: dict[str, HostAttribute] = {}

    def change_log_paths(self, flow_exploit_log_path: str, state_log_path: str) -> None:
        self.flow_exploit_log_path = flow_exploit_log_path
        self.state_log_path = state_log_path

    def add_flow_exploit(self, flow_exploit: FlowAlert):
        exploit_group_id = flow_exploit.get_flow_exploit_group_id()
        if exploit_group_id not in self.flow_exploits_dict:
            self.flow_exploits_dict[exploit_group_id] = [flow_exploit]
        else:
            self.flow_exploits_dict[exploit_group_id].append(flow_exploit)

    def get_unlogged_flow_exploit_group_length(self, ref_flow_exploit: FlowAlert) -> int:
        group_id = ref_flow_exploit.get_flow_exploit_group_id()
        return len(self.flow_exploits_dict.get(group_id, [])) - self._logged_flow_counts.get(group_id, 0)

    def log_flow_exploits(self, ref_flow_exploit: FlowAlert) -> int:
        """Archive new alerts as JSON lines, without aggregating or clearing them.

        Archive offsets and attack definitions belong to this reconstruction run;
        reset starts a new run without deleting records from previous runs.
        """
        group_id = ref_flow_exploit.get_flow_exploit_group_id()
        flows = self.flow_exploits_dict.get(group_id, [])
        pending = flows[self._logged_flow_counts.get(group_id, 0):]
        if not pending:
            return 0
        records = []
        for flow in pending:
            for attack in [flow.attack_type, *flow.attack_type_alternatives]:
                registered = self._archive_attack_types.get(attack.identifier)
                if registered is not None and registered != attack:
                    raise ValueError(f"Conflicting attack definitions for {attack.identifier}")
                self._archive_attack_types[attack.identifier] = attack
            records.append(json.dumps({
                "group_id": group_id,
                "attack_type": flow.attack_type.identifier,
                "attack_type_alternatives": [attack.identifier for attack in flow.attack_type_alternatives],
                "source_ip": flow.source_ip, "source_port": flow.source_port,
                "destination_ip": flow.destination_ip, "destination_port": flow.destination_port,
                "protocol": flow.protocol,
                "start_time": flow.start_time.isoformat(), "end_time": flow.end_time.isoformat(),
                "anomaly_score": flow.anomaly_score,
            }) + "\n")
        payload = "".join(records).encode("utf-8")
        batch = append_batch(self.flow_exploit_log_path, payload, 'Alert')
        self._flow_archive_batches[group_id].append(batch)
        self._logged_flow_counts[group_id] = len(flows)
        return len(pending)

    def clean_flow_exploits(self, ref_flow_exploit: FlowAlert) -> int:
        """Release only archived alerts from memory; leave pending alerts and steps intact."""
        group_id = ref_flow_exploit.get_flow_exploit_group_id()
        count = self._logged_flow_counts.get(group_id, 0)
        if count:
            del self.flow_exploits_dict[group_id][:count]
            self._logged_flow_counts[group_id] = 0
        return count

    def _all_flow_exploits_for_group(self, group_id: str) -> list[FlowAlert]:
        flows = []
        for batch in self._flow_archive_batches.get(group_id, []):
            for line in read_batch(batch, 'Alert').splitlines():
                record = json.loads(line)
                flows.append(FlowAlert(
                    self._archive_attack_types[record["attack_type"]],
                    [self._archive_attack_types[name] for name in record["attack_type_alternatives"]],
                    record["source_ip"], record["source_port"], record["destination_ip"],
                    record["destination_port"], record["protocol"],
                    datetime.fromisoformat(record["start_time"]), datetime.fromisoformat(record["end_time"]),
                    record["anomaly_score"],
                ))
        flows.extend(self.flow_exploits_dict.get(group_id, [])[self._logged_flow_counts.get(group_id, 0):])
        return flows

    def return_all_flow_exploits(self) -> dict[str, list[FlowAlert]]:
        """Return accepted alerts from the current run, including cleaned archive batches."""
        group_ids = dict.fromkeys([*self.flow_exploits_dict, *self._flow_archive_batches])
        return {group_id: self._all_flow_exploits_for_group(group_id) for group_id in group_ids}

    def return_flow_exploits(self) -> dict[str, list[FlowAlert]]:
        """Return active in-memory alerts; use return_all_flow_exploits for full history."""
        return self.flow_exploits_dict

    def return_states(self) -> list[NetworkState]:
        """Return active snapshots; use return_all_states for the complete history."""
        return self.state_sequence

    def return_all_states(self) -> list[NetworkState]:
        """Restore this run's archived snapshots and append unlogged active states."""
        states = []
        converter = NetworkStateParser(self._archive_state_attributes.__getitem__)
        for batch in self._state_archive_batches:
            states.extend(converter.from_str(line) for line in read_batch(batch, 'State').splitlines())
        states.extend(self.state_sequence[self._logged_state_count:])
        return states

    def get_flow_exploit_group_length(self, ref_flow_exploit: FlowAlert) -> int:
        return len(self.flow_exploits_dict[
                       ref_flow_exploit.get_flow_exploit_group_id()]) if ref_flow_exploit.get_flow_exploit_group_id() in self.flow_exploits_dict else 0

    def get_state_sequence_length(self):
        return len(self.state_sequence)

    def get_unlogged_state_sequence_length(self) -> int:
        return len(self.state_sequence) - self._logged_state_count

    def log_states(self) -> int:
        """Archive pending snapshots without clearing history or updating live hosts."""
        pending = self.state_sequence[self._logged_state_count:]
        if not pending:
            return 0
        for state in pending:
            for attributes in state.state.values():
                for attribute in attributes:
                    key = str(attribute.value)
                    registered = self._archive_state_attributes.get(key)
                    if registered is not None and registered != attribute:
                        raise ValueError(f"Conflicting state attribute definitions for {key}")
                    self._archive_state_attributes[key] = attribute
        payload = ''.join(str(state) + '\n' for state in pending).encode('utf-8')
        self._state_archive_batches.append(append_batch(self.state_log_path, payload, 'State'))
        self._logged_state_count = len(self.state_sequence)
        return len(pending)

    def clean_states(self) -> int:
        """Release only successfully archived snapshots; keep unlogged states active."""
        count = self._logged_state_count
        if count:
            del self.state_sequence[:count]
            self._logged_state_count = 0
        return count
