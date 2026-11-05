"""Attack definitions and the conditions required by recovery proposals."""

from .network import HostAttribute


class Precondition:
    def __init__(self, compromise_attributes: set[HostAttribute], targets_source: bool):
        self.targets_source = targets_source
        self.compromise_attributes = compromise_attributes

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Precondition):
            return False
        return self.targets_source == value.targets_source and self.compromise_attributes == value.compromise_attributes

    def __hash__(self) -> int:
        return hash((self.targets_source, frozenset(self.compromise_attributes)))


class AttackType:
    def __init__(self, identifier: str, preconditions: set[Precondition], postconditions: set[HostAttribute],
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
        return hash((
            self.identifier,
            frozenset(self.preconditions),
            frozenset(self.postconditions),
        ))

    def __str__(self) -> str:
        return self.identifier

    def get_preconditions(self) -> tuple[set[Precondition], set[Precondition]]:
        source_preconditions = set()
        destination_preconditions = set()
        for condition in self.preconditions:
            if condition.targets_source:
                source_preconditions.add(condition)
            else:
                destination_preconditions.add(condition)
        return source_preconditions, destination_preconditions


class RecoveryRequirement:
    """Requirement value with unordered source membership; keep hash identity fields stable."""

    def __init__(self, attack_type: AttackType, acceptable_source_ips: list[str], acceptable_destination_ip: str):
        self.attack_type = attack_type
        self.acceptable_source_ips = acceptable_source_ips
        self.acceptable_destination_ip = acceptable_destination_ip

    @property
    def _identity_key(self):
        return (self.attack_type, frozenset(self.acceptable_source_ips), self.acceptable_destination_ip)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, RecoveryRequirement):
            return False
        return self._identity_key == value._identity_key

    def __hash__(self) -> int:
        return hash(self._identity_key)
