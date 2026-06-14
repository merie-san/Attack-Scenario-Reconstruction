from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.scenario_reconstructor import AttackType


class AttackMapper:

    def __init__(self, attack_types: list[AttackType], type_threshold: float):
        self.attack_dict = {
            attack.identifier: attack for attack in attack_types}
        self.threshold = type_threshold

    def map(self, event: FlowEvent) -> AttackType | None:
        result = None
        if len(event.attack_scores) != len(self.attack_dict):
            raise RuntimeError(
                "provided flow event does not define the same number of attacks")
        for attack, score in event.attack_scores.items():
            if attack not in self.attack_dict:
                raise RuntimeError(
                    "Found attack not defined in provided types")
            if not result:
                if score > self.threshold:
                    result = attack
            else:
                if score > event.attack_scores[result]:
                    result = attack
        return self.attack_dict[result] if result else None
