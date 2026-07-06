from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.scenario_reconstructor import AttackType


class AttackMapper:

    def __init__(self, attack_types: list[AttackType], type_threshold: float):
        self.attack_dict = {
            attack.identifier: attack for attack in attack_types}
        self.threshold = type_threshold

    def map(self, event: FlowEvent) -> list[AttackType]:
        if set(event.attack_scores.keys()) != set(self.attack_dict.keys()):
            raise RuntimeError(
                "provided flow event does not define the same number of attacks")
        possible_types = []
        for attack, score in event.attack_scores.items():
            if score > self.threshold:
                possible_types.append(self.attack_dict[attack])
        possible_types.sort(key=lambda x: event.attack_scores[x.identifier])
        return possible_types
