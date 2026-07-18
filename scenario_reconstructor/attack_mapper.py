from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.scenario_reconstructor import AttackType


class AttackMapper:

    def __init__(self, attack_types: list[AttackType], type_threshold: float):
        self.attack_dict = {
            attack.identifier: attack for attack in attack_types}
        self.threshold = type_threshold

    def map(self, event: FlowEvent) -> tuple[None | AttackType, list[AttackType]]:
        if set(event.attack_scores.keys()) != set(self.attack_dict.keys()):
            raise RuntimeError(
                "provided flow event does not define the same number of attacks")
        possible_names = []
        for attack, score in event.attack_scores.items():
            if score > self.threshold:
                possible_names.append(attack)
        max_score = 0
        attack_type = None
        for name in possible_names:
            if event.attack_scores[name] > max_score:
                max_score = event.attack_scores[name]
                attack_type = self.attack_dict[name]
        other_attacks = [self.attack_dict[name] for name in possible_names if self.attack_dict[name] != attack_type]
        return attack_type, other_attacks
