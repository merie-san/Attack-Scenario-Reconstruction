"""Map scored flow events to classified alerts."""

from event_convertor.flow_event import FlowEvent

from .attack_mapper import AttackMapper
from .models import AttackType, FlowAlert


class AlertFactory:
    def __init__(self, mapper: AttackMapper, suspect_threshold: float, unknown_attack: AttackType) -> None:
        self.mapper = mapper
        self.suspect_threshold = suspect_threshold
        self.unknown_attack = unknown_attack

    def from_event(self, flow_event: FlowEvent) -> FlowAlert:
        if flow_event.anomaly_score <= self.suspect_threshold:
            raise RuntimeError("The flow event must exceed the suspect threshold")
        main_type, secondary_types = self.mapper.map(flow_event)
        return FlowAlert(main_type if main_type else self.unknown_attack,
                           secondary_types,
                           flow_event.source_ip,
                           flow_event.source_port, flow_event.destination_ip, flow_event.destination_port,
                           flow_event.protocol, flow_event.start_time, flow_event.end_time, flow_event.anomaly_score)

    to_flow_exploit = from_event
