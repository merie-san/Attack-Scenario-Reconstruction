"""Standalone aggregation keeps the context of each resulting temporal cluster."""

from datetime import timedelta

from scenario_reconstructor.aggregation import aggregate_alerts
from tests.support import ProjectTestCase


class TestAggregationFunctions(ProjectTestCase):
    def test_mixed_context_input_retains_each_clusters_type_and_hosts(self):
        first = self.make_flow(0)
        other = self.make_flow(2, attack=self.wrong, destination_ip='10.0.0.9')
        steps = aggregate_alerts([other, first], timedelta(seconds=1))
        self.assertEqual([step.attack_type for step in steps], [self.discover, self.wrong])
        self.assertEqual([step.destination_ip for step in steps], [first.destination_ip, other.destination_ip])
