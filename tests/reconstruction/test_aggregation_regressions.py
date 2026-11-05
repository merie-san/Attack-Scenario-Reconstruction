"""Identity, temporal, recovery, persistence, and runtime regression contracts."""

from tests.support import ProjectTestCase


class TestAggregationIntervals(ProjectTestCase):
    def test_B08_single_flow_exploit_preserves_actual_end(self):
        rec, flow = self.make_reconstructor(), self.make_flow(duration=5)
        rec.add_flow_exploit(flow)
        rec.update_exploits(flow)
        self.assertEqual(rec.return_exploits()[flow.get_flow_exploit_group_id()][0].end_time,
                         flow.end_time, 'BUG-08: singleton exploits must keep flow duration')

    def test_B08_cluster_end_is_maximum_flow_end(self):
        rec = self.make_reconstructor()
        flows = [self.make_flow(duration=5), self.make_flow(duration=5)]
        for flow in flows:
            rec.add_flow_exploit(flow)
        rec.update_exploits(flows[-1])
        steps = rec.return_exploits()[flows[0].get_flow_exploit_group_id()]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].end_time, max(flow.end_time for flow in flows),
                         'BUG-08: cluster intervals must use end times')

    def test_B12_nearby_flows_form_one_step_without_outlier_history(self):
        rec = self.make_reconstructor()
        flows = [self.make_flow(0, duration=0.0001), self.make_flow(0.001, duration=0.0001)]
        for flow in flows:
            rec.add_flow_exploit(flow)
        rec.update_exploits(flows[-1])
        self.assertEqual(len(rec.return_exploits()[flows[0].get_flow_exploit_group_id()]), 1,
                         'BUG-12: a one-millisecond gap must not be split by per-batch scaling')

    def test_B12_recovery_groups_nearby_flows_together(self):
        flows = [self.make_flow(0, duration=0.0001), self.make_flow(0.001, duration=0.0001)]
        _, cluster = self.make_manager()._find_most_recent_flow_cluster(flows)
        self.assertEqual(len(cluster), 2, 'BUG-12: recovery and aggregation need physical-time grouping')

    def test_control_identical_timestamps_do_not_crash(self):
        _, cluster = self.make_manager()._find_most_recent_flow_cluster([self.make_flow(), self.make_flow()])
        self.assertEqual(len(cluster), 2)
