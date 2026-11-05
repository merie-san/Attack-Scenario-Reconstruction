"""Physical-time aggregation and recovery contracts."""

from datetime import timedelta, timezone

from tests.support import EPOCH, ProjectTestCase


class TestStepAggregation(ProjectTestCase):
    def aggregate(self, rec, flows):
        for flow in flows:
            rec.add_flow_exploit(flow)
        rec.update_exploits_all()
        return rec.return_scenario_dag().steps

    def test_default_gap_is_one_second_and_configuration_is_validated(self):
        self.assertEqual(self.make_reconstructor().max_idle_gap, timedelta(seconds=1))
        self.assertEqual(self.make_reconstructor(max_idle_gap=timedelta(0)).max_idle_gap, timedelta(0))
        with self.assertRaises(ValueError):
            self.make_reconstructor(max_idle_gap=timedelta(microseconds=-1))
        with self.assertRaises(TypeError):
            self.make_reconstructor(max_idle_gap=1)

    def test_default_gap_boundary_is_inclusive_to_the_microsecond(self):
        for start, expected in [(1.999999, 1), (2, 1), (2.000001, 2)]:
            with self.subTest(start=start):
                steps = self.aggregate(self.make_reconstructor(), [self.make_flow(0), self.make_flow(start)])
                self.assertEqual(len(steps), expected)
                self.assertEqual(sum(step.size for step in steps), 2)

    def test_zero_gap_merges_overlap_and_touching_but_not_positive_idle_time(self):
        rec = self.make_reconstructor(max_idle_gap=timedelta(0))
        flows = [self.make_flow(0, duration=3), self.make_flow(1),
                 self.make_flow(3), self.make_flow(4.000001)]
        steps = self.aggregate(rec, flows)
        self.assertEqual([step.size for step in steps], [3, 1])
        self.assertEqual(steps[0].end_time, EPOCH + timedelta(seconds=4))

    def test_nested_overlap_uses_latest_end_and_does_not_mutate_unsorted_input(self):
        rec = self.make_reconstructor(max_idle_gap=timedelta(0))
        long, nested, tail = self.make_flow(0, duration=10), self.make_flow(2), self.make_flow(9, duration=3)
        flows = [tail, nested, long]
        original = list(flows)
        self.assertEqual(rec.group_flow_exploits(flows), [[long, nested, tail]])
        self.assertEqual(flows, original)
        steps = self.aggregate(rec, flows)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].size, 3)
        self.assertEqual(steps[0].start_time, EPOCH)
        self.assertEqual(steps[0].end_time, EPOCH + timedelta(seconds=12))

    def test_custom_gap_allows_unbounded_chains(self):
        rec = self.make_reconstructor(max_idle_gap=timedelta(days=1))
        flows = [self.make_flow(second, duration=0) for second in (0, 86400, 172800)]
        steps = self.aggregate(rec, flows)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].size, 3)
        self.assertEqual(steps[0].end_time - steps[0].start_time, timedelta(days=2))

    def test_contexts_remain_separate_while_ports_do_not_split_a_context(self):
        rec = self.make_reconstructor()
        flows = [self.make_flow(), self.make_flow(source_port='other', destination_port='443'),
                 self.make_flow(attack=self.wrong), self.make_flow(source_ip='other-source'),
                 self.make_flow(destination_ip='other-destination')]
        groups = rec.group_flow_exploits(flows)
        self.assertEqual(sorted(map(len, groups)), [1, 1, 1, 2])
        self.assertEqual(groups[0], flows[:2])
        self.assertEqual(sorted(step.size for step in self.aggregate(rec, flows)), [1, 1, 1, 2])

    def test_distant_history_does_not_change_existing_groups(self):
        rec = self.make_reconstructor()
        first, second = self.make_flow(0, duration=0.0001), self.make_flow(0.001, duration=0.0001)
        distant = self.make_flow(3600)
        self.assertEqual(rec.group_flow_exploits([first, second]), [[first, second]])
        self.assertEqual(rec.group_flow_exploits([distant, second, first]), [[first, second], [distant]])

    def test_statistics_stay_in_milliseconds_and_singletons_keep_duration(self):
        rec = self.make_reconstructor(max_idle_gap=timedelta(seconds=2))
        steps = self.aggregate(rec, [self.make_flow(0), self.make_flow(2), self.make_flow(5),
                                     self.make_flow(20, duration=5)])
        self.assertEqual([step.size for step in steps], [3, 1])
        self.assertEqual(steps[0].mean_interflow_time, 1500)
        self.assertEqual(steps[0].std_interflow_time, 500)
        self.assertEqual(steps[1].start_time, EPOCH + timedelta(seconds=20))
        self.assertEqual(steps[1].end_time, EPOCH + timedelta(seconds=25))
        self.assertEqual((steps[1].mean_interflow_time, steps[1].std_interflow_time), (-1, -1))

    def test_timezone_offsets_and_naive_utc_use_the_same_physical_gap(self):
        rec = self.make_reconstructor()
        offset = timezone(timedelta(hours=2))
        first = self.make_flow(start_time=EPOCH.astimezone(offset),
                               end_time=(EPOCH + timedelta(seconds=1)).astimezone(offset))
        second = self.make_flow(2, start_time=(EPOCH + timedelta(seconds=2)).replace(tzinfo=None),
                                end_time=(EPOCH + timedelta(seconds=3)).replace(tzinfo=None))
        steps = self.aggregate(rec, [second, first])
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].start_time, EPOCH)
        self.assertEqual(steps[0].end_time, EPOCH + timedelta(seconds=3))


class TestRecoveryGrouping(ProjectTestCase):
    def test_recovery_reads_the_reconstructors_custom_gap(self):
        flows = [self.make_flow(0, anomaly_score=0.3), self.make_flow(2, anomaly_score=0.9)]
        for gap, expected in [(timedelta(0), [flows[1]]), (timedelta(seconds=1), flows)]:
            with self.subTest(gap=gap):
                rec = self.make_reconstructor(max_idle_gap=gap)
                manager = self.make_manager(reconstructor=rec)
                score, cluster = manager._find_most_recent_flow_cluster(flows)
                self.assertEqual(cluster, expected)
                self.assertAlmostEqual(score, 0.9 if len(expected) == 1 else 0.6)
                self.assertEqual(cluster, rec.group_flow_exploits(flows)[-1])

    def test_latest_singleton_is_selected_over_an_older_multi_alert_group(self):
        manager = self.make_manager()
        first, second, latest = self.make_flow(), self.make_flow(1), self.make_flow(10, anomaly_score=0.7)
        flows = [latest, first, second]
        score, group = manager._find_most_recent_flow_cluster(flows)
        self.assertEqual(group, [latest])
        self.assertEqual(score, 0.7)
        self.assertEqual(flows, [latest, first, second])

    def test_empty_grouping_is_allowed_but_recovery_requires_evidence(self):
        rec = self.make_reconstructor()
        self.assertEqual(rec.group_flow_exploits([]), [])
        with self.assertRaises(RuntimeError):
            self.make_manager(reconstructor=rec)._find_most_recent_flow_cluster([])
