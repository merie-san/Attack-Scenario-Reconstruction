"""Identity, temporal, recovery, persistence, and runtime regression contracts."""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from tests.regression_support import Attribute, EPOCH, SOURCE, TARGET, RegressionCase
from scenario_reconstructor.scenario_reconstructor import (
    ExploitRequirement, NetworkState, Preconditions, StringToNetworkStateConvertor,
)


class TestIdentityAndStateRegressions(RegressionCase):
    def test_B05_destination_port_distinguishes_flow_identity(self):
        self.assertNotEqual(self.make_flow(destination_port='80'), self.make_flow(destination_port='443'),
                            'BUG-05: flows to different destination ports are distinct')

    def test_B05_destination_port_distinguishes_metric_identity(self):
        self.assertNotEqual(self.make_flow(destination_port='80').metric_key,
                            self.make_flow(destination_port='443').metric_key,
                            'BUG-05: metrics must not collapse different destination ports')

    def test_B06_equal_exploits_are_interchangeable_dictionary_keys(self):
        first = self.make_step(mean=1.0, std=2.0)
        nearby = self.make_step(mean=1.00005, std=2.0)
        if first == nearby:
            self.assertIn(nearby, {first: 'same exploit'},
                          'BUG-06: objects comparing equal must share dictionary identity')
        else:
            self.assertTrue(first.approx_match(nearby))

    def test_B06_exploit_equality_is_symmetric_with_unknown_statistics(self):
        unknown = self.make_step(mean=-1, std=-1)
        measured = self.make_step(mean=1, std=2)
        self.assertEqual(unknown == measured, measured == unknown,
                         'BUG-06: sentinel statistics cannot make equality asymmetric')

    def test_B06_exploit_equality_is_transitive(self):
        a, b, c = [self.make_step(mean=mean, std=2) for mean in (1.0, 1.000075, 1.00015)]
        self.assertFalse(a == b and b == c and a != c,
                         'BUG-06: tolerant matching must not be object equality')

    def test_B06_requirement_source_order_and_duplicates_have_consistent_identity(self):
        first = ExploitRequirement(self.discover, [SOURCE], TARGET)
        duplicate = ExploitRequirement(self.discover, [SOURCE, SOURCE], TARGET)
        self.assertEqual(first, duplicate)
        self.assertIn(duplicate, {first}, 'BUG-06: equal source sets must hash consistently')

    def test_B07_later_host_changes_do_not_rewrite_historical_state(self):
        rec = self.make_reconstructor()
        original = NetworkState.from_dict_of_host(rec.host_dict, EPOCH)
        rec.host_dict[TARGET].update_compromise_attributes({Attribute.DISCOVERED})
        self.assertEqual(original.state[TARGET], set(),
                         'BUG-07: snapshots must copy mutable host attribute sets')

    def test_B19_empty_host_attributes_round_trip(self):
        state = NetworkState({TARGET: set()}, EPOCH)
        restored = StringToNetworkStateConvertor(Attribute).from_str(str(state))
        self.assertEqual(restored, state)


class TestTemporalRegressions(RegressionCase):
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


class TestRecoveryRegressions(RegressionCase):
    def trigger(self, **options):
        return self.make_event(second=10, score=0.95,
                          scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}, **options)

    def test_B13_recover_suspect_using_its_alternative_attack_type(self):
        manager = self.make_manager()
        manager.accept(self.make_event(scores={'discover': 0.8, 'wrong': 0.9, 'finish': 0.0}))
        manager.accept(self.trigger())
        self.assertEqual([flow.attack_type for flow in manager.get_fns()], [self.discover],
                         'BUG-13: a viable alternative on the supporting suspect must be tried')
        self.assertEqual(manager.get_fps(), [])

    def test_B14_future_evidence_is_not_recovered_for_a_past_trigger(self):
        manager = self.make_manager()
        manager.accept(self.make_event(second=100))
        manager.accept(self.trigger())
        self.assertEqual(manager.get_fns(), [], 'BUG-14: recovery cannot use future evidence')
        self.assertNotIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes)

    def test_B14_unfinished_support_cannot_enable_an_earlier_action(self):
        manager = self.make_manager()
        manager.accept(self.make_event(second=0, duration=20))
        manager.accept(self.trigger())
        self.assertEqual(manager.get_fns(), [],
                         'BUG-14: conservative causality requires support to finish before the trigger')

    def test_B15_successful_recovery_retains_unused_suspect_clusters(self):
        manager = self.make_manager()
        manager.accept(self.make_event(second=0))
        manager.accept(self.make_event(second=8))
        manager.accept(self.trigger())
        recovered = {flow.start_time for flow in manager.get_fns()}
        remaining = {flow.start_time for group in manager.suspect_dict.values() for flow in group}
        self.assertEqual(remaining, {EPOCH, EPOCH + timedelta(seconds=8)} - recovered,
                         'BUG-15: remove only the evidence consumed by recovery')

    def test_B16_failed_recovery_cannot_commit_trigger(self):
        manager = self.make_manager()
        manager.accept(self.make_event())
        with patch.object(manager, '_recover_fns', return_value=None):
            manager.accept(self.trigger())
        self.assertNotIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes,
                         'BUG-16: recheck trigger preconditions after unsuccessful recovery')
        self.assertEqual(sum(map(len, manager.reconstructor.return_flow_exploits().values())), 0)

    def test_B16_failed_recovery_for_alternative_trigger_cannot_commit(self):
        manager = self.make_manager()
        manager.accept(self.make_event())
        # The primary type has a precondition no available exploit can provide.
        self.wrong.preconditions = {Preconditions({Attribute.COMPROMISED}, True)}
        event = self.make_event(second=10, score=0.95,
                           scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.9})
        with patch.object(manager, '_recover_fns', return_value=None):
            manager.accept(event)
        self.assertNotIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes,
                         'BUG-16: alternative-type recovery also needs a final precondition check')

    def test_B21_anomaly_threshold_boundary_matches_detection_metrics(self):
        manager = self.make_manager()
        manager.accept(self.make_event(score=0.8))
        _, alerts = manager.get_results()
        self.assertEqual(len(alerts), 1,
                         'BUG-21: detection uses >=, so an event exactly at the threshold must agree')

    def test_B21_suspect_threshold_must_be_below_anomaly_threshold(self):
        with self.assertRaises(ValueError, msg='BUG-21: reject an inverted threshold range'):
            self.make_manager(suspect_threshold=0.8, anomaly_threshold=0.2)


class TestPersistenceAndHostRegressions(RegressionCase):
    def test_B17_registered_external_destination_can_receive_postconditions(self):
        rec, flow = self.make_reconstructor(), self.make_flow()
        flow.destination_ip = '203.0.113.8'
        self.assertTrue(rec.check_preconditions(flow))
        self.assertTrue(rec.would_change_state(flow))
        rec.set_postconditions(flow)
        self.assertIn(Attribute.DISCOVERED, rec.seen_external_hosts_dict[flow.destination_ip].compromise_attributes)

    def test_B18_periodic_logging_preserves_final_results(self):
        manager = self.make_manager(length_when_log_exploits=0)
        manager.accept(self.make_event(score=0.95))
        steps, alerts = manager.get_results()
        self.assertEqual(len(alerts), 1, 'BUG-18: logging must not remove accepted evidence from results')
        self.assertEqual(len(steps), 1)

    def test_B18_logging_preserves_state_history(self):
        rec = self.make_reconstructor()
        before = list(rec.return_states())
        rec.log_states()
        self.assertEqual(rec.return_states(), before, 'BUG-18: logging must not discard historical states')

    def test_B18_repeated_state_logging_does_not_duplicate_correlations(self):
        rec = self.make_reconstructor()
        rec.add_correlation(self.make_flow())
        rec.log_states()
        first = Path(rec.correlation_log_path).read_text(encoding='utf-8')
        rec.log_states()
        self.assertEqual(Path(rec.correlation_log_path).read_text(encoding='utf-8'), first,
                         'BUG-18: each correlation must be logged once')
