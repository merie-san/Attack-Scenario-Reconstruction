"""Logging and memory cleanup must preserve the complete reconstructed scenario."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.support import ProjectTestCase


class TestAlertLifecycle(ProjectTestCase):
    def read_records(self, path):
        return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]

    def test_logging_is_incremental_and_does_not_aggregate_or_clear(self):
        rec = self.make_reconstructor()
        first, second = self.make_flow(), self.make_flow(2)
        rec.add_flow_exploit(first)
        self.assertEqual(rec.log_flow_exploits(first), 1)
        self.assertEqual(rec.log_flow_exploits(first), 0)
        self.assertEqual(rec.return_exploits(), {})
        self.assertEqual(rec.return_flow_exploits()[first.get_flow_exploit_group_id()], [first])
        rec.add_flow_exploit(second)
        self.assertEqual(rec.get_unlogged_flow_exploit_group_length(second), 1)
        self.assertEqual(rec.log_flow_exploits(second), 1)
        self.assertEqual(len(self.read_records(rec.flow_exploit_log_path)), 2)
        self.assertEqual(rec.return_all_flow_exploits()[first.get_flow_exploit_group_id()], [first, second])

    def test_cleanup_releases_only_archived_alerts_and_keeps_steps(self):
        rec = self.make_reconstructor()
        first, pending = self.make_flow(), self.make_flow(2)
        other = self.make_flow(3, attack=self.wrong)
        rec.add_flow_exploit(first)
        rec.add_flow_exploit(other)
        rec.update_exploits(first)
        before = list(rec.return_exploits()[first.get_flow_exploit_group_id()])
        self.assertEqual(rec.clean_flow_exploits(first), 0)
        rec.log_flow_exploits(first)
        rec.add_flow_exploit(pending)
        self.assertEqual(rec.clean_flow_exploits(first), 1)
        self.assertEqual(rec.clean_flow_exploits(first), 0)
        self.assertEqual(rec.return_flow_exploits()[first.get_flow_exploit_group_id()], [pending])
        self.assertEqual(rec.return_flow_exploits()[other.get_flow_exploit_group_id()], [other])
        self.assertEqual(rec.return_exploits()[first.get_flow_exploit_group_id()], before)
        self.assertEqual(rec.return_all_flow_exploits()[first.get_flow_exploit_group_id()], [first, pending])

    def test_archive_round_trip_preserves_unknown_types_alternatives_and_duplicates(self):
        rec = self.make_reconstructor()
        flow = self.make_flow(attack=self.unknown, attack_types_alternatives=[self.finish, self.wrong])
        rec.add_flow_exploit(flow)
        rec.add_flow_exploit(flow)
        rec.log_flow_exploits(flow)
        rec.clean_flow_exploits(flow)
        restored = rec.return_all_flow_exploits()[flow.get_flow_exploit_group_id()]
        self.assertEqual(len(restored), 2)
        for item in restored:
            self.assertEqual(vars(item), vars(flow))

    def test_partial_write_is_rolled_back_and_retry_preserves_alerts(self):
        rec = self.make_reconstructor()
        first, second = self.make_flow(), self.make_flow(2)
        rec.add_flow_exploit(first)
        rec.log_flow_exploits(first)
        previous = Path(rec.flow_exploit_log_path).read_bytes()
        rec.add_flow_exploit(second)
        with open(rec.flow_exploit_log_path, 'ab+') as real_archive:
            failing_archive = MagicMock(wraps=real_archive)
            failing_archive.__enter__.return_value = failing_archive
            failing_archive.__exit__.return_value = False

            def partial_write(payload):
                real_archive.write(payload[:len(payload) // 2])
                raise OSError('simulated disk failure')

            failing_archive.write.side_effect = partial_write
            with patch('builtins.open', return_value=failing_archive):
                with self.assertRaises(OSError):
                    rec.log_flow_exploits(second)
        self.assertEqual(Path(rec.flow_exploit_log_path).read_bytes(), previous)
        self.assertEqual(rec.get_unlogged_flow_exploit_group_length(second), 1)
        self.assertEqual(rec.clean_flow_exploits(first), 1)
        self.assertEqual(rec.return_flow_exploits()[first.get_flow_exploit_group_id()], [second])
        rec.log_flow_exploits(second)
        rec.clean_flow_exploits(second)
        self.assertEqual(len(self.read_records(rec.flow_exploit_log_path)), 2)
        self.assertEqual(rec.return_all_flow_exploits()[first.get_flow_exploit_group_id()], [first, second])

    def test_changing_log_paths_keeps_previous_archive_accessible(self):
        rec = self.make_reconstructor()
        first, second = self.make_flow(), self.make_flow(2)
        rec.add_flow_exploit(first)
        rec.log_flow_exploits(first)
        rec.clean_flow_exploits(first)
        rec.change_log_paths(self.log_path('next_alerts.log'), self.log_path('next_states.log'))
        rec.add_flow_exploit(second)
        rec.log_flow_exploits(second)
        rec.clean_flow_exploits(second)
        self.assertEqual(rec.return_all_flow_exploits()[first.get_flow_exploit_group_id()], [first, second])

    def test_reset_excludes_archived_alerts_from_previous_run(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.95))
        flow = next(iter(manager.reconstructor.return_flow_exploits().values()))[0]
        manager.reconstructor.clean_flow_exploits(flow)
        manager.reset({host: set() for host in manager.reconstructor.host_dict.values()})
        dag, alerts = manager.get_results()
        self.assertEqual(dag.steps, [])
        self.assertEqual(alerts, [])
        manager.accept(self.make_event(score=0.95))
        dag, alerts = manager.get_results()
        self.assertEqual(len(dag.steps), 1)
        self.assertEqual(len(alerts), 1)

    def test_logging_and_cleanup_boundaries_do_not_change_aggregation_or_dag(self):
        baseline = self.make_manager()
        archived = self.make_manager(length_when_log_flow_exploits=0)
        # Both managers use the same archive filename, but only archived writes to it.
        for second, attack in [(0, self.discover), (0.1, self.discover), (8, self.discover), (10, self.finish)]:
            scores = {candidate.identifier: float(candidate == attack) for candidate in self.types}
            event = self.make_event(second, score=0.95, scores=scores)
            baseline.accept(event)
            archived.accept(event)
            ref = self.make_flow(second, attack=attack)
            archived.reconstructor.clean_flow_exploits(ref)
        before_dag, before_alerts = baseline.get_results()
        after_dag, after_alerts = archived.get_results()
        self.assertEqual(after_alerts, before_alerts)
        self.assertEqual(after_dag.steps, before_dag.steps)
        self.assertEqual(after_dag.clause_parents_map, before_dag.clause_parents_map)
        self.assertEqual(after_dag.get_causal_pairs(), before_dag.get_causal_pairs())
        self.assertTrue(after_dag.get_adjacent_pairs())
        self.assertTrue(all(not group for group in archived.reconstructor.return_flow_exploits().values()))
        again_dag, again_alerts = archived.get_results()
        self.assertEqual(again_dag.steps, after_dag.steps)
        self.assertEqual(again_alerts, after_alerts)

    def test_logging_threshold_counts_pending_alerts_without_aggregation(self):
        manager = self.make_manager(length_when_log_flow_exploits=1)
        for second in range(5):
            manager.accept(self.make_event(second, score=0.95))
        rec = manager.reconstructor
        self.assertEqual(len(self.read_records(rec.flow_exploit_log_path)), 4)
        self.assertEqual(rec.get_unlogged_flow_exploit_group_length(self.make_flow()), 1)
        self.assertEqual(rec.return_exploits(), {})
        _, alerts = manager.get_results()
        self.assertEqual(len(alerts), 5)

    def test_missing_archive_is_reported_instead_of_returning_incomplete_results(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.95))
        ref = self.make_flow()
        manager.reconstructor.clean_flow_exploits(ref)
        Path(manager.reconstructor.flow_exploit_log_path).unlink()
        with self.assertRaises(FileNotFoundError):
            manager.get_results()
