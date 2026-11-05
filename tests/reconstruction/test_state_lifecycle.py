"""State logging and explicit cleanup preserve complete, independent snapshots."""

from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from scenario_reconstructor.models import NetworkState
from tests.support import Attribute, EPOCH, ProjectTestCase, SOURCE, TARGET


class TestStateLifecycle(ProjectTestCase):
    def append_state(self, rec, second=0, attributes=None):
        state = NetworkState({SOURCE: set(), TARGET: attributes or set()},
                             EPOCH + timedelta(seconds=second))
        rec.state_sequence.append(state)
        return state

    def test_logging_is_incremental_preserves_active_history_and_duplicate_occurrences(self):
        rec = self.make_reconstructor()
        initial = list(rec.return_states())
        self.assertEqual(rec.log_states(), 1)
        first_bytes = Path(rec.state_log_path).read_bytes()
        self.assertEqual(rec.log_states(), 0)
        self.assertEqual(Path(rec.state_log_path).read_bytes(), first_bytes)
        self.assertEqual(rec.return_states(), initial)
        duplicate = self.append_state(rec, attributes={Attribute.DISCOVERED})
        rec.state_sequence.append(duplicate)
        self.assertEqual(rec.log_states(), 2)
        self.assertEqual(rec.return_all_states(), [*initial, duplicate, duplicate])
        self.assertEqual(len(Path(rec.state_log_path).read_text(encoding='utf-8').splitlines()), 3)

    def test_cleanup_removes_only_archived_prefix_without_changing_live_hosts(self):
        rec = self.make_reconstructor()
        initial = list(rec.return_states())
        self.assertEqual(rec.clean_states(), 0)
        rec.log_states()
        pending = self.append_state(rec, attributes={Attribute.DISCOVERED})
        original_buffer = rec.state_sequence
        self.assertEqual(rec.clean_states(), 1)
        self.assertIs(rec.state_sequence, original_buffer)
        self.assertEqual(rec.clean_states(), 0)
        self.assertEqual(rec.return_states(), [pending])
        self.assertEqual(rec.get_unlogged_state_sequence_length(), 1)
        self.assertEqual(rec.host_dict[TARGET].compromise_attributes, set())
        self.assertEqual(rec.return_all_states(), [*initial, pending])
        rec.log_states()
        rec.clean_states()
        self.assertEqual(rec.return_states(), [])
        self.assertEqual(rec.return_all_states(), [*initial, pending])

    def test_path_changes_preserve_old_batches_and_snapshot_values(self):
        rec = self.make_reconstructor()
        expected = list(rec.return_states())
        rec.log_states()
        rec.clean_states()
        rec.change_log_paths(self.log_path('next_alerts.log'), self.log_path('next_states.log'))
        expected.append(self.append_state(rec, attributes={Attribute.DISCOVERED}))
        rec.log_states()
        rec.clean_states()
        rec.host_dict[TARGET].update_compromise_attributes({Attribute.COMPROMISED})
        self.assertEqual(rec.return_all_states(), expected)
        # Mutating a restored result does not mutate the archived record either.
        restored = rec.return_all_states()
        restored[-1].state[TARGET].clear()
        self.assertEqual(rec.return_all_states(), expected)

    def test_reset_starts_a_new_history_without_deleting_prior_records(self):
        rec = self.make_reconstructor()
        self.append_state(rec, attributes={Attribute.DISCOVERED})
        rec.log_states()
        rec.clean_states()
        previous = Path(rec.state_log_path).read_bytes()
        rec.reset({host: {Attribute.OTHER} for host in rec.host_dict.values()})
        expected = list(rec.return_states())
        self.assertEqual(rec.get_unlogged_state_sequence_length(), 1)
        self.assertEqual(rec.return_all_states(), expected)
        rec.log_states()
        rec.clean_states()
        self.assertTrue(Path(rec.state_log_path).read_bytes().startswith(previous))
        self.assertEqual(rec.return_all_states(), expected)

    def test_failed_partial_write_is_truncated_and_retry_does_not_lose_states(self):
        rec = self.make_reconstructor()
        rec.log_states()
        previous = Path(rec.state_log_path).read_bytes()
        pending = self.append_state(rec, attributes={Attribute.DISCOVERED})
        expected = list(rec.return_states())
        with open(rec.state_log_path, 'ab+') as archive:
            failing = MagicMock(wraps=archive)
            failing.__enter__.return_value = failing
            failing.__exit__.return_value = False

            def partial_write(payload):
                archive.write(payload[:len(payload) // 2])
                raise OSError('simulated state archive failure')

            failing.write.side_effect = partial_write
            with patch('builtins.open', return_value=failing):
                with self.assertRaises(OSError):
                    rec.log_states()
        self.assertEqual(Path(rec.state_log_path).read_bytes(), previous)
        self.assertEqual(rec.get_unlogged_state_sequence_length(), 1)
        self.assertEqual(rec.clean_states(), 1)
        self.assertEqual(rec.return_states(), [pending])
        self.assertEqual(rec.log_states(), 1)
        rec.clean_states()
        self.assertEqual(rec.return_all_states(), expected)

    def test_missing_or_truncated_archive_reports_error(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                rec = self.make_reconstructor()
                rec.log_states()
                rec.clean_states()
                path = Path(rec.state_log_path)
                if missing:
                    path.unlink()
                else:
                    path.write_bytes(b'')
                with self.assertRaises(OSError):
                    rec.return_all_states()

    def test_manager_counts_pending_states_and_does_not_clean_automatically(self):
        manager = self.make_manager(length_when_log_states=1)
        rec = manager.reconstructor
        with patch.object(rec, 'log_states', wraps=rec.log_states) as logger:
            manager.accept(self.make_event(score=0.95))  # Initial state + DISCOVERED.
            manager.accept(self.make_event(1, score=0.95))  # No new state.
            self.assertEqual(logger.call_count, 1)
            self.assertEqual(rec.get_state_sequence_length(), 2)
            manager.accept(self.make_event(2, score=0.95,
                           scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.0}))
            self.assertEqual(logger.call_count, 1)
            manager.accept(self.make_event(3, score=0.95,
                           scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
            self.assertEqual(logger.call_count, 2)
        self.assertEqual(rec.get_state_sequence_length(), 4)
        self.assertEqual(rec.get_unlogged_state_sequence_length(), 0)
        self.assertEqual(rec.return_all_states(), rec.return_states())

    def test_periodic_logging_and_cleanup_preserve_history_and_scenario(self):
        baseline = self.make_manager()
        archived = self.make_manager(length_when_log_states=0)
        for second, attack in [(0, self.discover), (1, self.wrong), (2, self.finish)]:
            event = self.make_event(second, score=0.95,
                        scores={candidate.identifier: float(candidate == attack) for candidate in self.types})
            baseline.accept(event)
            archived.accept(event)
            archived.reconstructor.clean_states()
        self.assertEqual(archived.reconstructor.return_states(), [])
        self.assertEqual(archived.reconstructor.return_all_states(), baseline.reconstructor.return_states())
        baseline_dag, baseline_alerts = baseline.get_results()
        archived_dag, archived_alerts = archived.get_results()
        self.assertEqual(archived_alerts, baseline_alerts)
        self.assertEqual(archived_dag.steps, baseline_dag.steps)
        self.assertEqual(archived_dag.clause_parents_map, baseline_dag.clause_parents_map)

    def test_state_archive_failure_keeps_the_complete_accepted_recovery_available(self):
        manager = self.make_manager(length_when_log_states=0)
        manager.accept(self.make_event(score=0.5))
        with patch('builtins.open', side_effect=OSError('simulated state archive failure')):
            with self.assertRaises(OSError):
                manager.accept(self.make_event(10, score=0.95,
                               scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        rec = manager.reconstructor
        self.assertEqual(len(manager.get_fns()), 1)
        self.assertEqual(rec.get_unlogged_state_sequence_length(), 3)
        expected = list(rec.return_states())
        self.assertEqual(rec.clean_states(), 0)
        self.assertEqual(rec.log_states(), 3)
        rec.clean_states()
        self.assertEqual(rec.return_all_states(), expected)
        _, alerts = manager.get_results()
        self.assertEqual([alert.attack_type for alert in alerts], [self.discover, self.finish])
