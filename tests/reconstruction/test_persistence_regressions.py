"""Identity, temporal, recovery, persistence, and runtime regression contracts."""

from pathlib import Path

from tests.support import ProjectTestCase


class TestPersistenceAndExternalHosts(ProjectTestCase):
    def test_B17_external_destination_does_not_accumulate_state(self):
        rec, flow = self.make_reconstructor(), self.make_flow()
        flow.destination_ip = '203.0.113.8'
        self.assertTrue(rec.check_preconditions(flow))
        self.assertFalse(rec.would_change_state(flow))
        rec.set_postconditions(flow)
        self.assertEqual(rec.seen_external_hosts_dict[flow.destination_ip].compromise_attributes, set())

    def test_B18_periodic_logging_preserves_final_results(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.95))
        predicted_dag, alerts = manager.get_results()
        self.assertEqual(len(alerts), 1, 'BUG-18: logging must not remove accepted evidence from results')
        self.assertEqual(len(predicted_dag.steps), 1)

    def test_B18_logging_preserves_state_history(self):
        rec = self.make_reconstructor()
        before = list(rec.return_states())
        rec.log_states()
        self.assertEqual(rec.return_states(), before, 'BUG-18: logging must not discard historical states')

    def test_B18_repeated_state_logging_does_not_duplicate_states(self):
        rec = self.make_reconstructor()
        rec.log_states()
        first = Path(rec.state_log_path).read_text(encoding='utf-8')
        rec.log_states()
        self.assertEqual(Path(rec.state_log_path).read_text(encoding='utf-8'), first,
                         'BUG-18: each state must be logged once')
