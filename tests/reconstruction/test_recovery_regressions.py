"""Identity, temporal, recovery, persistence, and runtime regression contracts."""

from datetime import timedelta
from math import nextafter
from unittest.mock import patch

import pandas as pd

from metrics import MetricsCalculator
from scenario_reconstructor.models import Precondition
from tests.support import Attribute, EPOCH, ProjectTestCase, TARGET


class TestRecoveryValidation(ProjectTestCase):
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

    def test_B14_support_is_available_from_its_first_flow_start(self):
        manager = self.make_manager()
        manager.accept(self.make_event(second=0, duration=20))
        manager.accept(self.trigger())
        self.assertEqual([flow.attack_type for flow in manager.get_fns()], [self.discover])
        self.assertIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes)

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
        self.wrong.preconditions = {Precondition({Attribute.COMPROMISED}, True)}
        event = self.make_event(second=10, score=0.95,
                           scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.9})
        with patch.object(manager, '_recover_fns', return_value=None):
            manager.accept(event)
        self.assertNotIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes,
                         'BUG-16: alternative-type recovery also needs a final precondition check')

    def test_B21_anomaly_threshold_boundary_matches_detection_metrics(self):
        for score, detected in ((nextafter(0.8, 0.0), False), (0.8, False),
                                (nextafter(0.8, 1.0), True)):
            with self.subTest(score=score):
                manager = self.make_manager()
                manager.accept(self.make_event(score=score))
                _, alerts = manager.get_results()
                frame = pd.DataFrame({'label': ['discover', 'normal'], 'anomaly_score': [score, 0.0]})
                _, _, _, tp = MetricsCalculator.get_detection_confusion_matrix(frame, 0.8)
                self.assertEqual(tp, int(detected))
                self.assertEqual(len(alerts), tp)
                self.assertEqual(sum(map(len, manager.suspect_dict.values())), int(not detected))

    def test_B21_suspect_threshold_is_exclusive(self):
        for score, suspect in ((nextafter(0.2, 0.0), False), (0.2, False),
                               (nextafter(0.2, 1.0), True)):
            with self.subTest(score=score):
                manager = self.make_manager()
                manager.accept(self.make_event(score=score))
                self.assertEqual(sum(map(len, manager.suspect_dict.values())), int(suspect))
                self.assertEqual(manager.get_results()[1], [])
                self.assertEqual(manager.get_fps(), [])
                self.assertEqual(manager.get_fns(), [])

    def test_B21_suspect_threshold_must_be_below_anomaly_threshold(self):
        for suspect, anomaly in ((0.8, 0.2), (0.8, 0.8)):
            with self.subTest(suspect=suspect, anomaly=anomaly):
                with self.assertRaisesRegex(ValueError, 'suspect_threshold.*less than.*anomaly_threshold'):
                    self.make_manager(suspect_threshold=suspect, anomaly_threshold=anomaly)
