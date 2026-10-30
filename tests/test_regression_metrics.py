"""Correctness contracts, including currently failing known-bug reproductions."""

import pandas as pd

from tests.regression_support import RegressionCase
from scenario_generator.compute_metrics import MetricsCalculator
from scenario_reconstructor.scenario_reconstructor import AttackType


class TestMetricRegressions(RegressionCase):
    def test_B01_scenario_completeness_counts_all_actual_pairs(self):
        actual = [self.make_step(i, AttackType(f'attack_{i}', set(), set()))
                  for i in range(10)]
        soundness, completeness = MetricsCalculator.get_scenario_soundness_completeness(actual[:2], actual)
        self.assertEqual(soundness, 1.0)
        self.assertAlmostEqual(completeness, 1 / 45,
                               msg='BUG-01: missing steps must remain in the actual pair denominator')

    def test_B02_aggregation_completeness_counts_missing_alerts(self):
        actual_alerts = [self.make_flow(i) for i in range(3)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=2, size=2)], [self.make_step(duration=3, size=3)],
            actual_alerts[:2], actual_alerts,
        )
        self.assertEqual(soundness, 1.0)
        self.assertAlmostEqual(completeness, 1 / 3,
                               msg='BUG-02: missing alerts must remain in the actual pair denominator')

    def test_B03_scenario_soundness_counts_unmatched_predictions(self):
        actual = [self.make_step(i, AttackType(f'attack_{i}', set(), set())) for i in range(2)]
        extra = self.make_step(2, AttackType('false_positive', set(), set()))
        soundness, completeness = MetricsCalculator.get_scenario_soundness_completeness(actual + [extra], actual)
        self.assertAlmostEqual(soundness, 1 / 3,
                               msg='BUG-03: unmatched predicted steps still contribute predicted pairs')
        self.assertEqual(completeness, 1.0)

    def test_B03_aggregation_soundness_counts_unmatched_predictions(self):
        actual_alerts = [self.make_flow(i) for i in range(2)]
        predicted_alerts = actual_alerts + [self.make_flow(2)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=3, size=3)], [self.make_step(duration=2, size=2)],
            predicted_alerts, actual_alerts,
        )
        self.assertAlmostEqual(soundness, 1 / 3,
                               msg='BUG-03: unmatched predicted alerts still contribute predicted pairs')
        self.assertEqual(completeness, 1.0)

    def test_control_splitting_matched_alerts_reduces_completeness(self):
        alerts = [self.make_flow(i) for i in range(3)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=1, size=2), self.make_step(2, duration=0, size=1)],
            [self.make_step(duration=2, size=3)], alerts, alerts,
        )
        self.assertEqual(soundness, 1.0)
        self.assertAlmostEqual(completeness, 1 / 3)

    def test_control_merging_matched_alerts_reduces_soundness(self):
        alerts = [self.make_flow(i) for i in range(4)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=3, size=4)],
            [self.make_step(duration=1, size=2), self.make_step(2, duration=1, size=2)],
            alerts, alerts,
        )
        self.assertAlmostEqual(soundness, 1 / 3)
        self.assertEqual(completeness, 1.0)

    def test_B04_recall_without_timing_matches_each_prediction_once(self):
        actual = [self.make_step(0), self.make_step(10)]
        self.assertEqual(
            MetricsCalculator.get_scenario_step_recall_no_timing([actual[0]], actual), 0.5,
            'BUG-04: one prediction cannot recover two repeated steps',
        )

    def test_B04_precision_without_timing_matches_each_actual_step_once(self):
        actual = [self.make_step(0)]
        self.assertEqual(
            MetricsCalculator.get_scenario_step_precision_no_timing([self.make_step(0), self.make_step(10)], actual),
            0.5, 'BUG-04: duplicate predictions cannot both receive credit',
        )

    def test_B04_timed_recall_does_not_reuse_prediction(self):
        actual = [self.make_step(0), self.make_step(0.1)]
        self.assertEqual(
            MetricsCalculator.get_scenario_step_recall([actual[0]], actual, 1000), 0.5,
            'BUG-04: overlapping tolerance windows still require one-to-one matching',
        )

    def test_B04_timed_precision_does_not_reuse_actual_step(self):
        self.assertEqual(
            MetricsCalculator.get_scenario_step_precision([self.make_step(0), self.make_step(0.1)], [self.make_step(0)], 1000),
            0.5, 'BUG-04: timed precision must penalize duplicate predictions',
        )

    def test_B20_detection_confusion_matrix_accepts_single_class(self):
        self.assertEqual(
            MetricsCalculator.get_detection_confusion_matrix(
                pd.DataFrame({'label': ['normal'], 'anomaly_score': [0.0]}), 0.8,
            ), (1, 0, 0, 0),
        )

    def test_B20_reconstruction_confusion_matrix_accepts_single_class(self):
        frame = self.make_scenario_frame()
        frame = frame[frame['label'] == 'normal'].copy()
        self.assertEqual(MetricsCalculator.get_reconstruction_confusion_matrix(frame, []), (1, 0, 0, 0))

    def test_control_exact_matching_keeps_perfect_precision_and_recall(self):
        actual = [self.make_step(0), self.make_step(10)]
        self.assertEqual(MetricsCalculator.get_scenario_step_precision(actual, actual, 0), 1.0)
        self.assertEqual(MetricsCalculator.get_scenario_step_recall(actual, actual, 0), 1.0)

    def assert_timed_scores(self, predicted, actual, expected):
        options = (predicted, actual, 1000, self.unknown)
        self.assertEqual(MetricsCalculator.get_scenario_step_precision(*options), expected)
        self.assertEqual(MetricsCalculator.get_scenario_step_recall(*options), expected)

    def test_control_unknown_step_with_correct_hosts_and_timing_is_accepted(self):
        self.assert_timed_scores(
            [self.make_step(attack=self.unknown)], [self.make_step()], 1.0,
        )

    def test_control_unknown_step_with_wrong_timing_is_rejected(self):
        self.assert_timed_scores(
            [self.make_step(second=10, attack=self.unknown)], [self.make_step()], 0.0,
        )

    def test_control_unknown_step_with_wrong_hosts_is_rejected(self):
        self.assert_timed_scores(
            [self.make_step(attack=self.unknown, destination_ip='10.0.0.99')],
            [self.make_step()], 0.0,
        )

    def test_control_wrong_known_type_is_not_a_wildcard(self):
        self.assert_timed_scores(
            [self.make_step(attack=self.wrong)], [self.make_step()], 0.0,
        )
