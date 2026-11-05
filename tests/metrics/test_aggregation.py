from metrics import MetricsCalculator
from tests.metrics.fixtures import MetricsFixture, UNDETERMINED
from tests.support import ProjectTestCase


class TestAggregationMetrics(MetricsFixture):
    def test_get_step_soundness_completeness(self):
        sound, compl = self.calculator.get_step_soundness_completeness(
            self.predicted_steps, self.actual_steps, self.predicted_alerts, self.actual_alerts, UNDETERMINED)
        self.assertEqual(sound, 1)
        # 5 matched alerts across 3 actual steps (2, 2, 1) -> 3 + 3 + 1 = 7 actual pairs (with self-loops);
        # predicted steps split step 2 into two singletons -> 3 + 1 + 1 + 1 = 6 predicted/correct pairs -> compl = 6 / 7
        self.assertAlmostEqual(compl, 6 / 7)

    def test_get_step_soundness_completeness_duplicate_alerts_ignored(self):
        # Duplicate predicted alerts are matched 1-to-1 and excess duplicates do not skew soundness or completeness
        dup_predicted_alerts = list(self.predicted_alerts) + [self.predicted_alerts[0]]
        sound, compl = self.calculator.get_step_soundness_completeness(
            self.predicted_steps, self.actual_steps, dup_predicted_alerts, self.actual_alerts, UNDETERMINED)
        self.assertEqual(sound, 1)
        self.assertAlmostEqual(compl, 6 / 7)


class TestAggregationRegressions(ProjectTestCase):
    def test_B02_aggregation_completeness_is_orthogonal_to_missing_alerts(self):
        actual_alerts = [self.make_flow(i) for i in range(3)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=2, size=2)], [self.make_step(duration=3, size=3)],
            actual_alerts[:2], actual_alerts,
        )
        self.assertEqual(soundness, 1.0)
        self.assertEqual(completeness, 1.0)
        self.assertAlmostEqual(MetricsCalculator.get_alert_recall(actual_alerts[:2], actual_alerts), 2 / 3)

    def test_B03_aggregation_soundness_is_orthogonal_to_unmatched_predictions(self):
        actual_alerts = [self.make_flow(i) for i in range(2)]
        predicted_alerts = actual_alerts + [self.make_flow(2)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=3, size=3)], [self.make_step(duration=2, size=2)],
            predicted_alerts, actual_alerts,
        )
        self.assertEqual(soundness, 1.0)
        self.assertEqual(completeness, 1.0)
        self.assertAlmostEqual(MetricsCalculator.get_alert_precision(predicted_alerts, actual_alerts), 2 / 3)

    def test_control_splitting_matched_alerts_reduces_completeness(self):
        alerts = [self.make_flow(i) for i in range(3)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=1, size=2), self.make_step(2, duration=0, size=1)],
            [self.make_step(duration=2, size=3)], alerts, alerts,
        )
        self.assertEqual(soundness, 1.0)
        # 3 alerts in 1 actual step -> 6 pairs (with self-loops); split into (2, 1) -> 3 + 1 = 4 pairs -> 4 / 6 = 2 / 3
        self.assertAlmostEqual(completeness, 2 / 3)

    def test_control_merging_matched_alerts_reduces_soundness(self):
        alerts = [self.make_flow(i) for i in range(4)]
        soundness, completeness = MetricsCalculator.get_step_soundness_completeness(
            [self.make_step(duration=3, size=4)],
            [self.make_step(duration=1, size=2), self.make_step(2, duration=1, size=2)],
            alerts, alerts,
        )
        # 2 actual steps of size 2 -> 3 + 3 = 6 pairs; merged into 1 predicted step of size 4 -> 10 pairs -> 6 / 10 = 3 / 5
        self.assertAlmostEqual(soundness, 3 / 5)
        self.assertEqual(completeness, 1.0)
