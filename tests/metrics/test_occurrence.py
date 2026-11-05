from metrics import MetricsCalculator
from tests.metrics.fixtures import MetricsFixture, UNDETERMINED
from tests.support import ProjectTestCase


class TestOccurrenceMetrics(MetricsFixture):
    def test_scenario_step_precision(self):
        # 5 predicted steps: 3 match the 3 actual steps via interval overlap, 1 is an FP, and 1 is a duplicate att_2 fragment -> 3 / 5 = 0.6
        self.assertEqual(self.calculator.get_scenario_step_precision(self.predicted_dag, self.actual_dag, UNDETERMINED), 0.6)

    def test_scenario_step_recall(self):
        # All 3 actual steps overlap with a predicted step -> 3 / 3 = 1.0
        self.assertEqual(self.calculator.get_scenario_step_recall(self.predicted_dag, self.actual_dag, UNDETERMINED), 1.0)


class TestOccurrenceRegressions(ProjectTestCase):
    def assert_timed_scores(self, predicted, actual, expected):
        self.assertEqual(MetricsCalculator.get_scenario_step_precision(predicted, actual, self.unknown), expected)
        self.assertEqual(MetricsCalculator.get_scenario_step_recall(predicted, actual, self.unknown), expected)

    def test_B04_timed_recall_does_not_reuse_prediction(self):
        actual = [self.make_step(0), self.make_step(0.1)]
        self.assertEqual(
            MetricsCalculator.get_scenario_step_recall([actual[0]], actual), 0.5,
            'BUG-04: overlapping windows still require one-to-one matching',
        )

    def test_B04_timed_precision_does_not_reuse_actual_step(self):
        self.assertEqual(
            MetricsCalculator.get_scenario_step_precision([self.make_step(0), self.make_step(0.1)], [self.make_step(0)]),
            0.5, 'BUG-04: step precision must penalize duplicate predictions',
        )

    def test_control_exact_matching_keeps_perfect_precision_and_recall(self):
        actual = [self.make_step(0), self.make_step(10)]
        self.assertEqual(MetricsCalculator.get_scenario_step_precision(actual, actual), 1.0)
        self.assertEqual(MetricsCalculator.get_scenario_step_recall(actual, actual), 1.0)

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
