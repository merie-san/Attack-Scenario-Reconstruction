import pandas as pd

from metrics import MetricsCalculator
from tests.metrics.fixtures import MetricsFixture, UNDETERMINED
from tests.support import ProjectTestCase


class TestDetectionMetrics(MetricsFixture):
    def test_detection_confusion_matrix(self):
        tn, fp, fn, tp = self.calculator.get_detection_confusion_matrix(
            self.scenario_df, 0.8)
        self.assertEqual(tn, 5)
        self.assertEqual(fp, 1)
        self.assertEqual(fn, 4)
        self.assertEqual(tp, 2)

    def test_reconstruction_confusion_matrix(self):
        tn, fp, fn, tp = self.calculator.get_reconstruction_confusion_matrix(self.scenario_df, self.predicted_alerts)
        self.assertEqual(tn,5)
        self.assertEqual(fp,1)
        self.assertEqual(fn,1)
        self.assertEqual(tp,5)

    def test_alert_precision(self):
        # 6 predicted alerts: 5 match the 6 actual alerts 1-to-1, 1 is an FP -> 5 / 6
        self.assertAlmostEqual(
            self.calculator.get_alert_precision(self.predicted_alerts, self.actual_alerts, UNDETERMINED),
            5 / 6,
        )
        # Adding a duplicate predicted alert reduces alert precision from 5/6 to 5/7
        dup_predicted_alerts = list(self.predicted_alerts) + [self.predicted_alerts[0]]
        self.assertAlmostEqual(
            self.calculator.get_alert_precision(dup_predicted_alerts, self.actual_alerts, UNDETERMINED),
            5 / 7,
        )

    def test_alert_recall(self):
        # 5 of the 6 actual alerts are matched 1-to-1 -> 5 / 6
        self.assertAlmostEqual(
            self.calculator.get_alert_recall(self.predicted_alerts, self.actual_alerts, UNDETERMINED),
            5 / 6,
        )


class TestDetectionRegressions(ProjectTestCase):
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
