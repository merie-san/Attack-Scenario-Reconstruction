import unittest
from datetime import datetime, timezone
from scenario_reconstructor.scenario_reconstructor import FlowExploit, Exploit, AttackType, HostAttribute
from scenario_generator.compute_metrics import MetricsCalculator
import pandas as pd


class TestHostAttributeConc(HostAttribute):
    ATT_1 = "att_1"
    ATT_2 = "att_2"
    ATT_3 = "att_3"


ATTACK_1 = AttackType("att_1", set(), set())
ATTACK_2 = AttackType("att_2", set(), set())
ATTACK_3 = AttackType("att_3", set(), set())
UNDETERMINED = AttackType("unk", set(), set())


class TestCalculator(unittest.TestCase):

    def setUp(self) -> None:
        self.actual_alerts = [
            FlowExploit(ATTACK_1, [], "10.0.0.2", "200", "10.0.0.5", "2000", "6", datetime(
                2001, 10, 10, 0, 0, 0), datetime(2001, 10, 10, 0, 0, 2), 0.8),
            FlowExploit(ATTACK_1, [], "10.0.0.2", "201", "10.0.0.5", "2010", "6", datetime(
                2001, 10, 10, 0, 0, 8), datetime(2001, 10, 10, 0, 0, 20), 0.4),
            FlowExploit(ATTACK_2, [], "10.0.0.2", "300", "10.0.0.5", "3000", "6", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 30), 0.9),
            FlowExploit(ATTACK_2, [], "10.0.0.2", "301", "10.0.0.5", "3010", "6", datetime(
                2001, 10, 10, 0, 0, 40), datetime(2001, 10, 10, 0, 1, 2), 0.999),
            FlowExploit(ATTACK_3, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(
                2001, 10, 10, 0, 1, 3), datetime(2001, 10, 10, 0, 1, 14), 0.01),
            FlowExploit(ATTACK_3, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 57), 0.76),]
        self.actual_steps = [
            Exploit(ATTACK_1, 2, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 0), datetime(
                2001, 10, 10, 0, 0, 8), (datetime(2001, 10, 10, 0, 0, 8)-datetime(2001, 10, 10, 0, 0, 2)).total_seconds(), 0),
            Exploit(ATTACK_2, 2, "10.0.0.2", "10.0.0.5",  datetime(2001, 10, 10, 0, 0, 28), datetime(
                2001, 10, 10, 0, 0, 40), (datetime(2001, 10, 10, 0, 0, 40) - datetime(2001, 10, 10, 0, 0, 30)).total_seconds(), 0),
            Exploit(ATTACK_3, 2, "10.0.0.5", "10.0.0.10",  datetime(2001, 10, 10, 0, 1, 3), datetime(2001, 10, 10, 0, 1, 38), (datetime(2001, 10, 10, 0, 1, 38) - datetime(2001, 10, 10, 0, 1, 2)).total_seconds(), 0)]
        self.predicted_alerts = [
            FlowExploit(ATTACK_1, [], "10.0.0.2", "200", "10.0.0.5", "2000", "6", datetime(
                2001, 10, 10, 0, 0, 0), datetime(2001, 10, 10, 0, 0, 2), 0.8),
            FlowExploit(ATTACK_1, [ATTACK_3], "10.0.0.7", "899",  "10.0.0.17", "1899", "6", datetime(
                2001, 10, 10, 0, 0, 2), datetime(2001, 10, 10, 0, 0, 4), 0.88),
            FlowExploit(ATTACK_1, [], "10.0.0.2", "201", "10.0.0.5", "2010", "6", datetime(
                2001, 10, 10, 0, 0, 8), datetime(2001, 10, 10, 0, 0, 20), 0.4),
            FlowExploit(ATTACK_2, [], "10.0.0.2", "300", "10.0.0.5", "3000", "6", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 30), 0.9),
            FlowExploit(ATTACK_2, [], "10.0.0.2", "301", "10.0.0.5", "3010", "6", datetime(
                2001, 10, 10, 0, 0, 40), datetime(2001, 10, 10, 0, 1, 2), 0.999),
            FlowExploit(UNDETERMINED, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 57), 0.76)]
        self.predicted_steps = [
            Exploit(ATTACK_1, 2, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 0), datetime(
                2001, 10, 10, 0, 0, 8), (datetime(2001, 10, 10, 0, 0, 8)-datetime(2001, 10, 10, 0, 0, 2)).total_seconds(), 0),
            Exploit(ATTACK_1, 1, "10.0.0.7", "10.0.0.17", datetime(
                2001, 10, 10, 0, 0, 2), datetime(2001, 10, 10, 0, 0, 2), -1, -1),
            Exploit(ATTACK_2, 1, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 28), -1, -1),
            Exploit(ATTACK_2, 1, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 40), datetime(
                2001, 10, 10, 0, 0, 40), -1, -1),
            Exploit(UNDETERMINED, 1, "10.0.0.5", "10.0.0.10", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 38), -1, -1)]
        df_dict = {

            "anomaly_score": [
                0.8, 0.4, 0.9, 0.999, 0.01, 0.76,
                0.7, 0.88, 0.1, 0.1, 0.8, 0.1
            ],
            "label": [
                "att1",
                "att1",
                "att2",
                "att2",
                "att3",
                "att3",
                "normal",
                "normal",
                "normal",
                "normal",
                "normal",
                "normal",
            ],
            "timestamp": [
                datetime(2001, 10, 10, 0, 0, 0),
                datetime(2001, 10, 10, 0, 0, 8),
                datetime(2001, 10, 10, 0, 0, 28),
                datetime(2001, 10, 10, 0, 0, 40),
                datetime(2001, 10, 10, 0, 1, 3),
                datetime(2001, 10, 10, 0, 1, 38),

                datetime(2001, 10, 10, 0, 0, 1),
                datetime(2001, 10, 10, 0, 0, 2),
                datetime(2001, 10, 10, 0, 0, 3),
                datetime(2001, 10, 10, 0, 0, 4),
                datetime(2001, 10, 10, 0, 0, 5),
                datetime(2001, 10, 10, 0, 0, 6),
            ],
            "src_ip": [
                "10.0.0.2",
                "10.0.0.2",
                "10.0.0.2",
                "10.0.0.2",
                "10.0.0.5",
                "10.0.0.5",

                "10.0.0.6",
                "10.0.0.7",
                "10.0.0.8",
                "10.0.0.9",
                "10.0.0.10",
                "10.0.0.11",
            ],
            "src_port": [
                "200",
                "201",
                "300",
                "301",
                "500",
                "500",

                "600",
                "899",
                "800",
                "900",
                "1000",
                "1100",
            ],
            "dst_ip": [
                "10.0.0.5",
                "10.0.0.5",
                "10.0.0.5",
                "10.0.0.5",
                "10.0.0.10",
                "10.0.0.10",

                "10.0.0.16",
                "10.0.0.17",
                "10.0.0.18",
                "10.0.0.19",
                "10.0.0.1",
                "10.0.0.1",
            ],

            "dst_port": [
                "2000",
                "2010",
                "3000",
                "3010",
                "5000",
                "5000",

                "6000",
                "1899",
                "8000",
                "9000",
                "10000",
                "11000",
            ],
            "protocol": [
                "6",
                "6",
                "6",
                "6",
                "6",
                "6",

                "6",
                "6",
                "17",
                "17",
                "1",
                "6",
            ],
            "duration": [
                (datetime(2001, 10, 10, 0, 0, 2) -
                 datetime(2001, 10, 10, 0, 0, 0)).total_seconds()*1000,
                (datetime(2001, 10, 10, 0, 0, 20) -
                 datetime(2001, 10, 10, 0, 0, 8)).total_seconds()*1000,
                (datetime(2001, 10, 10, 0, 0, 30) -
                 datetime(2001, 10, 10, 0, 0, 28)).total_seconds()*1000,
                (datetime(2001, 10, 10, 0, 1, 2) -
                 datetime(2001, 10, 10, 0, 0, 40)).total_seconds()*1000,
                (datetime(2001, 10, 10, 0, 1, 14) -
                 datetime(2001, 10, 10, 0, 1, 3)).total_seconds()*1000,
                (datetime(2001, 10, 10, 0, 1, 57) -
                 datetime(2001, 10, 10, 0, 1, 38)).total_seconds()*1000,
                2000,
                2000,
                2000,
                2000,
                2000,
                2000,
            ]
        }
        self.scenario_df = pd.DataFrame(df_dict)
        self.calculator = MetricsCalculator()

    def test_get_step_soundness_completeness(self):
        sound, compl = self.calculator.get_step_soundness_completeness(
            self.predicted_steps, self.actual_steps, self.predicted_alerts, self.actual_alerts, UNDETERMINED)
        self.assertEqual(sound, 1)
        self.assertEqual(compl, 0.5)

    def test_get_confusion_matrixes_detection(self):
        tn, fp, fn, tp = self.calculator.get_detection_confusion_matrix(
            self.scenario_df,0.8)
        self.assertEqual(tn,4)
        self.assertEqual(fp,2)
        self.assertEqual(fn,3)
        self.assertEqual(tp,3)

    def test_get_confusion_matrixes_reconstruction(self):
        tn, fp, fn, tp = self.calculator.get_reconstruction_confusion_matrix(self.scenario_df, self.predicted_alerts)
        self.assertEqual(tn,5)
        self.assertEqual(fp,1)
        self.assertEqual(fn,1)
        self.assertEqual(tp,5)

    def test_scenario_step_methods(self):
        self.assertEqual(self.calculator.get_scenario_step_precision(self.predicted_steps, self.actual_steps, 1000, UNDETERMINED), 0.2)
        self.assertEqual(self.calculator.get_scenario_step_precision_no_timing(self.predicted_steps, self.actual_steps, UNDETERMINED), 0.8)
        self.assertEqual(self.calculator.get_scenario_step_recall(self.predicted_steps, self.actual_steps, 1000, UNDETERMINED), 1/3)
        self.assertEqual(self.calculator.get_scenario_step_recall_no_timing(self.predicted_steps,self.actual_steps, UNDETERMINED), 1)

    def test_get_scenario_soundness_completeness(self):
        self.actual_steps.append(Exploit(ATTACK_3, 2, "10.0.0.6", "10.0.0.10",  datetime(2001, 10, 10, 0, 1, 3), datetime(2001, 10, 10, 0, 1, 38), (datetime(2001, 10, 10, 0, 1, 38) - datetime(2001, 10, 10, 0, 1, 2)).total_seconds(), 0))
        sound, compl=self.calculator.get_scenario_soundness_completeness(self.predicted_steps, self.actual_steps, UNDETERMINED)
        self.assertEqual(sound,1)
        self.assertEqual(compl,1)
