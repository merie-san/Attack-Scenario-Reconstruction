from datetime import datetime

import pandas as pd

from metrics import MetricsCalculator
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import (
    AttackStep,
    AttackType,
    FlowAlert,
    HostAttribute,
    Precondition,
)
from tests.support import ProjectTestCase


class ExampleHostAttribute(HostAttribute):
    ATT_1 = "att_1"
    ATT_2 = "att_2"
    ATT_3 = "att_3"


ATTACK_1 = AttackType("att_1", set(), {ExampleHostAttribute.ATT_1})
ATTACK_2 = AttackType(
    "att_2",
    {Precondition({ExampleHostAttribute.ATT_1}, False)},
    {ExampleHostAttribute.ATT_2},
)
ATTACK_3 = AttackType(
    "att_3",
    {Precondition({ExampleHostAttribute.ATT_2}, True)},
    {ExampleHostAttribute.ATT_3},
)
UNDETERMINED = AttackType(
    "unk",
    {
        Precondition({ExampleHostAttribute.ATT_1}, False),
        Precondition({ExampleHostAttribute.ATT_2}, True),
    },
    {
        ExampleHostAttribute.ATT_1,
        ExampleHostAttribute.ATT_2,
        ExampleHostAttribute.ATT_3,
    },
)


class MetricsFixture(ProjectTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.actual_alerts = [
            FlowAlert(ATTACK_1, [], "10.0.0.2", "200", "10.0.0.5", "2000", "6", datetime(
                2001, 10, 10, 0, 0, 0), datetime(2001, 10, 10, 0, 0, 2), 0.8),
            FlowAlert(ATTACK_1, [], "10.0.0.2", "201", "10.0.0.5", "2010", "6", datetime(
                2001, 10, 10, 0, 0, 8), datetime(2001, 10, 10, 0, 0, 20), 0.4),
            FlowAlert(ATTACK_2, [], "10.0.0.2", "300", "10.0.0.5", "3000", "6", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 30), 0.9),
            FlowAlert(ATTACK_2, [], "10.0.0.2", "301", "10.0.0.5", "3010", "6", datetime(
                2001, 10, 10, 0, 0, 40), datetime(2001, 10, 10, 0, 1, 2), 0.999),
            FlowAlert(ATTACK_3, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(
                2001, 10, 10, 0, 1, 3), datetime(2001, 10, 10, 0, 1, 14), 0.01),
            FlowAlert(ATTACK_3, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 57), 0.76),]
        self.actual_steps = [
            AttackStep(ATTACK_1, 2, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 0), datetime(
                2001, 10, 10, 0, 0, 8), (datetime(2001, 10, 10, 0, 0, 8)-datetime(2001, 10, 10, 0, 0, 2)).total_seconds(), 0),
            AttackStep(ATTACK_2, 2, "10.0.0.2", "10.0.0.5",  datetime(2001, 10, 10, 0, 0, 28), datetime(
                2001, 10, 10, 0, 0, 40), (datetime(2001, 10, 10, 0, 0, 40) - datetime(2001, 10, 10, 0, 0, 30)).total_seconds(), 0),
            AttackStep(ATTACK_3, 2, "10.0.0.5", "10.0.0.10",  datetime(2001, 10, 10, 0, 1, 3), datetime(2001, 10, 10, 0, 1, 38), (datetime(2001, 10, 10, 0, 1, 38) - datetime(2001, 10, 10, 0, 1, 2)).total_seconds(), 0)]
        self.predicted_alerts = [
            FlowAlert(ATTACK_1, [], "10.0.0.2", "200", "10.0.0.5", "2000", "6", datetime(
                2001, 10, 10, 0, 0, 0), datetime(2001, 10, 10, 0, 0, 2), 0.8),
            FlowAlert(ATTACK_1, [ATTACK_3], "10.0.0.7", "899",  "10.0.0.17", "1899", "6", datetime(
                2001, 10, 10, 0, 0, 2), datetime(2001, 10, 10, 0, 0, 4), 0.88),
            FlowAlert(ATTACK_1, [], "10.0.0.2", "201", "10.0.0.5", "2010", "6", datetime(
                2001, 10, 10, 0, 0, 8), datetime(2001, 10, 10, 0, 0, 20), 0.4),
            FlowAlert(ATTACK_2, [], "10.0.0.2", "300", "10.0.0.5", "3000", "6", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 30), 0.9),
            FlowAlert(ATTACK_2, [], "10.0.0.2", "301", "10.0.0.5", "3010", "6", datetime(
                2001, 10, 10, 0, 0, 40), datetime(2001, 10, 10, 0, 1, 2), 0.999),
            FlowAlert(UNDETERMINED, [], "10.0.0.5", "500", "10.0.0.10", "5000", "6", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 57), 0.76)]
        self.predicted_steps = [
            AttackStep(ATTACK_1, 2, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 0), datetime(
                2001, 10, 10, 0, 0, 8), (datetime(2001, 10, 10, 0, 0, 8)-datetime(2001, 10, 10, 0, 0, 2)).total_seconds(), 0),
            AttackStep(ATTACK_1, 1, "10.0.0.7", "10.0.0.17", datetime(
                2001, 10, 10, 0, 0, 2), datetime(2001, 10, 10, 0, 0, 2), -1, -1),
            AttackStep(ATTACK_2, 1, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 28), datetime(2001, 10, 10, 0, 0, 28), -1, -1),
            AttackStep(ATTACK_2, 1, "10.0.0.2", "10.0.0.5", datetime(
                2001, 10, 10, 0, 0, 40), datetime(
                2001, 10, 10, 0, 0, 40), -1, -1),
            AttackStep(UNDETERMINED, 1, "10.0.0.5", "10.0.0.10", datetime(2001, 10, 10, 0, 1, 38), datetime(2001, 10, 10, 0, 1, 38), -1, -1)]
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
        self.actual_dag = AttackScenarioDAG(self.actual_steps)
        self.predicted_dag = AttackScenarioDAG(self.predicted_steps)
        self.calculator = MetricsCalculator()
