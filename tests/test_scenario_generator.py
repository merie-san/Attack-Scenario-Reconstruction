from scenario_generator.scenario_generator import CAPTureScenarioGenerator
import unittest
from datetime import datetime, timedelta
import pandas as pd
import random


class TestScenarioGenerator(unittest.TestCase):

    def setUp(self):
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        self.source_df = pd.DataFrame({"timestamp": [start_time + timedelta(minutes=i) for i in range(20)],
                                      "label": ["rec", "rec", "normal", "rec", "normal", "rec", "normal", "bru", "normal", "bru", "bru", "dis", "dis", "rec", "dis", "dis", "ins", "imp", "normal", "rec"],
                                       "step_number": [0, 0, -1, 1, -1, 2, -1, 3, -1, 4, 4, 5, 5, 6, 7, 7, 8, 9, -1, 6], "duration": [random.randint(0, 5000) for _ in range(20)],
                                       "src_ip": ["10.0.0.1"]*20,
                                       "dst_ip": ["10.0.0.10"]*20
                                       })
        self.generator = CAPTureScenarioGenerator(
            dataframe=self.source_df,
            next_attack_dict={"start": ["rec"], "rec": ["rec", "bru"], "bru": [
                "dis"], "dis": ["dis", "ins"], "ins": ["imp"], "imp": ["end"]},
            ip_list=["10.0.0." + str(i) for i in range(11)],
            enable_src_for={"bru": ["dis"], "ins": ["imp"]},
            enable_dst_for={"rec": ["bru"], "bru": ["ins"], "dis": ["imp"]},
            possible_srcs={"rec": ["10.0.0.1"], "bru": [
                "10.0.0.1"], "dis": [], "ins": ["10.,0.0.1"], "imp": []},
            possible_dsts={"rec": [
                "10.0.0."+str(i) for i in range(2, 11)], "bru": [], "dis": ["10.0.0."+str(i) for i in range(2, 11)], "ins": [], "imp": []},
            dst_restricted_atks={"imp": ["10.0.0.10"]},
            final_atk="imp",
            enabling_atk="dis"
        )

    def test_generate_scenario_coherence(self):
        scenario_df = self.generator.generate_scenario()
        df_list = []
        for i in range(len(self.generator.step_id_list)):
            step_id = self.generator.step_id_list[i]
            df = self.source_df[self.source_df["step_number"]
                                == step_id].copy()
            delta = self.generator.attack_times[i][0] - df["timestamp"].iloc[0]
            df["timestamp"] = df["timestamp"] + delta
            df["src_ip"] = self.generator.attack_ips[i][0]
            df["dst_ip"] = self.generator.attack_ips[i][1]
            df["step_number"] = i
            df_list.append(df)
        res_df = pd.concat(df_list+[self.source_df[self.source_df["label"] == "normal"]],
                           ignore_index=True).sort_values("timestamp").reset_index(drop=True)
        for i, row in res_df.iterrows():
            self.assertEqual(
                scenario_df.iloc[i]["timestamp"], row["timestamp"])
            self.assertEqual(scenario_df.iloc[i]["src_ip"], row["src_ip"])
            self.assertEqual(scenario_df.iloc[i]["dst_ip"], row["dst_ip"])
            self.assertEqual(scenario_df.iloc[i]["label"], row["label"])
            self.assertEqual(
                scenario_df.iloc[i]["step_number"], row["step_number"])
            self.assertEqual(scenario_df.iloc[i]["duration"], row["duration"])
