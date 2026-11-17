from datetime import datetime, timedelta
import random

import pandas as pd

from scenario_generator import ScenarioGenerationError
from tests.support import ProjectTestCase


class TestScenarioGenerator(ProjectTestCase):

    def setUp(self):
        super().setUp()
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        self.source_df = pd.DataFrame({"timestamp": [start_time + timedelta(minutes=i) for i in range(20)],
                                      "label": ["rec", "rec", "normal", "rec", "normal", "rec", "normal", "bru", "normal", "bru", "bru", "dis", "dis", "rec", "dis", "dis", "ins", "imp", "normal", "rec"],
                                       "step_number": [0, 0, -1, 1, -1, 2, -1, 3, -1, 4, 4, 5, 5, 6, 7, 7, 8, 9, -1, 6], "duration": [random.randint(0, 5000) for _ in range(20)],
                                       "src_ip": ["10.0.0.1"]*20,
                                       "dst_ip": ["10.0.0.10"]*20
                                       })
        self.generator = self.make_generator(
            frame=self.source_df,
            next_attack_dict={"start": ["rec"], "rec": ["rec", "bru"], "bru": [
                "dis"], "dis": ["dis", "ins"], "ins": ["imp"], "imp": ["end"]},
            enable_src_for={"bru": ["dis"], "ins": ["imp"]},
            enable_dst_for={"rec": ["bru"], "bru": ["ins"], "dis": ["imp"]},
            possible_srcs={"rec": ["10.0.0.1"], "bru": [
                "10.0.0.1"], "dis": [], "ins": ["10.,0.0.1"], "imp": []},
            possible_dsts={"rec": [
                "10.0.0."+str(i) for i in range(2, 11)], "bru": [], "dis": ["10.0.0."+str(i) for i in range(2, 11)], "ins": [], "imp": []},
            dst_restricted_atks={"imp": ["10.0.0.10"]},
            final_atk="imp",
            enabling_atks="dis"
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

    def test_explicit_path_renders_exact_steps_without_search(self):
        from unittest.mock import patch

        path = [('imp', '10.0.0.20', '10.0.0.21'), ('rec', '10.0.0.22', '10.0.0.23'),
                ('imp', '10.0.0.20', '10.0.0.21')]
        with patch.object(self.generator, '_search_scenario') as search:
            result = self.generator.generate_scenario(2, path=path)
        search.assert_not_called()
        self.assertIs(result, self.generator.result)
        self.assertEqual(self.generator.attack_names, [step[0] for step in path])
        self.assertEqual(self.generator.attack_ips, [step[1:] for step in path])
        for index, (attack, src, dst) in enumerate(path):
            rows = result[result['step_number'] == index]
            self.assertEqual(set(rows['label']), {attack})
            self.assertEqual(set(rows['src_ip']), {src})
            self.assertEqual(set(rows['dst_ip']), {dst})

    def test_invalid_explicit_paths_preserve_previous_result(self):
        previous = self.generator.generate_scenario(path=[('rec', 'source', 'destination')])
        cases = [([], ScenarioGenerationError), ([('rec', 'same', 'same')], ScenarioGenerationError),
                 ([('missing', 'src', 'dst')], ScenarioGenerationError),
                 ([('normal', 'src', 'dst')], ScenarioGenerationError),
                 ('rec:src->dst', TypeError), (iter([]), TypeError),
                 ([('rec', 'src')], ValueError), ([('rec', '', 'dst')], ValueError),
                 ([('rec', 123, 'dst')], ValueError), (['abc'], ValueError)]
        for path, error in cases:
            with self.subTest(path=path), self.assertRaises(error):
                self.generator.generate_scenario(path=path)
            self.assertIs(self.generator.result, previous)

    def test_explicit_path_still_validates_limits_and_normal_flows(self):
        path = [('rec', 'source', 'destination')]
        for options in ({'normal_flow_number_divisor': 0}, {'max_steps': 0},
                        {'max_search_attempts': 0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.generator.generate_scenario(path=path, **options)
        del self.generator.data_source['normal']
        with self.assertRaisesRegex(ScenarioGenerationError, 'normal flows'):
            self.generator.generate_scenario(path=path)
