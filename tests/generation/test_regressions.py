"""Generation boundaries, interflow statistics, and failure regressions."""
import os
import subprocess
import sys
import textwrap
from datetime import timedelta
from unittest.mock import patch
import numpy as np
import pandas as pd
from tests.support import ProjectTestCase, REPO_ROOT, SOURCE, TARGET

class TestGeneratorRegressions(ProjectTestCase):
    def test_B09_generated_step_ends_at_last_flow_end(self):
        generator = self.make_generator()
        generator.generate_scenario()
        steps, alerts = generator.export_results([self.discover])
        self.assertEqual(steps[0].end_time, max(alert.end_time for alert in alerts),
                         'BUG-09: ground truth must include the duration of the final flow')

    def test_B10_generator_and_reconstructor_interflow_units_agree(self):
        generator = self.make_generator(self.make_scenario_frame(count=20, spacing_ms=500, duration_ms=250))
        generator.generate_scenario()
        actual, alerts = generator.export_results([self.discover])
        rec = self.make_reconstructor()
        for alert in alerts:
            rec.add_flow_exploit(alert)
        rec.update_exploits_all()
        predicted = rec.return_exploits()[alerts[0].get_flow_exploit_group_id()]
        self.assertEqual(len(predicted), 1)
        self.assertEqual(predicted[0].mean_interflow_time, actual[0].mean_interflow_time,
                         'BUG-10: reconstruction seconds and generator milliseconds differ by 1000')

    def test_B10_interflow_standard_deviation_uses_the_same_units(self):
        frame = self.make_scenario_frame(count=20, spacing_ms=500, duration_ms=250)
        offsets = np.cumsum([0] + [500 if i % 2 else 1000 for i in range(1, 20)])
        frame.loc[frame['label'] == 'discover', 'timestamp'] = [
            frame.iloc[0]['timestamp'] + timedelta(milliseconds=int(offset)) for offset in offsets
        ]
        generator = self.make_generator(frame)
        generator.generate_scenario()
        actual, alerts = generator.export_results([self.discover])
        rec = self.make_reconstructor()
        for alert in alerts:
            rec.add_flow_exploit(alert)
        rec.update_exploits_all()
        predicted = rec.return_exploits()[alerts[0].get_flow_exploit_group_id()]
        self.assertEqual(len(predicted), 1)
        self.assertAlmostEqual(predicted[0].std_interflow_time, actual[0].std_interflow_time,
                               msg='BUG-10: standard deviations also require the common duration unit')


    def test_B27_impossible_destination_terminates_instead_of_looping(self):
        # Guard against reintroducing nontermination: a child process can be killed
        # and reaped if generation ever exceeds the safety timeout.
        code = textwrap.dedent('''
            import sys
            import pandas as pd
            sys.path.insert(0, sys.argv[1])
            from scenario_generator.generator import ScenarioGenerator
            frame = pd.DataFrame({'timestamp': [pd.Timestamp('2026-01-01', tz='UTC')],
                                  'label': ['normal'], 'step_number': [-1], 'duration': [1]})
            try:
                generator = ScenarioGenerator(
                    frame, {'start': ['scan'], 'scan': ['end']}, {}, {},
                    {'scan': ['10.0.0.1']}, {'scan': ['10.0.0.1']}, {}, 'scan', [])
                generator.generate_scenario()
            except (ValueError, RuntimeError):
                sys.exit(0)
            sys.exit('BUG-27: impossible configuration was silently accepted')
        ''')
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        try:
            result = subprocess.run(
                [sys.executable, '-B', '-c', code, str(REPO_ROOT)],
                cwd=self.temp.name, env=environment, timeout=10,
                capture_output=True, text=True, check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail('BUG-27: no feasible destination; generator did not terminate within 10 seconds')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_B27_repeated_enabling_does_not_duplicate_sampling_weight(self):
        frame = self.make_scenario_frame()
        finish = frame.iloc[[0]].assign(label='finish', step_number=1)
        generator = self.make_generator(
            pd.concat([frame, finish], ignore_index=True),
            next_attack_dict={'start': ['discover'], 'discover': ['discover', 'finish'], 'finish': ['end']},
            enable_dst_for={'discover': ['finish']},
            possible_srcs={'discover': [SOURCE], 'finish': [SOURCE]},
            possible_dsts={'discover': [TARGET], 'finish': []}, final_atk='finish',
        )
        repeats = 0

        def choose(values):
            nonlocal repeats
            values = list(values)
            if values == ['discover', 'finish']:
                repeats += 1
                return 'discover' if repeats == 1 else 'finish'
            if values and isinstance(values[0], str) and values[0].startswith('10.'):
                self.assertEqual(len(values), len(set(values)),
                                 'BUG-27: enabling a host twice must not duplicate its sampling weight')
            return values[0]

        with patch('scenario_generator.search.random.choice', side_effect=choose):
            generator.generate_scenario()

    def test_B28_normal_subsampling_uses_positions_not_index_labels(self):
        frame = self.make_scenario_frame()
        attack = frame[frame['label'] != 'normal'].copy()
        attack.index = [100, 101]
        normal = pd.concat([frame[frame['label'] == 'normal']] * 4, ignore_index=True)
        normal['src_port'] = ['n0', 'n1', 'n2', 'n3']
        normal.index = [2, 4, 6, 8]
        generator = self.make_generator(pd.concat([attack, normal]))
        result = generator.generate_scenario(normal_flow_number_divisor=2)
        self.assertEqual(set(result.loc[result['label'] == 'normal', 'src_port']), {'n0', 'n2'},
                         'BUG-28: gapped index labels must not change the sampling fraction')
