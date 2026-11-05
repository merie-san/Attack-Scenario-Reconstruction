"""Small fixtures exercise real generator and notebook code without datasets."""

import ast
import contextlib
from datetime import datetime, timedelta
import io
import os
import runpy
import subprocess
import sys
import textwrap
from unittest.mock import patch

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve

from event_convertor.flow_event_generator import CAPTureFlowEventConvertor
from tests.support import (
    ProjectTestCase,
    REPO_ROOT,
    SOURCE,
    TARGET,
    notebook_cells,
    notebook_function,
)


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

    def test_B11_naive_input_is_normalized_before_utc_comparison(self):
        frame = self.make_scenario_frame()
        frame['timestamp'] = frame['timestamp'].dt.tz_localize(None)
        for name in ('nmap_10_T5', 'nmap_mqtt', 'nmap_banner',
                     'brute_force_malformed', 'dollar_char', 'scp_inst'):
            frame[name] = 0.0
        events = CAPTureFlowEventConvertor.convert(frame)
        self.assertTrue(all(event.start_time.utcoffset() is not None for event in events),
                        'BUG-11: naive ingestion later conflicts with explicitly UTC exploit times')

    def test_B27_impossible_destination_terminates_instead_of_looping(self):
        # A child process is necessary: the current generator has an infinite loop.
        # subprocess.run kills and reaps the child if the safety timeout expires.
        code = textwrap.dedent('''
            import sys
            import pandas as pd
            sys.path.insert(0, sys.argv[1])
            from scenario_generator.scenario_generator import CAPTureScenarioGenerator
            frame = pd.DataFrame({'timestamp': [pd.Timestamp('2026-01-01', tz='UTC')],
                                  'label': ['normal'], 'step_number': [-1], 'duration': [1]})
            try:
                generator = CAPTureScenarioGenerator(
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

        with patch('scenario_generator.scenario_generator.random.choice', side_effect=choose):
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


class TestNotebookPreparationRegressions(ProjectTestCase):
    def augmentation(self):
        namespace = {'np': np, 'pd': pd}
        for source in notebook_cells('attack_normal_merging.ipynb'):
            for node in ast.parse(source).body:
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == 'keywords_excluded' for target in node.targets
                ):
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<notebook constants>', 'exec'), namespace)
        return notebook_function('attack_normal_merging.ipynb', 'generate_dataframe', namespace)

    def normal_frame(self):
        return pd.DataFrame({
            'bidirectional_first_seen_ms': np.arange(130) * 10 + 1000,
            'bidirectional_last_seen_ms': np.arange(130) * 10 + 1005,
            'src2dst_bytes': list(range(129)) + [100000],
            'application': ['ssh', 'mqtt'] * 65,
            'application_category': ['remote', 'iot'] * 65,
        })

    def test_B22_gaussian_augmentation_preserves_nonnegative_counters(self):
        generated = self.augmentation()(self.normal_frame(), 5000, 500)
        self.assertTrue(generated['src2dst_bytes'].ge(0).all(),
                        'BUG-22: Gaussian perturbation produces physically invalid negative byte counts')

    def test_B22_directional_byte_totals_stay_consistent(self):
        frame = self.normal_frame()
        frame['bidirectional_bytes'] = frame['src2dst_bytes']
        frame['dst2src_bytes'] = 0
        generated = self.augmentation()(frame, 5000, 500)
        self.assertTrue(generated['bidirectional_bytes'].eq(
            generated['src2dst_bytes'] + generated['dst2src_bytes']).all(),
            'BUG-22: independently perturbed counters must retain the byte-total identity')

    def test_B23_filtered_indexes_do_not_create_missing_categories(self):
        frame = self.normal_frame()
        frame.index = np.arange(500, 630)
        generated = self.augmentation()(frame, 5000, 500)
        self.assertFalse(generated['application'].isna().any(),
                         'BUG-23: categorical assignment must align with filtered row indexes')

    def test_B23_augmentation_preserves_joint_categorical_relationships(self):
        generated = self.augmentation()(self.normal_frame(), 5000, 500)
        valid_pairs = {('ssh', 'remote'), ('mqtt', 'iot')}
        self.assertTrue(set(zip(generated['application'], generated['application_category'])) <= valid_pairs,
                        'BUG-23: independent column sampling invents incompatible categorical tuples')

    def test_B24_ipv4_filter_rejects_ipv6_source(self):
        frame = pd.DataFrame({'src_ip': [SOURCE, 'fe80::1', SOURCE],
                              'dst_ip': [TARGET, TARGET, 'fe80::2']})
        namespace = {'attack_test': frame.copy(), 'attack_train': frame.copy()}
        for source in notebook_cells('attack_normal_merging.ipynb'):
            for node in ast.parse(source).body:
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Subscript)
                        and any(isinstance(target, ast.Name) and target.id == 'attack_test' for target in node.targets)
                        and 'str.contains' in ast.unparse(node.value)):
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<real IPv4 filter>', 'exec'), namespace)
                    self.assertEqual(namespace['attack_test'].index.tolist(), [0],
                                     'BUG-24: a regex dot matches an unresolved IPv6 source')
                    return
        self.fail('IPv4 filtering expression moved; update this notebook-level regression to its extracted helper')

    def test_B25_compression_is_invariant_to_timestamp_origin(self):
        frame = self.normal_frame()
        shifted = frame.copy()
        cols = ['bidirectional_first_seen_ms', 'bidirectional_last_seen_ms']
        shifted[cols] += 1_000_000
        generate = self.augmentation()
        state = np.random.get_state()
        first = generate(frame, 5000, 500)
        np.random.set_state(state)
        second = generate(shifted, 5000, 500)
        pd.testing.assert_frame_equal(
            first[cols], second[cols], obj='BUG-25: relative compression must remove the input origin',
        )

    def test_B25_directional_times_remain_inside_shifted_flow_interval(self):
        frame = self.normal_frame()
        frame['src2dst_first_seen_ms'] = frame['bidirectional_first_seen_ms']
        frame['src2dst_last_seen_ms'] = frame['bidirectional_last_seen_ms']
        generated = self.augmentation()(frame, 5000, 500)
        self.assertTrue(
            generated['src2dst_first_seen_ms'].ge(generated['bidirectional_first_seen_ms']).all()
            and generated['src2dst_last_seen_ms'].le(generated['bidirectional_last_seen_ms']).all(),
            'BUG-25: shifting only bidirectional timestamps leaves contradictory directional times',
        )

    def test_B25_capture_time_conversion_handles_midnight_rollover(self):
        namespace = {'np': np, 'datetime': datetime, 'timedelta': timedelta,
                     'start_time': np.array(datetime(2026, 1, 1, 1), dtype=object)}
        for source in notebook_cells('process_attack_train.ipynb'):
            for node in ast.parse(source).body:
                if (isinstance(node, ast.Assign) and 'replace(hour=' in ast.unparse(node.value)
                        and any(isinstance(target, ast.Name) and target.id == 'start_time' for target in node.targets)):
                    value = eval(compile(ast.Expression(node.value), '<capture time conversion>', 'eval'), namespace)
                    self.assertIsInstance(value, datetime)
                    return
        self.fail('Time conversion moved; replace this notebook audit with the extracted conversion function')


class TestTrainingAndRunnerRegressions(ProjectTestCase):
    def threshold_function(self, namespace):
        return notebook_function('reconstruction_dataset_creation.ipynb', 'compute_thresh', namespace)

    def training_assignment_using_test_data(self, value_type):
        for source in notebook_cells('reconstruction_dataset_creation.ipynb'):
            for node in ast.parse(source).body:
                if (isinstance(node, ast.Assign) and isinstance(node.value, value_type)
                        and any(isinstance(target, ast.Name) and target.id == 'df_train' for target in node.targets)
                        and any(isinstance(child, ast.Name) and child.id == 'df_test' for child in ast.walk(node.value))):
                    return compile(ast.Module(body=[node], type_ignores=[]), '<training preparation>', 'exec')
        self.fail('Cross-split transformation moved; replace this audit with the extracted training helper')

    def test_B26_test_label_absence_does_not_remove_training_classes(self):
        train = pd.DataFrame({'label': ['discover', 'finish'], 'feature': [1, 2]})
        namespace = {'df_train': train.copy(), 'df_test': train.iloc[[0]].copy()}
        exec(self.training_assignment_using_test_data(ast.Subscript), namespace)
        self.assertEqual(set(namespace['df_train']['label']), {'discover', 'finish'},
                         'BUG-26: final test-label membership must not determine the training class list')

    def test_B26_test_schema_does_not_select_training_features(self):
        train = pd.DataFrame({'label': ['discover', 'finish'], 'feature': [1, 2]})
        namespace = {'df_train': train.copy(), 'df_test': train[['label']].copy()}
        exec(self.training_assignment_using_test_data(ast.Call), namespace)
        self.assertEqual(namespace['df_train'].columns.tolist(), train.columns.tolist(),
                         'BUG-26: the training schema must not be inferred from final test columns')

    def test_B26_threshold_selection_does_not_inspect_final_test_features(self):
        holdout = object()
        namespace = {'np': np, 'precision_recall_curve': precision_recall_curve,
                     'X_test': holdout, 'y_test': np.array([0, 1, 0, 1]),
                     'X_validation': object(), 'y_validation': np.array([0, 1, 0, 1])}
        case = self

        class Predictor:
            def predict_proba(self, data):
                case.assertIsNot(data, holdout, 'BUG-26: threshold tuning must not inspect the final holdout')
                return np.array([[0.9, 0.1], [0.2, 0.8], [0.7, 0.3], [0.1, 0.9]])

        with contextlib.redirect_stdout(io.StringIO()):
            self.threshold_function(namespace)(Predictor(), 0.8)

    def test_B26_zero_recall_target_does_not_index_past_thresholds(self):
        namespace = {'np': np, 'precision_recall_curve': precision_recall_curve,
                     'X_test': object(), 'y_test': np.array([0, 1]),
                     'X_validation': object(), 'y_validation': np.array([0, 1])}

        class Predictor:
            def predict_proba(self, data):
                return np.array([[0.9, 0.1], [0.1, 0.9]])

        with contextlib.redirect_stdout(io.StringIO()):
            self.threshold_function(namespace)(Predictor(), 0.0)

    def test_B29_runner_uses_current_python_interpreter(self):
        calls = []

        def legacy_system(command):
            calls.append(command)
            return 0

        def portable_run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        with patch('os.system', side_effect=legacy_system), \
                patch('subprocess.run', side_effect=portable_run), \
                patch.object(sys, 'argv', [str(REPO_ROOT / 'run_scripts.py')]), \
                contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(REPO_ROOT / 'run_scripts.py'), run_name='__main__')
        self.assertTrue(calls, 'The runner should dispatch at least one configured evaluation')
        for command in calls:
            self.assertIsInstance(command, (list, tuple),
                                  'BUG-29: dispatch must use an argument list, not a shell command')
            self.assertEqual(command[0], sys.executable, 'BUG-29: use the active Python interpreter')
