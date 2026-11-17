"""Dataset definitions and command entry points are safe to reuse as libraries."""
import contextlib
import io
import copy
from dataclasses import fields, replace
import json
from pathlib import Path
import re
import runpy
import sys
import subprocess
from unittest.mock import patch

import pandas as pd

from experiments import batch, capture, reporting
from scenario_configs import load_scenario_config
from scenario_configs.capture import ATK_TYPES, DOLLAR_CHAR, DollarCharHostAttributes, create_hosts
from scenario_generator import ScenarioGenerationError, ScenarioSearchLimitError
from scenario_generator import cli as generator_cli
from scenario_reconstructor import cli as reconstructor_cli
from scenario_reconstructor.serialization import AlertStepParser
from tests.support import ProjectTestCase, REPO_ROOT


def campaign_definition():
    """Return a small campaign independent of cAPTure attack identifiers."""
    return dict(
        attack_types=[dict(identifier='probe', preconditions=[dict(attributes=['start'], targets_source=True)],
                           postconditions=['ready'], description='Discover target'),
                      dict(identifier='finish', preconditions=[dict(attributes=['ready'], targets_source=False)],
                           postconditions=['done'])],
        hosts={'10.0.0.9': []}, external_host_attributes=['start'],
        next_attack_dict={'start': ['probe'], 'probe': ['finish'], 'finish': ['end']},
        possible_srcs={'probe': ['10.0.0.2'], 'finish': ['10.0.0.2']},
        possible_dsts={'probe': ['10.0.0.9'], 'finish': ['10.0.0.9']}, final_atk='finish',
        score_columns=['finish', 'probe'],
    )


class TestCampaignConfiguration(ProjectTestCase):
    def write_json(self, data):
        filename = self.log_path('campaign.json')
        Path(filename).write_text(json.dumps(data), encoding='utf-8')
        return filename

    def test_capture_defaults_preserve_identity_score_order_and_fresh_hosts(self):
        from events.conversion import CAPTURE_ATTACK_SCORE_COLUMNS

        for spec in ('capture', 'scenario_configs.capture'):
            config = load_scenario_config(spec)
            self.assertEqual(config.score_columns, CAPTURE_ATTACK_SCORE_COLUMNS)
            self.assertIs(config.attack_goal.attack_type, DOLLAR_CHAR)
            self.assertEqual(config.attack_goal.destination_ip, '10.0.0.1')
            self.assertEqual(config.external_host_attributes, {DollarCharHostAttributes.START_MACHINE})
            first, second = config.create_hosts(), config.create_hosts()
            self.assertIsNot(first[0], second[0])
            self.assertIsNot(first[0].compromise_attributes, second[0].compromise_attributes)

    def test_json_discovers_attributes_and_supplies_defaults(self):
        config = load_scenario_config(self.write_json(campaign_definition()))
        self.assertEqual([attack.identifier for attack in config.atk_types], ['probe', 'finish'])
        self.assertEqual(config.atk_types[0].description, 'Discover target')
        self.assertEqual(config.undetermined.identifier, 'undetermined')
        self.assertIs(config.attack_goal.attack_type, config.atk_types[1])
        self.assertEqual(config.enable_src_for, {})
        self.assertEqual(config.enable_dst_for, {})
        self.assertEqual(config.dst_restricted_atks, {})
        self.assertEqual(config.enable_atks, [])
        first, second = config.create_hosts(), config.create_hosts()
        first[0].update_compromise_attributes(config.atk_types[0].postconditions)
        self.assertEqual(second[0].compromise_attributes, set())
        self.assertEqual({a.value for a in config.external_host_attributes}, {'start'})

    def test_json_explicit_attributes_hosts_goal_and_undetermined(self):
        data = campaign_definition()
        data.update(attributes=['start', 'ready', 'done'],
                    hosts=[dict(ip='10.0.0.9', attributes=['ready'])],
                    attack_goal=dict(attack_type=None, source_ip='10.0.0.2', destination_ip='10.0.0.9'),
                    undetermined=dict(identifier='unknown', preconditions=[], postconditions=['ready']))
        del data['score_columns']
        config = load_scenario_config(self.write_json(data))
        self.assertEqual(config.score_columns, ('probe', 'finish'))
        self.assertEqual(config.undetermined.identifier, 'unknown')
        self.assertIsNone(config.attack_goal.attack_type)
        self.assertEqual(config.attack_goal.source_ip, '10.0.0.2')
        self.assertEqual(config.attack_goal.destination_ip, '10.0.0.9')
        self.assertEqual({a.value for a in config.create_hosts()[0].compromise_attributes}, {'ready'})

    def test_json_schema_errors_are_descriptive_value_errors(self):
        cases = []
        for field in ('attack_types', 'hosts', 'next_attack_dict', 'possible_srcs', 'possible_dsts', 'final_atk'):
            data = campaign_definition()
            del data[field]
            cases.append((data, field))
        for field, value in (('attributes', ['start']), ('score_columns', 'probe'), ('hosts', 'host'),
                             ('enable_atks', {}), ('next_attack_dict', {'start': 'probe'}),
                             ('attack_goal', {'attack_type': 'missing'})):
            data = campaign_definition()
            data[field] = value
            cases.append((data, 'Unknown attribute' if field == 'attributes' else field))
        data = campaign_definition()
        data['attack_types'][0]['preconditions'][0]['targets_source'] = 'true'
        cases.append((data, 'targets_source'))
        data = copy.deepcopy(data)
        del data['attack_types'][0]['identifier']
        cases.append((data, 'identifier'))
        for data, message in cases:
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, message):
                load_scenario_config(self.write_json(data))
        filename = self.write_json({})
        Path(filename).write_text('{bad json', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Invalid scenario configuration'):
            load_scenario_config(filename)

    def test_python_modules_validate_required_definitions(self):
        filename = self.log_path('invalid.py')
        Path(filename).write_text('ATK_TYPES = []\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'UNDETERMINED'):
            load_scenario_config(filename)

    def test_custom_json_and_python_campaigns_work_across_all_clis(self):
        data = campaign_definition()
        json_file = self.write_json(data)
        python_file = self.log_path('campaign.py')
        source = '''from scenario_reconstructor.models import AttackType, Host, HostAttribute, Precondition
class Attributes(HostAttribute):
    START = 'start'
    READY = 'ready'
    DONE = 'done'
ATK_TYPES = [AttackType('probe', {Precondition({Attributes.START}, True)}, {Attributes.READY}),
             AttackType('finish', {Precondition({Attributes.READY}, False)}, {Attributes.DONE})]
UNDETERMINED = AttackType('undetermined', set(), set())
HOSTS = [Host('10.0.0.9')]
EXTERNAL_HOST_ATTRIBUTES = {Attributes.START}
ATTACK_SCORE_COLUMNS = ('finish', 'probe')
ENABLE_SRC_FOR = {}
ENABLE_DST_FOR = {}
DST_RESTRICTED_ATKS = {}
ENABLE_ATKS = []
'''
        for field in ('next_attack_dict', 'possible_srcs', 'possible_dsts', 'final_atk'):
            source += f'{field.upper()} = {data[field]!r}\n'
        Path(python_file).write_text(source, encoding='utf-8')
        rows = []
        for index, label in enumerate(('normal', 'probe', 'finish')):
            rows.append(dict(timestamp=f'2026-01-01 00:00:0{index}', duration=100, label=label,
                             step_number=-1 if index == 0 else index, src_ip='10.0.0.2', dst_ip='10.0.0.9',
                             src_port=40000, dst_port=80, protocol=6, anomaly_score=float(index > 0),
                             probe=float(label == 'probe'), finish=float(label == 'finish')))
        dataset, output, actual, predicted = [self.log_path(name) for name in
                                              ('dataset.csv', 'out.csv', 'actual.txt', 'predicted.txt')]
        pd.DataFrame(rows).to_csv(dataset, index=False)
        for spec in (json_file, python_file):
            with self.subTest(config=spec):
                config = load_scenario_config(spec)
                first, second = config.create_hosts(), config.create_hosts()
                first[0].update_compromise_attributes(config.atk_types[0].postconditions)
                self.assertEqual(second[0].compromise_attributes, set())
                generator_cli.main(['-f', dataset, '-o', output, '--steps-output', actual,
                                    '--config', spec, '--quiet'])
                reconstructor_cli.main(['-f', output, '-o', predicted, '-c', spec, '--quiet'])
                parser = AlertStepParser(config.atk_types)
                self.assertEqual([parser.parse_step(line) for line in Path(actual).read_text().splitlines()],
                                 [parser.parse_step(line) for line in Path(predicted).read_text().splitlines()])
                log = self.log_path('custom-metrics.txt')
                capture.main(['-f', dataset, '-c', spec, '-t', '2', '-l', log, '--quiet'])
                self.assertIn('mean scenario detection rate: 1.0', Path(log).read_text())


class TestExperimentEntryPoints(ProjectTestCase):
    def test_config_and_path_errors_precede_dataset_reads(self):
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stderr(io.StringIO()):
            for main, required in ((capture.main, []), (reconstructor_cli.main, []),
                                   (generator_cli.main, ['-o', self.log_path('out.csv')])):
                for config in ('nonexistent_campaign', self.log_path('missing.json')):
                    with self.subTest(main=main, config=config), self.assertRaises(SystemExit) as result:
                        main(['-f', 'missing.csv', *required, '--config', config])
                    self.assertEqual(result.exception.code, 2)
            for main, required in ((capture.main, []), (generator_cli.main, ['-o', 'out.csv'])):
                for options in (['--step', 'broken'], ['--step', 'attack,src'],
                                ['--step', 'attack:same->same'],
                                ['--scenario-path', 'missing.json'],
                                ['--scenario-path', 'attack:src->dst', '--step', 'attack,src,dst']):
                    with self.subTest(main=main, options=options), self.assertRaises(SystemExit) as result:
                        main(['-f', 'missing.csv', *required, *options])
                    self.assertEqual(result.exception.code, 2)
        read_csv.assert_not_called()

    def test_config_imports_and_default_loading_preserve_domain_isolation(self):
        script = (
            'import sys; import scenario_configs; import scenario_reconstructor; '
            'scenario_configs.load_scenario_config(); '
            'assert not ({"metrics", "pandas", "sklearn"} & sys.modules.keys())'
        )
        result = subprocess.run([sys.executable, '-c', script], cwd=REPO_ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_importing_runners_does_not_read_data_or_launch_processes(self):
        with patch('pandas.read_csv') as read_csv, patch('subprocess.run') as run, \
                patch.object(pd.DataFrame, 'to_csv') as to_csv, patch.object(Path, 'mkdir') as mkdir, \
                patch('builtins.open') as open_file, patch.object(Path, 'open') as path_open:
            for filename in ('experiments/capture.py', 'experiments/batch.py',
                             'experiments/reporting.py',
                             'scenario_generator/cli.py', 'scenario_reconstructor/cli.py',
                             'scenario_reconstructor/reconstruct_cAPTure.py'):
                with self.subTest(filename=filename):
                    runpy.run_path(str(REPO_ROOT / filename), run_name='import_check')
            runpy.run_path(str(REPO_ROOT / 'run_scripts.py'), run_name='import_check')
        read_csv.assert_not_called()
        run.assert_not_called()
        to_csv.assert_not_called()
        mkdir.assert_not_called()
        open_file.assert_not_called()
        path_open.assert_not_called()

    def test_legacy_runner_exports_the_canonical_main_and_definitions(self):
        from scenario_reconstructor import reconstruct_cAPTure as legacy
        from scenario_configs import capture as definitions
        self.assertIs(legacy.main, capture.main)
        for name in definitions.__all__:
            self.assertIs(getattr(legacy, name), getattr(definitions, name))

    def test_help_does_not_require_a_dataset(self):
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stdout(io.StringIO()):
            for main in (capture.main, generator_cli.main, reconstructor_cli.main):
                with self.subTest(main=main), self.assertRaises(SystemExit) as result:
                    main(['--help'])
                self.assertEqual(result.exception.code, 0)
        read_csv.assert_not_called()

    def test_package_entry_points_show_help_without_reading_files(self):
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stdout(io.StringIO()):
            for package in ('scenario_generator', 'scenario_reconstructor'):
                with self.subTest(package=package), patch.object(sys, 'argv', [package, '--help']):
                    with self.assertRaises(SystemExit) as result:
                        runpy.run_module(package, run_name='__main__')
                    self.assertEqual(result.exception.code, 0)
        read_csv.assert_not_called()

    def test_importing_entry_points_does_not_generate_or_reconstruct(self):
        with patch.object(generator_cli.ScenarioGenerator, 'generate_scenario') as generate, \
                patch.object(reconstructor_cli.ScenarioReconstructor, '__init__', return_value=None) as reconstruct, \
                patch('pandas.read_csv') as read_csv, patch('subprocess.run') as run:
            for filename in ('scenario_generator/cli.py', 'scenario_reconstructor/cli.py',
                             'experiments/capture.py', 'experiments/batch.py',
                             'scenario_reconstructor/reconstruct_cAPTure.py'):
                with self.subTest(filename=filename):
                    runpy.run_path(str(REPO_ROOT / filename), run_name='import_check')
            for module in ('scenario_generator.__main__', 'scenario_reconstructor.__main__'):
                with self.subTest(module=module):
                    runpy.run_module(module, run_name='import_check')
        generate.assert_not_called()
        reconstruct.assert_not_called()
        read_csv.assert_not_called()
        run.assert_not_called()

    def test_invalid_reconstruction_arguments_are_parser_errors_before_reading(self):
        invalid = [
            ['--anomaly-threshold', '0'], ['--anomaly-threshold', '1.1'],
            ['--suspect-threshold', '-0.1'], ['--suspect-threshold', '0.8'],
            ['--suspect-threshold', '0.9'], ['--type-threshold', '-0.1'],
            ['--type-threshold', '1.1'], ['--type-threshold', 'nan'],
            ['--max-idle-gap', '-1'], ['--max-idle-gap', 'nan'], ['--max-idle-gap', 'inf'],
            ['--log-flow-exploits-threshold', '-2'], ['--log-states-threshold', '-2'],
            ['--suspect-max-length', '-2'],
        ]
        filename = self.log_path('input.csv')
        Path(filename).touch()
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stderr(io.StringIO()):
            for main in (capture.main, reconstructor_cli.main):
                for options in invalid:
                    with self.subTest(main=main, options=options), self.assertRaises(SystemExit) as result:
                        main(['-f', filename, *options])
                    self.assertEqual(result.exception.code, 2)
        read_csv.assert_not_called()

    def test_invalid_generation_and_evaluation_arguments_are_parser_errors(self):
        filename = self.log_path('input.csv')
        Path(filename).touch()
        invalid = [
            ['--normal-divisor', '0'], ['--max-steps', '0'],
            ['--max-search-attempts', '0'], ['--max-generation-retries', '-1'],
            ['--seed', '-1'], ['--seed', str(2**32)],
        ]
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stderr(io.StringIO()):
            for main, required in ((capture.main, []), (generator_cli.main, ['-o', self.log_path('out.csv')])):
                for options in invalid:
                    with self.subTest(main=main, options=options), self.assertRaises(SystemExit) as result:
                        main(['-f', filename, *required, *options])
                    self.assertEqual(result.exception.code, 2)
            for options in (['-t', '0'], ['-t', '-1'], ['--edge-recovery-threshold', '-0.1'],
                            ['--edge-recovery-threshold', '1.1'], ['--edge-recovery-threshold', 'nan']):
                with self.subTest(options=options), self.assertRaises(SystemExit) as result:
                    capture.main(['-f', filename, *options])
                self.assertEqual(result.exception.code, 2)
        read_csv.assert_not_called()

    def test_input_paths_must_be_existing_csv_files(self):
        non_csv = self.log_path('input.txt')
        Path(non_csv).touch()
        with patch('pandas.read_csv') as read_csv, contextlib.redirect_stderr(io.StringIO()):
            for main, required in ((capture.main, []), (reconstructor_cli.main, []),
                                   (generator_cli.main, ['-o', self.log_path('out.csv')])):
                for filename in (non_csv, self.log_path('missing.csv')):
                    with self.subTest(main=main, filename=filename), self.assertRaises(SystemExit) as result:
                        main(['-f', filename, *required])
                    self.assertEqual(result.exception.code, 2)
        read_csv.assert_not_called()

    def test_each_experiment_gets_independent_hosts_and_attribute_sets(self):
        first, second = create_hosts(), create_hosts()
        self.assertEqual([host.ip_address for host in first], [host.ip_address for host in second])
        for left, right in zip(first, second):
            self.assertIsNot(left, right)
            self.assertIsNot(left.compromise_attributes, right.compromise_attributes)
        first[0].compromise_attributes.add(DollarCharHostAttributes.CRASHED)
        self.assertNotIn(DollarCharHostAttributes.CRASHED, second[0].compromise_attributes)

    def test_batch_plan_retains_all_configured_valid_threshold_combinations(self):
        jobs = batch.build_jobs()
        self.assertEqual(len(jobs), 48)
        self.assertEqual(len({job.output_file for job in jobs}), len(jobs))
        self.assertTrue(all(job.suspect_threshold < job.anomaly_threshold for job in jobs))
        self.assertEqual({job.input_file for job in jobs},
                         {batch.DATASET_ROOT + name for name in batch.DATASET_FILES})


class TestEvaluationReporting(ProjectTestCase):
    def test_dataset_metadata_preserves_detector_names(self):
        for filename, detector, mapper in (
            ('xgb_lr_rec_dataset.csv', 'xgb', 'lr'),
            ('xgb_lr.csv', 'xgb', 'lr'),
            ('logistic_regression_gnb_rec_dataset.csv', 'logistic_regression', 'gnb'),
            ('perfect_xgb_rec_dataset.csv', 'perfect', 'xgb'),
            ('xgb_perfect_rec_dataset.csv', 'xgb', 'perfect'),
            ('other.csv', '', ''), ('unknown_mapper_rec_dataset.csv', '', ''),
            ('lr_rec_dataset.csv', '', ''),
        ):
            with self.subTest(filename=filename):
                self.assertEqual(reporting.parse_dataset_metadata('./data/final datasets/' + filename),
                                 (filename, detector, mapper))

    def test_text_formats_population_statistics_and_batch_rebuild(self):
        record = reporting.IterationRecord(**{field.name: 0 for field in fields(reporting.IterationRecord)})
        records = [record, replace(record, iteration=1, id_tp=4, rec_tp=2, scenario_detected=1)]
        root = Path(self.log_path('runs'))
        log = root / 'run.txt'
        reporting.write_evaluation_outputs(log, records, {'dataset': 'example.csv'},
                                           [['first', 'second']], [['predicted']])
        self.assertEqual(reporting.default_fn_log_path(log).read_text(),
                         'actual scenario\nfirst, second\npredicted scenario\npredicted\n')
        self.assertEqual(log.read_text(), (
            'mean ID true negatives: 0.0, mean REC true negatives: 0.0\n'
            'mean ID false positives: 0.0, mean REC false positives: 0.0\n'
            'mean ID false negatives: 0.0, mean REC false negatives: 0.0\n'
            'mean ID true positives: 2.0, mean REC true positives: 1.0\n'
            'mean precision of reconstructed alerts: 0.0\n'
            'mean recall of reconstructed alerts: 0.0\n'
            'mean soundness of reconstructed steps: 0.0\n'
            'mean completeness of reconstructed steps: 0.0\n'
            'mean precision of reconstructed scenarios: 0.0\n'
            'mean recall of reconstructed scenarios: 0.0\n'
            'mean soundness of reconstructed scenarios: 0.0\n'
            'mean completeness of reconstructed scenarios: 0.0\n'
            'mean scenario detection rate: 0.5\n'))
        summary = pd.read_csv(reporting.default_summary_csv_path(log))
        self.assertEqual(summary.loc[0, 'id_tp_std'], 2.0)
        self.assertEqual(summary.loc[0, 'scenario_detected_std'], 0.5)
        second_log = root / 'second.txt'
        reporting.write_evaluation_outputs(second_log, [record], {'dataset': 'second.csv'}, [], [])
        summary_out, iterations_out = reporting.aggregate_batch_results(
            root,
            summary_paths=[reporting.default_summary_csv_path(second_log), root / 'missing_summary.csv',
                           reporting.default_summary_csv_path(log)],
            iteration_paths=[reporting.default_iterations_csv_path(log),
                             reporting.default_iterations_csv_path(second_log)],
        )
        self.assertEqual(pd.read_csv(summary_out)['dataset'].tolist(), ['second.csv', 'example.csv'])
        self.assertEqual(len(pd.read_csv(iterations_out)), 3)
        reporting.main(['-d', str(root)])
        first = (summary_out.read_bytes(), iterations_out.read_bytes())
        reporting.main(['-d', str(root)])
        self.assertEqual(first, (summary_out.read_bytes(), iterations_out.read_bytes()))
        self.assertEqual(len(pd.read_csv(summary_out)), 2)
        self.assertEqual(len(pd.read_csv(iterations_out)), 3)

    def test_batch_noop_and_partial_inputs(self):
        root = Path(self.log_path('absent'))
        self.assertEqual(reporting.aggregate_batch_results(root), (None, None))
        self.assertEqual(reporting.main(['-d', str(root)]), (None, None))
        self.assertEqual(reporting.aggregate_batch_results(
            root, [root / 'missing_summary.csv'], [root / 'missing_iterations.csv']), (None, None))
        self.assertFalse(root.exists())
        root.mkdir()
        self.assertEqual(reporting.aggregate_batch_results(root), (None, None))
        self.assertEqual(list(root.iterdir()), [])
        source = Path(self.log_path('source.csv'))
        pd.DataFrame([{'id_tp_mean': 2.0}]).to_csv(source, index=False)
        summary, iterations = reporting.aggregate_batch_results(root, [source], [])
        self.assertEqual(summary, root / 'batch_summary.csv')
        self.assertIsNone(iterations)
        summary, iterations = reporting.aggregate_batch_results(root, [], [source])
        self.assertIsNone(summary)
        self.assertEqual(iterations, root / 'batch_iterations.csv')


class TestCaptureCliIntegration(ProjectTestCase):
    def setUp(self):
        super().setUp()
        self.input_file = self.log_path('templates.csv')
        rows = []
        for index, label in enumerate(['normal', *(attack.identifier for attack in ATK_TYPES)]):
            rows.append(dict(
                timestamp=pd.Timestamp('2026-01-01') + pd.Timedelta(seconds=index),
                duration=250, label=label, step_number=-1 if label == 'normal' else index,
                src_ip='10.0.0.2', dst_ip='10.0.0.17', src_port=40000 + index,
                dst_port=1883, protocol=6, anomaly_score=float(label != 'normal'),
                **{attack.identifier: float(label == attack.identifier) for attack in ATK_TYPES},
            ))
        pd.DataFrame(rows).to_csv(self.input_file, index=False)

    def generate_scenario(self, **options):
        paths = {name: self.log_path(f'generated/{name}/result.{extension}')
                 for name, extension in (('scenario', 'csv'), ('steps', 'txt'), ('alerts', 'txt'))}
        arguments = ['-f', self.input_file, '-o', paths['scenario'], '--steps-output', paths['steps'],
                     '--alerts-output', paths['alerts'], '--seed', '42', '--quiet']
        for name, value in options.items():
            arguments.extend([f"--{name.replace('_', '-')}", str(value)])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            generator_cli.main(arguments)
        self.assertEqual(stdout.getvalue(), '')
        return paths

    def test_evaluation_csv_defaults_and_custom_paths_include_all_metrics(self):
        dataset = self.log_path('logistic_regression_lr_rec_dataset.csv')
        Path(dataset).write_bytes(Path(self.input_file).read_bytes())
        for custom in (False, True):
            with self.subTest(custom=custom):
                log = self.log_path(f'report-{custom}/results.txt')
                iterations = (Path(self.log_path('custom/iterations/out.csv')) if custom
                              else reporting.default_iterations_csv_path(log))
                summary = (Path(self.log_path('custom/summary/out.csv')) if custom
                           else reporting.default_summary_csv_path(log))
                options = ['--iterations-csv', str(iterations), '--summary-csv', str(summary)] if custom else []
                with patch.object(capture.ReconstructionManager, 'get_fns', return_value=[object(), object()]), \
                        patch.object(capture.ReconstructionManager, 'get_fps', return_value=[object()]):
                    capture.main(['-f', dataset, '-t', '2', '-l', log, '--seed', '42', '--quiet', *options])
                frame, stats = pd.read_csv(iterations), pd.read_csv(summary)
                self.assertEqual(len(frame), 2)
                self.assertEqual(frame['iteration'].tolist(), [0, 1])
                self.assertEqual(frame['recovered_fns'].tolist(), [2, 2])
                self.assertEqual(frame['rejected_fps'].tolist(), [1, 1])
                self.assertEqual(len(stats), 1)
                for key, value in dict(dataset=Path(dataset).name, detector='logistic_regression', mapper='lr',
                                       config='capture', seed=42, times=2).items():
                    self.assertTrue((frame[key] == value).all())
                    self.assertEqual(stats.loc[0, key], value)
                for field in fields(reporting.IterationRecord):
                    self.assertIn(field.name, frame.columns)
                    if field.name != 'iteration':
                        self.assertAlmostEqual(stats.loc[0, field.name + '_mean'], frame[field.name].mean())
                        self.assertAlmostEqual(stats.loc[0, field.name + '_std'], frame[field.name].std(ddof=0))
                self.assertTrue(frame['scenario_detected'].isin([0, 1]).all())
                self.assertTrue(Path(log).is_file())
                self.assertTrue(reporting.default_fn_log_path(log).is_file())
                if custom:
                    self.assertFalse(reporting.default_iterations_csv_path(log).exists())
                    self.assertFalse(reporting.default_summary_csv_path(log).exists())

    def test_generate_then_reconstruct_scored_scenario_with_nested_outputs_and_archives(self):
        paths = self.generate_scenario()
        frame = pd.read_csv(paths['scenario'])
        self.assertIn(DOLLAR_CHAR.identifier, set(frame['label']))
        parser = AlertStepParser(ATK_TYPES)
        actual_steps = [parser.parse_step(line) for line in Path(paths['steps']).read_text().splitlines()]
        actual_alerts = [parser.parse_alert(line) for line in Path(paths['alerts']).read_text().splitlines()]
        self.assertGreater(len(actual_steps), 0)
        self.assertEqual(len(actual_alerts), int((frame['label'] != 'normal').sum()))
        output, alerts = self.log_path('reconstructed/steps/out.txt'), self.log_path('reconstructed/alerts/out.txt')
        flow_log, state_log = self.log_path('archives/flows/out.log'), self.log_path('archives/states/out.log')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                patch.object(reconstructor_cli, 'ScenarioReconstructor', wraps=reconstructor_cli.ScenarioReconstructor) as reconstruct, \
                patch.object(reconstructor_cli, 'ReconstructionManager', wraps=reconstructor_cli.ReconstructionManager) as manage:
            reconstructor_cli.main([
                '-f', paths['scenario'], '-o', output, '--alerts-output', alerts,
                '--anomaly-threshold', '0.9', '--suspect-threshold', '0.3', '--type-threshold', '0.1',
                '--max-idle-gap', '2.5', '--flow-log-path', flow_log, '--state-log-path', state_log,
                '--log-flow-exploits-threshold', '0', '--log-states-threshold', '0',
                '--suspect-max-length', '20', '--quiet',
            ])
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(reconstruct.call_args.kwargs['max_idle_gap'].total_seconds(), 2.5)
        self.assertEqual(manage.call_args.kwargs, dict(
            length_when_log_flow_exploits=0, length_when_log_states=0, suspect_list_max_length=20))
        predicted_steps = [parser.parse_step(line) for line in Path(output).read_text().splitlines()]
        predicted_alerts = [parser.parse_alert(line) for line in Path(alerts).read_text().splitlines()]
        self.assertEqual(len(predicted_steps), len(actual_steps))
        self.assertCountEqual(predicted_alerts, actual_alerts)
        for filename in (flow_log, state_log):
            self.assertGreater(Path(filename).stat().st_size, 0)

    def test_capture_config_is_explicitly_supported_by_all_clis(self):
        paths = self.generate_scenario(config='capture')
        reconstructor_cli.main(['-f', paths['scenario'], '--config', 'capture', '--quiet'])
        log = self.log_path('capture.txt')
        capture.main(['-f', self.input_file, '-c', 'capture', '-t', '1', '-l', log, '--quiet', '--seed', '42'])
        self.assertIn('mean scenario detection rate:', Path(log).read_text())

    def test_explicit_cli_paths_produce_exact_step_sequences(self):
        expected = [('scp_inst', '10.0.0.2', '10.0.0.7'),
                    ('nmap_mqtt', '10.0.0.7', '10.0.0.1'),
                    ('scp_inst', '10.0.0.2', '10.0.0.7')]
        json_path, text_path = self.log_path('path.json'), self.log_path('path.txt')
        Path(json_path).write_text(json.dumps({'steps': [list(expected[0]),
            dict(attack=expected[1][0], source_ip=expected[1][1], destination_ip=expected[1][2]),
            dict(attack=expected[2][0], src_ip=expected[2][1], dst_ip=expected[2][2])]}), encoding='utf-8')
        Path(text_path).write_text('# ordered steps\n\n' + '\n'.join(','.join(step) for step in expected),
                                   encoding='utf-8')
        specs = [f'{attack}:{src}->{dst}' for attack, src, dst in expected]
        options = [sum((['--step', spec] for spec in specs), []),
                   ['--scenario-path', json_path], ['--scenario-path', text_path],
                   ['--scenario-path', ';'.join(specs)], ['--scenario-path', '|'.join(specs)]]
        for arguments in options:
            with self.subTest(arguments=arguments):
                output, steps_file = self.log_path('explicit.csv'), self.log_path('explicit.txt')
                generator_cli.main(['-f', self.input_file, '-o', output, '--steps-output', steps_file,
                                    '--quiet', *arguments])
                steps = [AlertStepParser(ATK_TYPES).parse_step(line)
                         for line in Path(steps_file).read_text().splitlines()]
                self.assertEqual([(s.attack_type.identifier, s.source_ip, s.destination_ip) for s in steps], expected)

    def test_generation_retries_search_limit_then_writes_real_outputs(self):
        original = generator_cli.ScenarioGenerator.generate_scenario
        calls = []

        def fail_once(generator, *args, **kwargs):
            calls.append((args, kwargs))
            if len(calls) == 1:
                raise ScenarioSearchLimitError('max_search_attempts', 1234, 1234)
            return original(generator, *args, **kwargs)

        with patch.object(generator_cli.ScenarioGenerator, 'generate_scenario', new=fail_once):
            paths = self.generate_scenario(normal_divisor=2, max_steps=90, max_search_attempts=1234,
                                           max_generation_retries=1)
        self.assertEqual(calls, [((2,), dict(max_steps=90, max_search_attempts=1234))] * 2)
        self.assertGreater(Path(paths['alerts']).stat().st_size, 0)

    def test_generation_seed_reproduces_csv_steps_and_alerts(self):
        paths = self.generate_scenario()
        first = {name: Path(filename).read_bytes() for name, filename in paths.items()}
        self.generate_scenario()
        self.assertEqual(first, {name: Path(filename).read_bytes() for name, filename in paths.items()})

    def test_search_exhaustion_propagates_after_configured_retries(self):
        error = ScenarioSearchLimitError('max_steps', 1, 1)
        for main, extra in ((generator_cli.main, ['-o', self.log_path('failed/out.csv')]),
                            (capture.main, ['-t', '1', '-l', self.log_path('failed/log.txt')])):
            for retries in (0, 2):
                with self.subTest(main=main, retries=retries), \
                        patch.object(generator_cli.ScenarioGenerator, 'generate_scenario', side_effect=error) as generate, \
                        contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(ScenarioSearchLimitError) as result:
                        main(['-f', self.input_file, *extra, '--max-generation-retries', str(retries), '--quiet'])
                    self.assertIs(result.exception, error)
                    self.assertEqual(generate.call_count, retries + 1)
        self.assertFalse(Path(self.log_path('failed/out.csv')).exists())

    def test_invalid_templates_raise_generation_error_before_timestamp_sort(self):
        invalid_file = self.log_path('invalid.csv')
        pd.DataFrame({'label': ['normal']}).to_csv(invalid_file, index=False)
        for main, extra in ((capture.main, ['-t', '1']),
                            (generator_cli.main, ['-o', self.log_path('out.csv')])):
            with self.subTest(main=main), self.assertRaises(ScenarioGenerationError):
                main(['-f', invalid_file, *extra, '--quiet'])

    def test_evaluation_retries_per_iteration_and_reports_detection_rate(self):
        log = self.log_path('evaluation/summary/results.txt')
        flow_log, state_log = self.log_path('evaluation/flows/out.log'), self.log_path('evaluation/states/out.log')
        original = capture.ScenarioGenerator.generate_scenario
        generation_calls = []

        def fail_every_first_attempt(generator, *args, **kwargs):
            generation_calls.append((args, kwargs))
            if len(generation_calls) % 2 == 1:
                raise ScenarioSearchLimitError('max_search_attempts', 10_000, 10_000)
            return original(generator, *args, **kwargs)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                patch.object(capture.ScenarioGenerator, 'generate_scenario', new=fail_every_first_attempt), \
                patch.object(capture.MetricsCalculator, 'is_scenario_detected',
                             wraps=capture.MetricsCalculator.is_scenario_detected) as detected, \
                patch.object(capture, 'ScenarioReconstructor', wraps=capture.ScenarioReconstructor) as reconstruct, \
                patch.object(capture, 'ReconstructionManager', wraps=capture.ReconstructionManager) as manage:
            capture.main([
                '-f', self.input_file, '-t', '2', '-l', log, '--seed', '42', '--quiet',
                '--normal-divisor', '2', '--max-steps', '90', '--max-search-attempts', '10000',
                '--max-generation-retries', '1', '--edge-recovery-threshold', '0.75',
                '--max-idle-gap', '2.5', '--flow-log-path', flow_log, '--state-log-path', state_log,
                '--log-flow-exploits-threshold', '0', '--log-states-threshold', '0',
                '--suspect-max-length', '20',
            ])
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(generation_calls, [((2,), dict(max_steps=90, max_search_attempts=10000))] * 4)
        self.assertEqual(reconstruct.call_args.kwargs['max_idle_gap'].total_seconds(), 2.5)
        self.assertEqual(manage.call_args.kwargs, dict(
            length_when_log_flow_exploits=0, length_when_log_states=0, suspect_list_max_length=20))
        self.assertEqual(detected.call_count, 2)
        for call in detected.call_args_list:
            self.assertEqual(call.kwargs['edge_recovery_threshold'], 0.75)
            self.assertIs(call.args[2].attack_type, DOLLAR_CHAR)
            self.assertEqual(call.args[2].destination_ip, '10.0.0.1')
        summary = Path(log).read_text()
        tp = re.search(r'mean REC true positives: ([0-9.]+)', summary)
        self.assertIsNotNone(tp)
        self.assertGreater(float(tp.group(1)), 0)
        rate = re.search(r'mean scenario detection rate: ([0-9.]+)', summary)
        self.assertIsNotNone(rate)
        self.assertGreaterEqual(float(rate.group(1)), 0)
        self.assertLessEqual(float(rate.group(1)), 1)
        self.assertTrue(Path(log.removesuffix('.txt') + '_fn_generating_scenarios.txt').is_file())
        for filename in (flow_log, state_log):
            self.assertGreater(Path(filename).stat().st_size, 0)
