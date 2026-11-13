"""Dataset definitions and command entry points are safe to reuse as libraries."""
import contextlib
import io
from pathlib import Path
import re
import runpy
import sys
from unittest.mock import patch

import pandas as pd

from experiments import batch, capture
from scenario_configs.capture import ATK_TYPES, DOLLAR_CHAR, DollarCharHostAttributes, create_hosts
from scenario_generator import ScenarioGenerationError, ScenarioSearchLimitError
from scenario_generator import cli as generator_cli
from scenario_reconstructor import cli as reconstructor_cli
from scenario_reconstructor.serialization import AlertStepParser
from tests.support import ProjectTestCase, REPO_ROOT


class TestExperimentEntryPoints(ProjectTestCase):
    def test_importing_runners_does_not_read_data_or_launch_processes(self):
        with patch('pandas.read_csv') as read_csv, patch('subprocess.run') as run:
            for filename in ('experiments/capture.py', 'experiments/batch.py',
                             'scenario_generator/cli.py', 'scenario_reconstructor/cli.py',
                             'scenario_reconstructor/reconstruct_cAPTure.py'):
                with self.subTest(filename=filename):
                    runpy.run_path(str(REPO_ROOT / filename), run_name='import_check')
            runpy.run_path(str(REPO_ROOT / 'run_scripts.py'), run_name='import_check')
        read_csv.assert_not_called()
        run.assert_not_called()

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
