"""Batch dispatch uses the active interpreter without shell commands."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import threading
from unittest.mock import patch

import pandas as pd

from experiments import batch, capture, reporting
from experiments.policy import load_policy_config
from scenario_configs.capture import ATK_TYPES
from tests.support import ProjectTestCase, REPO_ROOT


class TestBatchRunner(ProjectTestCase):
    def test_failed_jobs_exclude_stale_and_partially_replaced_csvs(self):
        root = Path(self.log_path('reused-results'))
        root.mkdir()
        names = ('failed', 'partial', 'successful')
        jobs = [batch.EvaluationJob(f'{name}.csv', f'original/{name}.txt', 0.8, 0.4)
                for name in names]
        for name in names:
            for suffix in ('summary', 'iterations'):
                pd.DataFrame([{'dataset': f'old-{name}'}]).to_csv(
                    root / f'{name}_{suffix}.csv', index=False)
        for filename in ('batch_summary.csv', 'batch_iterations.csv'):
            pd.DataFrame([{'dataset': 'old-batch'}]).to_csv(root / filename, index=False)
        dispatched = []

        def run(command, **kwargs):
            log = Path(command[command.index('-l') + 1])
            dispatched.append(log.stem)
            self.assertFalse((root / 'batch_summary.csv').exists())
            self.assertFalse((root / 'batch_iterations.csv').exists())
            if log.stem == 'failed':
                return subprocess.CompletedProcess(command, 1)
            pd.DataFrame([{'dataset': f'new-{log.stem}'}]).to_csv(
                reporting.default_summary_csv_path(log), index=False)
            if log.stem == 'partial':
                return subprocess.CompletedProcess(command, 2)
            pd.DataFrame([{'dataset': f'new-{log.stem}'}]).to_csv(
                reporting.default_iterations_csv_path(log), index=False)
            return subprocess.CompletedProcess(command, 0)

        stdout = io.StringIO()
        with patch.object(batch, 'build_jobs', return_value=jobs), \
                patch('subprocess.run', side_effect=run), contextlib.redirect_stdout(stdout):
            batch.main(['--quiet', '--results-dir', str(root)])
        self.assertEqual(dispatched, list(names))
        for filename in ('batch_summary.csv', 'batch_iterations.csv'):
            self.assertEqual(pd.read_csv(root / filename)['dataset'].tolist(), ['new-successful'])
        self.assertIn('FAILED (exit 1)', stdout.getvalue())
        self.assertIn('FAILED (exit 2)', stdout.getvalue())
        # Preserve diagnostic job files, including the partial report from a failed process.
        for filename, expected in (('failed_summary.csv', 'old-failed'),
                                   ('failed_iterations.csv', 'old-failed'),
                                   ('partial_summary.csv', 'new-partial'),
                                   ('partial_iterations.csv', 'old-partial')):
            self.assertEqual(pd.read_csv(root / filename)['dataset'].tolist(), [expected])

    def test_all_failed_jobs_leave_no_stale_combined_reports(self):
        root = Path(self.log_path('all-failed'))
        root.mkdir()
        filenames = ('failed_summary.csv', 'failed_iterations.csv',
                     'batch_summary.csv', 'batch_iterations.csv')
        for filename in filenames:
            pd.DataFrame([{'dataset': 'old'}]).to_csv(root / filename, index=False)
        jobs = [batch.EvaluationJob('failed.csv', 'original/failed.txt', 0.8, 0.4)]
        with patch.object(batch, 'build_jobs', return_value=jobs), \
                patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1)), \
                contextlib.redirect_stdout(io.StringIO()):
            batch.main(['--quiet', '--results-dir', str(root)])
        self.assertFalse((root / 'batch_summary.csv').exists())
        self.assertFalse((root / 'batch_iterations.csv').exists())
        for filename in filenames[:2]:
            self.assertEqual(pd.read_csv(root / filename)['dataset'].tolist(), ['old'])

    def test_batch_aggregates_only_its_jobs_after_dispatch(self):
        root = Path(self.log_path('results'))
        root.mkdir()
        for suffix in ('summary', 'iterations'):
            pd.DataFrame([{'dataset': 'unrelated'}]).to_csv(root / f'unrelated_{suffix}.csv', index=False)
        jobs = [batch.EvaluationJob(f'{name}.csv', f'original/{name}.txt', 0.8, 0.4)
                for name in ('first', 'second')]
        dispatched = []

        def run(command, **kwargs):
            log = Path(command[command.index('-l') + 1])
            log.parent.mkdir(parents=True, exist_ok=True)
            pd.DataFrame([{'dataset': log.stem, 'id_tp_mean': 2.0}]).to_csv(
                reporting.default_summary_csv_path(log), index=False)
            pd.DataFrame([{'dataset': log.stem, 'iteration': 0, 'id_tp': 2}]).to_csv(
                reporting.default_iterations_csv_path(log), index=False)
            self.assertFalse((root / 'batch_summary.csv').exists())
            dispatched.append(log.stem)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(batch, 'build_jobs', return_value=jobs), patch('subprocess.run', side_effect=run):
            batch.main(['--quiet', '--results-dir', str(root)])
        self.assertEqual(dispatched, ['first', 'second'])
        for filename in ('batch_summary.csv', 'batch_iterations.csv'):
            self.assertEqual(pd.read_csv(root / filename)['dataset'].tolist(), dispatched)

    def test_batch_forwards_seed_quiet_and_leaves_missing_outputs_untouched(self):
        results = self.log_path('missing-results')
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            batch.main(['--quiet', '--seed', '7', '--results-dir', results])
        self.assertEqual(run.call_count, 48)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertEqual(command[command.index('--seed') + 1], '7')
            self.assertIn('--quiet', command)
            self.assertEqual(Path(command[command.index('-l') + 1]).parent, Path(results))
        self.assertFalse(Path(results).exists())

    def test_batch_default_seed_and_no_seed(self):
        for options, seed in (([], '42'), (['--no-seed'], None)):
            with self.subTest(options=options), \
                    patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
                batch.main(['--quiet', '--results-dir', self.log_path('absent'), *options])
            for call in run.call_args_list:
                command = call.args[0]
                if seed is None:
                    self.assertNotIn('--seed', command)
                else:
                    self.assertEqual(command[command.index('--seed') + 1], seed)

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

    def test_defaults_point_to_capture_dollar_char_paths(self):
        self.assertEqual(batch.DATASET_ROOT, './data/cAPTure/final_datasets/dollar_char/')
        self.assertEqual(batch.OUTPUT_ROOT, './data/cAPTure/results/dollar_char/')

    def test_batch_forwards_overrides_and_policy_flags(self):
        dataset_dir = self.log_path('custom_datasets')
        results_dir = self.log_path('custom_results')
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            batch.main([
                '--quiet',
                '--dataset-dir', dataset_dir,
                '--results-dir', results_dir,
                '--config', 'custom.json',
                '--times', '5',
                '--datasets', 'xgb_xgb', 'perfect_perfect_rec_dataset.csv',
                '--anomaly-thresholds', '0.8', '0.5',
                '--suspect-thresholds', '0.2', '0.6',
                '--type-threshold', '0.15',
                '--suspect-max-length', '500',
                '--max-idle-gap', '2.5',
                '--edge-recovery-threshold', '0.75',
                '--normal-divisor', '4',
            ])
        # Valid (av, sv) pairs: (0.8, 0.2), (0.8, 0.6), (0.5, 0.2) -> 2 datasets * 3 pairs = 6 jobs
        self.assertEqual(run.call_count, 6)
        first = run.call_args_list[0].args[0]
        self.assertEqual(first[first.index('-f') + 1], str(Path(dataset_dir) / 'xgb_xgb_rec_dataset.csv'))
        self.assertEqual(first[first.index('-c') + 1], 'custom.json')
        self.assertEqual(first[first.index('-t') + 1], '5')
        self.assertEqual(first[first.index('--type-threshold') + 1], '0.15')
        self.assertEqual(first[first.index('--suspect-max-length') + 1], '500')
        self.assertEqual(first[first.index('--max-idle-gap') + 1], '2.5')
        self.assertEqual(first[first.index('--edge-recovery-threshold') + 1], '0.75')
        self.assertEqual(first[first.index('--normal-divisor') + 1], '4')
        second_dataset_files = {
            call.args[0][call.args[0].index('-f') + 1]
            for call in run.call_args_list
        }
        self.assertEqual(second_dataset_files, {
            str(Path(dataset_dir) / 'xgb_xgb_rec_dataset.csv'),
            str(Path(dataset_dir) / 'perfect_perfect_rec_dataset.csv'),
        })

    def test_resolve_dataset_files_supports_detectors_mappers_and_all(self):
        self.assertEqual(
            batch.resolve_dataset_files(datasets=['xgb_xgb', 'xgb_xgb_rec_dataset', 'xgb_xgb_rec_dataset.csv']),
            ['xgb_xgb_rec_dataset.csv'],
        )
        all_files = batch.resolve_dataset_files(detectors=['all'], mappers=['all'])
        self.assertEqual(len(all_files), len(batch.ALL_DETECTORS) * len(batch.ALL_MAPPERS))
        self.assertIn('hbos_xgb_rec_dataset.csv', all_files)
        self.assertEqual(
            batch.resolve_dataset_files(detectors=['xgb'], mappers=['lr', 'xgb']),
            ['xgb_lr_rec_dataset.csv', 'xgb_xgb_rec_dataset.csv'],
        )

    def test_parallel_workers_preserve_deterministic_report_order_and_exclude_failures(self):
        root = Path(self.log_path('parallel-results'))
        root.mkdir()
        started_first = threading.Event()

        def run(command, **kwargs):
            log = Path(command[command.index('-l') + 1])
            stem = log.stem
            # Make the first job wait until the second job finishes first, and fail the third job.
            if 'av_0.3' in stem:
                started_first.wait(timeout=2)
            elif 'av_0.6' in stem:
                started_first.set()
            elif 'av_0.9' in stem:
                return subprocess.CompletedProcess(command, 1)

            pd.DataFrame([{'dataset': stem, 'id_tp_mean': 1.0}]).to_csv(
                reporting.default_summary_csv_path(log), index=False)
            pd.DataFrame([{'dataset': stem, 'iteration': 0, 'id_tp': 1}]).to_csv(
                reporting.default_iterations_csv_path(log), index=False)
            return subprocess.CompletedProcess(command, 0)

        with patch('subprocess.run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            batch.main([
                '--quiet', '--results-dir', str(root),
                '--datasets', 'xgb_xgb',
                '--anomaly-thresholds', '0.3', '0.6', '0.9',
                '--suspect-thresholds', '0.2',
                '--workers', '2',
            ])
        summary_datasets = pd.read_csv(root / reporting.BATCH_SUMMARY_FILENAME)['dataset'].tolist()
        iter_datasets = pd.read_csv(root / reporting.BATCH_ITERATIONS_FILENAME)['dataset'].tolist()
        expected = [
            'u_xgb_xgb_rec_dataset_av_0.3_sv_0.2',
            'u_xgb_xgb_rec_dataset_av_0.6_sv_0.2',
        ]
        self.assertEqual(summary_datasets, expected)
        self.assertEqual(iter_datasets, expected)

    def test_resume_skips_completed_outputs_and_aggregates_both(self):
        root = Path(self.log_path('resume-results'))
        root.mkdir()
        done_stem = 'u_xgb_xgb_rec_dataset_av_0.6_sv_0.2'
        todo_stem = 'u_xgb_xgb_rec_dataset_av_0.9_sv_0.2'
        pd.DataFrame([{'dataset': 'cached-done'}]).to_csv(root / f'{done_stem}_summary.csv', index=False)
        pd.DataFrame([{'dataset': 'cached-done', 'iteration': 0}]).to_csv(
            root / f'{done_stem}_iterations.csv', index=False)

        dispatched = []

        def run(command, **kwargs):
            log = Path(command[command.index('-l') + 1])
            dispatched.append(log.stem)
            pd.DataFrame([{'dataset': 'fresh-todo'}]).to_csv(
                reporting.default_summary_csv_path(log), index=False)
            pd.DataFrame([{'dataset': 'fresh-todo', 'iteration': 0}]).to_csv(
                reporting.default_iterations_csv_path(log), index=False)
            return subprocess.CompletedProcess(command, 0)

        with patch('subprocess.run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            batch.main([
                '--quiet', '--resume', '--results-dir', str(root),
                '--datasets', 'xgb_xgb',
                '--anomaly-thresholds', '0.6', '0.9',
                '--suspect-thresholds', '0.2',
            ])
        self.assertEqual(dispatched, [todo_stem])
        self.assertEqual(
            pd.read_csv(root / reporting.BATCH_SUMMARY_FILENAME)['dataset'].tolist(),
            ['cached-done', 'fresh-todo'],
        )

    def test_invalid_batch_arguments_reject_before_launching_subprocesses(self):
        invalid_cases = [
            ['--times', '0'],
            ['--workers', '0'],
            ['--datasets', 'xgb_xgb', '--detectors', 'xgb'],
            ['--datasets', 'xgb_xgb', '--mappers', 'xgb'],
            ['--anomaly-thresholds', '0.0'],
            ['--anomaly-thresholds', '1.1'],
            ['--suspect-thresholds', '-0.1'],
            ['--suspect-thresholds', '1.0'],
            ['--anomaly-thresholds', '0.3', '--suspect-thresholds', '0.4'],
            ['--type-threshold', '1.2'],
            ['--suspect-max-length', '-2'],
            ['--max-idle-gap', '-0.5'],
            ['--edge-recovery-threshold', '1.5'],
            ['--normal-divisor', '0'],
        ]
        with patch('subprocess.run') as run, contextlib.redirect_stderr(io.StringIO()):
            for options in invalid_cases:
                with self.subTest(options=options), self.assertRaises(SystemExit) as result:
                    batch.main(['--quiet', '--results-dir', self.log_path('absent'), *options])
                self.assertEqual(result.exception.code, 2)
        run.assert_not_called()

    def test_checked_in_dollar_char_policy_loads_for_batch_and_capture(self):
        policy_path = REPO_ROOT / 'experiments' / 'configs' / 'dollar_char_policy.json'
        batch_cfg = load_policy_config(policy_path, scope='batch')
        capture_cfg = load_policy_config(policy_path, scope='capture')
        self.assertEqual(batch_cfg['dataset_dir'], './data/cAPTure/final_datasets/dollar_char/')
        self.assertEqual(batch_cfg['anomaly_thresholds'], [0.3, 0.6, 0.9])
        self.assertEqual(batch_cfg['suspect_thresholds'], [0.2, 0.8])
        self.assertEqual(batch_cfg['log_flow_exploits_threshold'], -1)
        self.assertEqual(batch_cfg['log_states_threshold'], -1)
        self.assertNotIn('dataset_dir', capture_cfg)
        self.assertNotIn('anomaly_thresholds', capture_cfg)
        self.assertEqual(capture_cfg['times'], 100)
        self.assertEqual(capture_cfg['edge_recovery_threshold'], 0.8)

    def test_batch_policy_config_applies_settings_and_allows_cli_overrides(self):
        policy_path = Path(self.log_path('policy.json'))
        policy_path.write_text(json.dumps({
            'config': 'capture',
            'dataset_dir': self.log_path('policy_datasets'),
            'results_dir': self.log_path('policy_results'),
            'datasets': ['xgb_xgb'],
            'times': 25,
            'seed': None,
            'anomaly_threshold': 0.85,
            'suspect_threshold': 0.25,
            'type_threshold': 0.15,
            'max_idle_gap': 2.0,
            'suspect_max_length': 250,
            'log_flow_exploits_threshold': 50,
            'log_states_threshold': 60,
            'edge_recovery_threshold': 0.9,
            'normal_divisor': 5,
            'quiet': True,
        }), encoding='utf-8')

        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            batch.main(['--policy-config', str(policy_path)])
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index('-t') + 1], '25')
        self.assertEqual(cmd[cmd.index('--anomaly-threshold') + 1], '0.85')
        self.assertEqual(cmd[cmd.index('--suspect-threshold') + 1], '0.25')
        self.assertEqual(cmd[cmd.index('--type-threshold') + 1], '0.15')
        self.assertEqual(cmd[cmd.index('--max-idle-gap') + 1], '2.0')
        self.assertEqual(cmd[cmd.index('--suspect-max-length') + 1], '250')
        self.assertEqual(cmd[cmd.index('--log-flow-exploits-threshold') + 1], '50')
        self.assertEqual(cmd[cmd.index('--log-states-threshold') + 1], '60')
        self.assertEqual(cmd[cmd.index('--edge-recovery-threshold') + 1], '0.9')
        self.assertEqual(cmd[cmd.index('--normal-divisor') + 1], '5')
        self.assertNotIn('--seed', cmd)
        self.assertIn('--quiet', cmd)

        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            batch.main([
                '--policy-config', str(policy_path),
                '--datasets', 'perfect_perfect',
                '--times', '10',
                '--seed', '7',
            ])
        cmd = run.call_args.args[0]
        self.assertTrue(cmd[cmd.index('-f') + 1].endswith('perfect_perfect_rec_dataset.csv'))
        self.assertEqual(cmd[cmd.index('-t') + 1], '10')
        self.assertEqual(cmd[cmd.index('--seed') + 1], '7')

    def test_invalid_policy_configs_fail_before_subprocesses_or_csv_reads(self):
        missing = self.log_path('does_not_exist.json')
        malformed = Path(self.log_path('malformed.json'))
        malformed.write_text('{bad json', encoding='utf-8')
        unknown_key = Path(self.log_path('unknown.json'))
        unknown_key.write_text(json.dumps({'mystery_option': 1}), encoding='utf-8')
        bool_for_int = Path(self.log_path('bool_int.json'))
        bool_for_int.write_text(json.dumps({'times': True}), encoding='utf-8')
        conflict = Path(self.log_path('conflict.json'))
        conflict.write_text(json.dumps({'anomaly_threshold': 0.5, 'anomaly_thresholds': [0.5]}), encoding='utf-8')

        bad_paths = [missing, str(malformed), str(unknown_key), str(bool_for_int), str(conflict)]
        with patch('subprocess.run') as run, patch('pandas.read_csv') as read_csv, \
                contextlib.redirect_stderr(io.StringIO()):
            for path in bad_paths:
                with self.subTest(runner='batch', path=path), self.assertRaises(SystemExit) as result:
                    batch.main(['--policy-config', path])
                self.assertEqual(result.exception.code, 2)
                with self.subTest(runner='capture', path=path), self.assertRaises(SystemExit) as result:
                    capture.main(['-f', 'ignored.csv', '--policy-config', path])
                self.assertEqual(result.exception.code, 2)
        run.assert_not_called()
        read_csv.assert_not_called()

    def test_capture_policy_config_applies_settings_and_allows_cli_overrides(self):
        dataset = Path(self.log_path('perfect_perfect_rec_dataset.csv'))
        rows = [
            dict(
                timestamp=pd.Timestamp('2026-01-01') + pd.Timedelta(seconds=index),
                duration=250, label=label, step_number=-1 if label == 'normal' else index,
                src_ip='10.0.0.2', dst_ip='10.0.0.17', src_port=40000 + index,
                dst_port=1883, protocol=6, anomaly_score=float(label != 'normal'),
                **{attack.identifier: float(label == attack.identifier) for attack in ATK_TYPES},
            )
            for index, label in enumerate(['normal', *(attack.identifier for attack in ATK_TYPES)])
        ]
        pd.DataFrame(rows).to_csv(dataset, index=False)

        policy_path = Path(self.log_path('capture_policy.json'))
        policy_path.write_text(json.dumps({
            'times': 3,
            'seed': 11,
            'quiet': True,
            'anomaly_threshold': 0.7,
            'suspect_threshold': 0.3,
            'type_threshold': 0.15,
            'max_idle_gap': 2.0,
            'edge_recovery_threshold': 0.75,
            'normal_divisor': 2,
        }), encoding='utf-8')
        log = Path(self.log_path('capture_out/results.txt'))
        capture.main(['-f', str(dataset), '--policy-config', str(policy_path), '-t', '2', '-l', str(log)])
        summary = pd.read_csv(reporting.default_summary_csv_path(log))
        self.assertEqual(int(summary.loc[0, 'times']), 2)
        self.assertEqual(int(summary.loc[0, 'seed']), 11)
        self.assertAlmostEqual(float(summary.loc[0, 'anomaly_threshold']), 0.7)
        self.assertAlmostEqual(float(summary.loc[0, 'suspect_threshold']), 0.3)
        self.assertAlmostEqual(float(summary.loc[0, 'type_threshold']), 0.15)
        self.assertAlmostEqual(float(summary.loc[0, 'max_idle_gap']), 2.0)
        self.assertAlmostEqual(float(summary.loc[0, 'edge_recovery_threshold']), 0.75)
