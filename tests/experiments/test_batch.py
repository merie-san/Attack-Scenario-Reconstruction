"""Batch dispatch uses the active interpreter without shell commands."""
import contextlib
import io
from pathlib import Path
import runpy
import subprocess
import sys
from unittest.mock import patch

import pandas as pd

from experiments import batch, reporting
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
