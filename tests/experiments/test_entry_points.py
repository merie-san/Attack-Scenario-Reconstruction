"""Dataset definitions and command entry points are safe to reuse as libraries."""
import contextlib
import io
import runpy
from unittest.mock import patch

from experiments import batch, capture
from scenario_configs.capture import DollarCharHostAttributes, create_hosts
from tests.support import ProjectTestCase, REPO_ROOT


class TestExperimentEntryPoints(ProjectTestCase):
    def test_importing_runners_does_not_read_data_or_launch_processes(self):
        with patch('pandas.read_csv') as read_csv, patch('subprocess.run') as run:
            for filename in ('experiments/capture.py', 'experiments/batch.py',
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
            with self.assertRaises(SystemExit) as result:
                capture.main(['--help'])
        self.assertEqual(result.exception.code, 0)
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
