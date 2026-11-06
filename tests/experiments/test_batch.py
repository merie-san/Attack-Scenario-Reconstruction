"""Batch dispatch uses the active interpreter without shell commands."""
import contextlib
import io
import runpy
import subprocess
import sys
from unittest.mock import patch
from tests.support import ProjectTestCase, REPO_ROOT


class TestBatchRunner(ProjectTestCase):
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
