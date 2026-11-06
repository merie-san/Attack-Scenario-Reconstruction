"""Notebook wrappers use the tested helpers without running data or model cells."""
import ast
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from preprocessing.augmentation import EXCLUDED_FEATURE_KEYWORDS, augment_normal_flows
from preprocessing.time import absolute_flow_time
from tests.support import ProjectTestCase, REPO_ROOT, notebook_cells, notebook_function


class TestNotebookHelpers(ProjectTestCase):
    def test_augmentation_wrapper_delegates_to_shared_implementation(self):
        namespace = {'augment_normal_flows': augment_normal_flows,
                     'keywords_excluded': EXCLUDED_FEATURE_KEYWORDS}
        wrapper = notebook_function('attack_normal_merging.ipynb', 'generate_dataframe', namespace)
        frame = pd.DataFrame({'bidirectional_first_seen_ms': [100, 200],
                              'bidirectional_last_seen_ms': [110, 210]})
        state = np.random.get_state()
        expected = augment_normal_flows(frame, 5000, 2)
        np.random.set_state(state)
        pd.testing.assert_frame_equal(wrapper(frame, 5000, 2), expected)

    def test_absolute_time_notebook_aliases_use_shared_utc_conversion(self):
        for filename in ('process_attack_train.ipynb', 'process_attack_test.ipynb',
                         'attack_normal_merging.ipynb'):
            with self.subTest(filename=filename):
                imports = []
                for source in notebook_cells(filename):
                    for node in ast.parse(source).body:
                        if isinstance(node, ast.ImportFrom) and node.module == 'preprocessing.time':
                            imports.append(node)
                        elif (isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
                              and node.value.id == 'absolute_flow_time'):
                            imports.append(node)
                namespace = {}
                exec(compile(ast.Module(body=imports, type_ignores=[]), '<time helper imports>', 'exec'), namespace)
                self.assertIs(namespace['convert_to_absolute_time'], absolute_flow_time)
        start = datetime(2026, 1, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        self.assertEqual(absolute_flow_time(250, start),
                         datetime(2025, 12, 31, 23, 0, 0, 250000, tzinfo=timezone.utc))
        self.assertEqual(absolute_flow_time(250, start.replace(tzinfo=None)).utcoffset(), timedelta(0))

    def test_all_notebook_code_cells_parse(self):
        for path in (REPO_ROOT / 'jupyter notebook').glob('*.ipynb'):
            for index, source in enumerate(notebook_cells(path.name)):
                with self.subTest(notebook=path.name, code_cell=index):
                    ast.parse(source, filename=f'{path.name}:code_cell_{index}')
