"""Notebook wrappers use the tested helpers without running data or model cells."""
import ast
import contextlib
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd

from preprocessing.augmentation import EXCLUDED_FEATURE_KEYWORDS, augment_normal_flows
from preprocessing.time import absolute_flow_time
from tests.support import ProjectTestCase, REPO_ROOT, notebook_cells, notebook_function


class TestNotebookHelpers(ProjectTestCase):
    def test_reconstruction_notebook_exports_lr_alongside_other_mappers(self):
        filename = 'reconstruction_dataset_creation.ipynb'
        cells = notebook_cells(filename)
        model = Mock()
        model.predict_proba.return_value = np.array([[0.8, 0.2], [0.1, 0.9]])
        features = np.array([[1], [2]])
        namespace = {'logistic_regression_dict': {'probe': model}, 'X_test_dict': {'probe': features}}
        lr_cells = [source for source in cells if 'lr_attack_type_prob' in source and 'df_rec_dict' not in source]
        self.assertEqual(len(lr_cells), 3)
        with contextlib.redirect_stdout(io.StringIO()):
            for source in lr_cells:
                exec(compile(source, filename, 'exec'), namespace)
        model.predict_proba.assert_called_once()
        self.assertIs(model.predict_proba.call_args.args[0], features)
        np.testing.assert_array_equal(namespace['lr_attack_type_prob']['probe'], [0.2, 0.9])
        namespace.update(
            pd=pd, df_rec=pd.DataFrame({'index': [10, 20], 'timestamp': [2, 1]}), ind_test=[10, 20],
            anomaly_score_dict={'detector': [0.3, 0.8]}, xgb_attack_type_prob={'probe': [0.1, 0.7]},
            gnb_attack_type_prob={'probe': [0.4, 0.6]}, perfect_type_prob={'probe': [0, 1]},
        )
        merge_cell = next(source for source in cells if 'lr_df_rec' in source)
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(merge_cell, filename, 'exec'), namespace)
        outputs = namespace['df_rec_dict']
        self.assertEqual(set(outputs), {'detector_xgb', 'detector_gnb', 'detector_lr', 'detector_perfect'})
        self.assertEqual(outputs['detector_lr']['probe'].tolist(), [0.2, 0.9])
        self.assertEqual(outputs['detector_lr']['anomaly_score'].tolist(), [0.3, 0.8])
        save_cell = next(source for source in cells if 'for name, df in df_rec_dict.items()' in source)
        with patch('os.makedirs') as mkdir, patch.object(pd.DataFrame, 'to_csv') as save:
            exec(compile(save_cell, filename, 'exec'), namespace)
        mkdir.assert_called_once_with('data/final datasets', exist_ok=True)
        self.assertEqual({call.args[0] for call in save.call_args_list},
                         {f'data/final datasets/{name}_rec_dataset.csv' for name in outputs})

        notebook = json.loads((REPO_ROOT / 'jupyter notebook' / filename).read_text(encoding='utf-8'))
        self.assertEqual((notebook['nbformat'], notebook['nbformat_minor']), (4, 5))
        ids = [cell['id'] for cell in notebook['cells']]
        self.assertTrue(all(isinstance(cell_id, str) and cell_id for cell_id in ids))
        self.assertEqual(len(ids), len(set(ids)))
        for cell in notebook['cells']:
            if cell['cell_type'] == 'code':
                self.assertEqual(cell['outputs'], [])
                self.assertIsNone(cell['execution_count'])

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
