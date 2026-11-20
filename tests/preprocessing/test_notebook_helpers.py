"""Notebook wrappers use the tested helpers without running data or model cells."""
import ast
import contextlib
import io
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import numpy as np
import pandas as pd

from preprocessing.time import absolute_flow_time
from tests.support import ProjectTestCase, REPO_ROOT, notebook_cells


class TestNotebookHelpers(ProjectTestCase):
    def test_reconstruction_notebook_exports_lr_alongside_other_mappers(self):
        filename = 'reconstruction_dataset_creation.ipynb'
        cells = notebook_cells(filename)
        model = Mock()
        model.predict_proba.return_value = np.array([[0.8, 0.2], [0.1, 0.9], [0.4, 0.6]])
        features = np.array([[1], [2], [3]])
        namespace = {'logistic_regression_dict': {'probe': model}, 'X_test_dict': {'probe': features}}
        lr_cells = [source for source in cells if 'lr_attack_type_prob' in source and 'df_rec_dict' not in source]
        self.assertEqual(len(lr_cells), 3)
        with contextlib.redirect_stdout(io.StringIO()):
            for source in lr_cells:
                exec(compile(source, filename, 'exec'), namespace)
        model.predict_proba.assert_called_once()
        self.assertIs(model.predict_proba.call_args.args[0], features)
        np.testing.assert_array_equal(namespace['lr_attack_type_prob']['probe'], [0.2, 0.9, 0.6])
        namespace.update(
            pd=pd, np=np,
            df_rec=pd.DataFrame({
                'index': [10, 20, 30],
                'timestamp': [3, 2, 1],
                'campaign_id': [-1, 0, 1],
                'label': ['normal', 'probe', 'probe'],
            }),
            ind_test=np.array([10, 20, 30]),
            anomaly_score_dict={'detector': np.array([0.3, 0.8, 0.5])},
            xgb_attack_type_prob={'probe': np.array([0.1, 0.7, 0.2])},
            gnb_attack_type_prob={'probe': np.array([0.4, 0.6, 0.5])},
            perfect_type_prob={'probe': np.array([0, 1, 1])},
        )
        merge_cell = next(source for source in cells if 'mapper_probs' in source and 'df_rec_dict' in source)
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(merge_cell, filename, 'exec'), namespace)
        outputs = namespace['df_rec_dict']
        self.assertEqual(set(outputs), {'detector_xgb', 'detector_gnb', 'detector_lr', 'detector_perfect'})
        self.assertEqual(outputs['detector_lr']['probe'].tolist(), [0.2, 0.9, 0.6])
        self.assertEqual(outputs['detector_lr']['anomaly_score'].tolist(), [0.3, 0.8, 0.5])

        save_cell = next(source for source in cells if 'EXPORT_POOLED_COPY' in source and 'FINAL_DATA_ROOT' in source)
        campaign_ids = {'dollar_char': 0, 'empty_conn': 1}
        with tempfile.TemporaryDirectory() as tmpdir:
            final_root = Path(tmpdir)
            namespace['FINAL_DATA_ROOT'] = final_root
            namespace['campaign_ids'] = campaign_ids
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(save_cell, filename, 'exec'), namespace)

            for campaign_name in (*campaign_ids, 'all_campaigns'):
                for name in outputs:
                    self.assertTrue((final_root / campaign_name / f'{name}_rec_dataset.csv').is_file())

            dollar_df = pd.read_csv(final_root / 'dollar_char' / 'detector_lr_rec_dataset.csv')
            empty_df = pd.read_csv(final_root / 'empty_conn' / 'detector_lr_rec_dataset.csv')
            pooled_df = pd.read_csv(final_root / 'all_campaigns' / 'detector_lr_rec_dataset.csv')
            self.assertEqual(dollar_df['index'].tolist(), [20, 10])
            self.assertEqual(set(dollar_df['campaign_id']), {-1, 0})
            self.assertEqual(empty_df['index'].tolist(), [30, 10])
            self.assertEqual(set(empty_df['campaign_id']), {-1, 1})
            self.assertEqual(pooled_df['index'].tolist(), [30, 20, 10])

        notebook = json.loads((REPO_ROOT / 'jupyter notebook' / filename).read_text(encoding='utf-8'))
        self.assertEqual((notebook['nbformat'], notebook['nbformat_minor']), (4, 5))
        ids = [cell['id'] for cell in notebook['cells']]
        self.assertTrue(all(isinstance(cell_id, str) and cell_id for cell_id in ids))
        self.assertEqual(len(ids), len(set(ids)))

    def test_reconstruction_notebook_subdivides_steps_per_campaign(self):
        cells = notebook_cells('reconstruction_dataset_creation.ipynb')
        subdivision_cell = next(source for source in cells if '.ngroup()' in source and 'step_number' in source)
        df_rec = pd.DataFrame({
            'campaign_id': [-1, 0, 1],
            'step_number': [-1, 0, 0],
            'src_ip': ['10.0.0.5', '10.0.0.2', '10.0.0.2'],
            'dst_ip': ['10.0.0.1', '10.0.0.1', '10.0.0.1'],
        })
        namespace = {'df_rec': df_rec}
        exec(compile(subdivision_cell, 'reconstruction_dataset_creation.ipynb', 'exec'), namespace)
        updated = namespace['df_rec']
        self.assertEqual(updated.loc[0, 'step_number'], -1)
        self.assertNotEqual(updated.loc[1, 'step_number'], updated.loc[2, 'step_number'])

    def test_augmentation_calls_shared_implementation_directly(self):
        cells = notebook_cells('attack_normal_merging.ipynb')
        imports = [source for source in cells if 'from preprocessing.augmentation import augment_normal_flows' in source]
        self.assertTrue(imports)
        call_cells = [source for source in cells if 'augment_normal_flows(' in source]
        self.assertEqual(len(call_cells), 2)
        self.assertFalse(any('def generate_dataframe' in source for source in cells))

    def test_notebooks_define_no_local_helper_functions(self):
        for path in sorted((REPO_ROOT / 'jupyter notebook').glob('*.ipynb')):
            for index, source in enumerate(notebook_cells(path.name)):
                with self.subTest(notebook=path.name, code_cell=index):
                    tree = ast.parse(source, filename=f'{path.name}:code_cell_{index}')
                    defs = [
                        node.name for node in ast.walk(tree)
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ]
                    self.assertEqual(defs, [])

    def test_notebooks_import_shared_preprocessing_helpers(self):
        expected = {
            'convert_to_csv.ipynb': {
                ('preprocessing.datasets', 'get_subdirs'),
            },
            'process_attack_campaigns.ipynb': {
                ('preprocessing.time', 'shift_capture_time'),
                ('preprocessing.time', 'absolute_flow_time'),
                ('preprocessing.datasets', 'summarize_labeled_flows'),
            },
            'attack_normal_merging.ipynb': {
                ('preprocessing.network', 'build_mac_to_ipv4'),
                ('preprocessing.network', 'resolve_ipv6_with_mac'),
                ('preprocessing.network', 'filter_ipv4_flows'),
                ('preprocessing.augmentation', 'EXCLUDED_FEATURE_KEYWORDS'),
                ('preprocessing.augmentation', 'augment_normal_flows'),
                ('preprocessing.time', 'absolute_flow_time'),
                ('preprocessing.time', 'load_start_time'),
            },
            'reconstruction_dataset_creation.ipynb': {
                ('preprocessing.training', 'align_test_schema'),
                ('preprocessing.training', 'filter_known_test_classes'),
                ('preprocessing.training', 'encode_binary_labels'),
                ('preprocessing.training', 'apply_label_encoding'),
                ('preprocessing.training', 'split_training_validation'),
                ('preprocessing.training', 'report_calibrated_threshold'),
                ('preprocessing.evaluation', 'evaluate_classifier'),
                ('preprocessing.evaluation', 'plot_roc_curve'),
                ('preprocessing.evaluation', 'plot_prc_curve'),
                ('preprocessing.evaluation', 'evaluate_mappers'),
                ('preprocessing.evaluation', 'plot_mapper_roc_curves'),
                ('preprocessing.evaluation', 'plot_mapper_prc_curves'),
            },
        }
        for filename, required_imports in expected.items():
            with self.subTest(filename=filename):
                found = set()
                for source in notebook_cells(filename):
                    for node in ast.walk(ast.parse(source)):
                        if isinstance(node, ast.ImportFrom) and node.module:
                            for alias in node.names:
                                found.add((node.module, alias.name))
                self.assertTrue(required_imports <= found, f'Missing in {filename}: {required_imports - found}')

    def test_absolute_time_notebook_aliases_use_shared_utc_conversion(self):
        for filename in ('process_attack_campaigns.ipynb', 'attack_normal_merging.ipynb'):
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
