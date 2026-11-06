"""Training schema, validation isolation, and strict threshold calibration."""
import contextlib
import io
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve
from preprocessing.training import (align_test_schema, apply_label_encoding,
                                    calibrate_threshold, encode_binary_labels,
                                    filter_known_test_classes, split_training_validation)
from tests.support import ProjectTestCase, notebook_cells, notebook_function

class TestTrainingPreparation(ProjectTestCase):
    def threshold_function(self, namespace):
        namespace['calibrate_threshold'] = calibrate_threshold
        return notebook_function('reconstruction_dataset_creation.ipynb', 'compute_thresh', namespace)

    def training_function(self, name):
        return {'align_test_schema': align_test_schema,
                'filter_known_test_classes': filter_known_test_classes}[name]

    def test_B26_test_label_absence_does_not_remove_training_classes(self):
        train = pd.DataFrame({'label': ['discover', 'finish'], 'feature': [1, 2]})
        self.training_function('filter_known_test_classes')(train, train.iloc[[0]].copy())
        self.assertEqual(set(train['label']), {'discover', 'finish'},
                         'BUG-26: final test-label membership must not determine the training class list')

    def test_B26_test_schema_does_not_select_training_features(self):
        train = pd.DataFrame({'label': ['discover', 'finish'], 'feature': [1, 2]})
        original = train.copy(deep=True)
        with self.assertRaisesRegex(ValueError, 'feature'):
            self.training_function('align_test_schema')(train, train[['label']].copy())
        pd.testing.assert_frame_equal(train, original)

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

    def test_test_features_follow_training_order_and_preserve_metadata(self):
        train = pd.DataFrame({'label': ['discover'], 'feature': [1]})
        test = pd.DataFrame({'extra': [99], 'feature': [2], 'label': ['discover'], 'index': [7]})
        aligned = self.training_function('align_test_schema')(train, test)
        self.assertEqual(aligned.columns.tolist(), ['label', 'feature', 'index'])
        self.assertEqual(aligned['index'].tolist(), [7])
        self.assertEqual(test.columns.tolist(), ['extra', 'feature', 'label', 'index'])

    def test_validation_is_disjoint_and_scaler_fits_training_partition_only(self):
        namespace = {'np': np, 'pd': pd, 'attack_labels': ['discover'],
                     'df_train': pd.DataFrame({'label': ['normal'] * 12 + ['discover'] * 12,
                                               'feature': np.arange(24, dtype=float)}),
                     'df_test': pd.DataFrame({'label': ['normal', 'discover'],
                                              'feature': [10000.0, 20000.0], 'index': [100, 101]})}
        namespace.update(label_encode=encode_binary_labels,
                         label_encode_categories=apply_label_encoding,
                         split_training_validation=split_training_validation)
        cells = notebook_cells('reconstruction_dataset_creation.ipynb')
        with contextlib.redirect_stdout(io.StringIO()):
            for marker in ('df_fit, df_validation = split_training_validation(', 'y_validation, X_validation =',
                           'X_validation = scaler.transform('):
                source = next(source for source in cells if marker in source)
                exec(compile(source, '<real training/validation setup>', 'exec'), namespace)
        fit, validation = namespace['df_fit'], namespace['df_validation']
        self.assertTrue(set(fit.index).isdisjoint(validation.index))
        self.assertEqual(set(fit.index) | set(validation.index), set(range(24)))
        self.assertEqual(namespace['scaler'].mean_[0], fit['feature'].mean())
        self.assertEqual(len(namespace['X_validation']), len(validation))

    def test_threshold_matches_strict_greater_boundary_with_tied_scores(self):
        validation = object()
        scores = np.array([0.2, 0.8, 0.8, 0.1])
        labels = np.array([0, 1, 1, 0])
        case = self

        class Predictor:
            def predict_proba(self, data):
                case.assertIs(data, validation)
                return np.column_stack([1 - scores, scores])

        compute = self.threshold_function({'np': np, 'X_validation': validation, 'y_validation': labels})
        for recall in (0.0, 0.5, 1.0):
            with self.subTest(recall=recall), contextlib.redirect_stdout(io.StringIO()):
                threshold = compute(Predictor(), recall)
                predictions = scores > threshold
                if recall == 0:
                    self.assertFalse(predictions.any())
                else:
                    self.assertGreaterEqual(predictions[labels == 1].mean(), recall)
                    self.assertEqual(threshold, np.nextafter(0.8, -np.inf))
