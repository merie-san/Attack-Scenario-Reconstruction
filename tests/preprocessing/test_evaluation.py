"""Tests for classifier and attack-type mapper evaluation and plotting helpers."""
import contextlib
import io
from pathlib import Path
import tempfile

import matplotlib
matplotlib.use('Agg')
import numpy as np

from preprocessing.evaluation import (
    evaluate_classifier,
    evaluate_mappers,
    plot_mapper_prc_curves,
    plot_mapper_roc_curves,
    plot_prc_curve,
    plot_roc_curve,
)
from tests.support import ProjectTestCase


class _StubBinaryModel:
    def __init__(self, probs, preds):
        self._probs = np.asarray(probs, dtype=float)
        self._preds = np.asarray(preds, dtype=int)

    def predict(self, _x):
        return self._preds

    def predict_proba(self, _x):
        return np.column_stack([1.0 - self._probs, self._probs])


class TestEvaluationHelpers(ProjectTestCase):
    def test_evaluate_classifier_and_curve_plotting_write_png_and_handle_single_class(self):
        model = _StubBinaryModel([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1])
        x_test = np.zeros((4, 2))
        y_test = np.array([0, 0, 1, 1])

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            metrics = evaluate_classifier(model, x_test, y_test, 'Detector')
        self.assertEqual(metrics, {'accuracy': 1.0, 'recall': 1.0, 'precision': 1.0})
        self.assertIn('Detector test accuracy: 1.000', stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            plots_dir = Path(tmpdir)
            roc_probs = plot_roc_curve(model, x_test, y_test, 'Detector', plots_dir=plots_dir, show=False)
            prc_probs = plot_prc_curve(model, x_test, y_test, 'Detector', plots_dir=plots_dir, show=False)
            np.testing.assert_array_equal(roc_probs, [0.1, 0.2, 0.8, 0.9])
            np.testing.assert_array_equal(prc_probs, [0.1, 0.2, 0.8, 0.9])
            self.assertTrue((plots_dir / 'roc_Detector.png').is_file())
            self.assertTrue((plots_dir / 'prc_Detector.png').is_file())

            skip_out = io.StringIO()
            with contextlib.redirect_stdout(skip_out):
                plot_roc_curve(model, x_test, np.zeros(4, dtype=int), 'SingleClass', plots_dir=plots_dir, show=False)
                plot_prc_curve(model, x_test, np.zeros(4, dtype=int), 'SingleClass', plots_dir=plots_dir, show=False)
            self.assertIn('Skipping ROC for SingleClass', skip_out.getvalue())
            self.assertIn('Skipping PRC for SingleClass', skip_out.getvalue())
            self.assertFalse((plots_dir / 'roc_SingleClass.png').exists())

    def test_mapper_evaluation_and_plots_guard_single_class_and_save_grids(self):
        mappers = {
            'scan': _StubBinaryModel([0.1, 0.8, 0.2, 0.9], [0, 1, 0, 1]),
            'absent': _StubBinaryModel([0.1, 0.2, 0.1, 0.2], [0, 0, 0, 0]),
        }
        x_dict = {'scan': np.zeros((4, 2)), 'absent': np.zeros((4, 2))}
        y_dict = {'scan': np.array([0, 1, 0, 1]), 'absent': np.zeros(4, dtype=int)}

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            results = evaluate_mappers(mappers, x_dict, y_dict, 'XGB')
        self.assertEqual(results['scan'], {'accuracy': 1.0, 'recall': 1.0, 'precision': 1.0})
        self.assertEqual(results['absent'], {'accuracy': 1.0, 'recall': None, 'precision': None})
        self.assertIn('fewer than 2 unique labels in test set', stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            plots_dir = Path(tmpdir)
            plot_out = io.StringIO()
            with contextlib.redirect_stdout(plot_out):
                roc_probs = plot_mapper_roc_curves(mappers, x_dict, y_dict, 'XGB', plots_dir=plots_dir, show=False)
                prc_probs = plot_mapper_prc_curves(mappers, x_dict, y_dict, 'XGB', plots_dir=plots_dir, show=False)
            self.assertEqual(set(roc_probs), {'scan', 'absent'})
            self.assertEqual(set(prc_probs), {'scan', 'absent'})
            self.assertTrue((plots_dir / 'roc_XGB_mapper.png').is_file())
            self.assertTrue((plots_dir / 'prc_XGB_mapper.png').is_file())
            self.assertIn('Skipping ROC for XGB / absent', plot_out.getvalue())
            self.assertIn('Skipping PRC for XGB / absent', plot_out.getvalue())
