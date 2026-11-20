"""Tests for dataset directory discovery and labeled flow summary helpers."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

import pandas as pd

from preprocessing.datasets import get_subdirs, summarize_labeled_flows
from tests.support import ProjectTestCase


class TestDatasetsHelpers(ProjectTestCase):
    def test_get_subdirs_returns_sorted_directories_excluding_checkpoints_and_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / 'zeta').mkdir()
            (root / 'alpha').mkdir()
            (root / '.ipynb_checkpoints').mkdir()
            (root / 'notes.csv').write_text('x', encoding='utf-8')

            self.assertEqual(
                get_subdirs(root),
                [root / 'alpha', root / 'zeta'],
            )

    def test_summarize_labeled_flows_sorts_and_computes_step_and_label_metrics(self):
        t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        frame = pd.DataFrame({
            'step_number': [1, 1, 2],
            'label': ['scan', 'scan', 'exploit'],
            'phase_name': ['DISCOVERY', 'DISCOVERY', 'EXPLOIT'],
            'phase_number': [0, 0, 1],
            'timestamp': [t0 + timedelta(seconds=2), t0, t0 + timedelta(seconds=5)],
        })

        sorted_df, step_summary, label_summary = summarize_labeled_flows(frame)

        self.assertTrue(sorted_df['timestamp'].is_monotonic_increasing)
        self.assertEqual(step_summary['num_flws'].tolist(), [2, 1])
        self.assertAlmostEqual(step_summary.loc[0, 'fps'], 1.0)
        self.assertTrue(pd.isna(step_summary.loc[1, 'fps']))

        by_label = label_summary.set_index('label')
        self.assertEqual(by_label.loc['scan', 'total_steps'], 1)
        self.assertEqual(by_label.loc['scan', 'total_flws'], 2)
        self.assertAlmostEqual(by_label.loc['scan', 'avg_fps'], 1.0)
        self.assertEqual(by_label.loc['exploit', 'total_flws'], 1)
        self.assertTrue(pd.isna(by_label.loc['exploit', 'avg_fps']))
