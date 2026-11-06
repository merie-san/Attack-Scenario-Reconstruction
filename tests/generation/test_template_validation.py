"""Invalid templates are rejected without changing caller-owned data."""

from datetime import timedelta
from unittest.mock import patch

import numpy as np
import pandas as pd

from scenario_generator import ScenarioGenerationError
from tests.support import ProjectTestCase


class TestTemplateValidation(ProjectTestCase):
    def test_construction_and_generation_leave_original_timestamp_column_unchanged(self):
        frame = self.make_scenario_frame()
        frame['timestamp'] = frame['timestamp'].astype(str)
        frame['duration'] = frame['duration'].astype(str)
        original = frame.copy(deep=True)
        generator = self.make_generator(frame)
        generator.generate_scenario()
        pd.testing.assert_frame_equal(frame, original)
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(generator.result['timestamp']))
        self.assertTrue(pd.api.types.is_numeric_dtype(generator.result['duration']))

    def test_later_caller_edits_do_not_change_stored_templates(self):
        frame = self.make_scenario_frame()
        generator = self.make_generator(frame)
        expected = frame.loc[frame['label'] == 'discover', 'timestamp'].min()
        frame['timestamp'] += timedelta(days=1)
        self.assertEqual(generator.data_source['discover'][0]['timestamp'].min(), expected)

    def test_required_columns_and_nonempty_input(self):
        frame = self.make_scenario_frame()
        for column in ('timestamp', 'duration', 'label', 'step_number'):
            with self.subTest(column=column):
                with self.assertRaisesRegex(ScenarioGenerationError, column):
                    self.make_generator(frame.drop(columns=column))
        with self.assertRaisesRegex(ScenarioGenerationError, 'nonempty'):
            self.make_generator(frame.iloc[:0])

    def test_invalid_or_missing_timestamps_are_rejected(self):
        for value in (None, 'not-a-timestamp'):
            with self.subTest(value=value):
                frame = self.make_scenario_frame()
                frame['timestamp'] = frame['timestamp'].astype(str)
                frame.loc[frame.index[-1], 'timestamp'] = value
                with self.assertRaisesRegex(ScenarioGenerationError, 'timestamps'):
                    self.make_generator(frame)

    def test_duplicate_column_names_are_rejected(self):
        frame = self.make_scenario_frame()
        duplicate = pd.concat([frame, frame[['timestamp']]], axis=1)
        with self.assertRaisesRegex(ScenarioGenerationError, 'unique column names'):
            self.make_generator(duplicate)

    def test_invalid_durations_are_rejected_without_changing_input(self):
        for value in (-1, np.nan, np.inf, -np.inf, 'invalid', 1 + 2j, 1e30):
            with self.subTest(value=value):
                frame = self.make_scenario_frame()
                frame['timestamp'] = frame['timestamp'].astype(str)
                frame['duration'] = frame['duration'].astype(object)
                frame.loc[0, 'duration'] = value
                original = frame.copy(deep=True)
                with self.assertRaisesRegex(ScenarioGenerationError, 'durations|end times'):
                    self.make_generator(frame)
                pd.testing.assert_frame_equal(frame, original)

    def test_missing_group_identifiers_are_rejected(self):
        for column in ('label', 'step_number'):
            with self.subTest(column=column):
                frame = self.make_scenario_frame()
                frame.loc[0, column] = None
                with self.assertRaisesRegex(ScenarioGenerationError, 'labels and step numbers'):
                    self.make_generator(frame)

    def test_zero_duration_is_valid(self):
        generator = self.make_generator(self.make_scenario_frame(count=1, duration_ms=0))
        generator.generate_scenario()
        steps, alerts = generator.export_results([self.discover])
        self.assertEqual(steps[0].start_time, steps[0].end_time)
        self.assertEqual(alerts[0].start_time, alerts[0].end_time)

    def test_interstep_gap_uses_absolute_draw(self):
        for draw, expected in ((-3.0, 3), (3.0, 3), (0.0, 0)):
            with self.subTest(draw=draw):
                frame = self.make_scenario_frame(count=1)
                second = frame.loc[frame['label'] == 'discover'].assign(label='finish', step_number=1)
                generator = self.make_generator(
                    pd.concat([frame, second], ignore_index=True),
                    next_attack_dict={'start': ['discover'], 'discover': ['finish'], 'finish': ['end']},
                    possible_srcs={'discover': ['10.0.0.1'], 'finish': ['10.0.0.1']},
                    possible_dsts={'discover': ['10.0.0.2'], 'finish': ['10.0.0.2']},
                    final_atk='finish',
                )
                with patch('scenario_generator.rendering.np.random.normal', return_value=draw):
                    generator.generate_scenario()
                starts = [start for start, _ in generator.attack_times]
                self.assertEqual(starts[1] - starts[0], timedelta(seconds=expected))
