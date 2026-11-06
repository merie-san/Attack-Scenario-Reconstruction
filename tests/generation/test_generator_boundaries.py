"""Ground-truth durations, source ordering, and host enabling remain coherent."""

from datetime import timedelta
from unittest.mock import patch

import pandas as pd

from tests.support import ProjectTestCase, SOURCE, TARGET


class TestGeneratorBoundaries(ProjectTestCase):
    def test_step_end_includes_a_long_earlier_flow(self):
        frame = self.make_scenario_frame()
        frame.loc[frame['label'] == 'discover', 'duration'] = [5000, 100]
        generator = self.make_generator(frame)
        generator.generate_scenario()
        steps, alerts = generator.export_results([self.discover])
        self.assertGreater(alerts[0].end_time, alerts[-1].end_time)
        self.assertEqual(steps[0].end_time, alerts[0].end_time)
        self.assertEqual(steps[0].end_time - steps[0].start_time, timedelta(seconds=5))

    def test_single_flow_step_keeps_its_duration(self):
        generator = self.make_generator(self.make_scenario_frame(count=1, duration_ms=250))
        generator.generate_scenario()
        steps, alerts = generator.export_results([self.discover])
        self.assertEqual(steps[0].start_time, alerts[0].start_time)
        self.assertEqual(steps[0].end_time, alerts[0].end_time)
        self.assertEqual(steps[0].end_time - steps[0].start_time, timedelta(milliseconds=250))

    def test_unsorted_template_has_chronological_boundaries_and_interflow_statistics(self):
        frame = self.make_scenario_frame(count=3)
        generator = self.make_generator(frame.iloc[[2, 0, 3, 1]])
        generator.generate_scenario()
        steps, alerts = generator.export_results([self.discover])
        self.assertEqual(steps[0].start_time, min(alert.start_time for alert in alerts))
        self.assertEqual(steps[0].end_time, max(alert.end_time for alert in alerts))
        self.assertEqual(steps[0].mean_interflow_time, 750)
        self.assertEqual(steps[0].std_interflow_time, 0)

    def test_repeated_enabling_does_not_duplicate_possible_sources(self):
        frame = self.make_scenario_frame()
        finish = frame.iloc[[0]].assign(label='finish', step_number=1)
        generator = self.make_generator(
            pd.concat([frame, finish], ignore_index=True),
            next_attack_dict={'start': ['discover'], 'discover': ['discover', 'finish'], 'finish': ['end']},
            enable_src_for={'discover': ['finish']},
            possible_srcs={'discover': [SOURCE], 'finish': []},
            possible_dsts={'discover': [TARGET], 'finish': [SOURCE]}, final_atk='finish',
        )
        transitions = 0

        def choose(values):
            nonlocal transitions
            values = list(values)
            if values == ['discover', 'finish']:
                transitions += 1
                return 'discover' if transitions == 1 else 'finish'
            if values and isinstance(values[0], str) and values[0].startswith('10.'):
                self.assertEqual(len(values), len(set(values)))
            return values[0]

        with patch('scenario_generator.search.random.choice', side_effect=choose):
            generator.generate_scenario()
        self.assertEqual(generator.attack_ips[-1], (TARGET, SOURCE))
        self.assertEqual(generator.possible_srcs['finish'], [])

    def test_invalid_sampling_divisor_is_rejected_before_generation(self):
        generator = self.make_generator()
        for divisor, error in ((0, ValueError), (-1, ValueError), (1.5, TypeError)):
            with self.subTest(divisor=divisor):
                with self.assertRaises(error):
                    generator.generate_scenario(divisor)
