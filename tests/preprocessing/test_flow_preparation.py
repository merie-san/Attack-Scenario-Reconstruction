"""Normal-flow augmentation, endpoint filtering, and notebook wiring."""
import ast
from datetime import datetime
import numpy as np
import pandas as pd
from preprocessing.augmentation import augment_normal_flows
from preprocessing.network import filter_ipv4_flows, is_ipv4
from preprocessing.time import shift_capture_time
from tests.support import ProjectTestCase, SOURCE, TARGET, notebook_cells

class TestFlowPreparation(ProjectTestCase):
    def augmentation(self):
        return augment_normal_flows

    def normal_frame(self):
        return pd.DataFrame({
            'bidirectional_first_seen_ms': np.arange(130) * 10 + 1000,
            'bidirectional_last_seen_ms': np.arange(130) * 10 + 1005,
            'src2dst_bytes': list(range(129)) + [100000],
            'application': ['ssh', 'mqtt'] * 65,
            'application_category': ['remote', 'iot'] * 65,
        })

    def test_B22_gaussian_augmentation_preserves_nonnegative_counters(self):
        generated = self.augmentation()(self.normal_frame(), 5000, 500)
        self.assertTrue(generated['src2dst_bytes'].ge(0).all(),
                        'BUG-22: Gaussian perturbation produces physically invalid negative byte counts')

    def test_B22_directional_byte_totals_stay_consistent(self):
        frame = self.normal_frame()
        frame['bidirectional_bytes'] = frame['src2dst_bytes']
        frame['dst2src_bytes'] = 0
        generated = self.augmentation()(frame, 5000, 500)
        self.assertTrue(generated['bidirectional_bytes'].eq(
            generated['src2dst_bytes'] + generated['dst2src_bytes']).all(),
            'BUG-22: independently perturbed counters must retain the byte-total identity')

    def test_B23_filtered_indexes_do_not_create_missing_categories(self):
        frame = self.normal_frame()
        frame.index = np.arange(500, 630)
        generated = self.augmentation()(frame, 5000, 500)
        self.assertFalse(generated['application'].isna().any(),
                         'BUG-23: categorical assignment must align with filtered row indexes')

    def test_B23_augmentation_preserves_joint_categorical_relationships(self):
        generated = self.augmentation()(self.normal_frame(), 5000, 500)
        valid_pairs = {('ssh', 'remote'), ('mqtt', 'iot')}
        self.assertTrue(set(zip(generated['application'], generated['application_category'])) <= valid_pairs,
                        'BUG-23: independent column sampling invents incompatible categorical tuples')

    def test_B24_ipv4_filter_rejects_ipv6_source(self):
        frame = pd.DataFrame({'src_ip': [SOURCE, 'fe80::1', SOURCE],
                              'dst_ip': [TARGET, TARGET, 'fe80::2']})
        namespace = {'attack_test': frame.copy(), 'attack_train': frame.copy(),
                     'filter_ipv4_flows': filter_ipv4_flows}
        for source in notebook_cells('attack_normal_merging.ipynb'):
            for node in ast.parse(source).body:
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and any(isinstance(target, ast.Name) and target.id == 'attack_test' for target in node.targets)
                        and 'filter_ipv4_flows' in ast.unparse(node.value)):
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<real IPv4 filter>', 'exec'), namespace)
                    self.assertEqual(namespace['attack_test'].index.tolist(), [0],
                                     'BUG-24: a regex dot matches an unresolved IPv6 source')
                    return
        self.fail('Notebook must apply its IPv4 helper to both flow endpoints')

    def test_B25_compression_is_invariant_to_timestamp_origin(self):
        frame = self.normal_frame()
        shifted = frame.copy()
        cols = ['bidirectional_first_seen_ms', 'bidirectional_last_seen_ms']
        shifted[cols] += 1_000_000
        generate = self.augmentation()
        state = np.random.get_state()
        first = generate(frame, 5000, 500)
        np.random.set_state(state)
        second = generate(shifted, 5000, 500)
        pd.testing.assert_frame_equal(
            first[cols], second[cols], obj='BUG-25: relative compression must remove the input origin',
        )

    def test_B25_directional_times_remain_inside_shifted_flow_interval(self):
        frame = self.normal_frame()
        frame['src2dst_first_seen_ms'] = frame['bidirectional_first_seen_ms']
        frame['src2dst_last_seen_ms'] = frame['bidirectional_last_seen_ms']
        generated = self.augmentation()(frame, 5000, 500)
        self.assertTrue(
            generated['src2dst_first_seen_ms'].ge(generated['bidirectional_first_seen_ms']).all()
            and generated['src2dst_last_seen_ms'].le(generated['bidirectional_last_seen_ms']).all(),
            'BUG-25: shifting only bidirectional timestamps leaves contradictory directional times',
        )

    def test_B25_capture_time_conversion_handles_midnight_rollover(self):
        for filename in ('process_attack_train.ipynb', 'process_attack_test.ipynb', 'attack_normal_merging.ipynb'):
            with self.subTest(filename=filename):
                namespace = {'shift_capture_time': shift_capture_time, 'start_time': np.array(datetime(2026, 1, 1, 1), dtype=object)}
                assignments = [node for source in notebook_cells(filename) for node in ast.parse(source).body
                               if isinstance(node, ast.Assign) and 'shift_capture_time' in ast.unparse(node.value)
                               and any(isinstance(target, ast.Name) and target.id == 'start_time' for target in node.targets)]
                self.assertEqual(len(assignments), 1)
                value = eval(compile(ast.Expression(assignments[0].value), '<capture time conversion>', 'eval'), namespace)
                self.assertEqual(value, datetime(2025, 12, 31, 23))

    def test_packet_totals_zero_directions_and_recomputed_durations(self):
        frame = self.normal_frame()
        frame['src2dst_packets'] = np.arange(len(frame))
        frame['dst2src_packets'] = np.arange(len(frame)) % 2
        frame['bidirectional_packets'] = frame['src2dst_packets'] + frame['dst2src_packets']
        for direction in ('src2dst', 'dst2src'):
            present = frame[f'{direction}_packets'].gt(0)
            for endpoint in ('first', 'last'):
                frame[f'{direction}_{endpoint}_seen_ms'] = frame[f'bidirectional_{endpoint}_seen_ms'].where(present, 0)
        original = frame.copy(deep=True)
        generated = self.augmentation()(frame, 5000, 10)
        pd.testing.assert_frame_equal(frame, original)
        self.assertTrue(generated['bidirectional_packets'].eq(
            generated['src2dst_packets'] + generated['dst2src_packets']).all())
        for direction in ('bidirectional', 'src2dst', 'dst2src'):
            first, last = f'{direction}_first_seen_ms', f'{direction}_last_seen_ms'
            self.assertTrue(generated[f'{direction}_duration_ms'].eq(generated[last] - generated[first]).all())
            if direction != 'bidirectional':
                absent = original[f'{direction}_packets'].eq(0)
                self.assertTrue(generated.loc[absent, [first, last, f'{direction}_packets']].eq(0).all().all())

    def test_ipv4_helper_rejects_invalid_addresses_and_both_ipv6_endpoints(self):
        helper = is_ipv4
        for address, expected in ((SOURCE, True), ('fe80::1', False), ('bad.host', False),
                                  ('999.1.2.3', False), (None, False)):
            with self.subTest(address=address):
                self.assertEqual(helper(address), expected)

    def test_zero_origin_directional_timestamp_is_not_mistaken_for_absence(self):
        frame = pd.DataFrame({'bidirectional_first_seen_ms': [0], 'bidirectional_last_seen_ms': [0],
                              'src2dst_first_seen_ms': [0], 'src2dst_last_seen_ms': [0]})
        generated = self.augmentation()(frame, 5000, 10)
        self.assertEqual(generated['src2dst_first_seen_ms'].iloc[0], generated['bidirectional_first_seen_ms'].iloc[0])
        self.assertEqual(generated['src2dst_last_seen_ms'].iloc[0], generated['bidirectional_last_seen_ms'].iloc[0])
