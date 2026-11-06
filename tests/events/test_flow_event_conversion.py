"""Flow-event ingestion normalizes instants without modifying source data."""

from datetime import timedelta, timezone

import pandas as pd

from events.conversion import CaptureFlowEventConverter
from tests.support import ProjectTestCase


class TestFlowEventConversion(ProjectTestCase):
    def frame(self):
        frame = self.make_scenario_frame(duration_ms=250)
        for name in ('nmap_10_T5', 'nmap_mqtt', 'nmap_banner',
                     'brute_force_malformed', 'dollar_char', 'scp_inst'):
            frame[name] = 0.0
        frame['nmap_10_T5'] = 0.75
        return frame

    def test_naive_timestamps_become_utc_and_keep_millisecond_durations(self):
        frame = self.frame()
        expected = list(frame['timestamp'])
        frame['timestamp'] = frame['timestamp'].dt.tz_localize(None)
        original = frame.copy(deep=True)
        events = CaptureFlowEventConverter.convert(frame)
        pd.testing.assert_frame_equal(frame, original)
        self.assertEqual(len(events), len(frame))
        for event, timestamp in zip(events, expected, strict=True):
            self.assertEqual(event.start_time, timestamp)
            self.assertEqual(event.start_time.utcoffset(), timedelta(0))
            self.assertEqual(event.end_time.utcoffset(), timedelta(0))
            self.assertEqual(event.end_time - event.start_time, timedelta(milliseconds=250))
            self.assertEqual(event.attack_scores['nmap_10_T5'], 0.75)

    def test_explicit_offsets_preserve_instants_and_source_dtype(self):
        for as_string in (False, True):
            with self.subTest(as_string=as_string):
                frame = self.frame()
                expected = list(frame['timestamp'])
                frame['timestamp'] = frame['timestamp'].dt.tz_convert(timezone(timedelta(hours=2)))
                if as_string:
                    frame['timestamp'] = frame['timestamp'].astype(str)
                original = frame.copy(deep=True)
                events = CaptureFlowEventConverter.convert(frame)
                pd.testing.assert_frame_equal(frame, original)
                self.assertEqual([event.start_time for event in events], expected)
                self.assertTrue(all(event.start_time.utcoffset() == timedelta(0) for event in events))

    def test_naive_string_input_is_not_overwritten(self):
        frame = self.frame()
        frame['timestamp'] = frame['timestamp'].dt.tz_localize(None).astype(str)
        original = frame.copy(deep=True)
        events = CaptureFlowEventConverter.convert(frame)
        pd.testing.assert_frame_equal(frame, original)
        self.assertTrue(all(event.start_time.utcoffset() == timedelta(0) for event in events))

    def test_later_conversion_error_does_not_leave_input_partially_converted(self):
        frame = self.frame().drop(columns='scp_inst')
        frame['timestamp'] = frame['timestamp'].astype(str)
        original = frame.copy(deep=True)
        with self.assertRaises(AttributeError):
            CaptureFlowEventConverter.convert(frame)
        pd.testing.assert_frame_equal(frame, original)

    def test_B11_naive_input_is_normalized_before_utc_comparison(self):
        frame = self.make_scenario_frame()
        frame['timestamp'] = frame['timestamp'].dt.tz_localize(None)
        for name in ('nmap_10_T5', 'nmap_mqtt', 'nmap_banner',
                     'brute_force_malformed', 'dollar_char', 'scp_inst'):
            frame[name] = 0.0
        events = CaptureFlowEventConverter.convert(frame)
        self.assertTrue(all(event.start_time.utcoffset() is not None for event in events),
                        'BUG-11: naive ingestion later conflicts with explicitly UTC exploit times')
