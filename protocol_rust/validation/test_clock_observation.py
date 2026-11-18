"""Fake clock domains and Windows calls. Never changes system clocks."""
from pathlib import Path
import tempfile
import unittest

from clock_observation import Capture, SECOND, assess, query_interval, query_windows

MS = 1_000_000
UTC = 1_800_000_000 * SECOND


def reading(at, utc_adjustment=0, boot_adjustment=0, source='one'):
    return {'clock_source': source, 'utc_ns': UTC + at + utc_adjustment,
            'monotonic_ns': at + SECOND, 'boottime_ns': at + 2 * SECOND + boot_adjustment,
            'read_span_ns': 1000}


def row(index, event, at, **kwargs):
    return {'sequence': index, 'event': event, **reading(at, **kwargs)}


def bracket(start=0, latency=20*MS, offset=0, **kwargs):
    samples = iter((reading(start), reading(start+latency, **kwargs)))
    return query_windows(lambda: next(samples), lambda: UTC+start+latency//2+offset)


class ClockObservationTests(unittest.TestCase):
    def setUp(self):
        self.rows = [row(0,'start',0), row(1,'sample',SECOND), row(2,'end',2*SECOND)]

    def assess(self, rows=None, complete=True):
        return assess(self.rows if rows is None else rows, 'one', False, complete)

    def test_clean_same_source(self):
        report = self.assess()
        self.assertEqual(report['status'], 'locally_consistent')
        self.assertEqual(report['observed_monotonic_ns'], 2*SECOND)

    def test_backwards_utc_does_not_set_elapsed_time(self):
        self.rows[-1] = row(2,'end',2*SECOND,utc_adjustment=-24*SECOND)
        report = self.assess()
        self.assertIn('linux_utc_step_or_rate_difference',report['issues'])
        self.assertEqual(report['observed_monotonic_ns'],2*SECOND)

    def test_cumulative_rate_difference(self):
        rows = [row(0,'start',0), row(1,'sample',SECOND,utc_adjustment=45*MS),
                row(2,'sample',2*SECOND,utc_adjustment=90*MS),
                row(3,'end',3*SECOND,utc_adjustment=135*MS)]
        self.assertIn('linux_utc_drift_over_run',self.assess(rows)['issues'])

    def test_boottime_divergence(self):
        self.rows[-1] = row(2,'end',2*SECOND,boot_adjustment=5*SECOND)
        self.assertIn('suspend_or_elapsed_clock_difference',self.assess()['issues'])

    def test_no_cross_source_subtraction_even_with_matching_epoch(self):
        self.rows[-1]['clock_source'] = 'another-host'
        self.rows[-1]['monotonic_ns'] += 40*SECOND
        report = self.assess()
        self.assertIn('mixed_source_or_missing_record',report['issues'])
        self.assertEqual(report['observed_monotonic_ns'],SECOND)

    def test_interruption_and_missing_tail(self):
        self.assertEqual(self.assess(complete=False)['status'],'insufficient')
        self.assertIn('incomplete_observation',self.assess(self.rows[:-1])['issues'])

    def test_missing_sample_or_clock(self):
        self.assertIn('mixed_source_or_missing_record',self.assess([self.rows[0],self.rows[2]])['issues'])
        del self.rows[1]['boottime_ns']
        self.assertIn('missing_or_invalid_clock',self.assess()['issues'])

    def test_sample_gap_even_with_correct_sequence(self):
        self.rows[-1] = row(2,'end',5*SECOND)
        self.assertIn('sample_gap',self.assess()['issues'])

    def test_query_bounds_include_offset_and_measured_latency(self):
        result = query_interval(bracket(offset=250*MS), 'one')
        self.assertEqual(result['status'],'bounded')
        self.assertEqual(result['query_monotonic_ns'],20*MS)
        self.assertLess(result['offset_lower_ns'],250*MS)
        self.assertGreater(result['offset_upper_ns'],250*MS)
        self.assertGreater(result['offset_lower_ns'],100*MS)

    def test_query_rejects_jump_cross_source_and_slow_bracket(self):
        for query,status in (
            (bracket(utc_adjustment=SECOND),'clock_changed_during_query'),
            (bracket(boot_adjustment=SECOND),'clock_changed_during_query'),
            (bracket(source='another-host'),'mixed_source'),
            (bracket(latency=SECOND+1),'query_latency_out_of_bounds'),
        ):
            with self.subTest(status=status):
                result = query_interval(query,'one')
                self.assertEqual(result['status'],status)
                self.assertNotIn('offset_lower_ns',result)

    def test_query_failure_retains_linux_bracket(self):
        samples = iter((reading(0),reading(50*MS)))
        def unavailable():
            raise FileNotFoundError
        result = query_interval(query_windows(lambda: next(samples), unavailable),'one')
        self.assertEqual(result,{'status':'unavailable','query_monotonic_ns':50*MS})

    def test_windows_sampling_reports_disagreement_indeterminate_or_missing(self):
        for queries, expected in (
            ([], 'insufficient'),
            ([bracket(100*MS,offset=SECOND)], 'utc_disagreement_observed'),
            ([bracket(100*MS,latency=500*MS),bracket(SECOND,latency=500*MS)], 'offset_indeterminate'),
            ([bracket(100*MS),bracket(SECOND)], 'within_tolerance_in_sampled_queries'),
        ):
            rows = self.rows[:2] + [dict(q,event='windows_utc',clock_source='one') for q in queries] + self.rows[2:]
            report = assess((dict(r,sequence=i) for i,r in enumerate(rows)),'one',True,True)
            with self.subTest(expected=expected):
                self.assertEqual(report['windows']['status'],expected)

    def test_capture_replays_fake_source(self):
        samples = iter((reading(0),reading(SECOND),reading(2*SECOND)))
        with tempfile.TemporaryDirectory() as directory:
            capture = Capture(Path(directory)/'clocks.jsonl',False,lambda: next(samples))
            capture.tick('start')
            capture.tick()
            self.assertEqual(capture.finish(True)['status'],'locally_consistent')
