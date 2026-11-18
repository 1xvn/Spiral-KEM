"""Run-scoped Linux clock sampling and bounded Windows UTC observations."""
from concurrent.futures import ThreadPoolExecutor
import json
import shutil
import subprocess
import time
import uuid

SECOND = 1_000_000_000
READ_LIMIT = 20_000_000
DIVERGENCE_LIMIT = 50_000_000
SAMPLE_GAP_LIMIT = 2_500_000_000
QUERY_LIMIT = SECOND
QUERY_DIVERGENCE_LIMIT = 5_000_000
WINDOWS_INTERVAL = 30 * SECOND
WINDOWS_GAP_LIMIT = 35 * SECOND
OFFSET_LIMIT = 100_000_000


def linux_clocks():
    before = time.monotonic_ns()
    utc = time.time_ns()
    boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    after = time.monotonic_ns()
    return {'utc_ns': utc, 'monotonic_ns': after, 'boottime_ns': boottime,
            'read_span_ns': after - before}


def powershell_utc():
    executable = shutil.which('powershell.exe')
    if not executable:
        raise FileNotFoundError('Windows interop unavailable')
    done = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                           '-Command', '[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()'],
                          capture_output=True, timeout=3, check=True)
    return int(done.stdout.decode('ascii').strip()) * 1_000_000


def query_windows(sample=linux_clocks, read_windows=powershell_utc):
    before = sample()
    try:
        utc = read_windows()
        error = None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        utc = None
        error = type(exc).__name__
    return {'before': before, 'after': sample(), 'windows_utc_ns': utc, 'error_type': error}


def valid_sample(sample):
    names = ('monotonic_ns', 'boottime_ns', 'utc_ns', 'read_span_ns')
    return isinstance(sample, dict) and all(
        type(sample.get(name)) is int and 0 <= sample[name] < 2**63 for name in names
    ) and sample['read_span_ns'] <= READ_LIMIT


def deltas(before, after):
    elapsed = after['monotonic_ns'] - before['monotonic_ns']
    utc_skew = after['utc_ns'] - before['utc_ns'] - elapsed
    boot_skew = after['boottime_ns'] - before['boottime_ns'] - elapsed
    return elapsed, utc_skew, boot_skew


def query_interval(query, source):
    """Return an offset bracket only when the Linux clock pair is consistent."""
    before, after = query.get('before'), query.get('after')
    report = {'status': 'unavailable', 'query_monotonic_ns': None}
    if not valid_sample(before) or not valid_sample(after):
        return dict(report, status='invalid_linux_bracket')
    if before.get('clock_source') != source or after.get('clock_source') != source:
        return dict(report, status='mixed_source')
    elapsed, utc, boot = deltas(before, after)
    uncertainty = before['read_span_ns'] + after['read_span_ns']
    report['query_monotonic_ns'] = elapsed
    if not 0 < elapsed <= QUERY_LIMIT:
        return dict(report, status='query_latency_out_of_bounds')
    if max(abs(utc), abs(boot)) > QUERY_DIVERGENCE_LIMIT + uncertainty:
        return dict(report, status='clock_changed_during_query')
    stamp = query.get('windows_utc_ns')
    if type(stamp) is not int or not 0 < stamp < 2**63 or query.get('error_type') is not None:
        return report
    # The Windows timestamp is truncated to milliseconds. Linux readings
    # bracket the call, and the stability threshold qualifies the interval.
    margin = QUERY_DIVERGENCE_LIMIT + uncertainty
    return dict(report, status='bounded', offset_lower_ns=stamp - after['utc_ns'] - margin,
                offset_upper_ns=stamp + 1_000_000 - before['utc_ns'] + margin)


def assess(records, source, windows_requested, complete):
    """Assess one acquisition stream with its collector-declared source and end."""
    first = last = None
    seen_end = False
    count = longest_gap = 0
    utc_range, boot_range = [0, 0], [0, 0]
    issues = set()
    windows = []
    for index, row in enumerate(records):
        if (not isinstance(row, dict) or row.get('clock_source') != source
                or type(row.get('sequence')) is not int or row['sequence'] != index):
            issues.add('mixed_source_or_missing_record')
            # Do not subtract this sample from a sample from another source.
            continue
        kind = row.get('event')
        if kind == 'windows_utc':
            windows.append(row)
            if first is None:
                issues.add('invalid_record_order')
            continue
        if (index == 0 and kind != 'start' or index != 0 and kind not in ('sample', 'end')
                or seen_end):
            issues.add('invalid_record_order')
            continue
        seen_end = kind == 'end'
        if not valid_sample(row):
            issues.add('missing_or_invalid_clock')
            continue
        count += 1
        if first is None:
            first = last = row
            continue
        elapsed, utc, boot = deltas(last, row)
        longest_gap = max(longest_gap, elapsed)
        if elapsed <= 0 or row['boottime_ns'] <= last['boottime_ns']:
            issues.add('nonincreasing_elapsed_clock')
        if elapsed > SAMPLE_GAP_LIMIT:
            issues.add('sample_gap')
        _, utc_from_start, boot_from_start = deltas(first, row)
        for value, bounds in ((utc_from_start, utc_range), (boot_from_start, boot_range)):
            bounds[0] = min(bounds[0], value)
            bounds[1] = max(bounds[1], value)
        allowance = DIVERGENCE_LIMIT + last['read_span_ns'] + row['read_span_ns']
        if abs(utc) > allowance:
            issues.add('linux_utc_step_or_rate_difference')
        if abs(boot) > allowance:
            issues.add('suspend_or_elapsed_clock_difference')
        last = row

    if not complete or not seen_end or count < 2:
        issues.add('incomplete_observation')
    if utc_range[1] - utc_range[0] > DIVERGENCE_LIMIT + 2 * READ_LIMIT:
        issues.add('linux_utc_drift_over_run')
    if boot_range[1] - boot_range[0] > DIVERGENCE_LIMIT + 2 * READ_LIMIT:
        issues.add('boottime_drift_over_run')

    windows_report = assess_windows(windows, first, last, source) if windows_requested else {'status': 'not_requested'}
    return {'schema': 'spiral-clock-assessment/v1',
            'status': 'locally_consistent' if not issues else 'insufficient',
            'issues': sorted(issues), 'linux_samples': count, 'max_monotonic_sample_gap_ns': longest_gap,
            'utc_minus_monotonic_range_ns': utc_range, 'boottime_minus_monotonic_range_ns': boot_range,
            'observed_monotonic_ns': last['monotonic_ns'] - first['monotonic_ns'] if count >= 2 else None,
            'windows': windows_report}


def assess_windows(queries, first, last, source):
    brackets = []
    max_query_ns = None
    counts = {}
    previous = first['monotonic_ns'] if first else None
    covered = previous is not None and last is not None
    for query in queries:
        report = query_interval(query, source)
        if report['query_monotonic_ns'] is not None:
            max_query_ns = max(max_query_ns or 0, report['query_monotonic_ns'])
        status = report['status']
        counts[status] = counts.get(status, 0) + 1
        if status == 'bounded':
            start = query['before']['monotonic_ns']
            end = query['after']['monotonic_ns']
            if previous is None or not 0 <= start - previous <= WINDOWS_GAP_LIMIT or end > last['monotonic_ns']:
                covered = False
            previous = end
            brackets.append([report['offset_lower_ns'], report['offset_upper_ns']])
    covered = covered and previous is not None and 0 <= last['monotonic_ns'] - previous <= WINDOWS_GAP_LIMIT
    if any(low > OFFSET_LIMIT or high < -OFFSET_LIMIT for low, high in brackets):
        status = 'utc_disagreement_observed'
    elif len(brackets) < 2 or len(brackets) != len(queries) or not covered:
        status = 'insufficient'
    elif all(-OFFSET_LIMIT <= low <= high <= OFFSET_LIMIT for low, high in brackets):
        status = 'within_tolerance_in_sampled_queries'
    else:
        status = 'offset_indeterminate'
    return {'status': status, 'query_counts': counts, 'offset_intervals_ns': brackets,
            'max_query_monotonic_ns': max_query_ns}


class Capture:
    """One writer for Linux samples and asynchronous Windows query results."""
    def __init__(self, path, windows, sample=linux_clocks, read_windows=powershell_utc):
        self.source = uuid.uuid4().hex
        self.path = path
        self.trace = path.open('x')
        self.sequence = 0
        self.sample = sample
        self.read_windows = read_windows
        self.executor = ThreadPoolExecutor(max_workers=1) if windows else None
        self.pending = None
        self.next_windows = 0

    def append(self, event, fields):
        json.dump({'event': event, 'clock_source': self.source, 'sequence': self.sequence,
                   **fields}, self.trace)
        self.trace.write('\n')
        self.trace.flush()
        self.sequence += 1

    def read_sample(self):
        return {**self.sample(), 'clock_source': self.source}

    def tick(self, event='sample'):
        sample = self.read_sample()
        self.append(event, sample)
        if self.executor is None:
            return
        if self.pending is not None and self.pending.done():
            self.append_query()
        if event != 'end' and self.pending is None and sample['monotonic_ns'] >= self.next_windows:
            self.pending = self.executor.submit(query_windows, self.read_sample, self.read_windows)
            self.next_windows = sample['monotonic_ns'] + WINDOWS_INTERVAL

    def append_query(self):
        query = self.pending.result()
        self.pending = None
        self.append('windows_utc', {**query, 'assessment': query_interval(query, self.source)})

    def finish(self, complete):
        try:
            self.tick('end')
            if self.pending is not None:
                self.append_query()
        finally:
            if self.executor is not None:
                self.executor.shutdown()
            self.trace.close()
        with self.path.open() as trace:
            return assess((json.loads(line) for line in trace), self.source,
                          self.executor is not None, complete)
