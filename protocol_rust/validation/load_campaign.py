"""Collect a bounded real-TLS soak, process-resource samples and source provenance.

The probe runs server and clients in ONE process. Its RSS/FD/thread observations
are combined-endpoint laboratory measurements, not independent server capacity.
Credentials are generated outside the evidence directory and never archived.
"""
from __future__ import annotations
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'protocol_rust'))

PROFILES = {'30m': 1800, '1h': 3600, '2h': 7200, '6h': 21600,
            '12h': 43200, '24h': 86400}


def duration_value(value):
    match = re.fullmatch(r'([0-9]+)([smh])', value)
    if not match:
        raise argparse.ArgumentTypeError('use an integer duration such as 30m, 1h or 24h')
    seconds = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600}[match[2]]
    if not 10 <= seconds <= 86400:
        raise argparse.ArgumentTypeError('duration must be 10 seconds through 24 hours')
    return seconds


def watchdog_budget(duration, interval_ms):
    # A group ends at 240s or 32768 messages per lane, whichever comes first.
    # Add a spare epoch for rounding and bound each reconnect and close tail.
    minimum_epoch = min(240, 32767 * interval_ms / 1000)
    epochs = math.ceil(duration / minimum_epoch) + 1
    return math.ceil(duration + 60 + epochs * (30 + 10))


class ProgressWatch:
    """Echo deadlines apply to traffic; reconnect/close get fixed phase bounds."""
    def __init__(self, now):
        self.last_event = now
        self.phase = 'startup'
        self.phase_deadline = now + 60
        self.progress_at = None
        self.last_messages = None

    def observe(self, event, now):
        kind = event.get('event')
        self.last_event = now
        if kind == 'rotation_started':
            if self.phase not in ('startup', 'closing'):
                raise ValueError('unexpected rotation phase')
            self.phase = 'rotation'; self.phase_deadline = now + 32
            self.progress_at = None
        elif kind == 'rotation_progress':
            if self.phase != 'rotation':
                raise ValueError('rotation heartbeat outside setup')
            # Heartbeats must never extend the fixed reconnect deadline.
        elif kind == 'rotation_ready':
            if self.phase != 'rotation':
                raise ValueError('ready event outside setup')
            self.phase = 'ready'; self.phase_deadline = now + 10
        elif kind == 'traffic_started':
            if self.phase != 'ready':
                raise ValueError('traffic started without ready group')
            self.phase = 'soak'; self.phase_deadline = None
            self.progress_at = now
        elif kind == 'closing_started':
            if self.phase != 'soak':
                raise ValueError('closing event outside traffic')
            self.phase = 'closing'; self.phase_deadline = now + 12
            self.progress_at = None
        elif kind == 'sample':
            expected = event.get('expected_established_connections')
            if expected == 0:
                if self.phase != 'closing':
                    raise ValueError('shutdown sample outside closure')
                self.phase = 'shutdown'; self.phase_deadline = now + 10
            elif self.phase != 'soak':
                raise ValueError('traffic sample outside traffic')
            count = event.get('total_messages')
            if not finite_number(count) or (self.last_messages is not None and count < self.last_messages):
                raise ValueError('invalid/nonmonotonic echo counter')
            if self.last_messages is None or count > self.last_messages:
                if self.phase == 'soak':
                    self.progress_at = now
            self.last_messages = count
        elif kind == 'final':
            self.phase = 'finished'; self.phase_deadline = now + 10
            self.progress_at = None

    def check(self, now):
        if now - self.last_event > 30:
            raise TimeoutError('probe event heartbeat stalled')
        if self.phase_deadline is not None and now > self.phase_deadline:
            raise TimeoutError('probe ' + self.phase + ' phase deadline exceeded')
        if self.progress_at is not None and now - self.progress_at > 15:
            raise TimeoutError('verified echo progress stalled')


class ResourceSummary:
    """Constant-size aggregates; the full one-second trace is streamed to disk."""
    def __init__(self):
        self.count = 0; self.maxima = {}; self.warm_count = 0
        self.first_rss = []; self.tail_rss = deque(maxlen=60)

    def add(self, sample):
        self.count += 1
        for name in ('rss_kib', 'peak_rss_kib', 'fd_count', 'threads', 'cpu_seconds'):
            self.maxima[name] = max(self.maxima.get(name, 0), sample[name])
        if sample['elapsed_seconds'] >= 60:
            self.warm_count += 1
            if len(self.first_rss) < 60:
                self.first_rss.append(sample['rss_kib'])
            self.tail_rss.append(sample['rss_kib'])

    def report(self):
        import statistics
        result = dict(self.maxima)
        if self.warm_count >= 60:
            span = min(60, self.warm_count // 2)
            warm = statistics.median(self.first_rss[:span])
            tail = statistics.median(list(self.tail_rss)[-span:])
            result.update(warm_rss_median_kib=warm, tail_rss_median_kib=tail,
                          tail_minus_warm_rss_kib=tail - warm)
        return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON number')
    def floating(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('overflowing JSON number')
        return number
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid, parse_float=floating)


def source_snapshot(root=ROOT):
    files = set()
    for relative in ('protocol_rust/src', 'third_party/rustcrypto'):
        for path in (root / relative).rglob('*'):
            if path.is_file() and path.suffix in ('.rs', '.toml', '.json'):
                files.add(path)
    for relative in ('protocol_rust/Cargo.toml', 'protocol_rust/Cargo.lock',
                     'protocol_rust/build.rs', 'rust-toolchain.toml',
                     'protocol_rust/examples/load_probe.rs',
                     'protocol_rust/run_load_test.sh',
                     'protocol_rust/validation/load_campaign.py',
                     'protocol_rust/interop.py', 'protocol_v01/requirements.txt'):
        path = root / relative
        if path.is_file():
            files.add(path)
    for path in (root / 'native_research').glob('*'):
        if path.suffix in ('.c', '.h'):
            files.add(path)
    hashes = {p.relative_to(root).as_posix(): sha(p) for p in sorted(files)}
    canonical = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root))
    return {'git_head': revision, 'working_tree_dirty': dirty, 'files': hashes,
            'source_tree_sha256': hashlib.sha256(canonical).hexdigest()}


def sample_process(pid):
    base = Path('/proc') / str(pid)
    try:
        status = {}
        for line in (base / 'status').read_text().splitlines():
            key, _, value = line.partition(':')
            if key in ('VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'Threads'):
                status[key] = int(value.split()[0])
        raw = (base / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'rss_kib': status.get('VmRSS', 0),
                'peak_rss_kib': status.get('VmHWM', 0),
                'anonymous_rss_kib': status.get('RssAnon', 0),
                'file_rss_kib': status.get('RssFile', 0),
                'threads': status['Threads'],
                'fd_count': sum(1 for _ in (base / 'fd').iterdir()),
                'cpu_seconds': (int(raw[11]) + int(raw[12])) / os.sysconf('SC_CLK_TCK'),
                'minor_faults': int(raw[7]), 'major_faults': int(raw[9])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def resource_violation(sample, limits):
    if sample['peak_rss_kib'] > limits['rss_mib'] * 1024:
        return 'process RSS ceiling exceeded'
    if sample['fd_count'] > limits['fds']:
        return 'sampled descriptor ceiling exceeded'
    if sample['threads'] > limits['threads']:
        return 'sampled thread ceiling exceeded'
    return None


def finite_number(value, minimum=0):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= minimum


def validate_final(report, duration, connections):
    # The exact probe contract is checked here; a successful process exit alone
    # is insufficient and a short/empty run never counts as a completed soak.
    if not isinstance(report, dict) or report.get('status') != 'passed':
        raise ValueError('probe did not report a passed final result')
    if not finite_number(report.get('soak_elapsed_seconds'), duration):
        raise ValueError('soak was shorter than requested')
    if not finite_number(report.get('traffic_epoch_elapsed_seconds'), duration):
        raise ValueError('traffic epochs were shorter than requested')
    if not finite_number(report.get('total_messages'), connections):
        raise ValueError('no verified echo traffic for every connection')
    if report.get('peak_authenticated_connections') != connections:
        raise ValueError('requested authenticated concurrency was not reached')
    if report.get('active') != 0 or report.get('pending') != 0 or report.get('admission_released') is not True:
        raise ValueError('admission leases were not all released')
    if report.get('kem', {}).get('live_keys') != 0:
        raise ValueError('native KEM keys remain live')
    if report.get('authenticated_close_for_all_completed_pairs') is not True or report.get('auth_key_closed') is not True:
        raise ValueError('authenticated closure/identity cleanup incomplete')
    pairs = report.get('authenticated_pairs_total')
    if not finite_number(pairs, connections) or report.get('authenticated_pair_closes') != pairs:
        raise ValueError('authenticated pairs were not all closed')
    if report.get('successful_endpoint_handshakes') != pairs * 2 or report.get('kem', {}).get('executed_jobs') != pairs * 3:
        raise ValueError('handshake or KEM accounting mismatch')
    initial_fds = report.get('resource_baseline', {}).get('fd_count')
    final_fds = report.get('final_resources', {}).get('fd_count')
    # The initialized baseline includes the listener, which is closed at exit.
    if not finite_number(initial_fds, 1) or not finite_number(final_fds) or final_fds > initial_fds - 1:
        raise ValueError('descriptor recovery was not demonstrated')
    if report.get('errors') != []:
        raise ValueError('probe reported execution errors')
    required = ('per_ip', 'pending') + (('global',) if connections == 64 else ())
    if any(report.get('limit_checks', {}).get(key) is not True for key in required):
        raise ValueError('required real-socket admission-limit checks missing')


def stop(child):
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--list-profiles', action='store_true')
    p.add_argument('--binary', type=Path)
    p.add_argument('--output', type=Path)
    durations = p.add_mutually_exclusive_group()
    durations.add_argument('--duration', type=duration_value, help='10s..24h; profiles: ' + ', '.join(PROFILES))
    durations.add_argument('--duration-seconds', type=int, help='legacy seconds form; default 1800')
    p.add_argument('--connections', type=int, default=64)
    p.add_argument('--payload', type=int, default=16384)
    p.add_argument('--interval-ms', type=int, default=50)
    p.add_argument('--rss-limit-mib', type=int, default=512)
    p.add_argument('--fd-limit', type=int, default=256)
    p.add_argument('--thread-limit', type=int, default=64)
    p.add_argument('--platform', choices=('local', 'oci', 'wsl'), default='local')
    args = p.parse_args(argv)
    if args.list_profiles:
        for name, seconds in PROFILES.items():
            print(f'{name:>3}  {seconds:>5} traffic seconds; 64 connections, 16 KiB payload, 50 ms pacing')
        return 0
    if args.binary is None or args.output is None:
        p.error('--binary and --output are required for a campaign')
    args.duration_seconds = args.duration if args.duration is not None else (args.duration_seconds if args.duration_seconds is not None else 1800)
    if not (10 <= args.duration_seconds <= 86400 and 4 <= args.connections <= 64
            and 1 <= args.payload <= 16384 and 1 <= args.interval_ms <= 1000):
        p.error('duration must be 10..86400 seconds; connections 4..64, payload 1..16384, interval 1..1000 ms')
    if min(args.rss_limit_mib, args.fd_limit, args.thread_limit) <= 0:
        p.error('resource ceilings must be positive')
    if sys.platform != 'linux':
        p.error('Linux /proc is required for this resource collector')
    if args.platform == 'wsl' and 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        p.error('WSL label requires a Microsoft kernel')
    from interop import identities
    binary = args.binary.resolve(strict=True)
    archive = args.output.resolve().with_name(args.output.name + '.tar.gz')
    if archive.exists():
        p.error('evidence archive already exists; choose a new output path')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = args.output.resolve()
    before = source_snapshot()
    (output / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
    limits = {'rss_mib': args.rss_limit_mib, 'fds': args.fd_limit, 'threads': args.thread_limit}
    budget = watchdog_budget(args.duration_seconds, args.interval_ms)
    lifetime = budget + 3600
    result = {'schema': 'spiral-real-tls-load-campaign/v2', 'status': 'failed',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'requested_duration_seconds': args.duration_seconds,
              'requested_connections': args.connections, 'payload_bytes': args.payload,
              'interval_ms': args.interval_ms, 'environment_label': args.platform,
              'cloud_provider_independently_attested': False,
              'architecture': platform.machine(), 'kernel': platform.release(),
              'cpu_affinity_count': len(os.sched_getaffinity(0)),
              'scope': 'Single persistent probe with real loopback TCP/TLS; server and clients share one process; sampled resource ceilings are experiment guards, not production capacity guarantees.',
              'resource_limits': limits, 'resource_sample_interval_seconds': 1,
              'probe_event_watchdog_seconds': 30, 'echo_progress_watchdog_seconds': 15,
              'overall_watchdog_seconds': budget, 'fixture_lifetime_seconds': lifetime,
              'rotation_setup_deadline_seconds': 30, 'closing_deadline_seconds': 10,
              'phase_watchdog_grace_seconds': 2,
              'binary_sha256': sha(binary),
              'credentials_published': False, 'memory_or_constant_time_approval': False}
    started = time.monotonic()
    samples = ResourceSummary(); events = deque(maxlen=128); event_count = 0
    final = None; child = None
    try:
        with tempfile.TemporaryDirectory(prefix='spiral-load-private-') as temp:
            folder = Path(temp); folder.chmod(0o700)
            identities(folder, lifetime_seconds=lifetime)
            command = [str(binary), '--fixture-dir', str(folder),
                       '--duration-seconds', str(args.duration_seconds),
                       '--connections', str(args.connections), '--payload', str(args.payload),
                       '--interval-ms', str(args.interval_ms)]
            with (output / 'probe.stdout.jsonl').open('wb') as raw, (output / 'probe.stderr.log').open('wb') as errors, (output / 'resources.jsonl').open('w') as trace:
                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
                selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
                buffer = b''; eof = False; next_sample = time.monotonic()
                watch = ProgressWatch(next_sample); next_console = next_sample + 60
                while not eof:
                    now = time.monotonic()
                    watch.check(now)
                    if now - started > budget:
                        raise TimeoutError('probe exceeded bounded setup/soak/shutdown deadline')
                    if now >= next_sample:
                        sample = sample_process(child.pid)
                        if sample:
                            sample['elapsed_seconds'] = now - started
                            samples.add(sample); trace.write(json.dumps(sample) + '\n'); trace.flush()
                            bad = resource_violation(sample, limits)
                            if bad:
                                raise RuntimeError(bad)
                        next_sample = now + 1
                    if now >= next_console:
                        print(json.dumps({'event': 'collector_progress', 'wall_seconds': round(now - started),
                                          'phase': watch.phase, 'verified_echoes': watch.last_messages,
                                          'resource_samples': samples.count}), flush=True)
                        next_console = now + 60
                    for key, _ in selector.select(timeout=0.25):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            eof = True; break
                        raw.write(chunk); raw.flush(); buffer += chunk
                        if len(buffer) > 1024 * 1024:
                            raise ValueError('probe output line exceeded bound')
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            if not line:
                                continue
                            event = strict_json(line)
                            if not isinstance(event, dict):
                                raise ValueError('probe emitted a nonobject event')
                            kind = event.get('event')
                            watch.observe(event, time.monotonic())
                            if kind == 'final':
                                if final is not None:
                                    raise ValueError('duplicate final probe result')
                                final = event
                            # Keep at most small summary events in result; full trace is on disk.
                            if kind != 'sample':
                                events.append(event)
                                event_count += 1
                            if kind in ('start', 'phase', 'final'):
                                print(json.dumps(event), flush=True)
                    if child.poll() is not None and not eof:
                        continue
                if buffer.strip():
                    raise ValueError('truncated probe JSON output')
                selector.close()
                code = child.wait(timeout=10)
                result['probe_exit_code'] = code
                if code != 0:
                    raise RuntimeError('probe process failed')
                validate_final(final, args.duration_seconds, args.connections)
                if not samples.count:
                    raise ValueError('no process resource samples collected')
                result['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        if child is not None:
            stop(child)
        try:
            after = source_snapshot()
            result['source_unchanged'] = before['files'] == after['files']
        except Exception as error:
            after = {'snapshot_error': type(error).__name__}
            result['source_unchanged'] = False
        (output / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
        try:
            result['binary_unchanged'] = sha(binary) == result['binary_sha256']
        except OSError:
            result['binary_unchanged'] = False
        if not result['source_unchanged'] or not result['binary_unchanged']:
            result['status'] = 'failed'; result['failure'] = 'source or binary changed during campaign'
        result['wall_elapsed_seconds'] = time.monotonic() - started
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        result['probe_final'] = final; result['events'] = list(events)
        result['summary_event_count'] = event_count
        result['summary_events_retained'] = len(events)
        result['summary_events_truncated'] = event_count > len(events)
        result['resource_samples'] = samples.count
        if samples.count:
            result['resources'] = samples.report()
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        manifest = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file() and p.name != 'SHA256.json'}
        (output / 'SHA256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    # Archive only collected evidence, never the fixture directory or executable.
    try:
        with archive.open('xb') as archive_file:
            archive.chmod(0o600)
            with tarfile.open(fileobj=archive_file, mode='w:gz') as packed:
                for name in sorted(set(manifest) | {'SHA256.json'}):
                    packed.add(output / name, arcname=output.name + '/' + name, recursive=False)
    except OSError as error:
        print('Could not create evidence archive: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['status'], 'result': str(output / 'result.json'),
                      'archive': str(archive), 'failure': result.get('failure')}), flush=True)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
