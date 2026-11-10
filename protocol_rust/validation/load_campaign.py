"""Collect a bounded real-TLS soak, process-resource samples and source provenance.

The probe runs server and clients in ONE process. Its RSS/FD/thread observations
are combined-endpoint laboratory measurements, not independent server capacity.
Credentials are generated outside the evidence directory and never archived.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'protocol_rust'))
from interop import identities


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
    if not finite_number(initial_fds) or not finite_number(final_fds) or final_fds > initial_fds:
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
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--duration-seconds', type=int, default=1800)
    p.add_argument('--connections', type=int, default=64)
    p.add_argument('--payload', type=int, default=1024)
    p.add_argument('--interval-ms', type=int, default=50)
    p.add_argument('--rss-limit-mib', type=int, default=512)
    p.add_argument('--fd-limit', type=int, default=256)
    p.add_argument('--thread-limit', type=int, default=64)
    p.add_argument('--platform', choices=('local', 'oci', 'wsl'), default='local')
    args = p.parse_args(argv)
    if not (10 <= args.duration_seconds <= 1800 and 4 <= args.connections <= 64
            and 1 <= args.payload <= 16384 and 1 <= args.interval_ms <= 1000):
        p.error('duration must be 10..1800 seconds; connections 4..64, payload 1..16384, interval 1..1000 ms')
    if min(args.rss_limit_mib, args.fd_limit, args.thread_limit) <= 0:
        p.error('resource ceilings must be positive')
    if sys.platform != 'linux':
        p.error('Linux /proc is required for this resource collector')
    if args.platform == 'wsl' and 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        p.error('WSL label requires a Microsoft kernel')
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    before = source_snapshot()
    (output / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
    limits = {'rss_mib': args.rss_limit_mib, 'fds': args.fd_limit, 'threads': args.thread_limit}
    result = {'schema': 'spiral-real-tls-load-campaign/v1', 'status': 'failed',
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
              'binary_sha256': sha(binary),
              'credentials_published': False, 'memory_or_constant_time_approval': False}
    started = time.monotonic()
    samples = []; events = []; final = None; child = None; failure = None
    try:
        with tempfile.TemporaryDirectory(prefix='spiral-load-private-') as temp:
            folder = Path(temp); folder.chmod(0o700); identities(folder)
            command = [str(binary), '--fixture-dir', str(folder),
                       '--duration-seconds', str(args.duration_seconds),
                       '--connections', str(args.connections), '--payload', str(args.payload),
                       '--interval-ms', str(args.interval_ms)]
            with (output / 'probe.stdout.jsonl').open('wb') as raw, (output / 'probe.stderr.log').open('wb') as errors, (output / 'resources.jsonl').open('w') as trace:
                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
                selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
                buffer = b''; eof = False; next_sample = time.monotonic()
                last_event = next_sample; progress_at = None; last_messages = None
                while not eof:
                    now = time.monotonic()
                    if now - last_event > 30:
                        raise TimeoutError('probe event heartbeat stalled')
                    if progress_at is not None and now - progress_at > 15:
                        raise TimeoutError('verified echo progress stalled')
                    if now - started > args.duration_seconds + 300:
                        raise TimeoutError('probe exceeded bounded setup/soak/shutdown deadline')
                    if now >= next_sample:
                        sample = sample_process(child.pid)
                        if sample:
                            sample['elapsed_seconds'] = now - started
                            samples.append(sample); trace.write(json.dumps(sample) + '\n'); trace.flush()
                            bad = resource_violation(sample, limits)
                            if bad:
                                raise RuntimeError(bad)
                        next_sample = now + 1
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
                            last_event = time.monotonic()
                            kind = event.get('event')
                            if kind == 'sample' and event.get('expected_established_connections', 0) > 0:
                                count = event.get('total_messages')
                                if not finite_number(count) or (last_messages is not None and count < last_messages):
                                    raise ValueError('invalid/nonmonotonic echo counter')
                                if last_messages is None or count > last_messages:
                                    progress_at = last_event
                                last_messages = count
                            if kind == 'final':
                                if final is not None:
                                    raise ValueError('duplicate final probe result')
                                final = event
                            # Keep at most small summary events in result; full trace is on disk.
                            if kind != 'sample':
                                events.append(event)
                                if len(events) > 256:
                                    raise ValueError('too many probe summary events')
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
                if not samples:
                    raise ValueError('no process resource samples collected')
                result['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        failure = type(error).__name__ + ': ' + str(error)
        result['failure'] = failure
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
        result['probe_final'] = final; result['events'] = events
        result['resource_samples'] = len(samples)
        if samples:
            result['resources'] = {name: max(x[name] for x in samples) for name in ('rss_kib', 'peak_rss_kib', 'fd_count', 'threads', 'cpu_seconds')}
            # Observed medians/trends are not a proof of absence of small leaks.
            rss = [x['rss_kib'] for x in samples if x['elapsed_seconds'] >= 60]
            if len(rss) >= 60:
                import statistics
                span = min(60, len(rss) // 2)
                result['resources']['warm_rss_median_kib'] = statistics.median(rss[:span])
                result['resources']['tail_rss_median_kib'] = statistics.median(rss[-span:])
                result['resources']['tail_minus_warm_rss_kib'] = statistics.median(rss[-span:]) - statistics.median(rss[:span])
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        manifest = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file() and p.name != 'SHA256.json'}
        (output / 'SHA256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(output / 'result.json'), 'failure': result.get('failure')}), flush=True)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
