#!/usr/bin/env python3
"""Operator-run clock observations and short expected-failure checks.

Uses the existing collector without modifying protocol limits. No test starts
without an explicit --case. Temporary credentials stay outside the evidence.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

import load_campaign as campaign

ROOT = Path(__file__).resolve().parents[2]
FAILURES = {'interrupt': 'KeyboardInterrupt: ',
            'rss': 'RuntimeError: process RSS ceiling exceeded',
            'fds': 'RuntimeError: sampled descriptor ceiling exceeded',
            'threads': 'RuntimeError: sampled thread ceiling exceeded'}
REQUIRED_CHECKS = {'archive_and_hashes_valid', 'no_matching_probe_remaining',
                   'private_fixtures_removed', 'interrupt_sent_after_traffic', 'provenance_matches'}
LIMIT_FLAGS = {'rss': ['--rss-limit-mib', '1'],
               'fds': ['--fd-limit', '16'], 'threads': ['--thread-limit', '2']}


def matching_probes(binary, private, proc=Path('/proc')):
    """Find only this case's fixture-bound probe; never match by name alone."""
    found = []
    for path in proc.glob('[0-9]*/cmdline'):
        try:
            args = path.read_bytes().split(b'\0')
            if args and os.fsdecode(args[0]) == str(binary) and b'--fixture-dir' in args:
                fixture = Path(os.fsdecode(args[args.index(b'--fixture-dir') + 1]))
                if fixture.is_relative_to(private):
                    found.append(int(path.parent.name))
        except (OSError, ValueError, IndexError):
            continue
    return found


def evidence_valid(output):
    expected = {'result.json', 'source-before.json', 'source-after.json',
                'probe.stdout.jsonl', 'probe.stderr.log', 'resources.jsonl'}
    manifest = campaign.strict_json((output / 'SHA256.json').read_bytes())
    if set(manifest) not in (expected, expected | {'clocks.jsonl'}):
        return False
    expected = set(manifest)
    if any(campaign.sha(output / name) != digest for name, digest in manifest.items()):
        return False
    with tarfile.open(str(output) + '.tar.gz', 'r:gz') as packed:
        members = packed.getmembers()
        names = {output.name + '/' + name for name in expected | {'SHA256.json'}}
        if len(members) != len(names) or {m.name for m in members} != names or not all(m.isfile() for m in members):
            return False
        for member in members:
            data = packed.extractfile(member).read()
            if data != (output / Path(member.name).name).read_bytes():
                return False
    return True


def probe_identity(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        return (int(fields[19]), int(fields[2]))  # Start ticks and process group.
    except (OSError, ValueError, IndexError):
        return None


def terminate_case_probes(binary, private):
    targets = {pid:probe_identity(pid) for pid in matching_probes(binary, private)}
    for action, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 1)):
        for pid, identity in targets.items():
            if identity is not None and identity[1] == pid and probe_identity(pid) == identity:
                try:
                    os.killpg(pid, action)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + grace
        while matching_probes(binary, private) and time.monotonic() < deadline:
            time.sleep(.05)
        if not matching_probes(binary, private):
            return True
    return not matching_probes(binary, private)


def verdict(kind, code, result, checks):
    expected = (code == 0 and result.get('status') == 'passed') if kind == 'clock' else (
        code == 1 and result.get('status') == 'failed' and result.get('failure') == FAILURES[kind])
    unchanged = result.get('source_unchanged') is True and result.get('binary_unchanged') is True
    return (expected and unchanged and checks.keys() == REQUIRED_CHECKS
            and all(value is True for value in checks.values()))


def run_case(kind, args, root):
    folder = root / kind
    folder.mkdir(mode=0o700)
    output = folder / 'campaign'
    private = Path(tempfile.mkdtemp(prefix='spiral-short-private-')).resolve()
    env = os.environ.copy(); env['TMPDIR'] = str(private)
    duration = args.clock_seconds if kind == 'clock' else 300
    command = [str(args.python), '-B', str(ROOT / 'protocol_rust/validation/load_campaign.py'),
               '--binary', str(args.binary), '--output', str(output), '--platform', args.platform,
               '--duration-seconds', str(duration), '--connections', '64', '--payload', '16384',
               '--interval-ms', '50', *LIMIT_FLAGS.get(kind, [])]
    if args.windows_clock and kind == 'clock':
        command.append('--windows-clock')
    started = time.monotonic()
    signal_at = None; sent = False; traffic_seen = False
    offset = 0; pending = b''; child = None
    report = {'case': kind, 'status': 'failed', 'expected_failure': FAILURES.get(kind),
              'platform': args.platform, 'clock_duration_seconds': duration,
              'clock_interpretation': 'Collection success does not assert clock agreement or absence of host suspension.',
              'windows_clock_requested': args.windows_clock and kind == 'clock',
              'runner_sha256': campaign.sha(Path(__file__)),
              'classification': 'incomplete_or_tool_error',
              'scope': 'Experimental guard/collector process checks; forced termination does not demonstrate authenticated protocol closure.'}
    try:
        before_binary = campaign.sha(args.binary)
        with (folder / 'console.log').open('wb') as console:
            child = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT,
                                     env=env, cwd=ROOT, start_new_session=True)
            while True:
                elapsed = time.monotonic() - started
                if kind == 'interrupt' and not sent:
                    try:
                        with (output / 'probe.stdout.jsonl').open('rb') as raw:
                            raw.seek(offset); chunk = raw.read(1024 * 1024); offset += len(chunk)
                        pending += chunk
                        if len(pending) > 1024 * 1024:
                            raise ValueError('probe observation exceeded bound')
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            if line:
                                event = campaign.strict_json(line)
                                if event.get('event') == 'traffic_started':
                                    traffic_seen = True
                                if (traffic_seen and event.get('event') == 'sample'
                                        and event.get('expected_established_connections') == 64
                                        and campaign.finite_number(event.get('total_messages'), 1)
                                        and signal_at is None):
                                    signal_at = time.monotonic() + 5
                    except FileNotFoundError:
                        pass
                    if signal_at is not None and time.monotonic() >= signal_at and child.poll() is None:
                        child.send_signal(signal.SIGINT); sent = True
                if child.poll() is not None:
                    break
                if elapsed > (campaign.watchdog_budget(duration, 50) + 30 if kind == 'clock' else 60):
                    raise TimeoutError('short case deadline exceeded')
                time.sleep(.1)
        result = campaign.strict_json((output / 'result.json').read_bytes())
        checks = {'archive_and_hashes_valid': evidence_valid(output),
                  'no_matching_probe_remaining': not matching_probes(args.binary, private),
                  'private_fixtures_removed': not any(private.iterdir()),
                  'interrupt_sent_after_traffic': kind != 'interrupt' or sent,
                  'provenance_matches': result.get('binary_sha256') == result.get('binary_sha256_after')
                      == before_binary == campaign.sha(args.binary)
                      and campaign.strict_json((output/'source-before.json').read_bytes())
                      == campaign.strict_json((output/'source-after.json').read_bytes())}
        if kind == 'clock':
            campaign.validate_final(result['probe_final'], duration, 64)
        report.update(collector_exit_code=child.returncode, collector_status=result.get('status'),
                      collector_failure=result.get('failure'), checks=checks,
                      clock_assessment=result.get('clock_assessment'), timing_scope=result.get('timing_scope'))
        if verdict(kind, child.returncode, result, checks):
            report.update(status='passed',
                          classification='functional_pass' if kind == 'clock' else 'expected_rejection')
    except KeyboardInterrupt:
        report['error'] = 'KeyboardInterrupt'; report['operator_cancelled'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        # A single SIGINT gives the collector time to retain failure evidence.
        if child is not None and child.poll() is None:
            if not sent:
                child.send_signal(signal.SIGINT); sent = True
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=5)
                report['emergency_collector_kill'] = True
        remaining = matching_probes(args.binary, private)
        if remaining:
            report['status'] = 'failed'; report['emergency_probe_termination'] = True
            report['emergency_probe_cleanup_completed'] = terminate_case_probes(args.binary, private)
        report['no_matching_probe_after_cleanup'] = not matching_probes(args.binary, private)
        if not report['no_matching_probe_after_cleanup']:
            report['status'] = 'failed'
        if not any(private.iterdir()):
            private.rmdir()
        else:
            report['status'] = 'failed'; report['private_fixture_cleanup_failed'] = True
        if report['status'] != 'passed':
            report['classification'] = 'incomplete_or_tool_error'
        (folder / 'operator-result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', required=True, choices=('clock', 'interrupt', 'rss', 'fds', 'threads', 'all'))
    p.add_argument('--platform', required=True, choices=('local','oci','wsl'))
    p.add_argument('--clock-seconds', type=int, default=300, help='10..600; default five-minute clock campaign')
    p.add_argument('--windows-clock', action='store_true', help='WSL only: query Windows UTC every 30 seconds')
    p.add_argument('--python', type=Path, default=ROOT / '.venv-load/bin/python')
    p.add_argument('--binary', type=Path, default=ROOT / 'protocol_rust/target/release/examples/load_probe')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if sys.platform != 'linux' or not hasattr(time, 'CLOCK_BOOTTIME'):
        p.error('Linux CLOCK_BOOTTIME and /proc are required')
    if not 10 <= args.clock_seconds <= 600:
        p.error('--clock-seconds must be 10..600')
    if args.windows_clock and args.platform != 'wsl':
        p.error('--windows-clock is for WSL')
    if args.platform == 'wsl' and 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        p.error('WSL label requires a Microsoft kernel')
    args.python = args.python.absolute()  # Preserve venv executable symlinks.
    args.binary = args.binary.resolve()
    if not args.python.is_file() or not args.binary.is_file():
        p.error('Prepare the existing load runner first; Python environment or probe missing')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = (args.output or Path.home() / f'Spiral-short-ops-{args.platform}-{stamp}-{os.getpid()}').resolve()
    archive = Path(str(output) + '.tar.gz')
    if output.exists() or archive.exists():
        p.error('choose a new output path')
    os.umask(0o077); output.mkdir(mode=0o700, parents=True)
    kinds = ('clock','interrupt','rss','fds','threads') if args.case == 'all' else (args.case,)
    reports = []
    for kind in kinds:
        print('Starting short case: ' + kind, flush=True)
        report = run_case(kind, args, output); reports.append(report)
        print(kind + ': ' + report['status'], flush=True)
        if report.get('operator_cancelled'):
            break
    summary = {'schema':'spiral-short-operations/v1', 'status':'passed' if all(r['status']=='passed' for r in reports) else 'failed',
               'meaning':'Expected-failure cases pass only when the collector fails for the intended reason and evidence/cleanup checks pass.',
               'runner_sha256':campaign.sha(Path(__file__)), 'cases':reports}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    files = sorted(path for path in output.rglob('*') if path.is_file())
    manifest = {path.relative_to(output).as_posix():campaign.sha(path) for path in files}
    inventory = output / 'SHA256.json'; inventory.write_text(json.dumps(manifest, indent=2) + '\n')
    with tarfile.open(archive, 'x:gz') as packed:
        for path in [*files, inventory]:
            packed.add(path, arcname=output.name+'/'+path.relative_to(output).as_posix(), recursive=False)
    print(json.dumps({'status':summary['status'],'archive':str(archive)}), flush=True)
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
