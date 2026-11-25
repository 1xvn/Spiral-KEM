#!/usr/bin/env python3
"""Run bounded functional CI with count checks; memory evidence is a separate job."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import platform
import shutil
import subprocess
import sys

from evidence import (atomic_json, completed, contract, scratch_result, fresh_result, libtest_result, matching_hash,
                      require, sha, structured_result, unittest_result)

ROOT = Path(__file__).resolve().parents[1]


def source_state():
    names = subprocess.check_output([
        'git', 'ls-files', '-z', '--', '.github/workflows', 'ci', 'protocol_v01',
        'protocol_rust', 'native_research', 'third_party', 'code/opt2', 'rust-toolchain.toml',
    ], cwd=ROOT).decode().split('\0')
    inputs = {}
    for name in names:
        path = Path(name)
        if (name and not {'evidence', 'local_ci_20261107'} & set(path.parts)
                and (path.suffix in {'.py', '.rs', '.toml', '.lock', '.c', '.h', '.txt', '.sh', '.yml'}
                     or path.name == 'Makefile' or (path.parent == Path('ci') and path.suffix == '.json'))):
            inputs[name] = sha((ROOT / path).read_bytes())
    return {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'files': inputs}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--python', default=sys.executable)
    p.add_argument('--cargo', default='cargo')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    # Preserve a venv's executable symlink: resolving it would bypass pyvenv.cfg.
    python = os.path.abspath(shutil.which(args.python) or args.python)
    cargo = shutil.which(args.cargo)
    report = {'started_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'incomplete', 'scope': 'functional checks only; not memory or constant-time approval',
              'checks': [], 'memory_checked': False, 'constant_time_approved': False,
              'runner_sha256': sha(Path(__file__).read_bytes())}
    report['environment'] = {'kernel': platform.release(), 'arch': platform.machine(),
                             'python': platform.python_version()}
    atomic_json(out / 'result.json', report)
    env = os.environ.copy()
    built_hash = None
    before = None
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['LC_ALL'] = 'C'

    def run(name, command, timeout, minimum=None, rust_minimum=None, expected_ignored=0, json_result=None):
        record = {'name': name, 'command': command, 'timeout_seconds': timeout, 'passed': False}
        report['checks'].append(record)
        if json_result is not None:
            fresh_result(json_result)
            record['binary_sha256_before'] = sha(binary.read_bytes())
            matching_hash(built_hash, record['binary_sha256_before'], 'release binary')
        try:
            done = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=timeout)
            stdout, stderr = done.stdout, done.stderr
            record['exit'] = done.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
            record.update(exit=None, timeout=True)
        except OSError as exc:
            stdout, stderr = b'', str(exc).encode()
            record.update(exit=None, execution_error=type(exc).__name__)
        record['classification'] = 'incomplete_or_tool_error'
        try:
            for label, data in (('stdout', stdout), ('stderr', stderr)):
                # Child evidence is from fixture-only tests. Withhold a stream if
                # it contains an obvious private-key encoding.
                require(re.search(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|openssh-key-v1', data) is None,
                        'withheld output containing private-key material')
                path = out / (name + '.' + label)
                path.write_bytes(data)
                record[label] = {'file': path.name, 'sha256': sha(data)}
            completed(record)
            if minimum is not None:
                record['test_identities'] = unittest_result(stderr, minimum, suite=name)
                if json_result is None:
                    require(name == 'native-kem' or not stdout.strip(), 'unexpected unittest stdout')
            if name == 'rust-scratch-cleanup':
                digest = scratch_result(out / 'scratch-cleanup', stdout, stderr)
                record['structured_file'] = {'file': 'scratch-cleanup/result.json', 'sha256': digest}
            if name == 'native-kem':
                require(re.search(rb'(?m)^make: Leaving directory .+\n\Z', stdout) is not None,
                        'incomplete native make output')
            if rust_minimum is not None:
                inventory = contract('test_inventory')[name]
                if name == 'rust-unit' and expected_ignored == 0:
                    inventory = {k: v for k, v in inventory.items() if v != 'ignored'}
                record['test_groups'] = [libtest_result(stdout, rust_minimum, expected_ignored,
                                                       110 if '--features' in command else 0, inventory=inventory)]
            if rust_minimum is not None or command[0] == cargo:
                require(re.search(rb'(?m)^(?:error(?:\[[^\]]+\])?:|test result: FAILED|failures:)', stderr) is None,
                        'Rust tool reported a failure')
            if name in ('rust-release', 'rust-flow-diagnostics-cli'):
                require(re.search(rb'(?m)^ *Finished `[^\n]+` profile .+\n\Z', stderr) is not None,
                        'missing completed Cargo build')
            if json_result is not None:
                data = json_result.read_bytes()
                record['structured_tests'] = structured_result(data, minimum, built_hash, stdout, name)
                record['structured_file'] = {'file': json_result.name, 'sha256': sha(data)}
                record['binary_sha256_after'] = sha(binary.read_bytes())
                matching_hash(built_hash, record['binary_sha256_after'], 'release binary')
        except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError) as error:
            if re.search(rb'(?m)^(?:FAILED(?: |$)|test result: FAILED|FAIL: |ERROR: )', stdout + stderr):
                record['classification'] = 'functional_failure'
            record['error'] = str(error)
            raise RuntimeError(name + ': ' + str(error)) from error
        record.update(passed=True, classification='functional_pass')
        print(name, 'PASS', flush=True)
        return (stdout + stderr).decode()


    try:
        before = source_state()
        atomic_json(out / 'source-before.json', before)
        report['source_before_sha256'] = sha((out / 'source-before.json').read_bytes())
        run('python-protocol', [python, '-m', 'unittest', 'discover', '-s', 'protocol_v01/tests', '-v'], 300, minimum=85)
        run('diagnostic-parser', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/diagnostics', '-p', 'test_*.py', '-v'], 60, minimum=31)
        run('load-collector-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_load_campaign.py', '-v'], 60, minimum=30)
        run('short-operations-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_short_operations.py', '-v'], 60, minimum=10)
        run('clock-observation-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_clock_observation.py', '-v'], 60, minimum=13)
        run('cross-host-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_cross_host_smoke.py', '-v'], 60, minimum=13)
        run('inflight-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_inflight_disconnect.py', '-v'], 60, minimum=12)
        run('backpressure-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_backpressure_contract.py', '-v'], 60, minimum=19)
        run('backpressure-operator-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_slow_consumer.py', '-v'], 60, minimum=5)
        run('server-crash-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_crash_contract.py', '-v'], 60, minimum=19)
        run('server-crash-supervision', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_crash_supervisor.py', '-v'], 60, minimum=11)
        run('server-crash-coordinator', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_server_crash.py', '-v'], 60, minimum=2)
        run('wire-stall-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_wire*.py', '-v'], 60, minimum=42)
        run('session-isolation-contracts', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/validation', '-p', 'test_isolation.py', '-v'], 60, minimum=9)
        run('cc-version', ['cc', '--version'], 30)
        run('openssl-version', ['openssl', 'version'], 30)
        run('python-dependencies', [python, '-m', 'pip', 'check'], 60)
        run('native-kem', ['make', '-C', 'native_research', 'check', 'PYTHON=' + python], 300, minimum=9)
        if not cargo:
            raise RuntimeError('cargo executable not found')
        rustc = env.get('RUSTC') or shutil.which('rustc')
        if not rustc:
            raise RuntimeError('rustc executable not found')
        version = run('rustc-version', [rustc, '-Vv'], 30)
        if not re.search(r'(?m)^release: 1\.99\.1$', version):
            raise RuntimeError('CI requires exact Rust 1.99.1; no silent toolchain substitution')
        cargo_version = run('cargo-version', [cargo, '-V'], 30)
        if not cargo_version.startswith('cargo 1.99.1 '):
            raise RuntimeError('CI requires Cargo 1.99.1')
        cargo_base = ['--locked', '--manifest-path', str(ROOT / 'protocol_rust/Cargo.toml'), '--target-dir', str(ROOT / 'protocol_rust/target'), '-j', '2']
        ignored = 5 if re.search(r'(?m)^host: (?:x86_64|aarch64)-unknown-linux-', version) else 0
        run('rust-unit', [cargo, 'test', '--lib', *cargo_base], 1200, rust_minimum=102, expected_ignored=ignored)
        run('rust-flow-diagnostics', [cargo, 'test', '--lib', '--features', 'flow-diagnostics', 'diagnostic_', *cargo_base], 1200, rust_minimum=3)
        run('rust-wire-observer', [cargo, 'test', '--lib', '--features', 'flow-diagnostics', 'wire_observer_', *cargo_base], 1200, rust_minimum=3)
        # Check the opt-in executable without replacing the default release binary.
        run('rust-flow-diagnostics-cli', [cargo, 'check', '--bin', 'spiral-lab', '--features', 'flow-diagnostics', *cargo_base], 1200)
        run('rust-admission-boundaries', [cargo, 'test', '--test', 'admission_boundaries', *cargo_base], 60, rust_minimum=2)
        run('rust-scratch-cleanup', [python, str(ROOT / 'protocol_rust/validation/scratch_cleanup.py'),
            '--cargo', cargo, '--output', str(out / 'scratch-cleanup')], 1200)
        run('rust-doc', [cargo, 'test', '--doc', *cargo_base], 300, rust_minimum=6)
        run('rust-release', [cargo, 'build', '--release', *cargo_base], 1200)
        binary = ROOT / 'protocol_rust/target/release/spiral-lab'
        built_hash = sha(binary.read_bytes())
        report['binary_sha256_before'] = built_hash
        key_evidence = out / 'key-operations.json'
        run('rust-key-operations', [python, str(ROOT / 'protocol_rust/key_ops_tests.py'),
            '--binary', str(binary), '--json', str(key_evidence)], 300, minimum=11,
            json_result=key_evidence)
        recovery_evidence = out / 'key-recovery.json'
        run('rust-key-recovery', [python, str(ROOT / 'protocol_rust/key_recovery_tests.py'),
            '--binary', str(binary), '--json', str(recovery_evidence)], 300, minimum=20,
            json_result=recovery_evidence)
        auth_evidence = out / 'client-auth-lab.json'
        run('client-auth-lab', [python, str(ROOT / 'protocol_rust/client_auth_tests.py'),
            '--binary', str(binary), '--json', str(auth_evidence)], 120, minimum=2,
            json_result=auth_evidence)
        evidence = out / 'interop.json'
        run('rust-tls', [python, str(ROOT / 'protocol_rust/adversarial.py'), '--binary', str(binary), '--json', str(evidence)], 600, minimum=35, json_result=evidence)
        report['binary_sha256'] = built_hash
        report['cargo_lock_sha256'] = sha((ROOT / 'protocol_rust/Cargo.lock').read_bytes())
        report['status'] = 'passed'
    except (RuntimeError, KeyError, ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report.update(status='failed', error=str(exc))
    finally:
        try:
            if before is not None:
                after = source_state()
                atomic_json(out / 'source-after.json', after)
                report['source_after_sha256'] = sha((out / 'source-after.json').read_bytes())
                require(before == after, 'source, lockfile or toolchain pin changed')
            if built_hash:
                report['binary_sha256_after'] = sha(binary.read_bytes())
                require(report['binary_sha256_after'] == built_hash, 'release binary changed')
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report.update(status='failed', provenance_error=str(exc))
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        atomic_json(out / 'result.json', report)
    print(json.dumps({'status': report['status'], 'memory_checked': False, 'output': str(out)}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
