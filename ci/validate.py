#!/usr/bin/env python3
"""Run bounded functional CI with count checks; memory evidence is a separate job."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


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
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['LC_ALL'] = 'C'

    def run(name, command, timeout, minimum=None, rust_minimum=None, expected_ignored=0, json_result=None):
        record = {'name': name, 'command': command, 'timeout_seconds': timeout, 'passed': False}
        report['checks'].append(record)
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
        text = (stdout + b'\n' + stderr).decode(errors='replace')
        (out / (name + '.log')).write_bytes(stdout + b'\n' + stderr)
        record['log'] = name + '.log'
        passed = record['exit'] == 0
        if minimum is not None:
            matches = re.findall(r'Ran (\d+) tests? in ', text)
            record['tests_run'] = int(matches[-1]) if matches else 0
            passed &= record['tests_run'] >= minimum
            passed &= re.search(r'(?m)^OK\s*$', text) is not None
            passed &= not re.search(r'(?m)^OK \(', text)
        if rust_minimum is not None:
            groups = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
            record['test_groups'] = [{'passed': int(a), 'failed': int(b), 'ignored': int(c)} for a,b,c in groups]
            positive = sorted([g['passed'] for g in record['test_groups'] if g['passed']], reverse=True)
            passed &= bool(positive) and positive[0] >= rust_minimum
            passed &= all(g['failed'] == 0 for g in record['test_groups'])
            passed &= sum(g['ignored'] for g in record['test_groups']) == expected_ignored
        if json_result is not None:
            try:
                data = json.loads(json_result.read_text())
                record['structured_tests'] = {k: data[k] for k in ['tests', 'failures', 'errors']}
                passed &= data['tests'] >= minimum and data['failures'] == 0 and data['errors'] == 0
            except (OSError, ValueError, KeyError, TypeError) as exc:
                passed = False
                record['json_error'] = str(exc)
        record['passed'] = bool(passed)
        print(name, 'PASS' if passed else 'FAIL', flush=True)
        if not passed:
            print(text[-6000:], file=sys.stderr)
            raise RuntimeError(name)
        return text

    try:
        run('python-protocol', [python, '-m', 'unittest', 'discover', '-s', 'protocol_v01/tests', '-v'], 300, minimum=85)
        run('diagnostic-parser', [python, '-m', 'unittest', 'discover', '-s', 'protocol_rust/diagnostics', '-p', 'test_*.py', '-v'], 60, minimum=20)
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
        ignored = 5 if re.search(r'(?m)^host: x86_64-', version) else 0
        run('rust-unit', [cargo, 'test', '--lib', *cargo_base], 1200, rust_minimum=70, expected_ignored=ignored)
        run('rust-doc', [cargo, 'test', '--doc', *cargo_base], 300, rust_minimum=4)
        run('rust-release', [cargo, 'build', '--release', *cargo_base], 1200)
        binary = ROOT / 'protocol_rust/target/release/spiral-lab'
        evidence = out / 'interop.json'
        run('rust-tls', [python, str(ROOT / 'protocol_rust/adversarial.py'), '--binary', str(binary), '--json', str(evidence)], 600, minimum=35, json_result=evidence)
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['cargo_lock_sha256'] = hashlib.sha256((ROOT / 'protocol_rust/Cargo.lock').read_bytes()).hexdigest()
        report['status'] = 'passed'
    except (RuntimeError, KeyError, ValueError, OSError) as exc:
        report.update(status='failed', error=str(exc))
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'memory_checked': False, 'output': str(out)}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
