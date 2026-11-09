#!/usr/bin/env python3
"""Run the bounded private-scratch and feature compatibility matrix.

This is a focused harness, not the complete upstream dev/test suites. It does not
approve constant time, all secret copies, or production memory cleanliness.
"""
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

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / 'third_party/rustcrypto'
TEMPLATES = Path(__file__).with_suffix('')
PACKAGES = ('digest', 'hmac', 'hkdf', 'ed25519-dalek', 'curve25519-dalek')
HARNESS_NAMES = ('hmac', 'hkdf', 'signing', 'owners')
MATRIX = (
    ('hmac-on', 'hmac', ['--lib'], [1]),
    ('hmac-off', 'hmac', ['--lib', '--no-default-features'], [1]),
    ('hkdf-on', 'hkdf', ['--lib', '--test', 'cleanup_compat', '--features', 'zeroize'], [5, 2]),
    ('hkdf-off', 'hkdf', ['--test', 'cleanup_compat', '--no-default-features'], [2]),
    ('signing-on', 'signing', ['--lib', '--features', 'digest'], [6]),
    ('signing-off', 'signing', ['--test', 'feature_off', '--no-default-features', '--features', 'fast,digest'], [1]),
    ('scratch-live-owners', 'owners', ['--lib', '--features', 'zeroize'], [5]),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def quoted(path):
    return json.dumps(str(path), ensure_ascii=False)


def patch_table():
    return '\n[patch.crates-io]\n' + ''.join(
        name + ' = { path = ' + quoted(VENDOR / name) + ' }\n' for name in PACKAGES)


def write_manifest(directory, text):
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'Cargo.toml').write_text(text + patch_table())


def prepare_harnesses(out):
    """Build isolated manifests; main requires all four retained lockfile seeds."""
    harnesses = out / 'harnesses'
    harnesses.mkdir()
    write_manifest(harnesses / 'hmac', '''[package]
name = "scratch-hmac-compat"
version = "0.0.0"
edition = "2021"
publish = false
[workspace]
[lib]
path = "lib.rs"
[features]
default = ["cleanup"]
cleanup = ["hmac/zeroize", "sha2/zeroize"]
[dependencies]
hmac = "=0.13.0"
sha2 = "=0.11.1"
''')
    shutil.copyfile(TEMPLATES / 'hmac_vectors.rs', harnesses / 'hmac/lib.rs')
    write_manifest(harnesses / 'hkdf', '''[package]
name = "scratch-hkdf-compat"
version = "0.0.0"
edition = "2024"
publish = false
[workspace]
[lib]
name = "hkdf"
path = ''' + quoted(VENDOR / 'hkdf/src/lib.rs') + '''
[features]
zeroize = ["dep:zeroize", "hmac/zeroize"]
[dependencies]
hmac = "=0.13.0"
zeroize = { version = "=1.9.1", optional = true, default-features = false }
[dev-dependencies]
sha2 = { version = "=0.11.1", default-features = false, features = ["zeroize"] }
[[test]]
name = "cleanup_compat"
path = ''' + quoted(VENDOR / 'hkdf/tests/cleanup_compat.rs') + '\n')
    write_manifest(harnesses / 'signing', '''[package]
name = "ed25519-dalek"
version = "3.0.0"
edition = "2024"
publish = false
[workspace]
[lib]
name = "ed25519_dalek"
path = "src/lib.rs"
[features]
default = ["fast", "cleanup"]
cleanup = ["zeroize", "sha2/zeroize"]
fast = ["curve25519-dalek/precomputed-tables"]
zeroize = ["dep:zeroize", "curve25519-dalek/zeroize"]
alloc = ["curve25519-dalek/alloc", "ed25519/alloc", "zeroize?/alloc"]
digest = ["dep:signature", "signature/digest"]
hazmat = []
legacy_compatibility = ["curve25519-dalek/legacy_compatibility"]
batch = []
serde = []
rand_core = []
pem = []
pkcs8 = []
[dependencies]
curve25519-dalek = { version = "=5.0.0", features = ["digest"], default-features = false }
ed25519 = { version = "=3.0.0", default-features = false }
sha2 = { version = "=0.11.1", default-features = false }
subtle = { version = "=2.6.1", default-features = false }
zeroize = { version = "=1.9.1", default-features = false, optional = true }
signature = { version = "=3.0.0", default-features = false, optional = true }
[dev-dependencies]
hex = "=0.4.3"
[[test]]
name = "feature_off"
path = "feature_off.rs"
''')
    shutil.copytree(VENDOR / 'ed25519-dalek/src', harnesses / 'signing/src')
    changes = {}
    for name, old in (
        ('hazmat.rs', '#[cfg(test)]\nmod test {'),
        ('context.rs', '#[cfg(all(test, feature = "digest"))]\nmod test {'),
    ):
        path = harnesses / 'signing/src' / name
        original = path.read_text()
        require(original.count(old) == 1, 'upstream test-module boundary changed: ' + name)
        path.write_text(original.replace(old, '#[cfg(any())]\nmod test {'))
        changes[name] = {'from': old, 'to': '#[cfg(any())]\nmod test {'}
    identity = {'scope': 'Actual production source plus new scratch tests; two upstream-only dev test modules disabled in this copy.',
                'source_files': {}, 'prepared_files': {}, 'exact_test_only_replacements': changes}
    for original in sorted((VENDOR / 'ed25519-dalek/src').rglob('*.rs')):
        relative = str(original.relative_to(VENDOR / 'ed25519-dalek/src'))
        prepared = harnesses / 'signing/src' / relative
        identity['source_files'][relative] = digest(original)
        identity['prepared_files'][relative] = digest(prepared)
        require(relative in changes or digest(original) == digest(prepared), 'unexpected signing source transformation')
    (out / 'signing-source-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    shutil.copyfile(TEMPLATES / 'signing_compat.rs', harnesses / 'signing/feature_off.rs')
    write_manifest(harnesses / 'owners', '''[package]
name = "scratch-live-owners"
version = "0.0.0"
edition = "2021"
publish = false
[workspace]
[lib]
path = "lib.rs"
[features]
zeroize = ["dep:zeroize", "digest/zeroize"]
[dependencies]
zeroize = { version = "=1.9.1", default-features = false, optional = true }
digest = { version = "=0.11.3", default-features = false }
''')
    (harnesses / 'owners/lib.rs').write_text(''.join(
        '#[path = ' + quoted(VENDOR / name / 'src/secret_scratch.rs') + ']\nmod ' + module + ';\n'
        for name, module in [('digest', 'digest_owner'), ('hmac', 'hmac_owner'), ('curve25519-dalek', 'curve_owner')]))
    for name in HARNESS_NAMES:
        seed = TEMPLATES / (name + '.Cargo.lock')
        if seed.is_file():
            shutil.copyfile(seed, harnesses / name / 'Cargo.lock')
    return harnesses


def source_hashes():
    files = [Path(__file__)] + [p for p in TEMPLATES.rglob('*') if p.is_file()]
    for package in PACKAGES:
        files += [p for p in (VENDOR / package).rglob('*') if p.is_file()
                  and (p.suffix == '.rs' or p.name in ('Cargo.toml', 'Cargo.toml.orig'))]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(files)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.expanduser().resolve()
    if out.is_relative_to(VENDOR) or out.is_relative_to(TEMPLATES):
        parser.error('output must be outside vendored source and validation templates')
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'spiral-scratch-cleanup-validation/v1', 'status': 'incomplete',
              'scope': 'Focused cleanup and compatibility matrix; not the complete upstream dev/test suites.',
              'limitations': ['Upstream optional kdf feature and dev dependency suites are not included.',
                              'Signing source copy disables only the recorded upstream hazmat/context test modules.',
                              'Finite witnesses do not prove all historical/backend/register copies were erased.'],
              'constant_time_approved': False, 'production_memory_passed': False,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'checks': []}
    env = dict(os.environ, LC_ALL='C', RUST_BACKTRACE='0')
    # Prevent ambient filters/target/features from silently changing this matrix.
    for name in ('CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUST_TEST_THREADS', 'RUST_TEST_NOCAPTURE'):
        env.pop(name, None)
    try:
        cargo = shutil.which(args.cargo)
        require(bool(cargo), 'Cargo executable missing')
        for name in HARNESS_NAMES:
            require((TEMPLATES / (name + '.Cargo.lock')).is_file(), 'retained lockfile missing: ' + name)
        report['source_sha256'] = source_hashes()
        report['source_tree_sha256'] = hashlib.sha256(json.dumps(report['source_sha256'], sort_keys=True).encode()).hexdigest()
        harnesses = prepare_harnesses(out)
        report['signing_source_identity'] = 'signing-source-identity.json'
        for label, name, selection, expected in MATRIX:
            command = [cargo, 'test', '--locked', '--manifest-path', str(harnesses / name / 'Cargo.toml'),
                       '--target-dir', str(out / 'target'), '-j', '2', *selection, '--', '--test-threads=1']
            record = {'name': label, 'command': command, 'expected_group_counts': expected, 'passed': False}
            report['checks'].append(record)
            print(label, flush=True)
            try:
                done = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=600)
                text = (done.stdout + b'\n' + done.stderr).decode(errors='replace')
                record['exit'] = done.returncode
            except subprocess.TimeoutExpired as error:
                text = ((error.stdout or b'') + b'\n' + (error.stderr or b'')).decode(errors='replace')
                record.update(exit=None, timed_out=True)
            (out / (label + '.log')).write_text(text)
            record['log'] = label + '.log'
            groups = [tuple(map(int, group)) for group in re.findall(
                r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text)]
            record['test_groups'] = [{'passed': a, 'failed': b, 'ignored': c, 'measured': d, 'filtered_out': e}
                                     for a, b, c, d, e in groups]
            require(record['exit'] == 0, label + ' exited unsuccessfully; raw log retained')
            require(sorted(a for a, *_ in groups) == sorted(expected), label + ' missing/extra/zero test group')
            require(all(a > 0 and b == c == d == e == 0 for a, b, c, d, e in groups), label + ' failed/skipped/filtered tests')
            record['passed'] = True
        require(len(report['checks']) == len(MATRIX), 'matrix incomplete')
        require(source_hashes() == report['source_sha256'], 'source or templates changed during validation')
        report['source_unchanged'] = True
        report['tests'] = sum(g['passed'] for c in report['checks'] for g in c['test_groups'])
        report['status'] = 'passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(str(error), file=sys.stderr)
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'tests': report.get('tests', 0), 'output': str(out)}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
