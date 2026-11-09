#!/usr/bin/env python3
"""Read uploaded receipts, verify fixed Git inputs and logs, and write reviews.

No uploaded code is executed, no archive is extracted, and no Rust/TLS test is
rerun. The ELF and tool binaries are absent: their reported hashes are checked
for agreement, not independently recomputed from binaries.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib

REPO = Path(__file__).resolve().parents[3]
SOURCE_COMMIT = '0b0db39d36b9a6f243486615ca2624a6b76ce02b'
RUNTIME_BASE = '486697682beb66db1af05bdc45867d122a25d145'
BUNDLE_HASH = 'ef11e2be82944e7cad1fea88cea09f4c8f2de1319367860786dbae4107f054bd'
MANIFEST_HASH = 'e60c9fe1da07e0db98fb20327646a0c4837a550419d7fee4ca080ba433e9730b'
RUST_COMMIT = '58cf8f9c35b355199727627d07ae34a4e2846d67'
CARGO_COMMIT = '5f94df4789f005f9a352888e8355ffc645b7ed0e'
GATES = ('memory_checked', 'memory_cleanup_approved', 'production_memory_passed',
         'constant_time_approved', 'whole_goal_2_approved', 'whole_goal_5_approved',
         'deployment_approved')
SCOPE = 'Linux key-file policy, public-only CLI output, local restored-file agreement, and loopback TLS key rotation'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError('nonfinite JSON number: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def archive_files(path):
    require(path.stat().st_size < 16 * 1024 * 1024, 'unexpected archive size')
    root = path.name.removesuffix('.tar.gz')
    result = {}
    total = 0
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        require(0 < len(members) < 1000, 'unexpected member count')
        for member in members:
            parts = PurePosixPath(member.name).parts
            require(member.isfile() and parts and parts[0] == root
                    and not member.name.startswith('/') and '\\' not in member.name
                    and all(part not in ('', '.', '..') for part in member.name.split('/')),
                    'unsafe archive entry')
            name = '/'.join(parts[1:])
            require(name and name not in result, 'empty or duplicate archive member')
            total += member.size
            require(0 <= member.size <= 8 * 1024 * 1024 and total <= 32 * 1024 * 1024,
                    'archive expansion limit')
            result[name] = archive.extractfile(member).read()
    return result


def fixed_sources():
    path = REPO / 'downloads/key-operations-0b0db39/Spiral-key-operations-0b0db39.tar.gz'
    require(sha(path.read_bytes()) == BUNDLE_HASH, 'reference delivery hash mismatch')
    bundle = archive_files(path)
    raw = bundle['SOURCE.json']
    require(sha(raw) == MANIFEST_HASH, 'reference manifest hash mismatch')
    manifest = decode(raw)
    require(manifest['source_commit'] == SOURCE_COMMIT
            and manifest['runtime_base_commit'] == RUNTIME_BASE, 'reference commit mismatch')
    files = manifest['files']
    require(len(files) == 318, 'reference source inventory changed')
    git_tar = subprocess.check_output(['git', 'archive', '--format=tar', SOURCE_COMMIT, '--',
                                       *sorted(files)], cwd=REPO)
    observed = {}
    with tarfile.open(fileobj=io.BytesIO(git_tar)) as archive:
        for member in archive:
            if member.isdir():
                continue
            require(member.isfile() and member.name in files, 'unexpected Git source')
            observed[member.name] = sha(archive.extractfile(member).read())
    require(observed == files, 'delivery source inventory differs from Git')
    require(all(sha(bundle['source/' + name]) == value for name, value in files.items()),
            'delivery source bytes differ from manifest')
    return raw, files, bundle


def rust_rows(text):
    parsed = re.findall(r'^test (\S+) \.\.\. ([^\n]+)$', text, re.MULTILINE)
    require(len(parsed) == 86 and len({name for name, _ in parsed}) == 86,
            'missing, duplicate or extra Rust test status rows')
    require(all(status == 'ok' or status == 'ignored' or status.startswith('ignored,')
                for _, status in parsed), 'Rust test failed or had an unexpected status')
    rows = {name: ('ok' if status == 'ok' else 'ignored') for name, status in parsed}
    require(list(rows.values()).count('ok') == 81
            and list(rows.values()).count('ignored') == 5, 'Rust test identity/status counts differ')
    summary = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.MULTILINE)
    require(summary == [('81', '0', '5', '0', '0')], 'Rust summary differs')
    return rows


def key_test_rows(text, expected_tests):
    total = re.findall(r'^test_\S+ \([^\n]+\) \.\.\. [^\n]+$', text, re.MULTILINE)
    rows = re.findall(r'^(test_\w+) \(__main__\.KeyOperations\.(test_\w+)\) \.\.\. ([^\n]+)$', text, re.MULTILINE)
    require(len(total) == len(rows) == 11 and len({a for a, _, _ in rows}) == 11
            and all(a == b and status == 'ok' for a, b, status in rows)
            and {a for a, _, _ in rows} == expected_tests,
            'key operation test identities/status differ')
    require(re.search(r'^Ran 11 tests in [^\n]+\n\nOK\s*\Z', text, re.MULTILINE),
            'key operation final OK missing or trailing output present')


def review(path, label, raw_manifest, source_files, bundle, expected_rust, expected_nested):
    items = archive_files(path)
    hashes = decode(items['SHA256.json'])
    require(set(items) == set(hashes) | {'SHA256.json'}, 'result manifest omits/adds files')
    require(all(sha(items[name]) == value for name, value in hashes.items()), 'result file hash mismatch')
    require(items['source-manifest.json'] == raw_manifest, 'submitted source manifest differs')
    before, after = (decode(items[name]) for name in ('source-before.json', 'source-after.json'))
    require(before == after == source_files, 'before/after source hashes differ from Git')
    report = decode(items['result.json'])
    require(report['schema'] == 'spiral-key-operations-platform/v1'
            and report['status'] == 'passed' and report['platform_tests_passed'] is True
            and report['check_only'] is False and report['source_unchanged'] is True,
            'not a successful full focused platform receipt')
    require(report['source_commit'] == SOURCE_COMMIT and report['runtime_base_commit'] == RUNTIME_BASE
            and report['manifest_sha256'] == MANIFEST_HASH, 'unexpected source identity')
    require(all(report[key] is False for key in GATES), 'broader approval gate changed')
    tree_hash = sha(json.dumps(source_files, sort_keys=True, separators=(',', ':')).encode())
    require(report['source_tree_sha256_before'] == report['source_tree_sha256_after'] == tree_hash,
            'source tree digest mismatch')
    arch = {'oci': 'aarch64', 'wsl': 'x86_64'}[label]
    host = report['host']
    require(report['requested_platform'] == host['requested_platform'] == host['evidence_label'] == label
            and host['architecture'] == host['uname']['machine'] == arch
            and host['uname']['system'] == 'Linux' and type(host['effective_uid']) is int
            and host['effective_uid'] != 0 and host['oci_provider_attested'] is False,
            'platform/UID evidence mismatch')
    microsoft = 'microsoft' in (host['uname']['release'] + host['uname']['version'] + host['proc_version']).lower()
    require(microsoft == (label == 'wsl') == host['microsoft_kernel_evidence'], 'kernel evidence mismatch')
    commands = report['commands']
    names = [row['name'] for row in commands]
    expected_names = ['rustup-rustc', 'rustup-cargo', 'rustc-version', 'cargo-version',
                      'cc-version', 'ar-version', 'openssl-version', 'python-base', 'python-venv',
                      'python-install', 'python-version', 'python-pins', 'python-pip-check',
                      'python-freeze', 'rust-library-tests', 'release-build', 'key-operations']
    require(names == expected_names, 'unexpected command sequence')
    public = {'result.json', 'source-manifest.json', 'source-before.json', 'source-after.json',
              'requirements.txt', 'key_operations.json', 'SHA256.json'}
    timeouts = {'python-install': 900, 'rust-library-tests': 1800, 'release-build': 1800,
                'key-operations': 300}
    for row in commands:
        require(row['returncode'] == 0 and row['status'] == 'passed' and not row.get('timed_out'),
                'command failed or timed out')
        require(0 <= row['elapsed_seconds'] < row['timeout_seconds'], 'command exceeded its watchdog')
        require(row['timeout_seconds'] == timeouts.get(row['name'], 120), 'unexpected command timeout')
        require(row['stdout'] == 'logs/' + row['name'] + '.stdout.log'
                and row['stderr'] == 'logs/' + row['name'] + '.stderr.log', 'unexpected log path')
        public.update((row['stdout'], row['stderr']))
    require(set(items) == public and len(items) == 41, 'unexpected public/private result entries')
    def log(name, stream='stdout'):
        return items['logs/' + name + '.' + stream + '.log'].decode()
    tool = report['toolchain']
    for name, commit in (('rustc', RUST_COMMIT), ('cargo', CARGO_COMMIT)):
        text = log(name + '-version').strip()
        require(text == tool[name] and 'release: 1.99.1' in text.splitlines()
                and 'commit-hash: ' + commit in text.splitlines()
                and 'host: ' + arch + '-unknown-linux-gnu' in text.splitlines(), 'toolchain log mismatch')
    require(tool['host'] == arch + '-unknown-linux-gnu', 'outer toolchain host mismatch')
    observed_rust = rust_rows(log('rust-library-tests'))
    require(observed_rust == expected_rust, 'Rust test identities differ from fixed-source local receipt')
    require(report['rust_library_tests'] == {'passed': 81, 'failed': 0, 'ignored': 5,
                                           'measured': 0, 'filtered_out': 0}, 'outer Rust counts mismatch')
    require('Finished `release` profile [optimized]' in log('release-build', 'stderr'), 'release build completion missing')
    lock = tomllib.loads(bundle['source/protocol_rust/Cargo.lock'].decode())
    locked_packages = {(package['name'], package['version']) for package in lock['package']}
    for name in ('rust-library-tests', 'release-build'):
        compiled = set(re.findall(r'^\s+Compiling ([\w-]+) v([^\s]+)', log(name, 'stderr'), re.MULTILINE))
        require(compiled and compiled <= locked_packages, 'compiled package versions differ from Cargo.lock')
        for crate in ('digest', 'hmac', 'hkdf', 'ed25519-dalek', 'curve25519-dalek'):
            require(re.search(r'^\s+Compiling ' + re.escape(crate)
                              + r' v\S+ \([^\n]+/source/third_party/rustcrypto/'
                              + re.escape(crate) + r'\)$', log(name, 'stderr'), re.MULTILINE),
                    'local dependency patch build evidence missing: ' + crate)
    for name in ('rust-library-tests', 'release-build'):
        argv = commands[names.index(name)]['command']
        require('--locked' in argv and '--target-dir' in argv, 'Cargo lock/target isolation missing')
    command_by_name = {row['name']: row['command'] for row in commands}
    rustc_path = log('rustup-rustc').strip()
    cargo_path = log('rustup-cargo').strip()
    require(command_by_name['rustc-version'] == [rustc_path, '-vV']
            and command_by_name['cargo-version'] == [cargo_path, '-Vv'], 'tool command shape differs')
    lib_argv = command_by_name['rust-library-tests']
    require(len(lib_argv) == 10, 'unexpected Rust library argument count')
    # Derive paths from the fixed command shape, then reject any extra flags.
    target, source_manifest = lib_argv[7], lib_argv[9]
    require(PurePosixPath(target).is_absolute() and PurePosixPath(target).name == 'BUILD'
            and PurePosixPath(target).parent.name == path.name.removesuffix('.tar.gz')
            and PurePosixPath(source_manifest).is_absolute()
            and source_manifest.endswith('/Spiral-key-operations-0b0db39/source/protocol_rust/Cargo.toml'),
            'unexpected build/source paths')
    common = ['--locked', '-j', '2', '--target-dir', target, '--manifest-path', source_manifest]
    require(lib_argv == [cargo_path, 'test', '--lib', *common]
            and command_by_name['release-build'] == [cargo_path, 'build', '--release', *common],
            'Cargo test/build command differs from focused collection')
    source_root = PurePosixPath(source_manifest).parents[1]
    require(command_by_name['key-operations'] == [report['python']['executable'], '-I', '-B',
            str(source_root / 'protocol_rust/key_ops_tests.py'), '--binary',
            str(PurePosixPath(target) / 'release/spiral-lab'), '--json',
            str(PurePosixPath(target).parent / 'key_operations.json')], 'key operation command shape differs')
    parsed = ast.parse(bundle['source/protocol_rust/key_ops_tests.py'])
    cls = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == 'KeyOperations')
    expected_tests = {node.name for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
    key_log = log('key-operations', 'stderr')
    key_test_rows(key_log, expected_tests)
    key = decode(items['key_operations.json'])
    require(key['schema'] == 'spiral-rust-key-operations/v1'
            and key['scope'] == report['scope'] == SCOPE, 'unexpected nested schema or scope')
    require(decode(log('key-operations')) == key, 'raw key report differs from saved JSON')
    for field, expected in (('tests', 11), ('failures', 0), ('errors', 0), ('skipped', 0)):
        require(type(key[field]) is int and key[field] == expected, 'key operation count mismatch')
    require(key['status'] == 'passed' and key['source_and_binary_unchanged'] is True
            and key['failed_tests'] == key['error_tests'] == []
            and key['effective_uid'] == host['effective_uid'], 'key operation status/UID mismatch')
    require(key['platform'] == host['uname'], 'nested/outer host metadata mismatch')
    require(report['key_operations'] == {field: value for field, value in key.items()
                                        if field in ('tests', 'failures', 'errors', 'skipped', 'status')},
            'outer/nested key summaries differ')
    nested = key['source_sha256']
    require(nested == expected_nested and len(nested) == 181 and all(name in source_files and source_files[name] == value
                                     for name, value in nested.items()), 'nested source hashes differ from Git')
    require(key['runner_sha256'] == source_files['protocol_rust/key_ops_tests.py'], 'runner hash mismatch')
    binary_hash = key['binary_sha256']
    require(re.fullmatch('[a-f0-9]{64}', binary_hash)
            and report['binary_sha256_before'] == report['binary_sha256_after'] == binary_hash,
            'reported binary hashes disagree')
    pins = dict(line.split('==') for line in items['requirements.txt'].decode().splitlines() if line.strip())
    require(items['requirements.txt'] == bundle['source/protocol_v01/requirements.txt']
            and report['python']['requirements_sha256'] == sha(items['requirements.txt'])
            and report['python']['pinned_requirements'] == report['python']['installed_pins'] == decode(log('python-pins')) == pins,
            'Python requirement pins differ')
    require('No broken requirements found.' in log('python-pip-check'), 'pip check completion missing')
    normalize = lambda name: re.sub(r'[-_.]+', '-', name).lower()
    frozen = {normalize(name): version for name, version in
              (line.split('==', 1) for line in log('python-freeze').splitlines() if '==' in line)}
    require(all(frozen.get(normalize(name)) == version for name, version in pins.items()),
            'Python freeze versions differ from pinned requirements')
    python = decode(log('python-version'))
    require(python['version'] == report['python']['version'] and python['version'][:2] == [3, 12]
            and python['prefix'] != python['base_prefix'], 'Python version/venv mismatch')
    require(not any(b'-----BEGIN PRIVATE KEY-----' in data or b'-----BEGIN RSA PRIVATE KEY-----' in data
                    or b'-----BEGIN EC PRIVATE KEY-----' in data for data in items.values()), 'private PEM found')
    return {'schema': 'spiral-key-operations-receipt-review/v1', 'status': 'accepted',
            'reviewer_sha256': sha(Path(__file__).read_bytes()),
            'archive': path.name, 'archive_sha256': sha(path.read_bytes()), 'archive_bytes': path.stat().st_size,
            'archive_members': len(items), 'result_hashes_verified': len(hashes),
            'source_commit': SOURCE_COMMIT, 'runtime_base_commit': RUNTIME_BASE,
            'manifest_sha256': MANIFEST_HASH, 'source_files_matched_to_git': len(source_files),
            'nested_source_files_matched_to_git': len(nested),
            'source_before_after_equal': True, 'reported_binary_hashes_agree': True,
            'binary_sha256': binary_hash, 'requested_platform': label,
            'architecture': arch, 'effective_uid': host['effective_uid'],
            'kernel': host['uname']['release'], 'rustc_commit': RUST_COMMIT, 'cargo_commit': CARGO_COMMIT,
            'rust_tests': report['rust_library_tests'], 'key_operations': report['key_operations'],
            'raw_test_identities_verified': True, 'commands_passed': len(commands),
            'compiled_package_versions_match_lock': True, 'local_dependency_patches_compiled': 5,
            'python_version': python['version'], 'pinned_python_packages': pins,
            'gates': {name: False for name in GATES},
            'scope': report['scope'], 'machine_identity_independently_attested': False,
            'binary_and_tool_bytes_included': False,
            'new_full_ci_or_memory_or_fuzz_or_load_tests': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci', type=Path, required=True)
    parser.add_argument('--wsl', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    raw, source_files, bundle = fixed_sources()
    local = REPO / 'protocol_rust/evidence/key_operations_platforms_20261109/Spiral-key-ops-local-x86_64-20261109T123503Z-or6bhpgw.tar.gz'
    require(sha(local.read_bytes()) == 'd2e255e85855babcb5df4ce69455ef078a02e4e05895884390254818df2fabbf', 'local reference receipt hash mismatch')
    local_files = archive_files(local)
    expected_rust = rust_rows(local_files['logs/rust-library-tests.stdout.log'].decode())
    expected_nested = decode(local_files['key_operations.json'])['source_sha256']
    reviews = {label: review(path, label, raw, source_files, bundle, expected_rust, expected_nested)
               for label, path in (('oci', args.oci), ('wsl', args.wsl))}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for label, result in reviews.items():
        (args.output_dir / (label + '-review.json')).write_text(json.dumps(result, indent=2) + '\n')
    summary = {'schema': 'spiral-key-operations-two-platform-review/v1', 'status': 'accepted',
               'reviewer_sha256': sha(Path(__file__).read_bytes()),
               'reviewed_utc': datetime.now(timezone.utc).isoformat(), 'source_commit': SOURCE_COMMIT,
               'runtime_base_commit': RUNTIME_BASE, 'platform_key_operations_validation_complete': True,
               'source_files_verified_per_platform': len(source_files),
               'rust_passed_per_platform': 81, 'rust_ignored_per_platform': 5,
               'key_operations_passed_per_platform': 11, 'key_operations_failed_or_skipped': 0,
               'platforms': {label: {'archive': data['archive'], 'archive_sha256': data['archive_sha256'],
                                     'review': label + '-review.json'} for label, data in reviews.items()},
               'gates': {name: False for name in GATES}}
    (args.output_dir / 'platform-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
