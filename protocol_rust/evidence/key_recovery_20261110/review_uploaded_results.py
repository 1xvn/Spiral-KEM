#!/usr/bin/env python3
"""Verify the fixed uploaded recovery receipts without executing their code.

Reads tar members in memory, checks their hashes and logs against fixed Git
inputs, and writes review JSON. No extraction, build, crypto test, or network
operation is performed. Binary/tool hashes are declarations because those
bytes are absent from the public receipts.
"""
import argparse
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
HELPER = HERE.parent / 'key_operations_platforms_20261109/review_uploaded_results.py'
HELPER_SHA256 = 'bdfb76603d13ae034302290d6d24e8805e2ff564d8315b1bbe57890f00bff54b'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != HELPER_SHA256:
    raise ValueError('trusted archive/JSON helper hash changed')
_spec = importlib.util.spec_from_file_location('trusted_receipt_helpers', HELPER)
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)
archive_files, decode, sha, require = (_helper.archive_files, _helper.decode,
                                      _helper.sha, _helper.require)

SOURCE_COMMIT = 'd4c46bc81012e095ab8c78ac6e362ce2b6a63798'
RUNTIME_BASE = 'd2f19b9e733359f14331d7064a41697c851a1d80'
BUNDLE_SHA256 = 'fafa96381b1cca98b9ae9e87e04880f84d19440bfbc93df3e5c7c149878dbc10'
MANIFEST_SHA256 = '20707a5119e58d55fd8f133120b2a70bdca2ed17b5d787972c9101084d9f8c63'
LOCAL = 'Spiral-key-recovery-local-x86_64-20261109T212757Z-1m3ydfz5.tar.gz'
LOCAL_SHA256 = 'e89355705dad2392ae72cad3e07750989b708f93d62009f43e678b74239e3474'
UPLOAD_SHA256 = {
    'oci': 'e7bfd6ec799f224bb8cefb03a3a16be113a2c125654301224c94c8882938d373',
    'wsl': 'b260fcd5a4174949e2cadda34f7c2565bab26ad188b7f2d5f41c927b800a1d92',
}
RUST_COMMIT = '58cf8f9c35b355199727627d07ae34a4e2846d67'
CARGO_COMMIT = '5f94df4789f005f9a352888e8355ffc645b7ed0e'
GATES = ('memory_checked', 'memory_cleanup_approved', 'production_memory_passed',
         'constant_time_approved', 'whole_goal_2_approved', 'whole_goal_5_approved',
         'deployment_approved')
SCOPE = 'encrypted auth-seed and TLS-PEM backup/restore and cold rotation recovery lab'
BASE_SCOPE = 'Linux key-file policy, public-only CLI output, local restored-file agreement, and loopback TLS key rotation'
RECOVERY_SCOPE = 'Linux encrypted auth/TLS backup and externally pinned recovery, strict public CLI reports, private-file policy, and finite loopback TLS cold rotation drills'
DRILL_LIMITS = 'Temporary lab identities only; no service or vault integration, automatic production rollback, or rollback of a compromised identity is exercised.'
PINS = {'cryptography': '50.0.2', 'pyOpenSSL': '26.4.0', 'cffi': '2.1.1',
        'pycparser': '3.12', 'typing_extensions': '4.16.0'}
COMMANDS = ['rustup-rustc', 'rustup-cargo', 'rustc-version', 'cargo-version',
            'cc-version', 'ar-version', 'openssl-version', 'python-base', 'python-venv',
            'python-install', 'python-version', 'python-pins', 'python-pip-check',
            'python-freeze', 'rust-library-tests', 'release-build', 'key-operations',
            'key-recovery']
RUST_COUNTS = {'passed': 94, 'failed': 0, 'ignored': 5, 'measured': 0, 'filtered_out': 0}
PYTHON_PROBE = 'import json,sys,ssl;print(json.dumps(dict(version=list(sys.version_info[:3]),executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,openssl=ssl.OPENSSL_VERSION)))'
PINS_PROBE = "import importlib.metadata,json;print(json.dumps({name:importlib.metadata.version(name) for name in ['cryptography', 'pyOpenSSL', 'cffi', 'pycparser', 'typing_extensions']}))"


def hashed_members(path, expected_hash):
    require(sha(path.read_bytes()) == expected_hash, 'unexpected archive SHA-256: ' + path.name)
    items = archive_files(path)
    hashes = decode(items['SHA256.json'])
    require(set(items) == set(hashes) | {'SHA256.json'}, 'result inventory differs from hash manifest')
    require(all(sha(items[name]) == value for name, value in hashes.items()), 'member hash mismatch')
    return items, len(hashes)


def rust_rows(text):
    """Consume the entire Rust log, including its sole terminal summary."""
    match = re.fullmatch(
        r'\nrunning 99 tests\n((?:test [^\n]+\n)+)\n'
        r'test result: ok\. 94 passed; 0 failed; 5 ignored; 0 measured; '
        r'0 filtered out; finished in [0-9]+(?:\.[0-9]+)?s\n*', text)
    require(match is not None, 'Rust log structure or final summary differs')
    rows = {}
    for line in match[1].splitlines():
        row = re.fullmatch(r'test (\S+) \.\.\. (ok|ignored(?:, [^\n]+)?)', line)
        require(row is not None, 'Rust failed or unexpected status row')
        name, status = row.groups()
        require(name not in rows, 'duplicate Rust test identity')
        rows[name] = 'ok' if status == 'ok' else 'ignored'
    require(len(rows) == 99 and list(rows.values()).count('ok') == 94
            and list(rows.values()).count('ignored') == 5, 'Rust identity/status counts differ')
    return rows


def key_test_rows(text, class_name, expected):
    """Consume complete unittest output; OK must end the actual log."""
    match = re.fullmatch(
        r'((?:test_[^\n]*\n)+)\n-{10,}\nRan ' + str(len(expected))
        + r' tests in [0-9]+(?:\.[0-9]+)?s\n\nOK\n*', text)
    require(match is not None, class_name + ' final OK/summary missing or extra output present')
    names = []
    for line in match[1].splitlines():
        row = re.fullmatch(r'(test_\w+) \(__main__\.' + re.escape(class_name)
                           + r'\.(test_\w+)\) \.\.\. ok', line)
        require(row is not None and row[1] == row[2], class_name + ' failed/skipped/unexpected status')
        names.append(row[1])
    require(len(names) == len(set(names)) == len(expected) and set(names) == expected,
            class_name + ' missing, duplicate or extra test identity')
    return sorted(names)


def method_names(bundle, runner, class_name):
    parsed = ast.parse(bundle['source/protocol_rust/' + runner])
    classes = [node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    require(len(classes) == 1, 'reference test class differs')
    names = [node.name for node in classes[0].body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')]
    require(len(names) == len(set(names)), 'duplicate fixed-source test method')
    return set(names)


def fixed_sources():
    path = REPO / 'downloads/key-recovery-d4c46bc/Spiral-key-recovery-d4c46bc.tar.gz'
    require(sha(path.read_bytes()) == BUNDLE_SHA256, 'delivery bundle hash mismatch')
    bundle = archive_files(path)
    raw = bundle['SOURCE.json']
    require(sha(raw) == MANIFEST_SHA256, 'delivery source manifest hash mismatch')
    manifest = decode(raw)
    require(manifest['source_commit'] == SOURCE_COMMIT and manifest['runtime_base_commit'] == RUNTIME_BASE
            and manifest['profile'] == 'key-recovery', 'delivery source identity differs')
    files = manifest['files']
    require(len(files) == 324, 'delivery source inventory differs')
    git_tar = subprocess.check_output(['git', 'archive', '--format=tar', SOURCE_COMMIT, '--',
                                       *sorted(files)], cwd=REPO)
    observed = {}
    with tarfile.open(fileobj=io.BytesIO(git_tar)) as archive:
        for member in archive:
            if member.isdir():
                continue
            require(member.isfile() and member.name in files and member.name not in observed,
                    'unexpected Git source entry')
            observed[member.name] = sha(archive.extractfile(member).read())
    require(observed == files, 'delivery source inventory differs from Git')
    require(set(bundle) == {'SOURCE.json', 'README.md', 'run_checks.py'} | {'source/' + name for name in files}
            and all(sha(bundle['source/' + name]) == value for name, value in files.items()),
            'delivery source bytes/inventory differ from manifest')
    return raw, files, bundle


def reference_inputs(bundle, sources):
    local, _ = hashed_members(HERE / LOCAL, LOCAL_SHA256)
    expected = {}
    for name, runner, cls, count in (
            ('key_operations', 'key_ops_tests.py', 'KeyOperations', 11),
            ('key_recovery', 'key_recovery_tests.py', 'KeyRecovery', 20)):
        tests = method_names(bundle, runner, cls)
        require(len(tests) == count, 'fixed-source test count differs')
        key_test_rows(local['logs/' + name.replace('_', '-') + '.stderr.log'].decode(), cls, tests)
        nested = decode(local[name + '.json'])
        require(all(key in sources and sources[key] == value for key, value in nested['source_sha256'].items()),
                'local nested source map differs from Git')
        expected[name] = (runner, cls, tests, nested['source_sha256'])
    require(len(expected['key_operations'][3]) == 182 and len(expected['key_recovery'][3]) == 193,
            'local nested source inventory differs')
    return rust_rows(local['logs/rust-library-tests.stdout.log'].decode()), expected


def command_checks(report, items, path):
    rows = report['commands']
    require([row['name'] for row in rows] == COMMANDS, 'unexpected command sequence')
    public = {'result.json', 'source-manifest.json', 'source-before.json', 'source-after.json',
              'requirements.txt', 'key_operations.json', 'key_recovery.json', 'SHA256.json'}
    timeouts = {'python-install': 900, 'rust-library-tests': 1800, 'release-build': 1800,
                'key-operations': 600, 'key-recovery': 600}
    for row in rows:
        require(type(row['returncode']) is int and row['returncode'] == 0 and row['status'] == 'passed'
                and not row.get('timed_out'), 'command failed/timed out')
        require(type(row['elapsed_seconds']) in (int, float) and 0 <= row['elapsed_seconds'] < row['timeout_seconds']
                and row['timeout_seconds'] == timeouts.get(row['name'], 120), 'command watchdog differs')
        require(row['stdout'] == 'logs/' + row['name'] + '.stdout.log'
                and row['stderr'] == 'logs/' + row['name'] + '.stderr.log', 'unexpected log path')
        require(isinstance(row['command'], list) and all(isinstance(arg, str) for arg in row['command']),
                'command is not an argv string list')
        public.update((row['stdout'], row['stderr']))
    require(set(items) == public and len(items) == 44, 'unexpected public/private receipt members')
    commands = {row['name']: row['command'] for row in rows}
    rustc = items['logs/rustup-rustc.stdout.log'].decode().strip()
    cargo = items['logs/rustup-cargo.stdout.log'].decode().strip()
    require(PurePosixPath(rustc).is_absolute() and PurePosixPath(cargo).is_absolute()
            and commands['rustc-version'] == [rustc, '-vV']
            and commands['cargo-version'] == [cargo, '-Vv'], 'Rust tool paths/argv differ')
    rustup = commands['rustup-rustc'][0]
    require(PurePosixPath(rustup).is_absolute() and PurePosixPath(rustup).name == 'rustup'
            and commands['rustup-rustc'] == [rustup, 'which', '--toolchain', '1.99.1', 'rustc']
            and commands['rustup-cargo'] == [rustup, 'which', '--toolchain', '1.99.1', 'cargo'], 'rustup argv differs')
    lib = commands['rust-library-tests']
    require(len(lib) == 10, 'Rust library argv count differs')
    target, manifest = PurePosixPath(lib[7]), PurePosixPath(lib[9])
    require(re.fullmatch(r'/tmp/spiral-key-recovery-private-[\w-]+/BUILD', str(target))
            and manifest.is_absolute()
            and str(manifest).endswith('/Spiral-key-recovery-d4c46bc/source/protocol_rust/Cargo.toml'),
            'private build target/fixed source paths differ')
    common = ['--locked', '-j', '2', '--target-dir', str(target), '--manifest-path', str(manifest)]
    require(lib == [cargo, 'test', '--lib', *common]
            and commands['release-build'] == [cargo, 'build', '--release', *common], 'Cargo core argv differs')
    source = manifest.parents[1]
    output = source.parent.parent / path.name.removesuffix('.tar.gz')
    require(not target.is_relative_to(output), 'build target is inside public results')
    python = report['python']['executable']
    venv = target.parent / 'venv'
    require(python == str(venv / 'bin/python') and report['python']['prefix'] == str(venv),
            'Python venv is outside expected private scratch')
    for name, runner in (('key-operations', 'key_ops_tests.py'), ('key-recovery', 'key_recovery_tests.py')):
        require(commands[name] == [python, '-I', '-B', str(source / 'protocol_rust' / runner),
                '--binary', str(target / 'release/spiral-lab'), '--json',
                str(output / (name.replace('-', '_') + '.json'))], 'child test argv differs: ' + name)
    require(commands['python-base'] == ['/usr/bin/python3.12', '-I', '-c', PYTHON_PROBE]
            and commands['python-venv'] == ['/usr/bin/python3.12', '-I', '-m', 'venv', str(venv)]
            and commands['python-version'] == [python, '-I', '-c', PYTHON_PROBE]
            and commands['python-pins'] == [python, '-I', '-c', PINS_PROBE]
            and commands['python-pip-check'] == [python, '-I', '-m', 'pip', '--isolated', 'check']
            and commands['python-freeze'] == [python, '-I', '-m', 'pip', '--isolated', 'freeze', '--all']
            and commands['python-install'] == [python, '-I', '-m', 'pip', '--isolated', 'install',
                '--disable-pip-version-check', '--no-input', '--index-url', 'https://pypi.org/simple',
                '-r', str(source / 'protocol_v01/requirements.txt')], 'Python collector argv differs')
    for name, executable, flag in (('cc-version', '/usr/bin/cc', '--version'),
                                   ('ar-version', '/usr/bin/ar', '--version'),
                                   ('openssl-version', '/usr/bin/openssl', 'version')):
        require(commands[name] == [executable, flag], 'support tool argv differs')
    return source, target


def review(path, label, raw_manifest, sources, bundle, expected_rust, expected_nested):
    items, hash_count = hashed_members(path, UPLOAD_SHA256[label])
    require(hash_count == 43 and items['source-manifest.json'] == raw_manifest, 'receipt manifest differs')
    require(decode(items['source-before.json']) == decode(items['source-after.json']) == sources,
            'outer before/after source inventories differ from Git')
    report = decode(items['result.json'])
    require(report['schema'] == 'spiral-key-recovery-platform/v1' and report['profile'] == 'key-recovery'
            and report['status'] == 'passed' and report['platform_tests_passed'] is True
            and report['check_only'] is False and report['source_unchanged'] is True
            and report['offline'] is False and report['scope'] == SCOPE, 'focused platform receipt differs')
    require(report['source_commit'] == SOURCE_COMMIT and report['runtime_base_commit'] == RUNTIME_BASE
            and report['manifest_sha256'] == MANIFEST_SHA256, 'source identity differs')
    require(all(report[name] is False for name in GATES), 'broader approval gate changed')
    tree_hash = sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())
    require(report['source_tree_sha256_before'] == report['source_tree_sha256_after'] == tree_hash,
            'source tree digest differs')
    arch, uid = {'oci': ('aarch64', 1001), 'wsl': ('x86_64', 1000)}[label]
    host = report['host']
    require(report['requested_platform'] == host['requested_platform'] == host['evidence_label'] == label
            and host['architecture'] == host['uname']['machine'] == arch and host['uname']['system'] == 'Linux'
            and type(host['effective_uid']) is int and host['effective_uid'] == uid
            and host['oci_provider_attested'] is False, 'platform/normal UID metadata differs')
    microsoft = 'microsoft' in (host['uname']['release'] + host['uname']['version'] + host['proc_version']).lower()
    require(microsoft == (label == 'wsl') and host['microsoft_kernel_evidence'] is microsoft,
            'Microsoft kernel metadata differs')
    require(host['uname']['release'] in host['proc_version'] and host['uname']['version'] in host['proc_version'],
            'uname/proc kernel strings differ')
    source, target = command_checks(report, items, path)
    def log(name, stream='stdout'):
        return items['logs/' + name + '.' + stream + '.log'].decode()
    tool = report['toolchain']
    for name, commit in (('rustc', RUST_COMMIT), ('cargo', CARGO_COMMIT)):
        text = log(name + '-version').strip()
        require(text == tool[name] and text.startswith(name + ' 1.99.1 ')
                and 'release: 1.99.1' in text.splitlines() and 'commit-hash: ' + commit in text.splitlines()
                and 'host: ' + arch + '-unknown-linux-gnu' in text.splitlines()
                and re.fullmatch('[a-f0-9]{64}', tool[name + '_sha256']), 'raw/outer Rust tool metadata differs')
    require(tool['host'] == arch + '-unknown-linux-gnu', 'outer toolchain host differs')
    rust = rust_rows(log('rust-library-tests'))
    require(rust == expected_rust and report['rust_library_tests'] == RUST_COUNTS,
            'Rust identities/statuses/counts differ from fixed local reference')
    locked = {(p['name'], p['version']) for p in tomllib.loads(bundle['source/protocol_rust/Cargo.lock'].decode())['package']}
    compiled_counts = {}
    for name, profile in (('rust-library-tests', 'test'), ('release-build', 'release')):
        text = log(name, 'stderr')
        compiled = re.findall(r'^\s+Compiling ([\w-]+) v([^\s]+)', text, re.MULTILINE)
        require(compiled and set(compiled) <= locked, 'compiled package versions differ from Cargo.lock')
        require('Finished `' + profile + '` profile [' in text, 'build completion missing')
        for crate in ('digest', 'hmac', 'hkdf', 'ed25519-dalek', 'curve25519-dalek'):
            require(re.search(r'^\s+Compiling ' + re.escape(crate) + r' v\S+ \('
                              + re.escape(str(source / 'third_party/rustcrypto' / crate)) + r'\)$', text, re.MULTILINE),
                    'local vendor patch build evidence missing: ' + crate)
        compiled_counts[name] = len(set(compiled))
    require(re.search(r'Running unittests src/lib\.rs \(' + re.escape(str(target / 'debug/deps/spiral_protocol-'))
                      + r'[a-f0-9]+\)', log('rust-library-tests', 'stderr')), 'private debug test binary path differs')
    suites = {}
    binary = report['binary_sha256_before']
    require(re.fullmatch('[a-f0-9]{64}', binary) and report['binary_sha256_after'] == binary,
            'outer declared binary hashes disagree')
    for name, (runner, cls, expected, nested_sources) in expected_nested.items():
        count = len(expected)
        identities = key_test_rows(log(name.replace('_', '-'), 'stderr'), cls, expected)
        nested = decode(items[name + '.json'])
        require(decode(log(name.replace('_', '-'))) == nested, 'raw stdout differs from saved nested JSON')
        summary = {'tests': count, 'failures': 0, 'errors': 0, 'skipped': 0, 'status': 'passed'}
        require(all(type(nested[key]) is int and nested[key] == value for key, value in summary.items() if key != 'status')
                and nested['status'] == 'passed' and report[name] == summary, 'outer/nested suite summary differs')
        require(nested['failed_tests'] == nested['error_tests'] == [] and nested['source_and_binary_unchanged'] is True
                and nested['effective_uid'] == uid and type(nested['effective_uid']) is int
                and nested['platform'] == host['uname'], 'nested suite status/host/UID differs')
        require(nested['source_sha256'] == nested_sources
                and all(key in sources and sources[key] == value for key, value in nested_sources.items())
                and nested['runner_sha256'] == sources['protocol_rust/' + runner], 'nested sources differ from local reference/Git')
        require(nested['binary_sha256'] == binary, 'nested declared binary hash disagrees')
        require(nested['scope'] == (BASE_SCOPE if name == 'key_operations' else RECOVERY_SCOPE), 'nested scope differs')
        if name == 'key_recovery':
            require(nested['source_sha256_before'] == nested['source_sha256_after'] == nested_sources
                    and nested['binary_sha256_before'] == nested['binary_sha256_after'] == binary,
                    'recovery before/after/alias declarations disagree')
            require(nested['foreign_owner_checks_exercised'] is False and nested['drill_limits'] == DRILL_LIMITS
                    and nested['baseline_key_operations'] == {'tests': 11, 'execution': 'separate suite; not run by this runner'},
                    'recovery scope/foreign-owner coverage claim differs')
        suites[name] = {**summary, 'test_identities': identities, 'runner_sha256': nested['runner_sha256'],
                        'source_files_matched_to_git': len(nested_sources)}
    python = report['python']
    version = decode(log('python-version'))
    base = decode(log('python-base'))
    require(version == {key: python[key] for key in ('version', 'executable', 'prefix', 'base_prefix', 'openssl')}
            and version['version'] == base['version'] == [3, 12, 3]
            and version['prefix'] != version['base_prefix'] == base['prefix'] == base['base_prefix'] == '/usr'
            and base['executable'] == '/usr/bin/python3.12' and base['openssl'] == version['openssl'],
            'raw/outer Python version/venv metadata differs')
    require(items['requirements.txt'] == bundle['source/protocol_v01/requirements.txt']
            and dict(line.split('==') for line in items['requirements.txt'].decode().splitlines() if line.strip()) == PINS
            and python['requirements_sha256'] == sha(items['requirements.txt'])
            and python['pinned_requirements'] == python['installed_pins'] == decode(log('python-pins')) == PINS,
            'exact Python pins differ')
    frozen = {}
    for line in log('python-freeze').splitlines():
        pair = re.fullmatch(r'([\w.-]+)==([^\s]+)', line)
        require(pair is not None and pair[1] not in frozen, 'unexpected/duplicate frozen distribution')
        frozen[pair[1]] = pair[2]
    require(frozen == {**PINS, 'pip': '24.0'} and log('python-pip-check') == 'No broken requirements found.\n'
            and python['pip_check'] == 'passed' and python['distributions_log'] == 'logs/python-freeze.stdout.log',
            'Python freeze/pip check differs')
    require(not any(re.search(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', data) for data in items.values()),
            'private PEM found in public members')
    return {'schema': 'spiral-key-recovery-receipt-review/v1', 'status': 'accepted',
            **reviewer_metadata(), 'archive': path.name, 'archive_sha256': UPLOAD_SHA256[label],
            'archive_bytes': path.stat().st_size, 'archive_regular_members': len(items),
            'result_hashes_verified': hash_count, 'source_commit': SOURCE_COMMIT, 'runtime_base_commit': RUNTIME_BASE,
            'manifest_sha256': MANIFEST_SHA256, 'source_files_matched_to_git': len(sources),
            'source_before_after_equal': True, 'source_tree_sha256': tree_hash,
            'requested_platform': label, 'architecture': arch, 'effective_uid': uid, 'host': host,
            'rustc_commit': RUST_COMMIT, 'cargo_commit': CARGO_COMMIT, 'rust_tests': RUST_COUNTS,
            'rust_test_identities': dict(sorted(rust.items())), **suites,
            'raw_test_identities_verified': True, 'commands_passed': len(COMMANDS),
            'command_argv_and_watchdogs_verified': True, 'public_member_whitelist_verified': True,
            'private_target_outside_public_results': True, 'compiled_packages_matched_to_lock': compiled_counts,
            'local_dependency_patches_compiled_per_profile': 5, 'python_version': version['version'],
            'pinned_python_packages': PINS, 'reported_binary_hashes_agree': True, 'binary_sha256': binary,
            'binary_hashes_independently_verified': False, 'binary_and_tool_bytes_included': False,
            'tool_hashes_independently_verified': False, 'machine_identity_independently_attested': False,
            'foreign_owner_checks_exercised': False, 'scope': SCOPE, 'recovery_scope': RECOVERY_SCOPE,
            'drill_limits': DRILL_LIMITS, 'gates': {name: False for name in GATES},
            'new_full_ci_or_memory_or_fuzz_or_load_tests': False}


def reviewer_metadata():
    return {'reviewer_sha256': sha(Path(__file__).read_bytes()),
            'parser_regression_tests_sha256': sha((HERE / 'test_review_uploaded_results.py').read_bytes()),
            'trusted_helper': {'path': str(HELPER.relative_to(REPO)), 'sha256': HELPER_SHA256,
                               'functions': ['archive_files', 'decode', 'sha', 'require']},
            'fixed_delivery_sha256': BUNDLE_SHA256, 'fixed_local_reference_sha256': LOCAL_SHA256}


def command_path(path):
    resolved = path.resolve()
    return str(resolved.relative_to(REPO)) if resolved.is_relative_to(REPO) else str(resolved)


def write_reviews(args):
    raw, sources, bundle = fixed_sources()
    rust, nested = reference_inputs(bundle, sources)
    reviews = {label: review(path, label, raw, sources, bundle, rust, nested)
               for label, path in (('oci', args.oci), ('wsl', args.wsl))}
    collector = {name: sources['protocol_rust/validation/' + name]
                 for name in ('key_operations_platform.py', 'key_recovery_platform.py')}
    for result in reviews.values():
        result['collector_source_sha256'] = collector
    summary = {'schema': 'spiral-key-recovery-two-platform-review/v1', 'status': 'accepted',
               **reviewer_metadata(), 'collector_source_sha256': collector,
               'source_commit': SOURCE_COMMIT, 'runtime_base_commit': RUNTIME_BASE,
               'platform_key_recovery_validation_complete': True, 'full_goal_5_complete': False,
               'scope': 'finite research key recovery platform validation', 'drill_limits': DRILL_LIMITS,
               'source_files_verified_per_platform': len(sources), 'rust_passed_per_platform': 94,
               'rust_ignored_per_platform': 5, 'key_operations_passed_per_platform': 11,
               'key_recovery_passed_per_platform': 20, 'key_tests_failed_or_skipped': 0,
               'parser_regression_command': ['python3', '-I', '-B',
                   'protocol_rust/evidence/key_recovery_20261110/test_review_uploaded_results.py', '-v'],
               'review_command': ['python3', '-I', '-B',
                   'protocol_rust/evidence/key_recovery_20261110/review_uploaded_results.py',
                   '--oci', command_path(args.oci), '--wsl', command_path(args.wsl),
                   '--output-dir', command_path(args.output_dir)],
               'review_command_cwd': 'repository root',
               'platforms': {label: {'archive': data['archive'], 'archive_sha256': data['archive_sha256'],
                                   'review': label + '-review.json'} for label, data in reviews.items()},
               'binary_hashes_independently_verified': False, 'foreign_owner_checks_exercised': False,
               'new_full_ci_or_memory_or_fuzz_or_load_tests': False, 'gates': {name: False for name in GATES}}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for label, result in reviews.items():
        (args.output_dir / (label + '-review.json')).write_text(json.dumps(result, indent=2) + '\n')
    (args.output_dir / 'platform-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci', type=Path, required=True)
    parser.add_argument('--wsl', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        write_reviews(args)
    except Exception as error:
        # A failed rerun must invalidate any previous accepted primary summary.
        args.output_dir.mkdir(parents=True, exist_ok=True)
        failure = {'schema': 'spiral-key-recovery-two-platform-review/v1', 'status': 'failed',
                   'error': str(error), 'platform_key_recovery_validation_complete': False,
                   'full_goal_5_complete': False, 'gates': {name: False for name in GATES}}
        (args.output_dir / 'platform-summary.json').write_text(json.dumps(failure, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
