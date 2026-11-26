#!/usr/bin/env python3
"""CI gate for clean std controls, distinct from completion and production safety."""
import argparse
import re
from pathlib import Path
import sys

from evidence import atomic_json, exact, libtest_result, lines, require, sha, strict_json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol_rust/diagnostics'))
import libtest_memory
from libtest_memory import parse_memcheck

EXPECTED = {'empty-main', 'thread-current', 'thread-join', 'channel-roundtrip',
            'libtest-default', 'libtest-nocapture'}
REVIEWED_RUST_RELEASES = {'release: 1.99.1', 'release: 1.100.0'}
LEGACY_SCOPE_ERROR = 'unexpected Memcheck errors beyond the scoped runtime 48-byte signature'
# This v1 producer recorded the 1.99.1 and 1.100.0 comparison before the
# common summary parser changed. Its output still undergoes all raw checks.
PREVIOUS_V1_RUNNER_SHA256 = '5637e98b3d826b555222363027fbdb45fe5453e74f5e7ca5792522b05cd1d19d'


def check(data):
    if data.get('schema') != 'spiral-rust-libtest-memory-controls/v1':
        return False, 'Unknown result schema'
    if data.get('production_memory_passed') is not False or data.get('original_finding_resolved') is not False:
        return False, 'A diagnostic cannot approve production or close the original finding'
    cases = data.get('cases', [])
    names = [c.get('name') for c in cases]
    if set(names) != EXPECTED or len(names) != len(EXPECTED):
        return False, 'Missing or duplicate controls'
    if data.get('diagnostic_complete') is not True or data.get('errors'):
        return False, 'Diagnostic incomplete or had unexpected errors'
    bad = []
    for case in cases:
        summary = case.get('summary', {})
        lost = case.get('leaks', {})
        native = case.get('native', {})
        mem = case.get('memcheck', {})
        clean = (
            case.get('diagnostic_complete') is True and not case.get('errors')
            and native.get('exit') == 0 and native.get('expected_output') is True
            and mem.get('exit') == 0 and mem.get('expected_output') is True
            and summary.get('errors') == 0 and summary.get('suppressed_errors') == 0
            and case.get('memory_measurement_passed') is True
            and all(lost.get(kind, {}).get('bytes') == 0 for kind in
                    ['definitely lost', 'indirectly lost', 'possibly lost', 'suppressed'])
        )
        if not clean:
            bad.append(case['name'])
    if bad:
        return False, 'Memcheck controls remain failed: ' + ', '.join(bad)
    return True, 'All std controls were clean in this environment; production remains unapproved'


def streams(folder, label, record):
    for stream in ('stdout', 'stderr'):
        name = f'{label}.{stream}'
        require(record[stream + '_file'] == name, 'unexpected diagnostic stream')
        raw = (folder / name).read_bytes()
        require(sha(raw) == record[stream + '_sha256'] and raw.decode() == record[stream],
                'diagnostic stream mismatch')


def provenance(folder, data, historical):
    expected_runners = ({'0dfa8b7c4bed792afd932860d65036c22430a99dbb6bf100ca8dd318e82de654'}
                        if historical else
                        {sha(Path(libtest_memory.__file__).read_bytes()), PREVIOUS_V1_RUNNER_SHA256})
    require(data['runner_sha256'] in expected_runners,
            'unrecognized control producer')
    source = data['source']
    require(source['file'] == 'std_libtest_control.rs' and
            source['sha256'] == sha(libtest_memory.RUST_SOURCE.encode()) ==
            sha((folder / source['file']).read_bytes()), 'control source mismatch')
    for category, names in [('tools', {'rustc', 'valgrind'}), ('builds', {'main', 'libtest'})]:
        require(set(data[category]) == names, 'missing build/tool witness')
        for name, record in data[category].items():
            require(type(record['exit']) is int and record['exit'] == 0 and
                    record['timed_out'] is False and not record.get('execution_error'),
                    'build/tool command failed')
            label = name + '-version' if category == 'tools' else 'build-' + name
            streams(folder, label, record)
    tools = data['tools']
    for name, flag in [('rustc', '-Vv'), ('valgrind', '--version')]:
        tool = tools[name]
        command = tool['command']
        require(len(command) == 2 and Path(command[0]).name == name and command[1] == flag
                and re.fullmatch('[a-f0-9]{64}', tool['executable_sha256'])
                and not tool['stderr'], 'invalid tool identity')
    releases = [line for line in tools['rustc']['stdout'].splitlines() if line.startswith('release: ')]
    require(len(releases) == 1 and releases[0] in REVIEWED_RUST_RELEASES
            and re.fullmatch(r'valgrind-[\d.]+\n', tools['valgrind']['stdout']), 'wrong tool version')
    binaries = {}
    for name, filename in [('main', 'std-control'), ('libtest', 'libtest-control')]:
        build = data['builds'][name]
        cmd = build['command']
        binary = Path(cmd[-1])
        expected = [tools['rustc']['command'][0], '-g', '-C', 'opt-level=2']
        if name == 'libtest':
            expected.append('--test')
        require(cmd == expected + [str(binary.parent / source['file']), '-o', str(binary)]
                and binary.name == build['binary'] == filename
                and re.fullmatch('[a-f0-9]{64}', build['binary_sha256']),
                'unbound control build')
        binaries[name] = binary
    loader = data.get('loader')
    prefix = []
    if loader:
        require(re.fullmatch('[0-9a-f]{64}', loader['sha256']), 'invalid loader digest')
        prefix = [loader['path'], '--library-path', loader['library_path']]
    for case in data['cases']:
        name = case['name']
        lib = name.startswith('libtest-')
        binary = binaries['libtest' if lib else 'main']
        if not historical:
            digest = data['builds']['libtest' if lib else 'main']['binary_sha256']
            for child in (case['native'], case['memcheck']):
                require(child['binary_before'] == digest == child['binary_after'],
                        'executed binary differs from build')
        native = prefix + [str(binary)] + (['--exact', 'control::empty', '--test-threads=1'] if lib else [name])
        require(case['native']['command'] == native and
                case['rust_test_nocapture'] == ('1' if name == 'libtest-nocapture' else None),
                'native command not bound to control')
        require(case['memcheck']['command'] == [tools['valgrind']['command'][0],
                '--command-line-only=yes', '--tool=memcheck', '--leak-check=full',
                '--show-leak-kinds=all', '--errors-for-leak-kinds=definite,indirect,possible',
                '--error-exitcode=99', '--track-origins=yes',
                '--log-file=' + str(binary.parent / (name + '-memcheck.log')), *native],
                'Memcheck command not bound to control')


def scoped_48_warning(parsed):
    summary = parsed['summary']
    known = sum(record['classification'] != 'other' for record in parsed['possibly_lost_48_records'])
    leaks = parsed['leaks']
    return (summary['errors'] == summary['contexts'] == known > 0
            and leaks['possibly lost'] == {'bytes': 48 * known, 'blocks': known}
            and not any(leaks[kind]['bytes'] for kind in ('definitely lost', 'indirectly lost')))


def review(path, raw=None):
    if raw is None:
        raw = path.read_bytes()
    data = strict_json(raw)
    require(type(data) is dict and data.get('schema') == 'spiral-rust-libtest-memory-controls/v1',
            'invalid diagnostic schema')
    require(data.get('production_memory_passed') is False and data.get('original_finding_resolved') is False,
            'a diagnostic cannot approve production or close the original finding')
    cases = data.get('cases', [])
    require(len(cases) == len(EXPECTED) and {c.get('name') for c in cases} == EXPECTED,
            'missing or duplicate controls')
    # The archived v1 warning predates the per-invocation binary digests.
    historical = sha(raw) == '5184744a62ece330f7c704bdd54fb8341355b89269a8998c7d3f2e1f7652e680'
    provenance(path.parent, data, historical)
    warnings = []
    unattributed = []
    producer_errors = []
    for case in cases:
        name = case['name']
        for mode, record in (('native', case['native']), ('memcheck', case['memcheck'])):
            require(type(record.get('exit')) is int and record['timed_out'] is False
                    and not record.get('execution_error'), 'incomplete child command')
            streams(path.parent, f'{name}-{mode}', record)
            require(not record['stderr'] and record.get('expected_output') is True,
                    'unexpected diagnostic output')
            if name.startswith('libtest-'):
                libtest_result(record['stdout'].encode(), 1, filtered=0)
                require('test control::empty ... ok' in record['stdout'].splitlines(),
                        'unexpected libtest diagnostic identity')
            else:
                require(record['stdout'] == f'CONTROL_COMPLETED {name}\n', 'missing native completion')
        require(case['native']['exit'] == 0, 'incomplete native control')
        mem = case['memcheck']
        filename = f'{name}-memcheck.log'
        require(mem['log_file'] == filename, 'unexpected Memcheck log path')
        log = (path.parent / filename).read_bytes()
        require(sha(log) == mem['log_sha256'], 'Memcheck log hash mismatch')
        rows = lines(log)
        require(bool(rows) and re.fullmatch(r'==\d+== ERROR SUMMARY: [\d,]+ errors from [\d,]+ '
                r'contexts \(suppressed: [\d,]+ from [\d,]+\)', rows[-1]) is not None,
                'missing terminal Memcheck summary')
        parsed = parse_memcheck(log.decode())
        exact({key: case[key] for key in parsed}, parsed, 'Memcheck summary/log mismatch')
        count = parsed['summary']['errors']
        require(mem['exit'] == (99 if count else 0), 'Memcheck exit disagrees with raw log')
        warning = bool(count or parsed['summary']['suppressed_errors']
                       or any(parsed['leaks'][key]['bytes'] for key in
                              ('definitely lost', 'indirectly lost', 'possibly lost', 'suppressed')))
        require(case.get('memory_measurement_passed') is (not warning), 'Memcheck outcome disagrees with raw log')
        scoped = scoped_48_warning(parsed)
        errors = case.get('errors')
        # The v1 producer uses its 48-byte attribution scope as a completion check.
        # Only accept that exact finding once the independent evidence checks passed.
        scope_only = count > 0 and not scoped and errors == [LEGACY_SCOPE_ERROR]
        require((case.get('diagnostic_complete') is True and errors == [])
                or (case.get('diagnostic_complete') is False and scope_only),
                'incomplete control or unexpected producer error')
        producer_errors.extend(f'{name}: {error}' for error in errors)
        if warning:
            warnings.append(name)
            if not scoped:
                unattributed.append(name)
    require(data.get('errors') == producer_errors and data.get('diagnostic_complete') is (not producer_errors),
            'diagnostic completion disagrees with controls')
    if warnings:
        reason = 'Memcheck controls remain failed: ' + ', '.join(warnings)
        if unattributed:
            reason += '. Warning attribution remains undetermined for ' + ', '.join(unattributed)
        return False, 'diagnostic_warning', reason
    passed, reason = check(data)
    return passed, 'diagnostic_clean' if passed else 'incomplete_or_tool_error', reason


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result', type=Path)
    parser.add_argument('--verdict', type=Path)
    args = parser.parse_args()
    if args.verdict and args.verdict.resolve() == args.result.resolve():
        parser.error('verdict must be distinct from the diagnostic input')
    receipt = {'status': 'incomplete', 'classification': 'incomplete_or_tool_error'}
    if args.verdict:
        args.verdict.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(args.verdict, receipt)
    try:
        raw = args.result.read_bytes()
        receipt['input_sha256'] = sha(raw)
        passed, classification, reason = review(args.result, raw)
        receipt.update(status='passed' if passed else 'failed', classification=classification,
                       reason=reason)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        receipt.update(status='failed', reason='Invalid or missing diagnostic: ' + str(exc))
    if args.verdict:
        atomic_json(args.verdict, receipt)
    print(receipt['classification'], receipt['reason'])
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
