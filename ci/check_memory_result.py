#!/usr/bin/env python3
"""CI gate for clean std controls, distinct from completion and production safety."""
import argparse
import re
from pathlib import Path
import sys

from evidence import atomic_json, libtest_result, lines, require, sha, strict_json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol_rust/diagnostics'))
from libtest_memory import parse_memcheck

EXPECTED = {'empty-main', 'thread-current', 'thread-join', 'channel-roundtrip',
            'libtest-default', 'libtest-nocapture'}


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


def review(path):
    raw = path.read_bytes()
    data = strict_json(raw)
    require(type(data) is dict and data.get('schema') == 'spiral-rust-libtest-memory-controls/v1',
            'invalid diagnostic schema')
    cases = data.get('cases', [])
    require(len(cases) == len(EXPECTED) and {c.get('name') for c in cases} == EXPECTED,
            'missing or duplicate controls')
    require(data.get('diagnostic_complete') is True and data.get('errors') == [],
            'diagnostic incomplete')
    source = data['source']
    require(source['file'] == 'std_libtest_control.rs' and
            sha((path.parent / source['file']).read_bytes()) == source['sha256'],
            'diagnostic source mismatch')
    warning = False
    for case in cases:
        name = case['name']
        for mode, record in (('native', case['native']), ('memcheck', case['memcheck'])):
            require(type(record.get('exit')) is int and record['timed_out'] is False
                    and not record.get('execution_error'), 'incomplete child command')
            for stream in ('stdout', 'stderr'):
                filename = f'{name}-{mode}.{stream}'
                require(record[stream+'_file'] == filename, 'unexpected diagnostic stream path')
                content = (path.parent / filename).read_bytes()
                require(sha(content) == record[stream+'_sha256'] and
                        content.decode() == record[stream], 'diagnostic stream mismatch')
            require(not record['stderr'] and record.get('expected_output') is True,
                    'unexpected diagnostic output')
            if name.startswith('libtest-'):
                libtest_result(record['stdout'].encode(), 1, filtered=0)
                require('test control::empty ... ok' in record['stdout'].splitlines(),
                        'unexpected libtest diagnostic identity')
            else:
                require(record['stdout'] == f'CONTROL_COMPLETED {name}\n', 'missing native completion')
        require(case['native']['exit'] == 0 and case.get('diagnostic_complete') is True
                and case.get('errors') == [], 'incomplete native control')
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
        require(all(case[key] == value for key, value in parsed.items()), 'Memcheck summary/log mismatch')
        count = parsed['summary']['errors']
        require(mem['exit'] == (99 if count else 0), 'Memcheck exit disagrees with raw log')
        warning |= bool(count or parsed['summary']['suppressed_errors']
                        or any(parsed['leaks'][key]['bytes'] for key in
                               ('definitely lost', 'indirectly lost', 'possibly lost', 'suppressed')))
    passed, reason = check(data)
    classification = 'diagnostic_warning' if warning else (
        'diagnostic_clean' if passed else 'incomplete_or_tool_error')
    return passed and not warning, classification, reason


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
        passed, classification, reason = review(args.result)
        receipt.update(status='passed' if passed else 'failed', classification=classification,
                       input_sha256=sha(args.result.read_bytes()), reason=reason)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        receipt.update(status='failed', reason='Invalid or missing diagnostic: ' + str(exc))
    if args.verdict:
        atomic_json(args.verdict, receipt)
    print(receipt['classification'], receipt['reason'])
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
