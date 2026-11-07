#!/usr/bin/env python3
"""CI gate for clean std controls, distinct from completion and production safety."""
import json
from pathlib import Path
import sys

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


def main():
    try:
        data = json.loads(Path(sys.argv[1]).read_text())
        passed, reason = check(data)
    except (IndexError, OSError, ValueError, TypeError, KeyError) as exc:
        passed, reason = False, 'Invalid or missing diagnostic: ' + str(exc)
    print(reason)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
