"""Project private CI evidence onto a closed, public receipt schema."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

from evidence import atomic_json, require, strict_json


def publish(kind, outcome, root, destination):
    # Both strings come from workflow constants and the Actions step outcome.
    require(kind in ('functional', 'memory'), 'unknown workflow')
    require(outcome in ('success', 'failure', 'cancelled', 'skipped'), 'unknown outcome')
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    require(re.fullmatch('[0-9a-f]{40}', commit), 'invalid revision')
    receipt = {'schema': 1, 'workflow': kind, 'commit': commit,
               'outcome': outcome, 'evidence_sha256': {}}
    names = (['functional/result.json', 'functional/source-before.json',
              'functional/source-after.json', 'functional/interop.json',
              'functional/client-auth-lab.json', 'functional/key-operations.json',
              'functional/key-recovery.json', 'functional/scratch-cleanup/result.json']
             if kind == 'functional' else ['memory/result.json', 'memory-review.json'])
    for name in names:
        path = root / name
        if not path.is_file():
            require(outcome != 'success', 'successful run lacks required evidence')
            continue
        raw = path.read_bytes()
        receipt['evidence_sha256'][name] = hashlib.sha256(raw).hexdigest()
        if outcome == 'success' and name in ('functional/result.json', 'memory-review.json'):
            require(strict_json(raw).get('status') == 'passed', 'verdict disagrees with job')
    # No child-provided field, arbitrary filename, exception, or command is copied.
    atomic_json(destination / 'receipt.json', receipt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind')
    parser.add_argument('outcome')
    parser.add_argument('root', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    publish(args.kind, args.outcome, args.root, args.destination)
