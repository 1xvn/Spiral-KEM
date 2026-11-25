"""Project private CI evidence onto a closed, public receipt schema."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

from evidence import atomic_json, contract, require, strict_json


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
    parsed = {}
    for name in names:
        path = root / name
        if not path.is_file():
            require(outcome != 'success', 'successful run lacks required evidence')
            continue
        raw = path.read_bytes()
        receipt['evidence_sha256'][name] = hashlib.sha256(raw).hexdigest()
        if outcome == 'success' or name == 'memory-review.json':
            parsed[name] = strict_json(raw)
    hashes = receipt['evidence_sha256']
    if kind == 'functional' and outcome == 'success':
        result = parsed['functional/result.json']
        require(result['status'] == 'passed' and
                parsed['functional/source-before.json'] == parsed['functional/source-after.json'] and
                parsed['functional/source-before.json']['commit'] == commit and
                result['source_before_sha256'] == hashes['functional/source-before.json'] and
                result['source_after_sha256'] == hashes['functional/source-after.json'],
                'source receipt differs from completed check')
        required = {k for k in contract('test_inventory') if not k.startswith('scratch/')}
        required.update(('cc-version', 'openssl-version', 'python-dependencies', 'cargo-version',
                         'rustc-version', 'rust-scratch-cleanup', 'rust-flow-diagnostics-cli', 'rust-release'))
        checks = result['checks']
        require(len(checks) == len(required) and {c['name'] for c in checks} == required,
                'incomplete functional inventory')
        receipt['checks'] = {}
        for check in checks:
            name = check['name']
            require(check['passed'] is True and check['classification'] == 'functional_pass',
                    'functional check did not pass')
            digests = {}
            for stream in ('stdout', 'stderr'):
                filename = name + '.' + stream
                digest = hashlib.sha256((root / 'functional' / filename).read_bytes()).hexdigest()
                require(check[stream] == {'file': filename, 'sha256': digest}, 'raw stream changed')
                digests[stream + '_sha256'] = digest
            receipt['checks'][name] = digests
        recorded = {'functional/' + c['structured_file']['file']: c['structured_file']['sha256']
                    for c in result['checks'] if 'structured_file' in c}
        require(recorded == {n: hashes[n] for n in names[3:]}, 'validated evidence changed before publication')
    if kind == 'memory':
        verdict = parsed.get('memory-review.json', {})
        classification = verdict.get('classification', 'incomplete_or_tool_error')
        require(classification in ('diagnostic_clean', 'diagnostic_warning', 'incomplete_or_tool_error'),
                'unexpected memory classification')
        if classification != 'incomplete_or_tool_error' or outcome == 'success':
            require(verdict.get('input_sha256') == hashes.get('memory/result.json') and
                    bool(verdict.get('input_sha256')), 'memory review input changed')
        if outcome == 'success':
            require(classification == 'diagnostic_clean' and verdict['status'] == 'passed',
                    'memory verdict disagrees with job')
        receipt['classification'] = classification
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
