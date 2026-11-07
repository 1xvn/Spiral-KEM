"""Bounded coverage-guided Atheris runs with replayable public crash artifacts."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

from fuzzing.targets import KEM_MODULE, TARGETS, seed_inputs

ROOT = Path(__file__).resolve().parents[1]
MAX_LENGTH = {'frame': 16500, 'hello': 512, 'kem_pk': 1024, 'kem_ct': 1280, 'records': 4096}


def parse_feedback(text):
    executed = re.findall(r'stat::number_of_executed_units:\s*(\d+)', text)
    initialized = re.findall(r'#(\d+)\s+INITED\s+cov:', text)
    snapshots = re.findall(r'#(\d+)\s+(?:INITED|NEW|REDUCE|DONE)\s+cov:\s*(\d+)\s+ft:\s*(\d+)', text)
    result = {'executed': int(executed[-1]) if executed else None,
              'initialization_executed': int(initialized[-1]) if initialized else None,
              'initial_cov': int(snapshots[0][1]) if snapshots else None,
              'final_cov': int(snapshots[-1][1]) if snapshots else None,
              'final_features': int(snapshots[-1][2]) if snapshots else None,
              'new_corpus_events': len(re.findall(r'\bNEW\s+cov:', text))}
    return result


def classify(returncode, feedback, metadata):
    if returncode != 0:
        return False, 'child failed; preserve artifact and replay before accepting'
    if not metadata.get('instrumented_runtime_functions') or metadata.get('instrumentation_count', 0) <= 0:
        return False, 'missing runtime instrumentation'
    if not feedback.get('executed') or not feedback.get('final_cov') or not feedback.get('final_features'):
        return False, 'no executed inputs or target coverage feedback'
    if not feedback.get('initialization_executed') or feedback['executed'] <= feedback['initialization_executed']:
        return False, 'no mutation executions after corpus initialization'
    # No forced growth: a small target can be saturated by its starting corpus.
    return True, 'bounded campaign completed with runtime feedback'


def main():
    if not __debug__:
        raise RuntimeError('Python -O disables target assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', choices=['all', *TARGETS], default='all')
    p.add_argument('--runs', type=int, default=2000)
    p.add_argument('--seconds', type=int, default=10, help='libFuzzer time budget per target')
    p.add_argument('--seed', type=int, default=20261107)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--corpus-from', type=Path, help='reuse corpus from a previous campaign output')
    args = p.parse_args()
    if not 100 <= args.runs <= 10000000 or not 1 <= args.seconds <= 3600:
        p.error('runs100..10000000, seconds1..3600')
    if args.corpus_from and not args.corpus_from.is_dir():
        p.error('--corpus-from must be an existing campaign output directory')
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    names = list(TARGETS) if args.target == 'all' else [args.target]
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'running',
              'method': 'Atheris3.1/libFuzzer coverage feedback on runtime Python bytecode; independent oracles not instrumented',
              'coverage_scope': 'Python frame/ClientHello/KEM codec/record state only; not native C/Rust/OpenSSL machine coverage',
              'seed': args.seed, 'requested_runs_per_target': args.runs,
              'seconds_per_target': args.seconds, 'targets': [],
              'environment': {'python': sys.version, 'executable': sys.executable,
                              'platform': platform.platform(),
                              'atheris': version('atheris'), 'cryptography': version('cryptography')},
              'constant_time_approved': False, 'security_approved': False}
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'LC_ALL': 'C'}
    started = time.monotonic()
    try:
        seeds = seed_inputs()
        for name in names:
            work = out / name
            corpus, artifacts = work / 'corpus', work / 'artifacts'
            corpus.mkdir(parents=True); artifacts.mkdir()
            entry = {'name': name, 'status': 'incomplete'}
            report['targets'].append(entry)
            for data in seeds[name]:
                if len(data) > MAX_LENGTH[name]:
                    raise RuntimeError('starting seed exceeds bound: ' + name)
                # Save BEFORE checking: an unexpected seed failure stays replayable.
                path = corpus / hashlib.sha256(data).hexdigest()
                path.write_bytes(data)
                try:
                    TARGETS[name](data)
                except Exception:
                    (artifacts / 'initial-seed-failure').write_bytes(data)
                    raise
            sources = [(ROOT / 'fuzzing/regressions' / name, '*.bin')]
            if args.corpus_from:
                previous = args.corpus_from / name / 'corpus'
                if not previous.is_dir():
                    raise RuntimeError('previous corpus missing for ' + name)
                sources.append((previous, '*'))
            for directory, pattern in sources:
                for path in sorted(directory.glob(pattern)):
                    if not path.is_file():
                        continue
                    if path.stat().st_size > MAX_LENGTH[name]:
                        raise RuntimeError('corpus input exceeds bound')
                    data = path.read_bytes()
                    (corpus / hashlib.sha256(data).hexdigest()).write_bytes(data)
            entry['initial_corpus_files'] = len(list(corpus.iterdir()))
            metadata = work / 'instrumentation.json'
            command = [sys.executable, '-m', 'fuzzing.driver', '--target', name,
                       '--metadata', str(metadata), str(corpus),
                       '-runs=' + str(args.runs), '-max_total_time=' + str(args.seconds),
                       '-seed=' + str(args.seed), '-max_len=' + str(MAX_LENGTH[name]),
                       '-timeout=5', '-rss_limit_mb=1536', '-print_final_stats=1',
                       '-artifact_prefix=' + str(artifacts) + '/']
            entry['command'] = command
            log = work / 'engine.log'
            try:
                with log.open('wb') as stream:
                    done = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                          stderr=subprocess.STDOUT, timeout=args.seconds + 60)
                code = done.returncode
            except subprocess.TimeoutExpired:
                code = None
                entry['process_timeout'] = True
            text = log.read_text(errors='replace')
            meta = json.loads(metadata.read_text()) if metadata.is_file() else {}
            metrics = parse_feedback(text)
            passed, reason = classify(code, metrics, meta)
            entry.update(status='passed' if passed else 'failed', exit=code, reason=reason,
                         feedback=metrics, instrumentation_count=meta.get('instrumentation_count', 0),
                         final_corpus_files=len(list(corpus.iterdir())),
                         engine_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                         artifacts=[{'file': str(path.relative_to(out)), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
                                    for path in artifacts.iterdir() if path.is_file()],
                         replay='python -m fuzzing.replay --target ' + name + ' INPUT_FILE')
            print(name, entry['status'], json.dumps(metrics), flush=True)
            if not passed:
                print(text[-5000:], file=sys.stderr)
        report['status'] = 'passed' if len(report['targets']) == len(names) and all(x['status']=='passed' for x in report['targets']) else 'failed'
    except Exception as exc:
        report.update(status='failed', error=repr(exc))
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        sources = [*(ROOT/'fuzzing').glob('*.py'), ROOT/'fuzzing/requirements.txt',
                   ROOT/'protocol_v01/requirements.txt',
                   ROOT/'protocol_v01/wire.py', ROOT/'protocol_v01/handshake.py',
                   ROOT/'protocol_v01/records.py', ROOT/'protocol_v01/validation/fuzz_campaign.py',
                   ROOT/'protocol_v01/tests/fixtures/test_vectors_v0.1.json',
                   Path(KEM_MODULE.__file__).resolve()]
        report['source_sha256'] = {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in sorted(set(sources))}
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out/'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'output': str(out)}))
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
