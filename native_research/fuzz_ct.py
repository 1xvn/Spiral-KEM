"""Bounded C ciphertext fuzzing plus independent replay with public fixture keys."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from native_research import ct_oracle
from native_research.fuzz_pk import feedback, passes

SANITIZER_ERROR = re.compile(
    r'(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer)'
    r'|runtime error:|LeakSanitizer has encountered|Sanitizer CHECK failed|[Aa]ssertion.*failed')


def clean_exit(code, log):
    return code == 0 and not SANITIZER_ERROR.search(log)


def compare_record(record, data, expected):
    """Fail closed on missing results, swapped inputs or wrong reference output."""
    return (record.get('sha256') == hashlib.sha256(data).hexdigest()
            and type(record.get('status')) is int and record['status'] == expected['status']
            and record.get('canonical') is ct_oracle.canonical(data)
            and record.get('shared_secret_hex') == expected['ss'].hex())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_paths():
    names = ['native_research/fuzz_ct.c', 'native_research/fuzz_ct.py',
             'native_research/ct_oracle.py', 'native_research/fuzz_pk.py',
             'native_research/spiral_native.c', 'native_research/spiral_native.h',
             'code/opt2/spiral_kem_toy_v031_opt2.py',
             'protocol_v01/tests/fixtures/test_vectors_v0.1.json']
    if (ROOT/'native_research/__init__.py').is_file():
        names.append('native_research/__init__.py')
    return names


def make_bundle(out, archive):
    """Only logs, reports and public input data; keep local binaries for replay."""
    if not (out/'result.json').is_file():
        raise RuntimeError('refusing to package a result without result.json')
    descriptor, temporary = tempfile.mkstemp(prefix=archive.name+'.', suffix='.partial', dir=archive.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    try:
        with tarfile.open(temporary, 'w:gz') as bundle:
            bundle.add(out, arcname=out.name, recursive=False)
            for path in sorted(out.rglob('*')):
                if 'build' in path.relative_to(out).parts:
                    continue
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise RuntimeError('unexpected result entry: '+str(path))
                bundle.add(path, arcname=out.name+'/'+str(path.relative_to(out)), recursive=False)
        # Atomically publish a complete archive without overwriting another run.
        os.link(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)


def save_report(out, report):
    (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    files = {str(path.relative_to(out)):digest(path) for path in sorted(out.rglob('*'))
             if path.is_file() and path.name != 'SHA256.json'
             and 'build' not in path.relative_to(out).parts}
    (out/'SHA256.json').write_text(json.dumps(files, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True, choices=['oci', 'wsl', 'local'])
    parser.add_argument('--cc', default='clang-18')
    parser.add_argument('--runs', type=int, default=100000)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Python -O disables reference checks')
    if not 100 <= args.runs <= 10000000 or not 1 <= args.seconds <= 3600:
        parser.error('runs must be 100..10000000 and seconds 1..3600')
    if platform.system() != 'Linux':
        parser.error('run inside the OCI Linux or WSL Ubuntu terminal')
    is_wsl = 'microsoft' in platform.release().lower() or 'WSL_INTEROP' in os.environ
    if args.label == 'wsl' and not is_wsl:
        parser.error('--label wsl requires a WSL Linux terminal')
    if args.label == 'oci' and is_wsl:
        parser.error('use --label wsl inside WSL; run the OCI command on the instance')
    out = args.output.expanduser().absolute()
    archive = Path(str(out)+'.tar.gz')
    if out.exists() or archive.exists():
        parser.error('output directory and .tar.gz must both be new paths')
    out.mkdir(parents=True)
    corpus, artifacts, build, replay = (out/name for name in ('corpus', 'artifacts', 'build', 'replay'))
    for folder in (corpus, artifacts, build, replay):
        folder.mkdir()
    print('Output:', out, flush=True)
    started = time.monotonic()
    report = {'status': 'incomplete', 'label': args.label,
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'platform': dict(platform.uname()._asdict(), node="redacted"), 'python': sys.version,
              'requested_runs': args.runs, 'seconds': args.seconds, 'commands': [],
              'scope': 'C ciphertext decode/one-use key lifecycle with public fixed seeds; finite saved-corpus Python differential replay; OpenSSL machine code not instrumented',
              'constant_time_approved': False, 'security_approved': False,
              'sanitizer_environment': {'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                  'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1', 'LSAN_OPTIONS': 'exitcode=23'},
              'differential': {'status': 'incomplete', 'expected_files': 0, 'checked_files': 0,
                  'canonical_checked': 0, 'malformed_checked': 0, 'golden_checked': 0,
                  'canonical_other_checked': 0, 'mismatches': []}}
    env = {**os.environ, **report['sanitizer_environment']}
    env.pop('ASAN_SYMBOLIZER_PATH', None)
    differential = report['differential']

    def run(name, command, timeout, environment=None, separate_stderr=False):
        log = out/(name+'.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        report['commands'].append({'name': name, 'argv': command, 'timeout_seconds': timeout})
        stderr_path = out/(name+'.stderr.log')
        with log.open('wb') as stream:
            if separate_stderr:
                with stderr_path.open('wb') as errors:
                    done = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream,
                                          stderr=errors, timeout=timeout)
            else:
                done = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream,
                                      stderr=subprocess.STDOUT, timeout=timeout)
        text = log.read_text(errors='replace')
        diagnostics = text + (stderr_path.read_text(errors='replace') if separate_stderr else '')
        if not clean_exit(done.returncode, diagnostics):
            raise RuntimeError(name+' failed or reported sanitizer errors; see '+str(log))
        return text

    try:
        names = source_paths()
        report['source_sha256'] = {name:digest(ROOT/name) for name in names}
        report['commit'] = run('git-head', ['git', 'rev-parse', 'HEAD'], 30).strip()
        report['sources_match_head'] = True
        for name in names:
            saved = subprocess.run(['git', 'show', 'HEAD:'+name], cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=30)
            if saved.returncode or saved.stdout != (ROOT/name).read_bytes():
                report['sources_match_head'] = False
        if not report['sources_match_head']:
            raise RuntimeError('tested source files differ from HEAD; commit before platform comparison')
        # Load and verify the independent stdlib-only Python reference before
        # spending the campaign budget. No TLS dependencies or network needed.
        reference = ct_oracle.Reference()
        vectors = ct_oracle.fixture()
        header = build/'fuzz_ct_vectors.h'
        header.write_text(ct_oracle.render_header())
        report['generated_fixture_header_sha256'] = digest(header)
        (out/'public-fixture-vectors.h').write_bytes(header.read_bytes())
        (out/'public-fixture-header-sha256.json').write_text(json.dumps({
            'generator': 'native_research/ct_oracle.py', 'sha256': digest(header)})+'\n')
        cc = shutil.which(args.cc)
        if not cc:
            raise RuntimeError('compiler missing: '+args.cc)
        cc = os.path.abspath(cc)
        compiler = run('compiler', [cc, '--version'], 30)
        major = re.findall(r'clang version (\d+)', compiler)
        if not major:
            raise RuntimeError('Clang with libFuzzer support is required')
        report['compiler_major'] = int(major[0])
        symbolizer = shutil.which('llvm-symbolizer-'+major[0]) or shutil.which('llvm-symbolizer')
        report['symbolizer'] = symbolizer
        if symbolizer:
            env['ASAN_SYMBOLIZER_PATH'] = symbolizer
        if shutil.which('openssl'):
            run('openssl', ['openssl', 'version', '-a'], 30)
        if Path('/etc/os-release').is_file():
            (out/'os-release.txt').write_bytes(Path('/etc/os-release').read_bytes())
        base = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-fno-omit-frame-pointer', '-fno-sanitize-recover=undefined']
        includes = ['-I', str(build), '-I', str(ROOT/'native_research')]
        # Runtime coverage only; do not count oracle/harness routing as coverage.
        run('compile-harness', [cc, *base, '-fsanitize=address,undefined', *includes,
            '-c', str(ROOT/'native_research/fuzz_ct.c'), '-o', str(build/'harness.o')], 120)
        run('compile-runtime', [cc, *base, '-DSPIRAL_TESTING',
            '-fsanitize=fuzzer-no-link,address,undefined', '-c',
            str(ROOT/'native_research/spiral_native.c'), '-o', str(build/'runtime.o')], 120)
        binary = build/'fuzz-ct'
        run('link-engine', [cc, '-fsanitize=fuzzer,address,undefined', str(build/'harness.o'),
            str(build/'runtime.o'), '-lcrypto', '-o', str(binary)], 120)
        # Replay has an ordinary main and its own runtime without coverage hooks.
        replay_binary = build/'replay-ct'
        run('compile-replay', [cc, *base, '-DSPIRAL_TESTING', '-DFUZZ_CT_REPLAY_MAIN',
            '-fsanitize=address,undefined', *includes, str(ROOT/'native_research/fuzz_ct.c'),
            str(ROOT/'native_research/spiral_native.c'), '-lcrypto', '-o', str(replay_binary)], 120)
        report['binary_sha256'] = {'fuzz-ct':digest(binary), 'replay-ct':digest(replay_binary)}
        for data in ct_oracle.seed_inputs():
            if len(data) > 1280:
                raise RuntimeError('seed input exceeds 1280 bytes')
            (corpus/hashlib.sha256(data).hexdigest()).write_bytes(data)
        report['initial_corpus_files'] = len(list(corpus.iterdir()))
        engine_command = [str(binary), str(corpus), '-runs='+str(args.runs),
            '-max_total_time='+str(args.seconds), '-seed=20261107', '-max_len=1280',
            '-timeout=5', '-rss_limit_mb=1536', '-print_final_stats=1',
            '-artifact_prefix='+str(artifacts)+'/']
        report['commands'].append({'name': 'engine', 'argv': engine_command,
                                   'timeout_seconds': args.seconds+60})
        with (out/'engine.log').open('wb') as stream:
            done = subprocess.run(engine_command, cwd=ROOT, env=env, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=args.seconds+60)
        engine_text = (out/'engine.log').read_text(errors='replace')
        metrics = feedback(engine_text)
        report.update(engine_exit=done.returncode, feedback=metrics)
        if not clean_exit(done.returncode, engine_text) or not passes(done.returncode, metrics):
            raise RuntimeError('engine failed, lacked runtime feedback, or only initialized; see engine.log')

        inputs = sorted(corpus.iterdir())
        manifest = []
        for path in inputs:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1280:
                raise RuntimeError('unexpected corpus entry')
            data = path.read_bytes()
            manifest.append({'file':str(path.relative_to(out)), 'sha256':hashlib.sha256(data).hexdigest(),
                             'bytes':len(data), 'canonical':ct_oracle.canonical(data)})
        (out/'corpus-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        differential['expected_files'] = len(inputs)
        report['final_corpus_files'] = len(inputs)
        # This is a finite replay of saved corpus files, not a claim that every
        # live libFuzzer execution was differentially evaluated by Python.
        for at in range(0, len(inputs), 32):
            batch = inputs[at:at+32]
            output = run('replay/batch-'+str(at//32).zfill(4),
                         [str(replay_binary), *map(str, batch)], 180, env, True)
            rows = [json.loads(line) for line in output.splitlines() if line.strip()]
            if len(rows) != len(batch):
                raise RuntimeError('native replay did not return exactly one result per input')
            for offset, (path, row) in enumerate(zip(batch, rows)):
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != manifest[at+offset]['sha256']:
                    raise RuntimeError('corpus changed during replay')
                expected = reference.expected(data)
                if not compare_record(row, data, expected):
                    name = 'differential-'+hashlib.sha256(data).hexdigest()
                    (artifacts/name).write_bytes(data)
                    differential['mismatches'].append({'file':str(path.relative_to(out)),
                        'expected_status':expected['status'], 'expected_shared_secret_hex':expected['ss'].hex(),
                        'native':row})
                    raise RuntimeError('native/Python differential mismatch')
                differential['checked_files'] += 1
                if ct_oracle.canonical(data):
                    differential['canonical_checked'] += 1
                    if data == vectors['ct']:
                        differential['golden_checked'] += 1
                    else:
                        differential['canonical_other_checked'] += 1
                else:
                    differential['malformed_checked'] += 1
        if (differential['checked_files'] != differential['expected_files']
                or not differential['golden_checked'] or not differential['canonical_other_checked']
                or not differential['malformed_checked']):
            raise RuntimeError('differential replay lacks required input classes or completion')
        differential['status'] = 'passed'
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=repr(error))
        if differential['status'] != 'passed':
            differential['status'] = 'failed'
    finally:
        if 'source_sha256' in report:
            report['sources_unchanged_during_run'] = all(
                (ROOT/name).is_file() and digest(ROOT/name)==value
                for name,value in report['source_sha256'].items())
            if not report['sources_unchanged_during_run']:
                report.update(status='failed', error='source changed during run')
        if 'generated_fixture_header_sha256' in report:
            report['fixture_header_unchanged'] = (build/'fuzz_ct_vectors.h').is_file() and (
                digest(build/'fuzz_ct_vectors.h') == report['generated_fixture_header_sha256'])
            if not report['fixture_header_unchanged']:
                report.update(status='failed', error='generated fixture header changed during run')
        report['artifacts'] = [p.name for p in sorted(artifacts.iterdir()) if p.is_file()]
        if report['artifacts']:
            report['status'] = 'failed'
        report['elapsed_seconds'] = time.monotonic()-started
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report['archive'] = str(archive)
        save_report(out, report)
        try:
            make_bundle(out, archive)
        except Exception as error:
            report.update(status='failed', archive_error=repr(error))
            save_report(out, report)
    print(json.dumps({'status':report['status'], 'output':str(out), 'archive':str(archive),
                      'feedback':report.get('feedback'), 'differential':differential,
                      'error':report.get('error'), 'archive_error':report.get('archive_error')}))
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
