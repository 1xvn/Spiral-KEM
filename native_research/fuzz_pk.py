"""Portable, bounded first C libFuzzer target; saves OCI/WSL results separately."""
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
import time

ROOT = Path(__file__).resolve().parents[1]


def feedback(log):
    init = re.findall(r'#(\d+)\s+INITED\s+cov:', log)
    units = re.findall(r'stat::number_of_executed_units:\s*(\d+)', log)
    cover = re.findall(r'#\d+\s+(?:INITED|NEW|REDUCE|DONE)\s+cov:\s*(\d+)\s+ft:\s*(\d+)', log)
    return {'initialization_executed': int(init[-1]) if init else None,
            'executed': int(units[-1]) if units else None,
            'final_cov': int(cover[-1][0]) if cover else None,
            'final_features': int(cover[-1][1]) if cover else None}


def passes(code, metrics):
    return (code == 0 and bool(metrics.get('initialization_executed'))
            and bool(metrics.get('executed'))
            and metrics['executed'] > metrics['initialization_executed']
            and bool(metrics.get('final_cov')) and bool(metrics.get('final_features')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True, choices=['oci', 'wsl', 'local'])
    parser.add_argument('--cc', default='clang-18')
    parser.add_argument('--runs', type=int, default=100000)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.runs <= 10000000 or not 1 <= args.seconds <= 3600:
        parser.error('runs must be 100..10000000 and seconds 1..3600')
    if platform.system() != 'Linux':
        parser.error('Run inside OCI Linux or the WSL Linux terminal')
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    print('Output:', out, flush=True)
    started = time.monotonic()
    report = {'status': 'incomplete', 'label': args.label,
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'platform': dict(platform.uname()._asdict(), node="redacted"),
              'python': sys.version, 'commands': [],
              'requested_runs': args.runs, 'seconds': args.seconds,
              'scope': 'C public-key parsing/shared encapsulation through deterministic test API; harness/oracle and shared OpenSSL library are not coverage-instrumented',
              'constant_time_approved': False, 'security_approved': False}
    corpus, artifacts, build = out/'corpus', out/'artifacts', out/'build'
    corpus.mkdir(); artifacts.mkdir(); build.mkdir()

    def run(name, command, timeout):
        log = out/(name+'.log')
        report['commands'].append({'name': name, 'argv': command})
        with log.open('wb') as stream:
            done = subprocess.run(command, cwd=ROOT, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        if done.returncode:
            raise RuntimeError(name+' failed; see '+str(log))
        return log.read_text(errors='replace')

    try:
        cc = shutil.which(args.cc)
        if not cc:
            raise RuntimeError('compiler missing: '+args.cc)
        cc = os.path.abspath(cc)
        compiler_text = run('compiler', [cc, '--version'], 30)
        major = re.findall(r'clang version (\d+)', compiler_text)
        if not major:
            raise RuntimeError('compiler must be Clang with libFuzzer support')
        report['compiler_major'] = int(major[0])
        if shutil.which('openssl'):
            run('openssl', ['openssl', 'version', '-a'], 30)
        if Path('/etc/os-release').is_file():
            (out/'os-release.txt').write_bytes(Path('/etc/os-release').read_bytes())
        run('git-head', ['git', 'rev-parse', 'HEAD'], 30)
        report['commit'] = (out/'git-head.log').read_text().strip()
        sources = ['native_research/fuzz_pk.c', 'native_research/fuzz_pk.py',
                   'native_research/spiral_native.c', 'native_research/spiral_native.h',
                   'protocol_v01/tests/fixtures/test_vectors_v0.1.json']
        report['source_sha256'] = {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
        # Compare the tested files with HEAD, including newly added/untracked files.
        report['sources_match_head'] = True
        for name in sources:
            saved = subprocess.run(['git', 'show', 'HEAD:'+name], cwd=ROOT,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
            if saved.returncode or saved.stdout != (ROOT/name).read_bytes():
                report['sources_match_head'] = False
        base = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-fno-omit-frame-pointer', '-fno-sanitize-recover=undefined']
        run('compile-harness', [cc, *base, '-fsanitize=address,undefined',
            '-I', str(ROOT/'native_research'), '-c', str(ROOT/'native_research/fuzz_pk.c'),
            '-o', str(build/'harness.o')], 120)
        run('compile-runtime', [cc, *base, '-DSPIRAL_TESTING',
            '-fsanitize=fuzzer-no-link,address,undefined', '-c',
            str(ROOT/'native_research/spiral_native.c'), '-o', str(build/'native.o')], 120)
        binary = build/'fuzz-pk'
        run('link', [cc, '-fsanitize=fuzzer,address,undefined', str(build/'harness.o'),
            str(build/'native.o'), '-lcrypto', '-o', str(binary)], 120)
        fixture = json.loads((ROOT/sources[-1]).read_text())
        pk = bytes.fromhex(fixture['public']['kem_public_key_skw1'])
        assert len(pk) == 808
        seeds = [pk, pk[:-1], pk+b'\0', bytes([pk[0]^1])+pk[1:]]
        for coefficient in (0, 3328, 3329, 4095):
            seed = bytearray(pk)
            seed[40], seed[41] = coefficient & 255, (seed[41] & 240) | (coefficient >> 8)
            seeds.append(bytes(seed))
        for seed in seeds:
            (corpus/hashlib.sha256(seed).hexdigest()).write_bytes(seed)
        command = [str(binary), str(corpus), '-runs='+str(args.runs),
                   '-max_total_time='+str(args.seconds), '-seed=20261107',
                   '-max_len=1024', '-timeout=5', '-rss_limit_mb=1536',
                   '-print_final_stats=1', '-artifact_prefix='+str(artifacts)+'/']
        report['commands'].append({'name': 'engine', 'argv': command})
        env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
               'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
        symbolizer = shutil.which('llvm-symbolizer-'+major[0]) or shutil.which('llvm-symbolizer')
        if symbolizer:
            env['ASAN_SYMBOLIZER_PATH'] = symbolizer
        report['symbolizer'] = symbolizer
        with (out/'engine.log').open('wb') as stream:
            done = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=args.seconds+60)
        metrics = feedback((out/'engine.log').read_text(errors='replace'))
        report.update(engine_exit=done.returncode, feedback=metrics,
                      corpus_files=len(list(corpus.iterdir())),
                      status='passed' if passes(done.returncode, metrics) and report['sources_match_head'] else 'failed')
        if not report['sources_match_head']:
            report['error'] = 'tested source files differ from HEAD; commit them before platform comparison'
    except Exception as error:
        report.update(status='failed', error=repr(error))
    finally:
        report['elapsed_seconds'] = time.monotonic()-started
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report['artifacts'] = [p.name for p in sorted(artifacts.iterdir()) if p.is_file()]
        if report['artifacts']:
            report['status'] = 'failed'
        report['binary_sha256'] = hashlib.sha256((build/'fuzz-pk').read_bytes()).hexdigest() if (build/'fuzz-pk').is_file() else None
        (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        files = {str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(out.rglob('*')) if p.is_file() and 'build' not in p.relative_to(out).parts}
        (out/'SHA256.json').write_text(json.dumps(files, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'output': str(out),
                      'feedback': report.get('feedback'), 'error': report.get('error')}))
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
