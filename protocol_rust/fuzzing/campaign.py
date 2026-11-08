"""Instrumented Rust parser or DATA/CLOSE state campaigns with saved-corpus replay."""
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

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from protocol_rust.fuzzing import inputs, coverage_evidence
from protocol_rust.fuzzing.install_toolchain import RUSTC_COMMIT, RUSTC_RELEASE

SANITIZER_ERROR = re.compile(
    r'(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer)'
    r'|runtime error:|LeakSanitizer has encountered|Sanitizer CHECK failed'
    r'|thread .* panicked|[Aa]ssertion.*failed')
RUST_FLAGS = '-Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers=yes -Coverflow-checks=yes -Cdebug-assertions=yes'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_feedback(log):
    initialized = re.findall(r'#(\d+)\s+INITED\s+cov:', log)
    executed = re.findall(r'stat::number_of_executed_units:\s*(\d+)', log)
    snapshots = re.findall(r'#\d+\s+(?:INITED|NEW|REDUCE|DONE)\s+cov:\s*(\d+)\s+ft:\s*(\d+)', log)
    return {'initialization_executed':int(initialized[-1]) if initialized else None,
            'executed':int(executed[-1]) if executed else None,
            'initial_cov':int(snapshots[0][0]) if snapshots else None,
            'final_cov':int(snapshots[-1][0]) if snapshots else None,
            'final_features':int(snapshots[-1][1]) if snapshots else None,
            'new_corpus_events':len(re.findall(r'\bNEW\s+cov:', log))}


def clean_exit(code, log):
    return code == 0 and not SANITIZER_ERROR.search(log)


def search_completed(code, log, metrics):
    return (clean_exit(code, log) and bool(metrics.get('initialization_executed'))
            and bool(metrics.get('executed')) and metrics['executed'] > metrics['initialization_executed']
            and bool(metrics.get('final_cov')) and bool(metrics.get('final_features')))


def matches_reference(row, path, expected):
    if not isinstance(row, dict) or set(row) != {'file','result'} or row['file'] != str(path):
        return False
    # JSON-normalized equality also distinguishes true from 1 and 1 from 1.0.
    return json.dumps(row['result'],sort_keys=True,separators=(',',':')) == json.dumps(expected,sort_keys=True,separators=(',',':'))


def decode_row(text):
    def unique_pairs(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise ValueError('duplicate replay JSON field: '+key)
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError('non-finite replay JSON number: '+value)

    return json.loads(text,object_pairs_hook=unique_pairs,parse_constant=nonfinite)


def source_names():
    paths = [ROOT/'rust-toolchain.toml', ROOT/'protocol_rust/Cargo.toml',
             ROOT/'protocol_rust/Cargo.lock', ROOT/'protocol_rust/build.rs',
             ROOT/'protocol_rust/fuzz/Cargo.toml', ROOT/'protocol_rust/fuzz/Cargo.lock',
             ROOT/'native_research/spiral_native.c', ROOT/'native_research/spiral_native.h',
             ROOT/'protocol_v01/tests/fixtures/test_vectors_v0.1.json']
    paths += list((ROOT/'protocol_rust/src').rglob('*.rs'))
    paths += list((ROOT/'protocol_rust/fuzz').rglob('*.rs'))
    paths += list((ROOT/'protocol_rust/fuzzing').glob('*.py'))
    # Local dependency patches are compiled source, not opaque registry crates.
    vendor = ROOT/'third_party/rustcrypto'
    paths += [path for path in vendor.rglob('*') if path.is_file()
              and 'target' not in path.relative_to(vendor).parts
              and (path.suffix == '.rs' or path.name in ('Cargo.toml', 'README.md',
                                                       'upstream-provenance.json', 'patch-manifest.json'))]
    return sorted(str(path.relative_to(ROOT)) for path in set(paths))


def write_report(out, report):
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    files = {str(path.relative_to(out)):digest(path) for path in sorted(out.rglob('*'))
             if path.is_file() and path.name != 'SHA256.json' and 'build' not in path.relative_to(out).parts}
    (out/'SHA256.json').write_text(json.dumps(files,indent=2)+'\n')


def bundle(out, destination):
    if not (out/'result.json').is_file():
        raise RuntimeError('result.json is required before packaging')
    descriptor, temporary = tempfile.mkstemp(prefix=destination.name+'.',suffix='.partial',dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    try:
        with tarfile.open(temporary,'w:gz') as archive:
            archive.add(out,arcname=out.name,recursive=False)
            for path in sorted(out.rglob('*')):
                if 'build' in path.relative_to(out).parts:
                    continue
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise RuntimeError('unexpected result entry')
                archive.add(path,arcname=out.name+'/'+str(path.relative_to(out)),recursive=False)
        os.link(temporary,destination)
    finally:
        temporary.unlink(missing_ok=True)


def build_environment(toolchain, trace):
    env = dict(os.environ)
    for key in list(env):
        if (key in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_ENCODED_RUSTFLAGS',
                    'ASAN_SYMBOLIZER_PATH','CUSTOM_LIBFUZZER_PATH','CUSTOM_LIBFUZZER_STD_CXX')
                or key.startswith(('CFLAGS','CXXFLAGS','TARGET_CFLAGS','TARGET_CXXFLAGS','HOST_CFLAGS','HOST_CXXFLAGS'))):
            env.pop(key,None)
    env.update(RUSTC=str(toolchain/'bin/rustc'),RUSTDOC=str(toolchain/'bin/rustdoc'),
        RUSTC_WRAPPER=str(ROOT/'protocol_rust/fuzzing/rustc_wrapper.py'),
        SPIRAL_RUSTC_TRACE=str(trace),RUSTFLAGS=RUST_FLAGS,CARGO_INCREMENTAL='0',
        CARGO_PROFILE_RELEASE_LTO='false',CARGO_PROFILE_RELEASE_OPT_LEVEL='1',
        CARGO_PROFILE_RELEASE_DEBUG='1',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',
        CARGO_PROFILE_RELEASE_PANIC='abort',CARGO_PROFILE_RELEASE_STRIP='none',
        ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',LSAN_OPTIONS='exitcode=23')
    symbolizer = shutil.which('llvm-symbolizer-18') or shutil.which('llvm-symbolizer')
    if symbolizer:
        env['ASAN_SYMBOLIZER_PATH'] = symbolizer
    return env


def suite_configuration(suite):
    """Keep target selection explicit so an incomplete suite cannot pass."""
    if suite == 'parsers':
        return inputs, ('frame','hello'), ('frame_target','hello_target','replay_target'), 'replay_target'
    if suite == 'records':
        from protocol_rust.fuzzing import record_inputs
        return record_inputs, ('record',), ('record_target','record_replay'), 'record_replay'
    raise ValueError('unknown fuzz suite: '+str(suite))


def model_test_environment(env):
    """Run independent model tests separately from the audited release build."""
    result = dict(env)
    for key in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','SPIRAL_RUSTC_TRACE',
                'RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS'):
        result.pop(key,None)
    return result


def model_tests_completed(log):
    counts = re.findall(r'test result: ok\.\s+(\d+) passed;', log)
    return bool(counts) and sum(map(int, counts)) > 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite',choices=['parsers','records'],default='parsers')
    parser.add_argument('--label',choices=['oci','wsl','local'],required=True)
    parser.add_argument('--toolchain-dir',type=Path,required=True)
    parser.add_argument('--runs',type=int,default=100000)
    parser.add_argument('--seconds',type=int,default=60,help='libFuzzer time limit per target')
    parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    references, required_targets, binary_names, replay_binary = suite_configuration(args.suite)
    if not __debug__:
        parser.error('Python -O disables oracle assertions')
    if not 100 <= args.runs <= 10000000 or not 1 <= args.seconds <= 3600 or not 1 <= args.jobs <= 4:
        parser.error('runs100..10000000, seconds1..3600, jobs1..4')
    machine = platform.machine().lower()
    if platform.system() != 'Linux' or machine not in ('x86_64','aarch64'):
        parser.error('supported hosts are Linux x86_64 and aarch64')
    is_wsl = 'microsoft' in platform.release().lower() or 'WSL_INTEROP' in os.environ
    if args.label == 'wsl' and not is_wsl:
        parser.error('run the WSL command inside its Ubuntu terminal')
    if args.label == 'oci' and is_wsl:
        parser.error('run the OCI command on the instance, and use --label wsl here')
    out = args.output.expanduser().absolute(); destination = Path(str(out)+'.tar.gz')
    if out.exists() or destination.exists():
        parser.error('output folder and archive must both be new paths')
    out.mkdir(parents=True)
    print('Output:',out,flush=True)
    build = out/'build'; build.mkdir()
    report = {'status':'incomplete','label':args.label,'suite':args.suite,'started_utc':datetime.now(timezone.utc).isoformat(),
              'platform':platform.uname()._asdict(),'python':sys.version,'commands':[], 'targets':[],
              'requested_runs_per_target':args.runs,'seconds_per_target':args.seconds,
              'scope':coverage_evidence.profile_for(args.suite).scope+' Saved-corpus Python replay is finite; prebuilt-std coverage is not claimed.',
              'constant_time_approved':False,'security_approved':False}
    started = time.monotonic()
    toolchain = args.toolchain_dir.expanduser().resolve()
    trace = out/'rustc-invocations.jsonl'
    env = build_environment(toolchain,trace)

    def run(name,command,timeout,environment=None,separate_stderr=False):
        log = out/(name+'.log'); log.parent.mkdir(parents=True,exist_ok=True)
        stderr = out/(name+'.stderr.log')
        report['commands'].append({'name':name,'argv':command,'timeout_seconds':timeout})
        with log.open('wb') as output:
            if separate_stderr:
                with stderr.open('wb') as errors:
                    done = subprocess.run(command,cwd=ROOT,env=environment,stdout=output,stderr=errors,timeout=timeout)
            else:
                done = subprocess.run(command,cwd=ROOT,env=environment,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
        text = log.read_text(errors='replace')
        diagnostics = text+(stderr.read_text(errors='replace') if separate_stderr else '')
        if not clean_exit(done.returncode,diagnostics):
            raise RuntimeError(name+' failed; see '+str(log))
        return text

    try:
        if tuple(references.TARGETS) != required_targets:
            raise RuntimeError('all suite targets are required: '+repr(required_targets))
        names = source_names()
        report['source_sha256'] = {name:digest(ROOT/name) for name in names}
        report['commit'] = run('git-head',['git','rev-parse','HEAD'],30).strip()
        report['sources_match_head'] = True
        for name in names:
            saved = subprocess.run(['git','show',report['commit']+':'+name],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
            if (saved.returncode or saved.stdout != (ROOT/name).read_bytes()
                    or hashlib.sha256(saved.stdout).hexdigest()!=report['source_sha256'][name]):
                report['sources_match_head'] = False
        if not report['sources_match_head']:
            raise RuntimeError('tested source differs from HEAD; commit it before platform comparison')
        target = machine+'-unknown-linux-gnu'
        rustc = run('rustc-version',[str(toolchain/'bin/rustc'),'-Vv'],30)
        if (f'release: {RUSTC_RELEASE}\n' not in rustc or f'commit-hash: {RUSTC_COMMIT}\n' not in rustc
                or f'host: {target}\n' not in rustc):
            raise RuntimeError('compiler must match the pinned nightly and current host')
        cargo_version = run('cargo-version',[str(toolchain/'bin/cargo'),'-V'],30)
        if not cargo_version.startswith('cargo 1.101.0-nightly '):
            raise RuntimeError('Cargo must belong to the pinned nightly')
        if (toolchain/'.spiral-toolchain.json').is_file():
            (out/'toolchain-installation.json').write_bytes((toolchain/'.spiral-toolchain.json').read_bytes())
        report['build_environment'] = {key:env[key] for key in ('RUSTFLAGS','RUSTC_WRAPPER','CARGO_PROFILE_RELEASE_LTO',
            'CARGO_PROFILE_RELEASE_OPT_LEVEL','CARGO_PROFILE_RELEASE_DEBUG','CARGO_PROFILE_RELEASE_CODEGEN_UNITS',
            'CARGO_PROFILE_RELEASE_PANIC','CARGO_PROFILE_RELEASE_STRIP','ASAN_OPTIONS','LSAN_OPTIONS')}
        if Path('/etc/os-release').is_file():
            (out/'os-release.txt').write_bytes(Path('/etc/os-release').read_bytes())
        if shutil.which('openssl'):
            run('openssl',['openssl','version','-a'],30)
        if args.suite == 'parsers':
            # Parser references are std-only and do not link production code.
            oracle_tests = build/'oracle-tests'
            run('compile-oracle-tests',[str(toolchain/'bin/rustc'),'--edition','2021','--test',
                str(ROOT/'protocol_rust/fuzz/oracles.rs'),'-o',str(oracle_tests)],120)
            run('oracle-tests',[str(oracle_tests)],120)
        else:
            # The independent record model uses ring rather than the production
            # ChaCha20Poly1305 crate. Keep these tests out of the compiler audit.
            print('Testing the independent Rust record model.',flush=True)
            model_log = run('record-model-tests',[str(toolchain/'bin/cargo'),'test','--locked','--manifest-path',
                str(ROOT/'protocol_rust/fuzz/Cargo.toml'),'--bin','record_replay','--target',target,
                '--target-dir',str(build/'model-test-target'),'-j',str(args.jobs)],1800,model_test_environment(env))
            if not model_tests_completed(model_log):
                raise RuntimeError('independent Rust record model tests did not execute')
        cargo_target = build/'cargo-target'
        print('Building Rust targets; first build can take several minutes. Log:',out/'cargo-build.log',flush=True)
        build_command = [str(toolchain/'bin/cargo'),'build','--locked','--manifest-path',
            str(ROOT/'protocol_rust/fuzz/Cargo.toml'),'--release','--target',target,
            '--target-dir',str(cargo_target),'-j',str(args.jobs)]
        for name in binary_names:
            build_command += ['--bin',name]
        run('cargo-build',build_command,1800,env)
        binaries = {name:cargo_target/target/'release'/name for name in binary_names}
        coverage_dir = out/'coverage'; coverage_dir.mkdir()
        report['coverage'] = coverage_evidence.verify(cargo_target,trace,binaries,coverage_dir,suite=args.suite)
        if report['coverage'].get('status') != 'verified':
            raise RuntimeError('runtime-only coverage evidence was not verified')
        print('Rust',args.suite,'coverage verified; harness/oracles excluded.',flush=True)
        corpus_seeds = references.seeds()
        for name in references.TARGETS:
            work = out/name; corpus = work/'corpus'; artifacts = work/'artifacts'
            corpus.mkdir(parents=True); artifacts.mkdir(); (work/'replay').mkdir()
            entry = {'name':name,'status':'incomplete','differential':{'status':'incomplete','expected_files':0,
                     'checked_files':0,'accepted_checked':0,'rejected_checked':0,'mismatches':[]}}
            report['targets'].append(entry)
            differential = entry['differential']
            for data in corpus_seeds[name]:
                if len(data) > references.MAX_LEN[name]:
                    raise RuntimeError('initial seed exceeds target bound')
                (corpus/hashlib.sha256(data).hexdigest()).write_bytes(data)
            entry['initial_corpus_files'] = len(list(corpus.iterdir()))
            command = [str(binaries[name+'_target']),str(corpus),'-runs='+str(args.runs),
                '-max_total_time='+str(args.seconds),'-seed=20261107','-max_len='+str(references.MAX_LEN[name]),
                '-timeout=5','-rss_limit_mb=1536','-print_final_stats=1','-artifact_prefix='+str(artifacts)+'/']
            report['commands'].append({'name':name+'/engine','argv':command,'timeout_seconds':args.seconds+60})
            print('Starting',name,'with at most',args.runs,'runs or',args.seconds,'seconds',flush=True)
            with (work/'engine.log').open('wb') as output:
                done = subprocess.run(command,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=args.seconds+60)
            text = (work/'engine.log').read_text(errors='replace'); metrics = parse_feedback(text)
            entry.update(engine_exit=done.returncode,feedback=metrics)
            if not search_completed(done.returncode,text,metrics):
                raise RuntimeError(name+' engine failed or lacked search feedback')
            corpus_files = sorted(corpus.iterdir()); manifest = []
            for path in corpus_files:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > references.MAX_LEN[name]:
                    raise RuntimeError('unexpected saved corpus file')
                data = path.read_bytes()
                manifest.append({'file':str(path.relative_to(out)),'sha256':hashlib.sha256(data).hexdigest(),
                                 'bytes':len(data),'accepted':references.expected(name,data)['accepted']})
            (work/'corpus-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
            entry['final_corpus_files'] = len(corpus_files)
            differential['expected_files'] = len(corpus_files)
            for at in range(0,len(corpus_files),32):
                batch = corpus_files[at:at+32]
                raw = run(name+'/replay/batch-'+str(at//32).zfill(4),
                    [str(binaries[replay_binary]),name,*map(str,batch)],180,env,True)
                rows = [decode_row(line) for line in raw.splitlines() if line.strip()]
                if len(rows) != len(batch):
                    raise RuntimeError('native replay did not return every input')
                for offset,(path,row) in enumerate(zip(batch,rows)):
                    data = path.read_bytes()
                    if hashlib.sha256(data).hexdigest()!=manifest[at+offset]['sha256']:
                        raise RuntimeError('input changed during replay')
                    expected = references.expected(name,data)
                    if not matches_reference(row,path,expected):
                        artifact = artifacts/('differential-'+hashlib.sha256(data).hexdigest())
                        artifact.write_bytes(data)
                        differential['mismatches'].append({'file':str(path.relative_to(out)),
                            'expected':expected,'native':row})
                        raise RuntimeError(name+' Rust/Python differential mismatch')
                    differential['checked_files'] += 1
                    differential['accepted_checked' if expected['accepted'] else 'rejected_checked'] += 1
            if (differential['checked_files'] != differential['expected_files']
                    or not differential['accepted_checked'] or not differential['rejected_checked']):
                raise RuntimeError('replay completion or accepted/rejected class missing')
            differential['status'] = 'passed'; entry['status'] = 'passed'
            print(name,json.dumps({'feedback':metrics,'differential':differential}),flush=True)
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed',error=repr(error))
    finally:
        for entry in report['targets']:
            artifacts = out/entry['name']/'artifacts'
            entry['artifacts'] = [str(path.relative_to(out)) for path in sorted(artifacts.iterdir()) if path.is_file()]
            if entry['status'] != 'passed' or entry['artifacts']:
                report['status'] = 'failed'
        if 'source_sha256' in report:
            report['sources_unchanged_during_run'] = all((ROOT/name).is_file() and digest(ROOT/name)==value
                for name,value in report['source_sha256'].items())
            if not report['sources_unchanged_during_run']:
                report.update(status='failed',error='source changed during run')
        report['elapsed_seconds'] = time.monotonic()-started
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report['archive'] = str(destination)
        write_report(out,report)
        try:
            bundle(out,destination)
        except Exception as error:
            report.update(status='failed',archive_error=repr(error))
            write_report(out,report)
    print(json.dumps({'status':report['status'],'archive':str(destination),
                      'error':report.get('error'),'archive_error':report.get('archive_error')}))
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
