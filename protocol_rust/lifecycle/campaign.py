#!/usr/bin/env python3
"""Finite channel-loop and authenticated TLS lifecycle checks, with ASan.

Synthetic short-I/O checks and real TLS checks have separate evidence and counts.
No libFuzzer or runtime coverage instrumentation is used by this campaign.
"""
import argparse
from datetime import datetime,timezone
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

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))

from protocol_rust.fuzzing import campaign as shared
from protocol_rust.fuzzing.coverage_evidence import _values
from protocol_rust.fuzzing.install_toolchain import RUSTC_COMMIT,RUSTC_RELEASE

LOOP_IDS = frozenset({
 'backpressure_close_discards_undelivered_data_and_finishes',
 'backpressure_failure_cancels_delivery_without_reading_more',
 'cancelled_queued_ack_keeps_complete_record',
 'cancelled_sender_during_partial_write_keeps_commit',
 'close_racing_partial_write_rejects_queued_requests',
 'failed_shutdown_after_flushed_close_is_not_clean',
 'fragmented_close_preserves_progress_and_rejects_tail',
 'pending_shutdown_after_flushed_close_expires',
})
TLS_IDS = frozenset({'simultaneous_close','cancelled_send','cancelled_receive',
 'cancelled_close_resume','dropped_session_sender','concurrent_senders'})
PEER_IDS = frozenset({'independent_clean_close','independent_fragmented_application_writes',
 'independent_abrupt_tcp_eof','independent_tls_close_notify_without_record',
 'independent_close_without_tls_notify','independent_trailing_after_close'})


def require(condition,message):
    if not condition:
        raise ValueError(message)


def sources():
    names=set(shared.source_names())
    names.update(str(p.relative_to(ROOT)) for p in (ROOT/'protocol_rust/lifecycle').glob('*.py'))
    names.update(str(p.relative_to(ROOT)) for p in (ROOT/'protocol_v01').glob('*.py'))
    names.update(('protocol_rust/examples/lifecycle_probe.rs','protocol_rust/interop.py',
      'protocol_v01/validation/independent_peer.py','protocol_v01/requirements.txt',
      'code/opt2/spiral_kem_toy_v031_opt2.py'))
    return sorted(names)


def build_environment(toolchain,trace):
    env=shared.build_environment(toolchain,trace)
    env.update(RUSTC_WRAPPER=str(ROOT/'protocol_rust/lifecycle/rustc_audit.py'),
      SPIRAL_LIFECYCLE_RUSTC_TRACE=str(trace),CARGO_PROFILE_RELEASE_PANIC='unwind')
    env.pop('SPIRAL_RUSTC_TRACE',None)
    return env


def parse_cases(text,prefix):
    rows=[]
    for line in text.splitlines():
        if prefix in line:
            rows.append(shared.decode_row(line.split(prefix,1)[1]))
    return rows


def validate_cases(rows,ids,rounds=1,require_rounds=False):
    require(len(rows)==len(ids)*rounds,'missing/extra case observations')
    counts={name:0 for name in ids}
    observed=set()
    for row in rows:
        require(isinstance(row,dict) and row.get('id') in ids,'unexpected case identifier')
        require(row.get('status')=='passed','case did not pass')
        if require_rounds:
            turn=row.get('round')
            require(type(turn) is int and 0<=turn<rounds,'invalid/missing round')
            require((turn,row['id']) not in observed,'duplicate case within a round')
            observed.add((turn,row['id']))
        counts[row['id']]+=1
    require(all(count==rounds for count in counts.values()),'duplicate or missing required case')
    return counts


def validate_tls_result(rows,summary,rounds,seed):
    validate_cases(rows,TLS_IDS,rounds,True)
    sessions=set()
    delivered={'simultaneous_close':2,'cancelled_send':2,'cancelled_receive':1,
      'cancelled_close_resume':1,'dropped_session_sender':0,'concurrent_senders':16}
    cancelled={'cancelled_send','cancelled_receive','cancelled_close_resume'}
    for row in rows:
        require(all(row.get(key) is True for key in ('authenticated_pair','matching_transcript_and_binding','admission_released')),'authenticated session/cleanup observation missing')
        sid=row.get('session_id')
        require(isinstance(sid,str) and re.fullmatch('[0-9a-f]{32}',sid) and sid!='0'*32 and sid not in sessions,'invalid/reused authenticated SID')
        sessions.add(sid)
        require(type(row.get('delivered')) is int and row['delivered']==delivered[row['id']],'delivery accounting mismatch')
        require(type(row.get('cancelled_waiters')) is int and row['cancelled_waiters']==int(row['id'] in cancelled),'cancellation evidence missing')
        require(row.get('clean_close') is (row['id']!='dropped_session_sender'),'clean/failed close expectation mismatch')
    require(summary.get('status')=='passed' and summary.get('auth_key_closed') is True and summary.get('error') is None,'authenticated TLS final cleanup failed')
    for key,value in (('case_count',len(TLS_IDS)*rounds),('rounds',rounds),('seed',seed)):
        require(type(summary.get(key)) is int and summary[key]==value,'authenticated TLS summary accounting mismatch')
    kem=summary.get('kem',{})
    for key,value in (('live_keys',0),('executed_jobs',len(TLS_IDS)*rounds*3),('rejected_jobs',0)):
        require(type(kem.get(key)) is int and kem[key]==value,'KEM shutdown accounting mismatch')


def validate_peer_result(peer,rounds,seed):
    from protocol_rust.lifecycle.tls_peer import parse_report
    require(peer.get('status')=='passed','independent TLS peer suite failed')
    for key,value in (('rounds',rounds),('seed',seed),('tests',len(PEER_IDS)*rounds),('expected_cases',len(PEER_IDS)*rounds),('failures',0),('errors',0)):
        require(type(peer.get(key)) is int and peer[key]==value,'independent peer summary accounting mismatch')
    rows=peer.get('cases',[])
    validate_cases(rows,PEER_IDS,rounds,True)
    sessions=set()
    for row in rows:
        require(row.get('authenticated') is True and row.get('authenticated_echo') is True,'independent peer did not reach authenticated DATA')
        sid=row.get('session_id')
        require(isinstance(sid,str) and re.fullmatch('[0-9a-f]{32}',sid) and sid!='0'*32 and sid not in sessions,'invalid/reused independent session')
        sessions.add(sid)
        clean=row['id'] in ('independent_clean_close','independent_fragmented_application_writes')
        report,error=parse_report(row['server_stdout'],row['server_stderr'],row['server_exit'],clean=clean)
        require(report==row['server_report'] and error==row['observed_error'],'raw server evidence disagrees with reported result')
        if row['id']=='independent_close_without_tls_notify':
            require(row.get('tcp_held_open') is True and row.get('tls_close_notify_sent') is False and row.get('close_grace_termination_observed') is True and row.get('termination_seconds',0)>=1,'close-grace observation incomplete')
    return rows


def validate_loop_log(text):
    groups=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
    require(groups==[('8','0','0')],'all eight loop tests must execute without ignores')
    rows=parse_cases(text,'LIFECYCLE_CASE ')
    validate_cases(rows,LOOP_IDS)
    require(all(type(row.get('subcases')) is int and row['subcases']>0 for row in rows),'missing loop subcase count')
    return rows


def compiled_test_binary(text,build):
    candidates=[]
    for line in text.splitlines():
        try:
            row=json.loads(line)
        except ValueError:
            continue
        if (row.get('reason')=='compiler-artifact' and row.get('profile',{}).get('test') is True
                and row.get('target',{}).get('name')=='spiral_protocol' and row.get('executable')):
            candidates.append(Path(row['executable']).resolve())
    require(len(set(candidates))==1,'missing/ambiguous library test executable')
    path=candidates[0]
    require(path.is_relative_to(build.resolve()) and path.is_file(),'test executable outside build')
    return path


def verify_audit(path,expected_compiler=None,target=None):
    rows=[shared.decode_row(line) for line in path.read_text().splitlines()]
    selected={name:[] for name in ('library','library_tests','lifecycle_probe','spiral_lab')}
    for row in rows:
        args=row.get('args')
        require(isinstance(args,list) and all(isinstance(arg,str) for arg in args),'bad compiler audit arguments')
        if any(arg in ('-vV','-V','--version') or arg.startswith('--print') for arg in args):
            continue
        names=_values(args,'--crate-name')
        name=names[0] if len(names)==1 else None
        codegen=_values(args,'-C')
        require(not any('sancov' in value or 'sanitizer-coverage' in value for value in codegen),'unexpected feedback instrumentation')
        key='library_tests' if name=='spiral_protocol' and '--test' in args else 'library' if name=='spiral_protocol' else name
        if key not in selected:
            continue
        require(isinstance(row.get('cwd'),str) and Path(row['cwd']).is_absolute(),'compiler working directory missing')
        if expected_compiler is not None:
            require(row.get('rustc')==str(expected_compiler),'selected compiler path changed')
        if target is not None:
            require(_values(args,'--target')==[target],'selected compiler target changed')
        source_args=[value for value in args if value.endswith('.rs') and not value.startswith('-')]
        expected_source=ROOT/('protocol_rust/examples/lifecycle_probe.rs' if key=='lifecycle_probe' else
          'protocol_rust/src/main.rs' if key=='spiral_lab' else 'protocol_rust/src/lib.rs')
        require(len(source_args)==1 and (Path(row['cwd'])/source_args[0]).resolve()==expected_source,'selected Rust source path changed')
        require([v.split('=',1)[1] for v in _values(args,'-Z') if v.startswith('sanitizer=')]==['address'],'ASan absent from selected compile')
        for option,allowed in {'debuginfo':{'1','2'},'force-frame-pointers':{'yes','true','on'},
          'overflow-checks':{'yes','true','on'},'debug-assertions':{'yes','true','on'},'codegen-units':{'1'}}.items():
            values=[v.split('=',1)[1] for v in codegen if v.startswith(option+'=')]
            require(bool(values) and all(v in allowed for v in values),'required compiler option missing/overridden: '+option)
        require(all(v in ('lto=off','lto=false','lto=no','lto=0') for v in codegen if v.startswith('lto=')),'LTO unexpectedly enabled')
        selected[key].append(row)
    require(all(len(items)==1 for items in selected.values()),'one audited compile per required target is mandatory')
    return {'status':'verified','invocations':len(rows),'required_compiles':list(selected),
      'feedback_instrumentation':False,'sanitizer':'address','compiler_invocations':selected}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label',choices=('oci','wsl','local'),required=True)
    p.add_argument('--toolchain-dir',type=Path,required=True)
    p.add_argument('--python',required=True,help='Python venv with protocol_v01/requirements.txt installed')
    p.add_argument('--rounds',type=int,default=5)
    p.add_argument('--seed',type=int,default=20261108)
    p.add_argument('--jobs',type=int,default=2)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if not __debug__:
        p.error('Python -O is unsupported')
    if not 1<=args.rounds<=50 or not 0<=args.seed<2**63 or not 1<=args.jobs<=4:
        p.error('rounds1..50, seed0..2**63-1, jobs1..4')
    machine=platform.machine().lower()
    if platform.system()!='Linux' or machine not in ('x86_64','aarch64'):
        p.error('Linux x86_64 or aarch64 required')
    wsl='microsoft' in platform.release().lower() or 'WSL_INTEROP' in os.environ
    if (args.label=='wsl' and not wsl) or (args.label=='oci' and wsl):
        p.error('environment label does not match current host')
    out=args.output.expanduser().absolute(); archive=Path(str(out)+'.tar.gz')
    if out.exists() or archive.exists():
        p.error('output folder and archive must be new')
    out.mkdir(parents=True); build=out/'build'; build.mkdir()
    toolchain=args.toolchain_dir.expanduser().resolve()
    # Keep a venv symlink unresolved; resolving it selects the system interpreter.
    python=os.path.abspath(shutil.which(args.python) or os.path.expanduser(args.python))
    env=build_environment(toolchain,out/'rustc-invocations.jsonl')
    env['PYTHONDONTWRITEBYTECODE']='1'
    report={'status':'incomplete','label':args.label,'rounds':args.rounds,'seed':args.seed,
      'started_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.uname()._asdict(),
      'commands':[],'loop_rounds':[],'scope':'Finite synthetic channel-loop and real authenticated TLS lifecycle checks. No runtime coverage, full memory, constant-time or cryptographic approval.',
      'constant_time_approved':False,'security_approved':False}
    start=time.monotonic()

    def run(name,command,timeout,runenv=env):
        log=out/(name+'.log'); log.parent.mkdir(parents=True,exist_ok=True)
        report['commands'].append({'name':name,'argv':list(map(str,command)),'timeout_seconds':timeout})
        with log.open('wb') as stream:
            done=subprocess.run(list(map(str,command)),cwd=ROOT,env=runenv,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
        text=log.read_text(errors='replace')
        require(shared.clean_exit(done.returncode,text),name+' failed; see '+str(log))
        return text

    try:
        names=sources(); report['source_sha256']={name:shared.digest(ROOT/name) for name in names}
        report['commit']=run('git-head',['git','rev-parse','HEAD'],30).strip()
        report['sources_match_head']=all(hashlib.sha256(subprocess.check_output(['git','show',report['commit']+':'+name],cwd=ROOT)).hexdigest()==value for name,value in report['source_sha256'].items())
        require(report['sources_match_head'],'sources differ from HEAD; commit before platform comparison')
        target=machine+'-unknown-linux-gnu'
        version=run('rustc-version',[toolchain/'bin/rustc','-Vv'],30)
        require(all(part in version for part in (f'release: {RUSTC_RELEASE}\n',f'commit-hash: {RUSTC_COMMIT}\n',f'host: {target}\n')),'pinned nightly/current host required')
        require(run('cargo-version',[toolchain/'bin/cargo','-V'],30).startswith('cargo 1.101.0-nightly '),'wrong Cargo')
        receipt=toolchain/'.spiral-toolchain.json'
        if receipt.is_file():
            shutil.copyfile(receipt,out/'toolchain-installation.json')
        deps=run('python-dependencies',[python,'-c','import sys,json,importlib.metadata as m; print(json.dumps({"python":sys.version,"packages":{n:m.version(n) for n in ["cryptography","pyOpenSSL","cffi","pycparser","typing_extensions"]}}))'],30)
        package_info=shared.decode_row(deps.strip())
        for line in (ROOT/'protocol_v01/requirements.txt').read_text().splitlines():
            if line.strip() and not line.startswith('#'):
                name,version=line.strip().split('==')
                require(package_info['packages'].get(name)==version,'TLS peer dependency version mismatch: '+name)
        report['python_dependencies']=package_info
        report['build_environment']={key:env[key] for key in ('RUSTFLAGS','RUSTC_WRAPPER','CARGO_PROFILE_RELEASE_LTO','CARGO_PROFILE_RELEASE_OPT_LEVEL','CARGO_PROFILE_RELEASE_CODEGEN_UNITS','CARGO_PROFILE_RELEASE_DEBUG','CARGO_PROFILE_RELEASE_PANIC','ASAN_OPTIONS','LSAN_OPTIONS')}
        print('Building channel test executable and real TLS probes.',flush=True)
        cargo=[toolchain/'bin/cargo']; common=['--locked','--manifest-path',ROOT/'protocol_rust/Cargo.toml','--release','--target',target,'--target-dir',build/'cargo-target','-j',str(args.jobs)]
        compiled=run('cargo-tests',cargo+['test',*common,'--lib','--no-run','--message-format=json-render-diagnostics'],1800)
        libtest=compiled_test_binary(compiled,build)
        run('cargo-probes',cargo+['build',*common,'--example','lifecycle_probe','--bin','spiral-lab'],1800)
        probe=build/'cargo-target'/target/'release/examples/lifecycle_probe'
        lab=build/'cargo-target'/target/'release/spiral-lab'
        report['compiler_audit']=verify_audit(out/'rustc-invocations.jsonl',toolchain/'bin/rustc',target)
        binaries={'loop_tests':libtest,'authenticated_probe':probe,'lab_server':lab}
        report['binaries']={}
        for name,path in binaries.items():
            symbols=run('symbols-'+name,['nm','--defined-only','--no-demangle',path],60)
            require(re.search(r'\b__asan_init$',symbols,re.MULTILINE) is not None,'ASan runtime symbol missing: '+name)
            report['binaries'][name]={'path':str(path),'sha256':shared.digest(path),'bytes':path.stat().st_size,'asan_init_present':True}
        # All generated credentials stay under excluded build/, never in logs.
        fixture=build/'fixtures'; fixture.mkdir(mode=0o700)
        code='import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from interop import identities; identities(Path(sys.argv[2]))'
        run('fixture-setup',[python,'-c',code,ROOT/'protocol_rust',fixture],30)
        for turn in range(args.rounds):
            print('Channel compound checks round',turn+1,'of',args.rounds,flush=True)
            case_env=dict(env,SPIRAL_LIFECYCLE_SEED=str(args.seed+turn))
            text=run('loops/round-'+str(turn).zfill(3),[libtest,'channel::lifecycle_tests::','--test-threads=1','--nocapture'],120,case_env)
            report['loop_rounds'].append({'round':turn,'status':'passed','cases':validate_loop_log(text)})
        print('Running authenticated Rust TLS lifecycle cases.',flush=True)
        text=run('authenticated-tls',[probe,'--fixture-dir',fixture,'--rounds',args.rounds,'--seed',args.seed],max(120,args.rounds*60))
        tls_rows=parse_cases(text,'LIFECYCLE_TLS_CASE ')
        summary=shared.decode_row(text.strip().splitlines()[-1])
        validate_tls_result(tls_rows,summary,args.rounds,args.seed)
        report['authenticated_tls']={'status':'passed','cases':tls_rows,'summary':summary}
        print('Running independent Python TLS lifecycle cases.',flush=True)
        run('independent-tls',[python,ROOT/'protocol_rust/lifecycle/tls_peer.py','--binary',lab,'--rounds',args.rounds,'--seed',args.seed,'--output',out/'independent-tls.json'],max(180,args.rounds*90))
        peer=shared.decode_row((out/'independent-tls.json').read_text())
        validate_peer_result(peer,args.rounds,args.seed)
        report['independent_tls']={'status':'passed','cases':peer['cases']}
        report['case_counts']={'loop_methods':len(LOOP_IDS)*args.rounds,
          'loop_subcases':sum(row['subcases'] for turn in report['loop_rounds'] for row in turn['cases']),
          'authenticated_rust_tls':len(tls_rows),'independent_peer_tls':len(peer['cases'])}
        report['status']='passed'
    except Exception as error:
        report.update(status='failed',error=repr(error))
    finally:
        if 'source_sha256' in report:
            report['sources_unchanged_during_run']=all((ROOT/name).is_file() and shared.digest(ROOT/name)==value for name,value in report['source_sha256'].items())
            if not report['sources_unchanged_during_run']:
                report.update(status='failed',error='source changed during run')
        report.update(elapsed_seconds=time.monotonic()-start,finished_utc=datetime.now(timezone.utc).isoformat(),archive=str(archive))
        shared.write_report(out,report)
        try:
            shared.bundle(out,archive)
        except Exception as error:
            report.update(status='failed',archive_error=repr(error)); shared.write_report(out,report)
    print(json.dumps({'status':report['status'],'archive':str(archive),'error':report.get('error'),'case_counts':report.get('case_counts')}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
