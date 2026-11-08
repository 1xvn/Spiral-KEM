#!/usr/bin/env python3
"""Build and collect Linux amd64/arm64 secret-flow diagnostics, preserving errors.

Exit zero means collection completed. It is not constant-time or memory approval.
Requires installed Rust 1.99.1, C/OpenSSL, Valgrind and binutils; no auto-install.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from protocol_rust.diagnostics.receive_flow import digest,require
from protocol_rust.diagnostics.provenance import source_identity
from protocol_rust.fuzzing.campaign import source_names,write_report,bundle


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--toolchain-dir',type=Path)
    parser.add_argument('--valgrind',default=shutil.which('valgrind'))
    parser.add_argument('--loader',type=Path)
    parser.add_argument('--library-path',type=Path)
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','aarch64'):parser.error('requires Linux amd64 or arm64')
    if bool(args.loader)!=bool(args.library_path):parser.error('loader and library-path must be paired')
    if args.output:
        out=args.output.expanduser().absolute();out.mkdir(parents=True,exist_ok=False)
    else:
        out=Path(tempfile.mkdtemp(prefix='Spiral-secret-flow-'+platform.machine()+'-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-',dir=Path.home()))
    destination=Path(str(out)+'.tar.gz')
    if destination.exists():parser.error('archive already exists')
    print('Results:',out,flush=True)
    env=os.environ.copy()
    for name in list(env):
        if name in ('RUSTC','RUSTDOC','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER',
          'CARGO_BUILD_TARGET','CARGO_TARGET_DIR','VALGRIND_OPTS') or name.startswith(('CARGO_PROFILE_','SPIRAL_RX_TRACE_','SPIRAL_DERIVATION_')):env.pop(name,None)
    env.update(LC_ALL='C',RUSTUP_TOOLCHAIN='1.99.1',PYTHONDONTWRITEBYTECODE='1')
    report={'schema':'spiral-secret-flow-campaign/v1','diagnostic_complete':False,
      'constant_time_approved':False,'production_memory_passed':False,'platform':platform.uname()._asdict(),
      'started_utc':datetime.now(timezone.utc).isoformat(),'commands':[],'errors':[],'runner_sha256':digest(Path(__file__))}
    def run(label,command,timeout):
        print(label,flush=True)
        record={'name':label,'argv':command};report['commands'].append(record)
        with (out/(label+'.log')).open('wb') as stream:
            try:record['exit']=subprocess.run(command,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout).returncode
            except subprocess.TimeoutExpired:record.update(exit=None,timed_out=True);raise ValueError(label+' watchdog timeout')
        require(record['exit']==0,label+' failed; raw log retained')
        return (out/(label+'.log')).read_text(errors='replace')
    try:
        require(bool(args.valgrind),'Valgrind missing; install valgrind and libc6-dbg')
        for tool in ('cc','pkg-config','nm','objdump','readelf'):require(bool(shutil.which(tool)),'missing prerequisite: '+tool)
        rustup=shutil.which('rustup');tools={}
        for name in ('cargo','rustc','rustdoc'):
            if args.toolchain_dir:tools[name]=str(args.toolchain_dir.resolve()/'bin'/name)
            else:
                require(bool(rustup),'rustup or --toolchain-dir required')
                tools[name]=run('locate-'+name,[rustup,'which','--toolchain','1.99.1',name],30).strip()
        env.update(RUSTC=tools['rustc'],RUSTDOC=tools['rustdoc'])
        version=run('rustc-version',[tools['rustc'],'-Vv'],30)
        require('release: 1.99.1\n' in version and '58cf8f9c35b355199727627d07ae34a4e2846d67' in version,'exact Rust compiler required')
        require('host: '+platform.machine()+'-unknown-linux-gnu\n' in version,'compiler host differs')
        require(run('cargo-version',[tools['cargo'],'-V'],30).startswith('cargo 1.99.1 '),'exact Cargo required')
        run('valgrind-version',[args.valgrind,'--version'],30)
        names=set(source_names())|{str(p.relative_to(ROOT)) for p in (ROOT/'protocol_rust/diagnostics').glob('*.py')}
        report['source_sha256']={name:digest(ROOT/name) for name in sorted(names)}
        report.update(source_identity(ROOT))
        text=run('audit-build',[tools['cargo'],'test','--locked','--profile','audit','--manifest-path',str(ROOT/'protocol_rust/Cargo.toml'),
          '--target-dir',str(out/'build'),'--lib','--no-run','--message-format=json-render-diagnostics','-j','2'],1200)
        artifacts=[]
        for line in text.splitlines():
            try:row=json.loads(line)
            except ValueError:continue
            if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='spiral_protocol' and row.get('profile',{}).get('test') and row.get('executable'):artifacts.append(row)
        require(len(artifacts)==1,'one actual test executable required')
        binary=Path(artifacts[0]['executable']);report['binary_sha256']=digest(binary)
        native=run('native-functional',[str(binary),'--test-threads=1','--nocapture'],120)
        require(re.search(r'test result: ok\. 70 passed; 0 failed; 5 ignored;',native),'native fixture count differs')
        command=[sys.executable,str(ROOT/'protocol_rust/diagnostics/receive_flow.py'),'--rust-tests',str(binary),
          '--valgrind',args.valgrind,'--output',str(out/'trace')]
        if args.loader:command+=['--loader',str(args.loader),'--library-path',str(args.library_path)]
        run('secret-flow',command,1200)
        trace=json.loads((out/'trace/result.json').read_text())
        require(trace['diagnostic_complete'] is True,'trace incomplete')
        require(trace['counts']=={'fixture_variants':78,'public_baselines':78,'key_prefix_taint_traces':78,'positive_controls':2},'matrix incomplete')
        require(len(trace['derivation_seal_sign'])==2,'derivation baselines incomplete')
        report['trace_counts']=trace['counts'];report['instruction_mapping_complete']=trace['instruction_mapping_complete']
        report['source_and_binary_unchanged']=digest(binary)==report['binary_sha256'] and all(digest(ROOT/name)==value for name,value in report['source_sha256'].items())
        require(report['source_and_binary_unchanged'],'source or binary changed')
        report['diagnostic_complete']=True
    except Exception as error:report['errors'].append(str(error));print(str(error),file=sys.stderr)
    finally:
        report['finished_utc']=datetime.now(timezone.utc).isoformat()
        write_report(out,report)
        bundle(out,destination)
    print(json.dumps({'diagnostic_complete':report['diagnostic_complete'],'archive':str(destination),'errors':report['errors'],
      'constant_time_approved':False,'production_memory_passed':False}),flush=True)
    return 0 if report['diagnostic_complete'] else 1


if __name__=='__main__':raise SystemExit(main())
