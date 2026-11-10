#!/usr/bin/env python3
"""Record actual Rx secret-flow warnings without declassifying or suppressing.

Completion is not a zero-warning, memory, or constant-time acceptance verdict.
All cases use public synthetic fixtures. Only Memcheck shadow state is changed.
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
import time

ROOT=Path(__file__).resolve().parents[2]
import sys
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))
from protocol_rust.diagnostics.libtest_memory import parse_memcheck
from protocol_rust.diagnostics.provenance import source_identity
from protocol_rust.fuzzing.campaign import bundle,write_report,source_names

TRACE='receive_audit::trace_actual_receive'
POSITIVES={'branch':'receive_audit::positive_secret_branch','address':'receive_audit::positive_secret_address'}
LENGTHS=(1,16,63,64,65,1024,16384)


def require(condition,message):
    if not condition: raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def variants():
    rows=[]
    for role in (0,1):
        for length in LENGTHS:
            for mode in ('data-valid','data-bad-tag','data-bad-header'):
                rows.append({'mode':mode,'role':role,'length':length,'reason':0,'tag_index':15})
        for index in range(15):
            rows.append({'mode':'data-bad-tag','role':role,'length':65,'reason':0,'tag_index':index})
        rows.append({'mode':'close-valid','role':role,'length':1,'reason':0,'tag_index':15})
        for reason in (3,255):
            rows.append({'mode':'close-invalid-reason','role':role,'length':1,'reason':reason,'tag_index':15})
    return rows


def branch_records(text):
    lines=text.splitlines(); rows=[]
    for at,line in enumerate(lines):
        if not re.search(r'Conditional jump or move depends|Use of uninitialised value',line):continue
        stack=[]
        for item in lines[at+1:]:
            if not re.sub(r'^==\d+==\s*','',item).strip():break
            stack.append(item)
        require(bool(stack),'missing branch/address stack')
        match=re.search(r'\bat (0x[0-9A-Fa-f]+):',stack[0])
        require(match is not None,'missing top instruction address')
        rows.append({'kind':'conditional' if 'Conditional jump' in line else 'undefined_value_or_address',
                     'message':line,'stack':stack,'runtime_ip':int(match[1],16)})
    return rows


def category(record,instruction_verified):
    """Descriptive source candidates only; never an allowed-warning filter."""
    if not instruction_verified or record['kind']!='conditional':return 'unclassified'
    top=record['stack'][0]
    if ('decrypt_in_place_detached' in top and '(src/cipher.rs:87)' in top):
        return 'authentication_decision_candidate'
    if ('map_err<' in top and '(library/core/src/result.rs:965)' in top
            and any('(records.rs:215)' in row for row in record['stack'][1:3])):
        return 'authentication_result_propagation_candidate'
    if '(records.rs:216)' in top:return 'close_reason_validity_candidate'
    return 'unclassified'


def inspect_log(text,code):
    parsed=parse_memcheck(text); warnings=branch_records(text)
    require(not re.search(r'Invalid (?:read|write|free)|Mismatched free|Syscall param .*uninitialised',text),'unexpected memory-use diagnostic')
    require(parsed['leaks']['definitely lost']['bytes']==0 and parsed['leaks']['indirectly lost']['bytes']==0,'unexpected definite/indirect leak')
    require(parsed['leaks']['suppressed']['bytes']==0 and parsed['summary']['suppressed_errors']==0 and parsed['summary']['suppressed_contexts']==0,'suppressed diagnostic')
    losses=parsed['possibly_lost_48_records']
    require(len(losses)<=1 and all(row['classification']=='std_thread_and_libtest'
      and 'std::thread::current::init_current' in row['stack'] and 'ArcInner' in row['stack']
      for row in losses),'unexpected 48-byte ownership stack')
    require(parsed['leaks']['possibly lost']=={'bytes':48*len(losses),'blocks':len(losses)},'unexpected possible loss')
    require(parsed['summary']['contexts']==len(warnings)+len(losses),'unparsed or extra diagnostic context')
    require(parsed['summary']['errors']>=parsed['summary']['contexts'],'error count below context count')
    require(code==(99 if parsed['summary']['errors'] else 0),'exit disagrees with diagnostics')
    return parsed,warnings


def completed(text,marker):
    return (marker in text and re.search(r'(?m)^running 1 test\s*$',text) is not None
      and re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;',text) is not None)


def linked_instructions(text):
    instructions={}
    for line in text.splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+(?:(?:[0-9a-f]{8}|[0-9a-f]{2})\s+)+\s*(.*)',line)
        if match and match[2]:instructions[int(match[1],16)]=match[2]
    return instructions


def annotate(record,bias,instructions):
    rva=record['runtime_ip']-bias if bias is not None else None
    asm=instructions.get(rva,'')
    verified=bool(asm) and bool(re.match(r'(?:j(?!mp)[a-z]+|cmov[a-z]+|set[a-z]+|b\.[a-z]+|cbn?z|tbn?z|csel|csinc|csinv|csneg|csetm?)\b',asm))
    return {**record,'elf_rva':rva,'instruction':asm,'instruction_mapped':bool(asm),'conditional_instruction_verified':verified,
      'classification':category(record,verified)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rust-tests',type=Path,required=True)
    p.add_argument('--valgrind',required=True)
    p.add_argument('--loader',type=Path)
    p.add_argument('--library-path',type=Path)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','aarch64'):p.error('requires Linux x86-64 or aarch64')
    if bool(args.loader)!=bool(args.library_path):p.error('loader/library-path must be paired')
    binary=args.rust_tests.resolve(); vg=shutil.which(args.valgrind)
    if not binary.is_file() or not vg:p.error('test executable and Valgrind must exist')
    out=args.output.expanduser().absolute();archive=Path(str(out)+'.tar.gz')
    if out.exists() or archive.exists():p.error('output and archive must be new')
    out.mkdir(parents=True)
    env=dict(os.environ,LC_ALL='C',RUST_BACKTRACE='0')
    env.pop('VALGRIND_OPTS',None);env.pop('RUST_TEST_NOCAPTURE',None)
    for name in list(env):
        if name.startswith('SPIRAL_RX_TRACE_'):env.pop(name)
    report={'schema':'spiral-receive-secret-flow/v2','started_utc':datetime.now(timezone.utc).isoformat(),
      'diagnostic_complete':False,'constant_time_approved':False,'production_memory_passed':False,
      'binary':{'path':str(binary),'sha256':digest(binary),'bytes':binary.stat().st_size},
      'runner_sha256':digest(Path(__file__)),'public_contract':'AEAD authentication bit and CLOSE reason-range validity bit; DATA plaintext and full CLOSE value remain secret.',
      'platform':dict(platform.uname()._asdict(), node="redacted"),'declassification_used':True,'receive_declassification_used':False,
      'derivation_wire_output_declassification_used':True,'suppression_used':False,'positive_controls':[],'cases':[],'errors':[]}
    prefix=[str(args.loader.resolve()),'--library-path',str(args.library_path.resolve())] if args.loader else []
    started=time.monotonic()

    def run(label,command,environment=env):
        stdout=out/(label+'.stdout');stderr=out/(label+'.stderr');maps=[]
        with stdout.open('wb') as a,stderr.open('wb') as b:
            child=subprocess.Popen(command,cwd=ROOT,env=environment,stdout=a,stderr=b)
            deadline=time.monotonic()+120
            while child.poll() is None and time.monotonic()<deadline:
                try:
                    maps=[line for line in Path(f'/proc/{child.pid}/maps').read_text().splitlines() if line.endswith(' '+str(binary))]
                except OSError:maps=[]
                if maps:break
                time.sleep(0.005)
            try:code=child.wait(timeout=max(0.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill();child.wait();raise ValueError(label+' watchdog timeout')
        return {'argv':command,'exit':code,'stdout':stdout.name,'stderr':stderr.name,
          'binary_mappings':maps},stdout.read_text(errors='replace'),stderr.read_text(errors='replace')

    try:
        report.update(source_identity(ROOT))
        report['source_sha256']={name:digest(ROOT/name) for name in source_names()}
        report['tools']={}
        for name,command in (('valgrind',[vg,'--version']),('objdump',['objdump','--version']),
                             ('nm',['nm','--version']),('readelf',['readelf','--version'])):
            version=subprocess.check_output(command,env=env,text=True)
            path=Path(shutil.which(command[0])).resolve()
            report['tools'][name]={'version':version,'path':str(path),'sha256':digest(path)}
        if args.loader:
            report['loader']={'path':str(args.loader.resolve()),'sha256':digest(args.loader.resolve()),
              'library_path':str(args.library_path.resolve())}
        # Keep only the relevant linked functions, not a complete ELF dump.
        nm=subprocess.check_output(['nm','--defined-only','--no-demangle',str(binary)],text=True)
        syms=[line.split()[-1] for line in nm.splitlines() if any(marker in line for marker in
              ('2Rx6decode','25decrypt_in_place_detached','20trace_actual_receive','positive_secret_'))]
        require(any('2Rx6decode' in name for name in syms),'actual Rx symbol missing')
        (out/'linked-symbols.txt').write_text('\n'.join(line for line in nm.splitlines() if line.split()[-1] in syms)+'\n')
        disassembly='\n'.join(subprocess.check_output(['objdump','-d','-l','--inlines','--disassemble='+symbol,str(binary)],text=True) for symbol in syms)
        (out/'linked-disassembly.txt').write_text(disassembly)
        instructions=linked_instructions(disassembly)
        require(bool(instructions),'no linked instructions')
        headers=subprocess.check_output(['readelf','-Wl',str(binary)],text=True)
        (out/'elf-program-headers.txt').write_text(headers)
        load=re.search(r'(?m)^\s*LOAD\s+0x0+\s+0x0+\s+',headers)
        require(load is not None,'expected zero-based PIE load segment')
        require('DYN (Position-Independent Executable file)' in headers,'expected PIE executable')
        native,stdout,stderr=run('public-functional',prefix+[str(binary),'receive_audit::','--test-threads=1','--nocapture'])
        require(native['exit']==0 and not stderr and re.search(r'test result: ok\. 2 passed; 0 failed; 3 ignored;',stdout),'public functional tests failed')
        require('"fixtures_checked":78' in stdout,'all functional fixtures did not execute')
        report['functional']=native

        def measure(label,test,environment,marker):
            log=out/(label+'.log')
            command=[str(Path(vg).resolve()),'--command-line-only=yes','--tool=memcheck',
              '--leak-check=full','--show-leak-kinds=all','--errors-for-leak-kinds=definite,indirect,possible',
              '--error-exitcode=99','--num-callers=32','--log-file='+str(log),*prefix,str(binary),
              '--exact',test,'--ignored','--test-threads=1','--nocapture']
            record,stdout,stderr=run(label,command,environment)
            require(completed(stdout,marker) and not stderr,'test failed or missing: '+label)
            parsed,warnings=inspect_log(log.read_text(),record['exit'])
            bias=None
            for mapping in record['binary_mappings']:
                fields=mapping.split()
                if int(fields[2],16)==0:bias=int(fields[0].split('-')[0],16);break
            warnings=[annotate(warning,bias,instructions) for warning in warnings]
            return {**record,'log':log.name,'memcheck_summary':parsed['summary'],
               'leaks':parsed['leaks'],'warnings':warnings,'instruction_mapping_complete':all(row['instruction_mapped'] for row in warnings)}

        for kind,test in POSITIVES.items():
            record=measure('positive-'+kind,test,env,'RX_AUDIT_POSITIVE_COMPLETED '+kind)
            require(any(row['kind']==('conditional' if kind=='branch' else 'undefined_value_or_address') for row in record['warnings']),'positive control did not detect '+kind)
            report['positive_controls'].append({'kind':kind,**record})
        report['derivation_seal_sign']=[]
        for taint in ('public','secret'):
            record=measure('derivation-'+taint,'ffi::taint_audit::rust_secret_derivation_sealing_and_signing',
              dict(env,SPIRAL_DERIVATION_TAINT=taint),'DERIVATION_AUDIT_COMPLETED')
            if taint=='public':require(not record['warnings'],'unexpected warning in public derivation baseline')
            report['derivation_seal_sign'].append({'taint':taint,**record})
        matrix=variants();require(len(matrix)==78,'incomplete fixture matrix')
        for index,parameters in enumerate(matrix):
            for taint in ('public','secret'):
                label=f'case-{index:03d}-{taint}'
                case_env=dict(env,**{'SPIRAL_RX_TRACE_'+key.upper():str(value) for key,value in parameters.items()},SPIRAL_RX_TRACE_TAINT=taint)
                marker='RX_AUDIT_COMPLETED '+parameters['mode']+' '+ ' '.join(f'{key}={parameters[key]}' for key in ('role','length','reason','tag_index'))+' taint='+taint
                record=measure(label,TRACE,case_env,marker)
                if taint=='public' or parameters['mode']=='data-bad-header':
                    require(not record['warnings'],'unexpected taint warning in public/pre-auth control')
                report['cases'].append({'index':index,'parameters':parameters,'taint':taint,**record})
            if (index+1)%10==0:print('receive fixtures completed',index+1,'of',len(matrix),flush=True)
        require(digest(binary)==report['binary']['sha256'],'test executable changed during measurement')
        require(all(digest(ROOT/name)==value for name,value in report['source_sha256'].items()),'source changed during measurement')
        report['binary_and_source_unchanged']=True
        measurements=report['positive_controls']+report['cases']+report['derivation_seal_sign']
        report['instruction_mapping_complete']=all(row['instruction_mapping_complete'] for row in measurements)
        report['unclassified_warning_contexts']=sum(warning['classification']=='unclassified' for row in measurements for warning in row['warnings'])
        report['diagnostic_complete']=True
        report['counts']={'fixture_variants':len(matrix),'public_baselines':len(matrix),'key_prefix_taint_traces':len(matrix),'positive_controls':2}
    except Exception as error:
        report['errors'].append(repr(error))
    finally:
        report['elapsed_seconds']=time.monotonic()-started
        report['finished_utc']=datetime.now(timezone.utc).isoformat()
        write_report(out,report)
        try:bundle(out,archive)
        except Exception as error:
            report['diagnostic_complete']=False;report['errors'].append('archive: '+repr(error));write_report(out,report)
    print(json.dumps({'diagnostic_complete':report['diagnostic_complete'],'errors':report['errors'],
      'counts':report.get('counts'),'constant_time_approved':False,'archive':str(archive)}))
    return 0 if report['diagnostic_complete'] else 1


if __name__=='__main__':raise SystemExit(main())
