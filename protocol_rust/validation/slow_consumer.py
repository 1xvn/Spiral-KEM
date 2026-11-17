#!/usr/bin/env python3
"""Operator-run bounded receive-queue and retained-buffer pressure over SSH."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

import cross_host_smoke as base
import load_campaign as campaign
from backpressure_contract import PressureTracker

IDENTIFIERS=('session_id','binding_hash','transcript_hash')
CASES=('release','cancel','timeout')


def monitor(client, server, tunnel, outputs, controller, case):
    """Collect both peers without consuming the server's single connection."""
    tracker=PressureTracker(case)
    buffers={role:b'' for role in ('server','client')}
    totals={role:0 for role in buffers}
    processes={'client':client,'server':server}
    # Covers the production 60-second idle limit, two-second close, and cleanup.
    # This is an emergency collection bound, not an accepted expiry outcome.
    deadline=time.monotonic()+(100 if case=='timeout' else 25)
    with selectors.DefaultSelector() as selector:
        for role,process in processes.items():selector.register(process.stdout,selectors.EVENT_READ,role)
        while selector.get_map():
            if time.monotonic()>deadline:raise TimeoutError('backpressure collection watchdog exceeded')
            base.require(tunnel is None or tunnel.poll() is None,'SSH forwarder exited during pressure case')
            for key,_ in selector.select(.2):
                role=key.data;chunk=os.read(key.fd,65536)
                if not chunk:
                    base.require(not buffers[role].strip(),'truncated endpoint JSON')
                    selector.unregister(key.fileobj);continue
                totals[role]+=len(chunk)
                base.require(totals[role]<=1024*1024,'endpoint output exceeds bound')
                outputs[role].write(chunk);outputs[role].flush();buffers[role]+=chunk
                base.require(len(buffers[role])<=65536,'endpoint line exceeds bound')
                while b'\n' in buffers[role]:
                    line,buffers[role]=buffers[role].split(b'\n',1)
                    if not line.strip():continue
                    event=campaign.strict_json(line);tracker.observe(role,event)
                    record={'event':'endpoint_observed','role':role,'endpoint_event':event,
                            'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}
                    controller.write(json.dumps(record)+'\n');controller.flush()
        codes={role:process.wait(timeout=3) for role,process in processes.items()}
    return tracker,codes


def run_case(case, ssh, target, public, folder):
    base.require(case in CASES,'invalid pressure case')
    folder.mkdir(mode=0o700)
    tunnel=server=client=None
    report={'case':case,'status':'failed','remote_listener_lifetime_bound_seconds':95}
    try:
        with ExitStack() as stack:
            errors={role:stack.enter_context((folder/(role+'.stderr.log')).open('wb'))
                    for role in ('tunnel','server','client')}
            outputs={role:stack.enter_context((folder/(role+'.jsonl')).open('wb')) for role in ('server','client')}
            controller=stack.enter_context((folder/'controller.jsonl').open('w'))
            tunnel,port=base.start_tunnel(ssh,target,errors['tunnel'])
            server=subprocess.Popen(base.server_ssh_command(ssh,target,backpressure_case=case),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors['server'],start_new_session=True)
            base.readiness(server,outputs['server'])
            client=subprocess.Popen(base.client_command(port,public)+['--backpressure-case',case],
                stdout=subprocess.PIPE,stderr=errors['client'],start_new_session=True)
            tracker,codes=monitor(client,server,tunnel,outputs,controller,case)
        errors={role:(folder/(role+'.stderr.log')).read_bytes() for role in ('server','client')}
        tracker.validate(codes,errors)
        report.update(status='passed',endpoint_events=tracker.events,endpoint_finals=tracker.finals,
                      endpoint_exit_codes=codes)
    except (Exception,KeyboardInterrupt) as error:
        report['failure']=type(error).__name__+': '+str(error)
        if isinstance(error,KeyboardInterrupt):report['operator_cancelled']=True
    finally:
        for role,process in (('client',client),('server_ssh',server),('tunnel',tunnel)):
            if process is not None and process.poll() is None:report[role+'_cleanup_termination']=True
            base.stop(process)
        report['owned_local_processes_exited']=all(p is None or p.poll() is not None for p in (client,server,tunnel))
        (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def recovery_fresh(results, recovered):
    session=recovered['client']['sessions'][0]
    seen={field:set() for field in IDENTIFIERS}
    for result in results:
        events=result['endpoint_events']['client']
        pressure=next(event for event in events if event.get('event')=='pressure_saturated')
        for field in IDENTIFIERS:
            base.require(pressure[field] not in seen[field],'pressure cases reused session identifiers')
            seen[field].add(pressure[field])
    return all(session[field] not in seen[field] for field in IDENTIFIERS)


def run(args):
    target,ssh,output,public,before,remote=base.prepare_client(args,'Spiral-backpressure-')
    selected=CASES if args.case=='all' else (args.case,)
    results=[];fresh=None
    for case in selected:
        print('Starting '+case+(' (unchanged 60-second idle deadline)' if case=='timeout' else ''),flush=True)
        result=run_case(case,ssh,target,public,output/case);results.append(result)
        print(case+': '+result['status'],flush=True)
        if result['status']!='passed':break
    pressure_results=list(results)
    if len(results)==len(selected) and all(r['status']=='passed' for r in results):
        print('Starting fresh ordinary-session recovery.',flush=True)
        recovered=base.run_case('recovery',ssh,target,public,output/'recovery');results.append(recovered)
        if recovered['status']=='passed':
            try:fresh=recovery_fresh(pressure_results,recovered)
            except (KeyError,StopIteration,ValueError):fresh=False
    after=base.source()
    unchanged=(before['source']['files']==after['source']['files']
               and before['binary_sha256']==after['binary_sha256']
               and before['runner_sha256']==after['runner_sha256'])
    passed=(unchanged and fresh is True and len(results)==len(selected)+1
            and all(r['status']=='passed' for r in results))
    summary={'schema':'spiral-backpressure/v1','status':'passed' if passed else 'failed',
             'scope':'Authenticated receive queue saturation (8), retained plaintext pool exhaustion (18), '
                     '8 reserved send slots with 2 waiting producers, release/cancellation/idle expiry and fresh recovery. '
                     'Reserved slots are not queued DATA frames. No wire-buffer saturation, throughput, trusted WSL timing, '
                     'application client authorization or cryptographic-security claim.',
             'selected_cases':list(selected),'local_before':before,'local_after':after,'remote_preparation':remote,
             'local_unchanged':unchanged,'recovery_session_is_fresh':fresh,'cases':results}
    base.pack_results(output,summary)
    return 0 if passed else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run',))
    parser.add_argument('--case',choices=(*CASES,'all'),default='all')
    parser.add_argument('--target');parser.add_argument('--identity',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    base.require(sys.platform=='linux' and base.BINARY.is_file(),'Build the Linux spiral-lab binary with --features flow-diagnostics first')
    os.umask(0o077)
    def cancel(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancel)
    return run(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
