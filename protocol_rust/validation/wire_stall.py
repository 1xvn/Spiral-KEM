#!/usr/bin/env python3
"""Operator-run underlying TCP write stall, read resumption and idle expiry."""
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
from wire_contract import WireTracker

CASES=('release','timeout')
GATE_PORT=39402
IDENTIFIERS=('session_id','binding_hash','transcript_hash')


def remote_command(ssh,target,case):
    base.require(case in CASES,'invalid wire-stall case')
    return [*ssh,target,'cd "$HOME/Spiral-load-hours" && exec timeout --kill-after=5s 110s '
            'python3 -B protocol_rust/validation/wire_gate.py serve --case '+case]


def tunnel_state(tunnel,port):
    return {'alive':tunnel.poll() is None,'owned_listener_present':base.listening(port,tunnel.pid)}


class WireRun:
    """Coordinate a bounded gate and client; capture every control transition."""
    def __init__(self,case,supervisor,start_client,observe_tunnel,outputs,controller,
                 backend_port=base.REMOTE_PORT,gate_port=GATE_PORT):
        self.case=case;self.supervisor=supervisor;self.start_client=start_client
        self.observe_tunnel=observe_tunnel;self.outputs=outputs;self.controller=controller
        self.tracker=WireTracker(case,backend_port,gate_port)
        self.client=None;self.go_sent=False;self.tunnel_observations={}

    def record(self,event,**fields):
        self.controller.write(json.dumps({'event':event,**fields,'utc_ns':time.time_ns(),
                                         'monotonic_ns':time.monotonic_ns()})+'\n')
        self.controller.flush()

    def send(self,command):
        self.supervisor.stdin.write(json.dumps(command).encode()+b'\n');self.supervisor.stdin.flush()
        self.record('gate_command',command=command)

    def run(self):
        buffers={'supervisor':b'','client':b''};totals={role:0 for role in buffers}
        deadline=time.monotonic()+120
        with selectors.DefaultSelector() as selector:
            selector.register(self.supervisor.stdout,selectors.EVENT_READ,'supervisor')
            while selector.get_map():
                if time.monotonic()>deadline:raise TimeoutError('wire-stall controller collection deadline exceeded')
                for key,_ in selector.select(.2):
                    role=key.data;chunk=os.read(key.fd,65536)
                    if not chunk:
                        base.require(not buffers[role].strip(),'truncated wire-stall JSON')
                        base.require(self.go_sent,'process ended before controlled bulk transfer')
                        if role=='supervisor':base.require(self.tracker.finished is not None,'gate exited without teardown evidence')
                        selector.unregister(key.fileobj);continue
                    totals[role]+=len(chunk)
                    base.require(totals[role]<=1024*1024,'wire-stall output exceeds bound')
                    self.outputs[role].write(chunk);self.outputs[role].flush();buffers[role]+=chunk
                    base.require(len(buffers[role])<=65536,'wire-stall output line exceeds bound')
                    while b'\n' in buffers[role]:
                        line,buffers[role]=buffers[role].split(b'\n',1)
                        if not line.strip():continue
                        event=campaign.strict_json(line)
                        if role=='client':self.tracker.observe_client(event)
                        else:
                            self.tracker.observe_remote(event)
                            if event.get('event')=='server_endpoint':
                                self.outputs['server'].write(json.dumps(event['payload']).encode()+b'\n')
                                self.outputs['server'].flush()
                        self.record('process_observed',role=role,payload=event)
                if self.tracker.server_listening and self.tracker.gate_listening and self.client is None:
                    base.require(self.supervisor.poll() is None,'gate ended during readiness')
                    self.client=self.start_client()
                    selector.register(self.client.stdout,selectors.EVENT_READ,'client')
                    self.record('client_started');deadline=time.monotonic()+35
                if len(self.tracker.ready)==2 and not self.tracker.pause_requested:
                    base.require(self.client is not None and self.client.poll() is None
                                 and self.supervisor.poll() is None,'endpoint ended before gate pause')
                    state=self.observe_tunnel();self.tunnel_observations['before_pause']=state
                    base.require(state=={'alive':True,'owned_listener_present':True},'SSH forwarder failed before gate pause')
                    self.send(self.tracker.pause_command());deadline=time.monotonic()+35
                if self.tracker.paused and not self.go_sent:
                    base.require(self.client is not None and self.client.poll() is None,'client ended before GO')
                    self.client.stdin.write(b'GO\n');self.client.stdin.flush();self.client.stdin.close()
                    self.go_sent=True;self.record('client_go_sent')
                if self.tracker.stalled and self.tracker.gate_witness and 'after_stall' not in self.tunnel_observations:
                    state=self.observe_tunnel();self.tunnel_observations['after_stall']=state
                    base.require(state=={'alive':True,'owned_listener_present':True},'SSH forwarder failed during stall')
                    self.record('stall_confirmed',tunnel=state)
                    deadline=time.monotonic()+(90 if self.case=='timeout' else 35)
                    if self.case=='release':self.send(self.tracker.resume_command())
            base.require(self.client is not None,'client never started')
            codes={'client':self.client.wait(timeout=3),'supervisor':self.supervisor.wait(timeout=3)}
        self.tunnel_observations['after_end']=self.observe_tunnel()
        self.record('processes_exited',codes=codes,tunnel_observations=self.tunnel_observations)
        return codes


def run_case(case,ssh,target,public,folder):
    folder.mkdir(mode=0o700);tunnel=supervisor=None;monitor=None
    report={'case':case,'status':'failed','remote_watchdog_seconds':115}
    try:
        with ExitStack() as stack:
            errors={role:stack.enter_context((folder/(role+'.stderr.log')).open('wb'))
                    for role in ('tunnel','supervisor','client')}
            outputs={role:stack.enter_context((folder/(role+'.jsonl')).open('wb'))
                     for role in ('supervisor','server','client')}
            controller=stack.enter_context((folder/'controller.jsonl').open('w'))
            tunnel,port=base.start_tunnel(ssh,target,errors['tunnel'],remote_port=GATE_PORT)
            supervisor=subprocess.Popen(remote_command(ssh,target,case),stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=errors['supervisor'],start_new_session=True)
            def start_client():
                command=wire_client_command(port,public,case)
                return subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=errors['client'],start_new_session=True)
            monitor=WireRun(case,supervisor,start_client,lambda:tunnel_state(tunnel,port),outputs,controller)
            codes=monitor.run()
        monitor.tracker.validate(codes,{'client':(folder/'client.stderr.log').read_bytes(),
            'server':(folder/'supervisor.stderr.log').read_bytes()},monitor.tunnel_observations)
        report.update(status='passed',ready=monitor.tracker.ready,endpoint_events=monitor.tracker.events,
                      endpoint_finals=monitor.tracker.finals,gate_started=monitor.tracker.remote_started,
                      gate_paused=monitor.tracker.paused,wire_stalled=monitor.tracker.stalled,
                      gate_witness=monitor.tracker.gate_witness,gate_finished=monitor.tracker.finished,
                      exit_codes=codes,tunnel_observations=monitor.tunnel_observations)
    except (Exception,KeyboardInterrupt) as error:
        report['failure']=type(error).__name__+': '+str(error)
        if isinstance(error,KeyboardInterrupt):report['operator_cancelled']=True
    finally:
        client=monitor.client if monitor else None
        for role,process in (('client',client),('supervisor_ssh',supervisor),('tunnel',tunnel)):
            if process is not None and process.poll() is None:report[role+'_cleanup_termination']=True
            base.stop(process)
            if process is not None:
                for stream in (process.stdin,process.stdout):
                    if stream is not None and not stream.closed:stream.close()
        report['owned_local_processes_exited']=all(p is None or p.poll() is not None for p in (client,supervisor,tunnel))
        (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def wire_client_command(port,public,case):
    base.require(case in CASES,'invalid wire-stall case')
    command=base.client_command(port,public)
    for flag,value in (('--messages','1024'),('--payload','16384')):command[command.index(flag)+1]=value
    return command+['--wire-stall-case',case]


def recovery_fresh(results,recovered):
    session=recovered['client']['sessions'][0]
    seen={field:set() for field in IDENTIFIERS}
    for result in results:
        for field in IDENTIFIERS:
            value=result['ready']['client'][field]
            base.require(value not in seen[field],'wire-stall sessions reused identifiers')
            seen[field].add(value)
    return all(session[field] not in seen[field] for field in IDENTIFIERS)


def run(args):
    target,ssh,output,public,before,remote=base.prepare_client(args,'Spiral-wire-stall-')
    selected=CASES if args.case=='all' else (args.case,)
    results=[];fresh=None
    for case in selected:
        print('Starting actual socket-write stall: '+case,flush=True)
        result=run_case(case,ssh,target,public,output/case);results.append(result)
        print(case+': '+result['status'],flush=True)
        if result['status']!='passed':break
    pressure_results=list(results)
    if len(results)==len(selected) and all(r['status']=='passed' for r in results):
        print('Starting fresh ordinary-session recovery.',flush=True)
        recovered=base.run_case('recovery',ssh,target,public,output/'recovery');results.append(recovered)
        if recovered['status']=='passed':
            try:fresh=recovery_fresh(pressure_results,recovered)
            except (KeyError,ValueError):fresh=False
    after=base.source()
    unchanged=(before['source']['files']==after['source']['files']
               and before['binary_sha256']==after['binary_sha256']
               and before['runner_sha256']==after['runner_sha256'])
    passed=unchanged and fresh is True and len(results)==len(selected)+1 and all(r['status']=='passed' for r in results)
    summary={'schema':'spiral-wire-stall/v1','status':'passed' if passed else 'failed',
             'scope':'Observed underlying TCP write Pending with frozen peer read counters after authenticated echoes; '
                     'read resumption or own-server idle expiry, cleanup and fresh recovery. '
                     'Bounded one-stream functional test, not capacity, trusted WSL timing, client authorization or cryptographic security.',
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
    base.require(sys.platform=='linux' and base.BINARY.is_file(),'Build spiral-lab with --features flow-diagnostics first')
    os.umask(0o077)
    def cancel(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancel)
    return run(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
