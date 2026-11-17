#!/usr/bin/env python3
"""Operator-run cut of an authenticated, echoed session with a response pending."""
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

CHECKPOINT=3
PAYLOAD=1024
IDENTIFIERS=(('session_id',32),('binding_hash',64),('transcript_hash',64))


class PendingTracker:
    """A cut is eligible only after BOTH peers report the same pending request."""
    def __init__(self):
        self.pending={};self.cleanup=None;self.finals={};self.cut=False

    def observe(self, role, event):
        base.require(isinstance(event,dict),'nonobject endpoint event')
        if event.get('event')=='request_pending':
            base.require(not self.cut and role not in self.pending,'duplicate/late pending checkpoint')
            base.require(event.get('role')==role and event.get('fault_checkpoint')==CHECKPOINT,'checkpoint role/count mismatch')
            for field,size in IDENTIFIERS:
                value=event.get(field)
                base.require(isinstance(value,str) and len(value)==size and value!='0'*size
                             and all(c in '0123456789abcdef' for c in value),'invalid checkpoint identifier')
            if role=='client':
                base.require(event.get('sent_messages')==4 and event.get('verified_echoes')==3
                             and event.get('payload_bytes')==PAYLOAD,'client has no verified pending request')
            elif role=='server':
                base.require(event.get('received_messages')==4 and event.get('echoed_messages')==3
                             and event.get('pending_payload_bytes')==PAYLOAD,'server has no held authenticated request')
            else:raise ValueError('unexpected endpoint role')
            self.pending[role]=event
            if len(self.pending)==2:
                for field,_ in IDENTIFIERS:
                    base.require(self.pending['server'][field]==self.pending['client'][field],'checkpoint binding mismatch')
        elif event.get('event')=='failure_cleanup':
            base.require(self.cut and role=='server' and self.cleanup is None,'cleanup before cut or duplicate cleanup')
            self.cleanup=event
        elif 'status' in event:
            base.require(self.cut and role not in self.finals,'endpoint finished before injection or duplicate final')
            self.finals[role]=event
        else:raise ValueError('unexpected endpoint event')

    def inject(self):
        base.require(not self.cut and set(self.pending)=={'server','client'},'cut before both pending checkpoints')
        self.cut=True

    def validate(self, codes, errors):
        base.require(self.cut and set(self.finals)=={'server','client'},'cut/final evidence incomplete')
        for role in ('client','server'):
            result=self.finals[role]
            base.require(codes[role]==1 and result.get('status')=='failed','endpoint did not report expected failure')
            kem=result.get('kem',{})
            base.require(kem.get('live_keys')==0 and kem.get('rejected_jobs')==0,'native key ownership not released')
            base.require(kem.get('executed_jobs')==({'server':2,'client':1}[role]),'authenticated handshake accounting differs')
            # A watchdog/SSH kill is not evidence of the intended transport cut.
            terminal=[line.strip() for line in errors[role].splitlines() if line.strip().startswith(b'Error:')]
            base.require(len(terminal)==1 and terminal[0] in (b'Error: Closed',b'Error: Transport'),'unexpected endpoint error category')
        c=self.cleanup or {}
        base.require(c.get('role')=='server' and c.get('active')==0 and c.get('pending')==0
                     and c.get('auth_key_closed') is True and c.get('drained') is True,'server cleanup was not demonstrated')


def timestamp():
    return {'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}


def monitor(client, server, tunnel, port, outputs, controller):
    tracker=PendingTracker();buffers={'client':b'','server':b''};deadline=time.monotonic()+30
    processes={'client':client,'server':server}
    events=[]
    with selectors.DefaultSelector() as selector:
        for role,process in processes.items():selector.register(process.stdout,selectors.EVENT_READ,role)
        while selector.get_map():
            if time.monotonic()>deadline:raise TimeoutError('pending/cut outcome deadline exceeded')
            for key,_ in selector.select(.2):
                role=key.data;chunk=os.read(key.fd,65536)
                if not chunk:
                    base.require(tracker.cut,'endpoint ended before transport injection')
                    base.require(not buffers[role].strip(),'truncated endpoint JSON')
                    selector.unregister(key.fileobj);continue
                outputs[role].write(chunk);outputs[role].flush();buffers[role]+=chunk
                base.require(len(buffers[role])<=1024*1024,'endpoint line exceeds bound')
                while b'\n' in buffers[role]:
                    line,buffers[role]=buffers[role].split(b'\n',1)
                    if not line.strip():continue
                    event=campaign.strict_json(line);tracker.observe(role,event)
                    record={'event':'endpoint_observed','role':role,'endpoint_event':event,**timestamp()}
                    controller.write(json.dumps(record)+'\n');controller.flush()
            if not tracker.cut and len(tracker.pending)==2:
                base.require(all(p.poll() is None for p in processes.values()) and tunnel.poll() is None,'process failed before requested cut')
                tracker.inject()
                intent={'event':'cut_requested','pending':dict(tracker.pending),**timestamp()}
                controller.write(json.dumps(intent)+'\n');controller.flush();events.append(intent)
                base.stop(tunnel)
                base.require(tunnel.poll() is not None and not base.listening(port),'forwarder remained alive after cut')
                done={'event':'cut_completed','tunnel_exit':tunnel.returncode,**timestamp()}
                controller.write(json.dumps(done)+'\n');controller.flush();events.append(done)
                deadline=time.monotonic()+15
        codes={role:p.wait(timeout=3) for role,p in processes.items()}
    return tracker,codes,events


def run_fault(ssh, target, public, folder):
    folder.mkdir(mode=0o700);tunnel=server=client=None
    report={'case':'inflight-cut','status':'failed',
            'scope':'Three echoes verified; fourth authenticated DATA is received by server and its reply withheld. Cut the SSH forwarder while that request is pending.',
            'authenticated_protocol_close_claimed':False}
    try:
        with ExitStack() as stack:
            tunnel_errors=stack.enter_context((folder/'tunnel.stderr.log').open('wb'))
            server_errors=stack.enter_context((folder/'server.stderr.log').open('wb'))
            client_errors=stack.enter_context((folder/'client.stderr.log').open('wb'))
            outputs={role:stack.enter_context((folder/(role+'.jsonl')).open('wb')) for role in ('server','client')}
            controller=stack.enter_context((folder/'controller.jsonl').open('w'))
            tunnel,port=base.start_tunnel(ssh,target,tunnel_errors)
            server=subprocess.Popen(base.server_ssh_command(ssh,target,CHECKPOINT),stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=server_errors,start_new_session=True)
            base.readiness(server,outputs['server'])
            command=base.client_command(port,public)+['--fault-checkpoint',str(CHECKPOINT)]
            client=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=client_errors,start_new_session=True)
            tracker,codes,events=monitor(client,server,tunnel,port,outputs,controller)
        errors={role:(folder/(role+'.stderr.log')).read_bytes() for role in ('server','client')}
        tracker.validate(codes,errors)
        report.update(status='passed',checkpoints=tracker.pending,endpoint_finals=tracker.finals,
                      server_cleanup=tracker.cleanup,endpoint_exit_codes=codes,fault_events=events)
    except (Exception,KeyboardInterrupt) as error:
        report['failure']=type(error).__name__+': '+str(error)
        if isinstance(error,KeyboardInterrupt):report['operator_cancelled']=True
    finally:
        # Local processes are owned by this run. Remote timeout is an emergency
        # bound, never a successful cut verdict (the normal verdict needs exit1).
        for role,p in (('client',client),('server_ssh',server),('tunnel',tunnel)):
            if p is not None and p.poll() is None:report[role+'_cleanup_termination']=True
            base.stop(p)
        report['owned_local_processes_exited']=all(p is None or p.poll() is not None for p in (client,server,tunnel))
        (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def run(args):
    target,ssh,output,public,before,remote=base.prepare_client(args,'Spiral-inflight-')
    print('Waiting for three verified echoes and both pending-request checkpoints.',flush=True)
    fault=run_fault(ssh,target,public,output/'inflight-cut');results=[fault]
    print('inflight-cut: '+fault['status'],flush=True)
    fresh=None
    if fault['status']=='passed':
        print('Starting fresh-session recovery.',flush=True)
        recovered=base.run_case('recovery',ssh,target,public,output/'recovery');results.append(recovered)
        if recovered['status']=='passed':
            pending=fault['checkpoints']['client'];session=recovered['client']['sessions'][0]
            fresh=all(pending[field]!=session[field] for field,_ in IDENTIFIERS)
    after=base.source()
    unchanged=before['source']['files']==after['source']['files'] and before['binary_sha256']==after['binary_sha256'] and before['runner_sha256']==after['runner_sha256']
    summary={'schema':'spiral-inflight-disconnect/v1',
             'status':'passed' if unchanged and fresh is True and len(results)==2 and all(r['status']=='passed' for r in results) else 'failed',
             'scope':'Authenticated pending-response transport interruption and fresh connection over SSH; no replay/exactly-once, mid-frame cut, slow-reader, crash-recovery or client-authorization claim.',
             'local_before':before,'local_after':after,'remote_preparation':remote,
             'local_unchanged':unchanged,'recovery_session_is_fresh':fresh,'cases':results}
    base.pack_results(output,summary)
    return 0 if summary['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('run',))
    p.add_argument('--target');p.add_argument('--identity',type=Path);p.add_argument('--output',type=Path)
    args=p.parse_args()
    base.require(sys.platform=='linux' and base.BINARY.is_file(),'Build the Linux spiral-lab binary first')
    os.umask(0o077)
    def cancel(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancel)
    return run(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
