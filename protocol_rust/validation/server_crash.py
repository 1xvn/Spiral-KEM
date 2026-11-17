#!/usr/bin/env python3
"""Operator-run direct test-server SIGKILL and fresh-session recovery over SSH."""
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
from crash_contract import CrashTracker

IDENTIFIERS=('session_id','binding_hash','transcript_hash')


def supervisor_command(ssh,target):
    return [*ssh,target,'cd "$HOME/Spiral-load-hours" && exec timeout --kill-after=5s 60s '
            'python3 -B protocol_rust/validation/crash_supervisor.py serve']


def tunnel_state(tunnel,port):
    return {'alive':tunnel.poll() is None,'owned_listener_present':base.listening(port,tunnel.pid)}


class CrashRun:
    """Own the client and collect both streams, including SSH readiness."""
    def __init__(self,supervisor,start_client,observe_tunnel,outputs,controller,port=base.REMOTE_PORT):
        self.supervisor=supervisor;self.start_client=start_client;self.observe_tunnel=observe_tunnel
        self.outputs=outputs;self.controller=controller;self.client=None
        self.tracker=CrashTracker(port);self.tunnel_observations={}

    def record(self,event,**data):
        self.controller.write(json.dumps({'event':event,**data,'utc_ns':time.time_ns(),
                                         'monotonic_ns':time.monotonic_ns()})+'\n')
        self.controller.flush()

    def run(self):
        buffers={'supervisor':b'','client':b''};totals={role:0 for role in buffers}
        deadline=time.monotonic()+120
        with selectors.DefaultSelector() as selector:
            selector.register(self.supervisor.stdout,selectors.EVENT_READ,'supervisor')
            while selector.get_map():
                if time.monotonic()>deadline:raise TimeoutError('server crash collection deadline exceeded')
                for key,_ in selector.select(.2):
                    role=key.data;chunk=os.read(key.fd,65536)
                    if not chunk:
                        base.require(not buffers[role].strip(),'truncated crash JSON')
                        base.require(self.tracker.requested,'process ended before authorized crash')
                        if role=='supervisor':base.require(self.tracker.killed is not None,'supervisor ended without confirmed child kill')
                        selector.unregister(key.fileobj);continue
                    totals[role]+=len(chunk)
                    base.require(totals[role]<=1024*1024,'crash output exceeds bound')
                    self.outputs[role].write(chunk);self.outputs[role].flush();buffers[role]+=chunk
                    base.require(len(buffers[role])<=65536,'crash output line exceeds bound')
                    while b'\n' in buffers[role]:
                        line,buffers[role]=buffers[role].split(b'\n',1)
                        if not line.strip():continue
                        event=campaign.strict_json(line)
                        if role=='client':self.tracker.observe_client(event)
                        else:
                            self.tracker.observe_remote(event)
                            if event.get('event')=='server_endpoint':
                                self.outputs['server'].write(json.dumps(event['payload']).encode()+b'\n');self.outputs['server'].flush()
                            if event.get('event')=='owned_server_killed':
                                self.tunnel_observations['after_kill']=self.observe_tunnel()
                        self.record('process_observed',role=role,payload=event)
                if self.tracker.listening and self.client is None:
                    base.require(self.supervisor.poll() is None,'supervisor ended during readiness')
                    self.client=self.start_client()
                    selector.register(self.client.stdout,selectors.EVENT_READ,'client')
                    self.record('client_started');deadline=time.monotonic()+35
                if len(self.tracker.pending)==2 and not self.tracker.requested:
                    base.require(self.client is not None and self.client.poll() is None
                                 and self.supervisor.poll() is None,'process ended before crash request')
                    observation=self.observe_tunnel();self.tunnel_observations['before_request']=observation
                    base.require(observation=={'alive':True,'owned_listener_present':True},'SSH forwarder failed before crash')
                    command=self.tracker.authorize()
                    self.record('kill_requested',command=command,tunnel=observation)
                    self.supervisor.stdin.write(json.dumps(command).encode()+b'\n');self.supervisor.stdin.flush()
                    deadline=time.monotonic()+15
            base.require(self.client is not None,'client never started')
            codes={'client':self.client.wait(timeout=3),'supervisor':self.supervisor.wait(timeout=3)}
        self.tunnel_observations['after_client_exit']=self.observe_tunnel()
        self.record('processes_exited',codes=codes,tunnel_observations=self.tunnel_observations)
        return codes


def run_fault(ssh,target,public,folder):
    folder.mkdir(mode=0o700);tunnel=supervisor=None;monitor=None
    report={'case':'server-sigkill','status':'failed','server_userspace_cleanup_claimed':False,
            'authenticated_close_claimed_for_crashed_session':False,'remote_watchdog_seconds':65}
    try:
        with ExitStack() as stack:
            errors={role:stack.enter_context((folder/(role+'.stderr.log')).open('wb'))
                    for role in ('tunnel','supervisor','client')}
            outputs={role:stack.enter_context((folder/(role+'.jsonl')).open('wb'))
                     for role in ('supervisor','server','client')}
            controller=stack.enter_context((folder/'controller.jsonl').open('w'))
            tunnel,port=base.start_tunnel(ssh,target,errors['tunnel'])
            supervisor=subprocess.Popen(supervisor_command(ssh,target),stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=errors['supervisor'],start_new_session=True)
            def start_client():
                return subprocess.Popen(base.client_command(port,public)+['--fault-checkpoint','3'],
                    stdout=subprocess.PIPE,stderr=errors['client'],start_new_session=True)
            monitor=CrashRun(supervisor,start_client,lambda:tunnel_state(tunnel,port),outputs,controller)
            codes=monitor.run()
        monitor.tracker.validate(codes,(folder/'client.stderr.log').read_bytes(),monitor.tunnel_observations)
        report.update(status='passed',checkpoints=monitor.tracker.pending,
                      owned_server_started=monitor.tracker.started,owned_server_killed=monitor.tracker.killed,
                      client_final=monitor.tracker.client_final,exit_codes=codes,tunnel_observations=monitor.tunnel_observations)
    except (Exception,KeyboardInterrupt) as error:
        report['failure']=type(error).__name__+': '+str(error)
        if isinstance(error,KeyboardInterrupt):report['operator_cancelled']=True
    finally:
        client=monitor.client if monitor else None
        for role,process in (('client',client),('supervisor_ssh',supervisor),('tunnel',tunnel)):
            if process is not None and process.poll() is None:report[role+'_cleanup_termination']=True
            base.stop(process)
        report['owned_local_processes_exited']=all(p is None or p.poll() is not None for p in (client,supervisor,tunnel))
        (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def run(args):
    target,ssh,output,public,before,remote=base.prepare_client(args,'Spiral-server-crash-')
    print('Waiting for both authenticated pending-request checkpoints before server SIGKILL.',flush=True)
    fault=run_fault(ssh,target,public,output/'server-sigkill');results=[fault];fresh=None
    print('server-sigkill: '+fault['status'],flush=True)
    if fault['status']=='passed':
        print('Restarting an ordinary test server with the prepared identity.',flush=True)
        recovered=base.run_case('recovery',ssh,target,public,output/'recovery');results.append(recovered)
        if recovered['status']=='passed':
            session=recovered['client']['sessions'][0]
            fresh=all(session[field]!=fault['checkpoints']['client'][field] for field in IDENTIFIERS)
    after=base.source()
    unchanged=(before['source']['files']==after['source']['files']
               and before['binary_sha256']==after['binary_sha256']
               and before['runner_sha256']==after['runner_sha256'])
    passed=unchanged and fresh is True and len(results)==2 and all(r['status']=='passed' for r in results)
    summary={'schema':'spiral-server-crash/v1','status':'passed' if passed else 'failed',
             'scope':'Owned direct test-server SIGKILL with a full authenticated request pending, '
                     'SSH tunnel kept alive, client failure and fresh ordinary-server recovery. '
                     'No crashed-server userspace zeroization, cleanup-hook, persistence, rollback, '
                     'exactly-once, client-authorization or cryptographic-security claim.',
             'local_before':before,'local_after':after,'remote_preparation':remote,'local_unchanged':unchanged,
             'recovery_session_is_fresh':fresh,'server_userspace_cleanup_claimed':False,
             'authenticated_close_claimed_for_crashed_session':False,'cases':results}
    base.pack_results(output,summary)
    return 0 if passed else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run',))
    parser.add_argument('--target');parser.add_argument('--identity',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    base.require(sys.platform=='linux' and base.BINARY.is_file(),'Build the Linux spiral-lab binary first')
    os.umask(0o077)
    def cancel(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancel)
    return run(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
