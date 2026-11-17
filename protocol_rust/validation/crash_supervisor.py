#!/usr/bin/env python3
"""Own one test Rust server and accept a session-bound SIGKILL command on stdin."""
import argparse
import ctypes
import json
import os
import selectors
import signal
import subprocess
import sys
import time

import cross_host_smoke as base
import load_campaign as campaign

IDENTIFIERS=(('session_id',32),('binding_hash',64),('transcript_hash',64))
COMMAND_LIMIT=4096
OUTPUT_LIMIT=1024*1024


def parent_death_guard():
    """Prepare a Linux-only callback before fork; this supervisor has no threads.

    The guard remains active across exec of the ordinary non-setuid Rust binary.
    A parent check after prctl closes the fork/parent-exit race. No caller chooses
    a target PID; the callback changes only the newly created child's behavior.
    """
    base.require(sys.platform=='linux','the server supervisor requires Linux')
    owner=os.getpid()
    libc=ctypes.CDLL(None,use_errno=True)
    prctl=libc.prctl
    prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    prctl.restype=ctypes.c_int

    def guard():
        if prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=owner:
            os._exit(126)
    return guard


def check_identifiers(event):
    for name,size in IDENTIFIERS:
        value=event.get(name)
        base.require(isinstance(value,str) and len(value)==size and value!='0'*size
                     and all(c in '0123456789abcdef' for c in value),
                     'invalid pending-request identifier')


def check_pending(event):
    base.require(isinstance(event,dict) and event.get('event')=='request_pending'
                 and event.get('role')=='server' and event.get('fault_checkpoint')==3
                 and event.get('received_messages')==4 and event.get('echoed_messages')==3
                 and event.get('pending_payload_bytes')==1024,'invalid server pending checkpoint')
    check_identifiers(event)


def check_command(command, pending, already_requested=False):
    base.require(not already_requested and pending is not None,'kill command outside pending phase')
    base.require(isinstance(command,dict)
                 and set(command)=={'action',*(name for name,_ in IDENTIFIERS)}
                 and command['action']=='kill','invalid supervisor command')
    check_identifiers(command)
    base.require(all(command[name]==pending[name] for name,_ in IDENTIFIERS),
                 'kill command does not match the owned pending session')


def supervise(command, port, input_stream=None, output_stream=None):
    """Run a fixed owned command; CLI callers cannot supply commands, PIDs or signals.

    Tests may call this Python API with a disposable child. Remote operation uses
    only base.prepared_server_command(checkpoint=3). The caller supplies the outer
    watchdog; stdin loss, SIGTERM and errors additionally kill/reap this child.
    """
    source=input_stream if input_stream is not None else sys.stdin.buffer
    output=output_stream if output_stream is not None else sys.stdout
    base.require(isinstance(command,list) and command,'missing owned server command')
    child=None
    pending=None
    listening=False
    requested=False
    stdout_eof=False
    buffers={'stdin':b'','server':b''}
    total=0

    def emit(event):
        output.write(json.dumps(event)+'\n');output.flush()

    try:
        # No start_new_session: the outer timeout also owns this process group.
        # The kernel guard covers loss of the Python parent itself, including
        # SIGKILL, which cannot be handled by its finally block or watchdog.
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                               bufsize=0,preexec_fn=parent_death_guard())
        emit({'event':'owned_server_started','child_pid':child.pid,'parent_death_guard':True})
        deadline=time.monotonic()+35
        with selectors.DefaultSelector() as selector:
            selector.register(source,selectors.EVENT_READ,'stdin')
            selector.register(child.stdout,selectors.EVENT_READ,'server')
            while not (requested and stdout_eof):
                if time.monotonic()>deadline:raise TimeoutError('owned server supervisor deadline exceeded')
                for key,_ in selector.select(.1):
                    role=key.data;chunk=os.read(key.fd,65536 if role=='server' else COMMAND_LIMIT+1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        base.require(not buffers[role].strip(),'truncated supervisor input or server JSON')
                        if role=='server':
                            stdout_eof=True
                            base.require(requested,'owned server ended before authorized kill')
                        else:
                            base.require(requested,'controller stdin closed before authorized kill')
                        continue
                    if role=='stdin':
                        base.require(not requested,'duplicate supervisor command')
                        buffers[role]+=chunk
                        base.require(len(buffers[role])<=COMMAND_LIMIT,'supervisor command exceeds bound')
                        if b'\n' not in buffers[role]:continue
                        line,trailing=buffers[role].split(b'\n',1)
                        base.require(not trailing.strip(),'duplicate supervisor command')
                        buffers[role]=b''
                        value=campaign.strict_json(line)
                        check_command(value,pending,requested)
                        base.require(child.poll() is None,'owned server exited before authorized kill')
                        child.kill()
                        code=child.wait(timeout=3)
                        base.require(code==-signal.SIGKILL,'owned server was not terminated by SIGKILL')
                        requested=True
                        deadline=time.monotonic()+3
                    else:
                        total+=len(chunk)
                        base.require(total<=OUTPUT_LIMIT,'owned server output exceeds bound')
                        buffers[role]+=chunk
                        base.require(len(buffers[role])<=65536,'owned server line exceeds bound')
                        while b'\n' in buffers[role]:
                            line,buffers[role]=buffers[role].split(b'\n',1)
                            if not line.strip():continue
                            event=campaign.strict_json(line)
                            base.require(isinstance(event,dict),'nonobject owned server event')
                            if not listening:
                                base.require(event.get('listening')==port and event.get('loopback_only') is True,
                                             'unexpected owned server readiness')
                                base.require(base.listening(port,child.pid),'listener is not owned by this Rust child')
                                listening=True
                            else:
                                base.require(pending is None and not requested,'unexpected owned server event')
                                check_pending(event);pending=event
                            emit({'event':'server_endpoint','payload':event})
                if not requested:
                    base.require(child.poll() is None,'owned server exited before authorized kill')
            # Reject a second command already queued, without requiring the
            # controller to close stdin (that SSH control channel remains live).
            for key,_ in selector.select(0):
                if key.data=='stdin':
                    extra=os.read(key.fd,COMMAND_LIMIT+1)
                    base.require(not extra.strip(),'duplicate supervisor command')
        base.require(child.returncode==-signal.SIGKILL,'owned server exit was not reaped SIGKILL')
        end=time.monotonic()+3
        while base.listening(port):
            if time.monotonic()>end:raise TimeoutError('remote server listener remained after SIGKILL')
            time.sleep(.01)
        emit({'event':'owned_server_killed','child_pid':child.pid,'signal':'SIGKILL',
              'child_exit_code':child.returncode,'reaped':True,'stdout_eof':True,
              'listener_present':False,'checkpoint':pending})
        return 0
    finally:
        if child is not None:
            if child.poll() is None:
                try:child.kill()
                except ProcessLookupError:pass
            child.wait(timeout=3)
            child.stdout.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('serve',))
    parser.parse_args()
    os.umask(0o077)
    def cancelled(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancelled)
    return supervise(base.prepared_server_command(checkpoint=3),base.REMOTE_PORT)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
