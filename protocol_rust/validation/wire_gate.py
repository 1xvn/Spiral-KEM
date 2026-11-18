#!/usr/bin/env python3
"""Bounded raw TCP read gate around one directly owned diagnostic Rust server."""
import argparse
import errno
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import time

import crash_supervisor
import cross_host_smoke as base
import load_campaign as campaign

CASES=('release','timeout')
IDS=('session_id','binding_hash','transcript_hash')
BUFFER_LIMIT=65536
COMMAND_LIMIT=4096
OUTPUT_LIMIT=1024*1024


def receive(sock, limit):
    """Expose TCP reset as input EOF; TLS peers still judge authenticated closure.

    Linux may report ECONNRESET after all readable ciphertext was delivered.
    Returning EOF here must not discard queued ciphertext or suppress a failed
    send; the gate continues draining both buffers and the endpoint verdicts
    independently require authenticated protocol/TLS closure in release mode.
    """
    try:return sock.recv(limit),False
    except BlockingIOError:return None,False
    except ConnectionResetError:return b'',True


def check_bound(event, case, ready):
    base.require(isinstance(event,dict) and event.get('role')=='server'
                 and event.get('case')==case,'unexpected server wire event')
    crash_supervisor.check_identifiers(event)
    if ready is not None:
        base.require(all(event[name]==ready[name] for name in IDS),'wire session binding differs')


def check_command(command, case, ready, paused, stalled, resumed):
    base.require(case in CASES and ready is not None,'wire command before authenticated readiness')
    base.require(isinstance(command,dict) and set(command)=={'action',*IDS},'invalid wire gate command')
    crash_supervisor.check_identifiers(command)
    base.require(all(command[name]==ready[name] for name in IDS),'wire command session differs')
    action=command.get('action')
    if action=='pause':
        base.require(not paused and not stalled and not resumed,'duplicate or late pause command')
    elif action=='resume':
        base.require(case=='release' and paused and stalled and not resumed,'resume outside stalled release case')
    else:
        raise ValueError('unsupported wire gate action')
    return action


def server_command(case):
    base.require(case in CASES,'unsupported wire case')
    command=base.prepared_server_command()
    at=command.index('--messages')
    command[at+1]='1024'
    return [*command,'--payload','16384','--wire-stall-case',case]


def supervise(command, case, backend_port=39401, gate_port=39402, input_stream=None, output_stream=None, *, isolation=False):
    """Own one server and a single-client gate; CLI exposes no PID or command input."""
    base.require(case in CASES,'unsupported wire case')
    base.require(isinstance(command,list) and command,'missing owned server command')
    for port in (backend_port,gate_port):
        base.require(type(port) is int and 1<=port<=65535,'invalid wire gate port')
    base.require(backend_port!=gate_port,'gate and backend ports must differ')
    source=input_stream if input_stream is not None else sys.stdin.buffer
    output=output_stream if output_stream is not None else sys.stdout
    child=listener=front=back=None
    stdout_eof=False
    server_listening=False
    ready=None
    paused=False
    stalled=False
    resumed=False
    bulk=False
    expired=False
    final=None
    front_read=True
    back_read=True
    front_eof=False
    back_eof=False
    front_write_closed=False
    back_write_closed=False
    incoming={'stdin':b'','server':b''}
    upstream=bytearray()
    downstream=bytearray()
    backend_bytes_read=0
    pause_bytes=None
    receive_buffer_bytes=None
    total_output=0
    read_resets={'front':0,'back':0}
    started=time.monotonic()
    deadline=started+35
    selector=selectors.DefaultSelector()

    def emit(value):
        output.write(json.dumps(value)+'\n');output.flush()

    def phase(name, **fields):
        base.require(ready is not None,'gate phase before ready binding')
        emit({'event':name,'case':case,**{name:ready[name] for name in IDS},**fields})

    def watch(sock, events, role):
        if sock is None:return
        try:key=selector.get_key(sock)
        except KeyError:key=None
        if events:
            if key is None:selector.register(sock,events,role)
            elif key.events!=events:selector.modify(sock,events,role)
        elif key is not None:selector.unregister(sock)

    def close_socket(sock):
        if sock is not None:
            try:selector.unregister(sock)
            except KeyError:pass
            sock.close()

    def set_watches():
        watch(front,(selectors.EVENT_READ if front_read and not front_eof and len(upstream)<BUFFER_LIMIT else 0)
              |(selectors.EVENT_WRITE if downstream else 0),'front')
        watch(back,(selectors.EVENT_READ if back_read and not back_eof and len(downstream)<BUFFER_LIMIT else 0)
              |(selectors.EVENT_WRITE if upstream else 0),'back')

    def half_close(sock):
        try:sock.shutdown(socket.SHUT_WR)
        except OSError as error:
            if error.errno not in (errno.ENOTCONN,errno.EPIPE,errno.ECONNRESET):raise

    try:
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,bufsize=0,
                               preexec_fn=crash_supervisor.parent_death_guard())
        emit({'event':'owned_server_started','child_pid':child.pid,'parent_death_guard':True})
        listener=socket.socket()
        listener.bind(('127.0.0.1',gate_port));listener.listen(1);listener.setblocking(False)
        emit({'event':'gate_listening','port':gate_port,'backend_port':backend_port,'loopback_only':True})
        selector.register(listener,selectors.EVENT_READ,'listener')
        selector.register(source,selectors.EVENT_READ,'stdin')
        selector.register(child.stdout,selectors.EVENT_READ,'server')
        while True:
            now=time.monotonic()
            if now>deadline or now>started+100:raise TimeoutError('wire gate collection deadline exceeded')
            if front_eof and not upstream and back is not None and not back_write_closed and front_read:
                half_close(back);back_write_closed=True
            if back_eof and not downstream and front is not None and not front_write_closed and back_read:
                half_close(front);front_write_closed=True
            if stdout_eof:
                code=child.wait(timeout=3)
                base.require(final is not None and paused and bulk and stalled,'owned server ended before all wire phases')
                base.require(code==(0 if case=='release' or isolation else 1),'unexpected owned wire server exit')
                base.require(final.get('status')==('passed' if case=='release' or isolation else 'failed'),'owned wire server final differs')
                if case=='timeout':
                    base.require(expired and not resumed and not front_read and not back_read,
                                 'timeout case was not held through server expiry')
                    break
                base.require(resumed,'release server ended before gate resume')
                # The server may exit after flushing close_notify into TCP. Let
                # the relay deliver all ciphertext and authenticated EOF first.
                if back_eof and not downstream and front_eof and not upstream:break
            elif child.poll() is not None:
                # Drain its stdout before deciding whether termination was valid.
                deadline=min(deadline,time.monotonic()+3)
            set_watches()
            for key,mask in selector.select(.1):
                role=key.data
                if role=='listener':
                    connection,_=listener.accept()
                    if front is not None:
                        connection.close();raise ValueError('wire gate accepts one client only')
                    base.require(server_listening,'wire gate client arrived before owned backend readiness')
                    front=connection;front.setblocking(False)
                    back=socket.socket();back.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
                    receive_buffer_bytes=back.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
                    back.settimeout(3);back.connect(('127.0.0.1',backend_port));back.setblocking(False)
                elif role=='stdin':
                    chunk=os.read(key.fd,COMMAND_LIMIT+1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        base.require(not incoming[role].strip(),'truncated wire gate command')
                        base.require(stdout_eof,'wire controller stdin closed before server result')
                        continue
                    incoming[role]+=chunk
                    base.require(len(incoming[role])<=COMMAND_LIMIT,'wire command exceeds bound')
                    while b'\n' in incoming[role]:
                        line,incoming[role]=incoming[role].split(b'\n',1)
                        value=campaign.strict_json(line)
                        action=check_command(value,case,ready,paused,stalled,resumed)
                        base.require(child.poll() is None and front is not None and back is not None,
                                     'wire command without live owned connection')
                        if action=='pause':
                            base.require(not downstream,'ciphertext still buffered at pause request')
                            paused=True;back_read=False;pause_bytes=backend_bytes_read
                            phase('gate_paused',backend_read_enabled=False,frontend_read_enabled=True,
                                  backend_bytes_read=pause_bytes,down_buffered_bytes=0,
                                  receive_buffer_bytes=receive_buffer_bytes)
                        else:
                            base.require(not front_read and not back_read and not upstream and not downstream
                                         and backend_bytes_read==pause_bytes,'gate read advanced while stalled')
                            resumed=True;front_read=True;back_read=True
                            back.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
                            receive_buffer_bytes=back.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
                            phase('gate_resumed',backend_bytes_read=backend_bytes_read,
                                  receive_buffer_bytes=receive_buffer_bytes)
                elif role=='server':
                    chunk=os.read(key.fd,65536)
                    if not chunk:
                        selector.unregister(key.fileobj);stdout_eof=True
                        base.require(not incoming[role].strip(),'truncated owned server JSON')
                        deadline=min(deadline,time.monotonic()+3)
                        continue
                    total_output+=len(chunk)
                    base.require(total_output<=OUTPUT_LIMIT,'owned wire server output exceeds bound')
                    incoming[role]+=chunk
                    base.require(len(incoming[role])<=65536,'owned wire server line exceeds bound')
                    while b'\n' in incoming[role]:
                        line,incoming[role]=incoming[role].split(b'\n',1)
                        if not line.strip():continue
                        event=campaign.strict_json(line)
                        base.require(isinstance(event,dict),'nonobject owned wire server event')
                        kind=event.get('event')
                        if not server_listening:
                            base.require(event.get('listening')==backend_port and event.get('loopback_only') is True,
                                         'unexpected owned backend readiness')
                            base.require(base.listening(backend_port,child.pid),'backend listener not owned by direct server')
                            server_listening=True
                        elif kind=='wire_ready':
                            base.require(ready is None and not paused,'duplicate or late wire ready')
                            check_bound(event,case,None)
                            base.require(event.get('baseline_echoes')==3 and event.get('bulk_messages')==1021
                                         and event.get('payload_bytes')==16384,'unexpected wire workload')
                            ready=event
                        elif kind=='bulk_started':
                            check_bound(event,case,ready)
                            base.require(paused and not bulk and not upstream and backend_bytes_read==pause_bytes,
                                         'bulk started before read pause or GO was not drained')
                            bulk=True;front_read=False;deadline=min(started+100,time.monotonic()+85)
                        elif kind=='wire_stalled':
                            check_bound(event,case,ready)
                            base.require(bulk and paused and not stalled and not resumed and not front_read and not back_read
                                         and backend_bytes_read==pause_bytes and not upstream and not downstream,
                                         'wire stall without frozen gate reads')
                            stalled=True
                        elif kind=='wire_timeout':
                            check_bound(event,case,ready)
                            base.require(case=='timeout' and stalled and not resumed and not expired,'unexpected wire expiry')
                            expired=True
                        elif 'status' in event:
                            base.require(final is None,'duplicate owned server final');final=event
                        emit({'event':'server_endpoint','payload':event})
                        if kind=='bulk_started':
                            phase('reverse_held',frontend_read_enabled=False)
                        elif kind=='wire_stalled':
                            phase('gate_stall_confirmed',backend_bytes_read=backend_bytes_read,
                                  backend_read_enabled=False,frontend_read_enabled=False,
                                  up_buffered_bytes=0,down_buffered_bytes=0)
                elif role in ('front','back'):
                    sock=front if role=='front' else back
                    enabled=front_read if role=='front' else back_read
                    eof=front_eof if role=='front' else back_eof
                    target=upstream if role=='front' else downstream
                    # Recheck flags: a pause or bulk event may have been handled
                    # earlier in this same select batch.
                    if mask&selectors.EVENT_READ and enabled and not eof:
                        data,reset=receive(sock,BUFFER_LIMIT-len(target))
                        if reset:read_resets[role]+=1
                        if data:
                            target.extend(data)
                            if role=='back':backend_bytes_read+=len(data)
                        elif data==b'':
                            if role=='front':front_eof=True
                            else:back_eof=True
                    sending=downstream if role=='front' else upstream
                    if mask&selectors.EVENT_WRITE and sending:
                        try:count=sock.send(sending)
                        except BlockingIOError:count=0
                        if count:del sending[:count]
            base.require(len(upstream)<=BUFFER_LIMIT and len(downstream)<=BUFFER_LIMIT,'proxy buffer exceeds bound')
        close_socket(front);front=None
        close_socket(back);back=None
        close_socket(listener);listener=None
        base.require(not base.listening(gate_port) and not base.listening(backend_port),'owned listener remained after server exit')
        emit({'event':'gate_finished','case':case,'child_pid':child.pid,'child_exit_code':child.returncode,
              'reaped':True,'listener_present':False,'reads_held_until_server_exit':case=='timeout',
              'read_resets':read_resets})
        return 0
    finally:
        for sock in (front,back,listener):close_socket(sock)
        selector.close()
        if child is not None:
            if child.poll() is None:
                try:child.kill()
                except ProcessLookupError:pass
            child.wait(timeout=3);child.stdout.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('serve',))
    parser.add_argument('--case',choices=CASES,required=True)
    parser.add_argument('--isolation',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    def cancel(signum,frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancel)
    command = server_command(args.case)
    if args.isolation:
        command[command.index('--connections') + 1] = '5'
        command[command.index('--wire-stall-case')] = '--isolation-case'
    if not args.isolation:
        return supervise(command, args.case)
    before = base.source()
    result = supervise(command, args.case, isolation=True)
    after = base.source()
    base.require(before == after and not after['source']['working_tree_dirty'],
                 'remote source or binary changed during isolation case')
    print(json.dumps({'event':'source_verified','git_head':after['source']['git_head'],
                      'binary_sha256':after['binary_sha256'],
                      'source_tree_sha256':after['source']['source_tree_sha256']}),flush=True)
    return result


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
