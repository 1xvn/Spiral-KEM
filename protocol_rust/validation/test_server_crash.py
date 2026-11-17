"""Short real-process coordinator checks with synthetic endpoints, not TLS/KEM."""
from contextlib import ExitStack
import json
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

import cross_host_smoke as base
import server_crash as runner

IDS={'session_id':'a'*32,'binding_hash':'b'*64,'transcript_hash':'c'*64}
ENDPOINT=r'''
import json,socket,sys
role,port=sys.argv[1],int(sys.argv[2])
ids=json.loads(sys.argv[3])
def emit(value):print(json.dumps(value),flush=True)
if role=='server':
    listener=socket.socket();listener.bind(('127.0.0.1',port));listener.listen(1)
    emit({'listening':port,'loopback_only':True})
    connection,_=listener.accept();stream=connection.makefile('rb')
    for i in range(4):
        data=stream.readline();assert len(data)==1025
        if i<3:connection.sendall(data)
    emit(dict(event='request_pending',role='server',fault_checkpoint=3,
              received_messages=4,echoed_messages=3,pending_payload_bytes=1024,**ids))
    connection.recv(1)
    raise SystemExit(2)
else:
    connection=socket.create_connection(('127.0.0.1',port),timeout=2);stream=connection.makefile('rb')
    for i in range(3):
        data=bytes([65+i])*1024+b'\n';connection.sendall(data);assert stream.readline()==data
    connection.sendall(b'D'*1024+b'\n')
    emit(dict(event='request_pending',role='client',fault_checkpoint=3,
              sent_messages=4,verified_echoes=3,payload_bytes=1024,**ids))
    assert stream.readline()==b''
    emit({'status':'failed','kem':{'executed_jobs':1,'live_keys':0,'rejected_jobs':0}})
    print('Error: Closed',file=sys.stderr)
    raise SystemExit(1)
'''
RELAY=r'''
import asyncio,json,sys
async def pipe(reader,writer):
    while data:=await reader.read(65536):
        writer.write(data);await writer.drain()
async def handle(reader,writer):
    peer,remote=await asyncio.open_connection('127.0.0.1',int(sys.argv[1]))
    tasks={asyncio.create_task(pipe(reader,remote)),asyncio.create_task(pipe(peer,writer))}
    try:await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        writer.close();remote.close()
async def main():
    server=await asyncio.start_server(handle,'127.0.0.1',0)
    print(json.dumps({'port':server.sockets[0].getsockname()[1]}),flush=True)
    async with server:await server.serve_forever()
asyncio.run(main())
'''


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(3):raise TimeoutError('fixture readiness')
    return json.loads(process.stdout.readline())


def exercise(folder,fail_tunnel=False):
    """Actual sockets/process ownership; endpoint assertions and KEM metrics are synthetic."""
    owned=[];monitor=None
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    try:
        with ExitStack() as stack:
            errors={role:stack.enter_context((folder/(role+'.stderr.log')).open('wb'))
                    for role in ('relay','supervisor','client')}
            outputs={role:stack.enter_context((folder/(role+'.jsonl')).open('wb'))
                     for role in ('supervisor','server','client')}
            controller=stack.enter_context((folder/'controller.jsonl').open('w'))
            relay=subprocess.Popen([sys.executable,'-B','-u','-c',RELAY,str(port)],
                stdout=subprocess.PIPE,stderr=errors['relay']);owned.append(relay)
            local_port=line(relay)['port']
            command=[sys.executable,'-B','-u','-c',ENDPOINT,'server',str(port),json.dumps(IDS)]
            script=('import signal,sys\nsys.path.insert(0,'+repr(str(Path(__file__).parent))+')\n'
                    'import crash_supervisor\n'
                    'def cancel(signum,frame):raise KeyboardInterrupt()\n'
                    'signal.signal(signal.SIGTERM,cancel)\n'
                    'try:raise SystemExit(crash_supervisor.supervise('+repr(command)+','+str(port)+'))\n'
                    'except (Exception,KeyboardInterrupt):raise SystemExit(1)\n')
            supervisor=subprocess.Popen([sys.executable,'-B','-u','-c',script],stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=errors['supervisor']);owned.append(supervisor)
            def start_client():
                client=subprocess.Popen([sys.executable,'-B','-u','-c',ENDPOINT,'client',str(local_port),json.dumps(IDS)],
                    stdout=subprocess.PIPE,stderr=errors['client']);owned.append(client);return client
            def observe_tunnel():
                state=runner.tunnel_state(relay,local_port)
                if fail_tunnel:state['alive']=False
                return state
            monitor=runner.CrashRun(supervisor,start_client,observe_tunnel,outputs,controller,port=port)
            if fail_tunnel:
                try:monitor.run()
                except ValueError:
                    assert not monitor.tracker.requested and monitor.tracker.killed is None
                    return {'status':'expected denial','authorized':False}
                raise AssertionError('unhealthy forwarder authorized a crash')
            codes=monitor.run()
        monitor.tracker.validate(codes,(folder/'client.stderr.log').read_bytes(),monitor.tunnel_observations)
        result={'status':'passed','scope':'Synthetic endpoints over a real disposable TCP relay; no Rust/TLS/KEM execution.',
                'owned_server_started':monitor.tracker.started,'owned_server_killed':monitor.tracker.killed,
                'checkpoints':monitor.tracker.pending,'client_final':monitor.tracker.client_final,
                'codes':codes,'tunnel_observations':monitor.tunnel_observations}
        (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        # The client can have been created before monitor.run() raises.
        for process in reversed(owned):base.stop(process)
        for process in owned:
            for stream in (process.stdin,process.stdout):
                if stream is not None:stream.close()
        assert not base.listening(port),'fixture listener survived cleanup'


@unittest.skipUnless(sys.platform=='linux','Linux process and listener ownership checks')
class CoordinatorContracts(unittest.TestCase):
    def test_real_process_kill_preserves_forwarder_and_drains_client(self):
        with tempfile.TemporaryDirectory() as folder:
            result=exercise(Path(folder))
        self.assertEqual(result['owned_server_killed']['child_exit_code'],-signal.SIGKILL)
        self.assertEqual(result['codes'],{'client':1,'supervisor':0})
        self.assertEqual(set(result['tunnel_observations']),{'before_request','after_kill','after_client_exit'})

    def test_failed_forwarder_observation_prevents_authorization(self):
        with tempfile.TemporaryDirectory() as folder:
            result=exercise(Path(folder),True)
        self.assertFalse(result['authorized'])


if __name__=='__main__':unittest.main()
