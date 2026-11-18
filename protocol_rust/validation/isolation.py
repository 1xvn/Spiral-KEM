"""Bounded four-session experiment. Run on WSL, or use local for loopback evidence."""
import argparse
import asyncio
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

import cross_host_smoke as base
import isolation_contract as contract
import load_campaign as campaign
import wire_gate

CASES = ('hold','release','timeout')
GATE_PORT = 39402


class Collection:
    def __init__(self, folder, stack):
        self.folder = folder
        self.stack = stack
        self.procs = {}
        self.readers = []
        self.rows = []
        self.latest = {}
        self.changed = asyncio.Event()
        self.failure = None
        self.log = stack.enter_context((folder/'controller.jsonl').open('w'))

    def record(self, origin, data):
        row = {'ns': time.monotonic_ns(), 'origin': origin, 'data': data}
        self.rows.append(row)
        self.log.write(json.dumps(row)+'\n')
        self.log.flush()
        if origin == 'gate' and data.get('event') == 'server_endpoint':
            origin, data = 'server', data['payload']
        kind = data.get('event', 'listening' if 'listening' in data else 'final')
        self.latest[origin,kind,data.get('lane')] = data
        self.changed.set()

    async def read(self, origin, proc):
        raw = self.stack.enter_context((self.folder/(origin+'.jsonl')).open('wb'))
        try:
            total = 0
            while line := await proc.stdout.readline():
                total += len(line)
                base.require(total <= 2*1024*1024 and line.endswith(b'\n'), 'invalid output length')
                raw.write(line)
                raw.flush()
                self.record(origin, campaign.strict_json(line))
            self.changed.set()
        except Exception as error:
            self.failure = error
            self.changed.set()
            raise

    async def start(self, origin, command):
        base.require(origin not in self.procs, 'duplicate process or reconnect')
        err = self.stack.enter_context((self.folder/(origin+'.stderr.log')).open('wb'))
        proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=err)
        self.procs[origin] = proc
        self.readers.append(asyncio.create_task(self.read(origin,proc)))

    async def wait(self, predicate, seconds=5):
        async def check():
            while True:
                self.changed.clear()
                if self.failure:
                    raise self.failure
                if predicate():
                    return
                if any(p.returncode not in (None,0) for k,p in self.procs.items() if k!='0'):
                    raise ValueError('endpoint or supervisor failed; inspect raw logs')
                await self.changed.wait()
        await asyncio.wait_for(check(), seconds)

    def get(self, origin, kind, lane=None):
        return self.latest.get((origin,kind,lane))

    async def send(self, origin, data):
        stream = self.procs[origin].stdin
        stream.write(data)
        await stream.drain()

    async def stop(self):
        for proc in self.procs.values():
            if proc.returncode is None:
                try: proc.terminate()
                except ProcessLookupError: pass
            proc.stdin.close()
        for proc in self.procs.values():
            try: await asyncio.wait_for(proc.wait(),3)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        await asyncio.gather(*self.readers, return_exceptions=True)

    async def rounds(self, lanes, sequences):
        for lane in lanes:
            self.record('control',{'event':'echo','lane':lane,'sequence':sequences[lane]})
            await self.send(str(lane), b'E')
        def complete():
            return all((self.get(src, kind, lane) or {}).get('sequence') == sequences[lane]
                       for lane in lanes for src,kind in ((str(lane),'verified'),('server','echoed')))
        await self.wait(complete)
        for lane in lanes:
            sequences[lane] += 1

    async def close(self, lane):
        self.record('control',{'event':'close','lane':lane})
        await self.send(str(lane), b'C')


async def experiment(c, case, gate_command, ports, public, remote):
    mode = 'timeout' if case == 'timeout' else 'release'
    seq = [0]*5
    healthy = contract.HEALTHY
    async def launch(lane):
        port = ports[0 if lane == 0 else 1]
        await c.start(str(lane), [*base.client_command(port,public), '--isolation-case',mode,
                                  '--isolation-lane',str(lane)])
    await c.start('gate',gate_command)
    await c.wait(lambda: c.get('server','listening') and c.get('gate','gate_listening'), 25)
    for lane in range(4):
        await launch(lane)
    await c.wait(lambda: c.get('0','wire_ready') and c.get('server','wire_ready') and
                 all(c.get(str(i),'lane_ready',i) and c.get('server','lane_ready',i) for i in healthy))
    await c.rounds(healthy,seq)
    ready = c.get('server','wire_ready')
    ids = {k:ready[k] for k in wire_gate.IDS}
    async def gate_action(action):
        command = {'action':action,**ids}
        c.record('control',{'event':action,'command':command})
        await c.send('gate',json.dumps(command).encode()+b'\n')
    await gate_action('pause')
    await c.wait(lambda: c.get('gate','gate_paused'))
    await c.send('0',b'GO\n')
    c.procs['0'].stdin.close()
    start = None
    rounds = 0
    confirmed = False
    while not c.get('server','reclaimed',0):
        if start is None and c.get('gate','gate_stall_confirmed'):
            start = time.monotonic()
        await c.rounds(healthy,seq)
        if start is not None and not confirmed:
            rounds += 1
            if rounds >= 11 and (case!='hold' or time.monotonic()-start>=5):
                c.record('control',{'event':'overlap_verified'})
                confirmed = True
                if mode=='release':
                    await gate_action('resume')
        await asyncio.sleep(.22)
    base.require(confirmed,'target reclaimed before overlap proof')
    await launch(4)
    await c.wait(lambda: c.get('4','lane_ready',4) and c.get('server','lane_ready',4))
    await c.rounds((*healthy,4),seq)
    await c.close(4)
    await c.wait(lambda: c.get('4','final'))
    c.record('control',{'event':'replacement_closed'})
    await c.rounds(healthy,seq)
    for lane in healthy:
        await c.close(lane)
    await asyncio.gather(*c.readers)
    exits = {src:await proc.wait() for src,proc in c.procs.items()}
    return contract.validate(case,c.rows,exits,remote)


async def collect(case, folder, gateway, ports, public, remote):
    folder.mkdir(mode=0o700)
    with ExitStack() as stack:
        c = Collection(folder,stack)
        try:
            result = await asyncio.wait_for(experiment(c,case,gateway,ports,public,remote),120)
        except (Exception,KeyboardInterrupt,asyncio.CancelledError) as error:
            result = {'status':'failed','case':case,'failure':type(error).__name__+': '+str(error),
                      'observed_exits':{k:p.returncode for k,p in c.procs.items()}}
        finally:
            await c.stop()
        (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return result


def local_gate(private, mode):
    command = [str(base.BINARY),'server','--name',base.NAME,'--service',base.SERVICE,'--port',
               str(base.REMOTE_PORT),'--workers','1','--connections','5','--isolation-case',mode,
               '--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'),'--auth',str(private/'auth.bin')]
    return wire_gate.supervise(command,mode,isolation=True)


def run(args):
    with ExitStack() as stack:
        if args.action == 'local':
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='spiral-isolation-test-'))
            public = Path(directory)
            sys.path.insert(0,str(base.ROOT/'protocol_rust'))
            from interop import identities
            identities(public)
            before = base.source()
            remote = None
            output = args.output or Path.home()/f'Spiral-isolation-local-{time.time_ns()}'
            base.require(not Path(str(output)+'.tar.gz').exists(),'archive already exists')
            output.mkdir(mode=0o700)
            ports = (GATE_PORT,base.REMOTE_PORT)
            def gateway(mode):
                return [sys.executable,'-B',__file__,'local-gate','--private',directory,'--case',mode]
        else:
            target,ssh,output,public,before,remote = base.prepare_client(args,'Spiral-isolation-')
            base.require(before['source']['git_head']==remote['source']['git_head'] and
                         not before['source']['working_tree_dirty'] and not remote['source']['working_tree_dirty'],
                         'both checkouts must be clean and pinned to the same commit')
            ports = []
            for port in (GATE_PORT,base.REMOTE_PORT):
                # SSH diagnostics can include operator identifiers; keep them outside the archive.
                errors = stack.enter_context(tempfile.TemporaryFile())
                tunnel,forwarded = base.start_tunnel(ssh,target,errors,port)
                stack.callback(base.stop,tunnel)
                ports.append(forwarded)
            def gateway(mode):
                return [*ssh,target,'cd "$HOME/Spiral-isolation" && exec timeout --kill-after=5s 115s '
                        'python3 -B protocol_rust/validation/wire_gate.py serve --isolation --case '+mode]
        results = []
        for case in CASES if args.case=='all' else (args.case,):
            mode = 'timeout' if case=='timeout' else 'release'
            result = asyncio.run(collect(case,output/case,gateway(mode),ports,public,remote))
            results.append(result)
            if result['status']!='passed':
                break
        after = base.source()
        passed = all(r['status']=='passed' for r in results) and before==after
        summary = {'schema':'spiral-isolation/v1','status':'passed' if passed else 'failed',
                   'scope':args.action,'requested':args.case,'cases':results,'before':before,
                   'after':after,'remote_preparation':remote}
        base.pack_results(output,summary)
        return 0 if passed else 1


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=('local','run','local-gate'))
    ap.add_argument('--case',choices=(*CASES,'all'),default='all')
    ap.add_argument('--private',type=Path)
    ap.add_argument('--output',type=Path)
    ap.add_argument('--target')
    ap.add_argument('--identity',type=Path)
    args = ap.parse_args()
    os.umask(0o077)
    if args.action=='local-gate':
        def stop_signal(*_): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,stop_signal)
        raise SystemExit(local_gate(args.private,args.case))
    raise SystemExit(run(args))
