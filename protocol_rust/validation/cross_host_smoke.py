#!/usr/bin/env python3
"""Operator-run Rust TLS smoke over an authenticated SSH tunnel, across hosts."""
import argparse
import io
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import subprocess
import sys
import tarfile
import time

import load_campaign as campaign

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'protocol_rust/target/release/spiral-lab'
STATE = 'Spiral-cross-host-server'
REMOTE_PORT = 39401
NAME = 'spiral-lab.example'
SERVICE = 'spiral-research'


def require(value, message):
    if not value:
        raise ValueError(message)


def source():
    return {'source': campaign.source_snapshot(), 'runner_sha256': campaign.sha(Path(__file__)),
            'binary_sha256': campaign.sha(BINARY), 'architecture': platform.machine()}


def public_files(blob):
    require(len(blob) <= 2 * 1024 * 1024, 'public bundle exceeds bound')
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as packed:
        members = packed.getmembers()
        require(len(members) == 3 and {m.name for m in members} == {'ca.pem','pin.json','provenance.json'}, 'unexpected public bundle')
        require(all(m.isfile() and m.size < 1024 * 1024 for m in members), 'unsafe public bundle')
        return {m.name: packed.extractfile(m).read() for m in members}


def prepare():
    sys.path.insert(0, str(ROOT / 'protocol_rust'))
    from interop import identities
    state = Path.home() / STATE
    state.mkdir(mode=0o700, exist_ok=False)
    private = state / 'private'; private.mkdir(mode=0o700)
    identities(private, lifetime_seconds=86400)
    metadata = source()
    (state / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with tarfile.open(state / 'public.tar.gz', 'x:gz') as packed:
        for name in ('ca.pem','pin.json'):
            packed.add(private / name, arcname=name, recursive=False)
        packed.add(state / 'provenance.json', arcname='provenance.json', recursive=False)
    print('Prepared 24-hour TEST credentials. Private keys remain on this host.')
    print('Public bundle: ' + str(state / 'public.tar.gz'))


def serve():
    state = Path.home() / STATE
    saved = campaign.strict_json((state / 'provenance.json').read_bytes())
    current = source()
    require(saved['source']['files'] == current['source']['files'] and saved['runner_sha256'] == current['runner_sha256']
            and saved['binary_sha256'] == current['binary_sha256'], 'server source or binary changed since preparation')
    private = state / 'private'
    command = [str(BINARY),'server','--name',NAME,'--service',SERVICE,'--port',str(REMOTE_PORT),
               '--connections','1','--messages','10','--workers','1',
               '--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'),'--auth',str(private/'auth.bin')]
    # An interrupted SSH controller must not leave a persistent remote listener.
    # Coreutils bounds even a lost SSH channel; successful closure is still
    # checked from Rust's own final report by the client-side controller.
    os.execvp('timeout', ['timeout','--kill-after=5s','60s',*command])


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def listening(port, pid=None, proc=Path('/proc')):
    endpoint = f'0100007F:{port:04X}'
    inodes={parts[9] for line in (proc/'net/tcp').read_text().splitlines()[1:]
            if len(parts := line.split()) > 9 and parts[1] == endpoint and parts[3] == '0A'}
    if pid is None:return bool(inodes)
    try:
        return any(os.readlink(fd) in {'socket:['+inode+']' for inode in inodes}
                   for fd in (proc/str(pid)/'fd').iterdir())
    except (FileNotFoundError,ProcessLookupError,PermissionError):
        return False


def readiness(process, output):
    trace = bytearray(); deadline = time.monotonic() + 120
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key,_ in selector.select(.2):
                chunk = os.read(key.fd,65536)
                require(chunk, 'SSH/server ended before listening')
                trace.extend(chunk); output.write(chunk); output.flush()
                require(len(trace) <= 1024 * 1024, 'server readiness output exceeds bound')
                if b'\n' in trace:
                    first = campaign.strict_json(bytes(trace).split(b'\n',1)[0])
                    require(first.get('listening') == REMOTE_PORT and first.get('loopback_only') is True, 'unexpected server readiness')
                    return
        raise TimeoutError('SSH/server readiness timed out')


def final_report(data):
    reports = [campaign.strict_json(line) for line in data.splitlines() if line.strip()]
    require(reports and isinstance(reports[-1],dict), 'missing endpoint result')
    return reports[-1]


def validate_pair(server, client):
    for role, report in (('server',server),('client',client)):
        require(report.get('status') == 'passed' and report.get('role') == role
                and report.get('connections') == 1 and report.get('kem',{}).get('live_keys') == 0, 'endpoint result failed')
        sessions = report.get('sessions')
        require(isinstance(sessions,list) and len(sessions) == 1 and sessions[0].get('messages') == 10
                and sessions[0].get('authenticated_close') is True, 'echo count or closure differs')
    require(client['sessions'][0].get('payload_bytes') == 1024, 'client payload differs')
    require(server.get('admission_released') is True and server.get('auth_key_closed') is True, 'server ownership not released')
    for key,size in (('session_id',32),('binding_hash',64),('transcript_hash',64)):
        a=server['sessions'][0].get(key); b=client['sessions'][0].get(key)
        require(isinstance(a,str) and len(a)==size and a==b and a!='0'*size, 'endpoint binding/session mismatch')
        require(all(c in '0123456789abcdef' for c in a), 'malformed endpoint identifier')


def client_command(port, public, wrong=False):
    pin = public / 'pin.json'
    if wrong:
        value = campaign.strict_json(pin.read_bytes()); value['public_key_hex']='00'*32
        pin = public / 'wrong-pin.json'; pin.write_text(json.dumps(value))
    return [str(BINARY),'client','--name',NAME,'--service',SERVICE,'--port',str(port),
            '--connections','1','--messages','10','--payload','1024','--workers','1',
            '--ca',str(public/'ca.pem'),'--pin',str(pin)]


def run_case(kind, ssh, target, public, folder):
    folder.mkdir(mode=0o700)
    tunnel = remote = None
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0)); port = reserve.getsockname()[1]
    result={'case':kind,'status':'failed'}
    try:
        with (folder/'tunnel.stderr.log').open('wb') as tunnel_errors:
            tunnel = subprocess.Popen([*ssh,'-N','-o','ExitOnForwardFailure=yes','-L',
                f'127.0.0.1:{port}:127.0.0.1:{REMOTE_PORT}',target],stdout=subprocess.DEVNULL,
                stderr=tunnel_errors,start_new_session=True)
            deadline = time.monotonic()+120
            while not listening(port,tunnel.pid):
                require(tunnel.poll() is None, 'SSH tunnel failed; check tunnel.stderr.log')
                if time.monotonic()>deadline: raise TimeoutError('SSH tunnel setup timed out')
                time.sleep(.1)
            require(tunnel.poll() is None,'SSH tunnel exited during setup')
            if kind == 'unavailable':
                stop(tunnel)
                require(not listening(port),'tunnel listener still present')
            else:
                with (folder/'server.stderr.log').open('wb') as server_errors, (folder/'server.jsonl').open('wb') as server_out:
                    remote = subprocess.Popen([*ssh,target,
                        'cd "$HOME/Spiral-load-hours" && exec python3 -B protocol_rust/validation/cross_host_smoke.py serve'],
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=server_errors,start_new_session=True)
                    readiness(remote,server_out)  # No TCP readiness probe: that would consume the one connection.
                    client = subprocess.run(client_command(port,public,kind=='wrong-pin'),capture_output=True,timeout=40)
                    (folder/'client.jsonl').write_bytes(client.stdout); (folder/'client.stderr.log').write_bytes(client.stderr)
                    remaining,_ = remote.communicate(timeout=65); server_out.write(remaining)
                server = final_report((folder/'server.jsonl').read_bytes()); peer = final_report(client.stdout)
                if kind == 'wrong-pin':
                    require(client.returncode != 0 and remote.returncode != 0, 'wrong pin was accepted')
                    require(b'Authentication' in client.stderr, 'wrong-pin client failed for an unrelated reason')
                    require(all(r.get('status')=='failed' and r.get('kem',{}).get('live_keys')==0 for r in (server,peer)), 'wrong-pin cleanup/result differs')
                else:
                    require(client.returncode==0 and remote.returncode==0,'cross-host endpoint failed')
                    validate_pair(server,peer)
                result.update(server=server,client=peer,client_exit=client.returncode,server_exit=remote.returncode)
            if kind=='unavailable':
                client=subprocess.run(client_command(port,public),capture_output=True,timeout=10)
                (folder/'client.jsonl').write_bytes(client.stdout);(folder/'client.stderr.log').write_bytes(client.stderr)
                peer=final_report(client.stdout)
                require(client.returncode!=0 and peer.get('status')=='failed' and peer.get('kem',{}).get('live_keys')==0,'closed tunnel was unexpectedly usable')
                require(b'Transport' in client.stderr,'closed-tunnel client failed for an unrelated reason')
                result.update(client=peer,client_exit=client.returncode,scope='Transport unavailable before connection; not an in-flight session interruption.')
            result['status']='passed'
    except (Exception,KeyboardInterrupt) as error:
        result['failure']=type(error).__name__+': '+str(error)
        if isinstance(error,KeyboardInterrupt):result['operator_cancelled']=True
    finally:
        stop(remote); stop(tunnel)
        result['remote_listener_lifetime_bound_seconds']=65
        (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def run(args):
    target=args.target or input('Existing OCI SSH target (alias or ubuntu@host): ').strip()
    require(target and not target.startswith('-') and not any(c.isspace() for c in target),'invalid SSH target')
    identity=args.identity
    if identity is None:
        entered=input('Existing SSH private-key path in WSL (empty for agent/config): ').strip()
        identity=Path(entered).expanduser() if entered else None
    ssh=['ssh','-T','-o','ControlMaster=no','-o','ControlPath=none','-o','ForkAfterAuthentication=no','-o','ConnectTimeout=15',
         '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2']
    if identity is not None:
        require(identity.is_file(),'SSH key path is not a file');ssh += ['-i',str(identity)]
    output=(args.output or Path.home()/f'Spiral-cross-host-{time.time_ns()}').resolve()
    require(not output.exists() and not Path(str(output)+'.tar.gz').exists(),'choose a new output directory')
    output.mkdir(mode=0o700,parents=True); public=output/'public';public.mkdir(mode=0o700)
    before=source()
    fetched=subprocess.run([*ssh,target,'cat "$HOME/'+STATE+'/public.tar.gz"'],capture_output=True,timeout=120)
    require(fetched.returncode==0,'could not fetch public bundle; verify existing SSH access and OCI preparation')
    exported=public_files(fetched.stdout)
    for name,data in exported.items():(public/name).write_bytes(data)
    pin=campaign.strict_json(exported['pin.json'])
    require(pin['not_before'] <= time.time() < pin['not_after'] and pin['revoked'] is False,
            'public test identity expired/not yet valid/revoked; prepare fresh OCI credentials')
    remote=campaign.strict_json(exported['provenance.json'])
    require(remote['source']['files']==before['source']['files'] and remote['runner_sha256']==before['runner_sha256'],'OCI and WSL source differ; update/build/prepare both')
    cases=('normal','wrong-pin','unavailable','recovery') if args.case=='all' else (args.case,)
    results=[]
    for kind in cases:
        print('Starting '+kind,flush=True)
        result=run_case(kind,ssh,target,public,output/kind);results.append(result)
        print(kind+': '+result['status'],flush=True)
        if result['status']!='passed':break
    after=source()
    unchanged=before['source']['files']==after['source']['files'] and before['binary_sha256']==after['binary_sha256'] and before['runner_sha256']==after['runner_sha256']
    successful={r['case']:r for r in results if r['status']=='passed' and 'server' in r}
    recovery_fresh=None
    if 'normal' in successful and 'recovery' in successful:
        recovery_fresh=successful['normal']['client']['sessions'][0]['session_id']!=successful['recovery']['client']['sessions'][0]['session_id']
    summary={'status':'passed' if unchanged and recovery_fresh is not False and all(r['status']=='passed' for r in results) else 'failed',
             'scope':'Separate OCI/WSL hosts over SSH forwarding; server identity/echo/closure checks. SSH controls access. No application-level client authentication, capacity, or trustworthy WSL timing claim.',
             'local_before':before,'local_after':after,'remote_preparation':remote,'local_unchanged':unchanged,
             'recovery_session_is_fresh':recovery_fresh,'cases':results}
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    files=sorted(p for p in output.rglob('*') if p.is_file())
    manifest={p.relative_to(output).as_posix():campaign.sha(p) for p in files}
    inventory=output/'SHA256.json';inventory.write_text(json.dumps(manifest,indent=2)+'\n')
    with tarfile.open(str(output)+'.tar.gz','x:gz') as packed:
        for p in [*files,inventory]:packed.add(p,arcname=output.name+'/'+p.relative_to(output).as_posix(),recursive=False)
    print(json.dumps({'status':summary['status'],'archive':str(output)+'.tar.gz'}),flush=True)
    return 0 if summary['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare-server','serve','run'))
    p.add_argument('--case',choices=('normal','wrong-pin','unavailable','all'),default='normal')
    p.add_argument('--target',help='Existing SSH alias or user@host')
    p.add_argument('--identity',type=Path,help='Existing private-key path in WSL; never copied')
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    require(sys.platform=='linux','Use Ubuntu/WSL Linux')
    require(BINARY.is_file(),'Build the spiral-lab release binary first')
    os.umask(0o077)
    def cancelled(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,cancelled)
    if args.action=='prepare-server':prepare();return 0
    if args.action=='serve':serve();return 0
    return run(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
