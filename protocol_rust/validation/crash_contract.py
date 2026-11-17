"""Pure verdict contracts for an owned server SIGKILL and client failure."""
from copy import deepcopy

import cross_host_smoke as base
from inflight_disconnect import IDENTIFIERS, PendingTracker

TUNNEL_STAGES=('before_request','after_kill','after_client_exit')


def positive_pid(value):
    return type(value) is int and value>0


class CrashTracker:
    """Bind killing one owned child to matching authenticated checkpoints."""
    def __init__(self, port=base.REMOTE_PORT):
        base.require(type(port) is int and 1<=port<=65535,'invalid expected server port')
        self.port=port
        self._pending=PendingTracker()
        self.pending=self._pending.pending
        self.started=None
        self.killed=None
        self.client_final=None
        self.requested=False
        self.listening=False

    def observe_client(self, event):
        base.require(isinstance(event,dict) and self.client_final is None,'invalid or late client event')
        if event.get('event')=='request_pending':
            base.require(self.started is not None and self.listening and not self.requested,
                         'client checkpoint before readiness or after kill request')
            self._pending.observe('client',deepcopy(event))
        elif 'status' in event:
            base.require(self.requested,'client finished before kill authorization')
            self.client_final=deepcopy(event)
        else:
            raise ValueError('unexpected client event')

    def observe_remote(self, packet):
        base.require(isinstance(packet,dict) and self.killed is None,'invalid or late remote event')
        name=packet.get('event')
        if self.started is None:
            base.require(name=='owned_server_started' and positive_pid(packet.get('child_pid'))
                         and packet.get('parent_death_guard') is True,'missing guarded owned server')
            self.started=deepcopy(packet)
            return
        if name=='server_endpoint':
            event=packet.get('payload')
            base.require(isinstance(event,dict),'nonobject server endpoint event')
            if not self.listening:
                base.require(set(event)=={'listening','loopback_only'}
                             and type(event['listening']) is int and event['listening']==self.port
                             and event['loopback_only'] is True,'unexpected server readiness')
                self.listening=True
            else:
                base.require(not self.requested and event.get('event')=='request_pending',
                             'unexpected server event or userspace-cleanup claim')
                self._pending.observe('server',deepcopy(event))
        elif name=='owned_server_killed':
            self._check_killed(packet)
            self.killed=deepcopy(packet)
        else:
            raise ValueError('unexpected remote supervisor event')

    def authorize(self):
        base.require(self.started is not None and self.listening and not self.requested
                     and self.killed is None,'invalid kill authorization order')
        self._pending.inject()
        self.requested=True
        return {'action':'kill',**{name:self.pending['client'][name] for name,_ in IDENTIFIERS}}

    def _check_killed(self, packet):
        base.require(self.requested and set(self.pending)=={'client','server'},
                     'server died before matching checkpoint authorization')
        base.require(positive_pid(packet.get('child_pid'))
                     and packet['child_pid']==self.started['child_pid']
                     and packet.get('signal')=='SIGKILL'
                     and type(packet.get('child_exit_code')) is int and packet['child_exit_code']==-9
                     and packet.get('reaped') is True and packet.get('stdout_eof') is True
                     and packet.get('listener_present') is False,
                     'owned direct server child was not killed, reaped and released')
        base.require(packet.get('checkpoint')==self.pending['server'],'kill acknowledgment checkpoint differs')

    def validate(self, codes, client_stderr, tunnel_observations):
        base.require(self.requested and self.killed is not None and self.client_final is not None,
                     'kill or client failure evidence incomplete')
        self._check_killed(self.killed)
        base.require(isinstance(codes,dict) and set(codes)=={'client','supervisor'}
                     and type(codes['client']) is int and codes['client']==1
                     and type(codes['supervisor']) is int and codes['supervisor']==0,
                     'unexpected client or supervisor exit (including SSH/watchdog failure)')
        report=self.client_final
        kem=report.get('kem',{})
        base.require(report.get('status')=='failed' and isinstance(kem,dict)
                     and all(type(kem.get(name)) is int and kem[name]==expected
                             for name,expected in (('executed_jobs',1),('live_keys',0),('rejected_jobs',0))),
                     'client handshake or native-key cleanup differs')
        base.require(isinstance(client_stderr,bytes),'missing raw client terminal error')
        terminal=[line.strip() for line in client_stderr.splitlines() if line.strip().startswith(b'Error:')]
        base.require(len(terminal)==1 and terminal[0] in (b'Error: Closed',b'Error: Transport'),
                     'unexpected client error category after server crash')
        base.require(isinstance(tunnel_observations,dict) and set(tunnel_observations)==set(TUNNEL_STAGES),
                     'missing independent tunnel observations')
        for stage in TUNNEL_STAGES:
            observed=tunnel_observations[stage]
            base.require(isinstance(observed,dict) and observed.get('alive') is True
                         and observed.get('owned_listener_present') is True,
                         'forwarder failed or lost its owned listener: '+stage)
