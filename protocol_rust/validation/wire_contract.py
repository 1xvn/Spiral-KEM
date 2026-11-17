"""Pure verdicts for a gated underlying TCP writer; no processes or I/O."""
from copy import deepcopy

import cross_host_smoke as base
from backpressure_contract import cleaned, duration, integer, snapshot

IDENTIFIERS=(('session_id',32),('binding_hash',64),('transcript_hash',64))
CASES=('release','timeout')
TUNNEL_STAGES=('before_pause','after_stall','after_end')
MAX_COUNTER=(1 << 64)-1


def counter(value):
    return integer(value,0,MAX_COUNTER)


def wire_snapshot(value):
    base.require(isinstance(value,dict),'missing underlying TCP snapshot')
    for name in ('write_pending','transport_dropped'):
        base.require(type(value.get(name)) is bool,'invalid underlying TCP flag: '+name)
    for name in ('write_pending_polls','bytes_written'):
        base.require(counter(value.get(name)),'invalid underlying TCP counter: '+name)
    base.require(not (value['transport_dropped'] and value['write_pending']),
                 'dropped TCP transport remains pending')
    return value


class WireTracker:
    """Bind peer phases, controlled read suspension and actual TCP Pending."""
    def __init__(self,case,backend_port=39401,gate_port=39402):
        base.require(case in CASES,'unsupported wire-stall case')
        base.require(type(backend_port) is int and 1<=backend_port<=65535
                     and type(gate_port) is int and 1<=gate_port<=65535
                     and backend_port!=gate_port,'invalid wire-stall ports')
        self.case=case;self.backend_port=backend_port;self.gate_port=gate_port
        self.ready={};self.remote_started=None;self.gate_listening=None;self.server_listening=False
        self.paused=None;self.reverse_held=None;self.stalled=None;self.gate_witness=None
        self.resumed=None;self.finished=None;self.finals={};self.events={'client':[],'server':[]}
        self.identifiers=None;self.pause_requested=False;self.resume_requested=False
        self.bulk_started=None;self._last_wire={}
        self.expected={'server':['wire_ready','bulk_started','wire_stalled'],
                       'client':['wire_ready']}
        if case=='release':
            self.expected['server']+=['bulk_complete','flow_cleanup']
            self.expected['client']+=['bulk_complete','flow_cleanup']
        else:
            self.expected['server']+=['wire_timeout','flow_cleanup','failure_cleanup']
            self.expected['client']+=['client_wait_failed','flow_cleanup']

    def bind(self,event):
        identifiers={}
        for name,size in IDENTIFIERS:
            value=event.get(name)
            base.require(isinstance(value,str) and len(value)==size and value!='0'*size
                         and all(c in '0123456789abcdef' for c in value),
                         'invalid wire session identifier: '+name)
            identifiers[name]=value
        if self.identifiers is None:self.identifiers=identifiers
        base.require(identifiers==self.identifiers,'wire session binding differs')

    def _counts(self,event):
        base.require(type(event.get('payload_bytes')) is int and event['payload_bytes']==16384
                     and type(event.get('bulk_messages')) is int and event['bulk_messages']==1021,
                     'bounded wire workload differs')

    def _wire(self,role,value):
        value=wire_snapshot(value)
        previous=self._last_wire.get(role)
        if previous is not None:
            base.require(all(value[name]>=previous[name] for name in ('write_pending_polls','bytes_written')),
                         'underlying TCP counters decreased')
        self._last_wire[role]=deepcopy(value)
        return value

    def _gate_identity(self,event):
        base.require(event.get('case')==self.case,'gate case differs')
        self.bind(event)

    def observe_client(self,event):
        self._observe_endpoint('client',event)

    def _observe_endpoint(self,role,event):
        base.require(isinstance(event,dict) and role not in self.finals,'invalid or late endpoint event')
        expected=self.expected[role];index=len(self.events[role])
        if 'status' in event:
            base.require(index==len(expected),'endpoint finished before required wire phases')
            self.finals[role]=deepcopy(event);return
        base.require(index<len(expected) and event.get('event')==expected[index],
                     'missing, duplicate or reordered wire endpoint phase')
        name=event['event']
        base.require(event.get('role')==role,'wire endpoint role differs')
        if name=='failure_cleanup':
            base.require(all(type(event.get(k)) is int and event[k]==0 for k in ('active','pending'))
                         and event.get('drained') is True and event.get('auth_key_closed') is True,
                         'server admission or identity cleanup incomplete')
        else:
            base.require(event.get('case')==self.case,'wire endpoint case differs')
            self.bind(event)
            self._check_phase(role,name,event)
        self.events[role].append(deepcopy(event))

    def _check_phase(self,role,name,event):
        if name=='wire_ready':
            base.require(self.remote_started is not None and self.gate_listening is not None
                         and self.server_listening and not self.pause_requested,
                         'wire readiness before listener setup or after pause request')
            self._counts(event)
            base.require(type(event.get('baseline_echoes')) is int and event['baseline_echoes']==3,
                         'three verified baseline echoes not recorded')
            self.ready[role]=deepcopy(event)
        elif name=='bulk_started':
            base.require(role=='server' and self.paused is not None and self.bulk_started is None,
                         'bulk started before read pause')
            self._counts(event)
            base.require(counter(event.get('baseline_pending_polls')),'missing initial TCP Pending count')
            self.bulk_started=deepcopy(event)
        elif name=='wire_stalled':
            base.require(role=='server' and self.bulk_started is not None and self.reverse_held is not None
                         and self.paused is not None and self.stalled is None,
                         'stall before bidirectional read containment')
            self._counts(event)
            flow=snapshot(event.get('snapshot'));wire=self._wire(role,event.get('wire_snapshot'))
            start=wire_snapshot(event.get('stable_start_wire_snapshot'))
            baseline=self.bulk_started['baseline_pending_polls']
            base.require(type(event.get('baseline_pending_polls')) is int
                         and event['baseline_pending_polls']==baseline
                         and start['write_pending'] and not start['transport_dropped']
                         and start['write_pending_polls']>baseline
                         and wire['write_pending_polls']>=start['write_pending_polls']
                         and wire['bytes_written']==start['bytes_written']
                         and wire['write_pending'] and wire['write_pending_polls']>baseline
                         and not wire['transport_dropped'] and flow['state']==0
                         and not flow['reader_done'] and not flow['writer_done']
                         and not flow['send_channel_closed'] and flow['active_sends']>0
                         and duration(event.get('stable_ms'),200)
                         and integer(event.get('completed_bulk'),0,1020),
                         'new stable underlying TCP write stall not observed')
            self.stalled=deepcopy(event)
        elif name=='bulk_complete':
            base.require(self.case=='release' and self.resume_requested and self.gate_witness is not None,
                         'bulk completed without a confirmed stall and requested release')
            if role=='server':
                base.require(self.resumed is not None,'server completed before gate resumed')
            field='completed_bulk' if role=='server' else 'verified_bulk'
            base.require(type(event.get(field)) is int and event[field]==1021,
                         'bounded bulk transfer did not complete')
        elif name=='wire_timeout':
            base.require(role=='server' and self.case=='timeout' and self.gate_witness is not None
                         and self.reverse_held is not None and not self.resume_requested,
                         'server expiry without held reverse path and confirmed stall')
            category=event.get('send_error');reason=event.get('local_close_reason')
            flow=snapshot(event.get('snapshot'));self._wire(role,event.get('wire_snapshot'))
            base.require(category in ('Deadline','Closed') and integer(reason,0,255)
                         and flow['close_reason']==reason
                         and (category=='Deadline' or reason==1)
                         and duration(event.get('elapsed_ms'),55000)
                         and integer(event.get('completed_bulk'),self.stalled['completed_bulk'],1020),
                         'no positive evidence of the server blocked-send deadline')
        elif name=='client_wait_failed':
            base.require(role=='client' and self.case=='timeout' and self.paused is not None
                         and self.bulk_started is not None
                         and event.get('error') in ('Deadline','Closed','Transport'),
                         'client failed outside the gated timeout phase')
        elif name=='flow_cleanup':
            flow=snapshot(event.get('snapshot'));wire=self._wire(role,event.get('wire_snapshot'))
            base.require(event.get('drained') is True and cleaned(flow)
                         and wire['transport_dropped'] and not wire['write_pending'],
                         'flow, producer or TCP ownership not drained')

    def observe_remote(self,packet):
        base.require(isinstance(packet,dict) and self.finished is None,'invalid or late gate event')
        name=packet.get('event')
        if name=='owned_server_started':
            base.require(self.remote_started is None and type(packet.get('child_pid')) is int
                         and packet['child_pid']>0 and packet.get('parent_death_guard') is True,
                         'missing guarded direct server child')
            self.remote_started=deepcopy(packet);return
        base.require(self.remote_started is not None,'gate event before owned server')
        if name=='gate_listening':
            base.require(self.gate_listening is None and type(packet.get('port')) is int
                         and packet['port']==self.gate_port and type(packet.get('backend_port')) is int
                         and packet['backend_port']==self.backend_port and packet.get('loopback_only') is True,
                         'unexpected gate listener')
            self.gate_listening=deepcopy(packet);return
        if name=='server_endpoint':
            event=packet.get('payload');base.require(isinstance(event,dict),'invalid server envelope')
            if not self.server_listening:
                base.require(set(event)=={'listening','loopback_only'} and type(event['listening']) is int
                             and event['listening']==self.backend_port and event['loopback_only'] is True,
                             'unexpected server listener')
                self.server_listening=True
            else:self._observe_endpoint('server',event)
            return
        if name=='gate_finished':
            expected=0 if self.case=='release' else 1
            base.require(packet.get('case')==self.case and 'server' in self.finals
                         and self.gate_witness is not None
                         and type(packet.get('child_pid')) is int
                         and packet['child_pid']==self.remote_started['child_pid']
                         and type(packet.get('child_exit_code')) is int and packet['child_exit_code']==expected
                         and packet.get('reaped') is True and packet.get('listener_present') is False
                         and packet.get('reads_held_until_server_exit') is (self.case=='timeout'),
                         'server exit or gate/listener cleanup differs')
            base.require((self.case=='release' and self.resumed is not None)
                         or (self.case=='timeout' and self.resumed is None and not self.resume_requested),
                         'unexpected release in timeout case')
            self.finished=deepcopy(packet);return
        self._gate_identity(packet)
        if name=='gate_paused':
            base.require(self.pause_requested and self.paused is None and self.bulk_started is None
                         and packet.get('backend_read_enabled') is False
                         and packet.get('frontend_read_enabled') is True
                         and counter(packet.get('backend_bytes_read'))
                         and type(packet.get('down_buffered_bytes')) is int and packet['down_buffered_bytes']==0
                         and integer(packet.get('receive_buffer_bytes'),4096,1<<30),
                         'backend reads were not paused at the ready checkpoint')
            self.paused=deepcopy(packet)
        elif name=='reverse_held':
            base.require(self.paused is not None and self.bulk_started is not None
                         and self.reverse_held is None and packet.get('frontend_read_enabled') is False,
                         'reverse path not held after authenticated GO')
            self.reverse_held=deepcopy(packet)
        elif name=='gate_stall_confirmed':
            base.require(self.paused is not None and self.reverse_held is not None
                         and self.stalled is not None and self.gate_witness is None
                         and type(packet.get('backend_bytes_read')) is int
                         and packet['backend_bytes_read']==self.paused['backend_bytes_read']
                         and packet.get('backend_read_enabled') is False
                         and packet.get('frontend_read_enabled') is False
                         and all(type(packet.get(k)) is int and packet[k]==0
                                 for k in ('up_buffered_bytes','down_buffered_bytes')),
                         'gate read progress continued during the claimed TCP stall')
            self.gate_witness=deepcopy(packet)
        elif name=='gate_resumed':
            base.require(self.case=='release' and self.resume_requested and self.gate_witness is not None
                         and self.resumed is None and 'server' not in self.finals
                         and type(packet.get('backend_bytes_read')) is int
                         and packet['backend_bytes_read']==self.paused['backend_bytes_read']
                         and integer(packet.get('receive_buffer_bytes'),4096,1<<30),
                         'gate resumed outside authorized release')
            self.resumed=deepcopy(packet)
        else:raise ValueError('unexpected remote gate event')

    def pause_command(self):
        base.require(set(self.ready)=={'client','server'} and not self.pause_requested
                     and self.paused is None and self.finished is None,'pause before matching peer readiness')
        self.pause_requested=True
        return {'action':'pause',**self.identifiers}

    def resume_command(self):
        base.require(self.case=='release' and self.gate_witness is not None and self.stalled is not None
                     and self.reverse_held is not None and not self.resume_requested
                     and self.finished is None and 'server' not in self.finals,
                     'release before confirmed underlying TCP stall or during timeout')
        self.resume_requested=True
        return {'action':'resume',**self.identifiers}

    def validate(self,codes,errors,tunnel_observations):
        expected=0 if self.case=='release' else 1
        base.require(self.finished is not None and set(self.finals)=={'client','server'}
                     and self.stalled is not None and self.gate_witness is not None,
                     'wire/gate/final evidence incomplete')
        base.require(isinstance(codes,dict) and set(codes)=={'client','supervisor'}
                     and type(codes['client']) is int and codes['client']==expected
                     and type(codes['supervisor']) is int and codes['supervisor']==0,
                     'unexpected endpoint or SSH/watchdog exit')
        base.require(isinstance(errors,dict) and set(errors)=={'client','server'},'missing raw endpoint errors')
        for role in ('client','server'):
            report=self.finals[role];kem=report.get('kem',{})
            base.require(isinstance(kem,dict) and all(type(kem.get(k)) is int and kem[k]==v for k,v in
                         (('live_keys',0),('rejected_jobs',0),('executed_jobs',2 if role=='server' else 1))),
                         'native KEM handshake accounting or ownership differs')
            base.require(isinstance(errors[role],bytes),'endpoint errors must be raw bytes')
            terminal=[line.strip() for line in errors[role].splitlines() if line.strip().startswith(b'Error:')]
            if self.case=='timeout':
                allowed=(b'Error: Deadline',b'Error: Closed') if role=='server' else (
                    b'Error: Deadline',b'Error: Closed',b'Error: Transport')
                base.require(report.get('status')=='failed' and len(terminal)==1 and terminal[0] in allowed,
                             'unexpected gated timeout status or terminal error')
            else:
                base.require(report.get('status')=='passed' and report.get('role')==role
                             and type(report.get('connections')) is int and report['connections']==1
                             and not terminal,'unexpected successful transfer result')
                sessions=report.get('sessions')
                base.require(isinstance(sessions,list) and len(sessions)==1 and isinstance(sessions[0],dict),
                             'missing successful wire session')
                session=sessions[0];self.bind(session)
                base.require(session.get('wire_stall_case')==self.case
                             and session.get('authenticated_close') is True
                             and all(type(session.get(k)) is int and session[k]==v for k,v in
                                     (('baseline_echoes',3),('bulk_messages',1021),('messages',1024),('payload_bytes',16384))),
                             'successful wire workload or closure differs')
                if role=='server':
                    base.require(report.get('admission_released') is True and report.get('auth_key_closed') is True,
                                 'successful server admission or identity retained')
        base.require(isinstance(tunnel_observations,dict) and set(tunnel_observations)==set(TUNNEL_STAGES),
                     'missing tunnel ownership observations')
        for stage in TUNNEL_STAGES:
            value=tunnel_observations[stage]
            base.require(isinstance(value,dict) and value.get('alive') is True
                         and value.get('owned_listener_present') is True,'forwarder failed at '+stage)
