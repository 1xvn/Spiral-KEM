"""Synthetic wire-verdict contracts; no sockets, processes, TLS or KEM work."""
from copy import deepcopy
import unittest

from wire_contract import WireTracker

IDS={'session_id':'12'*16,'binding_hash':'34'*32,'transcript_hash':'56'*32}


def flow(live=False,**changes):
    value={'allocated_buffers':3,'free_buffers':3,'in_use_buffers':0,
           'buffer_limit':18,'buffer_capacity_bytes':16440,'buffer_waiters':0,'active_sends':0,
           'send_slot_waiters':0,'send_slots_capacity':8,'send_slots_in_use':None,
           'send_channel_closed':True,'receive_queue_length':None,'receive_queue_capacity':8,
           'receive_delivery_waiters':0,'reader_done':True,'writer_done':True,'state':3,'close_reason':0}
    if live:value.update(free_buffers=2,in_use_buffers=1,active_sends=1,send_slots_in_use=0,
                         send_channel_closed=False,receive_queue_length=0,
                         reader_done=False,writer_done=False,state=0)
    value.update(changes);return value


def wire(pending=False,polls=7,written=300000,dropped=True,**changes):
    value={'write_pending':pending,'write_pending_polls':polls,'bytes_written':written,'transport_dropped':dropped}
    value.update(changes);return value


def trace(case):
    def event(role,name,**fields):return dict(IDS,case=case,role=role,event=name,**fields)
    def gate(name,**fields):return dict(IDS,case=case,event=name,**fields)
    def server(event):return ('remote',{'event':'server_endpoint','payload':event})
    ready={'baseline_echoes':3,'payload_bytes':16384,'bulk_messages':1021}
    values=[
        ('remote',{'event':'owned_server_started','child_pid':12345,'parent_death_guard':True}),
        ('remote',{'event':'gate_listening','port':39402,'backend_port':39401,'loopback_only':True}),
        server({'listening':39401,'loopback_only':True}),
        server(event('server','wire_ready',**ready)),
        ('client',event('client','wire_ready',**ready)),
        ('pause',None),
        ('remote',gate('gate_paused',backend_read_enabled=False,frontend_read_enabled=True,
                       backend_bytes_read=60000,down_buffered_bytes=0,receive_buffer_bytes=8192)),
        server(event('server','bulk_started',baseline_pending_polls=2,payload_bytes=16384,bulk_messages=1021)),
        ('remote',gate('reverse_held',frontend_read_enabled=False)),
        server(event('server','wire_stalled',wire_snapshot=wire(True,5,300000,False),snapshot=flow(True),
                     stable_start_wire_snapshot=wire(True,4,300000,False),
                     stable_ms=205.0,baseline_pending_polls=2,completed_bulk=17,
                     payload_bytes=16384,bulk_messages=1021)),
        ('remote',gate('gate_stall_confirmed',backend_bytes_read=60000,backend_read_enabled=False,
                       frontend_read_enabled=False,up_buffered_bytes=0,down_buffered_bytes=0)),
    ]
    if case=='release':
        values += [('resume',None),
                   ('remote',gate('gate_resumed',backend_bytes_read=60000,receive_buffer_bytes=2097152)),
                   server(event('server','bulk_complete',completed_bulk=1021)),
                   ('client',event('client','bulk_complete',verified_bulk=1021)),
                   server(event('server','flow_cleanup',drained=True,snapshot=flow(),
                                wire_snapshot=wire(False,9,16777216,True))),
                   ('client',event('client','flow_cleanup',drained=True,snapshot=flow(),
                                   wire_snapshot=wire(False,2,60000,True)))]
    else:
        values += [('client',event('client','client_wait_failed',error='Deadline')),
                   ('client',event('client','flow_cleanup',drained=True,snapshot=flow(state=2),
                                   wire_snapshot=wire(False,2,60000,True))),
                   server(event('server','wire_timeout',elapsed_ms=59600.,send_error='Closed',
                                local_close_reason=1,completed_bulk=17,snapshot=flow(close_reason=1),
                                wire_snapshot=wire(False,7,300000,True))),
                   server(event('server','flow_cleanup',drained=True,snapshot=flow(close_reason=1),
                                wire_snapshot=wire(False,7,300000,True))),
                   server({'event':'failure_cleanup','role':'server','active':0,'pending':0,
                           'drained':True,'auth_key_closed':True})]
    for role in ('server','client'):
        final={'status':'passed' if case=='release' else 'failed',
               'kem':{'executed_jobs':2 if role=='server' else 1,'live_keys':0,'rejected_jobs':0}}
        if case=='release':
            final.update(role=role,connections=1,sessions=[dict(IDS,wire_stall_case=case,
                         baseline_echoes=3,bulk_messages=1021,messages=1024,payload_bytes=16384,
                         authenticated_close=True)])
            if role=='server':final.update(admission_released=True,auth_key_closed=True)
        values.append(server(final) if role=='server' else ('client',final))
    values.append(('remote',{'event':'gate_finished','case':case,'child_pid':12345,
                            'child_exit_code':0 if case=='release' else 1,'reaped':True,
                            'listener_present':False,'reads_held_until_server_exit':case=='timeout'}))
    return values


def find(values,name,role=None):
    for channel,event in values:
        if not isinstance(event,dict):continue
        value=event['payload'] if event.get('event')=='server_endpoint' else event
        if value.get('event')==name and (role is None or value.get('role')==role):return value
    raise AssertionError('missing fixture phase '+name)


def replay(case,values=None,codes=None,errors=None,tunnels=None):
    tracker=WireTracker(case)
    for channel,event in values or trace(case):
        if channel=='remote':tracker.observe_remote(event)
        elif channel=='client':tracker.observe_client(event)
        elif channel=='pause':
            assert tracker.pause_command()==dict(IDS,action='pause')
        elif channel=='resume':
            assert tracker.resume_command()==dict(IDS,action='resume')
        else:raise AssertionError('unknown fixture channel')
    tracker.validate(codes or {'client':0 if case=='release' else 1,'supervisor':0},
                     errors or ({'client':b'','server':b''} if case=='release' else
                                {'client':b'Error: Deadline\n','server':b'Error: Closed\n'}),
                     tunnels or {stage:{'alive':True,'owned_listener_present':True}
                                 for stage in ('before_pause','after_stall','after_end')})
    return tracker


class WireVerdictContracts(unittest.TestCase):
    def test_accepts_release_and_own_server_timeout(self):
        for case in ('release','timeout'):
            with self.subTest(case=case):
                tracker=replay(case)
                self.assertEqual(tracker.identifiers,IDS)
                self.assertEqual(set(tracker.finals),{'client','server'})

    def test_client_completion_may_precede_remote_resume_observation(self):
        values=trace('release')
        moved=[x for x in values if x[0]=='client' and x[1].get('event') in ('bulk_complete','flow_cleanup')]
        values=[x for x in values if x not in moved]
        index=next(i for i,x in enumerate(values) if x[0]=='resume')+1
        values[index:index]=moved
        replay('release',values)

    def test_client_timeout_may_precede_server_timeout(self):
        tracker=replay('timeout')
        self.assertEqual(tracker.events['client'][1]['event'],'client_wait_failed')

    def test_rejects_unknown_case_or_ports(self):
        for args in (('flood',),('release',0,39402),('release',39401,39401),('release',True,39402)):
            with self.subTest(args=args),self.assertRaises(ValueError):WireTracker(*args)

    def test_requires_both_matching_ready_events_before_pause(self):
        tracker=WireTracker('release')
        with self.assertRaises(ValueError):tracker.pause_command()
        values=trace('release');find(values,'wire_ready','client')['session_id']='ab'*16
        with self.assertRaises(ValueError):replay('release',values)

    def test_requires_owned_guarded_child_and_expected_listeners(self):
        for name,field,value in (('owned_server_started','child_pid',True),
                                  ('owned_server_started','parent_death_guard',False),
                                  ('gate_listening','port',39403),('gate_listening','loopback_only',False)):
            values=trace('release');find(values,name)[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)

    def test_ready_workload_and_identifier_encoding_are_strict(self):
        for field,value in (('baseline_echoes',2),('bulk_messages',1024),('payload_bytes',1024),
                            ('session_id','0'*32),('binding_hash','z'*64),('case','timeout')):
            values=trace('release');find(values,'wire_ready','server')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)

    def test_rejects_bulk_before_gate_pause_and_duplicate_gate_events(self):
        values=trace('release');i=next(i for i,x in enumerate(values) if isinstance(x[1],dict)
                                       and x[1].get('event')=='gate_paused')
        values[i],values[i+1]=values[i+1],values[i]
        with self.assertRaises(ValueError):replay('release',values)
        values=trace('release');values.insert(2,deepcopy(values[1]))
        with self.assertRaises(ValueError):replay('release',values)

    def test_requires_new_actual_tcp_pending_after_bulk_baseline(self):
        for field,value in (('write_pending',False),('write_pending_polls',2),
                            ('write_pending_polls',True),('transport_dropped',True),('bytes_written',-1)):
            values=trace('release');find(values,'wire_stalled')['wire_snapshot'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)
        values=trace('release');find(values,'wire_stalled')['baseline_pending_polls']=1
        with self.assertRaises(ValueError):replay('release',values)

    def test_stable_start_and_end_must_both_be_pending_without_byte_progress(self):
        for field,value in (('write_pending',False),('write_pending_polls',2),
                            ('write_pending_polls',6),('transport_dropped',True),('bytes_written',299999)):
            values=trace('release');find(values,'wire_stalled')['stable_start_wire_snapshot'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)
        values=trace('release');del find(values,'wire_stalled')['stable_start_wire_snapshot']
        with self.assertRaises(ValueError):replay('release',values)

    def test_requires_stable_open_incomplete_send(self):
        for field,value in (('stable_ms',199.),('stable_ms',float('nan')),('stable_ms',True),('completed_bulk',1021)):
            values=trace('release');find(values,'wire_stalled')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)
        for field,value in (('state',1),('active_sends',0),('writer_done',True),('buffer_limit',19)):
            values=trace('release');find(values,'wire_stalled')['snapshot'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)

    def test_requires_frozen_gate_counter_and_both_read_directions_held(self):
        for field,value in (('backend_bytes_read',60001),('backend_read_enabled',True),
                            ('frontend_read_enabled',True),('up_buffered_bytes',1),('down_buffered_bytes',1)):
            values=trace('release');find(values,'gate_stall_confirmed')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)

    def test_release_cannot_be_requested_early_or_during_timeout(self):
        for case in ('release','timeout'):
            with self.subTest(case=case),self.assertRaises(ValueError):WireTracker(case).resume_command()
        values=trace('timeout');index=next(i for i,x in enumerate(values) if isinstance(x[1],dict)
                                            and x[1].get('event')=='gate_stall_confirmed')+1
        values.insert(index,('resume',None))
        with self.assertRaises(ValueError):replay('timeout',values)

    def test_pause_and_resume_commands_cannot_repeat(self):
        for action in ('pause','resume'):
            values=trace('release');index=next(i for i,x in enumerate(values) if x[0]==action)
            values.insert(index+1,(action,None))
            with self.subTest(action=action),self.assertRaises(ValueError):replay('release',values)

    def test_timeout_requires_own_server_deadline_not_just_peer_close(self):
        values=trace('timeout');find(values,'wire_timeout')['local_close_reason']=0
        with self.assertRaises(ValueError):replay('timeout',values)
        find(values,'wire_timeout')['send_error']='Deadline'
        find(values,'wire_timeout')['snapshot']['close_reason']=0
        replay('timeout',values)

    def test_timeout_requires_elapsed_and_incomplete_bulk(self):
        for field,value in (('elapsed_ms',54000.),('send_error','Transport'),('completed_bulk',1021)):
            values=trace('timeout');find(values,'wire_timeout')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('timeout',values)

    def test_requires_all_flow_and_transport_ownership_to_drain(self):
        for field,value in (('drained',False),):
            values=trace('release');find(values,'flow_cleanup','server')[field]=value
            with self.assertRaises(ValueError):replay('release',values)
        for field,value in (('active_sends',1),('writer_done',False),('buffer_waiters',1)):
            values=trace('release');find(values,'flow_cleanup','server')['snapshot'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)
        values=trace('release');find(values,'flow_cleanup','server')['wire_snapshot']['transport_dropped']=False
        with self.assertRaises(ValueError):replay('release',values)

    def test_wire_counters_cannot_go_backwards(self):
        values=trace('release');find(values,'flow_cleanup','server')['wire_snapshot']['bytes_written']=299999
        with self.assertRaises(ValueError):replay('release',values)

    def test_requires_server_admission_cleanup_after_timeout(self):
        for field,value in (('active',1),('pending',1),('auth_key_closed',False),('drained',False)):
            values=trace('timeout');find(values,'failure_cleanup')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('timeout',values)

    def test_rejects_watchdog_or_ssh_failure_exit(self):
        for codes in ({'client':0,'supervisor':124},{'client':1,'supervisor':0},
                      {'client':0,'supervisor':0,'server':0},{'client':False,'supervisor':0}):
            with self.subTest(codes=codes),self.assertRaises(ValueError):replay('release',codes=codes)

    def test_expected_failure_category_and_key_accounting_are_required(self):
        for errors in ({'client':b'Error: Authentication\n','server':b'Error: Closed\n'},
                       {'client':b'Error: Closed\n','server':b'Error: Transport\n'},
                       {'client':b'Error: Closed\nError: Deadline\n','server':b'Error: Closed\n'}):
            with self.subTest(errors=errors),self.assertRaises(ValueError):replay('timeout',errors=errors)
        values=trace('release')
        final=next(v['payload'] for c,v in values if c=='remote' and v.get('event')=='server_endpoint'
                   and v['payload'].get('status'))
        final['kem']['live_keys']=1
        with self.assertRaises(ValueError):replay('release',values)

    def test_final_workload_binding_and_closure_are_required(self):
        for field,value in (('messages',10),('bulk_messages',1020),('payload_bytes',1024),
                            ('authenticated_close',False),('session_id','ab'*16)):
            values=trace('release');final=next(v for c,v in values if c=='client' and v.get('status'))
            final['sessions'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)

    def test_requires_owned_tunnel_at_each_observation(self):
        for stage in ('before_pause','after_stall','after_end'):
            values={name:{'alive':True,'owned_listener_present':True}
                    for name in ('before_pause','after_stall','after_end')}
            values[stage]['owned_listener_present']=False
            with self.subTest(stage=stage),self.assertRaises(ValueError):replay('release',tunnels=values)

    def test_requires_matching_reaped_server_and_gate_listener_cleanup(self):
        for field,value in (('child_pid',54321),('child_exit_code',124),('listener_present',True),
                            ('reaped',False),('reads_held_until_server_exit',True)):
            values=trace('release');find(values,'gate_finished')[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):replay('release',values)
        values=trace('timeout');find(values,'gate_finished')['reads_held_until_server_exit']=False
        with self.assertRaises(ValueError):replay('timeout',values)

    def test_missing_or_reordered_endpoint_phases_cannot_pass(self):
        values=trace('release');index=next(i for i,(c,v) in enumerate(values) if c=='client' and v.get('event')=='bulk_complete')
        del values[index]
        with self.assertRaises(ValueError):replay('release',values)
        values=trace('timeout');index=next(i for i,(c,v) in enumerate(values) if c=='remote' and v.get('event')=='server_endpoint'
                                         and v['payload'].get('event')=='wire_timeout')
        values[index],values[index+1]=values[index+1],values[index]
        with self.assertRaises(ValueError):replay('timeout',values)


if __name__=='__main__':unittest.main()
