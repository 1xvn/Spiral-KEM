"""Owned-server crash verdicts; no subprocesses, sockets, TLS or long workloads."""
from copy import deepcopy
import unittest

import crash_contract as crash


def checkpoints():
    common={'event':'request_pending','fault_checkpoint':3,'session_id':'12'*16,
            'binding_hash':'34'*32,'transcript_hash':'56'*32}
    return {'client':dict(common,role='client',sent_messages=4,verified_echoes=3,payload_bytes=1024),
            'server':dict(common,role='server',received_messages=4,echoed_messages=3,pending_payload_bytes=1024)}


def started(tracker=None):
    tracker=tracker or crash.CrashTracker()
    tracker.observe_remote({'event':'owned_server_started','child_pid':9001,'parent_death_guard':True})
    tracker.observe_remote({'event':'server_endpoint','payload':{'listening':tracker.port,'loopback_only':True}})
    return tracker


def pending(order=('client','server')):
    tracker=started();points=checkpoints()
    for role in order:
        if role=='client':tracker.observe_client(points[role])
        else:tracker.observe_remote({'event':'server_endpoint','payload':points[role]})
    return tracker


def killed_packet():
    return {'event':'owned_server_killed','child_pid':9001,'signal':'SIGKILL','child_exit_code':-9,
            'reaped':True,'stdout_eof':True,'listener_present':False,'checkpoint':checkpoints()['server']}


def final():
    return {'status':'failed','kem':{'executed_jobs':1,'live_keys':0,'rejected_jobs':0}}


def complete(final_first=False):
    tracker=pending();tracker.authorize()
    if final_first:tracker.observe_client(final())
    tracker.observe_remote(killed_packet())
    if not final_first:tracker.observe_client(final())
    return tracker


def tunnels():
    return {stage:{'alive':True,'owned_listener_present':True} for stage in crash.TUNNEL_STAGES}


class CheckpointContracts(unittest.TestCase):
    def test_accepts_either_pending_arrival_order_and_fixed_command(self):
        for order in (('client','server'),('server','client')):
            tracker=pending(order);command=tracker.authorize()
            self.assertEqual(command,{'action':'kill',**{n:checkpoints()['client'][n] for n,_ in crash.IDENTIFIERS}})
            self.assertNotIn('child_pid',command)

    def test_requires_owned_child_and_parent_death_guard(self):
        for field,value in (('child_pid',0),('child_pid',True),('child_pid','9001'),('parent_death_guard',False)):
            event={'event':'owned_server_started','child_pid':9001,'parent_death_guard':True};event[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):crash.CrashTracker().observe_remote(event)

    def test_rejects_endpoint_before_owner_and_duplicate_start(self):
        event={'event':'server_endpoint','payload':{'listening':39401,'loopback_only':True}}
        with self.assertRaises(ValueError):crash.CrashTracker().observe_remote(event)
        with self.assertRaises(ValueError):started().observe_remote({'event':'owned_server_started','child_pid':9001,'parent_death_guard':True})

    def test_requires_exact_owned_loopback_readiness(self):
        for payload in ({'listening':39402,'loopback_only':True},{'listening':39401,'loopback_only':False},
                        {'listening':39401,'loopback_only':True,'event':'request_pending'}):
            tracker=crash.CrashTracker();tracker.observe_remote({'event':'owned_server_started','child_pid':9001,'parent_death_guard':True})
            with self.subTest(payload=payload),self.assertRaises(ValueError):tracker.observe_remote({'event':'server_endpoint','payload':payload})

    def test_rejects_authorization_without_both_pending_peers(self):
        tracker=started();tracker.observe_client(checkpoints()['client'])
        with self.assertRaises(ValueError):tracker.authorize()
        with self.assertRaises(ValueError):crash.CrashTracker().authorize()

    def test_requires_verified_echoes_and_authenticated_pending_data(self):
        for role,field,value in (('client','verified_echoes',0),('client','sent_messages',3),
                                 ('server','received_messages',3),('server','echoed_messages',4),
                                 ('server','pending_payload_bytes',0)):
            tracker=started();point=checkpoints()[role];point[field]=value
            with self.subTest(role=role,field=field),self.assertRaises(ValueError):
                if role=='client':tracker.observe_client(point)
                else:tracker.observe_remote({'event':'server_endpoint','payload':point})

    def test_rejects_identifier_mismatch_and_malformed_identifiers(self):
        for field,size in crash.IDENTIFIERS:
            tracker=started();tracker.observe_client(checkpoints()['client']);point=checkpoints()['server'];point[field]='ab'*(size//2)
            with self.subTest(field=field),self.assertRaises(ValueError):tracker.observe_remote({'event':'server_endpoint','payload':point})
        tracker=started();point=checkpoints()['client'];point['session_id']='z'*32
        with self.assertRaises(ValueError):tracker.observe_client(point)

    def test_rejects_duplicate_pending_authorization_and_late_pending(self):
        tracker=pending()
        with self.assertRaises(ValueError):tracker.observe_client(checkpoints()['client'])
        tracker.authorize()
        with self.assertRaises(ValueError):tracker.authorize()
        with self.assertRaises(ValueError):tracker.observe_remote({'event':'server_endpoint','payload':checkpoints()['server']})

    def test_rejects_premature_client_failure_or_kill_acknowledgment(self):
        with self.assertRaises(ValueError):pending().observe_client(final())
        with self.assertRaises(ValueError):pending().observe_remote(killed_packet())

    def test_rejects_crashed_server_userspace_cleanup_or_final(self):
        for payload in ({'event':'failure_cleanup','role':'server','active':0,'pending':0},
                        {'status':'passed','role':'server'}, {'status':'failed','kem':{'live_keys':0}}):
            tracker=pending();tracker.authorize()
            with self.subTest(payload=payload),self.assertRaises(ValueError):tracker.observe_remote({'event':'server_endpoint','payload':payload})


class CrashVerdicts(unittest.TestCase):
    codes={'client':1,'supervisor':0}

    def test_accepts_expected_client_failure_before_or_after_remote_ack(self):
        for first in (False,True):
            for error in (b'Error: Closed\n',b'Error: Transport\n'):
                self.assertIsNone(complete(first).validate(self.codes,error,tunnels()))

    def test_requires_direct_child_sigkill_reaping_eof_and_listener_release(self):
        for field,value in (('child_pid',9002),('signal','SIGTERM'),('child_exit_code',-15),
                            ('child_exit_code',137),('reaped',False),('stdout_eof',False),('listener_present',True)):
            tracker=pending();tracker.authorize();packet=killed_packet();packet[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):tracker.observe_remote(packet)

    def test_requires_acknowledgment_for_the_authenticated_pending_request(self):
        tracker=pending();tracker.authorize();packet=killed_packet();packet['checkpoint']['transcript_hash']='ab'*32
        with self.assertRaises(ValueError):tracker.observe_remote(packet)

    def test_rejects_missing_evidence_duplicate_ack_or_client_final(self):
        tracker=pending();tracker.authorize()
        with self.assertRaises(ValueError):tracker.validate(self.codes,b'Error: Closed\n',tunnels())
        tracker=complete()
        with self.assertRaises(ValueError):tracker.observe_remote(killed_packet())
        with self.assertRaises(ValueError):tracker.observe_client(final())

    def test_rejects_watchdog_ssh_signal_or_success_client_exits(self):
        for role,code in (('supervisor',124),('supervisor',255),('supervisor',-15),('client',0),('client',137)):
            with self.subTest(role=role,code=code),self.assertRaises(ValueError):complete().validate(dict(self.codes,**{role:code}),b'Error: Closed\n',tunnels())

    def test_rejects_wrong_error_missing_error_or_multiple_terminal_errors(self):
        for message in (b'Error: Deadline\n',b'Error: Authentication\n',b'Connection closed\n',
                        b'Error: Closed\nError: Transport\n'):
            with self.subTest(message=message),self.assertRaises(ValueError):complete().validate(self.codes,message,tunnels())

    def test_requires_failed_client_and_zero_keys_with_completed_handshake(self):
        for field,value in (('live_keys',1),('rejected_jobs',1),('executed_jobs',0)):
            tracker=complete();tracker.client_final['kem'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):tracker.validate(self.codes,b'Error: Closed\n',tunnels())
        tracker=complete();tracker.client_final['status']='passed'
        with self.assertRaises(ValueError):tracker.validate(self.codes,b'Error: Closed\n',tunnels())

    def test_requires_live_owned_tunnel_at_all_three_stages(self):
        for stage in crash.TUNNEL_STAGES:
            for field in ('alive','owned_listener_present'):
                observed=tunnels();observed[stage][field]=False
                with self.subTest(stage=stage,field=field),self.assertRaises(ValueError):complete().validate(self.codes,b'Error: Closed\n',observed)
        observed=tunnels();del observed['after_kill']
        with self.assertRaises(ValueError):complete().validate(self.codes,b'Error: Closed\n',observed)

    def test_observations_are_snapshots_not_mutable_input_aliases(self):
        tracker=started();points=checkpoints();tracker.observe_client(points['client'])
        points['client']['session_id']='ab'*16
        tracker.observe_remote({'event':'server_endpoint','payload':points['server']})
        self.assertEqual(tracker.authorize()['session_id'],'12'*16)


if __name__=='__main__':unittest.main()
