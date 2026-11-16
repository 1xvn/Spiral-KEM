"""Pure failure-verdict contracts; no processes, SSH, sockets or TLS started."""
import unittest

import inflight_disconnect as fault


def checkpoints():
    common={'event':'request_pending','fault_checkpoint':3,'session_id':'12'*16,
            'binding_hash':'34'*32,'transcript_hash':'56'*32}
    return {'client':dict(common,role='client',sent_messages=4,verified_echoes=3,payload_bytes=1024),
            'server':dict(common,role='server',received_messages=4,echoed_messages=3,pending_payload_bytes=1024)}


def complete():
    tracker=fault.PendingTracker();points=checkpoints()
    tracker.observe('client',points['client']);tracker.observe('server',points['server']);tracker.inject()
    tracker.observe('server',{'event':'failure_cleanup','role':'server','active':0,'pending':0,
                             'auth_key_closed':True,'drained':True})
    for role,jobs in (('server',2),('client',1)):
        tracker.observe(role,{'status':'failed','kem':{'live_keys':0,'rejected_jobs':0,'executed_jobs':jobs}})
    return tracker


class PendingContracts(unittest.TestCase):
    def test_accepts_both_checkpoints_in_either_arrival_order(self):
        for order in (('client','server'),('server','client')):
            tracker=fault.PendingTracker();points=checkpoints()
            for role in order:tracker.observe(role,points[role])
            tracker.inject();self.assertTrue(tracker.cut)

    def test_rejects_cut_without_both_peers(self):
        tracker=fault.PendingTracker();tracker.observe('client',checkpoints()['client'])
        with self.assertRaises(ValueError):tracker.inject()

    def test_rejects_each_binding_mismatch(self):
        for name in ('session_id','binding_hash','transcript_hash'):
            points=checkpoints();points['server'][name]='ab'*(len(points['server'][name])//2)
            tracker=fault.PendingTracker();tracker.observe('client',points['client'])
            with self.subTest(field=name),self.assertRaises(ValueError):tracker.observe('server',points['server'])

    def test_requires_three_verified_echoes_and_fourth_received_request(self):
        for role,name,value in (('client','verified_echoes',0),('client','sent_messages',3),
                                ('server','received_messages',3),('server','pending_payload_bytes',0)):
            point=checkpoints()[role];point[name]=value
            with self.subTest(role=role,field=name),self.assertRaises(ValueError):fault.PendingTracker().observe(role,point)

    def test_rejects_duplicate_or_malformed_checkpoint(self):
        tracker=fault.PendingTracker();point=checkpoints()['client'];tracker.observe('client',point)
        with self.assertRaises(ValueError):tracker.observe('client',point)
        point['session_id']='z'*32
        with self.assertRaises(ValueError):fault.PendingTracker().observe('client',point)

    def test_rejects_failure_or_cleanup_before_injection(self):
        for event in ({'status':'failed'},{'event':'failure_cleanup','role':'server'}):
            with self.subTest(event=event),self.assertRaises(ValueError):fault.PendingTracker().observe('server',event)


class FailureVerdicts(unittest.TestCase):
    codes={'client':1,'server':1}
    errors={'client':b'Error: Closed\n','server':b'Error: Transport\n'}

    def test_accepts_closed_or_transport_after_recorded_cut(self):
        self.assertIsNone(complete().validate(self.codes,self.errors))

    def test_rejects_successful_endpoint_or_missing_final(self):
        tracker=complete();tracker.finals['client']['status']='passed'
        with self.assertRaises(ValueError):tracker.validate(self.codes,self.errors)
        tracker=complete();del tracker.finals['server']
        with self.assertRaises(ValueError):tracker.validate(self.codes,self.errors)

    def test_rejects_timeout_authentication_or_ssh_error(self):
        for message in (b'Error: Deadline\n',b'Error: Authentication\n',b'Connection closed\n',b'Error: Closed\nError: Deadline\n'):
            errors=dict(self.errors,client=message)
            with self.subTest(message=message),self.assertRaises(ValueError):complete().validate(self.codes,errors)

    def test_rejects_remote_watchdog_or_controller_termination(self):
        for code in (0,124,137,-15):
            with self.subTest(code=code),self.assertRaises(ValueError):complete().validate(dict(self.codes,server=code),self.errors)

    def test_requires_drained_admission_and_closed_identity(self):
        for name,value in (('active',1),('pending',1),('drained',False),('auth_key_closed',False)):
            tracker=complete();tracker.cleanup[name]=value
            with self.subTest(field=name),self.assertRaises(ValueError):tracker.validate(self.codes,self.errors)

    def test_requires_zero_keys_and_completed_kem_handshake(self):
        for name,value in (('live_keys',1),('rejected_jobs',1),('executed_jobs',0)):
            tracker=complete();tracker.finals['client']['kem'][name]=value
            with self.subTest(field=name),self.assertRaises(ValueError):tracker.validate(self.codes,self.errors)


if __name__=='__main__':unittest.main()
