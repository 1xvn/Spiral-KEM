"""Fail-closed scenario accounting and sanitizer/source provenance gates."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from protocol_rust.lifecycle.campaign import (
    ROOT,LOOP_IDS,TLS_IDS,compiled_test_binary,parse_cases,sources,validate_cases,
    validate_loop_log,validate_tls_result,verify_audit,
)


def tls_fixture(rounds=1):
    rows=[]
    delivered={'simultaneous_close':2,'cancelled_send':2,'cancelled_receive':1,
      'cancelled_close_resume':1,'dropped_session_sender':0,'concurrent_senders':16}
    for turn in range(rounds):
        for name in sorted(TLS_IDS):
            rows.append({'id':name,'round':turn,'status':'passed',
              'session_id':format(len(rows)+1,'032x'),'authenticated_pair':True,
              'matching_transcript_and_binding':True,'admission_released':True,
              'delivered':delivered[name],'cancelled_waiters':int(name in ('cancelled_send','cancelled_receive','cancelled_close_resume')),
              'clean_close':name!='dropped_session_sender'})
    summary={'status':'passed','auth_key_closed':True,'error':None,'case_count':6*rounds,
      'rounds':rounds,'seed':20261108,'kem':{'live_keys':0,'executed_jobs':18*rounds,'rejected_jobs':0}}
    return rows,summary


class ScenarioEvidence(unittest.TestCase):
    def test_required_ids_cannot_be_replaced_by_duplicates_or_other_rounds(self):
        rows=[{'id':name,'round':turn,'status':'passed'} for turn in range(2) for name in TLS_IDS]
        validate_cases(rows,TLS_IDS,2,True)
        for bad in (rows[:-1],rows+[rows[0]], [{**row,'round':0} for row in rows],
                    [{**row,'round':False} for row in rows], [{**row,'status':'failed'} for row in rows]):
            with self.assertRaises(ValueError):
                validate_cases(bad,TLS_IDS,2,True)

    def test_loop_stdout_needs_all_asserted_cases_and_no_ignored_tests(self):
        rows=[{'id':name,'status':'passed','subcases':3} for name in LOOP_IDS]
        log=''.join('test example ... LIFECYCLE_CASE '+json.dumps(row)+'\nok\n' for row in rows)
        ending='test result: ok. 8 passed; 0 failed; 0 ignored;\n'
        self.assertEqual(len(validate_loop_log(log+ending)),8)
        for changed in (log,log+ending.replace('0 ignored','1 ignored'),log+ending.replace('8 passed','7 passed')):
            with self.assertRaises(ValueError):
                validate_loop_log(changed)

    def test_observations_require_exact_json_and_reject_duplicate_fields(self):
        self.assertEqual(parse_cases('prefix LIFECYCLE_CASE {"id":"x"}','LIFECYCLE_CASE '),[{'id':'x'}])
        with self.assertRaises(ValueError):
            parse_cases('LIFECYCLE_CASE {"id":"x","id":"y"}','LIFECYCLE_CASE ')

    def test_tls_requires_authentication_delivery_cancel_and_cleanup_evidence(self):
        rows,summary=tls_fixture(2)
        validate_tls_result(rows,summary,2,20261108)
        for key,value in (('authenticated_pair',False),('matching_transcript_and_binding',False),
                          ('admission_released',False),('delivered',999),('cancelled_waiters',99),('session_id','0'*32)):
            changed=copy.deepcopy(rows); changed[0][key]=value
            with self.assertRaises(ValueError):
                validate_tls_result(changed,summary,2,20261108)

    def test_tls_reused_session_or_incomplete_native_cleanup_never_pass(self):
        rows,summary=tls_fixture()
        changed=copy.deepcopy(rows); changed[1]['session_id']=changed[0]['session_id']
        with self.assertRaises(ValueError):
            validate_tls_result(changed,summary,1,20261108)
        for key,value in (('live_keys',1),('executed_jobs',17),('rejected_jobs',1),('live_keys',False)):
            changed=copy.deepcopy(summary); changed['kem'][key]=value
            with self.assertRaises(ValueError):
                validate_tls_result(rows,changed,1,20261108)

    def test_nested_tests_and_all_peer_implementations_are_source_pinned(self):
        names=sources()
        for name in ('protocol_rust/src/channel/lifecycle_tests.rs','protocol_rust/examples/lifecycle_probe.rs',
                     'protocol_rust/lifecycle/rustc_audit.py','protocol_rust/lifecycle/tls_peer.py',
                     'protocol_v01/validation/independent_peer.py','code/opt2/spiral_kem_toy_v031_opt2.py'):
            self.assertIn(name,names)

    def test_test_executable_requires_cargo_artifact_inside_build(self):
        with tempfile.TemporaryDirectory() as folder:
            build=Path(folder); binary=build/'libtest'; binary.write_bytes(b'fixture')
            row={'reason':'compiler-artifact','profile':{'test':True},'target':{'name':'spiral_protocol'},'executable':str(binary)}
            self.assertEqual(compiled_test_binary(json.dumps(row),build),binary)
            for text in ('',json.dumps({**row,'executable':'/outside/libtest'}),json.dumps({**row,'profile':{'test':False}})):
                with self.assertRaises(ValueError):
                    compiled_test_binary(text,build)


def audited_compiles():
    rows=[]
    common=['--target','x86_64-unknown-linux-gnu','-Zsanitizer=address',
      '-Cdebuginfo=1','-Cforce-frame-pointers=yes','-Coverflow-checks=yes',
      '-Cdebug-assertions=yes','-Ccodegen-units=1','-Clto=off']
    for name,source,test in [('spiral_protocol','src/lib.rs',False),
       ('spiral_protocol','src/lib.rs',True),('lifecycle_probe','examples/lifecycle_probe.rs',False),
       ('spiral_lab','src/main.rs',False)]:
        rows.append({'rustc':'/tool/rustc','pid':1,'cwd':str(ROOT/'protocol_rust'),
          'args':['--crate-name',name,*common,source,*(['--test'] if test else [])]})
    return rows


class CompilerEvidence(unittest.TestCase):
    def check_rows(self,rows):
        with tempfile.TemporaryDirectory() as folder:
            trace=Path(folder)/'trace.jsonl'
            trace.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return verify_audit(trace,'/tool/rustc','x86_64-unknown-linux-gnu')

    def test_all_four_audited_compiles_are_required(self):
        rows=audited_compiles()
        self.assertEqual(self.check_rows(rows)['status'],'verified')
        with self.assertRaises(ValueError): self.check_rows(rows[:-1])
        with self.assertRaises(ValueError): self.check_rows(rows+[rows[0]])

    def test_sanitizer_overrides_and_driver_feedback_cannot_pass(self):
        for option in ('-Zsanitizer=memory','-Coverflow-checks=no','-Clto=thin','-Cpasses=sancov-module'):
            rows=audited_compiles(); rows[2]['args'].append(option)
            with self.assertRaises(ValueError): self.check_rows(rows)

    def test_source_compiler_and_target_substitution_are_rejected(self):
        for key,value in (('rustc','/other/rustc'),('cwd','/other')):
            rows=audited_compiles(); rows[0][key]=value
            with self.assertRaises(ValueError): self.check_rows(rows)
        rows=audited_compiles(); rows[0]['args']+=['--target','aarch64-unknown-linux-gnu']
        with self.assertRaises(ValueError): self.check_rows(rows)


if __name__=='__main__':
    unittest.main()
