"""Fail-closed evidence parsing for raw Rx traces; no constant-time verdict."""
from pathlib import Path
import unittest

from protocol_rust.diagnostics import receive_flow as runner

ROOT=Path(__file__).resolve().parents[2]


class ReceiveFlowGates(unittest.TestCase):
    def known_log(self):
        return (ROOT/'protocol_rust/evidence/secret_memory_20261108/wipe/memcheck.log').read_text()

    def warning(self,kind='conditional',top='decrypt_in_place_detached (src/cipher.rs:87)'):
        return {'kind':kind,'stack':['==12== at 0x1010: '+top], 'runtime_ip':0x1010}

    def test_fixture_matrix_covers_roles_lengths_and_all_tag_positions(self):
        cases=runner.variants()
        self.assertEqual(len(cases),78)
        self.assertEqual(len({tuple(row.values()) for row in cases}),78)
        for role in (0,1):
            selected=[row for row in cases if row['role']==role]
            self.assertEqual(len(selected),39)
            for mode in ('data-valid','data-bad-tag','data-bad-header'):
                self.assertEqual({r['length'] for r in selected if r['mode']==mode},set(runner.LENGTHS))
            self.assertEqual({r['tag_index'] for r in selected if r['mode']=='data-bad-tag' and r['length']==65},set(range(16)))
            self.assertEqual({r['reason'] for r in selected if r['mode']=='close-invalid-reason'},{3,255})

    def test_original_warning_and_exit_are_retained(self):
        parsed,warnings=runner.inspect_log(self.known_log(),99)
        self.assertEqual(parsed['leaks']['possibly lost']['bytes'],48)
        self.assertEqual(parsed['summary']['errors'],1)
        self.assertEqual(warnings,[])
        with self.assertRaises(ValueError):runner.inspect_log(self.known_log(),0)

    def test_partial_extra_and_suppressed_diagnostics_rejected(self):
        text=self.known_log()
        for changed in (
            text.split('ERROR SUMMARY:')[0],
            text.replace('1 errors from 1 contexts','2 errors from 2 contexts'),
            text.replace('1 errors from 1 contexts','0 errors from 1 contexts'),
            text.replace('suppressed: 0 from 0','suppressed: 1 from 1'),
            text.replace('std::thread::current::init_current','other_owner'),
            text.replace('ArcInner','other_owner'),
            text+'\nInvalid read of size 1\n',
            text.replace('possibly lost: 48 bytes','possibly lost: 96 bytes'),
        ):
            with self.subTest(change=changed[-120:]),self.assertRaises(ValueError):runner.inspect_log(changed,99)

    def test_branch_and_address_records_keep_full_stack(self):
        text=('==12== Conditional jump or move depends on uninitialised value(s)\n'
          '==12== at 0x1010: decrypt_in_place_detached (src/cipher.rs:87)\n'
          '==12== by 0x2020: Rx::decode (records.rs:209)\n==12== \n'
          '==12== Use of uninitialised value of size 8\n'
          '==12== at 0x3030: positive_secret_address (receive_audit.rs:260)\n==12== \n')
        records=runner.branch_records(text)
        self.assertEqual([r['kind'] for r in records],['conditional','undefined_value_or_address'])
        self.assertEqual(len(records[0]['stack']),2)
        self.assertEqual(records[1]['runtime_ip'],0x3030)
        with self.assertRaises(ValueError):runner.branch_records('Conditional jump or move depends\n\n')

    def test_classification_requires_exact_linked_conditional_instruction(self):
        instructions=runner.linked_instructions('  10: 75 03 jne 15 <target>\n  12: 0f b6 04 07 movzbl (%rdi,%rax,1),%eax\n')
        self.assertEqual(runner.annotate(self.warning(),0x1000,instructions)['classification'],'authentication_decision_candidate')
        address=self.warning(kind='undefined_value_or_address');address['runtime_ip']=0x1012
        mapped=runner.annotate(address,0x1000,instructions)
        self.assertTrue(mapped['instruction_mapped'])
        self.assertFalse(mapped['conditional_instruction_verified'])
        self.assertEqual(mapped['classification'],'unclassified')
        for bias,table,row in ((None,instructions,self.warning()),(0x2000,instructions,self.warning()),
          (0x1000,{0x10:'jmp 15'},self.warning()),(0x1000,instructions,self.warning(kind='undefined_value_or_address')),
          (0x1000,instructions,self.warning(top='Rx::decode (records.rs:209)'))):
            self.assertEqual(runner.annotate(row,bias,table)['classification'],'unclassified')

    def test_authentication_propagation_requires_inline_callsite(self):
        row=self.warning(top='map_err<(), aead::Error> (library/core/src/result.rs:965)')
        self.assertEqual(runner.category(row,True),'unclassified')
        row['stack'].append('==12== by 0x1010: closure (records.rs:215)')
        self.assertEqual(runner.category(row,True),'authentication_result_propagation_candidate')
        row['stack'][-1]='==12== by 0x1010: closure (records.rs:209)'
        self.assertEqual(runner.category(row,True),'unclassified')
        self.assertEqual(runner.category(self.warning(top='closure (records.rs:216)'),True),'close_reason_validity_candidate')

    def test_completion_cannot_be_a_missing_ignored_or_zero_test(self):
        marker='RX_AUDIT_COMPLETED data-valid role=0 length=65 reason=0 tag_index=15 taint=secret'
        text='running 1 test\n'+marker+'\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        self.assertTrue(runner.completed(text,marker))
        for changed in (text.replace(marker,''),text.replace('1 passed','0 passed'),
          text.replace('0 ignored','1 ignored'),text.replace('running 1 test','running 0 tests')):
            self.assertFalse(runner.completed(changed,marker))


if __name__=='__main__':unittest.main()
