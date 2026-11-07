"""Records must retain production feedback while their independent model has none."""
import json
from pathlib import Path
import tempfile
import unittest

from protocol_rust.fuzzing import campaign, coverage_evidence as evidence
from protocol_rust.fuzzing.rustc_wrapper import instrument_args


def records_audit():
    rows = []
    for name in evidence.RECORD_CRATES:
        production = name == 'spiral_protocol'
        kind = 'lib' if production else 'bin'
        args, metadata = instrument_args([
            '--crate-name',name,'--crate-type',kind,'--emit=dep-info,metadata,link',
            '-Ccodegen-units=1','-Clto=off',
            '-Zsanitizer=address','-Cdebuginfo=1','-Cforce-frame-pointers=yes',
            '-Coverflow-checks=yes','-Cdebug-assertions=yes',
        ])
        rows.append({**metadata,'args':args,'rustc':'/toolchain/bin/rustc','pid':100})
    return rows


class RecordBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def read(self, rows):
        trace = self.root/'trace.jsonl'
        trace.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        return evidence._read_trace(trace,evidence.RECORD_PROFILE)

    def test_record_audit_requires_both_native_drivers_and_production(self):
        rows = records_audit()
        self.assertEqual(len(self.read(rows)),3)
        for index,name in enumerate(evidence.RECORD_CRATES):
            with self.subTest(missing=name):
                with self.assertRaisesRegex(ValueError,'missing compiler audit for '+name):
                    self.read(rows[:index]+rows[index+1:])

    def test_record_model_and_crypto_dependency_cannot_receive_feedback(self):
        for name in ('record_target','record_replay','ring'):
            with self.subTest(crate=name):
                rows = records_audit()
                if name == 'ring':
                    args, metadata = instrument_args(['--crate-name=ring','--crate-type=lib'])
                    row = {**metadata,'args':args,'rustc':'/toolchain/bin/rustc','pid':101}
                    rows.append(row)
                else:
                    row = next(row for row in rows if row['crate_name']==name)
                row['args'].append('-Cllvm-args=-sanitizer-coverage-trace-compares')
                with self.assertRaisesRegex(ValueError,'feedback instrumentation leaked'):
                    self.read(rows)

    def test_record_driver_must_emit_ir_but_has_no_feedback_flags(self):
        for name in evidence.RECORD_CRATES[1:]:
            args, metadata = instrument_args(['--crate-name='+name,'--crate-type=bin'])
            self.assertTrue(metadata['llvm_ir_enabled'])
            self.assertFalse(metadata['coverage_enabled'])
            self.assertIn('--emit=link,llvm-ir',args)
            self.assertFalse(any('sancov' in arg or 'sanitizer-coverage' in arg for arg in args))
        rows = records_audit()
        rows[1]['llvm_ir_enabled'] = False
        with self.assertRaisesRegex(ValueError,'LLVM IR decision audit mismatch'):
            self.read(rows)

    def test_wrong_profile_cannot_accept_a_records_only_audit(self):
        trace = self.root/'trace.jsonl'
        trace.write_text(''.join(json.dumps(row)+'\n' for row in records_audit()))
        with self.assertRaisesRegex(ValueError,'missing compiler audit for frame_target'):
            evidence._read_trace(trace)
        with self.assertRaisesRegex(ValueError,'unknown coverage suite'):
            evidence.profile_for('record')

    def test_each_audited_crate_requires_sanitizer_and_runtime_checks(self):
        for flag in ('-Zsanitizer=address','-Cdebuginfo=1','-Cforce-frame-pointers=yes',
                     '-Coverflow-checks=yes','-Cdebug-assertions=yes'):
            with self.subTest(missing=flag):
                rows = records_audit()
                rows[1]['args'].remove(flag)
                with self.assertRaises(ValueError):
                    self.read(rows)
        rows = records_audit()
        rows[1]['args'].append('-Coverflow-checks=no')
        with self.assertRaisesRegex(ValueError,'required overflow-checks is disabled'):
            self.read(rows)

    def test_model_tests_are_separate_and_must_actually_run(self):
        env = campaign.model_test_environment({
            'RUSTC_WRAPPER':'wrapper','RUSTC_WORKSPACE_WRAPPER':'other',
            'SPIRAL_RUSTC_TRACE':'trace','RUSTFLAGS':'asan',
            'CARGO_ENCODED_RUSTFLAGS':'asan','RUSTC':'pinned','PATH':'keep',
        })
        self.assertEqual(env,{'RUSTC':'pinned','PATH':'keep'})
        self.assertTrue(campaign.model_tests_completed('test result: ok. 7 passed; 0 failed;'))
        self.assertFalse(campaign.model_tests_completed('test result: ok. 0 passed; 0 failed;'))
        self.assertFalse(campaign.model_tests_completed('Finished test profile'))

    def test_nested_bridge_and_model_sources_are_captured(self):
        sources = campaign.source_names()
        self.assertIn('protocol_rust/fuzzing/campaign.py',sources)
        bridge = campaign.ROOT/'protocol_rust/src/records/fuzz_support.rs'
        if bridge.exists():
            self.assertIn('protocol_rust/src/records/fuzz_support.rs',sources)


class RecordIrTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)/'records.ll'

    def ir(self, *, omit=None, no_counter=None, no_trace=None):
        rows = ['@__sancov_gen_.0 = global i8 0, section "__sancov_cntrs"\n']
        for label,marker in evidence.RECORD_FUNCTION_MARKERS.items():
            if label == omit:
                continue
            rows.append('define void @_RNvCsTEST_15spiral_protocol'+marker+'() {\n')
            if label != no_counter:
                rows += ['  %a = load i8, ptr @__sancov_gen_.0\n',
                         '  store i8 %a, ptr @__sancov_gen_.0\n']
            if label != no_trace:
                rows.append('  call void @__sanitizer_cov_trace_const_cmp8(i64 1, i64 0)\n')
            rows.append('  ret void\n}\n')
        self.path.write_text(''.join(rows))

    def test_each_actual_record_operation_needs_its_own_counter_and_comparison(self):
        self.ir()
        info,bodies = evidence._inspect_ir(self.path,True,evidence.RECORD_PROFILE)
        self.assertEqual(set(info['functions']),set(evidence.RECORD_FUNCTION_MARKERS))
        self.assertEqual(len(bodies),6)
        for label in ('tx_data','tx_close','tx_encode','rx_decode'):
            with self.subTest(function=label):
                self.ir(no_counter=label)
                with self.assertRaisesRegex(ValueError,'no inline counter access in '+label):
                    evidence._inspect_ir(self.path,True,evidence.RECORD_PROFILE)
                self.ir(no_trace=label)
                with self.assertRaisesRegex(ValueError,'no comparison tracing in '+label):
                    evidence._inspect_ir(self.path,True,evidence.RECORD_PROFILE)

    def test_missing_rx_cannot_be_replaced_by_global_feedback(self):
        self.ir(omit='rx_decode')
        with self.assertRaisesRegex(ValueError,'missing production protocol function definitions'):
            evidence._inspect_ir(self.path,True,evidence.RECORD_PROFILE)

    def test_inline_evidence_needs_exact_child_parent_source_and_callback(self):
        text = ('_wire():\n/workspace/protocol_rust/src/wire.rs:90\n'
                ' (inlined by) _rx()\n  call __sanitizer_cov_trace_const_cmp8\n')
        self.assertTrue(evidence._inline_function_evidence(text,'_wire','_rx','wire.rs'))
        for wrong in (text.replace('_wire','_other'),text.replace('_rx','_other'),
                      text.replace('wire.rs','records.rs'),text.replace('__sanitizer_cov_trace_','unrelated_')):
            self.assertFalse(evidence._inline_function_evidence(wrong,'_wire','_rx','wire.rs'))


if __name__ == '__main__':
    unittest.main()
