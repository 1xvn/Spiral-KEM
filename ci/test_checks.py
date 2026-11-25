"""The CI gate must not confuse diagnostic completion with clean memory."""
import copy
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci'))
import check_memory_result as gate
from evidence import completed, fresh_result, libtest_result, matching_hash, structured_result, unittest_result


class MemoryGateTests(unittest.TestCase):
    def setUp(self):
        self.real = json.loads((ROOT / 'protocol_rust/evidence/libtest_memory_20261107/result.json').read_text())

    def clean_fixture(self):
        value = copy.deepcopy(self.real)
        value['runner_sha256'] = gate.sha(Path(gate.libtest_memory.__file__).read_bytes())
        for case in value['cases']:
            build = value['builds']['libtest' if case['name'].startswith('libtest-') else 'main']
            for mode in ('native', 'memcheck'):
                case[mode].update(binary_before=build['binary_sha256'], binary_after=build['binary_sha256'])
            case['errors'] = []
            case['memory_measurement_passed'] = True
            case['memcheck']['exit'] = 0
            case['summary']['errors'] = case['summary']['suppressed_errors'] = 0
            for kind in ['definitely lost','indirectly lost','possibly lost','suppressed']:
                case['leaks'][kind]['bytes'] = 0
        return value

    def test_synthetic_clean_controls_do_not_approve_production(self):
        value = self.clean_fixture()
        self.assertTrue(gate.check(value)[0])
        self.assertIs(value['production_memory_passed'], False)
        self.assertIs(value['original_finding_resolved'], False)

    def test_real_completed_diagnostic_still_fails_memory(self):
        self.assertTrue(self.real['diagnostic_complete'])
        self.assertFalse(gate.check(self.real)[0])

    def test_fake_success_flag_does_not_hide_child_99(self):
        value = self.clean_fixture()
        value['cases'][0]['memcheck']['exit'] = 99
        self.assertFalse(gate.check(value)[0])

    def test_missing_or_duplicate_case_fails(self):
        for edit in ['missing', 'duplicate']:
            value = self.clean_fixture()
            if edit == 'missing': value['cases'].pop()
            else: value['cases'].append(copy.deepcopy(value['cases'][0]))
            with self.subTest(edit=edit): self.assertFalse(gate.check(value)[0])

    def test_suppression_and_native_failure_fail(self):
        for edit in ['suppression','native','unexpected']:
            value = self.clean_fixture()
            if edit == 'suppression': value['cases'][0]['summary']['suppressed_errors'] = 1
            elif edit == 'native': value['cases'][0]['native']['exit'] = 1
            else: value['cases'][0]['errors'].append('unexpected')
            with self.subTest(edit=edit): self.assertFalse(gate.check(value)[0])

    def test_production_or_original_approval_rejected(self):
        for name in ['production_memory_passed','original_finding_resolved']:
            value = self.clean_fixture(); value[name] = True
            with self.subTest(name=name): self.assertFalse(gate.check(value)[0])

    def test_missing_json_cli_is_nonzero(self):
        done = subprocess.run([sys.executable, str(ROOT/'ci/check_memory_result.py'), str(ROOT/'ci/does-not-exist.json')], capture_output=True)
        self.assertNotEqual(done.returncode, 0)


    def test_original_warning_and_failed_recheck_replace_success(self):
        source = ROOT / 'protocol_rust/evidence/libtest_memory_20261107'
        self.assertEqual(gate.review(source/'result.json')[:2], (False, 'diagnostic_warning'))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(source, root, dirs_exist_ok=True)
            result = root/'result.json'
            verdict = root/'review.json'
            # Build a clean synthetic control using the original child streams
            # and a consistent clean Memcheck transcript for each case.
            value = self.clean_fixture()
            for case in value['cases']:
                log = b'==1== All heap blocks were freed -- no leaks are possible\n==1== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n'
                mem = case['memcheck']
                (root/mem['log_file']).write_bytes(log)
                mem['log_sha256'] = gate.sha(log)
                case.update(gate.parse_memcheck(log.decode()))
            result.write_text(json.dumps(value))
            command = [sys.executable, str(ROOT/'ci/check_memory_result.py'),
                       str(result), '--verdict', str(verdict)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(json.loads(verdict.read_text())['classification'], 'diagnostic_clean')
            first = value['cases'][0]['memcheck']
            raw_log = root/first['log_file']
            raw_log.write_bytes(raw_log.read_bytes()+b'failure after final summary\n')
            first['log_sha256'] = gate.sha(raw_log.read_bytes())
            result.write_text(json.dumps(value))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(json.loads(verdict.read_text())['classification'], 'incomplete_or_tool_error')
            self.assertEqual(json.loads(verdict.read_text())['status'], 'failed')


class TranscriptContracts(unittest.TestCase):
    python_log = (b'test_one (suite.C.test_one) ... ok\n'
                  b'test_two (suite.C.test_two) ... ok\n\n' + b'-'*70 +
                  b'\nRan 2 tests in 0.001s\n\nOK\n')
    rust_log = (b'\nrunning 2 tests\ntest case_a ... ok\ntest case_b ... ignored, probe only\n\n'
                b'test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n')

    def test_python_requires_complete_unique_executed_cases(self):
        self.assertEqual(unittest_result(self.python_log, 2), ['suite.C.test_one', 'suite.C.test_two'])
        for data in (b'', self.python_log[:-1], self.python_log+b'FAILED (errors=1)\n',
                     self.python_log.replace(b'test_two (suite.C.test_two) ... ok\n', b''),
                     self.python_log.replace(b'test_two', b'test_one'),
                     self.python_log.replace(b'... ok', b'... skipped reason'),
                     self.python_log.replace(b'Ran 2', b'Ran 0')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                unittest_result(data, 2)

    def test_rust_keeps_ignored_separate_and_requires_terminal_summary(self):
        self.assertEqual(libtest_result(self.rust_log, 1, 1)['passed'], 1)
        for data in (self.rust_log[:-1], self.rust_log+b'test result: FAILED\n',
                     self.rust_log.replace(b'test case_b ... ignored, probe only\n', b''),
                     self.rust_log.replace(b'case_b', b'case_a'),
                     self.rust_log.replace(b'1 passed', b'0 passed')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                libtest_result(data, 1, 1)
        with self.assertRaises(ValueError):
            libtest_result(self.rust_log, 2)

    def test_exit_timeout_source_or_binary_mismatch_and_stale_report(self):
        completed({'exit': 0})
        for record in ({'exit':None,'timeout':True}, {'exit':0,'timeout':True},
                       {'exit':0,'execution_error':'OSError'}, {'exit':False}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                completed(record)
        for label in ('source', 'binary'):
            with self.assertRaisesRegex(ValueError, label + ' hash mismatch'):
                matching_hash('original', 'changed', label)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'report.json'
            fresh_result(path)
            path.write_text('{"status":"passed"}')
            with self.assertRaisesRegex(ValueError, 'stale'):
                fresh_result(path)

    def test_structured_summary_matches_current_stdout_and_binary(self):
        data = {'tests': 2, 'failures': 0, 'errors': 0, 'skipped': 0,
                'status': 'passed', 'source_and_binary_unchanged': True, 'binary_sha256': 'a'}
        raw = json.dumps(data).encode()+b'\n'
        structured_result(raw, 2, 'a', raw, 'rust-key-recovery')
        for saved, stdout, digest in ((raw, raw+b'error\n', 'a'), (raw, b'', 'a'), (raw, raw, 'b')):
            with self.assertRaises(ValueError):
                structured_result(saved, 2, digest, stdout, 'rust-key-recovery')


if __name__ == '__main__':
    unittest.main()
