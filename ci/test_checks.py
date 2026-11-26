"""The CI gate must not confuse diagnostic completion with clean memory."""
import copy
import json
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MEMORY_EVIDENCE = ROOT / 'protocol_rust/evidence/libtest_memory_20261107'
sys.path.insert(0, str(ROOT / 'ci'))
import check_memory_result as gate
from evidence import completed, fresh_result, libtest_result, matching_hash, structured_result, unittest_result


class MemoryGateTests(unittest.TestCase):
    def setUp(self):
        self.real = json.loads((MEMORY_EVIDENCE / 'result.json').read_text())

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

    def write_clean_evidence(self, root):
        shutil.copytree(MEMORY_EVIDENCE, root, dirs_exist_ok=True)
        value = self.clean_fixture()
        for case in value['cases']:
            log = (b'==1== All heap blocks were freed -- no leaks are possible\n'
                   b'==1== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n')
            mem = case['memcheck']
            (root / mem['log_file']).write_bytes(log)
            mem['log_sha256'] = gate.sha(log)
            case.update(gate.parse_memcheck(log.decode()))
        return value

    def write_unattributed_warning(self, root):
        value = self.write_clean_evidence(root)
        case = next(row for row in value['cases'] if row['name'] == 'thread-current')
        mem = case['memcheck']
        original = (MEMORY_EVIDENCE / mem['log_file']).read_bytes()
        log = re.sub(rb'\b48 bytes\b', b'64 bytes', original).replace(b'596 bytes', b'612 bytes')
        (root / mem['log_file']).write_bytes(log)
        mem.update(exit=99, log_sha256=gate.sha(log))
        case.update(gate.parse_memcheck(log.decode()))
        legacy_error = 'unexpected Memcheck errors beyond the scoped runtime 48-byte signature'
        case.update(diagnostic_complete=False, errors=[legacy_error],
                    only_scoped_runtime_48_errors=False, memory_measurement_passed=False)
        value.update(diagnostic_complete=False, errors=[f'thread-current: {legacy_error}'])
        return value, case

    def review_evidence(self, root, value, verdict=None):
        result = root / 'result.json'
        verdict = verdict or root / 'review.json'
        result.write_text(json.dumps(value))
        command = [sys.executable, '-B', str(ROOT / 'ci/check_memory_result.py'),
                   str(result), '--verdict', str(verdict)]
        exit_code = subprocess.run(command, capture_output=True).returncode
        return exit_code, json.loads(verdict.read_text())

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
        self.assertEqual(gate.review(MEMORY_EVIDENCE / 'result.json')[:2], (False, 'diagnostic_warning'))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value = self.write_clean_evidence(root)
            status, verdict = self.review_evidence(root, value)
            self.assertEqual(status, 0)
            self.assertEqual(verdict['classification'], 'diagnostic_clean')
            first = value['cases'][0]['memcheck']
            raw_log = root/first['log_file']
            raw_log.write_bytes(raw_log.read_bytes()+b'failure after final summary\n')
            first['log_sha256'] = gate.sha(raw_log.read_bytes())
            status, verdict = self.review_evidence(root, value)
            self.assertEqual(status, 1)
            self.assertEqual(verdict['classification'], 'incomplete_or_tool_error')
            self.assertEqual(verdict['status'], 'failed')

    def test_complete_64_byte_warning_fails_without_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value, case = self.write_unattributed_warning(root)
            self.assertEqual(case['leaks']['possibly lost'], {'bytes': 64, 'blocks': 1})
            status, verdict = self.review_evidence(root, value)
            self.assertEqual(status, 1)
            self.assertEqual(verdict['status'], 'failed')
            self.assertEqual(verdict['classification'], 'diagnostic_warning')
            self.assertIn('attribution remains undetermined for thread-current', verdict['reason'])

    def test_contradictory_summary_fails_and_publishes_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory = root / 'memory'
            value = self.write_clean_evidence(memory)
            case = value['cases'][0]
            memcheck = case['memcheck']
            log = memory / memcheck['log_file']
            inconsistent = log.read_bytes().replace(b'0 errors from 0 contexts', b'0 errors from 1 contexts')
            log.write_bytes(inconsistent)
            memcheck['log_sha256'] = gate.sha(inconsistent)
            case['summary']['contexts'] = 1

            verdict_path = root / 'memory-review.json'
            status, verdict = self.review_evidence(memory, value, verdict_path)
            self.assertEqual(status, 1)
            self.assertEqual(verdict['status'], 'failed')
            self.assertEqual(verdict['classification'], 'incomplete_or_tool_error')
            self.assertIn('more contexts than errors', verdict['reason'])

            outcome = 'failure' if status else 'success'
            public = root / 'public'
            subprocess.run([sys.executable, '-B', str(ROOT / 'ci/public_receipt.py'),
                            'memory', outcome, str(root), str(public)],
                           cwd=ROOT, check=True, capture_output=True)
            receipt = json.loads((public / 'receipt.json').read_bytes())
            self.assertEqual(receipt['outcome'], 'failure')
            self.assertEqual(receipt['classification'], 'incomplete_or_tool_error')
            self.assertEqual(receipt['evidence_sha256'], {
                'memory/result.json': gate.sha((memory / 'result.json').read_bytes()),
                'memory-review.json': gate.sha(verdict_path.read_bytes()),
            })

    def test_warning_with_incomplete_evidence_is_not_a_diagnostic_warning(self):
        for failure in ('missing log', 'truncated log', 'missing summary', 'duplicate summary',
                        'hash mismatch', 'timeout', 'exit mismatch', 'missing case',
                        'duplicate case', 'additional producer error'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                value, case = self.write_unattributed_warning(root)
                mem = case['memcheck']
                log = root / mem['log_file']
                if failure == 'missing log':
                    log.unlink()
                elif failure == 'truncated log':
                    log.write_bytes(log.read_bytes()[:-1])
                    mem['log_sha256'] = gate.sha(log.read_bytes())
                elif failure == 'missing summary':
                    log.write_bytes(b''.join(log.read_bytes().splitlines(keepends=True)[:-1]))
                    mem['log_sha256'] = gate.sha(log.read_bytes())
                elif failure == 'duplicate summary':
                    raw = log.read_bytes()
                    log.write_bytes(raw + raw.splitlines(keepends=True)[-1])
                    mem['log_sha256'] = gate.sha(log.read_bytes())
                elif failure == 'hash mismatch':
                    mem['log_sha256'] = '0' * 64
                elif failure == 'timeout':
                    mem.update(exit=None, timed_out=True)
                elif failure == 'exit mismatch':
                    mem['exit'] = 0
                elif failure == 'missing case':
                    value['cases'].remove(case)
                elif failure == 'duplicate case':
                    value['cases'][-1] = copy.deepcopy(case)
                else:
                    case['errors'].append('additional tool failure')
                    value['errors'].append('thread-current: additional tool failure')
                status, verdict = self.review_evidence(root, value)
                self.assertEqual(status, 1)
                self.assertEqual(verdict['status'], 'failed')
                self.assertEqual(verdict['classification'], 'incomplete_or_tool_error')


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
