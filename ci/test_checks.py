"""The CI gate must not confuse diagnostic completion with clean memory."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('memory_gate', ROOT / 'ci/check_memory_result.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class MemoryGateTests(unittest.TestCase):
    def setUp(self):
        self.real = json.loads((ROOT / 'protocol_rust/evidence/libtest_memory_20261107/result.json').read_text())

    def clean_fixture(self):
        value = copy.deepcopy(self.real)
        for case in value['cases']:
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


if __name__ == '__main__':
    unittest.main()
