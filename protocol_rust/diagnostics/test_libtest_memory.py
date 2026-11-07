"""Regression checks for diagnostic interpretation, not production memory tests."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("libtest_memory_runner", Path(__file__).with_name("libtest_memory.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class DiagnosticTests(unittest.TestCase):
    def log(self, name):
        return (ROOT / "protocol_rust/evidence/libtest_memory_20261107" / name).read_text()

    def test_original_runtime_warning_classified_with_stack(self):
        log = (ROOT / "protocol_rust/evidence/v03/taint/rust-secret-path.log").read_text()
        value = runner.parse_memcheck(log)
        self.assertEqual(value["leaks"]["possibly lost"]["bytes"], 48)
        self.assertEqual(value["summary"]["errors"], 1)
        self.assertEqual(value["possibly_lost_48_records"][0]["classification"], "std_thread_and_libtest")

    def test_new_empty_main_is_clean_but_reachable_is_retained(self):
        value = runner.parse_memcheck(self.log("empty-main-memcheck.log"))
        self.assertEqual(value["summary"]["errors"], 0)
        self.assertEqual(value["leaks"]["possibly lost"]["bytes"], 0)
        self.assertEqual(value["leaks"]["still reachable"]["bytes"], 548)

    def test_missing_and_duplicate_summaries_rejected(self):
        log = self.log("libtest-default-memcheck.log")
        for value in [log.split("ERROR SUMMARY:")[0], log + log]:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                runner.parse_memcheck(value)

    def test_zero_tests_does_not_count_as_valid_control(self):
        self.assertFalse(runner.output_is_expected({"stdout": "running 0 tests\ntest result: ok. 0 passed\n", "stderr": ""}, None))

    def test_exactly_one_completed_test_is_required(self):
        output = (ROOT / "protocol_rust/evidence/libtest_memory_20261107/libtest-default-native.stdout").read_text()
        self.assertTrue(runner.output_is_expected({"stdout": output, "stderr": ""}, None))
        self.assertFalse(runner.output_is_expected({"stdout": output, "stderr": "unexpected"}, None))

    def test_known_native_output_is_exact(self):
        self.assertTrue(runner.output_is_expected({"stdout": "CONTROL_COMPLETED empty-main\n", "stderr": ""}, "empty-main"))
        self.assertFalse(runner.output_is_expected({"stdout": "CONTROL_COMPLETED other\n", "stderr": ""}, "empty-main"))


if __name__ == "__main__":
    unittest.main()
