"""Interpretation gates for public thread ownership controls, not memory approval."""
import copy
from pathlib import Path
import unittest

from protocol_rust.diagnostics import thread_ownership as runner


ROOT = Path(__file__).resolve().parents[2]


class OwnershipGates(unittest.TestCase):
    def known_log(self):
        return (ROOT / "protocol_rust/evidence/libtest_memory_20261107/thread-current-memcheck.log").read_text()

    def clean_log(self):
        return (ROOT / "protocol_rust/evidence/libtest_memory_20261107/empty-main-memcheck.log").read_text()

    def test_original_exact_std_allocation_is_diagnostic_not_memory_pass(self):
        result = runner.classify_measurement(self.known_log(), 99)
        self.assertEqual(result["scoped_thread_48_blocks"], 1)
        self.assertFalse(result["memory_measurement_passed"])
        self.assertEqual(result["summary"]["errors"], 1)

    def test_clean_measurement_retains_reachable_bytes(self):
        result = runner.classify_measurement(self.clean_log(), 0)
        self.assertTrue(result["memory_measurement_passed"])
        self.assertEqual(result["leaks"]["still reachable"]["bytes"], 548)

    def test_missing_stack_extra_errors_suppression_or_wrong_exit_rejected(self):
        text = self.known_log()
        for changed, code in (
            (text.replace("std::thread::current::init_current", "other_allocation"), 99),
            (text.replace("ArcInner", "other_owner"), 99),
            (text.replace("1 errors from 1 contexts", "2 errors from 2 contexts"), 99),
            (text.replace("suppressed: 0 from 0", "suppressed: 1 from 1"), 99),
            (text + "\nInvalid read of size 1\n", 99),
            (text, 0),
            (text.split("ERROR SUMMARY:")[0], 99),
        ):
            with self.subTest(code=code), self.assertRaises(ValueError):
                runner.classify_measurement(changed, code)

    def test_control_completion_requires_exact_output_and_no_process_timeout(self):
        good = {"exit": 99, "timed_out": False, "stdout": "CONTROL_COMPLETED current-once\n", "stderr": ""}
        self.assertTrue(runner.expected_output(good, "current-once"))
        for changed in ({**good, "timed_out": True}, {**good, "exit": None},
                        {**good, "stdout": ""}, {**good, "stderr": "unexpected"}):
            self.assertFalse(runner.expected_output(changed, "current-once"))

    def test_native_link_arguments_are_one_pure_library_list(self):
        self.assertEqual(runner.native_libraries("note: native-static-libs: -lgcc_s -lpthread -lm -ldl -lc\n"),
                         ["-lgcc_s", "-lpthread", "-lm", "-ldl", "-lc"])
        for text in ("", "native-static-libs: -lpthread\nnative-static-libs: -lm\n",
                     "native-static-libs: -lpthread -Wl,other\n", "native-static-libs: -lpthread $(command)\n"):
            with self.assertRaises(ValueError):
                runner.native_libraries(text)

    def test_lifetime_pattern_is_observed_and_never_production_approval(self):
        cases = [{"name": name, "scoped_thread_48_blocks": int(name in
                 ("current-once", "current-many", "foreign-touch-return"))} for name in runner.CASE_NAMES]
        result = runner.compare_lifetimes(cases)
        self.assertEqual(result["classification"], "supports_thread_local_ownership_and_exit_lifetime")
        self.assertFalse(result["production_memory_passed"])
        self.assertFalse(result["original_finding_resolved"])
        changed = copy.deepcopy(cases)
        changed[-1]["scoped_thread_48_blocks"] = 1
        self.assertEqual(runner.compare_lifetimes(changed)["classification"], "different_or_partial_pattern")
        for row in changed:
            row["scoped_thread_48_blocks"] = 0
        self.assertEqual(runner.compare_lifetimes(changed)["classification"], "not_reproduced")

    def test_lifetime_comparison_cannot_omit_or_duplicate_a_control(self):
        rows = [{"name": name, "scoped_thread_48_blocks": 0} for name in runner.CASE_NAMES]
        for changed in (rows[:-1], rows + [rows[0]], [rows[0]] * 10):
            with self.assertRaises(ValueError):
                runner.compare_lifetimes(changed)


if __name__ == "__main__":
    unittest.main()
