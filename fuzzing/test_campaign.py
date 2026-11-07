"""Supervisor evidence gates, tested without importing Atheris."""
import unittest

from fuzzing.campaign import classify, parse_feedback


class FeedbackTests(unittest.TestCase):
    def test_realistic_libfuzzer_progress_and_final_statistics(self):
        log = """INFO: Using entropic power schedule (0xFF, 100).
INFO: Seed: 20261107
INFO: Loaded 1 modules (256 inline 8-bit counters): 256 [0x1234, 0x1334),
INFO:       29 files found in /tmp/public-corpus
#30     INITED cov: 121 ft: 204 corp: 28/938b exec/s: 0 rss: 39Mb
#48     NEW    cov: 127 ft: 229 corp: 29/981b lim: 16384 exec/s: 0 rss: 39Mb L: 43/128 MS: 3 ChangeByte-CrossOver-EraseBytes-
#53     REDUCE cov: 127 ft: 229 corp: 29/976b lim: 16384 exec/s: 0 rss: 39Mb L: 38/128 MS: 5 ShuffleBytes-EraseBytes-CrossOver-ChangeByte-EraseBytes-
#78     NEW    cov: 130 ft: 242 corp: 30/1018b lim: 16384 exec/s: 0 rss: 39Mb L: 42/128 MS: 1 ChangeBinInt-
#2000   DONE   cov: 130 ft: 242 corp: 30/1018b lim: 16384 exec/s: 2000 rss: 39Mb
Done 2000 runs in 1 second(s)
stat::number_of_executed_units: 2000
stat::average_exec_per_sec:     2000
stat::new_units_added:         2
stat::slowest_unit_time_sec:   0
stat::peak_rss_mb:             39
"""
        self.assertEqual(parse_feedback(log), {
            "executed": 2000, "initial_cov": 121, "final_cov": 130,
            "final_features": 242, "new_corpus_events": 2, "initialization_executed": 30,
        })

    def test_last_execution_statistic_is_used(self):
        log = ("#1 INITED cov: 5 ft: 8\nstat::number_of_executed_units: 1\n"
               "#80 DONE cov: 7 ft: 12\nstat::number_of_executed_units: 80\n")
        self.assertEqual(parse_feedback(log)["executed"], 80)
        self.assertEqual(parse_feedback(log)["final_cov"], 7)
        self.assertEqual(parse_feedback(log)["initialization_executed"], 1)

    def test_missing_execution_statistic_is_not_invented_from_progress(self):
        feedback = parse_feedback("#999 DONE cov: 10 ft: 20 corp: 2/40b\n")
        self.assertIsNone(feedback["executed"])
        self.assertEqual(feedback["final_cov"], 10)
        self.assertIsNone(feedback["initialization_executed"])

    def test_missing_coverage_is_not_invented_from_final_statistics(self):
        feedback = parse_feedback("stat::number_of_executed_units: 999\n")
        self.assertEqual(feedback["executed"], 999)
        for field in ("initial_cov", "final_cov", "final_features", "initialization_executed"):
            self.assertIsNone(feedback[field])
        self.assertEqual(feedback["new_corpus_events"], 0)

    def test_empty_or_unrelated_log_has_no_feedback(self):
        for log in ("", "INFO: Atheris initialized\n", "coverage: 400 features: 700 runs: 999"):
            with self.subTest(log=log):
                self.assertEqual(parse_feedback(log), {
                    "executed": None, "initial_cov": None, "final_cov": None,
                    "final_features": None, "new_corpus_events": 0, "initialization_executed": None,
                })

    def test_missing_initialization_is_not_invented_from_mutation_or_done(self):
        feedback = parse_feedback(
            "#48 NEW cov: 121 ft: 204 corp: 42/32Kb exec/s: 0 rss: 40Mb\n"
            "#2000 DONE cov: 121 ft: 204 corp: 42/32Kb exec/s: 2000 rss: 40Mb\n"
            "stat::number_of_executed_units: 2000\n")
        self.assertIsNone(feedback["initialization_executed"])
        self.assertEqual(feedback["executed"], 2000)


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.feedback = {"executed": 2000, "initial_cov": 42, "final_cov": 42,
                         "final_features": 75, "new_corpus_events": 0, "initialization_executed": 43}
        self.metadata = {"instrumentation_count": 2,
                         "instrumented_runtime_functions": ["wire.parse_frame", "wire.parse_header"]}

    def test_stable_nonzero_coverage_passes_without_growth(self):
        passed, reason = classify(0, self.feedback, self.metadata)
        self.assertTrue(passed)
        self.assertIn("runtime feedback", reason)

    def test_child_failure_or_timeout_cannot_pass_with_positive_feedback(self):
        for code in (1, 2, -9, 77, None):
            with self.subTest(returncode=code):
                passed, reason = classify(code, self.feedback, self.metadata)
                self.assertFalse(passed)
                self.assertIn("child failed", reason)

    def test_missing_runtime_instrumentation_cannot_pass(self):
        cases = ({}, {"instrumentation_count": 2},
                 {"instrumented_runtime_functions": ["wire.parse_frame"]},
                 {**self.metadata, "instrumentation_count": 0},
                 {**self.metadata, "instrumentation_count": -1},
                 {**self.metadata, "instrumented_runtime_functions": []},
                 {**self.metadata, "instrumented_runtime_functions": None})
        for metadata in cases:
            with self.subTest(metadata=metadata):
                passed, reason = classify(0, self.feedback, metadata)
                self.assertFalse(passed)
                self.assertIn("missing runtime instrumentation", reason)

    def test_missing_or_zero_execution_coverage_or_features_cannot_pass(self):
        for field in ("executed", "final_cov", "final_features"):
            for value in (None, 0):
                with self.subTest(field=field, value=value):
                    feedback = {**self.feedback, field: value}
                    passed, reason = classify(0, feedback, self.metadata)
                    self.assertFalse(passed)
                    self.assertIn("no executed inputs or target coverage feedback", reason)
            with self.subTest(field=field, missing=True):
                feedback = {key: value for key, value in self.feedback.items() if key != field}
                self.assertFalse(classify(0, feedback, self.metadata)[0])

    def test_parse_and_classify_saturated_corpus_run(self):
        feedback = parse_feedback(
            "#43 INITED cov: 121 ft: 204 corp: 42/32Kb exec/s: 0 rss: 40Mb\n"
            "#2000 DONE cov: 121 ft: 204 corp: 42/32Kb exec/s: 2000 rss: 40Mb\n"
            "Done 2000 runs in 1 second(s)\nstat::number_of_executed_units: 2000\n")
        self.assertEqual(feedback["new_corpus_events"], 0)
        self.assertEqual(feedback["initialization_executed"], 43)
        self.assertTrue(classify(0, feedback, self.metadata)[0])

    def test_missing_or_zero_initialization_cannot_pass(self):
        cases = [{**self.feedback, "initialization_executed": value} for value in (None, 0)]
        cases.append({key: value for key, value in self.feedback.items() if key != "initialization_executed"})
        for feedback in cases:
            with self.subTest(feedback=feedback):
                passed, reason = classify(0, feedback, self.metadata)
                self.assertFalse(passed)
                self.assertEqual(reason, "no mutation executions after corpus initialization")

    def test_initialization_only_successful_child_cannot_pass(self):
        feedback = parse_feedback(
            "#202 INITED cov: 121 ft: 204 corp: 201/32Kb exec/s: 0 rss: 40Mb\n"
            "#202 DONE cov: 121 ft: 204 corp: 201/32Kb exec/s: 0 rss: 40Mb\n"
            "Done 202 runs in 0 second(s)\nstat::number_of_executed_units: 202\n")
        self.assertEqual(feedback["executed"], 202)
        self.assertEqual(feedback["initialization_executed"], 202)
        passed, reason = classify(0, feedback, self.metadata)
        self.assertFalse(passed)
        self.assertEqual(reason, "no mutation executions after corpus initialization")

    def test_execution_count_below_initialization_cannot_pass(self):
        feedback = {**self.feedback, "executed": 201, "initialization_executed": 202}
        self.assertFalse(classify(0, feedback, self.metadata)[0])


if __name__ == "__main__":
    unittest.main()
