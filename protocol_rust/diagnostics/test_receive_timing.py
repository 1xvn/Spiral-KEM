import csv
import json
import tempfile
import unittest
from pathlib import Path

from receive_timing import COMPARISONS, CPU_FIELD, DECISIONS, SAMPLE_FIELDS, interpret, summarize, summarize_schedstat


class ReceiveTimingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "samples.csv"
        self.rows = [[d, c, i, pos, "AB"[pos ^ (i % 2)], 100 + pos]
                     for d in DECISIONS for c in COMPARISONS for i in range(4) for pos in range(2)]

    def read(self, with_cpu=False):
        with self.path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(SAMPLE_FIELDS + ([CPU_FIELD] if with_cpu else []))
            writer.writerows(self.rows)
        return summarize(self.path, pairs=4)

    def test_pairing_uses_class_not_position(self):
        summary = self.read()["reject"]["key"]
        self.assertEqual((summary["pairs"], summary["paired_t"]), (4, 0))

    def test_incomplete_duplicate_and_unbalanced_data(self):
        orig = self.rows
        for rows in (orig[:-1], orig + orig[:1], [orig[0], [*orig[1][:3], 0, *orig[1][4:]], *orig[2:]]):
            self.rows = rows
            with self.assertRaises(ValueError):
                self.read()

    def test_scheduler_columns_preserve_wall_statistics_and_raw_gaps(self):
        baseline = self.read()
        self.rows = [r + [None if r[2] == 0 else 120] for r in self.rows]
        measured = self.read(with_cpu=True)
        for decision in DECISIONS:
            for comparison in COMPARISONS:
                data = measured[decision][comparison]
                diagnostic = data.pop("scheduler_observations")
                self.assertEqual(data, baseline[decision][comparison])
                self.assertEqual(diagnostic["thread_cpu_missing"], 2)
                self.assertEqual(diagnostic["thread_cpu_samples"], 6)
                self.assertLess(diagnostic["median_wall_minus_thread_cpu_ns"], 0)
                self.assertIsNone(diagnostic["largest_abs_wall_deltas"][0]["A"][CPU_FIELD])
        self.rows[0][-1] = -1
        with self.assertRaises(ValueError):
            self.read(with_cpu=True)

    def test_schedstat_unavailable_zero_and_regressed(self):
        rows = [
            {"decision": d, "comparison": c, "before": [100, 10, 1], "after": [200, 10, 3]}
            for d in DECISIONS for c in COMPARISONS
        ]
        rows[0]["before"] = None
        rows[1]["after"] = [50, 9, 0]
        rows[3]["after"][1] += 111
        self.path.write_text(json.dumps({"schedstats_enabled": None, "streams": rows}))
        data = summarize_schedstat(self.path)["streams"]
        self.assertEqual(data["accept"]["positive"], {"status": "unavailable", "delta": None})
        self.assertEqual(data["accept"]["sham"]["status"], "counter_regressed")
        self.assertEqual(data["accept"]["key"]["status"], "zero_wait_reported")
        self.assertEqual(data["reject"]["positive"]["delta"]["runqueue_wait_ns"], 111)
        self.path.write_text(json.dumps({"schedstats_enabled": False, "streams": rows}))
        self.assertEqual(summarize_schedstat(self.path)["streams"]["reject"]["positive"]["status"], "disabled")

    def test_failed_controls_and_non_replicating_signals(self):
        def trial(positive=6, sham=0, key=0):
            return {"accept": {k: {"paired_t": t} for k, t in zip(COMPARISONS, (positive, sham, key))}}
        for args, expected in [
            ([trial(), trial()], "no_threshold_crossing_in_sample"),
            ([trial(key=6), trial(key=8)], "repeatable_threshold_crossing"),
            ([trial(key=-6), trial(key=8)], "inconsistent_threshold_crossing"),
            ([trial(key=-6), trial()], "inconsistent_threshold_crossing"),
            ([trial(), trial(sham=5)], "inconclusive_controls_or_variance"),
            ([trial(positive=1), trial()], "inconclusive_controls_or_variance"),
            ([trial(key=None), trial()], "inconclusive_controls_or_variance"),
        ]:
            self.assertEqual(interpret(args, "accept"), expected)
