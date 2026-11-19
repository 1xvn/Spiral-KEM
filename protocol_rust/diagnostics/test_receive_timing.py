import csv
import tempfile
import unittest
from pathlib import Path

from receive_timing import COMPARISONS, DECISIONS, interpret, summarize


class ReceiveTimingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "samples.csv"
        self.rows = [[d, c, i, pos, "AB"[pos ^ (i % 2)], 100 + pos]
                     for d in DECISIONS for c in COMPARISONS for i in range(4) for pos in range(2)]

    def read(self):
        with self.path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["decision", "comparison", "pair", "position", "class", "ns"])
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
