"""Regression checks for the fixed-budget public research sampler."""

import gzip
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import key_weight as kw


class KeyWeightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "seeds.csv.gz"

    def test_fixed_budget_is_smallest_meeting_target(self):
        self.assertLessEqual(-math.expm1(math.log(0.05) / kw.DRAWS), 0.001)
        self.assertGreater(-math.expm1(math.log(0.05) / (kw.DRAWS - 1)), 0.001)

    def test_repeated_draws_count_and_replay(self):
        with patch.object(kw, "DRAWS", 3), patch.object(kw.secrets, "token_bytes", return_value=bytes(32)):
            kw.collect(self.path)
            report = kw.review(self.path)
            self.assertEqual(report["draws"], 3)
            self.assertEqual(report["minimum_weight"], report["maximum_weight"])
            self.assertEqual(report["event_count"], 0)
            with self.assertRaises(FileExistsError):
                kw.collect(self.path)

    def test_boundary_and_refusal_of_zero_event_limit_on_hit(self):
        with gzip.open(self.path, "wt") as f:
            f.write("sigma_hex,weight\n")
            f.write(f"{bytes(32).hex()},830\n")
            f.write(f"{bytes([1] * 32).hex()},831\n")
        with patch.object(kw, "DRAWS", 2), patch.object(kw, "reference_weight", side_effect=[830, 831]):
            report = kw.review(self.path)
        self.assertEqual(report["event_count"], 1)
        self.assertIsNone(report["one_sided_95_upper_if_zero"])

    def test_incomplete_and_changed_weight(self):
        with gzip.open(self.path, "wt") as f:
            f.write("sigma_hex,weight\n")
        with self.assertRaisesRegex(ValueError, "Expected"):
            kw.review(self.path)
        with gzip.open(self.path, "at") as f:
            f.write(f"{bytes(32).hex()},1025\n")
        with self.assertRaisesRegex(ValueError, "Weight mismatch"):
            kw.review(self.path)
