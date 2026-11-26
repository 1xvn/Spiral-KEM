"""Regression tests for the standalone OPT2 HRT experiment."""

from itertools import product
import unittest

from experiment_hrt import (
    CENTERS,
    MULTIPLIER,
    PAIRS,
    Q,
    CombinedHRTExperiment,
    HRTExperiment,
    decoder_table,
    observation_sets,
    paired_trials,
    project,
    verify_bound,
    verify_combined_bound,
)


class HRTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table, cls.decoder = decoder_table()
        cls.candidate = HRTExperiment(cls.table)

    def test_all_radius_six_observations_are_distinct_and_decode(self):
        check = verify_bound(self.table)
        self.assertEqual(check["observations_per_symbol"], [169] * 4)
        self.assertEqual(check["distinct_observations"], 676)

    def test_fixed_radius_seven_collision(self):
        self.assertEqual(project(3, -6), 2945)
        self.assertEqual(project(832 - 3, 7), 2945)
        observed = observation_sets(7)
        self.assertIn(2945, observed[0] & observed[1])
        self.assertEqual(self.table[2945], 0)

    def test_every_residue_against_independent_minimax(self):
        # Fix v modulo q. Its shortest lift and the corresponding shortest
        # lift of u are optimal for that v, so only q possible v need a check.
        half = Q // 2
        reference = [half] * Q
        for v in range(-half, half + 1):
            offset = MULTIPLIER * v
            absolute_v = abs(v)
            for residue, old in enumerate(reference):
                if absolute_v < old:
                    u = (residue - offset) % Q
                    absolute_u = min(u, Q - u)
                    reference[residue] = min(old, max(absolute_u, absolute_v))
        ties = 0
        for residue in range(Q):
            costs = [reference[(residue - center) % Q] for center in CENTERS]
            best = min(costs)
            ties += costs.count(best) > 1
            self.assertEqual(self.table[residue], costs.index(best), residue)
        self.assertEqual(ties, 197)
        self.assertEqual(self.decoder["tied_residues"], ties)

    def test_pairing_and_bit_order(self):
        for j, symbol in product((0, 7, 8, 127), range(4)):
            with self.subTest(j=j, symbol=symbol):
                bits = ((symbol & 1) << j) | ((symbol >> 1) << (j + PAIRS))
                message = bits.to_bytes(32, "little")
                encoded = self.candidate._encode_message(message)
                self.assertEqual(encoded[:PAIRS], (0,) * j + (CENTERS[symbol],) + (0,) * (PAIRS - j - 1))
                self.assertEqual(encoded[PAIRS:], (0,) * PAIRS)
                noisy = list(encoded)
                noisy[j] = (noisy[j] - 6) % Q
                noisy[j + PAIRS] = 6
                self.assertEqual(self.candidate._decode_message(tuple(noisy)), message)

    def test_paired_wire_and_full_message_metrics(self):
        result = paired_trials(3, self.candidate)
        self.assertEqual(result["distinct_baseline_candidate_ciphertexts"], 3)
        self.assertEqual(result["baseline"]["full_message_failures"], 0)
        # The fixed public fixtures contain enough honest noise to fail this candidate.
        self.assertEqual(result["hrt"]["full_message_failures"], 3)
        self.assertEqual(result["hrt"]["coefficient_pairs"], 384)
        self.assertEqual(result["hrt"]["coefficient_pairs_outside_radius_6"], 342)
        for codec in ("baseline", "hrt"):
            self.assertEqual(result[codec]["serialized_ciphertext_sizes_bytes"], {
                "skw1": {1160: 3}, "legacy": {1589: 3},
            })


class CombinedHRTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = CombinedHRTExperiment()

    def test_representatives_and_projection(self):
        expected = {(0, 0): (0, 0), (0, 1): (0, 1664),
                    (1, 0): (1664, 800), (1, 1): (1664, 2464)}
        for (a, b), pair in expected.items():
            with self.subTest(a=a, b=b):
                self.assertEqual(self.candidate.encode_pair(a, b), pair)
                self.assertEqual(project(*pair), 800 * b)
                self.assertEqual(self.candidate.decode_pair(*pair), (a, b))

    def test_full_message_bit_order_and_round_trip(self):
        message = bytes.fromhex("aa" * 16 + "cc" * 16)
        encoded = self.candidate._encode_message(message)
        self.assertEqual(encoded[:PAIRS], (0, 1664, 0, 1664) * 32)
        self.assertEqual(encoded[PAIRS:], (0, 800, 1664, 2464) * 32)
        self.assertEqual(self.candidate._decode_message(encoded), message)
        noisy = tuple((value + (-831 if j % 2 else 831)) % Q
                      for j, value in enumerate(encoded))
        self.assertEqual(self.candidate._decode_message(noisy), message)

    def test_all_coefficient_pair_errors_through_radius_831(self):
        report = verify_combined_bound(self.candidate)
        self.assertEqual(report["guaranteed_max_absolute_coefficient_error"], 831)
        self.assertEqual(report["coefficient_pair_error_cases_checked"], 11_062_276)
        self.assertEqual([row["error_cases_checked"] for row in report["symbols"].values()],
                         [2_765_569] * 4)

    def test_radius_832_boundary_collision(self):
        x0, y0 = self.candidate.encode_pair(0, 0)
        x1, y1 = self.candidate.encode_pair(0, 1)
        self.assertEqual((x0, (y0 + 832) % Q), (0, 832))
        self.assertEqual((x1, (y1 - 832) % Q), (0, 832))
        self.assertEqual(self.candidate.decode_pair(0, 832), (0, 0))

    def test_paired_wire_and_full_message_metrics(self):
        result = paired_trials(3, self.candidate)
        self.assertEqual(result["completed_comparisons"], 3)
        self.assertEqual(result["distinct_baseline_candidate_ciphertexts"], 3)
        self.assertEqual(result["wire_formats_decapsulated_per_encoding"], ["skw1", "legacy"])
        self.assertEqual(result["combined"]["coefficient_pairs_outside_radius_831"], 0)
        for codec in ("baseline", "combined"):
            metrics = result[codec]
            self.assertEqual(metrics["full_message_failures"], 0)
            self.assertEqual(metrics["shared_key_mismatches"], 0)
            self.assertEqual(metrics["max_absolute_coefficient_error"], 54)
            self.assertEqual(metrics["serialized_ciphertext_sizes_bytes"], {
                "skw1": {1160: 3}, "legacy": {1589: 3},
            })


if __name__ == "__main__":
    unittest.main()
