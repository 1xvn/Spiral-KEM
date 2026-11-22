"""Independent small-ring, decoder and source checks for the failure calculation."""

import itertools
import math
import unittest
from collections import Counter
from fractions import Fraction
from hashlib import shake_256
from unittest.mock import patch

from recheck_failure import coefficient_counts, decoded, failure_counts
from spiral_kem_toy_v031_opt2 import SpiralKEM


def mul2(a, b):
    return a[0] * b[0] - a[1] * b[1], a[0] * b[1] + a[1] * b[0]


def q5bit(value):
    return int(value % 5 in (2, 3))


class FailureRecheck(unittest.TestCase):
    def test_exhaustive_toy_exchange(self):
        # n=2,k=1,q=5. Enumerate all five CBD1 polynomial inputs.
        # Each zero has two preimages among (0,0),(0,1),(1,0),(1,1).
        single = Counter(a - b for a, b in itertools.product(range(2), repeat=2))
        polys = [(p, single[p[0]] * single[p[1]]) for p in itertools.product(single, repeat=2)]
        matrix = (1, 2)
        marginals = [Counter(), Counter()]
        messages = list(itertools.product((0, 1), repeat=2))
        any_failure = Counter()
        for fields in itertools.product(polys, repeat=5):
            (s, e, r, e1, e2), weights = zip(*fields)
            weight = math.prod(weights)
            t = tuple((x + y) % 5 for x, y in zip(mul2(matrix, s), e))
            u = tuple((x + y) % 5 for x, y in zip(mul2(matrix, r), e1))
            tr, su = mul2(t, r), mul2(s, u)
            error = tuple(x - y + z for x, y, z in zip(mul2(e, r), mul2(s, e1), e2))
            for i in range(2):
                self.assertEqual((tr[i] + e2[i] - su[i]) % 5, error[i] % 5)
                self.assertLessEqual(abs(error[i]), 1 + sum(v != 0 for v in (*s, *e)))
                marginals[i][error[i]] += weight
            for message in messages:
                v = [(tr[i] + e2[i] + 2 * message[i]) % 5 for i in range(2)]
                if any(q5bit(v[i] - su[i]) != message[i] for i in range(2)):
                    any_failure[message] += weight
        counts = coefficient_counts(2, 1)
        total = 4**10
        self.assertEqual(len(counts), 11)
        for marginal in marginals:
            self.assertEqual(sum(marginal.values()), total)
            for index, count in enumerate(counts):
                self.assertEqual(marginal[index - 5] * sum(counts), count * total)
        per_bit = failure_counts(counts, 5)
        for bit in (0, 1):
            direct = sum(w for error, w in marginals[0].items() if q5bit(2 * bit + error) != bit)
            self.assertEqual(Fraction(direct, total), Fraction(per_bit[bit], sum(counts)))
        for msg in messages:
            upper = Fraction(sum(per_bit[b] for b in msg), sum(counts))
            self.assertGreater(any_failure[msg], 0)
            self.assertLessEqual(Fraction(any_failure[msg], total), upper)
        p1 = Fraction(per_bit[1], sum(counts))
        self.assertNotEqual(Fraction(any_failure[(1, 1)], total), 1 - (1 - p1)**2)

    def test_published_default_distribution(self):
        counts = coefficient_counts(256, 2)
        self.assertEqual(sum(counts), 1 << 3074)
        # The old DP implementation and the analytic quadratic recurrence use
        # different coefficient algorithms. Freeze the published precision here.
        p0, p1 = failure_counts(counts, 3329)
        self.assertAlmostEqual(math.log2(p0) - 3074, -1866.830888201881, places=8)
        self.assertAlmostEqual(math.log2(p1) - 3074, -1863.062786892389, places=8)
        self.assertAlmostEqual(math.log2(256 * max(p0, p1)) - 3074, -1855.0628, places=4)

    def test_default_decoder_every_residue_and_encoding_bit_order(self):
        kem = SpiralKEM()
        n, q = kem.p.n, kem.p.q
        for start in range(0, q, n):
            values = tuple(range(start, start + n))
            bits = kem._decode_message(values)
            for i, value in enumerate(values):
                self.assertEqual((bits[i // 8] >> (i % 8)) & 1, decoded(value, q))
        message = bytes(range(32))
        self.assertEqual(kem._encode_message(message), tuple(
            1664 * ((message[i // 8] >> (i % 8)) & 1) for i in range(n)
        ))
        for bit, lo, hi in ((0, -832, 832), (1, -831, 832)):
            for err in range(-1025, 1026):
                self.assertEqual(decoded(1664 * bit + err, q) == bit, lo <= err <= hi)

    def test_default_source_cancellation(self):
        kem = SpiralKEM()
        n, q = kem.p.n, kem.p.q
        rho, sigma, z, message = (bytes([i]) * 32 for i in range(4))
        with patch("spiral_kem_toy_v031_opt2.secrets.token_bytes", side_effect=[rho, sigma, z, message]):
            pk, sk = kem.keygen()
            ct, _ = kem.encapsulate(pk)
        # Reconstruct the framed SHAKE byte pairs independently of the production sampler.
        context = b"Spiral-KEM-v0.3/research-only/" + b"".join(
            p.to_bytes(4, "little") for p in (256, 2, 3329, 1, 32)
        )

        def xof(label, payload, length):
            return shake_256(context + len(label).to_bytes(2, "little") + label + payload).digest(length)

        def small(label, seed):
            stream = xof(b"small/" + label, seed, 2 * n)
            return [(a % 2) - (b % 2) for a, b in zip(stream[::2], stream[1::2])]

        def vector(label, seed):
            return [small(label + b"/" + i.to_bytes(2, "little"), seed) for i in range(2)]

        coins = xof(b"coins/", message + kem._public_key_hash(pk), 32)
        s, e = vector(b"key/s", sigma), vector(b"key/e", sigma)
        r, e1, e2 = vector(b"enc/r", coins), vector(b"enc/e1", coins), small(b"enc/e2", coins)
        self.assertEqual(sk.s, tuple(tuple(x % q for x in p) for p in s))
        error = e2.copy()
        for left_vec, right_vec, sign in ((e, r, 1), (s, e1, -1)):
            for left, right in zip(left_vec, right_vec, strict=True):
                for i, a in enumerate(left):
                    for j, b in enumerate(right):
                        degree = i + j
                        error[degree % n] += sign * (1 if degree < n else -1) * a * b
        aligned = kem._poly_sub(ct.v, kem._dot(sk.s, ct.u))
        expected = tuple((x + y) % q for x, y in zip(kem._encode_message(message), error))
        self.assertEqual(aligned, expected)
        self.assertEqual(kem.deserialize_ciphertext_compact(kem.serialize_ciphertext_compact(ct)), ct)


if __name__ == "__main__":
    unittest.main()
