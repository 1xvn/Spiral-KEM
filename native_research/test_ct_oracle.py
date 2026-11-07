"""Checks of the independent CT framing oracle and pinned OPT2 reference."""

from __future__ import annotations

import copy
import json
import random
import re
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from native_research import ct_oracle


def set_coefficient(data, index, value):
    """Test-side byte/nibble encoding, independent of the oracle's bit packing."""
    changed = bytearray(data)
    offset = 8 + 3 * (index // 2)
    if index % 2:
        changed[offset + 1] = (changed[offset + 1] & 15) | ((value & 15) << 4)
        changed[offset + 2] = value >> 4
    else:
        changed[offset] = value & 255
        changed[offset + 1] = (changed[offset + 1] & 240) | (value >> 8)
    return bytes(changed)


class FixtureTests(unittest.TestCase):
    def test_fixture_uses_existing_public_vector(self):
        original = json.loads(ct_oracle.FIXTURE_SOURCE.read_text())
        vector = ct_oracle.fixture()
        self.assertIn("public test fixtures", original["notice"])
        self.assertEqual(original["kem_source_sha256"], ct_oracle.REFERENCE_SHA256)
        expected_seeds = b"".join(bytes.fromhex(original["inputs"]["kem_test_seeds"][name])
                                  for name in ("matrix", "secret", "fallback"))
        self.assertEqual(vector["seeds"], expected_seeds)
        self.assertEqual({name: len(value) for name, value in vector.items()},
                         {"seeds": 96, "pk": 808, "ct": 1160, "ss": 32, "message": 32})
        self.assertEqual(vector["pk"].hex(), original["public"]["kem_public_key_skw1"])
        self.assertEqual(vector["ct"].hex(), original["public"]["kem_ciphertext_skw1"])
        self.assertEqual(vector["ss"].hex(), original["expected"]["shared_secret"])
        self.assertEqual(vector["message"].hex(), original["inputs"]["kem_test_seeds"]["message"])

    def test_header_contains_exactly_the_four_public_arrays(self):
        header = ct_oracle.render_header()
        arrays = re.findall(r"static const uint8_t (FIXTURE_\w+)\[(\d+)\] = \{(.*?)\};",
                            header, re.DOTALL)
        self.assertEqual([name for name, _, _ in arrays],
                         ["FIXTURE_SEEDS", "FIXTURE_PK", "FIXTURE_CT", "FIXTURE_SS"])
        vector = ct_oracle.fixture()
        for name, length, body in arrays:
            with self.subTest(array=name):
                data = bytes(int(byte, 16) for byte in re.findall(r"0x([0-9a-f]{2})", body))
                self.assertEqual(data, vector[name.removeprefix("FIXTURE_").lower()])
                self.assertEqual(len(data), int(length))
        self.assertIn("#ifndef SPIRAL_CT_FIXTURE_H", header)
        self.assertIn("#include <stdint.h>", header)

    def test_generation_and_reference_work_without_site_packages(self):
        script = """
import sys
from native_research.ct_oracle import fixture, canonical, seed_inputs, render_header, Reference
assert not any(name.startswith('cryptography') for name in sys.modules)
assert 'protocol_v01.handshake' not in sys.modules
assert canonical(fixture()['ct'])
assert seed_inputs() and render_header()
reference = Reference()
assert reference.expected(fixture()['ct'])['ss'] == fixture()['ss']
assert not any(name.startswith('cryptography') for name in sys.modules)
assert 'protocol_v01.handshake' not in sys.modules
"""
        done = subprocess.run([sys.executable, "-S", "-c", script], cwd=ct_oracle.ROOT,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


class CanonicalTests(unittest.TestCase):
    def setUp(self):
        self.golden = ct_oracle.fixture()["ct"]

    def test_exact_type_length_and_every_prefix_byte(self):
        self.assertTrue(ct_oracle.canonical(self.golden))
        for data in (None, "", bytearray(self.golden), memoryview(self.golden), 1160):
            with self.subTest(type=type(data).__name__):
                self.assertFalse(ct_oracle.canonical(data))
        class BytesSubclass(bytes):
            pass
        self.assertFalse(ct_oracle.canonical(BytesSubclass(self.golden)))
        for length in (0, 1, 7, 8, 1159):
            with self.subTest(length=length):
                self.assertFalse(ct_oracle.canonical(self.golden[:length]))
        self.assertFalse(ct_oracle.canonical(self.golden + b"\x00"))
        self.assertFalse(ct_oracle.canonical(self.golden + bytes(120)))
        for offset in range(8):
            changed = bytearray(self.golden)
            changed[offset] ^= 1
            with self.subTest(prefix_byte=offset):
                self.assertFalse(ct_oracle.canonical(bytes(changed)))

    def test_boundary_coefficients_in_both_nibbles_and_last_pair(self):
        for index in (0, 1, 254, 255, 256, 257, 510, 511, 512, 513, 766, 767):
            for value in (0, 1, 3328, 3329, 4095):
                with self.subTest(index=index, coefficient=value):
                    changed = set_coefficient(self.golden, index, value)
                    self.assertEqual(ct_oracle.canonical(changed), value < 3329)

    def test_seed_corpus_covers_framing_and_polynomial_boundaries(self):
        seeds = ct_oracle.seed_inputs()
        self.assertEqual(seeds, ct_oracle.seed_inputs())
        self.assertEqual(len(seeds), len(set(seeds)))
        self.assertEqual(seeds[0], self.golden)
        self.assertTrue(all(type(seed) is bytes and len(seed) <= 1280 for seed in seeds))
        for length in (0, 1, 7, 8, 1159):
            self.assertIn(self.golden[:length], seeds)
        self.assertIn(self.golden + b"\x00", seeds)
        self.assertIn(self.golden + bytes(120), seeds)
        for offset in range(8):
            changed = bytearray(self.golden)
            changed[offset] ^= 1
            self.assertIn(bytes(changed), seeds)
        for index in (0, 1, 256, 257, 512, 513):
            for value in (0, 1, 3328, 3329, 4095):
                self.assertIn(set_coefficient(self.golden, index, value), seeds)
        self.assertGreater(sum(ct_oracle.canonical(data) for data in seeds), 1)
        self.assertTrue(any(not ct_oracle.canonical(data) for data in seeds))


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = ct_oracle.Reference()
        cls.vector = ct_oracle.fixture()

    def test_golden_expected(self):
        self.assertEqual(self.reference.expected(self.vector["ct"]),
                         {"status": 0, "ss": self.vector["ss"]})

    def test_malformed_expected_invokes_pinned_parser_without_decapsulation(self):
        original_parser = self.reference.kem.deserialize_ciphertext_compact
        malformed = (b"", self.vector["ct"][:-1],
                     set_coefficient(self.vector["ct"], 767, 3329))
        for data in malformed:
            with self.subTest(length=len(data)):
                with patch.object(self.reference.kem, "deserialize_ciphertext_compact",
                                  wraps=original_parser) as parser:
                    with patch.object(self.reference.kem, "decapsulate") as decapsulate:
                        self.assertEqual(self.reference.expected(data),
                                         {"status": 1, "ss": bytes(32)})
                        parser.assert_called_once_with(data)
                        decapsulate.assert_not_called()

    def test_detects_pinned_parser_accepting_noncanonical_input(self):
        ciphertext = self.reference.kem.deserialize_ciphertext_compact(self.vector["ct"])
        with patch.object(self.reference.kem, "deserialize_ciphertext_compact",
                          return_value=ciphertext) as parser:
            with patch.object(self.reference.kem, "decapsulate") as decapsulate:
                with self.assertRaisesRegex(AssertionError, "accepted a noncanonical"):
                    self.reference.expected(b"")
                parser.assert_called_once_with(b"")
                decapsulate.assert_not_called()

    def test_detects_pinned_parser_rejecting_canonical_input(self):
        error = self.reference.module.InputValidationError("injected parser rejection")
        with patch.object(self.reference.kem, "deserialize_ciphertext_compact",
                          side_effect=error) as parser:
            with self.assertRaisesRegex(AssertionError, "rejected a canonical") as caught:
                self.reference.expected(self.vector["ct"])
            self.assertIs(caught.exception.__cause__, error)
            parser.assert_called_once_with(self.vector["ct"])

    def test_unexpected_parser_exception_is_not_mapped_to_input_status(self):
        error = RuntimeError("injected unexpected parser failure")
        with patch.object(self.reference.kem, "deserialize_ciphertext_compact", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.reference.expected(b"")
            self.assertIs(caught.exception, error)

    def test_canonical_tamper_uses_actual_fallback_and_retains_key(self):
        key_before = copy.deepcopy(self.reference.sk)
        original = self.reference.kem.deserialize_ciphertext_compact(self.vector["ct"])
        changed = set_coefficient(self.vector["ct"], 0, (original.u[0][0] + 1) % 3329)
        self.assertTrue(ct_oracle.canonical(changed))
        parsed = self.reference.kem.deserialize_ciphertext_compact(changed)
        direct = self.reference.kem.decapsulate(self.reference.sk, parsed)
        self.assertNotEqual(direct, self.vector["ss"])
        self.assertEqual(self.reference.expected(changed), {"status": 0, "ss": direct})
        self.assertEqual(self.reference.expected(b""), {"status": 1, "ss": bytes(32)})
        self.assertEqual(self.reference.sk, key_before)
        self.assertEqual(self.reference.expected(self.vector["ct"])["ss"], self.vector["ss"])

    def test_all_candidates_agree_with_pinned_parser_and_decapsulation(self):
        rng = random.Random(20261107)
        candidates = ct_oracle.seed_inputs()
        # Arbitrary payloads, single-byte mutations, and full canonical payloads
        # exercise parser agreement beyond the hand-selected corpus boundaries.
        candidates.extend(rng.randbytes(size) for size in (0, 1, 7, 8, 1159, 1160, 1161, 1280))
        for _ in range(48):
            changed = bytearray(self.vector["ct"])
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            candidates.append(bytes(changed))
        for _ in range(8):
            packed = bytearray(ct_oracle.PREFIX)
            for _ in range(384):
                low, high = rng.randrange(3329), rng.randrange(3329)
                packed.extend((low & 255, (low >> 8) | ((high & 15) << 4), high >> 4))
            candidates.append(bytes(packed))
        for index, data in enumerate(candidates):
            with self.subTest(candidate=index):
                try:
                    ciphertext = self.reference.kem.deserialize_ciphertext_compact(data)
                except self.reference.module.InputValidationError:
                    self.assertFalse(ct_oracle.canonical(data))
                    self.assertEqual(self.reference.expected(data), {"status": 1, "ss": bytes(32)})
                else:
                    self.assertTrue(ct_oracle.canonical(data))
                    self.assertEqual(self.reference.expected(data), {
                        "status": 0,
                        "ss": self.reference.kem.decapsulate(self.reference.sk, ciphertext),
                    })

    def test_reference_source_hash_is_checked_even_after_initial_load(self):
        untrusted_source = Mock()
        untrusted_source.read_bytes.return_value = b"raise AssertionError('must not execute')\n"
        with patch.object(ct_oracle, "REFERENCE_SOURCE", untrusted_source):
            with self.assertRaisesRegex(RuntimeError, "source hash differs"):
                ct_oracle.Reference()


if __name__ == "__main__":
    unittest.main()
