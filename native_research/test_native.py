"""Differential checks of the experimental C backend against pinned Python OPT2."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes as c
import hashlib
import json
from pathlib import Path
import random
import subprocess
import time
import unittest
from unittest.mock import patch

from protocol_v01.handshake import load_kem

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
Byte32 = c.c_uint8 * 32
PK = c.c_uint8 * 808
CT = c.c_uint8 * 1160
Seeds = c.c_uint8 * 96
Poly = c.c_uint16 * 256


def fixture(index):
    return [
        hashlib.sha256(f"spiral-native-fixture/{index}/{k}".encode()).digest()
        for k in range(4)
    ]


def library(testing=True):
    path = (
        HERE / "build" / ("libspiral_testing.so" if testing else "libspiral_native.so")
    )
    lib = c.CDLL(str(path))
    lib.sp_keygen.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
    lib.sp_keygen.restype = c.c_int
    lib.sp_encaps.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]
    lib.sp_encaps.restype = c.c_int
    lib.sp_decaps_once.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p]
    lib.sp_decaps_once.restype = c.c_int
    lib.sp_key_destroy.argtypes = [c.POINTER(c.c_void_p)]
    lib.sp_key_destroy.restype = None
    if testing:
        lib.sp_test_keygen.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p)]
        lib.sp_test_keygen.restype = c.c_int
        lib.sp_test_encaps.argtypes = [
            c.c_void_p,
            c.c_size_t,
            c.c_void_p,
            c.c_void_p,
            c.c_void_p,
        ]
        lib.sp_test_encaps.restype = c.c_int
        lib.sp_test_cleared.argtypes = [c.c_void_p]
        lib.sp_test_cleared.restype = c.c_int
        lib.sp_test_poly_mul.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
        lib.sp_test_poly_mul.restype = None
    return lib


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = library()
        cls.module = load_kem()
        cls.cases = 0

    def new_key(self, seeds):
        pk, key = PK(), c.c_void_p()
        self.assertEqual(
            self.lib.sp_test_keygen(
                Seeds.from_buffer_copy(b"".join(seeds[:3])), pk, c.byref(key)
            ),
            0,
        )
        return bytes(pk), key

    def destroy(self, key):
        self.lib.sp_key_destroy(c.byref(key))
        self.assertIsNone(key.value)
        self.lib.sp_key_destroy(c.byref(key))

    def python_fixture(self, seeds):
        kem = self.module.SpiralKEM()
        with patch.object(self.module.secrets, "token_bytes", side_effect=seeds):
            pk, sk = kem.keygen()
            ct, ss = kem.encapsulate(pk)
        return kem, pk, sk, ct, ss

    def test_32_seeded_cross_implementation_roundtrips(self):
        for i in range(32):
            with self.subTest(fixture=i):
                seeds = fixture(i)
                kem, pk, sk, ct, ss = self.python_fixture(seeds)
                native_pk, key = self.new_key(seeds)
                try:
                    self.assertEqual(native_pk, kem.serialize_public_key_compact(pk))
                    output_ct, output_ss = CT(), Byte32()
                    self.assertEqual(
                        self.lib.sp_test_encaps(
                            native_pk, 808, seeds[3], output_ct, output_ss
                        ),
                        0,
                    )
                    self.assertEqual(
                        bytes(output_ct), kem.serialize_ciphertext_compact(ct)
                    )
                    self.assertEqual(bytes(output_ss), ss)
                    native_ss = Byte32()
                    self.assertEqual(
                        self.lib.sp_decaps_once(key, bytes(output_ct), 1160, native_ss),
                        0,
                    )
                    self.assertEqual(bytes(native_ss), ss)
                    self.assertEqual(kem.decapsulate(sk, ct), ss)
                    self.assertEqual(self.lib.sp_test_cleared(key), 1)
                    self.assertEqual(
                        self.lib.sp_decaps_once(key, bytes(output_ct), 1160, native_ss),
                        3,
                    )
                    self.assertEqual(bytes(native_ss), bytes(32))
                finally:
                    self.destroy(key)

    def test_pinned_protocol_vector(self):
        v = json.loads(
            (ROOT / "protocol_v01/tests/fixtures/test_vectors_v0.1.json").read_text()
        )
        seeds = [
            bytes.fromhex(v["inputs"]["kem_test_seeds"][name])
            for name in ("matrix", "secret", "fallback", "message")
        ]
        public, key = self.new_key(seeds)
        try:
            self.assertEqual(public.hex(), v["public"]["kem_public_key_skw1"])
            wire = bytes.fromhex(v["public"]["kem_ciphertext_skw1"])
            output = Byte32()
            self.assertEqual(self.lib.sp_decaps_once(key, wire, len(wire), output), 0)
            self.assertEqual(bytes(output).hex(), v["expected"]["shared_secret"])
        finally:
            self.destroy(key)

    def test_valid_format_tampering_matches_python_fallback(self):
        seeds = fixture("fallback")
        kem, pk, sk, ct, good = self.python_fixture(seeds)
        rng = random.Random(63251)
        for case in range(96):
            polys = [list(p) for p in ct.u + (ct.v,)]
            row, pos = rng.randrange(3), rng.randrange(256)
            polys[row][pos] = (polys[row][pos] + rng.randrange(1, 3329)) % 3329
            changed = self.module.Ciphertext(
                tuple(tuple(p) for p in polys[:2]), tuple(polys[2])
            )
            wire = kem.serialize_ciphertext_compact(changed)
            expected = kem.decapsulate(sk, changed)
            _, key = self.new_key(seeds)
            try:
                out = Byte32()
                self.assertEqual(self.lib.sp_decaps_once(key, wire, len(wire), out), 0)
                self.assertEqual(bytes(out), expected)
                self.assertNotEqual(bytes(out), good)
                self.assertEqual(self.lib.sp_test_cleared(key), 1)
            finally:
                self.destroy(key)

    def test_malformed_ciphertexts_consume_and_clear_key(self):
        seeds = fixture("malformed")
        kem, pk, sk, ct, ss = self.python_fixture(seeds)
        wire = kem.serialize_ciphertext_compact(ct)
        invalid_coefficient = bytearray(wire)
        invalid_coefficient[8:11] = b"\xff\xff\xff"
        cases = [wire[:n] for n in (0, 1, 7, 8, 1159)]
        cases += [wire + b"\0", wire + bytes(1 << 20), bytes(invalid_coefficient)]
        cases += [wire[:j] + bytes([wire[j] ^ 1]) + wire[j + 1 :] for j in range(8)]
        for data in cases:
            _, key = self.new_key(seeds)
            try:
                out = Byte32(*([0xFF] * 32))
                self.assertEqual(self.lib.sp_decaps_once(key, data, len(data), out), 1)
                self.assertEqual(bytes(out), bytes(32))
                self.assertEqual(self.lib.sp_test_cleared(key), 1)
                self.assertEqual(self.lib.sp_decaps_once(key, wire, len(wire), out), 3)
            finally:
                self.destroy(key)

    def test_malformed_public_key_never_outputs_material(self):
        seeds = fixture("invalid-pk")
        wire, key = self.new_key(seeds)
        self.destroy(key)
        data = bytearray(wire)
        data[40:43] = b"\xff\xff\xff"
        for bad in [wire[:n] for n in (0, 7, 8, 39, 807)] + [
            wire + bytes(1 << 20),
            bytes(data),
            b"X" + wire[1:],
        ]:
            ct, ss = CT(*([0xFF] * 1160)), Byte32(*([0xFF] * 32))
            self.assertEqual(self.lib.sp_encaps(bad, len(bad), ct, ss), 1)
            self.assertEqual(bytes(ct), bytes(1160))
            self.assertEqual(bytes(ss), bytes(32))

    def test_parallel_calls_claim_key_once(self):
        seeds = fixture("threads")
        kem, pk, sk, ct, ss = self.python_fixture(seeds)
        wire = kem.serialize_ciphertext_compact(ct)
        _, key = self.new_key(seeds)

        def execute(_):
            output = Byte32()
            result = self.lib.sp_decaps_once(key, wire, len(wire), output)
            return result, bytes(output)

        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                result = list(pool.map(execute, range(32)))
            self.assertEqual(sum(status == 0 for status, _ in result), 1)
            self.assertEqual(sum(status == 3 for status, _ in result), 31)
            self.assertEqual([out for status, out in result if status == 0], [ss])
            self.assertTrue(
                all(out == bytes(32) for status, out in result if status == 3)
            )
            self.assertEqual(self.lib.sp_test_cleared(key), 1)
        finally:
            self.destroy(key)

    def test_polynomial_boundary_and_random_inputs(self):
        kem = self.module.SpiralKEM()
        rng = random.Random(20261106)
        cases = [((3328,) * 256, (3328,) * 256), ((1,) + (0,) * 255, (0,) * 255 + (1,))]
        cases += [
            (
                tuple(rng.randrange(3329) for _ in range(256)),
                tuple(rng.randrange(3329) for _ in range(256)),
            )
            for _ in range(32)
        ]
        for a, b in cases:
            output = Poly()
            self.lib.sp_test_poly_mul(output, Poly(*a), Poly(*b))
            self.assertEqual(tuple(output), kem._poly_mul_reference(a, b))

    def test_production_rng_and_cross_decapsulation(self):
        prod = library(False)
        kem = self.module.SpiralKEM()
        seen = set()
        for _ in range(8):
            pk, key = PK(), c.c_void_p()
            self.assertEqual(prod.sp_keygen(pk, c.byref(key)), 0)
            try:
                parsed = kem.deserialize_public_key_compact(bytes(pk))
                self.assertNotIn(bytes(pk), seen)
                seen.add(bytes(pk))
                ct, ss = kem.encapsulate(parsed)
                out = Byte32()
                self.assertEqual(
                    prod.sp_decaps_once(
                        key, kem.serialize_ciphertext_compact(ct), 1160, out
                    ),
                    0,
                )
                self.assertEqual(bytes(out), ss)
            finally:
                prod.sp_key_destroy(c.byref(key))
            pk_python, sk_python = kem.keygen()
            ct_native, ss_native = CT(), Byte32()
            wire = kem.serialize_public_key_compact(pk_python)
            self.assertEqual(prod.sp_encaps(wire, len(wire), ct_native, ss_native), 0)
            self.assertEqual(
                kem.decapsulate(
                    sk_python, kem.deserialize_ciphertext_compact(bytes(ct_native))
                ),
                bytes(ss_native),
            )

    def test_production_has_no_diagnostic_exports(self):
        exported = subprocess.check_output(
            ["nm", "-D", "--defined-only", str(HERE / "build/libspiral_native.so")],
            text=True,
        )
        self.assertNotIn("sp_test_", exported)
        self.assertNotIn("decode", exported)


if __name__ == "__main__":
    unittest.main(verbosity=2)
