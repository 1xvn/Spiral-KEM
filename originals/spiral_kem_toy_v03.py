#!/usr/bin/env python3
"""
Spiral KEM v0.3 — mathematical-analysis baseline without public transforms
=====================================================

    R_q = Z_3329[x]/(x^256 + 1)
    t = A s + e
    u = A^T r + e1
    v = t^T r + e2 + Encode(m)
    v - s^T u = Encode(m) + e^T r + e2 - s^T e1

Changes in v0.3:
    - Public U A V transforms and spiral_seed were removed; older code is retained for comparative experiments.
    - Every SHAKE256 input includes the version, complete parameters, and a length-prefixed purpose label.
    - Decode uses circular distance to the two message centers, resolving ties to 0.
      For q=3329 and Encode(1)=1664, coefficients 833 <= a <= 2496 decode to 1.
    - Separate analysis/tests cover boundaries, independent polynomial arithmetic, sampling, and the error term.
    - Canonical input validation, re-encryption checks, and fallback key derivation are retained.

Defaults (n,k,q,eta,key_bytes)=(256,2,3329,1,32) are for comparative research.
Lattice attack costs for eta=1 have not been validated. This code is neither an ML-KEM implementation,
a security proof, nor a constant-time implementation. Do not use it to protect real data.
Increasing parameters alone is not evidence of security.

Usage (Python 3.10+, no external packages):
    python spiral_kem_toy_v03.py
    python spiral_kem_toy_v03.py --self-test --trials 50
    python spiral_kem_toy_v03.py --lab --n 8 --self-test
    python -m unittest discover -s tests -v
    python analysis/analyze_math.py --output analysis/results.json

API:
    kem = SpiralKEM()
    pk, sk = kem.keygen()
    ciphertext, alice_key = kem.encapsulate(pk)
    wire = kem.serialize_ciphertext(ciphertext)
    bob_key = kem.decapsulate(sk, kem.deserialize_ciphertext(wire))

Compatibility: key/ciphertext encodings and hashes differ from v0.1/v0.2. Generate new
keys. PublicKey contains only (matrix_seed,t). spiral_descriptor and
regenerate_path_seed were removed. Deterministic encryption is internal/test-only.

The regular API requires exact bytes and tuple/int types, rejecting bool, noncanonical coefficients,
and invalid lengths. Encoding errors raise InputValidationError; canonically encoded ciphertexts
that fail re-encryption verification return a deterministic 32-byte fallback key.
Public-key encoding validation does not authenticate the peer. Do not expose test diagnostics or
reduced-parameter modes to a service. Python does not guarantee secret-memory erasure or
constant-time execution. Actual security levels and IND-CCA security remain unverified.
"""

from __future__ import annotations

import argparse
import hmac
import secrets
from dataclasses import dataclass, field
from hashlib import sha3_256, shake_256
from typing import Sequence


VERSION = "0.3"
DOMAIN = b"Spiral-KEM-v0.3/research-only/"
BASELINE = (256, 2, 3329, 1, 32)
SUPPORTED_N = (8, 16, 32, 64, 128, 256)


class InputValidationError(ValueError):
    """Encoding/parameter error; messages never include input contents or secret values."""


Poly = tuple[int, ...]
PolyVec = tuple[Poly, ...]
PolyMat = tuple[tuple[Poly, ...], ...]


@dataclass(frozen=True)
class Parameters:
    """Research parameters; no claim of ML-KEM security."""

    n: int = 256      # One polynomial carries a 32-byte message.
    k: int = 2        # Module dimension.
    q: int = 3329     # Coefficient modulus.
    eta: int = 1      # Small-error distribution width.
    key_bytes: int = 32

    def __post_init__(self) -> None:
        values = (self.n, self.k, self.q, self.eta, self.key_bytes)
        if any(type(value) is not int for value in values):
            raise InputValidationError("Parameters must be integers, excluding bool.")
        if self.n not in SUPPORTED_N:
            raise InputValidationError("n must be one of 8, 16, 32, 64, 128, 256.")
        if values[1:] != BASELINE[1:]:
            raise InputValidationError("v0.3 fixes k=2, q=3329, eta=1, key_bytes=32.")

    @property
    def message_bytes(self) -> int:
        return self.n // 8


@dataclass(frozen=True)
class PublicKey:
    matrix_seed: bytes
    t: PolyVec


@dataclass(frozen=True)
class SecretKey:
    s: PolyVec = field(repr=False)
    public_key: PublicKey = field(repr=False)
    fallback_secret: bytes = field(repr=False)


@dataclass(frozen=True)
class Ciphertext:
    u: PolyVec
    v: Poly


class SpiralKEM:
    """Spiral KEM research model using Module-LWE cancellation."""

    def __init__(
        self, params: Parameters | None = None, *, lab_mode: bool = False
    ) -> None:
        if type(lab_mode) is not bool:
            raise InputValidationError("lab_mode must be bool.")
        if params is None:
            params = Parameters()
        if type(params) is not Parameters:
            raise InputValidationError("params must be a Parameters instance.")
        params.__post_init__()
        if params != Parameters() and not lab_mode:
            raise InputValidationError("Reduced parameters require lab_mode=True.")
        self._params = params
        self._lab_mode = lab_mode

    @property
    def p(self) -> Parameters:
        return self._params

    @property
    def lab_mode(self) -> bool:
        return self._lab_mode

    @property
    def profile(self) -> str:
        return "lab (reduced experiments enabled)" if self.lab_mode else "baseline (research only)"

    # ------------------------------------------------------------------
    # Public API.
    # ------------------------------------------------------------------
    def keygen(self) -> tuple[PublicKey, SecretKey]:
        """Generate a public key and secret key."""

        matrix_seed = secrets.token_bytes(32)
        secret_seed = secrets.token_bytes(32)

        a_matrix = self._base_matrix(matrix_seed)
        s = self._small_vector(secret_seed, b"key/s")
        e = self._small_vector(secret_seed, b"key/e")
        t = self._vec_add(self._mat_vec(a_matrix, s), e)

        pk = PublicKey(matrix_seed=matrix_seed, t=t)
        sk = SecretKey(
            s=s,
            public_key=pk,
            fallback_secret=secrets.token_bytes(32),
        )
        return pk, sk

    def encapsulate(self, pk: PublicKey) -> tuple[Ciphertext, bytes]:
        """Generate a ciphertext and a 32-byte shared key."""

        self._validate_public_key(pk)
        message = secrets.token_bytes(self.p.message_bytes)
        ciphertext = self._encrypt_message(pk, message)
        shared_key = self._derive_valid_key(pk, message, ciphertext)
        return ciphertext, shared_key

    def decapsulate(self, sk: SecretKey, ciphertext: Ciphertext) -> bytes:
        """Validate a ciphertext and recover the shared key.

        Encoding errors raise InputValidationError. A canonically encoded ciphertext
        that fails re-encryption verification returns a deterministic 32-byte fallback key.
        The caller must handle errors. Python constant-time execution is not guaranteed.
        """

        self._validate_ciphertext(ciphertext)
        self._validate_secret_key(sk)
        shared_key, _ = self._decapsulate_core(sk, ciphertext)
        return shared_key

    def _decapsulate_core(
        self, sk: SecretKey, ciphertext: Ciphertext
    ) -> tuple[bytes, bool]:
        """Internal function for validated inputs; diagnostic flags are not exposed through the regular API."""

        pk = sk.public_key

        # Cancel the A-dependent terms using secret s.
        aligned = self._poly_sub(ciphertext.v, self._dot(sk.s, ciphertext.u))
        recovered_message = self._decode_message(aligned)

        # Regenerate r, e1, e2 from recovered_message and verify the ciphertext again.
        expected = self._encrypt_message(pk, recovered_message)
        valid = hmac.compare_digest(
            self.serialize_ciphertext(ciphertext),
            self.serialize_ciphertext(expected),
        )

        candidate = self._derive_valid_key(pk, recovered_message, ciphertext)
        fallback = self._xof(
            b"fallback/",
            sk.fallback_secret
            + self._public_key_hash(pk)
            + sha3_256(self.serialize_ciphertext(ciphertext)).digest(),
            self.p.key_bytes,
        )
        # Always compute both candidates. This selection expression does not ensure constant-time Python execution.
        mask = -int(valid)
        selected = bytes(
            (good & mask) | (bad & ~mask)
            for good, bad in zip(candidate, fallback, strict=True)
        )
        return selected, valid

    def serialize_public_key(self, pk: PublicKey) -> bytes:
        self._validate_public_key(pk)
        return (
            self._wire_prefix(b"pk/")
            + pk.matrix_seed
            + self._pack_vector(pk.t)
        )

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> bytes:
        self._validate_ciphertext(ciphertext)
        return (
            self._wire_prefix(b"ct/")
            + self._pack_vector(ciphertext.u)
            + self._pack_poly(ciphertext.v)
        )

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        """Read a canonical v0.3 public key, checking version, parameters, length, and coefficient bounds."""
        prefix = self._wire_prefix(b"pk/")
        self._validate_wire(data, prefix, 32 + 2 * self.p.k * self.p.n)
        offset = len(prefix)
        matrix_seed = data[offset : offset + 32]
        t = self._unpack_polys(data[offset + 32 :], self.p.k)
        pk = PublicKey(matrix_seed, t)
        self._validate_public_key(pk)
        return pk

    def deserialize_ciphertext(self, data: bytes) -> Ciphertext:
        """Read a canonical v0.3 ciphertext; reject encoding errors before fallback handling."""
        prefix = self._wire_prefix(b"ct/")
        self._validate_wire(data, prefix, 2 * (self.p.k + 1) * self.p.n)
        polynomials = self._unpack_polys(data[len(prefix) :], self.p.k + 1)
        ciphertext = Ciphertext(polynomials[:-1], polynomials[-1])
        self._validate_ciphertext(ciphertext)
        return ciphertext

    # ------------------------------------------------------------------
    # External input boundary: validate every value before beginning big-integer multiplication.
    # ------------------------------------------------------------------
    def _valid_poly(self, poly: object) -> bool:
        return (
            type(poly) is tuple
            and len(poly) == self.p.n
            and all(type(x) is int and 0 <= x < self.p.q for x in poly)
        )

    def _valid_vector(self, vector: object) -> bool:
        return (
            type(vector) is tuple
            and len(vector) == self.p.k
            and all(self._valid_poly(poly) for poly in vector)
        )

    def _validate_public_key(self, pk: PublicKey) -> None:
        if not (
            type(pk) is PublicKey
            and type(pk.matrix_seed) is bytes
            and len(pk.matrix_seed) == 32
            and self._valid_vector(pk.t)
        ):
            raise InputValidationError("Invalid public-key encoding.")

    def _validate_secret_key(self, sk: SecretKey) -> None:
        if not (
            type(sk) is SecretKey
            and self._valid_vector(sk.s)
            and type(sk.fallback_secret) is bytes
            and len(sk.fallback_secret) == 32
        ):
            raise InputValidationError("Invalid secret-key encoding.")
        if any(x not in (0, 1, self.p.q - 1) for poly in sk.s for x in poly):
            raise InputValidationError("Secret-key coefficients exceed the baseline distribution range.")
        self._validate_public_key(sk.public_key)

    def _validate_ciphertext(self, ciphertext: Ciphertext) -> None:
        if not (
            type(ciphertext) is Ciphertext
            and self._valid_vector(ciphertext.u)
            and self._valid_poly(ciphertext.v)
        ):
            raise InputValidationError("Invalid ciphertext encoding.")

    def _wire_prefix(self, kind: bytes) -> bytes:
        return DOMAIN + kind + self._parameter_bytes()

    @staticmethod
    def _validate_wire(data: bytes, prefix: bytes, payload_length: int) -> None:
        if (
            type(data) is not bytes
            or len(data) != len(prefix) + payload_length
            or not data.startswith(prefix)
        ):
            raise InputValidationError("Invalid byte-input version, parameters, or encoding.")

    def _unpack_polys(self, data: bytes, count: int) -> PolyVec:
        size = 2 * self.p.n
        if len(data) != count * size:
            raise InputValidationError("Invalid polynomial byte length.")
        polys = tuple(
            tuple(int.from_bytes(data[i : i + 2], "little") for i in range(start, start + size, 2))
            for start in range(0, len(data), size)
        )
        if not all(self._valid_poly(poly) for poly in polys):
            raise InputValidationError("Byte-input coefficients are outside the canonical range.")
        return polys

    # ------------------------------------------------------------------
    # KEM core.
    # ------------------------------------------------------------------
    def _encrypt_message(self, pk: PublicKey, message: bytes) -> Ciphertext:
        self._check_message(message)

        coins = self._coin_seed(pk, message)
        r = self._small_vector(coins, b"enc/r")
        e1 = self._small_vector(coins, b"enc/e1")
        e2 = self._small_poly(coins, b"enc/e2")

        a_matrix = self._base_matrix(pk.matrix_seed)
        u = self._vec_add(self._transpose_mat_vec(a_matrix, r), e1)
        v = self._poly_add(
            self._poly_add(self._dot(pk.t, r), e2),
            self._encode_message(message),
        )
        return Ciphertext(u=u, v=v)

    def _xof(self, label: bytes, payload: bytes, length: int) -> bytes:
        """Internal, unambiguous byte framing that separates profiles and purposes."""
        context = DOMAIN + self._parameter_bytes()
        framed_label = len(label).to_bytes(2, "little") + label
        return shake_256(context + framed_label + payload).digest(length)

    def _coin_seed(self, pk: PublicKey, message: bytes) -> bytes:
        return self._xof(b"coins/", message + self._public_key_hash(pk), 32)

    def _derive_valid_key(
        self, pk: PublicKey, message: bytes, ciphertext: Ciphertext
    ) -> bytes:
        return self._xof(
            b"shared-key/",
            message
            + self._public_key_hash(pk)
            + sha3_256(self.serialize_ciphertext(ciphertext)).digest(),
            self.p.key_bytes,
        )

    # ------------------------------------------------------------------
    # Public matrix A; spiral transforms are excluded from the cryptographic core.
    # ------------------------------------------------------------------
    def _base_matrix(self, matrix_seed: bytes) -> PolyMat:
        return tuple(
            tuple(
                self._uniform_poly(
                    matrix_seed,
                    b"matrix/" + i.to_bytes(2, "little") + j.to_bytes(2, "little"),
                )
                for j in range(self.p.k)
            )
            for i in range(self.p.k)
        )

    # ------------------------------------------------------------------
    # Arithmetic in R_q = Z_q[x] / (x^n + 1).
    # ------------------------------------------------------------------
    def _poly_add(self, a: Poly, b: Poly) -> Poly:
        return tuple((x + y) % self.p.q for x, y in zip(a, b, strict=True))

    def _poly_sub(self, a: Poly, b: Poly) -> Poly:
        return tuple((x - y) % self.p.q for x, y in zip(a, b, strict=True))

    def _poly_mul(self, a: Poly, b: Poly) -> Poly:
        """Simple O(n^2) negacyclic multiplication with x^n = -1."""

        n = self.p.n
        accum = [0] * n
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                index = i + j
                if index < n:
                    accum[index] += x * y
                else:
                    accum[index - n] -= x * y
        return tuple(value % self.p.q for value in accum)

    def _zero_poly(self) -> Poly:
        return (0,) * self.p.n

    def _vec_add(self, a: PolyVec, b: PolyVec) -> PolyVec:
        return tuple(self._poly_add(x, y) for x, y in zip(a, b, strict=True))

    def _mat_vec(self, matrix: PolyMat, vector: PolyVec) -> PolyVec:
        output: list[Poly] = []
        for row in matrix:
            total = self._zero_poly()
            for entry, value in zip(row, vector, strict=True):
                total = self._poly_add(total, self._poly_mul(entry, value))
            output.append(total)
        return tuple(output)

    def _transpose_mat_vec(self, matrix: PolyMat, vector: PolyVec) -> PolyVec:
        output: list[Poly] = []
        for column in range(self.p.k):
            total = self._zero_poly()
            for row in range(self.p.k):
                total = self._poly_add(
                    total,
                    self._poly_mul(matrix[row][column], vector[row]),
                )
            output.append(total)
        return tuple(output)

    def _dot(self, a: PolyVec, b: PolyVec) -> Poly:
        total = self._zero_poly()
        for x, y in zip(a, b, strict=True):
            total = self._poly_add(total, self._poly_mul(x, y))
        return total

    # ------------------------------------------------------------------
    # Sampling, encoding, and serialization.
    # ------------------------------------------------------------------
    def _uniform_poly(self, seed: bytes, label: bytes) -> Poly:
        """16-bit rejection sampling; removes modulo bias for ideal uniform input."""

        limit = 65536 - (65536 % self.p.q)
        coefficients: list[int] = []
        counter = 0

        while len(coefficients) < self.p.n:
            block = self._xof(
                b"uniform/" + label, seed + counter.to_bytes(4, "little"), 256
            )
            counter += 1
            for offset in range(0, len(block), 2):
                candidate = int.from_bytes(block[offset : offset + 2], "little")
                if candidate < limit:
                    coefficients.append(candidate % self.p.q)
                    if len(coefficients) == self.p.n:
                        break

        return tuple(coefficients)

    def _small_poly(self, seed: bytes, label: bytes) -> Poly:
        """Sample [-eta, eta] using a simple centered-binomial construction."""

        needed = 2 * self.p.eta * self.p.n
        stream = self._xof(b"small/" + label, seed, needed)
        result: list[int] = []
        cursor = 0

        for _ in range(self.p.n):
            positive = sum(stream[cursor + i] & 1 for i in range(self.p.eta))
            cursor += self.p.eta
            negative = sum(stream[cursor + i] & 1 for i in range(self.p.eta))
            cursor += self.p.eta
            result.append((positive - negative) % self.p.q)

        return tuple(result)

    def _small_vector(self, seed: bytes, label: bytes) -> PolyVec:
        return tuple(
            self._small_poly(seed, label + b"/" + i.to_bytes(2, "little"))
            for i in range(self.p.k)
        )

    def _encode_message(self, message: bytes) -> Poly:
        self._check_message(message)
        encoded: list[int] = []
        one = self.p.q // 2
        for byte in message:
            for bit_index in range(8):
                encoded.append(one if (byte >> bit_index) & 1 else 0)
        return tuple(encoded)

    def _decode_message(self, poly: Poly) -> bytes:
        lower = self.p.q // 4
        upper = (3 * self.p.q) // 4
        output = bytearray(self.p.message_bytes)

        for index, coefficient in enumerate(poly):
            value = coefficient % self.p.q
            # Circular distance to centers 0 and floor(q/2); the tie at 832 resolves to 0.
            bit = 1 if lower < value <= upper else 0
            output[index // 8] |= bit << (index % 8)
        return bytes(output)

    def _pack_poly(self, poly: Poly) -> bytes:
        # Do not repair inputs: use canonical coefficients validated by the public serialization API.
        return b"".join(value.to_bytes(2, "little") for value in poly)

    def _pack_vector(self, vector: PolyVec) -> bytes:
        return b"".join(self._pack_poly(poly) for poly in vector)

    def _public_key_hash(self, pk: PublicKey) -> bytes:
        return sha3_256(self.serialize_public_key(pk)).digest()

    def _parameter_bytes(self) -> bytes:
        return b"".join(
            value.to_bytes(4, "little")
            for value in (self.p.n, self.p.k, self.p.q, self.p.eta, self.p.key_bytes)
        )

    def _check_message(self, message: bytes) -> None:
        if type(message) is not bytes or len(message) != self.p.message_bytes:
            raise InputValidationError("Invalid message type or length.")



class SpiralKEMTestHarness:
    """Local regression tests only. Do not use or expose in service code.

    This is not a Python access-control boundary. It is an explicit interface that
    separates diagnostics from the regular API and performs the same encoding checks.
    """

    def __init__(self, kem: SpiralKEM) -> None:
        if type(kem) is not SpiralKEM:
            raise InputValidationError("Diagnostics require a SpiralKEM instance.")
        self._kem = kem

    def decapsulate_with_status(
        self, sk: SecretKey, ciphertext: Ciphertext
    ) -> tuple[bytes, bool]:
        self._kem._validate_ciphertext(ciphertext)
        self._kem._validate_secret_key(sk)
        return self._kem._decapsulate_core(sk, ciphertext)


def run_self_test(
    trials: int = 25, *, params: Parameters | None = None, lab_mode: bool = False
) -> bool:
    """Run actual regression tests. Return False on failure; do not rely on assert statements.

    Adversarial-input tests use fixed test data unrelated to operational secrets.
    Repeated normal-path tests use OS randomness and multiple key pairs.
    """
    import contextlib
    import io
    import sys
    import unittest
    from dataclasses import replace
    from unittest.mock import patch

    if type(trials) is not int or not 1 <= trials <= 1000:
        raise InputValidationError("trials must be an integer in 1..1000.")

    kem = SpiralKEM(params, lab_mode=lab_mode)
    diagnostic = SpiralKEMTestHarness(kem)

    # Randomness is replaced only while constructing this test fixture.
    # Regular keygen/encapsulate provides no fixed-seed option.
    with patch.object(secrets, "token_bytes", side_effect=[
        bytes(range(32)), b"S" * 32, b"Z" * 32,
        bytes(range(kem.p.message_bytes)),
    ]):
        pk, sk = kem.keygen()
        ciphertext, alice_key = kem.encapsulate(pk)

    def change(field_name: str = "v", delta: int = 1, row: int = 0) -> Ciphertext:
        poly = list(ciphertext.v if field_name == "v" else ciphertext.u[row])
        poly[0] = (poly[0] + delta) % kem.p.q
        if field_name == "v":
            return replace(ciphertext, v=tuple(poly))
        u = list(ciphertext.u)
        u[row] = tuple(poly)
        return replace(ciphertext, u=tuple(u))

    class RegressionTests(unittest.TestCase):
        def test_normal_roundtrips_multiple_keys(self) -> None:
            current_pk, current_sk = pk, sk
            for trial in range(trials):
                if trial % 5 == 0:
                    current_pk, current_sk = kem.keygen()
                c, expected_key = kem.encapsulate(current_pk)
                with self.subTest(trial=trial):
                    actual = kem.decapsulate(current_sk, c)
                    self.assertIs(type(actual), bytes)
                    self.assertEqual(len(actual), 32)
                    self.assertEqual(actual, expected_key)

        def test_deterministic_encryption_and_reencryption(self) -> None:
            m = bytes(range(kem.p.message_bytes))
            self.assertEqual(kem._encrypt_message(pk, m), ciphertext)
            r = kem._small_vector(kem._coin_seed(pk, m), b"enc/r")
            bob_m = kem._decode_message(kem._poly_sub(ciphertext.v, kem._dot(sk.s, ciphertext.u)))
            self.assertEqual(bob_m, m)
            self.assertEqual(kem._small_vector(kem._coin_seed(pk, bob_m), b"enc/r"), r)
            self.assertEqual(kem.decapsulate(sk, ciphertext), alice_key)

        def test_wire_roundtrip_in_fresh_instance(self) -> None:
            other = SpiralKEM(kem.p, lab_mode=kem.lab_mode)
            pk_wire = kem.serialize_public_key(pk)
            c_wire = kem.serialize_ciphertext(ciphertext)
            self.assertEqual(other.deserialize_public_key(pk_wire), pk)
            self.assertEqual(other.deserialize_ciphertext(c_wire), ciphertext)
            self.assertEqual(other.serialize_public_key(other.deserialize_public_key(pk_wire)), pk_wire)
            self.assertEqual(other.serialize_ciphertext(other.deserialize_ciphertext(c_wire)), c_wire)
            self.assertEqual(other.decapsulate(sk, other.deserialize_ciphertext(c_wire)), alice_key)

        def test_six_value_changes_use_fallback(self) -> None:
            for field_name, row in (("v", 0), ("u", 0), ("u", 1)):
                for delta in (1, kem.p.q // 4):
                    with self.subTest(field=field_name, row=row, delta=delta):
                        changed = change(field_name, delta, row)
                        key, valid = diagnostic.decapsulate_with_status(sk, changed)
                        self.assertFalse(valid)
                        self.assertEqual(len(key), 32)
                        self.assertNotEqual(key, alice_key)
                        self.assertEqual(kem.decapsulate(sk, changed), key)

        def test_fallback_repeat_and_ciphertext_binding(self) -> None:
            c1, c2 = change(delta=1), change(delta=2)
            key1 = kem.decapsulate(sk, c1)
            self.assertEqual(kem.decapsulate(sk, c1), key1)
            self.assertNotEqual(kem.decapsulate(sk, c2), key1)
            self.assertEqual(kem.decapsulate(sk, ciphertext), alice_key)

        def test_fallback_secret_binding(self) -> None:
            altered_sk = replace(sk, fallback_secret=b"Y" * 32)
            changed = change()
            self.assertNotEqual(kem.decapsulate(sk, changed), kem.decapsulate(altered_sk, changed))
            self.assertEqual(kem.decapsulate(altered_sk, ciphertext), alice_key)

        def test_malformed_objects_rejected_before_arithmetic(self) -> None:
            cases = [None, {}, (),
                replace(ciphertext, u=()),
                replace(ciphertext, u=list(ciphertext.u)),
                replace(ciphertext, u=(list(ciphertext.u[0]), ciphertext.u[1])),
                replace(ciphertext, u=(ciphertext.u[0][:-1], ciphertext.u[1])),
                replace(ciphertext, u=(ciphertext.u[0] + (0, 0), ciphertext.u[1])),
                replace(ciphertext, v=ciphertext.v[:-1]),
                replace(ciphertext, v=ciphertext.v + (0,)),
                replace(ciphertext, v=list(ciphertext.v)),
            ]
            for value in ("bad", None, True, 1.5, -1, kem.p.q, 1 << 4096):
                cases.append(replace(ciphertext, v=(value,) + ciphertext.v[1:]))
                cases.append(replace(ciphertext, u=((value,) + ciphertext.u[0][1:], ciphertext.u[1])))
            with patch.object(kem, "_dot", side_effect=AssertionError("invalid input reached arithmetic")):
                for index, c in enumerate(cases):
                    with self.subTest(case=index):
                        for call in (
                            lambda: kem.decapsulate(sk, c),
                            lambda: diagnostic.decapsulate_with_status(sk, c),
                            lambda: kem.serialize_ciphertext(c),
                        ):
                            with self.assertRaises(InputValidationError) as error:
                                call()
                            self.assertEqual(str(error.exception), "Invalid ciphertext encoding.")

        def test_modular_aliases_rejected(self) -> None:
            cases = [
                replace(ciphertext, v=(ciphertext.v[0] + kem.p.q,) + ciphertext.v[1:]),
                replace(ciphertext, v=(ciphertext.v[0] - kem.p.q,) + ciphertext.v[1:]),
                replace(ciphertext, u=((ciphertext.u[0][0] + kem.p.q,) + ciphertext.u[0][1:], ciphertext.u[1])),
            ]
            for index, c in enumerate(cases):
                with self.subTest(case=index):
                    with self.assertRaises(InputValidationError):
                        kem.decapsulate(sk, c)
                    with self.assertRaises(InputValidationError):
                        kem.serialize_ciphertext(c)

        def test_public_key_validation_before_rng(self) -> None:
            cases = [None, {}, replace(pk, matrix_seed=b"short"),
                replace(pk, matrix_seed=bytearray(32)), replace(pk, t=()),
                replace(pk, t=((kem.p.q,) + pk.t[0][1:], pk.t[1])),
                replace(pk, t=(pk.t[0][:-1], pk.t[1])),
            ]
            with patch.object(secrets, "token_bytes", side_effect=AssertionError("invalid pk reached RNG")):
                for index, bad_pk in enumerate(cases):
                    with self.subTest(case=index):
                        with self.assertRaises(InputValidationError):
                            kem.encapsulate(bad_pk)
                        with self.assertRaises(InputValidationError):
                            kem.serialize_public_key(bad_pk)

        def test_secret_key_validation_before_arithmetic(self) -> None:
            cases = [None, {}, replace(sk, s=()), replace(sk, fallback_secret=b""),
                replace(sk, fallback_secret=bytearray(32)), replace(sk, public_key=None),
                replace(sk, s=((2,) + sk.s[0][1:], sk.s[1])),
            ]
            with patch.object(kem, "_dot", side_effect=AssertionError("invalid sk reached arithmetic")):
                for index, bad_sk in enumerate(cases):
                    with self.subTest(case=index):
                        with self.assertRaises(InputValidationError):
                            kem.decapsulate(bad_sk, ciphertext)

        def test_wire_length_version_type_and_coefficient_checks(self) -> None:
            pairs = [
                (kem.serialize_public_key(pk), kem.deserialize_public_key, len(kem._wire_prefix(b"pk/")) + 32),
                (kem.serialize_ciphertext(ciphertext), kem.deserialize_ciphertext, len(kem._wire_prefix(b"ct/"))),
            ]
            for wire, parser, offset in pairs:
                cases = [None, "bad", bytearray(wire), memoryview(wire), b"", wire[:-1], wire + b"\x00",
                         b"X" + wire[1:], wire.replace(b"v0.3/", b"v0.2/", 1)]
                for value in (kem.p.q, 65535):
                    cases.append(wire[:offset] + value.to_bytes(2, "little") + wire[offset + 2:])
                for index, data in enumerate(cases):
                    with self.subTest(parser=parser.__name__, case=index):
                        with self.assertRaises(InputValidationError):
                            parser(data)

        def test_canonical_boundary_coefficients_roundtrip(self) -> None:
            edge = tuple(0 if i % 2 else kem.p.q - 1 for i in range(kem.p.n))
            c = Ciphertext((edge,) * kem.p.k, edge)
            self.assertEqual(kem.deserialize_ciphertext(kem.serialize_ciphertext(c)), c)
            self.assertEqual(len(kem.decapsulate(sk, c)), 32)

        def test_parameters_reject_unsupported_and_wrong_types(self) -> None:
            cases = [dict(n=0), dict(n=24), dict(n=512), dict(n=True), dict(n=256.0),
                     dict(k=0), dict(k=3), dict(q=5), dict(q=3329.0), dict(eta=0),
                     dict(eta=2), dict(key_bytes=0), dict(key_bytes=-1), dict(key_bytes=True)]
            for index, kwargs in enumerate(cases):
                with self.subTest(case=index):
                    with self.assertRaises(InputValidationError):
                        Parameters(**kwargs)
            with self.assertRaises(InputValidationError):
                SpiralKEM({})
            with self.assertRaises(InputValidationError):
                SpiralKEM(lab_mode=1)

        def test_lab_opt_in_and_cross_profile_rejection(self) -> None:
            self.assertEqual(SpiralKEM().p, Parameters())
            with self.assertRaises(InputValidationError):
                SpiralKEM(Parameters(n=8))
            tiny = SpiralKEM(Parameters(n=8), lab_mode=True)
            tiny_pk, tiny_sk = tiny.keygen()
            tiny_c, tiny_key = tiny.encapsulate(tiny_pk)
            self.assertEqual(tiny.decapsulate(tiny_sk, tiny_c), tiny_key)
            self.assertIn("lab", tiny.profile)
            baseline = SpiralKEM()
            with self.assertRaises(InputValidationError):
                baseline.deserialize_ciphertext(tiny.serialize_ciphertext(tiny_c))
            with self.assertRaises(InputValidationError):
                baseline.deserialize_public_key(tiny.serialize_public_key(tiny_pk))
            with self.assertRaises(AttributeError):
                baseline.p = Parameters(n=8)

        def test_general_api_has_no_validity_method(self) -> None:
            self.assertFalse(hasattr(kem, "decapsulate_with_status"))
            self.assertIs(type(kem.decapsulate(sk, ciphertext)), bytes)
            key, valid = diagnostic.decapsulate_with_status(sk, ciphertext)
            self.assertTrue(valid)
            self.assertEqual(key, alice_key)

        def test_message_validation(self) -> None:
            for m in (None, "text", b"", bytes(kem.p.message_bytes + 1), bytearray(kem.p.message_bytes)):
                with self.assertRaises(InputValidationError):
                    kem._encrypt_message(pk, m)

        def test_demo_and_repr_do_not_print_secret_values(self) -> None:
            captured = io.StringIO()
            with patch.object(kem, "keygen", return_value=(pk, sk)), \
                    patch.object(kem, "encapsulate", return_value=(ciphertext, alice_key)), \
                    contextlib.redirect_stdout(captured):
                run_demo(kem)
            text = captured.getvalue()
            self.assertNotIn(alice_key.hex(), text)
            self.assertNotIn(sk.fallback_secret.hex(), text)
            self.assertNotIn(repr(sk.s), text)
            self.assertEqual(repr(sk), "SecretKey()")
            self.assertIn("Shared keys match: True", text)

        def test_negacyclic_ring_identity(self) -> None:
            x = (0, 1) + (0,) * (kem.p.n - 2)
            x_last = (0,) * (kem.p.n - 1) + (1,)
            self.assertEqual(kem._poly_mul(x, x_last), (kem.p.q - 1,) + (0,) * (kem.p.n - 1))

        def test_tiny_profile_remains_explicitly_breakable(self) -> None:
            # Exhaustive recovery is expected for n=8 and does not demonstrate baseline security.
            tiny = SpiralKEM(Parameters(n=8), lab_mode=True)
            tiny_pk, _ = tiny.keygen()
            target, expected_key = tiny.encapsulate(tiny_pk)
            matches = []
            for guess in range(256):
                message = bytes([guess])
                if tiny._encrypt_message(tiny_pk, message) == target:
                    matches.append(tiny._derive_valid_key(tiny_pk, message, target))
            self.assertEqual(matches, [expected_key])

    print(f"Spiral KEM v{VERSION} regressions: {kem.profile}, n={kem.p.n}, trials={trials}", flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RegressionTests)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()


def run_demo(kem: SpiralKEM | None = None) -> None:
    if kem is None:
        kem = SpiralKEM()
    pk, sk = kem.keygen()
    ciphertext, alice_key = kem.encapsulate(pk)
    bob_key = kem.decapsulate(sk, ciphertext)

    print(f"Spiral KEM v{VERSION} research demo")
    print(f"Profile: {kem.profile}")
    print("Research code without a security proof or constant-time guarantee.")
    if kem.lab_mode:
        print("LAB mode: exhaustive search can recover shared keys for reduced parameters.")
    print(
        f"Parameters: n={kem.p.n}, k={kem.p.k}, q={kem.p.q}, eta={kem.p.eta}"
    )
    print(f"Public-key fingerprint: {sha3_256(kem.serialize_public_key(pk)).hexdigest()[:32]}")
    print(f"Ciphertext size: {len(kem.serialize_ciphertext(ciphertext))} bytes")
    print(f"Shared-key length: {len(alice_key)} bytes (value not displayed)")
    print(f"Shared keys match: {hmac.compare_digest(alice_key, bob_key)}")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Spiral KEM v0.3 research baseline")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run input-validation, key-recovery, tampering, output, and lab-mode regressions.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=25,
        help="Number of self-test trials (default: 25)",
    )
    parser.add_argument("--lab", action="store_true", help="Explicitly enable reduced-parameter experiments.")
    parser.add_argument("--n", type=int, choices=SUPPORTED_N, default=None,
                        help="Default 256; defaults to 8 with --lab. Reduced parameters require --lab.")
    args = parser.parse_args(argv)

    n = args.n if args.n is not None else (8 if args.lab else 256)
    if n != 256 and not args.lab:
        parser.error("Reduced parameters require --lab.")
    if not 1 <= args.trials <= 1000:
        parser.error("--trials must be 1..1000.")
    params = Parameters(n=n)
    if args.self_test:
        if not run_self_test(args.trials, params=params, lab_mode=args.lab):
            raise SystemExit(1)
    else:
        run_demo(SpiralKEM(params, lab_mode=args.lab))


if __name__ == "__main__":
    main()
