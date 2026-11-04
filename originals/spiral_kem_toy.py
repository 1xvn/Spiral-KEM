#!/usr/bin/env python3
"""
Spiral KEM v0.1 — research and educational prototype
==========================================

This example turns the following idea into executable code:

    B = U_omega A V_omega
    t = B s + e
    u = B^T r + e1
    v = t^T r + e2 + Encode(m)
    v - s^T u = Encode(m) + small error

Deriving r deterministically from message m lets Bob recover m and regenerate
the same r (the seed of the spiral path) as Alice.

This is a toy model for exploring a cryptographic research direction.
It has no security proof, validated parameters, constant-time implementation, or side-channel defenses.
Never use it to protect real data.

Usage:
    python spiral_kem_toy.py
    python spiral_kem_toy.py --self-test --trials 25

No external packages are required. Python 3.10+ is recommended.
"""

from __future__ import annotations

import argparse
import hmac
import secrets
from dataclasses import dataclass
from hashlib import sha3_256, shake_256
from typing import Sequence


DOMAIN = b"Spiral-KEM-v0.1/research-only/"

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
        if self.n <= 0 or self.n % 8 != 0:
            raise ValueError("n must be a positive multiple of 8.")
        if self.k <= 0:
            raise ValueError("k must be positive.")
        if self.q < 5 or self.q >= 65536:
            raise ValueError("This example requires 5 <= q < 65536.")
        if self.eta <= 0:
            raise ValueError("eta must be positive.")

    @property
    def message_bytes(self) -> int:
        return self.n // 8


@dataclass(frozen=True)
class PublicKey:
    matrix_seed: bytes
    spiral_seed: bytes
    t: PolyVec


@dataclass(frozen=True)
class SecretKey:
    s: PolyVec
    public_key: PublicKey
    fallback_secret: bytes


@dataclass(frozen=True)
class Ciphertext:
    u: PolyVec
    v: Poly


@dataclass(frozen=True)
class SpiralDescriptor:
    """Description of public invertible transforms forming U_omega and V_omega."""

    row_permutation: tuple[int, ...]
    row_shifts: tuple[int, ...]
    row_signs: tuple[int, ...]
    column_permutation: tuple[int, ...]
    column_shifts: tuple[int, ...]
    column_signs: tuple[int, ...]


class SpiralKEM:
    """Spiral KEM research model using Module-LWE cancellation."""

    def __init__(self, params: Parameters | None = None) -> None:
        self.p = params or Parameters()

    # ------------------------------------------------------------------
    # Public API.
    # ------------------------------------------------------------------
    def keygen(self) -> tuple[PublicKey, SecretKey]:
        """Generate a public key and secret key."""

        matrix_seed = secrets.token_bytes(32)
        spiral_seed = secrets.token_bytes(32)
        secret_seed = secrets.token_bytes(32)

        b_matrix = self._spiral_matrix(matrix_seed, spiral_seed)
        s = self._small_vector(secret_seed, b"key/s")
        e = self._small_vector(secret_seed, b"key/e")
        t = self._vec_add(self._mat_vec(b_matrix, s), e)

        pk = PublicKey(matrix_seed=matrix_seed, spiral_seed=spiral_seed, t=t)
        sk = SecretKey(
            s=s,
            public_key=pk,
            fallback_secret=secrets.token_bytes(32),
        )
        return pk, sk

    def encapsulate(self, pk: PublicKey) -> tuple[Ciphertext, bytes]:
        """Generate a ciphertext and a 32-byte shared key."""

        message = secrets.token_bytes(self.p.message_bytes)
        ciphertext = self._encrypt_message(pk, message)
        shared_key = self._derive_valid_key(pk, message, ciphertext)
        return ciphertext, shared_key

    def decapsulate(self, sk: SecretKey, ciphertext: Ciphertext) -> bytes:
        """Validate a ciphertext and recover the shared key.

        Invalid ciphertexts return a fallback key without directly exposing a verification error.
        Because Python is not a constant-time environment, this is only conceptual implicit
        rejection and does not provide actual side-channel security.
        """

        shared_key, _ = self.decapsulate_with_status(sk, ciphertext)
        return shared_key

    def decapsulate_with_status(
        self, sk: SecretKey, ciphertext: Ciphertext
    ) -> tuple[bytes, bool]:
        """Also return the verification outcome for testing."""

        pk = sk.public_key

        # Bob cancels the shared movement using secret alignment axis s.
        aligned = self._poly_sub(ciphertext.v, self._dot(sk.s, ciphertext.u))
        recovered_message = self._decode_message(aligned)

        # Regenerate r, e1, e2 from recovered_message and verify the ciphertext again.
        expected = self._encrypt_message(pk, recovered_message)
        valid = hmac.compare_digest(
            self.serialize_ciphertext(ciphertext),
            self.serialize_ciphertext(expected),
        )

        if valid:
            return self._derive_valid_key(pk, recovered_message, ciphertext), True

        fallback = shake_256(
            DOMAIN
            + b"fallback/"
            + sk.fallback_secret
            + self._public_key_hash(pk)
            + sha3_256(self.serialize_ciphertext(ciphertext)).digest()
        ).digest(self.p.key_bytes)
        return fallback, False

    def regenerate_path_seed(self, pk: PublicKey, message: bytes) -> PolyVec:
        """Deterministically regenerate spiral path vector r from m."""

        self._check_message(message)
        coins = self._coin_seed(pk, message)
        return self._small_vector(coins, b"enc/r")

    def spiral_descriptor(self, spiral_seed: bytes) -> SpiralDescriptor:
        """Return construction details for public spiral transforms U_omega, V_omega."""

        row_perm = self._permutation(spiral_seed, b"spiral/row-permutation")
        col_perm = self._permutation(spiral_seed, b"spiral/column-permutation")
        row_shifts = tuple(
            self._number(spiral_seed, b"spiral/row-shift/" + bytes([i])) % self.p.n
            for i in range(self.p.k)
        )
        col_shifts = tuple(
            self._number(spiral_seed, b"spiral/column-shift/" + bytes([i])) % self.p.n
            for i in range(self.p.k)
        )
        row_signs = tuple(
            1
            if self._number(spiral_seed, b"spiral/row-sign/" + bytes([i])) & 1
            else -1
            for i in range(self.p.k)
        )
        col_signs = tuple(
            1
            if self._number(spiral_seed, b"spiral/column-sign/" + bytes([i])) & 1
            else -1
            for i in range(self.p.k)
        )
        return SpiralDescriptor(
            row_permutation=row_perm,
            row_shifts=row_shifts,
            row_signs=row_signs,
            column_permutation=col_perm,
            column_shifts=col_shifts,
            column_signs=col_signs,
        )

    def serialize_public_key(self, pk: PublicKey) -> bytes:
        return (
            DOMAIN
            + b"pk/"
            + self._parameter_bytes()
            + pk.matrix_seed
            + pk.spiral_seed
            + self._pack_vector(pk.t)
        )

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> bytes:
        return self._pack_vector(ciphertext.u) + self._pack_poly(ciphertext.v)

    # ------------------------------------------------------------------
    # KEM core.
    # ------------------------------------------------------------------
    def _encrypt_message(self, pk: PublicKey, message: bytes) -> Ciphertext:
        self._check_message(message)

        coins = self._coin_seed(pk, message)
        r = self._small_vector(coins, b"enc/r")
        e1 = self._small_vector(coins, b"enc/e1")
        e2 = self._small_poly(coins, b"enc/e2")

        b_matrix = self._spiral_matrix(pk.matrix_seed, pk.spiral_seed)
        u = self._vec_add(self._transpose_mat_vec(b_matrix, r), e1)
        v = self._poly_add(
            self._poly_add(self._dot(pk.t, r), e2),
            self._encode_message(message),
        )
        return Ciphertext(u=u, v=v)

    def _coin_seed(self, pk: PublicKey, message: bytes) -> bytes:
        return shake_256(
            DOMAIN + b"coins/" + message + self._public_key_hash(pk)
        ).digest(32)

    def _derive_valid_key(
        self, pk: PublicKey, message: bytes, ciphertext: Ciphertext
    ) -> bytes:
        return shake_256(
            DOMAIN
            + b"shared-key/"
            + message
            + self._public_key_hash(pk)
            + sha3_256(self.serialize_ciphertext(ciphertext)).digest()
        ).digest(self.p.key_bytes)

    # ------------------------------------------------------------------
    # Spiral basis change A -> B = U_omega A V_omega.
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

    def _spiral_matrix(self, matrix_seed: bytes, spiral_seed: bytes) -> PolyMat:
        """Invertibly transform the public matrix with signed permutations and x^j rotations.

        Multiplication by ±x^j in the ring x^n = -1 is an invertible rotation that
        preserves coefficient magnitude. Combine it with row/column permutations to form U_omega, V_omega.
        """

        a_matrix = self._base_matrix(matrix_seed)
        d = self.spiral_descriptor(spiral_seed)

        left = tuple(
            tuple(
                self._mul_monomial(
                    a_matrix[d.row_permutation[i]][j],
                    d.row_shifts[i],
                    d.row_signs[i],
                )
                for j in range(self.p.k)
            )
            for i in range(self.p.k)
        )

        return tuple(
            tuple(
                self._mul_monomial(
                    left[i][d.column_permutation[j]],
                    d.column_shifts[j],
                    d.column_signs[j],
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

    def _mul_monomial(self, poly: Poly, shift: int, sign: int) -> Poly:
        """Multiply poly by sign*x^shift, with sign equal to ±1."""

        if sign not in (-1, 1):
            raise ValueError("sign must be -1 or 1.")
        shift %= self.p.n
        result = [0] * self.p.n
        for i, value in enumerate(poly):
            index = i + shift
            if index < self.p.n:
                result[index] += sign * value
            else:
                result[index - self.p.n] -= sign * value
        return tuple(value % self.p.q for value in result)

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
        """Generate uniform coefficients in [0, q) with 16-bit rejection sampling."""

        limit = 65536 - (65536 % self.p.q)
        coefficients: list[int] = []
        counter = 0

        while len(coefficients) < self.p.n:
            block = shake_256(
                DOMAIN + b"uniform/" + label + seed + counter.to_bytes(4, "little")
            ).digest(256)
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
        stream = shake_256(DOMAIN + b"small/" + label + seed).digest(needed)
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
            bit = 1 if lower < value < upper else 0
            output[index // 8] |= bit << (index % 8)
        return bytes(output)

    def _pack_poly(self, poly: Poly) -> bytes:
        return b"".join((value % self.p.q).to_bytes(2, "little") for value in poly)

    def _pack_vector(self, vector: PolyVec) -> bytes:
        return b"".join(self._pack_poly(poly) for poly in vector)

    def _public_key_hash(self, pk: PublicKey) -> bytes:
        return sha3_256(self.serialize_public_key(pk)).digest()

    def _parameter_bytes(self) -> bytes:
        return b"".join(
            value.to_bytes(4, "little")
            for value in (self.p.n, self.p.k, self.p.q, self.p.eta)
        )

    def _check_message(self, message: bytes) -> None:
        if len(message) != self.p.message_bytes:
            raise ValueError(
                f"Message must be exactly {self.p.message_bytes} bytes."
            )

    def _number(self, seed: bytes, label: bytes) -> int:
        return int.from_bytes(
            shake_256(DOMAIN + b"number/" + label + seed).digest(8), "little"
        )

    def _permutation(self, seed: bytes, label: bytes) -> tuple[int, ...]:
        scored = []
        for index in range(self.p.k):
            score = shake_256(
                DOMAIN + b"permutation/" + label + seed + index.to_bytes(2, "little")
            ).digest(16)
            scored.append((score, index))
        return tuple(index for _, index in sorted(scored))


def tamper_ciphertext(kem: SpiralKEM, ciphertext: Ciphertext) -> Ciphertext:
    """Change the first coefficient of v by 1 for a tamper-rejection experiment."""

    changed = list(ciphertext.v)
    changed[0] = (changed[0] + 1) % kem.p.q
    return Ciphertext(u=ciphertext.u, v=tuple(changed))


def run_self_test(trials: int = 25) -> None:
    if trials <= 0:
        raise ValueError("trials must be positive.")

    kem = SpiralKEM()
    pk, sk = kem.keygen()

    # The same m produces the same r and ciphertext, enabling re-encryption verification.
    fixed_message = bytes(range(kem.p.message_bytes))
    c1 = kem._encrypt_message(pk, fixed_message)
    c2 = kem._encrypt_message(pk, fixed_message)
    assert kem.serialize_ciphertext(c1) == kem.serialize_ciphertext(c2)
    assert kem.regenerate_path_seed(pk, fixed_message) == kem.regenerate_path_seed(
        pk, fixed_message
    )

    for trial in range(1, trials + 1):
        ciphertext, alice_key = kem.encapsulate(pk)
        bob_key, valid = kem.decapsulate_with_status(sk, ciphertext)
        assert valid, f"Valid ciphertext rejected: trial={trial}"
        assert alice_key == bob_key, f"Shared-key mismatch: trial={trial}"

    ciphertext, alice_key = kem.encapsulate(pk)
    forged = tamper_ciphertext(kem, ciphertext)
    forged_key, valid = kem.decapsulate_with_status(sk, forged)
    assert not valid, "Tampered ciphertext was accepted."
    assert forged_key != alice_key, "Tampered ciphertext produced the original shared key."

    base = kem._base_matrix(pk.matrix_seed)
    spiral = kem._spiral_matrix(pk.matrix_seed, pk.spiral_seed)
    descriptor = kem.spiral_descriptor(pk.spiral_seed)
    transformation_is_nontrivial = base != spiral

    print("[PASS] Deterministic r regeneration and re-encryption")
    print(f"[PASS] {trials} valid encapsulation/decapsulation trials")
    print("[PASS] Tampered-ciphertext implicit rejection")
    print(f"[INFO] Public spiral transform is nontrivial: {transformation_is_nontrivial}")
    print(f"[INFO] Spiral transform description: {descriptor}")


def run_demo() -> None:
    kem = SpiralKEM()
    pk, sk = kem.keygen()
    ciphertext, alice_key = kem.encapsulate(pk)
    bob_key, valid = kem.decapsulate_with_status(sk, ciphertext)

    print("Spiral KEM v0.1 research demo")
    print("Educational code; unsuitable for protecting real data.")
    print(
        f"Parameters: n={kem.p.n}, k={kem.p.k}, q={kem.p.q}, eta={kem.p.eta}"
    )
    print(f"Public-key fingerprint: {sha3_256(kem.serialize_public_key(pk)).hexdigest()[:32]}")
    print(f"Ciphertext size: {len(kem.serialize_ciphertext(ciphertext))} bytes")
    print(f"Alice shared key: {alice_key.hex()}")
    print(f"Bob shared key:   {bob_key.hex()}")
    print(f"Match and verification: {alice_key == bob_key and valid}")
    print(f"Spiral transform: {kem.spiral_descriptor(pk.spiral_seed)}")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Spiral KEM research prototype")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run repeated encapsulation and tamper-rejection tests.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=25,
        help="Number of self-test trials (default: 25)",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        run_self_test(args.trials)
    else:
        run_demo()


if __name__ == "__main__":
    main()
