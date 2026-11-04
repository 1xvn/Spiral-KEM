#!/usr/bin/env python3
"""
Karatsuba algorithm and Fast Fourier Transform (FFT) implementations
=========================================================

  Function                    Description                         Time complexity
  ---------------------------  -----------------------------  --------------------------
  karatsuba(x, y)              Big-integer multiplication         O(n^log2(3)) ≈ O(n^1.585)
  fft_recursive(a)             Recursive FFT (educational)        O(n log n)
  fft(a) / ifft(a)             Iterative in-place FFT / inverse    O(n log n)
  multiply_polynomials(a, b)   FFT polynomial convolution          O(n log n)
  fft_multiply(x, y)           FFT big-integer multiplication      O(n log n)

Run:      python karatsuba_fft.py     (correctness tests and a simple benchmark)
Requires: Python 3.8+ / standard library only
"""

from __future__ import annotations

import cmath
import math
import random
import time
from typing import Sequence


# ════════════════════════════════════════════════════════════════
# 1. Karatsuba algorithm.
# ════════════════════════════════════════════════════════════════
def karatsuba(x: int, y: int, threshold_bits: int = 64) -> int:
    """Multiply two integers using the Karatsuba algorithm.

    Split x and y into high/low parts at bit m.
        x = x1 · 2^m + x0
        y = y1 · 2^m + y0

    Then
        x·y = z2 · 2^(2m) + z1 · 2^m + z0
        z2  = x1 · y1
        z0  = x0 · y0
        z1  = x1·y0 + x0·y1 = (x1 + x0)(y1 + y0) - z2 - z0

    Computing z1 needs one multiplication plus additions/subtractions rather than two, reducing
    four recursive products to three: T(n) = 3·T(n/2) + O(n) ⇒ O(n^log2(3)) ≈ O(n^1.585).

    (For decimal splitting, use divmod(x, 10**m) instead of bit operations.
     Binary splitting is used here because shifts/masks are much faster and avoid
     large-integer string-conversion limits.)

    threshold_bits: use built-in multiplication if either operand has at most this many bits.
                    Recursive-call overhead dominates for small operands.
    """
    # Handle signs separately, then operate only on nonnegative integers.
    if x < 0 or y < 0:
        sign = -1 if (x < 0) != (y < 0) else 1
        return sign * karatsuba(abs(x), abs(y), threshold_bits)

    # Base case (minimum 4 bits ensures recursion terminates).
    if min(x.bit_length(), y.bit_length()) <= max(threshold_bits, 4):
        return x * y

    m = max(x.bit_length(), y.bit_length()) // 2  # Split position in bits.
    mask = (1 << m) - 1
    x1, x0 = x >> m, x & mask
    y1, y0 = y >> m, y & mask

    z0 = karatsuba(x0, y0, threshold_bits)
    z2 = karatsuba(x1, y1, threshold_bits)
    z1 = karatsuba(x0 + x1, y0 + y1, threshold_bits) - z0 - z2

    return (z2 << (2 * m)) + (z1 << m) + z0


# ════════════════════════════════════════════════════════════════
# 2. Fast Fourier Transform (FFT).
# ════════════════════════════════════════════════════════════════
# Discrete Fourier Transform (DFT): X[k] = Σ_{j=0}^{n-1} a[j] · ω^(jk), ω = e^(-2πi/n).
# The inverse DFT uses ω^-1 and divides by n at the end.
# Same sign convention as NumPy numpy.fft.fft / ifft.
def _check_power_of_two(n: int) -> None:
    if n < 1 or (n & (n - 1)) != 0:
        raise ValueError(f"Input length must be a power of two (got {n}).")


def _next_power_of_two(n: int) -> int:
    return 1 << (max(n, 1) - 1).bit_length()


def dft_naive(a: Sequence[complex], invert: bool = False) -> list[complex]:
    """Direct O(n²) DFT from the definition, for validation."""
    n = len(a)
    sign = 1 if invert else -1
    out = [
        sum(a[j] * cmath.exp(sign * 2j * math.pi * j * k / n) for j in range(n))
        for k in range(n)
    ]
    return [v / n for v in out] if invert else out


def _fft_rec(a: list[complex], sign: int) -> list[complex]:
    n = len(a)
    if n == 1:
        return a
    even = _fft_rec(a[0::2], sign)  # DFT of even-indexed elements.
    odd = _fft_rec(a[1::2], sign)  # DFT of odd-indexed elements.
    half = n // 2
    out = [0j] * n
    for k in range(half):
        t = cmath.exp(sign * 2j * math.pi * k / n) * odd[k]  # ω^k · O[k]
        out[k] = even[k] + t
        out[k + half] = even[k] - t
    return out


def fft_recursive(a: Sequence[complex], invert: bool = False) -> list[complex]:
    """Recursive radix-2 Cooley-Tukey FFT for studying the algorithm.

    Split even/odd indices and compute their DFTs E and O:
        X[k]       = E[k] + ω^k · O[k]
        X[k + n/2] = E[k] - ω^k · O[k]        (k = 0 .. n/2 - 1)
    T(n) = 2·T(n/2) + O(n)  ⇒  O(n log n).
    """
    n = len(a)
    _check_power_of_two(n)
    out = _fft_rec([complex(v) for v in a], 1 if invert else -1)
    return [v / n for v in out] if invert else out


def fft(a: Sequence[complex], invert: bool = False) -> list[complex]:
    """Iterative in-place FFT: bit reversal and butterflies without recursive calls."""
    n = len(a)
    _check_power_of_two(n)
    a = [complex(v) for v in a]  # Copy to avoid modifying the input.

    # (1) Rearrange into bit-reversed order.
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    # (2) Build butterflies for lengths 2, 4, 8, ... n.
    #     Compute twiddle factors directly to avoid accumulating their rounding error.
    sign = 1 if invert else -1
    roots = [cmath.exp(sign * 2j * math.pi * k / n) for k in range(n // 2)]
    length = 2
    while length <= n:
        half = length // 2
        step = n // length
        for start in range(0, n, length):
            for k in range(half):
                u = a[start + k]
                v = a[start + k + half] * roots[k * step]
                a[start + k] = u + v
                a[start + k + half] = u - v
        length <<= 1

    if invert:
        a = [v / n for v in a]
    return a


def ifft(a: Sequence[complex]) -> list[complex]:
    """Inverse FFT."""
    return fft(a, invert=True)


# ════════════════════════════════════════════════════════════════
# 3. Multiplication using FFT.
# ════════════════════════════════════════════════════════════════
def multiply_polynomials(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Multiply integer-coefficient polynomials by FFT; a[i], b[i] are coefficients of x^i.

    Polynomial multiplication is coefficient convolution, which becomes pointwise multiplication in Fourier space.
        FFT(a), FFT(b) → elementwise product → IFFT (O(n log n)).
    Round assuming integer coefficients. For real coefficients, use .real without round.
    """
    if not a or not b:
        return []
    result_len = len(a) + len(b) - 1
    n = _next_power_of_two(result_len)  # Zero-pad to a power-of-two length.

    fa = fft(list(a) + [0] * (n - len(a)))
    fb = fft(list(b) + [0] * (n - len(b)))
    fc = ifft([p * q for p, q in zip(fa, fb)])
    return [round(v.real) for v in fc[:result_len]]


def fft_multiply(x: int, y: int) -> int:
    """Multiply large integers by FFT.

    Treat integers as lists of base-256 digits (bytes), compute their convolution,
    and propagate carries to obtain the product.

    Floating-point FFT can round incorrectly for very large inputs (roughly hundreds of thousands of bytes).
    Use an integer NTT if exactness is essential.
    """
    if x == 0 or y == 0:
        return 0
    sign = -1 if (x < 0) != (y < 0) else 1
    x, y = abs(x), abs(y)

    # (1) Little-endian bytes are base-256 digits (each at most 255).
    a = list(x.to_bytes((x.bit_length() + 7) // 8, "little"))
    b = list(y.to_bytes((y.bit_length() + 7) // 8, "little"))

    # (2) Convolution: c[k] = Σ a[i] · b[k-i].
    c = multiply_polynomials(a, b)

    # (3) Carry propagation (O(n)).
    out = bytearray()
    carry = 0
    for v in c:
        carry += v
        out.append(carry & 0xFF)
        carry >>= 8
    while carry:
        out.append(carry & 0xFF)
        carry >>= 8

    return sign * int.from_bytes(out, "little")


# ════════════════════════════════════════════════════════════════
# 4. Tests and benchmarks.
# ════════════════════════════════════════════════════════════════
def _schoolbook_convolution(a: Sequence[int], b: Sequence[int]) -> list[int]:
    c = [0] * (len(a) + len(b) - 1)
    for i, p in enumerate(a):
        for j, q in enumerate(b):
            c[i + j] += p * q
    return c


def _max_error(u: Sequence[complex], v: Sequence[complex]) -> float:
    return max(abs(p - q) for p, q in zip(u, v))


def _random_pair(rng: random.Random, bits: int) -> tuple[int, int]:
    """Integer pairs with varying signs and lengths."""
    x = rng.getrandbits(bits) * rng.choice((1, -1))
    y = rng.getrandbits(rng.randint(1, bits)) * rng.choice((1, -1))
    return x, y


def run_tests() -> None:
    rng = random.Random(0)
    edge = [(0, 0), (0, 12345), (1, 1), (-7, 9), (-7, -9), (2**200, 2**200 - 1)]

    # --- Karatsuba ---
    for x, y in edge:
        assert karatsuba(x, y) == x * y
    for bits in (8, 64, 65, 100, 1000, 10_000):
        for _ in range(100):
            x, y = _random_pair(rng, bits)
            assert karatsuba(x, y) == x * y
            if bits <= 1000:  # Exercise deeper recursion.
                assert karatsuba(x, y, threshold_bits=8) == x * y
    print("[OK] karatsuba")

    # --- FFT: compare with the naive DFT definition and check inversion ---
    for n in (1, 2, 4, 8, 16, 64, 128):
        a = [complex(rng.uniform(-1, 1), rng.uniform(-1, 1)) for _ in range(n)]
        ref = dft_naive(a)
        assert _max_error(fft_recursive(a), ref) < 1e-9
        assert _max_error(fft(a), ref) < 1e-9
        assert _max_error(ifft(fft(a)), a) < 1e-9
        assert _max_error(fft_recursive(fft_recursive(a), invert=True), a) < 1e-9
    try:
        fft([1, 2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("Length-three input must be rejected")
    print("[OK] fft / ifft / fft_recursive")

    # --- FFT polynomial multiplication ---
    for la, lb in ((1, 1), (1, 5), (7, 3), (50, 80), (200, 200)):
        a = [rng.randint(-1000, 1000) for _ in range(la)]
        b = [rng.randint(-1000, 1000) for _ in range(lb)]
        assert multiply_polynomials(a, b) == _schoolbook_convolution(a, b)
    print("[OK] multiply_polynomials")

    # --- FFT integer multiplication ---
    for x, y in edge:
        assert fft_multiply(x, y) == x * y
    for bits, reps in ((8, 50), (100, 50), (1000, 30), (10_000, 5)):
        for _ in range(reps):
            x, y = _random_pair(rng, bits)
            assert fft_multiply(x, y) == x * y
    print("[OK] fft_multiply")


def _best_time(fn, *args, repeat: int = 3) -> float:
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - start)
    return best


def benchmark() -> None:
    """Compare timing growth when input size doubles.

    Theoretical growth is approximately 3x for Karatsuba and 2x plus overhead for FFT.
    Built-in multiplication is implemented in C (CPython also uses Karatsuba for large integers)
    and is much faster than pure Python. Only growth trends are compared here.
    """
    rng = random.Random(42)
    print("Timing growth when size doubles (ms; parentheses show the ratio to the preceding row)")
    print(f"{'bits':>8} | {'built-in *':>10} | {'karatsuba':>18} | {'fft_multiply':>18}")
    prev_k = prev_f = None
    for bits in (2**12, 2**13, 2**14, 2**15, 2**16):
        x, y = rng.getrandbits(bits), rng.getrandbits(bits)
        assert karatsuba(x, y) == fft_multiply(x, y) == x * y

        t_b = _best_time(lambda: x * y)
        t_k = _best_time(karatsuba, x, y)
        t_f = _best_time(fft_multiply, x, y)

        r_k = f"(x{t_k / prev_k:.1f})" if prev_k else ""
        r_f = f"(x{t_f / prev_f:.1f})" if prev_f else ""
        print(
            f"{bits:>8} | {t_b * 1e3:>10.3f} | "
            f"{t_k * 1e3:>10.2f} {r_k:>7} | {t_f * 1e3:>10.2f} {r_f:>7}"
        )
        prev_k, prev_f = t_k, t_f


if __name__ == "__main__":
    run_tests()
    print()
    benchmark()
