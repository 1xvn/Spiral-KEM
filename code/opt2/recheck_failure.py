"""Recalculate the honest OPT2 decoding-failure bounds from the repository root."""

import json
import math
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from fractions import Fraction
from hashlib import sha256, shake_256
from pathlib import Path
from zipfile import ZipFile

from spiral_kem_toy_v031_opt2 import PublicKey, SpiralKEM


ROOT = Path(__file__).resolve().parents[2]
SIX = Path("archives/research/Spiral_KEM_six_candidates_results.zip")
BENCH = Path("results/results.zip")
PREFIX = "spiral-six-candidate-assessment/results/"


def coefficient_counts(n, k):
    """Integer masses in ascending signed-error order, for ideal independent CBD1."""
    m = 2 * n * k
    # For P=(1+6x+x²)^m, compare coefficients in (1+6x+x²)P'=m(6+2x)P.
    products = [1]
    for j in range(1, 2 * m + 1):
        prev2 = products[j - 2] if j >= 2 else 0
        mass, remainder = divmod(
            6 * (m - j + 1) * products[-1] + (2 * m - j + 2) * prev2, j
        )
        if remainder or mass < 0:
            raise ArithmeticError("Invalid polynomial recurrence")
        products.append(mass)
    padded = [0, 0, *products, 0, 0]
    counts = [a + 2 * b + c for a, b, c in zip(padded, padded[1:], padded[2:])]
    if sum(counts) != 4 * 8**m or counts != counts[::-1]:
        raise ArithmeticError("Invalid coefficient mass or symmetry")
    return counts


def decoded(value, q):
    """Classify by circular distance, with ties assigned to zero."""
    zero, one = value % q, (value - q // 2) % q
    return int(min(one, q - one) < min(zero, q - zero))


def failure_counts(counts, q):
    radius = len(counts) // 2
    return [
        sum(mass for error, mass in enumerate(counts, -radius)
            if decoded(bit * (q // 2) + error, q) != bit)
        for bit in (0, 1)
    ]


def chernoff_endpoint(tails, m, n, rounding):
    """Enclose the archived B(832)+B(833) calculation on one side."""
    with localcontext() as ctx:
        ctx.prec = 110
        ctx.rounding = rounding

        def exp_endpoint(x):
            # Decimal.exp is correctly rounded to nearest, independently of ctx.rounding.
            y = x.exp()
            return y.next_minus() if rounding == ROUND_FLOOR else y.next_plus()

        total = Decimal(0)
        for a in (832, 833):
            rational_t = Fraction(tails[str(a)]["positive_t_exact"])
            t = Decimal(rational_t.numerator) / Decimal(rational_t.denominator)
            if Fraction(t) != rational_t or t <= 0 or Fraction(-a * t) != -a * rational_t:
                raise ValueError("Archived tilt must be positive and exactly representable")
            pair = exp_endpoint(t) + exp_endpoint(-t)
            product_mgf = (pair + 6) / 8
            tail = exp_endpoint(-a * t) * ((pair + 2) / 4)
            for _ in range(m):
                tail *= product_mgf
            total += tail
        return n * total


def archived_trials(kem, archive):
    data = archive.read(PREFIX + "correctness/A_k2_eta1.jsonl")
    summary = json.loads(archive.read(PREFIX + "correctness/A_k2_eta1.json"))
    weights = []
    mismatches = 0
    seen = set()
    for trial, line in enumerate(data.splitlines()):
        row = json.loads(line)
        seed = bytes.fromhex(row["fixture_seed_hex"])
        if (row["trial"] != trial or len(seed) != 32 or seed in seen or "error" in row
                or type(row["key_mismatch"]) is not bool):
            raise ValueError(f"Invalid archived trial {trial}")
        seen.add(seed)
        mismatches += row["key_mismatch"]
        # Rebuild only the public experimental key, using the archived common.py fixture.
        stream = shake_256(b"Spiral-six-candidate-test-fixture-v1/" + seed).digest(128)
        rho, sigma = stream[:32], stream[32:64]
        s = kem._small_vector(sigma, b"key/s")
        e = kem._small_vector(sigma, b"key/e")
        t = kem._vec_add(kem._mat_vec(kem._base_matrix(rho), s), e)
        digest = sha256(kem.serialize_public_key(PublicKey(rho, t))).hexdigest()
        if digest != row["pk_sha256"]:
            raise ValueError(f"Public fixture key mismatch at trial {trial}")
        weights.append(sum(x != 0 for poly in (*s, *e) for x in poly))
    count = len(weights)
    if (count, mismatches, summary["exceptions"]) != (summary["trials"], summary["key_mismatches"], 0):
        raise ValueError("Archived rows disagree with summary")
    return {
        "jsonl_sha256": sha256(data).hexdigest(),
        "archived_exchanges": count,
        "archived_shared_key_mismatches": mismatches,
        "additional_random_exchanges": 0,
        "iid_fixture_one_sided_95_upper": -math.expm1(math.log(0.05) / count) if mismatches == 0 else None,
        "public_key_hashes_reproduced": count,
        "min_nonzero_s_and_e": min(weights),
        "max_nonzero_s_and_e": max(weights),
        "keys_certified_for_all_honest_messages": sum(w + 1 <= 831 for w in weights),
    }


def report():
    kem = SpiralKEM()
    n, k, q = kem.p.n, kem.p.k, kem.p.q
    if (n, k, q, kem.p.eta, kem.p.key_bytes) != (256, 2, 3329, 1, 32):
        raise ValueError("Re-derive the decoder thresholds for the changed default profile")
    m = 2 * k * n
    counts = coefficient_counts(n, k)
    failures = failure_counts(counts, q)
    exponent = 3 * m + 2
    union = min(1 << exponent, n * max(failures))
    with ZipFile(ROOT / SIX) as archive:
        cert = json.loads(archive.read(PREFIX + "failure-bounds/A_k2_eta1.json"))
        tails = cert["one_sided_tail_certificates"]
        lo = chernoff_endpoint(tails, m, n, ROUND_FLOOR)
        hi = chernoff_endpoint(tails, m, n, ROUND_CEILING)
        saved = cert["full_message_union_upper"]
        if not (Fraction(saved["lower_rational"]) <= Fraction(lo) <= Fraction(hi)
                <= Fraction(saved["upper_rational"])):
            raise ValueError("Recomputed Chernoff interval falls outside the archived interval")
        exact_union = Fraction(union, 1 << exponent)
        if not exact_union <= Fraction(lo) <= Fraction(hi) <= Fraction(1, 2**1850):
            raise ArithmeticError("Inconsistent ideal-model bounds")
        fixtures = archived_trials(kem, archive)
    with ZipFile(ROOT / BENCH) as archive:
        benchmarks = {}
        for name in sorted(archive.namelist()):
            if name.startswith("json/Spiral_opt2_MLKEM_comparison_") and name.endswith(".json"):
                result = json.loads(archive.read(name))["implementations"]["opt2"]
                benchmarks[name] = {"exchanges": result["samples"], "shared_key_mismatches": result["key_mismatches"]}
    # If at most 830 of the 2kn key-side coefficients are nonzero,
    # every |E_i| <= 831, regardless of the encryption coins or the message.
    heavy = sum(math.comb(m, j) for j in range(831, m + 1))
    sources = (SIX, BENCH, Path("code/opt2/spiral_kem_toy_v031_opt2.py"),
               Path("native_research/spiral_native.c"), Path("originals/spiral_kem_v03_math_spec.md"))
    return {
        "profile": {"n": n, "k": k, "q": q, "eta": 1, "key_bytes": 32},
        "source_sha256": {str(path): sha256((ROOT / path).read_bytes()).hexdigest() for path in sources},
        "ideal_independent_cbd1": {
            "max_abs_integer_error": m + 1,
            "common_denominator_log2": exponent,
            "bit_failure_numerators": [str(x) for x in failures],
            "bit_failure_log2_approx": [math.log2(x) - exponent for x in failures],
            "message_union_bound_numerator": str(union),
            "message_union_bound_log2_approx": math.log2(union) - exponent,
            "archived_chernoff_t": {a: tails[a]["positive_t_exact"] for a in ("832", "833")},
            "chernoff_message_bound_interval": [str(lo), str(hi)],
            "chernoff_message_bound_log2_approx": float(hi.ln() / Decimal(2).ln()),
        },
        "fixed_shake": {
            "sufficient_max_nonzero_s_and_e": 830,
            "unconditional_numeric_default_failure_rate": None,
        },
        "iid_key_coefficients_only": {
            "message_failure_upper_numerator": str(heavy), "denominator_log2": m,
            "upper_log2_approx": math.log2(heavy) - m,
        },
        "historical_observations": {"baseline_A": fixtures, "opt2_benchmarks": benchmarks},
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, allow_nan=False))
