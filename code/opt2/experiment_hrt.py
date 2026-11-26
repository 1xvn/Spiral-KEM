"""Paired, deterministic OPT2 message-encoding experiment with public fixtures."""

import argparse
from collections import Counter
from hashlib import sha256, shake_256
from itertools import product
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys
from unittest.mock import call, patch

import spiral_kem_toy_v031_opt2 as opt2


ROOT = Path(__file__).resolve().parents[2]
Q = 3329
MULTIPLIER = 1729
CENTERS = (0, 832, 1664, 2496)
PAIRS = 128
RADIUS = 6
COMBINED_RADIUS = 831
COMBINED_OFFSET = 800
FIXTURE_DOMAIN = b"Spiral-OPT2-HRT-paired-experiment-v1\0"


def project(u: int, v: int) -> int:
    return (u + MULTIPLIER * v) % Q


def square_shell(radius: int):
    """Enumerate integer pairs with max(abs(u), abs(v)) == radius."""
    for u in range(-radius, radius + 1):
        yield u, -radius
        yield u, radius
    for v in range(-radius + 1, radius):
        yield -radius, v
        yield radius, v


def projected_distances() -> tuple[int, ...]:
    distances = [-1] * Q
    distances[0] = 0
    remaining = Q - 1
    # Every residue has a signed lift with v = 0 and |u| <= Q // 2.
    for radius in range(1, Q // 2 + 1):
        for u, v in square_shell(radius):
            residue = project(u, v)
            if distances[residue] == -1:
                distances[residue] = radius
                remaining -= 1
        if remaining == 0:
            return tuple(distances)
    raise RuntimeError("Some projected residues are unreachable")


def decoder_table() -> tuple[tuple[int, ...], dict]:
    distances = projected_distances()
    symbols = []
    ties = Counter()
    for residue in range(Q):
        costs = [distances[(residue - center) % Q] for center in CENTERS]
        best = min(costs)
        winners = [symbol for symbol, cost in enumerate(costs) if cost == best]
        symbols.append(winners[0])
        if len(winners) > 1:
            ties[len(winners)] += 1
    return tuple(symbols), {
        "residues_classified": len(symbols),
        "tie_policy": "choose the lowest numeric two-bit symbol among minimum-cost symbols",
        "tied_residues": sum(ties.values()),
        "ties_by_number_of_minimizing_symbols": dict(sorted(ties.items())),
        "decoded_residues_per_symbol": {f"{symbol:02b}": symbols.count(symbol) for symbol in range(4)},
    }


def observation_sets(radius: int) -> tuple[set[int], ...]:
    return tuple(
        {project(center + u, v) for u, v in product(range(-radius, radius + 1), repeat=2)}
        for center in CENTERS
    )


def verify_bound(table: tuple[int, ...]) -> dict:
    observations = observation_sets(RADIUS)
    expected_per_symbol = (2 * RADIUS + 1) ** 2
    union_size = len(set.union(*observations))
    if (any(len(values) != expected_per_symbol for values in observations)
            or union_size != expected_per_symbol * len(CENTERS)
            or any(table[value] != symbol
                   for symbol, values in enumerate(observations) for value in values)):
        raise RuntimeError("Radius-six observations are not distinct and correctly decoded")
    first = project(CENTERS[0] + 3, -6)
    second = project(CENTERS[1] - 3, 7)
    if first != 2945 or second != first:
        raise RuntimeError("The fixed radius-seven collision was not reproduced")
    return {
        "guaranteed_max_absolute_coefficient_error": RADIUS,
        "observations_per_symbol": [len(values) for values in observations],
        "distinct_observations": union_size,
        "radius_seven_collision": {
            "00": [3, -6],
            "01": [-3, 7],
            "residue": first,
            "decoded_symbol": f"{table[first]:02b}",
        },
    }


class HRTExperiment(opt2.SpiralKEM):
    """Experiment-only codec. All other OPT2 operations are inherited."""

    result_name = "hrt"
    guaranteed_radius = RADIUS

    def __init__(self, table: tuple[int, ...]):
        super().__init__()
        self._table = table

    def _encode_message(self, message: bytes) -> opt2.Poly:
        self._check_message(message)
        bits = int.from_bytes(message, "little")
        symbols = [((bits >> j) & 1) | (((bits >> (j + PAIRS)) & 1) << 1) for j in range(PAIRS)]
        return tuple(CENTERS[symbol] for symbol in symbols) + (0,) * PAIRS

    def _decode_message(self, poly: opt2.Poly) -> bytes:
        bits = 0
        for j in range(PAIRS):
            symbol = self._table[project(poly[j], poly[j + PAIRS])]
            bits |= (symbol & 1) << j
            bits |= (symbol >> 1) << (j + PAIRS)
        return bits.to_bytes(self.p.message_bytes, "little")


class CombinedHRTExperiment(opt2.SpiralKEM):
    """Read an OPT2 bit, then undo its shift before reading the other bit."""

    result_name = "combined"
    guaranteed_radius = COMBINED_RADIUS

    def __init__(self):
        super().__init__()
        # Derive the per-coefficient truth table from the unchanged OPT2
        # decoder. Both the polynomial decoder and the exhaustive check use it.
        bit_table = []
        for start in range(0, Q, self.p.n):
            residues = tuple(range(start, min(start + self.p.n, Q)))
            poly = residues + (0,) * (self.p.n - len(residues))
            bits = int.from_bytes(super()._decode_message(poly), "little")
            bit_table.extend((bits >> i) & 1 for i in range(len(residues)))
        self._bit_table = tuple(bit_table)

    @staticmethod
    def encode_pair(a: int, b: int) -> tuple[int, int]:
        return (Q // 2) * a, ((Q // 2) * b + COMBINED_OFFSET * a) % Q

    def decode_pair(self, x: int, y: int) -> tuple[int, int]:
        a = self._bit_table[x % Q]
        b = self._bit_table[(y - COMBINED_OFFSET * a) % Q]
        return a, b

    def _encode_message(self, message: bytes) -> opt2.Poly:
        self._check_message(message)
        bits = int.from_bytes(message, "little")
        pairs = [
            self.encode_pair((bits >> j) & 1, (bits >> (j + PAIRS)) & 1)
            for j in range(PAIRS)
        ]
        xs, ys = zip(*pairs, strict=True)
        return xs + ys

    def _decode_message(self, poly: opt2.Poly) -> bytes:
        bits = 0
        for j in range(PAIRS):
            a, b = self.decode_pair(poly[j], poly[j + PAIRS])
            bits |= (a << j) | (b << (j + PAIRS))
        return bits.to_bytes(self.p.message_bytes, "little")


def verify_combined_bound(candidate: CombinedHRTExperiment) -> dict:
    radius = candidate.guaranteed_radius
    errors = range(-radius, radius + 1)
    geometry = {}
    cases_checked = 0
    for a, b in product(range(2), repeat=2):
        x, y = candidate.encode_pair(a, b)
        projected = project(x, y)
        if projected != COMBINED_OFFSET * b:
            raise RuntimeError("Combined representative projects to the wrong class")
        expected = (a, b)
        observed_xs = [(x + error) % Q for error in errors]
        observed_ys = [(y + error) % Q for error in errors]
        checked = 0
        for observed_x, observed_y in product(observed_xs, observed_ys):
            if candidate.decode_pair(observed_x, observed_y) != expected:
                raise RuntimeError("Combined pair failed within the guaranteed radius")
            checked += 1
        geometry[f"{a}{b}"] = {
            "representative": (x, y),
            "projection": projected,
            "error_cases_checked": checked,
        }
        cases_checked += checked

    collision = (0, 832)
    x0, y0 = candidate.encode_pair(0, 0)
    x1, y1 = candidate.encode_pair(0, 1)
    if (x0, (y0 + 832) % Q) != collision or (x1, (y1 - 832) % Q) != collision:
        raise RuntimeError("The fixed radius-832 collision was not reproduced")
    decoded_a, decoded_b = candidate.decode_pair(*collision)
    return {
        "guaranteed_max_absolute_coefficient_error": radius,
        "coefficient_pair_error_cases_checked": cases_checked,
        "symbols": geometry,
        "radius_832_collision": {
            "00": (0, 832),
            "01": (0, -832),
            "observed_pair": collision,
            "decoded_symbol": f"{decoded_a}{decoded_b}",
        },
    }


def fixtures(trial: int) -> tuple[tuple[bytes, ...], bytes]:
    stream = shake_256(FIXTURE_DOMAIN + trial.to_bytes(8, "little")).digest(128)
    return (stream[:32], stream[32:64], stream[64:96]), stream[96:]


class Measurements:
    def __init__(self):
        self.message_failures = 0
        self.shared_key_mismatches = 0
        self.compact_sizes = Counter()
        self.legacy_sizes = Counter()

    def evaluate(self, kem, sk, message, ciphertext, expected_key):
        compact = kem.serialize_ciphertext_compact(ciphertext)
        restored = kem.deserialize_ciphertext_compact(compact)
        legacy = kem.serialize_ciphertext(ciphertext)
        restored_legacy = kem.deserialize_ciphertext(legacy)
        if restored != ciphertext or restored_legacy != ciphertext:
            raise RuntimeError("OPT2 wire codec changed ciphertext coefficients")

        # Both wire formats restore the same coefficients. Inspect the decoder
        # input once and run the existing decapsulation for each restored object.
        aligned = kem._poly_sub(restored.v, kem._dot(sk.s, restored.u))
        recovered = kem._decode_message(aligned)
        failed = recovered != message
        actual_key = kem.decapsulate(sk, restored)
        if kem.decapsulate(sk, restored_legacy) != actual_key:
            raise RuntimeError("OPT2 decapsulation disagrees between wire formats")
        self.compact_sizes[len(compact)] += 1
        self.legacy_sizes[len(legacy)] += 1
        self.message_failures += failed
        self.shared_key_mismatches += actual_key != expected_key
        return aligned, failed

    def report(self, max_coefficient_error):
        return {
            "full_message_failures": self.message_failures,
            "shared_key_mismatches": self.shared_key_mismatches,
            "max_absolute_coefficient_error": max_coefficient_error,
            "serialized_ciphertext_sizes_bytes": {
                "skw1": dict(sorted(self.compact_sizes.items())),
                "legacy": dict(sorted(self.legacy_sizes.items())),
            },
        }


def paired_trials(trials: int, candidate: HRTExperiment | CombinedHRTExperiment) -> dict:
    baseline = opt2.SpiralKEM()
    if (baseline.p.n, baseline.p.k, baseline.p.q, baseline.p.eta, baseline.p.message_bytes) != (256, 2, Q, 1, 32):
        raise RuntimeError("This experiment requires the original OPT2 profile")

    bit_results, candidate_results = Measurements(), Measurements()
    radius = candidate.guaranteed_radius
    completed = 0
    out_of_radius = 0
    messages_out_of_radius = 0
    distinct_ciphertexts = 0
    max_pair_error = 0
    pair_error_histogram = Counter()
    for trial in range(trials):
        seeds, message = fixtures(trial)
        with patch.object(opt2.secrets, "token_bytes", side_effect=(*seeds, message, message)) as rng:
            pk, sk = baseline.keygen()
            bit_ct, bit_key = baseline.encapsulate(pk)
            candidate_ct, candidate_key = candidate.encapsulate(pk)
            if rng.call_args_list != [call(32)] * 5:
                raise RuntimeError("OPT2 random input consumption changed")
        # Both encapsulations derive identical coins from the same key and message.
        if bit_ct.u != candidate_ct.u:
            raise RuntimeError("The paired ciphertexts do not share the same randomness")
        distinct_ciphertexts += bit_ct != candidate_ct
        bit_aligned, _ = bit_results.evaluate(baseline, sk, message, bit_ct, bit_key)
        candidate_aligned, candidate_failed = candidate_results.evaluate(
            candidate, sk, message, candidate_ct, candidate_key
        )
        bit_noise = baseline._poly_sub(bit_aligned, baseline._encode_message(message))
        candidate_noise = candidate._poly_sub(candidate_aligned, candidate._encode_message(message))
        if bit_noise != candidate_noise:
            raise RuntimeError("The paired pre-decoding coefficient errors differ")
        signed = tuple((error + Q // 2) % Q - Q // 2 for error in candidate_noise)
        maxima = [max(abs(signed[j]), abs(signed[j + PAIRS])) for j in range(PAIRS)]
        pair_error_histogram.update(maxima)
        beyond = sum(value > radius for value in maxima)
        out_of_radius += beyond
        messages_out_of_radius += beyond > 0
        max_pair_error = max(max_pair_error, max(maxima))
        if candidate_failed and not beyond:
            raise RuntimeError("A full-message failure occurred within the proven bound")
        completed += 1

    return {
        "trials": trials,
        "completed_comparisons": completed,
        "distinct_baseline_candidate_ciphertexts": distinct_ciphertexts,
        "wire_formats_decapsulated_per_encoding": ["skw1", "legacy"],
        "baseline": bit_results.report(max_pair_error),
        candidate.result_name: candidate_results.report(max_pair_error) | {
            "coefficient_pairs": completed * PAIRS,
            f"coefficient_pairs_outside_radius_{radius}": out_of_radius,
            f"messages_with_pairs_outside_radius_{radius}": messages_out_of_radius,
            "max_pair_error": max_pair_error,
            "pair_error_max_absolute_histogram": dict(sorted(pair_error_histogram.items())),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", choices=("projection", "combined"), default="projection")
    args = parser.parse_args()
    if not 0 < args.trials <= 2**64:
        parser.error("--trials must be positive and fit the 64-bit fixture index")
    if args.output.exists():
        parser.error("--output already exists; select a new result path")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()
    worktree = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "-uall"], cwd=ROOT, text=True
    ).splitlines()
    sources = [Path(__file__).resolve(), Path(opt2.__file__).resolve()]
    source_hashes = {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest() for path in sources}
    result = {
        "schema": ("spiral-opt2-hrt-combined-experiment/v1" if args.candidate == "combined"
                   else "spiral-opt2-hrt-experiment/v1"),
        "checkout_branch": branch,
        "checkout_commit": commit,
        "worktree_before_run_porcelain": worktree,
        "source_sha256": source_hashes,
        "command": shlex.join(sys.orig_argv),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "profile": {"n": 256, "k": 2, "q": Q, "eta": 1, "message_bytes": 32},
        "fixture_domain_hex": FIXTURE_DOMAIN.hex(),
        "fixture_derivation": "SHAKE256(domain || uint64_le(trial), 128 bytes); 3 keygen seeds then one shared message",
        "trial_indices": [0, args.trials - 1],
    }
    if args.candidate == "combined":
        candidate = CombinedHRTExperiment()
        result["hrt"] = {
            "projection_multiplier": MULTIPLIER,
            "pair_indices": "j and j+128 for j=0..127",
            "symbol_bit_order": "ab: a is bit j, b is bit j+128",
            "class_projection": "800*b mod 3329",
            "decoder": "a=OPT2(x); b=OPT2((y-800*a) mod 3329)",
        }
        result["mathematical_check"] = verify_combined_bound(candidate)
    else:
        table, decoder = decoder_table()
        candidate = HRTExperiment(table)
        result["hrt"] = {
            "projection_multiplier": MULTIPLIER,
            "centers_by_symbol": CENTERS,
            "representatives_by_symbol": [(center, 0) for center in CENTERS],
            "pair_indices": "j and j+128 for j=0..127",
            "symbol_bit_order": "low bit j and high bit j+128 of the little-endian message",
            "decoder_cost": "min(max(abs(e_u), abs(e_v))) over integer lifts of residue minus center",
        }
        result["mathematical_check"] = verify_bound(table)
        result["decoder"] = decoder
    result["paired_measurements"] = paired_trials(args.trials, candidate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(args.output)


if __name__ == "__main__":
    main()
