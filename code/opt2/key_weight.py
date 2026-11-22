"""Collect and replay the predeclared OPT2 fixed-SHAKE key-weight sample."""

import argparse
import csv
import gzip
import hashlib
import json
import math
import secrets
from pathlib import Path

import spiral_kem_toy_v031_opt2 as opt2


DRAWS = 2995
HEAVY = 831
HEADER = ["sigma_hex", "weight"]
PROFILE = (256, 2, 3329, 1, 32)


def collect(path):
    kem = opt2.SpiralKEM()
    p = kem.p
    if (p.n, p.k, p.q, p.eta, p.key_bytes) != PROFILE:
        raise ValueError("The sampling plan applies only to the pinned default profile")
    with gzip.open(path, "xt", newline="", encoding="ascii") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(HEADER)
        for _ in range(DRAWS):
            sigma = secrets.token_bytes(32)
            s = kem._small_vector(sigma, b"key/s")
            e = kem._small_vector(sigma, b"key/e")
            weight = sum(x != 0 for poly in (*s, *e) for x in poly)
            writer.writerow([sigma.hex(), weight])


def reference_weight(sigma):
    # For CBD1, the positive-minus-negative result is nonzero iff the low bits differ.
    n, k, _, _, _ = PROFILE
    domain = b"Spiral-KEM-v0.3/research-only/" + b"".join(x.to_bytes(4, "little") for x in PROFILE)
    weight = 0
    for prefix in (b"small/key/s/", b"small/key/e/"):
        for i in range(k):
            label = prefix + i.to_bytes(2, "little")
            frame = domain + len(label).to_bytes(2, "little") + label + sigma
            data = hashlib.shake_256(frame).digest(2 * n)
            weight += sum((x ^ y) & 1 for x, y in zip(data[::2], data[1::2]))
    return weight


def review(path):
    weights = []
    with gzip.open(path, "rt", newline="", encoding="ascii") as stream:
        reader = csv.reader(stream)
        if next(reader, None) != HEADER:
            raise ValueError("Invalid sample header")
        for i, (text, recorded) in enumerate(reader, 1):
            if i > DRAWS:
                raise ValueError("Sample exceeds fixed budget")
            sigma = bytes.fromhex(text)
            if len(sigma) != 32 or text != sigma.hex():
                raise ValueError(f"Invalid seed at draw {i}")
            weight = reference_weight(sigma)
            if str(weight) != recorded:
                raise ValueError(f"Weight mismatch at draw {i}")
            weights.append(weight)
    if len(weights) != DRAWS:
        raise ValueError(f"Expected {DRAWS} draws, found {len(weights)}")
    count = sum(w >= HEAVY for w in weights)
    return {
        "draws": len(weights),
        "event": "W >= 831",
        "event_count": count,
        "minimum_weight": min(weights),
        "maximum_weight": max(weights),
        "confidence_model": "iid uniform 32-byte seed draws with replacement for fixed SHAKE",
        "one_sided_95_upper_if_zero": -math.expm1(math.log(0.05) / DRAWS) if count == 0 else None,
        "kem_exchanges": 0,
        "archive_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "opt2_source_sha256": hashlib.sha256(Path(opt2.__file__).read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "review"))
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if args.action == "collect":
        collect(args.archive)
    print(json.dumps(review(args.archive), indent=2, allow_nan=False))
