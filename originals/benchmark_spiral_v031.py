#!/usr/bin/env python3
"""Measure the original Spiral-KEM 0.3.1 using only Python's standard library.

Put this file beside spiral_kem_toy_v031.py, then run:
    py benchmark_spiral_v031.py

Defaults: 30 warm-up exchanges, 300 measured exchanges. A new UTF-8 JSON
report stores timings and environment details; keys and ciphertexts are not
stored. Source files and earlier reports are never modified.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time
import uuid


SOURCE_NAME = "spiral_kem_toy_v031.py"
SOURCE_SHA256 = "898e540b4aded14e3710b591c6aa03a44bf5774c1d591f630e488b041655fd6c"


def load_original(directory: Path):
    source_path = directory / SOURCE_NAME
    if not source_path.is_file():
        raise ValueError(
            f"Place this script in the same directory as {SOURCE_NAME}."
        )
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError(
            "The baseline code differs from the 0.3.1 used in the previous evaluation. "
            "Place this script in the results ZIP source directory and run it there."
        )
    name = "spiral_original_v031_pc_benchmark"
    spec = importlib.util.spec_from_file_location(name, source_path)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load the baseline Python file.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.SpiralKEM(), digest


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10000 or not 0 <= args.warmup <= 10000:
        parser.error("rounds must be 1..10000 and warmup must be 0..10000.")

    directory = Path(__file__).resolve().parent
    kem, digest = load_original(directory)
    print(f"Spiral-KEM 0.3.1 PC benchmark: {args.warmup} warmups, {args.rounds} measurements", flush=True)
    started = datetime.now(timezone.utc)
    metadata = {
        "started_utc": started.isoformat(),
        "python": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor_identifier": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
        "logical_cpu_count": os.cpu_count(),
        "cpu_affinity_pinned": False,
        "garbage_collection_enabled": gc.isenabled(),
        "source_filename": SOURCE_NAME,
        "source_sha256": digest,
        "parameters": {"n": 256, "k": 2, "q": 3329, "eta": 1, "key_bytes": 32},
        "measured_exchanges": args.rounds,
        "warmup_exchanges": args.warmup,
        "clock": "time.perf_counter_ns",
        "randomness": "normal public APIs, operating system RNG",
        "timed_scope": "keygen, encapsulate, decapsulate public API calls, including their internal validation and hashing",
        "external_serialization_and_network_excluded": True,
        "measurement_order": "keygen, encapsulate, decapsulate in each fresh exchange",
        "application_level_matrix_cache": False,
    }
    rows = []
    expected_sizes = None
    for iteration in range(-args.warmup, args.rounds):
        start = time.perf_counter_ns()
        pk, sk = kem.keygen()
        after_keygen = time.perf_counter_ns()
        ciphertext, sender_key = kem.encapsulate(pk)
        after_encapsulate = time.perf_counter_ns()
        receiver_key = kem.decapsulate(sk, ciphertext)
        after_decapsulate = time.perf_counter_ns()
        if sender_key != receiver_key:
            raise ValueError(f"Key mismatch detected; measurement stopped at round {iteration}.")
        sizes = {
            "public_key_bytes": len(kem.serialize_public_key(pk)),
            "ciphertext_bytes": len(kem.serialize_ciphertext(ciphertext)),
            "shared_key_bytes": len(sender_key),
        }
        if expected_sizes is None:
            expected_sizes = sizes
        elif sizes != expected_sizes:
            raise ValueError("Wire size changed between rounds.")
        if iteration >= 0:
            rows.append({
                "round": iteration + 1,
                "keygen_ns": after_keygen - start,
                "encapsulate_ns": after_encapsulate - after_keygen,
                "decapsulate_ns": after_decapsulate - after_encapsulate,
            })
            if (iteration + 1) % 50 == 0:
                print(f"Measurement progress: {iteration + 1}/{args.rounds}", flush=True)

    operations = {}
    for name in ("keygen", "encapsulate", "decapsulate"):
        values = [row[name + "_ns"] / 1_000_000 for row in rows]
        operations[name] = {
            "median_ms": statistics.median(values),
            "p95_ms": percentile(values, 0.95),
            "mean_ms": statistics.mean(values),
            "minimum_ms": min(values),
            "maximum_ms": max(values),
        }
    metadata["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report = {
        "environment": metadata,
        "key_mismatches": 0,
        "wire_sizes": expected_sizes,
        "operations": operations,
        "raw_timings_ns": rows,
    }
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output_path = directory / f"Spiral_v031_PC_benchmark_{stamp}_{uuid.uuid4().hex[:8]}.json"
    with output_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")

    print("\nMeasurement complete — medians")
    for label, name in (("Key generation", "keygen"), ("Encapsulation", "encapsulate"), ("Decapsulation", "decapsulate")):
        print(f"{label}: {operations[name]['median_ms']:.3f} ms")
    print(f"Public key: {expected_sizes['public_key_bytes']} bytes")
    print(f"Ciphertext: {expected_sizes['ciphertext_bytes']} bytes")
    print(f"Key mismatches: 0/{args.rounds} (measurement interval)")
    print(f"Results file: {output_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
