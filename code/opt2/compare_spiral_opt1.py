#!/usr/bin/env python3
"""Run equivalence checks, then compare original/opt1 in one Python process.

Run on Windows: py compare_spiral_opt1.py
No extra packages. Fresh exchanges use normal OS randomness. JSON contains
all measured timings and verification logs, but no generated secret values.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import uuid

from verify_equivalence import SOURCE_NAMES, load_implementations, run_checks


OPERATIONS = ("keygen", "encapsulate", "decapsulate")
ORDER_SEED = 20261023


def measure(kem):
    t0 = time.perf_counter_ns()
    pk, sk = kem.keygen()
    t1 = time.perf_counter_ns()
    pk_wire = kem.serialize_public_key(pk)
    t2 = time.perf_counter_ns()
    received_pk = kem.deserialize_public_key(pk_wire)
    t3 = time.perf_counter_ns()
    ct, sender_key = kem.encapsulate(received_pk)
    t4 = time.perf_counter_ns()
    ct_wire = kem.serialize_ciphertext(ct)
    t5 = time.perf_counter_ns()
    received_ct = kem.deserialize_ciphertext(ct_wire)
    t6 = time.perf_counter_ns()
    receiver_key = kem.decapsulate(sk, received_ct)
    t7 = time.perf_counter_ns()
    if sender_key != receiver_key:
        raise ValueError("Key mismatch detected; measurement stopped.")
    if (len(pk_wire), len(ct_wire), len(sender_key)) != (1109, 1589, 32):
        raise ValueError("Unexpected output byte length.")
    row = {"keygen_ns": t1-t0, "encapsulate_ns": t4-t3, "decapsulate_ns": t7-t6,
           "pk_export_ns": t2-t1, "pk_import_ns": t3-t2,
           "ct_export_ns": t5-t4, "ct_import_ns": t6-t5,
           "wire_keygen_ns": t2-t0, "wire_encapsulate_ns": t5-t2,
           "wire_decapsulate_ns": t7-t5, "wire_total_ns": t7-t0}
    row["native_total_ns"] = sum(row[op + "_ns"] for op in OPERATIONS)
    return row


def stats(values):
    ordered = sorted(value / 1e6 for value in values)
    position = (len(ordered) - 1) * .95
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return {"median_ms": statistics.median(ordered), "mean_ms": statistics.mean(ordered),
            "p95_ms": ordered[low] + (ordered[high] - ordered[low]) * (position - low),
            "minimum_ms": ordered[0], "maximum_ms": ordered[-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10000 or not 0 <= args.warmup <= 10000:
        parser.error("rounds must be 1..10000 and warmup must be 0..10000.")
    root = Path(__file__).resolve().parent
    modules = load_implementations()
    environment = {"started_utc": datetime.now(timezone.utc).isoformat(),
                   "python": sys.version, "platform": platform.platform(),
                   "python_implementation": platform.python_implementation(),
                   "processor_identifier": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
                   "logical_cpu_count": os.cpu_count(), "cpu_affinity_pinned": False,
                   "garbage_collection_enabled": gc.isenabled(),
                   "warmup_exchanges_each": args.warmup, "measured_exchanges_each": args.rounds,
                   "order_seed": ORDER_SEED, "clock": "time.perf_counter_ns",
                   "schedule": "fresh sequential exchanges; shuffled implementation order each round",
                   "randomness": "OS randomness, normal public APIs; fixed seeds only in preceding tests",
                   "parameters": {"n": 256, "k": 2, "q": 3329, "eta": 1, "key_bytes": 32},
                   "source_sha256": {name: hashlib.sha256((root / filename).read_bytes()).hexdigest()
                                     for name, filename in SOURCE_NAMES.items()},
                   "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "verification_sha256": hashlib.sha256((root / "verify_equivalence.py").read_bytes()).hexdigest(),
                   "timing_scope": {"native": "public API calls, including internal validation, hashing and encoding",
                                    "wire": "also external public-key/ciphertext export and import",
                                    "network_included": False, "additional_cache": False}}
    print("Running baseline/optimized equivalence and regression checks first.", flush=True)
    verification = run_checks(modules)
    print("Validation passed: all 65,536 byte pairs, seed/parameter comparisons, and both regression suites", flush=True)
    targets = {name: module.SpiralKEM() for name, module in modules.items()}
    order = random.Random(ORDER_SEED)
    raw = []
    print(f"Baseline / opt1: {args.warmup} warmups and {args.rounds} measurements each", flush=True)
    for iteration in range(-args.warmup, args.rounds):
        names = list(targets)
        order.shuffle(names)
        for position, name in enumerate(names):
            measured = measure(targets[name])
            if iteration >= 0:
                raw.append({"round": iteration + 1, "position_in_round": position + 1,
                            "implementation": name, **measured})
        if iteration >= 0 and (iteration + 1) % 50 == 0:
            print(f"Measurement progress: {iteration + 1}/{args.rounds}", flush=True)
    summaries = {}
    metrics = tuple(op + "_ns" for op in OPERATIONS) + ("native_total_ns",) + tuple("wire_" + op + "_ns" for op in OPERATIONS) + ("wire_total_ns",)
    for name in targets:
        rows = [r for r in raw if r["implementation"] == name]
        summaries[name] = {"samples": len(rows), "key_mismatches": 0,
                           "sizes": {"public_key_bytes": 1109, "ciphertext_bytes": 1589, "shared_key_bytes": 32},
                           "timings": {metric: stats([r[metric] for r in rows]) for metric in metrics}}
    reductions = {metric: 100 * (1 - summaries["opt1"]["timings"][metric]["median_ms"] /
                                summaries["original"]["timings"][metric]["median_ms"])
                  for metric in metrics}
    environment["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report = {"environment": environment, "verification": verification,
              "implementations": summaries, "median_time_reduction_percent": reductions,
              "raw_timings_ns": raw}
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output = root / f"Spiral_opt1_comparison_{stamp}_{uuid.uuid4().hex[:8]}.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print("\nMedian time including byte I/O — baseline → opt1 (time reduction)")
    for label, metric in (("Key generation", "wire_keygen_ns"), ("Encapsulation", "wire_encapsulate_ns"),
                          ("Decapsulation", "wire_decapsulate_ns"), ("Total", "wire_total_ns")):
        before = summaries["original"]["timings"][metric]["median_ms"]
        after = summaries["opt1"]["timings"][metric]["median_ms"]
        print(f"{label}: {before:.3f} → {after:.3f} ms ({reductions[metric]:.1f}%)")
    print(f"Both implementations: 0/{args.rounds} key mismatches; public key 1109 bytes, ciphertext 1589 bytes")
    print(f"Results file: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
