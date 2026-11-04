#!/usr/bin/env python3
"""Compare original Spiral, opt1 and kyber-py ML-KEM-512 in one process.

Windows: py compare_spiral_opt1_mlkem.py
Dependency: kyber-py==1.2.0
Each implementation gets 30 warm-up and 300 measured fresh exchanges.
The order is shuffled each round. Timings include byte interfaces; native
API timings are also saved. No generated secret values are stored.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import random
import sys
import time
import uuid

from compare_spiral_opt1 import measure as measure_spiral, stats
from verify_equivalence import SOURCE_NAMES, load_implementations, run_checks


PACKAGE_VERSION = "1.2.0"
OPT1_SHA256 = "7ffb12c4494f92327bc560d4579731a642d749ec812e120ad955f6fc49391b51"
ORDER_SEED = 20261023
OPERATIONS = ("keygen", "encapsulate", "decapsulate")
LABELS = {"original": "Spiral-KEM 0.3.1 baseline", "opt1": "Spiral-KEM 0.3.1 opt1",
          "mlkem512": "ML-KEM-512 (kyber-py 1.2.0)"}


def load_mlkem():
    try:
        version = importlib.metadata.version("kyber-py")
        import kyber_py
        from kyber_py.ml_kem import ML_KEM_512
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise ValueError('First run py -m pip install "kyber-py==1.2.0".') from error
    if version != PACKAGE_VERSION:
        raise ValueError(f'kyber-py {version} is installed. Run py -m pip install "kyber-py==1.2.0".')
    if (ML_KEM_512.k, ML_KEM_512.eta_1, ML_KEM_512.eta_2, ML_KEM_512.du, ML_KEM_512.dv) != (2, 3, 2, 10, 4):
        raise ValueError("Unexpected ML-KEM-512 parameters.")
    package_root = Path(kyber_py.__file__).resolve().parent
    hashes = {p.relative_to(package_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(package_root.rglob("*.py"))}
    return ML_KEM_512, hashes


def measure_mlkem(kem):
    t0 = time.perf_counter_ns()
    pk, sk = kem.keygen()
    t1 = time.perf_counter_ns()
    sender_key, ct = kem.encaps(pk)
    t2 = time.perf_counter_ns()
    receiver_key = kem.decaps(sk, ct)
    t3 = time.perf_counter_ns()
    if sender_key != receiver_key:
        raise ValueError("ML-KEM-512: key mismatch detected; measurement stopped.")
    if (len(pk), len(ct), len(sender_key)) != (800, 768, 32):
        raise ValueError("ML-KEM-512: unexpected output byte length.")
    return {"keygen_ns": t1-t0, "encapsulate_ns": t2-t1, "decapsulate_ns": t3-t2,
            "pk_export_ns": 0, "pk_import_ns": 0, "ct_export_ns": 0, "ct_import_ns": 0,
            "wire_keygen_ns": t1-t0, "wire_encapsulate_ns": t2-t1,
            "wire_decapsulate_ns": t3-t2, "wire_total_ns": t3-t0, "native_total_ns": t3-t0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10000 or not 0 <= args.warmup <= 10000:
        parser.error("rounds must be 1..10000 and warmup must be 0..10000.")
    root = Path(__file__).resolve().parent
    modules = load_implementations()
    if hashlib.sha256((root/SOURCE_NAMES['opt1']).read_bytes()).hexdigest() != OPT1_SHA256:
        raise ValueError("The opt1 SHA-256 does not match the validated file.")
    mlkem, package_hashes = load_mlkem()
    files = tuple(SOURCE_NAMES.values()) + ("compare_spiral_opt1.py", "verify_equivalence.py", Path(__file__).name)
    environment = {"started_utc": datetime.now(timezone.utc).isoformat(),
                   "python": sys.version, "python_implementation": platform.python_implementation(),
                   "platform": platform.platform(),
                   "processor_identifier": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
                   "logical_cpu_count": os.cpu_count(), "cpu_affinity_pinned": False,
                   "garbage_collection_enabled": gc.isenabled(),
                   "warmup_exchanges_each": args.warmup, "measured_exchanges_each": args.rounds,
                   "order_seed": ORDER_SEED, "clock": "time.perf_counter_ns (elapsed wall time)",
                   "schedule": "one process, sequential fresh exchanges, shuffled implementation order each round",
                   "randomness": "normal OS randomness; fixed seeds only in preceding Spiral tests",
                   "source_sha256": {file: hashlib.sha256((root/file).read_bytes()).hexdigest() for file in files},
                   "mlkem_distribution": "kyber-py", "mlkem_distribution_version": PACKAGE_VERSION,
                   "mlkem_source_hashes": package_hashes,
                   "timing_scope": {"native": "normal public API calls including internal validation, hashing and encoding",
                                    "wire": "adds public-key/ciphertext export and import for both Spiral implementations; ML-KEM APIs already use bytes",
                                    "network_included": False, "additional_matrix_cache": False},
                   "comparison_scope": "research Python implementations with different noise and compression settings; no equal-security claim"}
    print("Running baseline/opt1 equivalence and regression checks first.", flush=True)
    verification = run_checks(modules)
    print("Validation passed. Alternating three implementations in one process.", flush=True)
    targets = {name: module.SpiralKEM() for name, module in modules.items()}
    targets["mlkem512"] = mlkem
    raw = []
    order = random.Random(ORDER_SEED)
    print(f"{args.warmup} warmups and {args.rounds} measurements each", flush=True)
    for iteration in range(-args.warmup, args.rounds):
        names = list(targets)
        order.shuffle(names)
        for position, name in enumerate(names):
            measured = measure_mlkem(targets[name]) if name == "mlkem512" else measure_spiral(targets[name])
            if iteration >= 0:
                raw.append({"round": iteration + 1, "position_in_round": position + 1,
                            "implementation": name, **measured})
        if iteration >= 0 and (iteration + 1) % 50 == 0:
            print(f"Measurement progress: {iteration + 1}/{args.rounds} (all three implementations)", flush=True)
    metrics = tuple(op + "_ns" for op in OPERATIONS) + ("native_total_ns",) + tuple("wire_" + op + "_ns" for op in OPERATIONS) + ("wire_total_ns",)
    summaries = {}
    for name in targets:
        rows = [r for r in raw if r["implementation"] == name]
        spiral = name != "mlkem512"
        summaries[name] = {"label": LABELS[name], "samples": len(rows), "key_mismatches": 0,
                           "parameters": ({"n": 256, "k": 2, "q": 3329, "eta": 1, "key_bytes": 32} if spiral else
                                          {"n": 256, "k": 2, "q": 3329, "eta1": 3, "eta2": 2, "du": 10, "dv": 4, "key_bytes": 32}),
                           "sizes": {"public_key_bytes": 1109 if spiral else 800,
                                     "ciphertext_bytes": 1589 if spiral else 768, "shared_key_bytes": 32},
                           "timings": {metric: stats([r[metric] for r in rows]) for metric in metrics}}
    a = summaries["original"]["timings"]["wire_total_ns"]["median_ms"]
    b = summaries["opt1"]["timings"]["wire_total_ns"]["median_ms"]
    c = summaries["mlkem512"]["timings"]["wire_total_ns"]["median_ms"]
    comparison = {"opt1_vs_original_wire_total_median_time_reduction_percent": 100 * (1-b/a),
                  "opt1_over_mlkem_wire_total_median_time_ratio": b/c}
    environment["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report = {"schema_version": 1, "environment": environment, "verification": verification,
              "implementations": summaries, "comparison": comparison, "raw_timings_ns": raw}
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output = root/f"Spiral_opt1_MLKEM_comparison_{stamp}_{uuid.uuid4().hex[:8]}.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print("\nMeasurement complete — median time including byte I/O")
    for name, summary in summaries.items():
        print(f"\n{LABELS[name]}")
        for label, metric in (("Key generation", "wire_keygen_ns"), ("Encapsulation", "wire_encapsulate_ns"),
                              ("Decapsulation", "wire_decapsulate_ns"), ("Total", "wire_total_ns")):
            print(f"  {label}: {summary['timings'][metric]['median_ms']:.3f} ms")
        print(f"  Public key: {summary['sizes']['public_key_bytes']} bytes")
        print(f"  Ciphertext: {summary['sizes']['ciphertext_bytes']} bytes")
        print(f"  Key mismatches: 0/{args.rounds} (measurement interval)")
    print(f"\nopt1 total time reduction from baseline: {100*(1-b/a):.1f}%")
    print(f"opt1 total time / ML-KEM total time: {b/c:.3f} (below 1 means opt1 measured faster)")
    print("Total is the median of the sum of three operations per round; network time is excluded.")
    print(f"Results file: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
