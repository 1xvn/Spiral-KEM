#!/usr/bin/env python3
"""Compare two research Python implementations on the same computer.

Place this script beside spiral_kem_toy_v031.py, then run:
    py -m pip install "kyber-py==1.2.0"
    py compare_spiral_mlkem.py

Each implementation gets 30 warm-up and 300 measured exchanges, interleaved
in a reproducibly shuffled order. Source files and earlier reports are not
modified. The new JSON report contains environment details and raw timings,
but no generated keys, messages, or ciphertexts.

The printed figures measure normal public API calls. The JSON also records
byte-interface costs: Spiral's extra key/ciphertext serialization and parsing
are added there; kyber-py's APIs already accept and return bytes. This compares
implementations with different parameter choices, not equal security levels.

ML-KEM implementation: https://github.com/GiacomoPope/kyber-py
Pinned dependency: https://pypi.org/project/kyber-py/1.2.0/
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import uuid


SOURCE_NAME = "spiral_kem_toy_v031.py"
SOURCE_SHA256 = "898e540b4aded14e3710b591c6aa03a44bf5774c1d591f630e488b041655fd6c"
PACKAGE_VERSION = "1.2.0"
ORDER_SEED = 20261023
OPERATIONS = ("keygen", "encapsulate", "decapsulate")


def load_targets(directory: Path):
    path = directory / SOURCE_NAME
    if not path.is_file():
        raise ValueError(f"Place this script in the same directory as {SOURCE_NAME}.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("Code differs from baseline 0.3.1. Run from the previous results ZIP source directory.")
    name = "spiral_original_for_mlkem_comparison"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load the baseline implementation.")
    original = importlib.util.module_from_spec(spec)
    sys.modules[name] = original
    spec.loader.exec_module(original)

    try:
        version = importlib.metadata.version("kyber-py")
        import kyber_py
        from kyber_py.ml_kem import ML_KEM_512
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise ValueError('First run py -m pip install "kyber-py==1.2.0".') from error
    if version != PACKAGE_VERSION:
        raise ValueError(f'kyber-py {version} is installed. Run py -m pip install "kyber-py==1.2.0".')
    package_root = Path(kyber_py.__file__).resolve().parent
    package_hashes = {
        p.relative_to(package_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(package_root.rglob("*.py"))
    }
    if (ML_KEM_512.k, ML_KEM_512.eta_1, ML_KEM_512.eta_2, ML_KEM_512.du, ML_KEM_512.dv) != (2, 3, 2, 10, 4):
        raise ValueError("Unexpected ML-KEM-512 parameters.")
    return original.SpiralKEM(), ML_KEM_512, package_hashes


def time_exchange(name, kem):
    if name == "spiral":
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
        row = {
            "keygen_ns": t1 - t0,
            "encapsulate_ns": t4 - t3,
            "decapsulate_ns": t7 - t6,
            "pk_export_ns": t2 - t1,
            "pk_import_ns": t3 - t2,
            "ct_export_ns": t5 - t4,
            "ct_import_ns": t6 - t5,
        }
        expected = (1109, 1589, 32)
    else:
        t0 = time.perf_counter_ns()
        pk, sk = kem.keygen()
        t1 = time.perf_counter_ns()
        sender_key, ct = kem.encaps(pk)
        t2 = time.perf_counter_ns()
        receiver_key = kem.decaps(sk, ct)
        t3 = time.perf_counter_ns()
        pk_wire, ct_wire = pk, ct
        row = {
            "keygen_ns": t1 - t0,
            "encapsulate_ns": t2 - t1,
            "decapsulate_ns": t3 - t2,
            "pk_export_ns": 0,
            "pk_import_ns": 0,
            "ct_export_ns": 0,
            "ct_import_ns": 0,
        }
        expected = (800, 768, 32)
    if sender_key != receiver_key:
        raise ValueError(f"{name}: key mismatch detected; measurement stopped.")
    actual = (len(pk_wire), len(ct_wire), len(sender_key))
    if actual != expected:
        raise ValueError(f"{name}: unexpected byte sizes: {actual}")
    row["wire_keygen_ns"] = row["keygen_ns"] + row["pk_export_ns"]
    row["wire_encapsulate_ns"] = row["pk_import_ns"] + row["encapsulate_ns"] + row["ct_export_ns"]
    row["wire_decapsulate_ns"] = row["ct_import_ns"] + row["decapsulate_ns"]
    row["wire_three_operations_total_ns"] = sum(row[f"wire_{op}_ns"] for op in OPERATIONS)
    return row, actual


def stats(values):
    ordered = sorted(values)
    position = (len(ordered) - 1) * 0.95
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return {
        "median_ms": statistics.median(values),
        "p95_ms": ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower),
        "mean_ms": statistics.mean(values),
        "minimum_ms": min(values),
        "maximum_ms": max(values),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=300)
    ap.add_argument("--warmup", type=int, default=30)
    args = ap.parse_args()
    if not 1 <= args.rounds <= 10000 or not 0 <= args.warmup <= 10000:
        ap.error("rounds must be 1..10000 and warmup must be 0..10000.")
    directory = Path(__file__).resolve().parent
    spiral, mlkem, package_hashes = load_targets(directory)
    targets = {"spiral": spiral, "mlkem512": mlkem}
    labels = {"spiral": "Spiral-KEM 0.3.1", "mlkem512": "ML-KEM-512 (kyber-py 1.2.0)"}
    environment = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor_identifier": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
        "logical_cpu_count": os.cpu_count(),
        "cpu_affinity_pinned": False,
        "garbage_collection_enabled": gc.isenabled(),
        "measured_exchanges_per_implementation": args.rounds,
        "warmup_exchanges_per_implementation": args.warmup,
        "order_seed": ORDER_SEED,
        "scheduling": "sequential fresh exchanges, shuffled implementation order each round",
        "randomness": "normal API defaults, operating system randomness",
        "clock": "time.perf_counter_ns",
        "source_sha256": SOURCE_SHA256,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "mlkem_distribution": "kyber-py",
        "mlkem_distribution_version": PACKAGE_VERSION,
        "mlkem_source_hashes": package_hashes,
        "timing_scope": {
            "operations": "normal native public API calls; internal hashing, validation and byte encoding included",
            "byte_interface_operations": "adds external serialization and parsing for Spiral; ML-KEM API is already byte-based",
            "network_included": False,
            "additional_matrix_cache_in_harness": False,
        },
        "comparison_scope": "two research Python implementations with different noise and compression settings; not equal-security or cryptographic-strength comparison",
    }
    raw = []
    sizes = {}
    order = random.Random(ORDER_SEED)
    print(f"Spiral / ML-KEM-512 comparison: {args.warmup} warmups, {args.rounds} measurements each", flush=True)
    for iteration in range(-args.warmup, args.rounds):
        names = list(targets)
        order.shuffle(names)
        for position, name in enumerate(names):
            row, actual_sizes = time_exchange(name, targets[name])
            sizes[name] = {"public_key_bytes": actual_sizes[0], "ciphertext_bytes": actual_sizes[1], "shared_key_bytes": actual_sizes[2]}
            if iteration >= 0:
                raw.append({"round": iteration + 1, "position_in_round": position + 1, "implementation": name, **row})
        if iteration >= 0 and (iteration + 1) % 50 == 0:
            print(f"Measurement progress: {iteration + 1}/{args.rounds} (both implementations)", flush=True)
    summaries = {}
    for name in targets:
        selected = [r for r in raw if r["implementation"] == name]
        summaries[name] = {
            "label": labels[name],
            "samples": len(selected),
            "key_mismatches": 0,
            "parameters": ({"n": 256, "k": 2, "q": 3329, "eta": 1} if name == "spiral" else {"n": 256, "k": 2, "q": 3329, "eta1": 3, "eta2": 2, "du": 10, "dv": 4}),
            "wire_sizes": sizes[name],
            "operations": {op: stats([r[op + "_ns"] / 1e6 for r in selected]) for op in OPERATIONS},
            "byte_interface_operations": {op: stats([r["wire_" + op + "_ns"] / 1e6 for r in selected]) for op in OPERATIONS},
            "byte_interface_three_operations_total": stats([r["wire_three_operations_total_ns"] / 1e6 for r in selected]),
        }
    environment["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report = {"environment": environment, "implementations": summaries, "raw_timings_ns": raw}
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output = directory / f"Spiral_MLKEM_PC_comparison_{stamp}_{uuid.uuid4().hex[:8]}.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print("\nMeasurement complete — API-call medians")
    for name, summary in summaries.items():
        print(f"\n{labels[name]}")
        for label, op in (("Key generation", "keygen"), ("Encapsulation", "encapsulate"), ("Decapsulation", "decapsulate")):
            print(f"  {label}: {summary['operations'][op]['median_ms']:.3f} ms")
        print(f"  Public key: {sizes[name]['public_key_bytes']} bytes")
        print(f"  Ciphertext: {sizes[name]['ciphertext_bytes']} bytes")
        print(f"  Key mismatches: 0/{args.rounds} (measurement interval)")
    print("\nTimings including byte I/O conversion are also recorded in the results file.")
    print(f"Results file: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
