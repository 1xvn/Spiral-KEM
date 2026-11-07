"""Small real-TLS Rust/Rust matrix; not a capacity or constant-time claim."""

import argparse
import hashlib
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import re
import select
import shutil
import statistics
import subprocess
import tempfile
import time
from interop import identities, NAME, SERVICE, ROOT


def percentile(v, p):
    return sorted(v)[math.ceil(len(v) * p) - 1]


def stats(v):
    return {
        "median": statistics.median(v),
        "p95": percentile(v, 0.95),
        "p99": percentile(v, 0.99),
    }


def run(binary, folder, workers, payload, timer):
    timed = lambda cmd: [str(timer), "-f", "SPIRAL_RSS_KIB=%M", *cmd] if timer else cmd
    common = [
        "--name",
        NAME,
        "--service",
        SERVICE,
        "--connections",
        "4",
        "--workers",
        str(workers),
        "--messages",
        "32",
    ]
    server = subprocess.Popen(
        timed(
            [
                str(binary),
                "server",
                *common,
                "--port",
                "0",
                "--cert",
                str(folder / "cert.pem"),
                "--key",
                str(folder / "key.pem"),
                "--auth",
                str(folder / "auth.bin"),
            ]
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        if not select.select([server.stdout], [], [], 10)[0]:
            raise RuntimeError("server start timeout")
        port = json.loads(server.stdout.readline())["listening"]
        start = time.perf_counter()
        client = subprocess.run(
            timed(
                [
                    str(binary),
                    "client",
                    *common,
                    "--port",
                    str(port),
                    "--ca",
                    str(folder / "ca.pem"),
                    "--pin",
                    str(folder / "pin.json"),
                    "--payload",
                    str(payload),
                    "--pipeline",
                    "8",
                ]
            ),
            capture_output=True,
            text=True,
            timeout=20,
        )
        elapsed = time.perf_counter() - start
        stdout, stderr = server.communicate(timeout=20)
        if client.returncode or server.returncode:
            raise RuntimeError((client.stdout, client.stderr, stdout, stderr))
        a = json.loads(client.stdout.strip().splitlines()[-1])
        b = json.loads(stdout.strip().splitlines()[-1])
        assert a["kem"]["live_keys"] == b["kem"]["live_keys"] == 0
        assert sorted(x["transcript_hash"] for x in a["sessions"]) == sorted(
            x["transcript_hash"] for x in b["sessions"]
        )
        rss = lambda text: (
            int(re.search(r"SPIRAL_RSS_KIB=(\d+)", text)[1])
            if re.search(r"SPIRAL_RSS_KIB=(\d+)", text)
            else None
        )
        return {
            "wall_seconds": elapsed,
            "sessions": a["sessions"],
            "server_kem": b["kem"],
            "client_peak_rss_kib": rss(client.stderr),
            "server_peak_rss_kib": rss(stderr),
        }
    finally:
        if server.poll() is None:
            os.killpg(server.pid, 9)
        server.communicate(timeout=5)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--binary", type=Path, default=ROOT / "protocol_rust/target/release/spiral-lab"
    )
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--time", type=Path, default=shutil.which("time"))
    args = p.parse_args()
    if not 3 <= args.trials <= 30:
        raise SystemExit("trials must be 3..30")
    data = {
        "schema": "spiral-rust-c-loopback-benchmark/v1",
        "date_utc": datetime.now(timezone.utc).date().isoformat(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "cargo_lock_sha256": hashlib.sha256(
            (ROOT / "protocol_rust/Cargo.lock").read_bytes()
        ).hexdigest(),
        "platform": platform.platform(),
        "cpu_affinity_count": len(os.sched_getaffinity(0)),
        "scope": "Fresh server/client processes per trial, four loopback sessions, TLS1.3 plus inner Spiral AEAD, 32 echoed records per session, eight send producers, two warmup trials per profile. Wall time includes client startup and authenticated close. Small sample; no production capacity or language comparison.",
        "profiles": [],
    }
    with tempfile.TemporaryDirectory(prefix="spiral-rust-bench-") as tmp:
        folder = Path(tmp)
        identities(folder)
        for workers in (1, 2, 4):
            for payload in (64, 1024, 16384):
                for _ in range(2):
                    run(args.binary.resolve(), folder, workers, payload, args.time)
                raw = [
                    run(args.binary.resolve(), folder, workers, payload, args.time)
                    for _ in range(args.trials)
                ]
                sessions = [s for trial in raw for s in trial["sessions"]]
                summary = {
                    k: stats([s[k] for s in sessions])
                    for k in ("handshake_ms", "tcp_ms", "tls_ms", "spiral_ms", "app_ms")
                }
                throughput = [
                    (2 * 4 * 32 * payload) / (x["wall_seconds"] * 1024 * 1024)
                    for x in raw
                ]
                rss = {
                    k: stats([x[k] for x in raw])
                    for k in ("client_peak_rss_kib", "server_peak_rss_kib")
                    if all(x[k] is not None for x in raw)
                }
                profile = {
                    "workers_per_endpoint": workers,
                    "payload": payload,
                    "trials": args.trials,
                    "connection_samples": len(sessions),
                    "summary_ms": summary,
                    "whole_run_echo_payload_MiB_per_second": stats(throughput),
                    "rss_kib": rss,
                    "raw": raw,
                }
                data["profiles"].append(profile)
                args.output.write_text(json.dumps(data, indent=2) + "\n")
                print(
                    json.dumps(
                        {
                            "workers": workers,
                            "payload": payload,
                            "handshake_ms": summary["handshake_ms"],
                            "whole_run_echo_MiBps": stats(throughput),
                        }
                    ),
                    flush=True,
                )


if __name__ == "__main__":
    main()
