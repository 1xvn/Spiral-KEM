"""Collect two bounded, synthetic record-opening timing trials on one Linux CPU."""
import argparse
import csv
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
TEST = "receive_audit::timing::collect"
PAIRS = 2000
THRESHOLD = 4.5
DECISIONS = ("accept", "reject")
COMPARISONS = ("positive", "sham", "key")


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def summarize(path, pairs=PAIRS):
    groups = defaultdict(dict)
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != ["decision", "comparison", "pair", "position", "class", "ns"]:
            raise ValueError("invalid sample header")
        for row in reader:
            decision, comp = row["decision"], row["comparison"]
            pair, position, ns = (int(row[k]) for k in ("pair", "position", "ns"))
            group = row["class"]
            if (None in row or decision not in DECISIONS or comp not in COMPARISONS
                    or not 0 <= pair < pairs or position not in (0, 1)
                    or group not in ("A", "B") or ns <= 0):
                raise ValueError("invalid sample")
            observations = groups[decision, comp]
            if (pair, group) in observations:
                raise ValueError("duplicate sample")
            observations[pair, group] = position, ns

    summaries = {}
    for decision in DECISIONS:
        summaries[decision] = {}
        for comp in COMPARISONS:
            values = groups[decision, comp]
            if len(values) != 2 * pairs:
                raise ValueError("incomplete comparison")
            delta = []
            for i in range(pairs):
                a_position, a = values[i, "A"]
                b_position, b = values[i, "B"]
                if a_position == b_position or (i % 2 and a_position == values[i - 1, "A"][0]):
                    raise ValueError("unbalanced execution order")
                delta.append(b - a)
            mean, sd = statistics.mean(delta), statistics.stdev(delta)
            summaries[decision][comp] = {
                "pairs": pairs, "mean_delta_ns_B_minus_A": mean,
                "median_delta_ns_B_minus_A": statistics.median(delta),
                "paired_t": mean / (sd / math.sqrt(pairs)) if sd else None,
                "mean_ns": {c: statistics.mean(values[i, c][1] for i in range(pairs)) for c in "AB"},
            }
    return summaries


def interpret(trials, decision):
    rows = [trial[decision] for trial in trials]
    if len(rows) != 2:
        raise ValueError("two trials required")
    for row in rows:
        positive, sham, target = (row[k]["paired_t"] for k in COMPARISONS)
        if (None in (positive, sham, target) or positive < THRESHOLD or abs(sham) >= THRESHOLD):
            return "inconclusive_controls_or_variance"
    signals = [row["key"]["paired_t"] for row in rows]
    if all(t >= THRESHOLD for t in signals) or all(t <= -THRESHOLD for t in signals):
        return "repeatable_threshold_crossing"
    if any(abs(t) >= THRESHOLD for t in signals):
        return "inconsistent_threshold_crossing"
    return "no_threshold_crossing_in_sample"


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def collect(out, cargo):
    manifest = ROOT / "protocol_rust/Cargo.toml"
    build = [cargo, "test", "--locked", "--manifest-path", str(manifest), "--profile", "audit",
             "--features", "receive-timing", "--lib", "--no-run", "--message-format=json"]
    with (out / "build.log").open("w") as log:
        proc = subprocess.run(build, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                              stderr=log, timeout=1800)
    proc.check_returncode()
    artifacts = [json.loads(line) for line in proc.stdout.splitlines()]
    exe, = [Path(a["executable"]) for a in artifacts if a.get("reason") == "compiler-artifact"
            and a["target"]["name"] == "spiral_protocol" and a["profile"]["test"] and a["executable"]]
    cpus = sorted(os.sched_getaffinity(0))
    cpu = cpus[0]
    meta = {
        "schema": 1, "source_commit": command("git", "rev-parse", "HEAD"),
        "tracked_changes": bool(command("git", "status", "--porcelain", "--untracked-files=no")),
        "rustc": command(os.environ.get("RUSTC", "rustc"), "-vV"), "cargo": command(cargo, "-V"),
        "kernel": platform.release(), "architecture": platform.machine(), "cpu": cpu,
        "available_cpus": cpus, "profile": "audit", "feature": "receive-timing",
        "cpu_model": next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text()
                           .splitlines() if line.startswith(("model name", "CPU part"))), "unknown"),
        "sha256": {"libtest": sha(exe), "lock": sha(manifest.with_name("Cargo.lock")),
                   "probe": sha(ROOT / "protocol_rust/src/receive_audit/timing.rs"), "collector": sha(Path(__file__))},
        "threshold_abs_t": THRESHOLD, "warmup_pairs_per_stream": 128, "clock": "std::time::Instant",
        "constant_time_approved": False, "trials": [],
    }
    for trial in range(2):
        raw = out / f"trial-{trial}.csv"
        log = out / f"trial-{trial}.log"
        env = dict(os.environ, SPIRAL_TIMING_CSV=str(raw), SPIRAL_TIMING_TRIAL=str(trial))
        with log.open("w") as f:
            proc = subprocess.run(["taskset", "-c", str(cpu), str(exe), "--exact", TEST,
                                   "--ignored", "--test-threads=1", "--nocapture"], env=env,
                                  cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, timeout=120)
        proc.check_returncode()
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in log.read_text():
            raise ValueError("timing probe did not complete")
        meta["trials"].append(summarize(raw))
        meta["sha256"][raw.name] = sha(raw)
    meta["interpretation"] = {d: interpret(meta["trials"], d) for d in DECISIONS}
    return meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory; archive is created alongside it")
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    out = args.output.expanduser().resolve()
    archive = Path(str(out) + ".tar.gz")
    if not hasattr(os, "sched_getaffinity") or not shutil.which("taskset"):
        parser.error("requires Linux with taskset")
    if archive.exists() or out.exists():
        parser.error("choose a new output path")
    out.mkdir(parents=True)
    try:
        result = collect(out, args.cargo)
        result["collection_complete"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result = {"collection_complete": False, "error": str(error), "constant_time_approved": False}
    (out / "result.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    with tarfile.open(archive, "x:gz") as tar:
        tar.add(out, arcname="results")
    print(json.dumps(result.get("interpretation", result.get("error"))), flush=True)
    print(archive)
    return 0 if result["collection_complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
