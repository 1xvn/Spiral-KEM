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
SAMPLE_FIELDS = ["decision", "comparison", "pair", "position", "class", "ns"]
CPU_FIELD = "thread_cpu_ns"
SCHEDSTAT_FIELDS = ("cpu_runtime_ns", "runqueue_wait_ns", "timeslices")


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def summarize(path, pairs=PAIRS):
    groups = defaultdict(dict)
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        has_cpu = reader.fieldnames == SAMPLE_FIELDS + [CPU_FIELD]
        if reader.fieldnames != SAMPLE_FIELDS and not has_cpu:
            raise ValueError("invalid sample header")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("invalid sample width")
            decision, comp = row["decision"], row["comparison"]
            pair, position, ns = (int(row[k]) for k in ("pair", "position", "ns"))
            group = row["class"]
            cpu_ns = int(row[CPU_FIELD]) if has_cpu and row[CPU_FIELD] else None
            if (decision not in DECISIONS or comp not in COMPARISONS
                    or not 0 <= pair < pairs or position not in (0, 1)
                    or group not in ("A", "B") or ns <= 0 or (cpu_ns is not None and cpu_ns < 0)):
                raise ValueError("invalid sample")
            observations = groups[decision, comp]
            if (pair, group) in observations:
                raise ValueError("duplicate sample")
            observations[pair, group] = position, ns, cpu_ns

    summaries = {}
    for decision in DECISIONS:
        summaries[decision] = {}
        for comp in COMPARISONS:
            values = groups[decision, comp]
            if len(values) != 2 * pairs:
                raise ValueError("incomplete comparison")
            delta = []
            for i in range(pairs):
                a_position, a, _ = values[i, "A"]
                b_position, b, _ = values[i, "B"]
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
            if has_cpu:
                summaries[decision][comp]["scheduler_observations"] = sample_scheduling(values, delta)
    return summaries


def sample_scheduling(values, delta):
    gaps = [wall - cpu for _, wall, cpu in values.values() if cpu is not None]
    top_pairs = sorted(range(len(delta)), key=lambda i: abs(delta[i]), reverse=True)[:3]
    outliers = []
    for i in top_pairs:
        pair = {"pair": i, "wall_delta_ns_B_minus_A": delta[i]}
        for group in ("A", "B"):
            position, wall, cpu = values[i, group]
            pair[group] = {
                "position": position, "wall_ns": wall, CPU_FIELD: cpu,
                "wall_minus_thread_cpu_ns": None if cpu is None else wall - cpu,
            }
        outliers.append(pair)
    return {
        "thread_cpu_samples": len(gaps),
        "thread_cpu_missing": len(values) - len(gaps),
        "thread_cpu_zero_samples": sum(cpu == 0 for _, _, cpu in values.values()),
        "median_wall_minus_thread_cpu_ns": statistics.median(gaps) if gaps else None,
        "largest_abs_wall_deltas": outliers,
    }


def summarize_schedstat(path):
    data = json.loads(path.read_text())
    enabled = data["schedstats_enabled"]
    if enabled is not None and type(enabled) is not bool:
        raise ValueError("invalid schedstats setting")
    stats = {d: {} for d in DECISIONS}
    for row in data["streams"]:
        d, c = row["decision"], row["comparison"]
        if d not in DECISIONS or c not in COMPARISONS or c in stats[d]:
            raise ValueError("invalid schedstat stream")
        before, after = row["before"], row["after"]
        for snapshot in (before, after):
            if snapshot is not None and (
                not isinstance(snapshot, list) or len(snapshot) != len(SCHEDSTAT_FIELDS)
                or any(type(n) is not int or n < 0 for n in snapshot)
            ):
                raise ValueError("invalid schedstat snapshot")
        delta = None
        if before is None or after is None:
            status = "unavailable"
        elif any(end < begin for begin, end in zip(before, after)):
            status = "counter_regressed"
        else:
            delta = dict(zip(SCHEDSTAT_FIELDS, (end - begin for begin, end in zip(before, after))))
            if enabled is False:
                status = "disabled"
            elif delta["runqueue_wait_ns"]:
                status = "nonzero_wait_reported"
            else:
                status = "zero_wait_reported"
        stats[d][c] = {"status": status, "delta": delta}
    if any(set(rows) != set(COMPARISONS) for rows in stats.values()):
        raise ValueError("missing schedstat stream")
    return {"schedstats_enabled": enabled, "streams": stats}


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
        "schema": 2, "source_commit": command("git", "rev-parse", "HEAD"),
        "tracked_changes": bool(command("git", "status", "--porcelain", "--untracked-files=no")),
        "rustc": command(os.environ.get("RUSTC", "rustc"), "-vV"), "cargo": command(cargo, "-V"),
        "kernel": platform.release(), "architecture": platform.machine(), "cpu": cpu,
        "available_cpus": cpus, "profile": "audit", "feature": "receive-timing",
        "cpu_model": next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text()
                           .splitlines() if line.startswith(("model name", "CPU part"))), "unknown"),
        "sha256": {"libtest": sha(exe), "lock": sha(manifest.with_name("Cargo.lock")),
                   "probe": sha(ROOT / "protocol_rust/src/receive_audit/timing.rs"), "collector": sha(Path(__file__))},
        "threshold_abs_t": THRESHOLD, "warmup_pairs_per_stream": 128, "clock": "std::time::Instant",
        "constant_time_approved": False, "trials": [], "schedstat_trials": [],
        "thread_cpu_clock": "CLOCK_THREAD_CPUTIME_ID (brackets wider than Instant)",
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
        summary = summarize(raw)
        if any("scheduler_observations" not in stream for rows in summary.values() for stream in rows.values()):
            raise ValueError("timing probe did not emit the thread CPU column")
        scheduler = raw.with_suffix(".scheduler.json")
        meta["trials"].append(summary)
        meta["schedstat_trials"].append(summarize_schedstat(scheduler))
        for path in (raw, scheduler):
            meta["sha256"][path.name] = sha(path)
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
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result = {"collection_complete": False, "error": str(error), "constant_time_approved": False}
    (out / "result.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    with tarfile.open(archive, "x:gz") as tar:
        tar.add(out, arcname="results")
    print(json.dumps(result.get("interpretation", result.get("error"))), flush=True)
    print(archive)
    return 0 if result["collection_complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
