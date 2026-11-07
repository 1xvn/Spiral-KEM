#!/usr/bin/env python3
"""Measure Rust std/libtest memory controls without Spiral or cryptographic code.

Exit 0 means the diagnostic completed, including any recorded Memcheck exit 99.
It never means production memory checks passed or the original finding is fixed.
Install the requested tools separately; this runner never downloads dependencies.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


RUST_SOURCE = r'''use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let mode = std::env::args().nth(1).expect("a control mode is required");
    match mode.as_str() {
        "empty-main" => {},
        "thread-current" => {
            std::hint::black_box(thread::current().id());
        },
        "thread-join" => {
            let value = thread::spawn(|| 73_u32).join().expect("worker panicked");
            assert_eq!(value, 73);
        },
        "channel-roundtrip" => {
            let (gate_tx, gate_rx) = mpsc::sync_channel::<()>(0);
            let (value_tx, value_rx) = mpsc::channel::<u32>();
            let worker = thread::spawn(move || {
                gate_rx.recv().expect("gate disconnected");
                value_tx.send(73).expect("value receiver disconnected");
            });
            // The sender cannot publish until this receive has blocked and
            // timed out. This exercises the main thread's channel context
            // even when scheduling would otherwise take a fast receive path.
            assert!(matches!(value_rx.recv_timeout(Duration::from_millis(10)),
                             Err(mpsc::RecvTimeoutError::Timeout)));
            gate_tx.send(()).expect("gate receiver disconnected");
            assert_eq!(value_rx.recv().expect("value sender disconnected"), 73);
            worker.join().expect("worker panicked");
        },
        _ => panic!("unknown control mode"),
    }
    println!("CONTROL_COMPLETED {}", mode);
}

#[cfg(test)]
mod control {
    #[test]
    fn empty() {}
}
'''

LEAK_KINDS = (
    "definitely lost", "indirectly lost", "possibly lost", "still reachable", "suppressed"
)
TIMEOUT_SECONDS = 120


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_bytes(value):
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")


def run(command, directory, label, env):
    """Keep raw subprocess output, including partial output on timeout."""
    record = {"command": command, "timeout_seconds": TIMEOUT_SECONDS}
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=TIMEOUT_SECONDS, check=False, env=env
        )
        stdout, stderr = completed.stdout, completed.stderr
        record.update(exit=completed.returncode, timed_out=False)
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = text_bytes(exc.stdout), text_bytes(exc.stderr)
        record.update(exit=None, timed_out=True)
    except OSError as exc:
        stdout, stderr = b"", str(exc).encode("utf-8", errors="replace")
        record.update(exit=None, timed_out=False, execution_error=str(exc))
    stdout_path = directory / f"{label}.stdout"
    stderr_path = directory / f"{label}.stderr"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    record.update(
        stdout_file=stdout_path.name, stderr_file=stderr_path.name,
        stdout_sha256=sha256(stdout_path), stderr_sha256=sha256(stderr_path),
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )
    return record


def parse_memcheck(log):
    """Require a complete summary, and retain each 48-byte loss record's stack."""
    counts = re.findall(
        r"ERROR SUMMARY: ([\d,]+) errors from ([\d,]+) contexts "
        r"\(suppressed: ([\d,]+) from ([\d,]+)\)", log
    )
    if len(counts) != 1:
        raise ValueError("expected exactly one complete Memcheck ERROR SUMMARY")
    summary = dict(zip(
        ("errors", "contexts", "suppressed_errors", "suppressed_contexts"),
        (int(value.replace(",", "")) for value in counts[0]),
    ))
    leaks = {}
    all_freed = "All heap blocks were freed -- no leaks are possible" in log
    for kind in LEAK_KINDS:
        matches = re.findall(
            rf"\b{re.escape(kind)}:\s+([\d,]+) bytes in ([\d,]+) blocks", log
        )
        if len(matches) == 1:
            byte_count, block_count = (int(v.replace(",", "")) for v in matches[0])
        elif all_freed and not matches:
            byte_count, block_count = 0, 0
        else:
            raise ValueError(f"missing or ambiguous leak summary: {kind}")
        leaks[kind] = {"bytes": byte_count, "blocks": block_count}

    records = []
    lines = log.splitlines()
    for index, line in enumerate(lines):
        if not re.search(r"\b48 bytes in 1 blocks are possibly lost in loss record\b", line):
            continue
        stack_lines = [line]
        for next_line in lines[index + 1:]:
            # Valgrind's blank lines normally retain their ==PID== prefix.
            if not re.sub(r"^==\d+==\s*", "", next_line).strip():
                break
            stack_lines.append(next_line)
        stack = "\n".join(stack_lines)
        thread_frame = "std::thread::" in stack
        channel_frame = "std::sync::mpmc" in stack
        libtest_frame = bool(re.search(r"(?:\btest::|\blibtest\b)", stack))
        records.append({
            "stack": stack,
            "std_thread_frame": thread_frame,
            "std_channel_frame": channel_frame,
            "libtest_frame": libtest_frame,
            "classification": (
                "std_thread_and_libtest" if thread_frame and libtest_frame else
                "std_thread_or_channel" if thread_frame or channel_frame else "other"
            ),
        })
    return {"summary": summary, "leaks": leaks, "possibly_lost_48_records": records}


def output_is_expected(record, mode):
    if mode is not None:
        return record["stdout"] == f"CONTROL_COMPLETED {mode}\n" and not record["stderr"]
    # --exact and the expected count rule out a misspelled filter / zero tests.
    stdout = record["stdout"]
    return (
        re.search(r"(?m)^running 1 test\s*$", stdout) is not None
        and re.search(r"(?m)^test control::empty \.\.\. ok\s*$", stdout) is not None
        and re.search(
            r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
            stdout,
        ) is not None
        and not record["stderr"]
    )


def executable(argument, parser):
    located = shutil.which(argument)
    if not located:
        parser.error(f"executable not found or not executable: {argument}")
    return str(Path(located).resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True, help="installed Rust compiler path")
    parser.add_argument("--valgrind", required=True, help="installed Valgrind path")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--loader", type=Path, help="optional matching ELF loader")
    parser.add_argument("--library-path", type=Path, help="library directory paired with --loader")
    args = parser.parse_args()
    if bool(args.loader) != bool(args.library_path):
        parser.error("--loader and --library-path must be supplied together")
    rustc = executable(args.rustc, parser)
    valgrind = executable(args.valgrind, parser)
    if args.loader and (not args.loader.is_file() or not args.library_path.is_dir()):
        parser.error("--loader must be a file and --library-path must be a directory")
    output = args.output.absolute()
    try:
        # Do not resolve the final component first: even a dangling symlink is
        # existing evidence and must not be followed or overwritten.
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(f"--output must be a new writable directory: {exc}")
    output = output.resolve()
    env = os.environ.copy()
    env.pop("RUST_TEST_NOCAPTURE", None)
    # Keep parser formats reproducible without recording unrelated environment.
    env["LC_ALL"] = "C"
    result = {
        "schema": "spiral-rust-libtest-memory-controls/v1",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "public std/libtest fixtures only; no Spiral, cryptography, secrets or network",
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(),
        "runner_sha256": sha256(Path(__file__).resolve()),
        "timeout_seconds_per_command": TIMEOUT_SECONDS,
        "production_memory_passed": False,
        "original_finding_resolved": False,
        "diagnostic_complete": False,
        "errors": [], "cases": [],
        "interpretation": "inconclusive: diagnostic has not completed",
    }
    status = 1
    try:
        source = output / "std_libtest_control.rs"
        source.write_text(RUST_SOURCE, encoding="utf-8")
        result["source"] = {"file": source.name, "sha256": sha256(source)}
        result["tools"] = {}
        for name, command in (("rustc", [rustc, "-Vv"]),
                              ("valgrind", [valgrind, "--version"])):
            record = run(command, output, f"{name}-version", env)
            result["tools"][name] = record
            result["tools"][name]["executable_sha256"] = sha256(Path(command[0]))
            if record["exit"] != 0 or not record["stdout"].strip():
                raise ValueError(f"{name} version command failed")
        prefix = []
        if args.loader:
            loader = args.loader.resolve()
            library_path = args.library_path.resolve()
            prefix = [str(loader), "--library-path", str(library_path)]
            result["loader"] = {
                "path": str(loader), "sha256": sha256(loader),
                "library_path": str(library_path),
                "applies_to": "both native and Memcheck fixture executions",
            }
        binaries = {"main": output / "std-control", "libtest": output / "libtest-control"}
        result["builds"] = {}
        for name, binary in binaries.items():
            command = [rustc, "-g", "-C", "opt-level=2"]
            if name == "libtest":
                command.append("--test")
            command += [str(source), "-o", str(binary)]
            record = run(command, output, f"build-{name}", env)
            result["builds"][name] = record
            if record["exit"] != 0 or not binary.is_file():
                raise ValueError(f"{name} compilation failed")
            record.update(binary=binary.name, binary_sha256=sha256(binary))

        cases = [(mode, "main", mode, None) for mode in
                 ("empty-main", "thread-current", "thread-join", "channel-roundtrip")]
        cases += [("libtest-default", "libtest", None, None),
                  ("libtest-nocapture", "libtest", None, "1")]
        for name, binary_kind, mode, nocapture in cases:
            case_env = env.copy()
            if nocapture is not None:
                case_env["RUST_TEST_NOCAPTURE"] = nocapture
            command = prefix + [str(binaries[binary_kind])]
            command += [mode] if mode else ["--exact", "control::empty", "--test-threads=1"]
            item = {"name": name, "rust_test_nocapture": nocapture,
                    "diagnostic_complete": False, "production_memory_passed": False,
                    "errors": []}
            result["cases"].append(item)
            native = run(command, output, f"{name}-native", case_env)
            item["native"] = native
            native["expected_output"] = output_is_expected(native, mode)
            if native["exit"] != 0 or not native["expected_output"]:
                item["errors"].append("native control failed, timed out, or produced unexpected output")
            log_path = output / f"{name}-memcheck.log"
            checked = run([
                valgrind, "--command-line-only=yes", "--tool=memcheck",
                "--leak-check=full", "--show-leak-kinds=all",
                "--errors-for-leak-kinds=definite,indirect,possible", "--error-exitcode=99",
                "--track-origins=yes", f"--log-file={log_path}", *command,
            ], output, f"{name}-memcheck", case_env)
            item["memcheck"] = checked
            checked["expected_output"] = output_is_expected(checked, mode)
            if checked["exit"] not in (0, 99) or not checked["expected_output"]:
                item["errors"].append("Memcheck control failed, timed out, or produced unexpected output")
            if log_path.is_file():
                checked.update(log_file=log_path.name, log_sha256=sha256(log_path))
                try:
                    item.update(parse_memcheck(log_path.read_text(encoding="utf-8", errors="replace")))
                except ValueError as exc:
                    item["errors"].append(str(exc))
            else:
                item["errors"].append("Memcheck log is missing")
            if "summary" in item:
                measured_errors = item["summary"]["errors"]
                expected_exit = 99 if measured_errors else 0
                if checked["exit"] != expected_exit:
                    item["errors"].append("Memcheck exit does not agree with ERROR SUMMARY")
                item["observation"] = (
                    "measurement_failed_with_errors" if measured_errors else "no_errors_observed"
                )
                known_records = [record for record in item["possibly_lost_48_records"]
                                 if record["classification"] != "other"]
                known_count = len(known_records)
                known_runtime_only = (
                    measured_errors == known_count
                    and item["summary"]["contexts"] == known_count
                    and item["leaks"]["possibly lost"] == {
                        "bytes": 48 * known_count, "blocks": known_count,
                    }
                    and item["leaks"]["definitely lost"]["bytes"] == 0
                    and item["leaks"]["indirectly lost"]["bytes"] == 0
                )
                item["only_scoped_runtime_48_errors"] = known_runtime_only and measured_errors > 0
                if measured_errors and not known_runtime_only:
                    item["errors"].append("unexpected Memcheck errors beyond the scoped runtime 48-byte signature")
                if (item["summary"]["suppressed_errors"] or
                        item["leaks"]["suppressed"]["bytes"]):
                    item["errors"].append("suppressed Memcheck errors or leaks make the control inconclusive")
                item["memory_measurement_passed"] = (
                    checked["exit"] == 0 and measured_errors == 0 and not item["errors"]
                )
            item["diagnostic_complete"] = not item["errors"]
            result["errors"].extend(f"{name}: {error}" for error in item["errors"])

        result["diagnostic_complete"] = not result["errors"]
        reproduced = [case["name"] for case in result["cases"] if any(
            record["classification"] in ("std_thread_and_libtest", "std_thread_or_channel")
            for record in case.get("possibly_lost_48_records", [])
        )]
        result["runtime_48_byte_warning_reproduced_in"] = reproduced
        if result["diagnostic_complete"] and reproduced:
            result["interpretation"] = (
                "A 48-byte possibly-lost allocation with std thread/channel or libtest frames "
                "was reproduced without Spiral. This supports a runtime attribution hypothesis; "
                "it does not establish the cause of the original finding, prove harmlessness, "
                "or make the production memory check pass."
            )
        elif result["diagnostic_complete"]:
            result["interpretation"] = (
                "inconclusive: the scoped runtime signature was not reproduced; "
                "the original finding remains unresolved"
            )
        else:
            result["interpretation"] = "inconclusive: one or more diagnostic controls did not complete"
        status = 0 if result["diagnostic_complete"] else 1
    except (OSError, ValueError) as exc:
        result["errors"].append(str(exc))
    finally:
        (output / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps({
        "diagnostic_complete": result["diagnostic_complete"],
        "production_memory_passed": False,
        "original_finding_resolved": False,
        "result": str(output / "result.json"),
        "interpretation": result["interpretation"],
    }, ensure_ascii=False))
    return status


if __name__ == "__main__":
    sys.exit(main())
