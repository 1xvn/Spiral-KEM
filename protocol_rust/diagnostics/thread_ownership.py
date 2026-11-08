#!/usr/bin/env python3
"""Measure std thread ownership across repeated calls, joins and C exit paths.

These public, std-only controls never run Spiral, cryptography or secrets. Exit
zero means that all diagnostic observations completed and were understood; it
does not make any production memory check pass or resolve the original finding.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from protocol_rust.diagnostics.libtest_memory import parse_memcheck, run, sha256
from protocol_rust.fuzzing.campaign import bundle, write_report


RUSTC_RELEASE = "1.99.1"
RUSTC_COMMIT = "58cf8f9c35b355199727627d07ae34a4e2846d67"
MAIN_CASES = (
    "empty-main", "current-once", "current-many", "workers-1", "workers-8", "workers-64"
)
FOREIGN_CASES = (
    "foreign-empty-return", "foreign-touch-return",
    "foreign-empty-pthread-exit", "foreign-touch-pthread-exit",
)
CASE_NAMES = MAIN_CASES + FOREIGN_CASES

MAIN_SOURCE = r'''use std::hint::black_box;
use std::thread;

fn touch(count: usize) {
    for _ in 0..count {
        black_box(thread::current().id());
    }
}

fn main() {
    let mode = std::env::args().nth(1).expect("one mode is required");
    match mode.as_str() {
        "empty-main" => {},
        "current-once" => touch(1),
        "current-many" => touch(10_000),
        "workers-1" | "workers-8" | "workers-64" => {
            let count: usize = mode.strip_prefix("workers-").unwrap().parse().unwrap();
            // This main thread never calls current(). Each worker owns and
            // drops its temporary Thread handles before its joined exit.
            let workers: Vec<_> = (0..count).map(|_| thread::spawn(|| {
                touch(10);
                73_u32
            })).collect();
            for worker in workers {
                assert_eq!(worker.join().expect("worker panic"), 73);
            }
        },
        _ => panic!("unknown ownership control"),
    }
    println!("CONTROL_COMPLETED {}", mode);
}
'''

LIB_SOURCE = r'''#[unsafe(no_mangle)]
pub extern "C" fn ownership_touch_current() -> usize {
    // The temporary public Thread handle is dropped before returning to C.
    // No Rust frame remains when the C caller later invokes pthread_exit.
    std::hint::black_box(std::thread::current().id());
    73
}
'''

C_SOURCE = r'''#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern size_t ownership_touch_current(void);

int main(int argc, char **argv) {
    if (argc != 2) return 42;
    int touch = 0;
    int thread_exit = 0;
    if (strcmp(argv[1], "foreign-empty-return") == 0) {}
    else if (strcmp(argv[1], "foreign-touch-return") == 0) touch = 1;
    else if (strcmp(argv[1], "foreign-empty-pthread-exit") == 0) thread_exit = 1;
    else if (strcmp(argv[1], "foreign-touch-pthread-exit") == 0) {
        touch = 1;
        thread_exit = 1;
    } else return 42;
    if (touch && ownership_touch_current() != 73) return 43;
    if (printf("CONTROL_COMPLETED %s\n", argv[1]) < 0 || fflush(stdout) != 0) return 44;
    // This is C main after ownership_touch_current has returned completely.
    // No pthread cancellation unwinds across a live Rust stack frame.
    if (thread_exit) pthread_exit(NULL);
    return 0;
}
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native_libraries(text):
    """Accept only rustc's one Linux static-library dependency list."""
    matches = re.findall(r"(?m)^\s*(?:note: )?native-static-libs:\s*([^\n]+)$", text)
    require(len(matches) == 1, "expected one rustc native-static-libs list")
    libraries = shlex.split(matches[0])
    require(bool(libraries), "empty native-static-libs list")
    require(all(re.fullmatch(r"-l[A-Za-z0-9_+.\-]+", item) for item in libraries),
            "unsupported native-static-libs argument")
    return libraries


def expected_output(record, name):
    return (record.get("exit") in (0, 99)
            and record.get("timed_out") is False
            and not record.get("execution_error")
            and record.get("stdout") == f"CONTROL_COMPLETED {name}\n"
            and not record.get("stderr"))


def classify_measurement(log, process_exit):
    """Allow a completed diagnostic only for clean or exact std Thread48 logs."""
    parsed = parse_memcheck(log)
    summary, leaks = parsed["summary"], parsed["leaks"]
    require(not summary["suppressed_errors"] and not summary["suppressed_contexts"]
            and leaks["suppressed"] == {"bytes": 0, "blocks": 0},
            "suppressed diagnostics cannot establish ownership")
    require(leaks["definitely lost"] == {"bytes": 0, "blocks": 0}
            and leaks["indirectly lost"] == {"bytes": 0, "blocks": 0},
            "unexpected definite or indirect loss")
    require(not re.search(
        r"Invalid (?:read|write|free)|Mismatched free|Conditional jump or move depends"
        r"|Use of uninitialised value|Syscall param .*uninitialised", log),
        "unexpected memory-use errors")
    records = parsed["possibly_lost_48_records"]
    known = [record for record in records if
             "std::thread::current::init_current" in record["stack"]
             and "std::thread::thread::Thread" in record["stack"]
             and "ArcInner" in record["stack"]]
    count = len(known)
    require(len(records) == count, "48-byte record lacks the exact std Thread allocation stack")
    require(leaks["possibly lost"] == {"bytes": count * 48, "blocks": count},
            "unexpected possibly-lost allocation size or count")
    require(summary["errors"] == summary["contexts"] == count,
            "ERROR SUMMARY includes diagnostics beyond the exact Thread48 records")
    require(process_exit == (99 if count else 0),
            "Memcheck exit disagrees with complete diagnostics")
    parsed.update(
        observation="scoped_std_thread_48" if count else "no_errors_observed",
        scoped_thread_48_blocks=count,
        memory_measurement_passed=(count == 0),
    )
    return parsed


def compare_lifetimes(cases):
    """Interpret observed changes; do not assume a foreign-exit result."""
    require({case["name"] for case in cases} == set(CASE_NAMES)
            and len(cases) == len(CASE_NAMES), "all ten distinct controls are required")
    values = {case["name"]: case["scoped_thread_48_blocks"] for case in cases}
    checks = {
        "empty_rust_main_clean": values["empty-main"] == 0,
        "one_current_call_retains_one_thread_block": values["current-once"] == 1,
        "ten_thousand_current_calls_still_one_block": values["current-many"] == 1,
        "joined_workers_clean": all(values[f"workers-{n}"] == 0 for n in (1, 8, 64)),
        "foreign_empty_return_clean": values["foreign-empty-return"] == 0,
        "foreign_empty_pthread_exit_clean": values["foreign-empty-pthread-exit"] == 0,
        "foreign_touch_return_retains_one_block": values["foreign-touch-return"] == 1,
        "foreign_touch_pthread_exit_releases_block": values["foreign-touch-pthread-exit"] == 0,
    }
    if all(checks.values()):
        classification = "supports_thread_local_ownership_and_exit_lifetime"
    elif not any(values.values()):
        classification = "not_reproduced"
    else:
        classification = "different_or_partial_pattern"
    return {"classification": classification, "checks": checks,
            "scoped_thread_48_blocks": values,
            "production_memory_passed": False, "original_finding_resolved": False}


def located(argument, parser):
    value = shutil.which(str(argument))
    if value is None:
        parser.error("executable not found: " + str(argument))
    return str(Path(value).resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--valgrind", required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--library-path", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "aarch64") or struct.calcsize("P") != 8:
        parser.error("64-bit Linux x86_64 or aarch64 is required")
    if bool(args.loader) != bool(args.library_path):
        parser.error("loader and library-path must be paired")
    if args.loader and (not args.loader.is_file() or not args.library_path.is_dir()):
        parser.error("loader file or library-path directory is absent")
    tools = {name: located(value, parser) for name, value in
             (("rustc", args.rustc), ("valgrind", args.valgrind), ("cc", args.cc))}
    output = args.output.expanduser().absolute()
    archive = Path(str(output) + ".tar.gz")
    if archive.exists():
        parser.error("archive already exists")
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error("output must be a new directory: " + str(error))
    output = output.resolve()
    build = output / "build"
    build.mkdir()
    env = dict(os.environ)
    env.update(LC_ALL="C", RUST_BACKTRACE="0")
    env.pop("VALGRIND_OPTS", None)
    result = {
        "schema": "spiral-rust-thread-ownership/v1",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "public std-only controls; no Spiral, cryptography, secret or network",
        "platform": platform.platform(), "machine": platform.machine(),
        "runner_sha256": sha256(Path(__file__)), "diagnostic_complete": False,
        "production_memory_passed": False, "original_finding_resolved": False,
        "tools": {}, "sources": {}, "builds": {}, "cases": [], "errors": [],
        "archive": str(archive),
    }

    def checked_run(label, command):
        record = run(command, output, label, env)
        require(record["exit"] == 0 and not record["timed_out"], label + " failed")
        return record

    try:
        for name, command in (("rustc", [tools["rustc"], "-Vv"]),
                              ("valgrind", [tools["valgrind"], "--version"]),
                              ("cc", [tools["cc"], "--version"])):
            record = checked_run(name + "-version", command)
            require(bool(record["stdout"].strip()), name + " version output is absent")
            record["executable_sha256"] = sha256(Path(command[0]))
            result["tools"][name] = record
        version = result["tools"]["rustc"]["stdout"]
        require(f"release: {RUSTC_RELEASE}\n" in version
                and f"commit-hash: {RUSTC_COMMIT}\n" in version,
                "the pinned Rust 1.99.1 compiler is required")

        for filename, contents in (("thread_main.rs", MAIN_SOURCE),
                                   ("thread_static.rs", LIB_SOURCE),
                                   ("foreign_main.c", C_SOURCE)):
            path = output / filename
            path.write_text(contents)
            result["sources"][filename] = {"sha256": sha256(path), "bytes": path.stat().st_size}
        rust_flags = ["--edition=2021", "--color=never", "-g", "-Copt-level=2", "-Cpanic=abort"]
        binary = build / "thread-main"
        record = checked_run("build-main", [tools["rustc"], *rust_flags,
                             str(output / "thread_main.rs"), "-o", str(binary)])
        result["builds"]["main"] = {**record, "binary_sha256": sha256(binary)}
        static = build / "libthread_control.a"
        record = checked_run("build-static", [tools["rustc"], *rust_flags,
                             "--crate-type=staticlib", "--print=native-static-libs",
                             str(output / "thread_static.rs"), "-o", str(static)])
        libraries = native_libraries(record["stdout"] + "\n" + record["stderr"])
        result["builds"]["static"] = {**record, "binary_sha256": sha256(static),
                                        "native_libraries": libraries}
        foreign = build / "foreign-main"
        record = checked_run("build-foreign", [tools["cc"], "-std=c11", "-g", "-O2", "-Wall", "-Wextra", "-Werror",
                             str(output / "foreign_main.c"), str(static), *libraries, "-o", str(foreign)])
        result["builds"]["foreign"] = {**record, "binary_sha256": sha256(foreign)}

        prefix = []
        if args.loader:
            loader = args.loader.resolve()
            libraries = args.library_path.resolve()
            prefix = [str(loader), "--library-path", str(libraries)]
            result["loader"] = {"path": str(loader), "sha256": sha256(loader),
                                "library_path": str(libraries),
                                "applies_to": "native and Memcheck cases"}
        for name in CASE_NAMES:
            command = prefix + [str(binary if name in MAIN_CASES else foreign), name]
            case = {"name": name, "diagnostic_complete": False,
                    "production_memory_passed": False, "errors": []}
            result["cases"].append(case)
            native = run(command, output, name + "-native", env)
            case["native"] = native
            if native["exit"] != 0 or not expected_output(native, name):
                case["errors"].append("native execution did not complete exactly")
            log = output / (name + "-memcheck.log")
            measured = run([tools["valgrind"], "--command-line-only=yes", "--tool=memcheck",
                            "--leak-check=full", "--show-leak-kinds=all", "--num-callers=40",
                            "--errors-for-leak-kinds=definite,indirect,possible", "--error-exitcode=99",
                            "--track-origins=yes", "--log-file=" + str(log), *command],
                           output, name + "-memcheck", env)
            case["memcheck"] = measured
            if not expected_output(measured, name):
                case["errors"].append("Memcheck execution did not complete exactly")
            if log.is_file():
                measured.update(log_file=log.name, log_sha256=sha256(log))
                try:
                    case.update(classify_measurement(log.read_text(errors="replace"), measured["exit"]))
                except ValueError as error:
                    case["errors"].append(str(error))
            else:
                case["errors"].append("Memcheck log is absent")
            case["diagnostic_complete"] = not case["errors"]
            result["errors"].extend(name + ": " + error for error in case["errors"])
            print(json.dumps({"case": name, "diagnostic_complete": case["diagnostic_complete"],
                              "memcheck_exit": measured["exit"],
                              "thread_48_blocks": case.get("scoped_thread_48_blocks")}), flush=True)
        if not result["errors"]:
            result["comparison"] = compare_lifetimes(result["cases"])
            result["diagnostic_complete"] = True
    except (OSError, ValueError) as error:
        result["errors"].append(str(error))
    finally:
        write_report(output, result)
        try:
            bundle(output, archive)
        except (OSError, ValueError, RuntimeError) as error:
            result["diagnostic_complete"] = False
            result["errors"].append("archive: " + str(error))
            write_report(output, result)
    print(json.dumps({"diagnostic_complete": result["diagnostic_complete"],
                      "production_memory_passed": False, "original_finding_resolved": False,
                      "comparison": result.get("comparison"), "archive": str(archive),
                      "errors": result["errors"]}))
    return 0 if result["diagnostic_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
