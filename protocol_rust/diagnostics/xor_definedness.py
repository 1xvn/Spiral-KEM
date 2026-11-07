#!/usr/bin/env python3
"""Reproduce a scoped x86-64 Valgrind definedness artifact, using public bytes.

Exit 0 means these diagnostic controls were consistent, not that production
memory checks passed. A newer tool may correctly track cancellation: that is
reported as not_reproduced, rather than requiring a false positive to pass.
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


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, directory, label, timeout=45):
    completed = subprocess.run(
        command, text=True, capture_output=True, timeout=timeout, check=False
    )
    (directory / f"{label}.stdout").write_text(completed.stdout, encoding="utf-8")
    (directory / f"{label}.stderr").write_text(completed.stderr, encoding="utf-8")
    return {
        "command": command,
        "exit": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def summary(log):
    matches = re.findall(
        r"ERROR SUMMARY: ([\d,]+) errors from ([\d,]+) contexts "
        r"\(suppressed: ([\d,]+) from ([\d,]+)\)", log
    )
    if len(matches) != 1:
        raise ValueError("expected exactly one complete Memcheck ERROR SUMMARY")
    values = [int(value.replace(",", "")) for value in matches[0]]
    leaks = {}
    for label in ("definitely lost", "indirectly lost", "possibly lost"):
        if "All heap blocks were freed -- no leaks are possible" in log:
            leaks[label] = 0
            continue
        match = re.search(rf"{label}:\s+([\d,]+) bytes", log)
        if not match:
            raise ValueError(f"missing leak summary: {label}")
        leaks[label] = int(match[1].replace(",", ""))
    return dict(zip(("errors", "contexts", "suppressed", "suppressed_contexts"), values)), leaks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new results directory")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--valgrind", default="valgrind")
    parser.add_argument("--valgrind-include", type=Path, help="parent of valgrind/memcheck.h")
    parser.add_argument("--loader", type=Path, help="optional debug-symbol matching ELF loader")
    parser.add_argument("--library-path", type=Path, help="paired with --loader")
    args = parser.parse_args()
    if bool(args.loader) != bool(args.library_path):
        parser.error("--loader and --library-path must be supplied together")
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("this assembly control requires Linux x86-64; OCI ARM is unsupported")
    if not re.search(r"\bavx\b", Path("/proc/cpuinfo").read_text(encoding="utf-8")):
        parser.error("AVX is required; no control was run")
    cc, valgrind = shutil.which(args.cc), shutil.which(args.valgrind)
    if not cc or not valgrind:
        parser.error("C compiler and Valgrind must both be installed")
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("--output must be a new directory to preserve earlier evidence")
    source = Path(__file__).resolve().parent
    binary = output / "xor_control"
    result = {
        "schema": "spiral-xor-definedness-control/v1",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "public fixture diagnostic only; no Spiral, TLS, keys or network",
        "production_memory_passed": False,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "valgrind_lib": os.environ.get("VALGRIND_LIB"),
        "source_sha256": {name: sha256(source / name) for name in
                          ("xor_control.c", "xor_control.S", "xor_definedness.py")},
        "cases": [],
        "diagnostic_consistent": False,
    }
    exit_code = 1
    try:
        result["compiler"] = run([cc, "--version"], output, "compiler-version")
        result["valgrind"] = run([valgrind, "--version"], output, "valgrind-version")
        command = [cc, "-O2", "-g", "-Wall", "-Wextra", "-Werror"]
        if args.valgrind_include:
            command += ["-I", str(args.valgrind_include.resolve())]
        command += [str(source / "xor_control.c"), str(source / "xor_control.S"),
                    "-o", str(binary)]
        result["build"] = run(command, output, "build")
        if result["build"]["exit"] != 0:
            raise ValueError("control compilation failed; inspect build.stderr")
        result["binary_sha256"] = sha256(binary)
        executable = [str(binary)]
        if args.loader:
            loader = args.loader.resolve()
            result["loader_sha256"] = sha256(loader)
            executable = [str(loader), "--library-path", str(args.library_path.resolve()),
                          str(binary)]
        for mode in ("cancel", "clear"):
            native = run(executable + [mode], output, f"{mode}-native")
            item = {"mode": mode, "native": native}
            result["cases"].append(item)
            native_values = json.loads(native["stdout"])
            expected_mode = "direct-clear" if mode == "clear" else "copy-branch-cancel"
            if (native["exit"] != 0 or native["stderr"] or native_values != {
                "mode": expected_mode, "zero_output_checks": 1000,
                "definedness_reports": 0, "running_on_valgrind": 0,
            }):
                raise ValueError(f"{mode} native control failed")
            log_path = output / f"{mode}-memcheck.log"
            checked = run([
                valgrind, "--tool=memcheck", "--error-exitcode=99", "--track-origins=yes",
                "--leak-check=full", "--show-leak-kinds=all", "--errors-for-leak-kinds=all",
                f"--log-file={log_path}", *executable, mode,
            ], output, f"{mode}-memcheck")
            item["memcheck"] = checked
            values = json.loads(checked["stdout"])
            counts, leaks = summary(log_path.read_text(encoding="utf-8"))
            item.update(values=values, summary=counts, leaks=leaks,
                        log_sha256=sha256(log_path))
            if (values.get("mode") != expected_mode or values.get("zero_output_checks") != 1000
                    or values.get("running_on_valgrind") != 1 or checked["stderr"]
                    or any(leaks.values()) or counts["suppressed"] != 0):
                raise ValueError(f"{mode} instrumentation, value or leak control failed")
            reports = values.get("definedness_reports")
            if reports == 0 and counts["errors"] == 0 and checked["exit"] == 0:
                item["observation"] = "not_reproduced" if mode == "cancel" else "defined_zero"
            elif (mode == "cancel" and reports == 1000 and counts["errors"] == 1000
                  and counts["contexts"] == 1 and checked["exit"] == 99):
                item["observation"] = "copy_branch_cancellation_false_positive_reproduced"
            else:
                raise ValueError(f"{mode} unexpected diagnostic errors; inspect the full log")
        result["diagnostic_consistent"] = True
        exit_code = 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["failure"] = str(exc)
    finally:
        (output / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps({"diagnostic_consistent": result["diagnostic_consistent"],
                      "production_memory_passed": False, "result": str(output / "result.json")},
                     ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
