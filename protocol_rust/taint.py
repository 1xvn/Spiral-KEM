"""Run explicit positive controls and scoped native/Rust secret-taint checks.

This is branch/address instrumentation, not a constant-time proof. The Rust test
binary must be built with `cargo test --profile audit --lib --no-run`.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-tests", type=Path, required=True)
    parser.add_argument(
        "--native-build", type=Path, default=root / "native_research/build"
    )
    parser.add_argument("--valgrind", default=shutil.which("valgrind"))
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--library-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.valgrind or bool(args.loader) != bool(args.library_path):
        parser.error("Valgrind required; loader/library-path must be paired")
    args.output.mkdir(parents=True, exist_ok=True)
    prefix = (
        [str(args.loader), "--library-path", str(args.library_path)]
        if args.loader
        else []
    )
    rust = str(args.rust_tests.resolve())
    native = args.native_build.resolve()
    base = "ffi::taint_audit::"
    cases = [
        (
            "rust-positive",
            [
                rust,
                "--exact",
                base + "positive_control",
                "--ignored",
                "--test-threads=1",
            ],
            99,
        ),
        (
            "rust-secret-path",
            [
                rust,
                "--exact",
                base + "rust_secret_derivation_sealing_and_signing",
                "--ignored",
                "--test-threads=1",
            ],
            0,
        ),
        ("native-positive", [str(native / "taint"), "positive"], 99),
        ("native-secret-path", [str(native / "taint")], 0),
        ("native-memory", [str(native / "check_memcheck")], 0),
    ]
    results = []
    for name, command, expected in cases:
        log = (args.output / f"{name}.log").resolve()
        p = subprocess.run(
            [
                str(args.valgrind),
                "--error-exitcode=99",
                "--track-origins=yes",
                "--leak-check=full",
                f"--log-file={log}",
                *prefix,
                *command,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        (args.output / f"{name}.stdout").write_text(p.stdout + p.stderr)
        match = re.search(r"ERROR SUMMARY: ([\d,]+) errors", log.read_text())
        errors = int(match[1].replace(",", "")) if match else None
        contents = log.read_text()
        branch_address_contexts = len(
            re.findall(
                r"Conditional jump or move depends|Use of uninitialised value|Invalid read|Invalid write|Syscall param .*uninitialised",
                contents,
            )
        )
        possible = re.search(r"possibly lost: ([\d,]+) bytes", contents)
        passed = (
            p.returncode == expected
            and errors is not None
            and (branch_address_contexts > 0 if expected == 99 else errors == 0)
        )
        item = {
            "case": name,
            "process_exit": p.returncode,
            "expected_exit": expected,
            "memcheck_errors": errors,
            "branch_address_contexts": branch_address_contexts,
            "possibly_lost_bytes": (
                int(possible[1].replace(",", "")) if possible else None
            ),
            "scoped_secret_branch_check_passed": (
                "secret-path" in name
                and branch_address_contexts == 0
                and "completed" in (p.stdout + p.stderr).lower()
                if name.startswith("native")
                else "secret-path" in name
                and branch_address_contexts == 0
                and "1 passed" in p.stdout
            ),
            "passed": passed,
            "binary_sha256": hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),
        }
        results.append(item)
        print(json.dumps(item), flush=True)
    (args.output / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    raise SystemExit(not all(item["passed"] for item in results))


if __name__ == "__main__":
    main()
