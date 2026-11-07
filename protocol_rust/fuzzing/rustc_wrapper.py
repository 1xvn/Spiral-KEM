#!/usr/bin/env python3
"""Add protocol-crate feedback and record every rustc invocation.

The runner supplies ASan flags separately.  Only the exact production library
crate receives libFuzzer feedback; the targets and independent oracles do not.
"""

import json
import os
import sys


COVERAGE_FLAGS = (
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
)
IR_CRATES = frozenset(
    {"spiral_protocol", "frame_target", "hello_target", "replay_target",
     "record_target", "record_replay"}
)


def _option_occurrences(args, option):
    """Return (value index, is combined, value) for a rustc option."""
    occurrences = []
    prefix = option + "="
    for index, arg in enumerate(args):
        if arg == option:
            if index + 1 == len(args) or args[index + 1].startswith("-"):
                raise ValueError(f"missing value for {option}")
            occurrences.append((index + 1, False, args[index + 1]))
        elif arg.startswith(prefix):
            value = arg[len(prefix) :]
            if not value:
                raise ValueError(f"missing value for {option}")
            occurrences.append((index, True, value))
    return occurrences


def instrument_args(args):
    """Return the final rustc arguments and deterministic audit metadata."""
    new_args = list(args)
    names = [item[2] for item in _option_occurrences(new_args, "--crate-name")]
    types = [item[2] for item in _option_occurrences(new_args, "--crate-type")]
    crate_name = names[0] if len(names) == 1 else None
    crate_type = types[0] if len(types) == 1 else None
    is_query = any(
        arg in {"-vV", "-V", "--version", "-h", "--help", "--print"}
        or arg.startswith(("--print=", "--help="))
        for arg in new_args
    )
    coverage_match = names == ["spiral_protocol"] and types == ["lib"]
    coverage_enabled = coverage_match and not is_query
    llvm_ir_enabled = crate_name in IR_CRATES and not is_query

    if llvm_ir_enabled:
        emits = _option_occurrences(new_args, "--emit")
        already_emits_ir = any(
            output.split("=", 1)[0] == "llvm-ir"
            for _, _, value in emits
            for output in value.split(",")
        )
        if not already_emits_ir:
            if emits:
                index, combined, value = emits[-1]
                new_args[index] = ("--emit=" if combined else "") + value + ",llvm-ir"
            else:
                # Without --emit, rustc normally emits a linked artifact.
                new_args.append("--emit=link,llvm-ir")

    if coverage_enabled:
        new_args.extend(COVERAGE_FLAGS)

    return new_args, {
        "crate_name": crate_name,
        "crate_type": crate_type,
        "crate_names": names,
        "crate_types": types,
        "coverage_match": coverage_match,
        "coverage_enabled": coverage_enabled,
        "llvm_ir_enabled": llvm_ir_enabled,
        "is_query": is_query,
        "args": list(new_args),
    }


def main():
    trace_path = os.environ.get("SPIRAL_RUSTC_TRACE")
    if not trace_path:
        raise ValueError("SPIRAL_RUSTC_TRACE must name the rustc audit log")
    if len(sys.argv) < 2:
        raise ValueError("expected rustc path followed by rustc arguments")

    rustc = sys.argv[1]
    args, metadata = instrument_args(sys.argv[2:])
    metadata.update({"rustc": rustc, "pid": os.getpid()})
    record = (json.dumps(metadata, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(trace_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        # A single O_APPEND write keeps concurrent compiler records together.
        if os.write(descriptor, record) != len(record):
            raise OSError("partial write to rustc audit log")
    finally:
        os.close(descriptor)
    os.execv(rustc, [rustc, *args])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"rustc_wrapper.py: {error}", file=sys.stderr)
        sys.exit(1)
