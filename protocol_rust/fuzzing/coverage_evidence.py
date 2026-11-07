"""Verify and retain evidence for Rust parser-only libFuzzer feedback."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


CRATES = ("spiral_protocol", "frame_target", "hello_target", "replay_target")
COVERAGE_CODEGEN = frozenset(
    {
        "passes=sancov-module",
        "llvm-args=-sanitizer-coverage-level=4",
        "llvm-args=-sanitizer-coverage-inline-8bit-counters",
        "llvm-args=-sanitizer-coverage-pc-table",
        "llvm-args=-sanitizer-coverage-trace-compares",
    }
)
FUNCTION_MARKERS = {
    "header_parse": "6Header5parse",
    "wire_parse": "4wire5parse",
    "parse_frame": "11parse_frame",
    "parse_client_hello": "18parse_client_hello",
    "parse_hello": "11parse_hello",
    "validate_identity": "17validate_identity",
}
FRAME_FUNCTIONS = ("header_parse", "wire_parse", "parse_frame")
HELLO_FUNCTIONS = ("parse_client_hello", "parse_hello", "validate_identity")
IR_SYMBOL = re.compile(rb'@(?:"([^"\n]+)"|([^\s(]+))\(')


def _require(condition, message):
    if not condition:
        raise ValueError("coverage evidence: " + message)


def _file_info(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": size}


def _values(args, option):
    values = []
    for index, arg in enumerate(args):
        if arg == option:
            _require(index + 1 < len(args), f"missing value for {option}")
            values.append(args[index + 1])
        elif option.startswith("--") and arg.startswith(option + "="):
            values.append(arg[len(option) + 1 :])
        elif option in {"-C", "-Z"} and arg.startswith(option) and len(arg) > 2:
            values.append(arg[2:])
    return values


def _function_label(symbol):
    if "spiral_protocol" not in symbol:
        return None
    for label, marker in FUNCTION_MARKERS.items():
        if marker not in symbol:
            continue
        suffix = symbol.split(marker, 1)[1]
        # Accept v0 names, LLVM clone suffixes, and legacy Rust hash suffixes;
        # exclude nested helpers such as parse_hello::take and closures.
        if not suffix or re.fullmatch(r"(?:\.[A-Za-z0-9_$]+)+|\d+h[0-9a-f]+E", suffix):
            return label
    return None


def _read_trace(trace_path):
    records = []
    with trace_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            _require(bool(line.strip()), f"empty audit record at line {line_number}")
            record = json.loads(line)
            _require(isinstance(record, dict), f"invalid audit record at line {line_number}")
            required = {
                "args", "crate_name", "crate_type", "crate_names", "crate_types",
                "coverage_enabled", "coverage_match", "llvm_ir_enabled", "is_query",
                "rustc", "pid",
            }
            _require(required.issubset(record), f"missing audit metadata at line {line_number}")
            _require(isinstance(record["rustc"], str) and bool(record["rustc"]), "missing audited compiler path")
            _require(type(record["pid"]) is int and record["pid"] > 0, "invalid audited compiler process")
            args = record.get("args")
            _require(
                isinstance(args, list) and all(isinstance(arg, str) for arg in args),
                f"missing compiler arguments at audit line {line_number}",
            )
            names = _values(args, "--crate-name")
            types = _values(args, "--crate-type")
            name = names[0] if len(names) == 1 else None
            crate_type = types[0] if len(types) == 1 else None
            query = any(
                arg in {"-vV", "-V", "--version", "-h", "--help", "--print"}
                or arg.startswith(("--print=", "--help="))
                for arg in args
            )
            expected = names == ["spiral_protocol"] and types == ["lib"] and not query
            _require(record.get("crate_name") == name, "crate-name audit mismatch")
            _require(record.get("crate_type") == crate_type, "crate-type audit mismatch")
            _require(record["crate_names"] == names and record["crate_types"] == types, "crate option occurrence audit mismatch")
            _require(record["is_query"] is query, "compiler query audit mismatch")
            _require(record["coverage_match"] is (names == ["spiral_protocol"] and types == ["lib"]), "coverage crate match audit mismatch")
            _require(record.get("coverage_enabled") is expected, "coverage decision audit mismatch")
            ir_expected = name in CRATES and not query
            _require(record.get("llvm_ir_enabled") is ir_expected, "LLVM IR decision audit mismatch")
            codegen = _values(args, "-C")
            feedback = [value for value in codegen if "sancov" in value or "sanitizer-coverage" in value]
            if expected:
                _require(COVERAGE_CODEGEN.issubset(codegen), "production coverage flags are incomplete")
            else:
                _require(not feedback, f"feedback instrumentation leaked into {name!r}")
            if ir_expected:
                emits = [item for value in _values(args, "--emit") for item in value.split(",")]
                _require(any(item.split("=", 1)[0] == "llvm-ir" for item in emits), f"no IR output for {name}")
                units = [value.partition("=")[2] for value in codegen if value.partition("=")[0] == "codegen-units"]
                _require(bool(units) and all(value == "1" for value in units), f"multiple codegen units for {name}")
                for value in codegen:
                    key, _, setting = value.partition("=")
                    if key in {"lto", "linker-plugin-lto"}:
                        _require(setting in {"off", "false", "no", "0"}, f"LTO enabled for {name}")
            records.append(record)
    _require(bool(records), "empty compiler audit")
    for name in CRATES:
        _require(any(record.get("crate_name") == name and record.get("llvm_ir_enabled") for record in records), f"missing compiler audit for {name}")
    return records


def _ir_path(record, build_dir):
    args = record["args"]
    directories = _values(args, "--out-dir")
    _require(len(directories) == 1, f"ambiguous output directory for {record['crate_name']}")
    directory = Path(directories[0])
    _require(directory.is_absolute(), "compiler output directory is not absolute")
    directory = directory.resolve()
    _require(directory.is_relative_to(build_dir), "compiler output is outside the audited build directory")
    explicit = [
        output.split("=", 1)[1]
        for value in _values(args, "--emit")
        for output in value.split(",")
        if output.startswith("llvm-ir=")
    ]
    if explicit:
        _require(len(explicit) == 1, "ambiguous explicit LLVM IR output")
        path = Path(explicit[0])
        _require(path.is_absolute(), "cannot attribute a relative explicit LLVM IR output")
    else:
        extra = [value.split("=", 1)[1] for value in _values(args, "-C") if value.startswith("extra-filename=")]
        _require(len(extra) <= 1, "ambiguous compiler output suffix")
        path = directory / (record["crate_name"] + (extra[0] if extra else "") + ".ll")
    path = path.resolve()
    _require(path.is_relative_to(build_dir) and path.is_file(), f"missing audited LLVM IR: {path}")
    return path


def _linked_output(record, build_dir):
    args = record["args"]
    directories = _values(args, "--out-dir")
    extra = [value.split("=", 1)[1] for value in _values(args, "-C") if value.startswith("extra-filename=")]
    _require(len(directories) == 1 and len(extra) <= 1, "ambiguous audited executable output")
    _require(not any(arg == "-o" or arg.startswith("-o=") for arg in args), "explicit executable output is unsupported")
    targets = _values(args, "--target")
    _require(len(targets) == 1 and "-linux-" in targets[0], "an explicit Linux target is required")
    path = (Path(directories[0]) / (record["crate_name"] + (extra[0] if extra else ""))).resolve()
    _require(path.is_relative_to(build_dir) and path.is_file(), f"missing audited executable output: {path}")
    return path


def _inspect_ir(path, production):
    digest = hashlib.sha256()
    size = 0
    counts = {"sancov_counter_section_tokens": 0, "sancov_generated_tokens": 0, "trace_callback_tokens": 0}
    tokens = {
        "sancov_counter_section_tokens": b"__sancov_cntrs",
        "sancov_generated_tokens": b"__sancov_gen_",
        "trace_callback_tokens": b"__sanitizer_cov_trace_",
    }
    functions = {}
    bodies = {}
    current = None
    body = []
    with path.open("rb") as stream:
        for line in stream:
            digest.update(line)
            size += len(line)
            for key, token in tokens.items():
                counts[key] += line.count(token)
            if production and line.startswith(b"define "):
                _require(current is None, "unterminated production function definition")
                match = IR_SYMBOL.search(line)
                if match:
                    symbol = (match.group(1) or match.group(2)).decode("ascii")
                    label = _function_label(symbol)
                    if label:
                        _require(label not in functions, f"ambiguous production function {label}")
                        current = (label, symbol)
                        body = []
            if current is not None:
                body.append(line)
                if line.strip() == b"}":
                    label, symbol = current
                    raw = b"".join(body)
                    load = any(b"load i8" in item and b"@__sancov_gen_" in item for item in body)
                    store = any(b"store i8" in item and b"@__sancov_gen_" in item for item in body)
                    trace = any(b"call " in item and b"@__sanitizer_cov_trace_" in item for item in body)
                    _require(load and store, f"no inline counter access in {label}")
                    if label != "parse_client_hello":
                        _require(trace, f"no comparison tracing in {label}")
                    functions[label] = {
                        "symbol": symbol,
                        "counter_access": True,
                        "trace_comparisons": trace,
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                    bodies[label] = raw
                    current = None
    _require(current is None, "unterminated production parser IR")
    if production:
        _require(set(functions) == set(FUNCTION_MARKERS), "missing production parser function definitions")
        _require(all(counts[key] > 0 for key in counts), "missing production sanitizer coverage IR")
    else:
        _require(not any(counts.values()), f"harness/oracle feedback exists in {path.name}")
    return {
        "path": str(path), "sha256": digest.hexdigest(), "bytes": size,
        **counts, "functions": functions,
    }, bodies


def _run(command):
    completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=60)
    _require(completed.returncode == 0, f"command failed: {command!r}: {completed.stderr.strip()}")
    return completed.stdout


def _inline_wire_evidence(disassembly, wire_symbol, wrapper_symbol):
    blocks = []
    current = None
    for line in disassembly.splitlines():
        if line and not line[0].isspace() and line.endswith("():"):
            if current:
                blocks.append("\n".join(current))
            current = [line] if line == wire_symbol + "():" else None
        elif current is not None:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return any(
        "wire.rs:" in block
        and any("inlined by" in line and wrapper_symbol in line for line in block.splitlines())
        and "__sanitizer_cov_trace_" in block
        for block in blocks
    )


def _inspect_binary(name, path, required, ir_functions, out):
    path = path.resolve()
    _require(path.is_file(), f"missing linked binary {path}")
    nm_command = ["nm", "--defined-only", "--no-demangle", str(path)]
    nm_output = _run(nm_command)
    symbols = {}
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in {"T", "t", "W", "w"}:
            symbols[fields[2]] = line
    functions = {}
    disassembly = {}
    commands = [nm_command]
    symbol_lines = []
    for label in required:
        symbol = ir_functions[label]["symbol"]
        if symbol not in symbols:
            _require(label == "wire_parse", f"{name} does not link production function {label}")
            continue
        symbol_lines.append(symbols[symbol])
        command = ["objdump", "-d", "-l", "--inlines", "--disassemble=" + symbol, str(path)]
        text = _run(command)
        _require(re.search(r"^\s*[0-9a-fA-F]+ <" + re.escape(symbol) + r">:", text, re.MULTILINE), f"no linked function body for {name}/{label}")
        trace = "__sanitizer_cov_trace_" in text
        if label != "parse_client_hello":
            _require(trace, f"linked parser {name}/{label} lacks comparison callbacks")
        functions[label] = {
            "symbol": symbol, "attribution": "standalone",
            "trace_comparisons": trace,
            "counter_reference_present": "__sancov_cntrs" in text,
        }
        disassembly[label] = text
        commands.append(command)
    if "wire_parse" in required and "wire_parse" not in functions:
        wire_symbol = ir_functions["wire_parse"]["symbol"]
        wrapper_symbol = ir_functions["parse_frame"]["symbol"]
        _require(_inline_wire_evidence(disassembly["parse_frame"], wire_symbol, wrapper_symbol), f"no linked inline wire::parse attribution in {name}")
        functions["wire_parse"] = {
            "symbol": wire_symbol, "attribution": "inlined",
            "inlined_into": wrapper_symbol, "source": "wire.rs",
            "trace_comparisons": True,
        }
        symbol_lines.append(f"# {wire_symbol} is attributed by DWARF inline records inside {wrapper_symbol}")
    _require(set(functions) == set(required), f"incomplete linked parser attribution for {name}")
    symbol_path = out / (name + "-parser-symbols.txt")
    symbol_path.write_text("\n".join(symbol_lines) + "\n", encoding="utf-8")
    disassembly_path = out / (name + "-parser-disassembly.txt")
    disassembly_path.write_text("\n\n".join("# " + label + "\n" + text for label, text in disassembly.items()), encoding="utf-8")
    return {
        **_file_info(path), "functions": functions, "commands": commands,
        "symbol_evidence": _file_info(symbol_path),
        "disassembly_evidence": _file_info(disassembly_path),
    }


def verify(build_dir: Path, trace_path: Path, binaries: dict[str, Path], out: Path) -> dict:
    """Fail closed unless audit, emitted IR, and linked parser evidence agree.

    The caller creates a fresh output directory and archives the complete rustc
    trace.  This function retains the relevant compiler invocations, six complete
    parser definitions, and linked-symbol/disassembly evidence without copying
    the full production IR file.
    """
    build_dir = Path(build_dir).resolve()
    trace_path = Path(trace_path).resolve()
    out = Path(out).resolve()
    _require(build_dir.is_dir(), "missing build directory")
    _require(out.is_dir() and not any(out.iterdir()), "output directory must exist and be empty")
    records = _read_trace(trace_path)
    profile_path = Path(__file__).resolve().parent.parent / "fuzz" / "Cargo.toml"
    with profile_path.open("rb") as stream:
        profile = tomllib.load(stream).get("profile", {}).get("release", {})
    _require(profile.get("lto") is False, "fuzz release profile does not explicitly disable LTO")

    selected = [record for record in records if record.get("crate_name") in CRATES and record.get("llvm_ir_enabled")]
    compiler_path = out / "compiler-invocations.json"
    compiler_path.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")
    ir = {}
    production_bodies = {}
    for name in CRATES:
        paths = {_ir_path(record, build_dir) for record in selected if record["crate_name"] == name}
        _require(len(paths) == 1, f"ambiguous LLVM IR artifacts for {name}")
        info, bodies = _inspect_ir(paths.pop(), name == "spiral_protocol")
        ir[name] = info
        if name == "spiral_protocol":
            production_bodies = bodies
    parser_path = out / "production-parser-functions.ll"
    with parser_path.open("wb") as stream:
        for label in FUNCTION_MARKERS:
            stream.write(("; Verified production function: " + label + "\n").encode("ascii"))
            stream.write(production_bodies[label])
            stream.write(b"\n")

    canonical = {}
    for key, path in binaries.items():
        name = key if key.endswith("_target") else key + "_target"
        _require(name in CRATES[1:] and name not in canonical, f"unexpected or duplicate binary {key}")
        canonical[name] = Path(path)
    _require(set(canonical) == set(CRATES[1:]), "all three parser binaries are required")
    linked = {}
    for name in CRATES[1:]:
        candidate = canonical[name].resolve()
        _require(candidate.is_relative_to(build_dir), f"binary {name} is outside the audited build directory")
        outputs = {_linked_output(record, build_dir) for record in selected if record["crate_name"] == name}
        _require(len(outputs) == 1, f"ambiguous linked output for {name}")
        audited = _file_info(outputs.pop())
        supplied = _file_info(candidate)
        _require(supplied["sha256"] == audited["sha256"] and supplied["bytes"] == audited["bytes"], f"binary {name} differs from the audited linked output")
        required = FRAME_FUNCTIONS if name == "frame_target" else HELLO_FUNCTIONS if name == "hello_target" else tuple(FUNCTION_MARKERS)
        linked[name] = _inspect_binary(name, candidate, required, ir["spiral_protocol"]["functions"], out)
        linked[name]["audited_link_output"] = audited

    return {
        "status": "verified",
        "scope": "Reachable spiral-protocol Rust parser instrumentation; harness/oracles excluded. No native C or OpenSSL coverage claim.",
        "trace": {
            **_file_info(trace_path), "invocations": len(records),
            "instrumented_invocations": sum(record["coverage_enabled"] for record in records),
        },
        "llvm_ir": ir,
        "binaries": linked,
        "lto_disabled": True,
        "fuzz_profile": _file_info(profile_path),
        "artifacts": {
            "compiler_invocations": _file_info(compiler_path),
            "production_parser_functions": _file_info(parser_path),
        },
    }
