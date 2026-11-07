"""Reject misleading instrumentation evidence without invoking a compiler."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from protocol_rust.fuzzing import coverage_evidence


def audit_records():
    """A minimal independently written four-crate compiler audit."""
    records = []
    for name in ("spiral_protocol", "frame_target", "hello_target", "replay_target"):
        production = name == "spiral_protocol"
        crate_type = "lib" if production else "bin"
        args = [
            "--crate-name", name, "--crate-type", crate_type,
            "--emit=dep-info,metadata,link,llvm-ir", "-C", "codegen-units=1",
            "-Zsanitizer=address", "-Cdebuginfo=1",
            "-Cforce-frame-pointers=yes", "-Coverflow-checks=yes",
            "-Cdebug-assertions=yes",
        ]
        if production:
            args += [
                "-Cpasses=sancov-module",
                "-Cllvm-args=-sanitizer-coverage-level=4",
                "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
                "-Cllvm-args=-sanitizer-coverage-pc-table",
                "-Cllvm-args=-sanitizer-coverage-trace-compares",
            ]
        records.append({
            "crate_name": name, "crate_type": crate_type,
            "crate_names": [name], "crate_types": [crate_type],
            "coverage_match": production, "coverage_enabled": production,
            "llvm_ir_enabled": True, "is_query": False,
            "args": args, "rustc": "/toolchain/bin/rustc", "pid": 100,
        })
    return records


class CompilerAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="spiral-evidence-test-")
        self.addCleanup(temporary.cleanup)
        self.trace = Path(temporary.name) / "rustc.jsonl"
        self.records = audit_records()
        self.assertEqual(len(self.read(self.records)), 4)

    def read(self, records):
        self.trace.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )
        return coverage_evidence._read_trace(self.trace)

    def test_metadata_cannot_lie_about_the_actual_compiler_invocation(self):
        cases = (
            (0, "coverage_enabled", False, "coverage decision audit mismatch"),
            (1, "crate_name", "spiral_protocol", "crate-name audit mismatch"),
            (1, "llvm_ir_enabled", False, "LLVM IR decision audit mismatch"),
        )
        for index, key, value, message in cases:
            with self.subTest(field=key):
                records = copy.deepcopy(self.records)
                records[index][key] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.read(records)

    def test_feedback_flags_cannot_leak_into_harness_or_dependency(self):
        records = copy.deepcopy(self.records)
        records[1]["args"] += ["-C", "passes=sancov-module"]
        with self.assertRaisesRegex(ValueError, "feedback instrumentation leaked"):
            self.read(records)

        dependency = {
            "crate_name": "oracle_dependency", "crate_type": "lib",
            "crate_names": ["oracle_dependency"], "crate_types": ["lib"],
            "coverage_match": False, "coverage_enabled": False,
            "llvm_ir_enabled": False, "is_query": False,
            "args": ["--crate-name=oracle_dependency", "--crate-type=lib",
                     "-Cllvm-args=-sanitizer-coverage-trace-compares"],
            "rustc": "/toolchain/bin/rustc", "pid": 101,
        }
        with self.assertRaisesRegex(ValueError, "feedback instrumentation leaked"):
            self.read(self.records + [dependency])

    def test_protocol_requires_the_pass_counters_pc_table_and_comparisons(self):
        flags = (
            "-Cpasses=sancov-module",
            "-Cllvm-args=-sanitizer-coverage-level=4",
            "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
            "-Cllvm-args=-sanitizer-coverage-pc-table",
            "-Cllvm-args=-sanitizer-coverage-trace-compares",
        )
        for flag in flags:
            with self.subTest(missing=flag):
                records = copy.deepcopy(self.records)
                records[0]["args"].remove(flag)
                with self.assertRaisesRegex(ValueError, "coverage flags are incomplete"):
                    self.read(records)

    def test_lto_and_overriding_codegen_units_invalidate_attribution(self):
        for flags, message in (
            (["-Clto=thin"], "LTO enabled"),
            (["-C", "linker-plugin-lto=yes"], "LTO enabled"),
            (["-Ccodegen-units=2"], "multiple codegen units"),
        ):
            with self.subTest(flags=flags):
                records = copy.deepcopy(self.records)
                records[2]["args"] += flags
                with self.assertRaisesRegex(ValueError, message):
                    self.read(records)

    def test_partial_audit_cannot_stand_in_for_the_complete_build(self):
        records = copy.deepcopy(self.records)
        del records[0]["coverage_enabled"]
        with self.assertRaisesRegex(ValueError, "missing audit metadata"):
            self.read(records)
        with self.assertRaisesRegex(ValueError, "missing compiler audit for hello_target"):
            self.read(self.records[:2] + self.records[3:])
        self.trace.write_text(json.dumps(self.records[0]) + "\n{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            coverage_evidence._read_trace(self.trace)


class IrEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="spiral-ir-test-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "harness.ll"

    def test_harness_counter_sections_globals_and_callbacks_are_rejected(self):
        clean = "define void @harness() {\n  ret void\n}\n"
        self.path.write_text(clean, encoding="utf-8")
        info, functions = coverage_evidence._inspect_ir(self.path, False)
        self.assertEqual(info["sancov_generated_tokens"], 0)
        self.assertEqual(functions, {})
        leaks = (
            '@counter = global i8 0, section "__sancov_cntrs"\n',
            "@__sancov_gen_.0 = global i8 0\n",
            "declare void @__sanitizer_cov_trace_const_cmp8(i64, i64)\n",
        )
        for leak in leaks:
            with self.subTest(leak=leak):
                self.path.write_text(leak + clean, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "harness/oracle feedback exists"):
                    coverage_evidence._inspect_ir(self.path, False)

    def test_global_counter_declarations_do_not_prove_parser_counter_access(self):
        self.path.write_text(
            '@__sancov_gen_.0 = global i8 0, section "__sancov_cntrs"\n'
            'define void @_RNvMNtCsTEST_15spiral_protocol4wireNtB2_6Header5parse() {\n'
            '  call void @__sanitizer_cov_trace_const_cmp8(i64 40, i64 0)\n'
            '  ret void\n}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "no inline counter access in header_parse"):
            coverage_evidence._inspect_ir(self.path, True)


if __name__ == "__main__":
    unittest.main()
