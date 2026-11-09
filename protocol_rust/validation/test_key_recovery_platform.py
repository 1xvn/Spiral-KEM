#!/usr/bin/env python3
"""Focused recovery collector integrity tests; no Rust or TLS execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "key_recovery_platform", Path(__file__).with_name("key_recovery_platform.py"))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
HELPER_BYTES = Path(__file__).with_name("key_operations_platform.py").read_bytes()


class RecoveryCollectorContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.source = self.folder / "source"
        self.source.mkdir()
        self.output = self.folder / "results"
        self.output.mkdir()

    def manifest(self):
        names = collector.RECOVERY_INPUTS | {
            collector.HELPER, "rust-toolchain.toml", "protocol_rust/Cargo.toml",
            "protocol_rust/Cargo.lock", "protocol_rust/build.rs", "protocol_rust/key_ops_tests.py",
            "protocol_rust/fuzzing/campaign.py", "protocol_rust/fuzz/Cargo.toml",
            "protocol_rust/fuzz/Cargo.lock", "native_research/spiral_native.c",
            "native_research/spiral_native.h", "protocol_v01/tests/fixtures/test_vectors_v0.1.json",
            "protocol_v01/channel.py", "protocol_v01/__init__.py"}
        files = {}
        for name in names:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(HELPER_BYTES if name == collector.HELPER else (name + "\n").encode())
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        value = {"schema": "spiral-key-operations-source/v1", "profile": "key-recovery",
                 "source_commit": "a" * 40, "runtime_base_commit": "b" * 40, "files": files}
        path = self.folder / "SOURCE.json"
        collector.write_json(path, value)
        return path, hashlib.sha256(path.read_bytes()).hexdigest(), files

    def invoke(self, path, expected, *flags):
        output = io.StringIO()
        with mock.patch.object(collector, "ROOT", self.source), contextlib.redirect_stdout(output):
            status = collector.main(["--platform", "local", "--source-manifest", str(path),
                                     "--expected-manifest-sha256", expected,
                                     "--output-parent", str(self.output), *flags])
        return status, json.loads(output.getvalue())

    def support(self, path, expected):
        with mock.patch.object(collector, "ROOT", self.source):
            return collector.load_support(path, expected)[0]

    def integration(self, helper, files):
        sources = collector.expected_recovery_sources(helper, files)
        return {"schema": "spiral-rust-key-recovery/v1", "status": "passed", "tests": collector.RECOVERY_TESTS,
                "failures": 0, "errors": 0, "skipped": 0, "source_and_binary_unchanged": True,
                "binary_sha256": "c" * 64, "binary_sha256_before": "c" * 64, "binary_sha256_after": "c" * 64,
                "source_sha256": sources, "source_sha256_before": sources, "source_sha256_after": sources,
                "runner_sha256": files[collector.RUNNER], "failed_tests": [], "error_tests": []}

    def test_parser_requires_platform_and_integrity_pin(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in ([], ["--platform", "local"], ["--platform", "wrong"]):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    collector.parser().parse_args(args)

    def test_support_loaded_only_from_authenticated_bytes(self):
        path, expected, _ = self.manifest()
        helper = self.support(path, expected)
        self.assertEqual(helper.ROOT, self.source)
        self.assertEqual(helper.RUST_VERSION, "1.99.1")

    def test_tampered_helper_is_not_executed(self):
        path, expected, _ = self.manifest()
        marker = self.folder / "executed"
        (self.source / collector.HELPER).write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        status, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(status, 1)
        self.assertFalse(marker.exists())
        report = json.loads((Path(summary["result_directory"]) / "result.json").read_text())
        self.assertIn("helper SHA256 mismatch", report["error"])
        with tarfile.open(summary["archive"]) as archive:
            self.assertEqual({Path(name).name for name in archive.getnames()}, {"result.json", "SHA256.json"})

    def test_wrong_manifest_pin_is_archived_without_executing_helper(self):
        path, _, _ = self.manifest()
        status, summary = self.invoke(path, "0" * 64, "--check-only")
        self.assertEqual(status, 1)
        report = json.loads((Path(summary["result_directory"]) / "result.json").read_text())
        self.assertIn("manifest SHA256 mismatch", report["error"])
        self.assertFalse(report["platform_tests_passed"])

    def test_manifest_requires_recovery_profile(self):
        path, _, _ = self.manifest()
        value = json.loads(path.read_text())
        del value["profile"]
        collector.write_json(path, value)
        with self.assertRaisesRegex(collector.ValidationError, "unsupported recovery"):
            self.support(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_duplicate_manifest_fields_rejected(self):
        with self.assertRaisesRegex(collector.ValidationError, "duplicate JSON"):
            collector.strict_json('{"files":{},"files":{}}')

    def test_helper_symlink_and_hardlink_are_rejected(self):
        path, expected, _ = self.manifest()
        helper = self.source / collector.HELPER
        outside = self.folder / "helper.py"
        helper.rename(outside)
        helper.symlink_to(outside)
        with self.assertRaises(OSError):
            self.support(path, expected)
        helper.unlink()
        helper.hardlink_to(outside)
        with self.assertRaisesRegex(collector.ValidationError, "one link"):
            self.support(path, expected)

    def test_check_only_never_grants_platform_or_other_approvals(self):
        path, expected, _ = self.manifest()
        status, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(status, 0)
        self.assertEqual(summary["status"], "source-integrity-passed")
        out = Path(summary["result_directory"])
        self.assertRegex(out.name, r"^Spiral-key-recovery-local-[^-]+-\d{8}T\d{6}Z-[a-z0-9_]+$")
        report = json.loads((out / "result.json").read_text())
        self.assertEqual(report["schema"], collector.SCHEMA)
        self.assertEqual(report["commands"], [])
        for field in ("platform_tests_passed", "memory_cleanup_approved", "constant_time_approved",
                      "memory_checked", "production_memory_passed", "whole_goal_2_approved",
                      "whole_goal_5_approved", "deployment_approved"):
            self.assertIs(report[field], False)
        with tarfile.open(summary["archive"]) as archive:
            self.assertFalse(any({"BUILD", "venv", "scratch"} & set(Path(name).parts)
                                 for name in archive.getnames()))
        self.assertEqual(report["source_tree_sha256_before"], report["source_tree_sha256_after"])
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)

    def test_wrong_and_filtered_rust_counts_rejected(self):
        with mock.patch.object(collector, "RUST_PASSED", 94):
            accepted = "test result: ok. 94 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; done\n"
            self.assertEqual(collector.parse_rust_tests(accepted)["passed"], 94)
            for text in (accepted.replace("94 passed", "93 passed"), accepted.replace("5 ignored", "4 ignored"),
                         accepted.replace("0 filtered", "1 filtered"), accepted * 2, ""):
                with self.subTest(text=text), self.assertRaises(collector.ValidationError):
                    collector.parse_rust_tests(text)

    def test_exact_report_and_manifest_covered_sources_accepted(self):
        path, expected, files = self.manifest()
        helper = self.support(path, expected)
        sources = collector.expected_recovery_sources(helper, files)
        for name in (collector.RUNNER, "protocol_rust/key_ops_tests.py", "protocol_rust/interop.py",
                     "protocol_v01/requirements.txt", "protocol_v01/channel.py", "protocol_v01/__init__.py"):
            self.assertEqual(sources[name], files[name])
        self.assertNotIn(collector.COLLECTOR, sources)
        result = collector.validate_recovery_report(helper, self.integration(helper, files), files, "c" * 64)
        self.assertEqual(result["tests"], collector.RECOVERY_TESTS)

    def test_changed_before_after_and_extra_sources_rejected(self):
        path, expected, files = self.manifest()
        helper = self.support(path, expected)
        for field, value in (("schema", "wrong"), ("tests", True), ("tests", collector.RECOVERY_TESTS - 1),
                             ("skipped", 1), ("errors", 1), ("failures", 1), ("source_and_binary_unchanged", False),
                             ("binary_sha256_before", "d" * 64), ("binary_sha256_after", "d" * 64),
                             ("source_sha256_before", {}), ("source_sha256_after", {}),
                             ("runner_sha256", "d" * 64), ("failed_tests", ["bad"]), ("error_tests", ["bad"])):
            report = self.integration(helper, files)
            report[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(collector.ValidationError):
                collector.validate_recovery_report(helper, report, files, "c" * 64)
        report = self.integration(helper, files)
        report["source_sha256"] = dict(report["source_sha256"], **{"unlisted.py": "d" * 64})
        with self.assertRaisesRegex(collector.ValidationError, "exactly match"):
            collector.validate_recovery_report(helper, report, files, "c" * 64)

    def test_archive_failure_rewrites_report_and_removes_partial_success(self):
        path, expected, _ = self.manifest()
        helper = self.support(path, expected)
        original = helper.finalize
        def fail_after_finalize(out, report, public):
            original(out, report, public)
            raise OSError("simulated archive failure")
        with mock.patch.object(collector, "load_support", return_value=(helper, path.read_bytes(), json.loads(path.read_text()))), \
                mock.patch.object(helper, "finalize", side_effect=fail_after_finalize):
            status, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(status, 1)
        out = Path(summary["result_directory"])
        report = json.loads((out / "result.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(out.with_suffix(".tar.gz").exists())
        self.assertEqual(json.loads((out / "SHA256.json").read_text())["result.json"],
                         hashlib.sha256((out / "result.json").read_bytes()).hexdigest())

    def test_launcher_verifies_helper_before_collector_execution(self):
        path, expected, files = self.manifest()
        template = Path(__file__).resolve().parents[2] / "tools/key_recovery_launcher.py.in"
        launcher = self.folder / "run_checks.py"
        launcher.write_text(template.read_text().replace("__MANIFEST_SHA256__", expected)
                            .replace("__COLLECTOR_SHA256__", files[collector.COLLECTOR]))
        # The collector would create this marker if launcher integrity checks
        # reached execution. A changed helper must block it first.
        marker = self.folder / "collector-executed"
        (self.source / collector.COLLECTOR).write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        (self.source / collector.HELPER).write_text("raise RuntimeError('untrusted helper')\n")
        completed = subprocess.run([sys.executable, "-I", "-B", str(launcher)], capture_output=True, timeout=10)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"Bundle verification failed", completed.stderr)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
