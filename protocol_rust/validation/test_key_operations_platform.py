#!/usr/bin/env python3
"""Focused collector contract tests; these do not run the Rust/TLS suites."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "key_operations_platform", Path(__file__).with_name("key_operations_platform.py"))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CollectorContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.output = self.base / "output"
        self.output.mkdir()

    def manifest(self, extra=None):
        names = set(collector.REQUIRED_FILES) | {
            "rust-toolchain.toml", "protocol_rust/fuzz/Cargo.toml", "protocol_rust/fuzz/Cargo.lock",
            "native_research/spiral_native.c", "native_research/spiral_native.h",
            "protocol_v01/tests/fixtures/test_vectors_v0.1.json"}
        files = {}
        for name in sorted(names):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + "\n").encode())
            files[name] = collector.digest(path)
        if extra:
            files.update(extra)
        value = {"schema": "spiral-key-operations-source/v1", "source_commit": "a" * 40, "files": files}
        path = self.base / "external-manifest.json"
        collector.write_json(path, value)
        return path, collector.digest(path), files

    def integration_report(self, files):
        return {"schema": "spiral-rust-key-operations/v1", "status": "passed", "tests": 11,
                "failures": 0, "errors": 0, "skipped": 0, "source_and_binary_unchanged": True,
                "binary_sha256": "b" * 64, "source_sha256": collector.expected_integration_sources(files),
                "runner_sha256": files["protocol_rust/key_ops_tests.py"],
                "failed_tests": [], "error_tests": []}

    def invoke(self, manifest, expected, *flags):
        stream = io.StringIO()
        with mock.patch.object(collector, "ROOT", self.source), contextlib.redirect_stdout(stream):
            result = collector.main(["--platform", "local", "--source-manifest", str(manifest),
                                     "--expected-manifest-sha256", expected,
                                     "--output-parent", str(self.output), *flags])
        return result, json.loads(stream.getvalue())

    def test_parser_requires_explicit_platform_and_manifest_pin(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in ([], ["--platform", "local"], ["--platform", "unknown"]):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    collector.parser().parse_args(args)

    def test_external_manifest_and_source_are_verified(self):
        path, expected, files = self.manifest()
        raw, value = collector.load_manifest(path, expected)
        self.assertEqual(value["files"], files)
        self.assertEqual(collector.sha256(raw), expected)
        self.assertEqual(collector.verify_source(self.source, files), files)

    def test_manifest_hash_and_commit_rejected(self):
        path, expected, _ = self.manifest()
        with self.assertRaisesRegex(collector.ValidationError, "SHA256 mismatch"):
            collector.load_manifest(path, "0" * 64)
        value = json.loads(path.read_text())
        value["source_commit"] = "a" * 7
        collector.write_json(path, value)
        with self.assertRaisesRegex(collector.ValidationError, "full lowercase"):
            collector.load_manifest(path, collector.digest(path))

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaisesRegex(collector.ValidationError, "duplicate JSON"):
            collector.strict_json('{"status":"passed","status":"failed"}')

    def test_path_traversal_and_noncanonical_paths_rejected(self):
        for name in ("../escape", "/etc/passwd", "a/../../b", "a//b", "a/./b", "a/", "a\\b", "a\0b", ".git/config"):
            with self.subTest(name=name), self.assertRaises(collector.ValidationError):
                collector.safe_name(name)

    def test_manifest_path_traversal_rejected_even_with_trusted_digest(self):
        path, _, _ = self.manifest({"../outside": "0" * 64})
        with self.assertRaisesRegex(collector.ValidationError, "unsafe source path"):
            collector.load_manifest(path, collector.digest(path))

    def test_source_changes_rejected(self):
        _, _, files = self.manifest()
        (self.source / "protocol_rust/Cargo.toml").write_text("changed")
        with self.assertRaisesRegex(collector.ValidationError, "source SHA256 mismatch"):
            collector.verify_source(self.source, files)

    def test_leaf_and_parent_symlinks_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "file").write_text("outside")
        (self.source / "leaf").symlink_to(outside / "file")
        (self.source / "parent").symlink_to(outside, target_is_directory=True)
        for name in ("leaf", "parent/file"):
            with self.subTest(name=name), self.assertRaises(OSError):
                collector.read_source(self.source, name)

    def test_fifo_rejected_without_blocking(self):
        os.mkfifo(self.source / "fifo")
        with self.assertRaisesRegex(collector.ValidationError, "regular file"):
            collector.read_source(self.source, "fifo")

    def test_exact_rust_counts_accepted(self):
        report = collector.parse_rust_tests("test result: ok. 81 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.2s\n")
        self.assertEqual(report["passed"], 81)

    def test_wrong_or_filtered_rust_counts_rejected(self):
        for text in ("test result: ok. 80 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.2s\n",
                     "test result: ok. 81 passed; 0 failed; 4 ignored; 0 measured; 1 filtered out; finished in 0.2s\n",
                     "test result: FAILED. 81 passed; 1 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.2s\n",
                     "", "test result: ok. 81 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; x\n" * 2):
            with self.subTest(text=text), self.assertRaises(collector.ValidationError):
                collector.parse_rust_tests(text)

    def test_exact_integration_report_accepted(self):
        _, _, files = self.manifest()
        self.assertEqual(collector.validate_integration(self.integration_report(files), files, "b" * 64)["tests"], 11)

    def test_skips_wrong_counts_failures_changed_source_and_binary_rejected(self):
        _, _, files = self.manifest()
        for field, value in (("tests", 10), ("tests", True), ("skipped", 1), ("failures", 1), ("errors", 1),
                             ("status", "failed"), ("source_and_binary_unchanged", False),
                             ("binary_sha256", "c" * 64), ("source_sha256", {}),
                             ("runner_sha256", "0" * 64), ("failed_tests", ["bad"])):
            report = self.integration_report(files)
            report[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(collector.ValidationError):
                collector.validate_integration(report, files, "b" * 64)

    def test_unlisted_integration_source_rejected(self):
        _, _, files = self.manifest()
        report = self.integration_report(files)
        report["source_sha256"]["injected.py"] = "0" * 64
        with self.assertRaisesRegex(collector.ValidationError, "exactly match"):
            collector.validate_integration(report, files, "b" * 64)

    def test_environment_drops_rust_compiler_python_and_key_policy_controls(self):
        inherited = {"HOME": "/home/user", "CARGO_HOME": "/cache", "HTTPS_PROXY": "https://proxy.invalid",
                     "SSL_CERT_FILE": "/ca", "RUSTFLAGS": "bad", "CC": "bad", "CFLAGS": "bad",
                     "CARGO_BUILD_TARGET": "bad", "RUSTC_WRAPPER": "bad", "PYTHONPATH": "bad",
                     "PYTHONHOME": "bad", "SPIRAL_KEYFILES_UMASK_CHILD": "bad", "TMPDIR": "/unsafe"}
        env = collector.clean_environment(Path("/private"), inherited)
        for name in ("RUSTFLAGS", "CC", "CFLAGS", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "PYTHONPATH",
                     "PYTHONHOME", "SPIRAL_KEYFILES_UMASK_CHILD"):
            self.assertNotIn(name, env)
        self.assertEqual(env["HTTPS_PROXY"], inherited["HTTPS_PROXY"])
        for name in ("TMPDIR", "TMP", "TEMP"):
            self.assertEqual(env[name], "/private")

    def test_cargo_configuration_is_rejected(self):
        cargo = self.base / "cargo-home"
        cargo.mkdir()
        (cargo / "config.toml").write_text('[build]\nrustflags = ["--cfg", "bad"]\n')
        with self.assertRaisesRegex(collector.ValidationError, "ambient Cargo configuration"):
            collector.reject_cargo_configs(self.source, {"HOME": str(self.base), "CARGO_HOME": str(cargo)})

    def test_host_label_architecture_and_kernel_are_enforced(self):
        uname = platform.uname()._replace(system="Linux", machine="x86_64", release="6.8", version="generic")
        with mock.patch.object(collector.sys, "platform", "linux"):
            for label in ("oci", "wsl"):
                with self.subTest(label=label), self.assertRaises(collector.ValidationError):
                    collector.host_evidence(label, uname=uname, uid=1000, proc_version="Linux generic")
            with self.assertRaisesRegex(collector.ValidationError, "effective UID 0"):
                collector.host_evidence("local", uname=uname, uid=0, proc_version="Linux generic")
            evidence = collector.host_evidence("local", uname=uname, uid=1000, proc_version="Linux generic")
            self.assertEqual(evidence["evidence_label"], "local")
            wsl = collector.host_evidence("wsl", uname=uname._replace(release="microsoft-standard-WSL2"), uid=1000,
                                          proc_version="Linux Microsoft")
            self.assertTrue(wsl["microsoft_kernel_evidence"])

    def test_wsl_windows_mount_paths_rejected(self):
        with self.assertRaisesRegex(collector.ValidationError, "native Linux filesystem"):
            collector.require_native_wsl_paths((Path("/mnt/c/source"),))
        collector.require_native_wsl_paths((self.source, self.output))

    def test_check_only_has_no_platform_approval_and_archives_public_files(self):
        path, expected, _ = self.manifest()
        result, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(result, 0)
        self.assertEqual(summary["status"], "source-integrity-passed")
        out = Path(summary["result_directory"])
        report = json.loads((out / "result.json").read_text())
        self.assertFalse(report["platform_tests_passed"])
        self.assertEqual(report["commands"], [])
        for key in ("memory_cleanup_approved", "constant_time_approved", "whole_goal_2_approved",
                    "whole_goal_5_approved", "deployment_approved"):
            self.assertIs(report[key], False)
        with tarfile.open(summary["archive"]) as archive:
            names = archive.getnames()
        self.assertFalse(any("BUILD" in Path(name).parts for name in names))
        self.assertTrue(any(name.endswith("source-after.json") for name in names))
        self.assertEqual(collector.digest(Path(summary["archive"])), summary["archive_sha256"])
        self.assertEqual(collector.digest(out / "SHA256.json"), summary["result_manifest_sha256"])
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)

    def test_manifest_failure_still_archives_failed_scope(self):
        path, _, _ = self.manifest()
        result, summary = self.invoke(path, "0" * 64, "--check-only")
        self.assertEqual(result, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(Path(summary["archive"]).is_file())
        report = json.loads((Path(summary["result_directory"]) / "result.json").read_text())
        self.assertFalse(report["platform_tests_passed"])
        self.assertIn("SHA256 mismatch", report["error"])

    def test_end_source_mutation_converts_check_only_success_to_failure(self):
        path, expected, files = self.manifest()
        original = collector.snapshot_source
        calls = 0
        def mutate(root, names):
            nonlocal calls
            calls += 1
            if calls == 2:
                (root / "protocol_rust/Cargo.toml").write_text("mutated during collection")
            return original(root, names)
        with mock.patch.object(collector, "snapshot_source", side_effect=mutate):
            result, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(result, 1)
        report = json.loads((Path(summary["result_directory"]) / "result.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source_unchanged"])
        self.assertFalse(report["platform_tests_passed"])
        self.assertIn("source changed", report["source_integrity_error"])
        self.assertNotEqual(report["source_tree_sha256_before"], report["source_tree_sha256_after"])

    def test_archive_failure_rewrites_success_report_as_failed(self):
        path, expected, _ = self.manifest()
        original = collector.finalize
        def fail_after_writing(out, report, public):
            original(out, report, public)
            raise OSError("simulated archive failure")
        with mock.patch.object(collector, "finalize", side_effect=fail_after_writing):
            result, summary = self.invoke(path, expected, "--check-only")
        self.assertEqual(result, 1)
        out = Path(summary["result_directory"])
        report = json.loads((out / "result.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["platform_tests_passed"])
        self.assertIn("simulated archive failure", report["archive_error"])
        self.assertFalse(out.with_suffix(".tar.gz").exists())
        self.assertEqual(json.loads((out / "SHA256.json").read_text())["result.json"], collector.digest(out / "result.json"))

    def test_explicit_public_archive_does_not_walk_build_or_private_scratch(self):
        out = self.output / "result"
        out.mkdir()
        (out / "BUILD").mkdir()
        (out / "BUILD/secret.bin").write_bytes(b"must never be packaged")
        (out / "unexpected-private-key.pem").write_text("must never be packaged")
        collector.write_json(out / "public.json", {"public": True})
        summary = collector.finalize(out, {"status": "failed"}, {"public.json"})
        with tarfile.open(summary["archive"]) as archive:
            self.assertEqual(set(archive.getnames()), {"result/result.json", "result/public.json", "result/SHA256.json"})

    def test_raw_failure_logs_retained(self):
        out = self.output / "command"
        (out / "logs").mkdir(parents=True)
        public, report = set(), {"commands": []}
        commands = collector.Commands(out, collector.clean_environment(self.base), report, public)
        with self.assertRaisesRegex(collector.ValidationError, "failed; see raw logs"):
            commands.run("failure", [sys.executable, "-I", "-c", "import sys;print('public failure');sys.exit(3)"], cwd=self.source)
        self.assertEqual((out / "logs/failure.stdout.log").read_text(), "public failure\n")
        self.assertEqual(report["commands"][0]["returncode"], 3)
        self.assertEqual(report["commands"][0]["status"], "failed")

    def test_watchdog_kills_spawned_process_group(self):
        out = self.output / "watchdog"
        (out / "logs").mkdir(parents=True)
        commands = collector.Commands(out, collector.clean_environment(self.base), {"commands": []}, set())
        code = "import os,subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);print(p.pid,flush=True);time.sleep(60)"
        with self.assertRaisesRegex(collector.ValidationError, "process-group watchdog"):
            commands.run("watchdog", [sys.executable, "-I", "-c", code], timeout=0.25, cwd=self.source)
        pid = int((out / "logs/watchdog.stdout.log").read_text())
        # A reparented process can remain a zombie until the host's init reaps it.
        proc_stat = Path("/proc") / str(pid) / "stat"
        for _ in range(50):
            if not proc_stat.exists() or proc_stat.read_text().split()[2] == "Z":
                break
            time.sleep(0.01)
        else:
            self.fail("watchdog left its grandchild running")


if __name__ == "__main__":
    unittest.main()
