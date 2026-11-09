#!/usr/bin/env python3
"""Collect bounded Linux encrypted key backup, restore, and recovery evidence.

The trusted source manifest digest is mandatory. Public reports and raw logs are
archived; build products, virtual environments, and private test scratch are not.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tarfile
import tempfile
import types

ROOT = Path(__file__).resolve().parents[2]
HELPER = "protocol_rust/validation/key_operations_platform.py"
COLLECTOR = "protocol_rust/validation/key_recovery_platform.py"
RUNNER = "protocol_rust/key_recovery_tests.py"
SCHEMA = "spiral-key-recovery-platform/v1"
RUST_PASSED = 94
RECOVERY_TESTS = 20
SCOPE = "encrypted auth-seed and TLS-PEM backup/restore and cold rotation recovery lab"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
RECOVERY_INPUTS = {COLLECTOR, RUNNER, "protocol_rust/interop.py", "protocol_v01/requirements.txt",
                   "code/opt2/spiral_kem_toy_v031_opt2.py"}


class ValidationError(ValueError):
    """A collector or manifest contract failed."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, "duplicate JSON field: " + name)
            result[name] = value
        return result
    def nonfinite(value):
        raise ValidationError("nonfinite JSON value: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def bootstrap_read(root, name):
    """Read verified code without importing a helper or following links."""
    require(isinstance(name, str) and name and not name.startswith("/")
            and "\\" not in name and "\x00" not in name
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and PurePosixPath(name).parts[0] != ".git", "unsafe source path")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in name.split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(name.split("/")[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=descriptor)
        try:
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "collection input must be a regular file with one link")
            with os.fdopen(leaf, "rb", closefd=False) as stream:
                raw = stream.read()
            after = os.fstat(leaf)
            fields = ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(all(getattr(before, field) == getattr(after, field) for field in fields),
                    "collection input changed while reading")
            return raw
        finally:
            os.close(leaf)
    finally:
        os.close(descriptor)


def load_support(manifest_path, expected_sha256):
    """Authenticate the helper with stdlib code before executing any helper byte."""
    require(bool(SHA256_RE.fullmatch(expected_sha256)), "expected manifest digest must be lowercase SHA256")
    raw = bootstrap_read(manifest_path.parent, manifest_path.name)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "source manifest SHA256 mismatch")
    manifest = strict_json(raw)
    require(isinstance(manifest, dict) and manifest.get("schema") == "spiral-key-operations-source/v1"
            and manifest.get("profile") == "key-recovery", "unsupported recovery source manifest")
    files = manifest.get("files")
    require(isinstance(files, dict) and HELPER in files, "manifest omits verified collector helper")
    helper_bytes = bootstrap_read(ROOT, HELPER)
    require(hashlib.sha256(helper_bytes).hexdigest() == files[HELPER], "collector helper SHA256 mismatch")
    # Execute the bytes just authenticated, rather than reopening the source via
    # an import loader after verification. Its ROOT naturally matches this tree.
    helper = types.ModuleType("spiral_key_recovery_support")
    helper.__file__ = str(ROOT / HELPER)
    exec(compile(helper_bytes, helper.__file__, "exec"), helper.__dict__)
    raw, manifest = helper.load_manifest(manifest_path, expected_sha256)
    require(RECOVERY_INPUTS <= manifest["files"].keys(), "manifest omits recovery collection inputs")
    return helper, raw, manifest


def parse_rust_tests(text):
    require(RUST_PASSED > 0, "collector Rust pass count has not been pinned")
    rows = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;[^\n]*$", text, re.MULTILINE)
    require(len(rows) == 1, "expected exactly one Rust library test summary")
    status, *values = rows[0]
    counts = tuple(map(int, values))
    require(status == "ok" and counts == (RUST_PASSED, 0, 5, 0, 0),
            "Rust library counts must be exactly " + str(RUST_PASSED)
            + " passed, 0 failed, 5 ignored, 0 measured, 0 filtered")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), counts))


def expected_recovery_sources(helper, files):
    names = set(helper.expected_integration_sources(files)) | (RECOVERY_INPUTS - {COLLECTOR})
    names.update(name for name in files
                 if PurePosixPath(name).parent == PurePosixPath("protocol_v01")
                 and PurePosixPath(name).suffix == ".py")
    require(names <= files.keys(), "manifest omits recovery runner source inputs")
    return {name: files[name] for name in sorted(names)}


def validate_recovery_report(helper, report, files, binary_sha256):
    require(isinstance(report, dict) and report.get("schema") == "spiral-rust-key-recovery/v1",
            "invalid key recovery report schema")
    require(report.get("status") == "passed", "key recovery report did not pass")
    for field, expected in (("tests", RECOVERY_TESTS), ("failures", 0), ("errors", 0), ("skipped", 0)):
        require(type(report.get(field)) is int and report[field] == expected,
                "key recovery report requires " + field + "=" + str(expected))
    require(report.get("source_and_binary_unchanged") is True, "recovery runner reports changed source/binary")
    for field in ("binary_sha256", "binary_sha256_before", "binary_sha256_after"):
        require(report.get(field) == binary_sha256, "recovery runner binary digest mismatch: " + field)
    expected = expected_recovery_sources(helper, files)
    for field in ("source_sha256", "source_sha256_before", "source_sha256_after"):
        require(report.get(field) == expected, "recovery runner source hashes do not exactly match manifest: " + field)
    require(report.get("runner_sha256") == files[RUNNER], "recovery runner digest does not match manifest")
    require(report.get("failed_tests") == [] and report.get("error_tests") == [],
            "recovery runner reports failed/error test IDs")
    return {"tests": RECOVERY_TESTS, "failures": 0, "errors": 0, "skipped": 0, "status": "passed"}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def bootstrap_failure_archive(out, report):
    """Archive only the failure report when support code could not be trusted."""
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(out / "result.json", report)
    write_json(out / "SHA256.json", {"result.json": hashlib.sha256((out / "result.json").read_bytes()).hexdigest()})
    archive = out.with_suffix(".tar.gz")
    with archive.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
            for name in ("result.json", "SHA256.json"):
                bundle.add(out / name, arcname=out.name + "/" + name, recursive=False)
    return {"status": "failed", "result_directory": str(out), "archive": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "result_manifest_sha256": hashlib.sha256((out / "SHA256.json").read_bytes()).hexdigest()}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--platform", choices=("oci", "wsl", "local"), required=True)
    result.add_argument("--source-manifest", type=Path, required=True)
    result.add_argument("--expected-manifest-sha256", required=True)
    result.add_argument("--python", type=Path, help="existing Python 3.12 venv with exact pinned requirements")
    result.add_argument("--toolchain-dir", type=Path, help="installed exact Rust 1.99.1 root or bin directory")
    result.add_argument("--output-parent", type=Path, default=Path.home())
    result.add_argument("--check-only", action="store_true", help="verify source only; no platform/test approval")
    result.add_argument("--offline", action="store_true", help="no pip install; cargo --offline (requires --python)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    old_umask = os.umask(0o077)
    out = helper = files = before = None
    public = set()
    report = {"schema": SCHEMA, "status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "requested_platform": args.platform, "check_only": args.check_only, "offline": args.offline,
              "scope": SCOPE, "memory_cleanup_approved": False, "constant_time_approved": False,
              "memory_checked": False, "production_memory_passed": False,
              "whole_goal_2_approved": False, "whole_goal_5_approved": False,
              "deployment_approved": False, "platform_tests_passed": False, "commands": []}
    try:
        parent = args.output_parent.expanduser().resolve()
        require(parent.is_dir(), "output parent must be an existing directory")
        require(not parent.is_relative_to(ROOT), "output parent must be outside the source tree")
        arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = Path(tempfile.mkdtemp(prefix="Spiral-key-recovery-" + args.platform + "-" + arch + "-" + stamp + "-", dir=parent))
        (out / "logs").mkdir(mode=0o700)
        require(not args.offline or args.python is not None, "--offline requires --python")
        helper, raw, manifest = load_support(args.source_manifest.expanduser().absolute(), args.expected_manifest_sha256)
        (out / "source-manifest.json").write_bytes(raw)
        public.add("source-manifest.json")
        files = manifest["files"]
        report.update(source_commit=manifest["source_commit"], manifest_sha256=helper.sha256(raw), profile="key-recovery")
        runtime = manifest.get("runtime_base_commit")
        require(isinstance(runtime, str) and re.fullmatch(r"[0-9a-f]{40}", runtime), "runtime base commit must be full lowercase 40-hex")
        report["runtime_base_commit"] = runtime
        before = helper.verify_source(ROOT, files)
        helper.write_json(out / "source-before.json", before)
        public.add("source-before.json")
        report["source_tree_sha256_before"] = helper.source_tree_digest(before)
        if args.check_only:
            report["status"] = "source-integrity-passed"
        else:
            report["host"] = helper.host_evidence(args.platform)
            if args.platform == "wsl":
                helper.require_native_wsl_paths((ROOT, out, Path("/tmp")))
            with tempfile.TemporaryDirectory(prefix="spiral-key-recovery-private-", dir="/tmp") as scratch_name:
                scratch = Path(scratch_name)
                os.chmod(scratch, 0o700)
                require(not scratch.is_relative_to(out), "private temporary directory cannot be in results")
                env = helper.clean_environment(scratch)
                require(bool(env.get("HOME")), "HOME must identify the normal user")
                commands = helper.Commands(out, env, report, public)
                helper.reject_cargo_configs(ROOT, env)
                cargo = helper.prepare_toolchain(args, commands, report["host"]["architecture"])
                executable = helper.prepare_python(args, commands, scratch, files)
                (out / "requirements.txt").write_bytes(helper.read_source(ROOT, "protocol_v01/requirements.txt"))
                public.add("requirements.txt")
                # Private/build data are physically outside the public results.
                build = scratch / "BUILD"
                common = ["--locked", "-j", "2", "--target-dir", build,
                          "--manifest-path", ROOT / "protocol_rust/Cargo.toml"]
                if args.offline:
                    common.append("--offline")
                stdout, _ = commands.run("rust-library-tests", [cargo, "test", "--lib", *common], timeout=1800, cwd=ROOT)
                report["rust_library_tests"] = parse_rust_tests(helper.bounded_text(stdout))
                commands.run("release-build", [cargo, "build", "--release", *common], timeout=1800, cwd=ROOT)
                binary = build / "release/spiral-lab"
                require(binary.is_file() and not binary.is_symlink(), "release binary missing")
                binary_hash = helper.digest(binary)
                report["binary_sha256_before"] = binary_hash
                for label, runner, destination in (("key-operations", "protocol_rust/key_ops_tests.py", "key_operations.json"),
                                                   ("key-recovery", RUNNER, "key_recovery.json")):
                    public.add(destination)
                    commands.run(label, [executable, "-I", "-B", ROOT / runner, "--binary", binary,
                                         "--json", out / destination], timeout=600, cwd=ROOT)
                    integration = helper.strict_json((out / destination).read_bytes())
                    report[label.replace("-", "_")] = (helper.validate_integration(integration, files, binary_hash)
                        if label == "key-operations" else validate_recovery_report(helper, integration, files, binary_hash))
                report["binary_sha256_after"] = helper.digest(binary)
                require(report["binary_sha256_after"] == binary_hash, "release binary changed during integration tests")
                report.update(platform_tests_passed=True, status="passed")
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="failed", error=type(error).__name__ + ": " + str(error), platform_tests_passed=False)
    finally:
        try:
            if files is not None and before is not None:
                after = helper.snapshot_source(ROOT, files)
                helper.write_json(out / "source-after.json", after)
                public.add("source-after.json")
                report["source_tree_sha256_after"] = helper.source_tree_digest(after)
                require(after == before and after == files, "source changed during collection")
                report["source_unchanged"] = True
        except Exception as error:
            report.update(status="failed", source_unchanged=False, platform_tests_passed=False,
                          source_integrity_error=type(error).__name__ + ": " + str(error))
        try:
            if out is None:
                summary = {"status": "failed", "error": report.get("error", "result directory unavailable")}
            elif helper is None:
                summary = bootstrap_failure_archive(out, report)
            else:
                public = {name for name in public if (out / name).is_file()}
                summary = helper.finalize(out, report, public)
            print(json.dumps(summary, sort_keys=True), flush=True)
        except Exception as error:
            report.update(status="failed", platform_tests_passed=False,
                          archive_error=type(error).__name__ + ": " + str(error))
            if out is not None:
                try:
                    write_json(out / "result.json", report)
                    hashes = {name: hashlib.sha256(bootstrap_read(out, name)).hexdigest()
                              for name in sorted(public | {"result.json"})
                              if (out / name).is_file() and not (out / name).is_symlink()}
                    write_json(out / "SHA256.json", hashes)
                    archive = out.with_suffix(".tar.gz")
                    archive.unlink(missing_ok=True)
                    archive.with_name(archive.name + ".sha256").unlink(missing_ok=True)
                except OSError:
                    pass
            print(json.dumps({"status": "failed", "result_directory": str(out),
                              "archive_error": report["archive_error"]}), flush=True)
        os.umask(old_umask)
    return 0 if report["status"] in ("passed", "source-integrity-passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
