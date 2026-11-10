#!/usr/bin/env python3
"""Collect bounded Linux key-operation evidence from a pinned standalone source tree.

The manifest digest must come from the trusted delivery instructions. Archives
contain public reports and raw logs only; BUILD and private test scratch are never
packaged. A successful run is not approval of memory cleanup, constant time,
whole Goal 2/5, or deployment.
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
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "spiral-key-operations-platform/v1"
RUST_VERSION = "1.99.1"
RUST_COMMIT = "58cf8f9c35b355199727627d07ae34a4e2846d67"
CARGO_COMMIT = "5f94df478"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_FILES = {"protocol_rust/Cargo.toml", "protocol_rust/Cargo.lock",
                  "protocol_rust/build.rs", "protocol_rust/key_ops_tests.py",
                  "protocol_rust/fuzzing/campaign.py", "protocol_v01/requirements.txt",
                  "protocol_rust/validation/key_operations_platform.py"}
SCOPE = "Linux key-file policy, public-only CLI output, local restored-file agreement, and loopback TLS key rotation"


class ValidationError(ValueError):
    """A required invariant failed."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field: " + key)
            result[key] = value
        return result
    def nonfinite(value):
        raise ValidationError("nonfinite JSON value: " + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)


def safe_name(name):
    require(isinstance(name, str) and bool(name), "source path must be nonempty text")
    parts = PurePosixPath(name).parts
    require(not name.startswith("/") and "\\" not in name and "\x00" not in name
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and str(PurePosixPath(name)) == name, "unsafe source path: " + name)
    require(parts[0] != ".git", "git metadata is not source")
    return parts


def read_source(root, name):
    """Open each component without following symlinks, including the leaf."""
    parts = safe_name(name)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=descriptor)
        try:
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode), "source is not a regular file: " + name)
            require(before.st_nlink == 1, "source has multiple hard links: " + name)
            with os.fdopen(leaf, "rb", closefd=False) as stream:
                data = stream.read()
            after = os.fstat(leaf)
            require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "source changed while reading: " + name)
            return data
        finally:
            os.close(leaf)
    finally:
        os.close(descriptor)


def load_manifest(path, expected_sha256):
    require(bool(SHA256_RE.fullmatch(expected_sha256)), "expected manifest digest must be lowercase SHA256")
    require(path.is_file() and not path.is_symlink(), "manifest must be a regular nonsymlink file")
    raw = path.read_bytes()
    require(sha256(raw) == expected_sha256, "source manifest SHA256 mismatch")
    manifest = strict_json(raw)
    require(isinstance(manifest, dict) and manifest.get("schema") == "spiral-key-operations-source/v1",
            "unsupported source manifest schema")
    require(isinstance(manifest.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]), "source commit must be full lowercase 40-hex")
    files = manifest.get("files")
    require(isinstance(files, dict) and bool(files), "source manifest files must be nonempty")
    for name, value in files.items():
        safe_name(name)
        require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)), "invalid source digest: " + name)
    require(REQUIRED_FILES <= files.keys(), "source manifest omits a required collector/build input")
    return raw, manifest


def verify_source(root, files):
    observed = snapshot_source(root, files)
    changed = [name for name in observed if observed[name] != files[name]]
    require(not changed, "source SHA256 mismatch: " + ", ".join(changed))
    return observed


def snapshot_source(root, files):
    return {name: sha256(read_source(root, name)) for name in sorted(files)}


def source_tree_digest(files):
    return sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def host_evidence(label, *, uname=None, uid=None, proc_version=None):
    uname = platform.uname() if uname is None else uname
    uid = os.geteuid() if uid is None else uid
    if proc_version is None:
        proc_version = Path("/proc/version").read_text()
    require(sys.platform.startswith("linux") and uname.system == "Linux", "a real Linux host is required")
    require(uid != 0, "run as a normal user; effective UID 0 invalidates key permission checks")
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(uname.machine.lower(), uname.machine.lower())
    require(arch in ("x86_64", "aarch64"), "unsupported Linux architecture")
    kernel_text = uname.release + " " + uname.version + " " + proc_version
    wsl_kernel = "microsoft" in kernel_text.lower()
    if label == "oci":
        require(arch == "aarch64", "OCI collection requires Linux aarch64")
        require(not wsl_kernel, "Microsoft kernel cannot be labelled OCI")
    elif label == "wsl":
        require(arch == "x86_64" and wsl_kernel, "WSL collection requires x86_64 and Microsoft kernel evidence")
    else:
        require(label == "local", "unknown platform label")
    return {"requested_platform": label, "evidence_label": "local" if label == "local" else label,
            "architecture": arch, "uname": dict(uname._asdict(), node="redacted"), "proc_version": proc_version.strip(),
            "effective_uid": uid, "microsoft_kernel_evidence": wsl_kernel,
            "oci_provider_attested": False}


def require_native_wsl_paths(paths):
    for path in paths:
        require(not re.match(r"^/mnt/[a-z](?:/|$)", str(path.resolve()), re.IGNORECASE),
                "WSL source, output, and scratch must use the native Linux filesystem: " + str(path))


def clean_environment(scratch, inherited=None):
    inherited = os.environ if inherited is None else inherited
    keep = {"HOME", "CARGO_HOME", "RUSTUP_HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE",
            "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "CARGO_HTTP_CAINFO"}
    env = {name: value for name, value in inherited.items() if name in keep}
    env.update(PATH="/usr/local/bin:/usr/bin:/bin", LC_ALL="C", LANG="C", TZ="UTC",
               TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
               PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull,
               PIP_DISABLE_PIP_VERSION_CHECK="1", RUST_BACKTRACE="0", CARGO_TERM_COLOR="never")
    return env


def reject_cargo_configs(root, env):
    locations = {ancestor / ".cargo" for ancestor in (root, *root.parents)}
    locations.add(Path(env.get("CARGO_HOME", str(Path(env["HOME"]) / ".cargo"))))
    for folder in locations:
        for name in ("config", "config.toml"):
            require(not (folder / name).exists() and not (folder / name).is_symlink(),
                    "ambient Cargo configuration must be removed for this collection: " + str(folder / name))


class Commands:
    def __init__(self, out, env, report, public):
        self.out, self.env, self.report, self.public = out, env, report, public

    def run(self, label, command, *, timeout=120, cwd=ROOT):
        require(bool(re.fullmatch(r"[a-z0-9-]+", label)), "unsafe command log label")
        names = ["logs/" + label + suffix for suffix in (".stdout.log", ".stderr.log")]
        record = {"name": label, "command": list(map(str, command)), "timeout_seconds": timeout,
                  "stdout": names[0], "stderr": names[1], "status": "failed"}
        self.report["commands"].append(record)
        self.public.update(names)
        print("key operations: " + label, file=sys.stderr, flush=True)
        started = time.monotonic()
        process = None
        try:
            with (self.out / names[0]).open("xb") as stdout, (self.out / names[1]).open("xb") as stderr:
                process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=self.env,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    record["returncode"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    raise ValidationError(label + " exceeded process-group watchdog")
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        require(record["returncode"] == 0, label + " failed; see raw logs")
        record["status"] = "passed"
        return self.out / names[0], self.out / names[1]


def bounded_text(path, maximum=32 * 1024 * 1024):
    require(path.stat().st_size <= maximum, "report/log is too large: " + path.name)
    return path.read_text(errors="replace")


def parse_rust_tests(text):
    rows = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;[^\n]*$", text, re.MULTILINE)
    require(len(rows) == 1, "expected exactly one Rust library test summary")
    status_text, *numbers = rows[0]
    counts = tuple(map(int, numbers))
    require(status_text == "ok" and counts == (81, 0, 5, 0, 0),
            "Rust library counts must be exactly 81 passed, 0 failed, 5 ignored, 0 measured, 0 filtered")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), counts))


def expected_integration_sources(files):
    fixed = {"rust-toolchain.toml", "protocol_rust/Cargo.toml", "protocol_rust/Cargo.lock",
             "protocol_rust/build.rs", "protocol_rust/fuzz/Cargo.toml", "protocol_rust/fuzz/Cargo.lock",
             "native_research/spiral_native.c", "native_research/spiral_native.h",
             "protocol_v01/tests/fixtures/test_vectors_v0.1.json", "protocol_rust/key_ops_tests.py"}
    for name in files:
        path = PurePosixPath(name)
        if ((name.startswith(("protocol_rust/src/", "protocol_rust/fuzz/")) and path.suffix == ".rs")
                or (path.parent == PurePosixPath("protocol_rust/fuzzing") and path.suffix == ".py")
                or (name.startswith("third_party/rustcrypto/") and "target" not in path.parts
                    and (path.suffix == ".rs" or path.name in
                         ("Cargo.toml", "README.md", "upstream-provenance.json", "patch-manifest.json")))):
            fixed.add(name)
    require(fixed <= files.keys(), "manifest omits integration runner source inputs")
    return {name: files[name] for name in sorted(fixed)}


def validate_integration(report, manifest_files, binary_sha256):
    require(isinstance(report, dict) and report.get("schema") == "spiral-rust-key-operations/v1",
            "invalid key operation report schema")
    require(report.get("status") == "passed", "key operation report did not pass")
    for field, expected in (("tests", 11), ("failures", 0), ("errors", 0), ("skipped", 0)):
        require(type(report.get(field)) is int and report[field] == expected,
                "key operation report requires " + field + "=" + str(expected))
    require(report.get("source_and_binary_unchanged") is True, "runner reports changed source/binary")
    require(report.get("binary_sha256") == binary_sha256, "runner binary digest does not match release binary")
    require(report.get("source_sha256") == expected_integration_sources(manifest_files),
            "runner source hashes do not exactly match the pinned source manifest")
    require(report.get("runner_sha256") == manifest_files["protocol_rust/key_ops_tests.py"],
            "runner digest does not match pinned source")
    require(report.get("failed_tests") == [] and report.get("error_tests") == [], "runner reports failed/error test IDs")
    return {"tests": 11, "failures": 0, "errors": 0, "skipped": 0, "status": "passed"}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inspect_python(commands, executable, label):
    code = "import json,sys,ssl;print(json.dumps(dict(version=list(sys.version_info[:3]),executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,openssl=ssl.OPENSSL_VERSION)))"
    stdout, _ = commands.run(label, [executable, "-I", "-c", code])
    info = strict_json(bounded_text(stdout))
    require(info["version"][:2] == [3, 12], "Python 3.12 is required")
    return info


def prepare_python(args, commands, scratch, files):
    requirements = "protocol_v01/requirements.txt"
    requirements_path = ROOT / requirements
    pins = {}
    for line in read_source(ROOT, requirements).decode().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", line.strip())
        require(match is not None, "requirements must contain exact simple package pins")
        require(match[1] not in pins, "duplicate requirement")
        pins[match[1]] = match[2]
    require(bool(pins), "requirements pins are empty")
    if args.python:
        executable = str(args.python.expanduser().absolute())
        require(os.access(executable, os.X_OK), "--python must name an existing executable")
    else:
        base = shutil.which("python3.12", path=commands.env["PATH"])
        require(base is not None, "Python 3.12 missing; provide --python for an existing pinned venv")
        inspect_python(commands, base, "python-base")
        commands.run("python-venv", [base, "-I", "-m", "venv", scratch / "venv"])
        executable = str(scratch / "venv/bin/python")
        commands.run("python-install", [executable, "-I", "-m", "pip", "--isolated", "install",
                                       "--disable-pip-version-check", "--no-input", "--index-url",
                                       "https://pypi.org/simple", "-r", requirements_path], timeout=900)
    info = inspect_python(commands, executable, "python-version")
    require(info["prefix"] != info["base_prefix"], "test Python must be a virtual environment")
    code = "import importlib.metadata,json;print(json.dumps({name:importlib.metadata.version(name) for name in " + repr(list(pins)) + "}))"
    stdout, _ = commands.run("python-pins", [executable, "-I", "-c", code])
    installed = strict_json(bounded_text(stdout))
    require(installed == pins, "installed Python packages do not match exact requirement pins")
    commands.run("python-pip-check", [executable, "-I", "-m", "pip", "--isolated", "check"])
    stdout, _ = commands.run("python-freeze", [executable, "-I", "-m", "pip", "--isolated", "freeze", "--all"])
    commands.report["python"] = dict(info, pinned_requirements=pins, installed_pins=installed,
                                    requirements_sha256=files[requirements], pip_check="passed",
                                    distributions_log=str(stdout.relative_to(commands.out)))
    return executable


def prepare_toolchain(args, commands, arch):
    if args.toolchain_dir:
        directory = args.toolchain_dir.expanduser().resolve()
        if (directory / "bin/rustc").is_file():
            directory /= "bin"
        rustc, cargo = directory / "rustc", directory / "cargo"
    else:
        rustup = shutil.which("rustup", path=str(Path(commands.env["HOME"]) / ".cargo/bin") + ":" + commands.env["PATH"])
        require(rustup is not None, "rustup missing; provide --toolchain-dir for installed Rust 1.99.1")
        stdout, _ = commands.run("rustup-rustc", [rustup, "which", "--toolchain", RUST_VERSION, "rustc"])
        rustc = Path(bounded_text(stdout).strip())
        stdout, _ = commands.run("rustup-cargo", [rustup, "which", "--toolchain", RUST_VERSION, "cargo"])
        cargo = Path(bounded_text(stdout).strip())
        directory = rustc.parent
    for executable in (rustc, cargo, directory / "rustdoc"):
        require(executable.is_file() and os.access(executable, os.X_OK), "toolchain executable missing: " + str(executable))
    stdout, _ = commands.run("rustc-version", [rustc, "-vV"])
    rust_version = bounded_text(stdout)
    require(re.search(r"^release: " + re.escape(RUST_VERSION) + r"$", rust_version, re.MULTILINE)
            and re.search(r"^commit-hash: " + RUST_COMMIT + r"$", rust_version, re.MULTILINE),
            "installed rustc is not pinned Rust 1.99.1")
    expected_host = arch + "-unknown-linux-gnu"
    require("host: " + expected_host in rust_version.splitlines(), "Rust compiler host differs from collector host")
    stdout, _ = commands.run("cargo-version", [cargo, "-Vv"])
    cargo_version = bounded_text(stdout)
    require(re.search(r"^cargo " + re.escape(RUST_VERSION) + r" \(" + CARGO_COMMIT + r" ", cargo_version)
            and "host: " + expected_host in cargo_version.splitlines(), "installed cargo version/host is not pinned")
    commands.env.update(RUSTC=str(rustc), RUSTDOC=str(directory / "rustdoc"),
                        PATH=str(directory) + ":" + commands.env["PATH"])
    commands.report["toolchain"] = {"rustc": rust_version.strip(), "cargo": cargo_version.strip(),
                                    "host": expected_host, "rustc_sha256": digest(rustc),
                                    "cargo_sha256": digest(cargo)}
    for name in ("cc", "ar", "openssl"):
        executable = shutil.which(name, path="/usr/bin:/bin")
        require(executable is not None, "system tool missing: " + name)
        flag = "version" if name == "openssl" else "--version"
        commands.run(name + "-version", [executable, flag])
        if name == "cc":
            commands.env["CC"] = executable
        elif name == "ar":
            commands.env["AR"] = executable
    return cargo


def finalize(out, report, public):
    """Package only explicitly registered regular public files, including failures."""
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    public.add("result.json")
    write_json(out / "result.json", report)
    hashes = {}
    for name in sorted(public):
        safe_name(name)
        require(not ({"BUILD", "venv", "scratch", "tmp"} & set(PurePosixPath(name).parts)), "private/build file cannot be packaged")
        path = out / name
        require(not path.is_symlink() and path.is_file(), "public artifact missing or unsafe: " + name)
        hashes[name] = sha256(read_source(out, name))
    write_json(out / "SHA256.json", hashes)
    archive = out.with_suffix(".tar.gz")
    require(not archive.exists(), "archive already exists")
    with archive.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
            for name in sorted(public | {"SHA256.json"}):
                bundle.add(out / name, arcname=out.name + "/" + name, recursive=False)
    archive_hash = digest(archive)
    archive.with_name(archive.name + ".sha256").write_text(archive_hash + "  " + archive.name + "\n")
    return {"status": report["status"], "result_directory": str(out), "archive": str(archive),
            "archive_sha256": archive_hash, "result_manifest_sha256": digest(out / "SHA256.json")}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--platform", choices=("oci", "wsl", "local"), required=True)
    result.add_argument("--source-manifest", type=Path, required=True)
    result.add_argument("--expected-manifest-sha256", required=True)
    result.add_argument("--python", type=Path, help="existing Python 3.12 venv with exact pinned requirements")
    result.add_argument("--toolchain-dir", type=Path, help="installed exact Rust 1.99.1 root or bin directory")
    result.add_argument("--output-parent", type=Path, default=Path.home())
    result.add_argument("--check-only", action="store_true", help="verify source integrity only; no platform/test approval")
    result.add_argument("--offline", action="store_true", help="no pip install; cargo --offline (requires --python)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    old_umask = os.umask(0o077)
    out = None
    report = {"schema": SCHEMA, "status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "requested_platform": args.platform, "check_only": args.check_only, "offline": args.offline,
              "scope": SCOPE, "memory_cleanup_approved": False, "constant_time_approved": False,
              "memory_checked": False, "production_memory_passed": False,
              "whole_goal_2_approved": False, "whole_goal_5_approved": False,
              "deployment_approved": False, "platform_tests_passed": False, "commands": []}
    public = set()
    files = None
    before = None
    try:
        parent = args.output_parent.expanduser().resolve()
        require(parent.is_dir(), "output parent must be an existing directory")
        require(not parent.is_relative_to(ROOT), "output parent must be outside the source tree")
        arch = platform.machine().lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = Path(tempfile.mkdtemp(prefix="Spiral-key-ops-" + args.platform + "-" + arch + "-" + stamp + "-", dir=parent))
        (out / "logs").mkdir(mode=0o700)
        (out / "BUILD").mkdir(mode=0o700)
        require(not args.offline or args.python is not None, "--offline requires --python")
        raw, manifest = load_manifest(args.source_manifest.expanduser().absolute(), args.expected_manifest_sha256)
        (out / "source-manifest.json").write_bytes(raw)
        public.add("source-manifest.json")
        files = manifest["files"]
        report.update(source_commit=manifest["source_commit"], manifest_sha256=sha256(raw))
        if "runtime_base_commit" in manifest:
            require(isinstance(manifest["runtime_base_commit"], str)
                    and re.fullmatch(r"[0-9a-f]{40}", manifest["runtime_base_commit"]),
                    "runtime base commit must be full lowercase 40-hex")
            report["runtime_base_commit"] = manifest["runtime_base_commit"]
        before = verify_source(ROOT, files)
        write_json(out / "source-before.json", before)
        public.add("source-before.json")
        report["source_tree_sha256_before"] = source_tree_digest(before)
        if args.check_only:
            report["status"] = "source-integrity-passed"
        else:
            report["host"] = host_evidence(args.platform)
            if args.platform == "wsl":
                require_native_wsl_paths((ROOT, out, Path("/tmp")))
            with tempfile.TemporaryDirectory(prefix="spiral-key-ops-private-", dir="/tmp") as scratch_name:
                scratch = Path(scratch_name)
                os.chmod(scratch, 0o700)
                require(not scratch.is_relative_to(out), "private temporary directory cannot be in results")
                env = clean_environment(scratch)
                require(bool(env.get("HOME")), "HOME must identify the normal user")
                commands = Commands(out, env, report, public)
                reject_cargo_configs(ROOT, env)
                cargo = prepare_toolchain(args, commands, report["host"]["architecture"])
                executable = prepare_python(args, commands, scratch, files)
                (out / "requirements.txt").write_bytes(read_source(ROOT, "protocol_v01/requirements.txt"))
                public.add("requirements.txt")
                common = ["--locked", "-j", "2", "--target-dir", out / "BUILD",
                          "--manifest-path", ROOT / "protocol_rust/Cargo.toml"]
                if args.offline:
                    common.append("--offline")
                stdout, _ = commands.run("rust-library-tests", [cargo, "test", "--lib", *common], timeout=1800)
                report["rust_library_tests"] = parse_rust_tests(bounded_text(stdout))
                commands.run("release-build", [cargo, "build", "--release", *common], timeout=1800)
                binary = out / "BUILD/release/spiral-lab"
                require(binary.is_file() and not binary.is_symlink(), "release binary missing")
                binary_hash = digest(binary)
                report["binary_sha256_before"] = binary_hash
                public.add("key_operations.json")
                commands.run("key-operations", [executable, "-I", "-B", ROOT / "protocol_rust/key_ops_tests.py",
                                               "--binary", binary, "--json", out / "key_operations.json"], timeout=300)
                report["key_operations"] = validate_integration(strict_json((out / "key_operations.json").read_bytes()), files, binary_hash)
                report["binary_sha256_after"] = digest(binary)
                require(report["binary_sha256_after"] == binary_hash, "release binary changed during integration tests")
                report["platform_tests_passed"] = True
                report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="failed", error=type(error).__name__ + ": " + str(error), platform_tests_passed=False)
    finally:
        try:
            if files is not None and before is not None:
                after = snapshot_source(ROOT, files)
                write_json(out / "source-after.json", after)
                public.add("source-after.json")
                report["source_tree_sha256_after"] = source_tree_digest(after)
                require(after == before and after == files, "source changed during collection")
                report["source_unchanged"] = True
        except Exception as error:
            report.update(status="failed", source_unchanged=False, platform_tests_passed=False,
                          source_integrity_error=type(error).__name__ + ": " + str(error))
        try:
            if out is not None:
                # A failed child may never create its promised JSON report.
                public = {name for name in public if (out / name).is_file()}
                summary = finalize(out, report, public)
            else:
                summary = {"status": "failed", "error": report.get("error", "result directory unavailable")}
            print(json.dumps(summary, sort_keys=True), flush=True)
        except Exception as error:
            report.update(status="failed", platform_tests_passed=False,
                          archive_error=type(error).__name__ + ": " + str(error))
            if out is not None:
                # Do not leave a successful report or partial success archive
                # when final packaging fails after writing result.json.
                try:
                    write_json(out / "result.json", report)
                    hashes = {name: sha256(read_source(out, name))
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
