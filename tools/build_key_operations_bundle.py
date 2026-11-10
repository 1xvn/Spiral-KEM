#!/usr/bin/env python3
"""Package immutable Git inputs for the bounded Linux key-operations checks."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from source_revision import resolve_source_commit

REPO = Path(__file__).resolve().parents[1]
RUNTIME_BASE = "4866976"


def git(*arguments):
    arguments = [resolve_source_commit(REPO, value) for value in arguments]
    return subprocess.check_output(["git", *arguments], cwd=REPO)


def selected(name):
    path = PurePosixPath(name)
    if any(part in {"target", "build", "evidence", "__pycache__", ".git"} for part in path.parts):
        return False
    if name == "rust-toolchain.toml":
        return True
    if name.startswith("third_party/rustcrypto/"):
        return True
    if name.startswith("code/opt2/"):
        return path.suffix == ".py" or path.name == "requirements.txt"
    if name.startswith("native_research/"):
        return len(path.parts) == 2 and (path.suffix in {".c", ".h", ".py"} or path.name == "Makefile")
    if name.startswith("protocol_v01/"):
        if name in {"protocol_v01/VALIDATION.json", "protocol_v01/validation/RESULTS.json"}:
            return False
        return path.suffix in {".py", ".json"} or path.name == "requirements.txt"
    if name.startswith("protocol_rust/"):
        return (path.suffix in {".rs", ".py"}
                or path.name in {"Cargo.toml", "Cargo.lock", "KEY_OPERATIONS.md"})
    return False


def add(archive, name, data, mode=0o644):
    entry = tarfile.TarInfo(name)
    entry.size = len(data)
    entry.mode = mode
    entry.uid = entry.gid = entry.mtime = 0
    entry.uname = entry.gname = ""
    archive.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--output-parent", type=Path, required=True)
    args = parser.parse_args()
    commit = git("rev-parse", "--verify", args.commit + "^{commit}").decode().strip()
    if not re.fullmatch("[a-f0-9]{40}", commit):
        parser.error("expected a full immutable Git commit")
    runtime = git("rev-parse", RUNTIME_BASE + "^{commit}").decode().strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", runtime, commit], cwd=REPO, check=True)
    entries = git("ls-tree", "-r", "--name-only", "-z", commit).decode().split("\0")
    names = sorted(name for name in entries if name and selected(name))
    collector = "protocol_rust/validation/key_operations_platform.py"
    required = {collector, "protocol_rust/key_ops_tests.py", "protocol_rust/interop.py",
                "protocol_v01/requirements.txt", "protocol_rust/Cargo.lock",
                "protocol_rust/fuzz/Cargo.lock", "native_research/spiral_native.c",
                "third_party/rustcrypto/patch-manifest.json"}
    if not required.issubset(names):
        parser.error("commit omits required collection inputs: " + str(sorted(required - set(names))))
    # Read bytes from Git, never from possibly modified working-tree inputs.
    source = {}
    raw_archive = git("archive", "--format=tar", commit, "--", *names)
    with tarfile.open(fileobj=io.BytesIO(raw_archive)) as original:
        for member in original:
            if member.isdir():
                continue
            if member.name not in names or not member.isfile():
                raise ValueError("non-regular or unexpected Git input: " + member.name)
            source[member.name] = (original.extractfile(member).read(), member.mode)
    if set(source) != set(names):
        raise ValueError("incomplete Git archive")
    files = {name: hashlib.sha256(source[name][0]).hexdigest() for name in names}
    manifest = (json.dumps({"schema": "spiral-key-operations-source/v1",
                          "source_commit": commit, "runtime_base_commit": runtime,
                          "files": files}, indent=2) + "\n").encode()
    manifest_hash = hashlib.sha256(manifest).hexdigest()
    template = git("show", commit + ":tools/key_operations_launcher.py.in").decode()
    launcher = (template.replace("__MANIFEST_SHA256__", manifest_hash)
                .replace("__COLLECTOR_SHA256__", files[collector]).encode())
    name = "Spiral-key-operations-" + commit[:7]
    readme = f"""# Operational key-management validation bundle for OCI and WSL

Immutable source: {commit}
Runtime baseline: {runtime} (historical key-operations integration)

Run without Git/GitHub authentication. Extract into a Linux home filesystem.
Python 3.12, Rust/Cargo 1.99.1, cc/build-essential, pkg-config, libssl-dev,
OpenSSL is required. Reuse the Rust toolchain from the previous validation environment.
Exact Python dependency versions are installed in a private temporary venv.

OCI Ubuntu ARM:
python3 "$HOME/{name}/run_checks.py" --platform oci

WSL Ubuntu x86-64:
python3 "$HOME/{name}/run_checks.py" --platform wsl

To use an existing Python venv, add --python /absolute/venv/bin/python.
If rustup is unavailable, add --toolchain-dir /absolute/rust-prefix.
--check-only verifies source integrity only and does not count as a test pass.

Check 81 Rust unit tests (5 separately ignored), a release build, and 11 key-management/live TLS rotation tests.
Test keys are created and cleaned in a temporary 0700 path outside the result directory.
Both success and failure produce a Spiral-key-ops-*.tar.gz result archive in the home directory.
The result archive path is printed at completion. Missing tool installations produce preserved
failure logs; tools are not silently replaced with different versions.

This run does not execute full functional CI, Memcheck, long-duration load testing, or constant-time/memory/
production deployment approval checks. The OCI label records a Linux ARM run and the user-selected
environment name; it does not independently attest the cloud provider's identity.
""".encode()
    args.output_parent.mkdir(parents=True, exist_ok=True)
    output = args.output_parent / (name + ".tar.gz")
    # Reproducible packaging: stable file order, zero timestamps, no host paths.
    with output.open("xb") as stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                add(archive, name + "/README.md", readme)
                add(archive, name + "/SOURCE.json", manifest)
                add(archive, name + "/run_checks.py", launcher, 0o755)
                for path in names:
                    data, mode = source[path]
                    add(archive, name + "/source/" + path, data, mode)
    result = {"archive": str(output.resolve()), "root": name, "source_commit": commit,
              "runtime_base_commit": runtime, "source_files": len(files),
              "manifest_sha256": manifest_hash,
              "archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "bytes": output.stat().st_size}
    output.with_name("bundle.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
