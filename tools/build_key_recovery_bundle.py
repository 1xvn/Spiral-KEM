#!/usr/bin/env python3
"""Package immutable public Git inputs for portable key recovery validation."""
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

from build_key_operations_bundle import REPO, add, git, selected

RUNTIME_BASE = "d2f19b9e733359f14331d7064a41697c851a1d80"
COLLECTOR = "protocol_rust/validation/key_recovery_platform.py"
TEMPLATE = "tools/key_recovery_launcher.py.in"


def selected_source(name):
    """Extend the public-code selector with recovery guidance and exclusions."""
    path = PurePosixPath(name)
    private_parts = {"build", "venv", ".venv", "scratch", "tmp", "evidence", "target", "__pycache__", ".git"}
    if any(part.lower() in private_parts for part in path.parts):
        return False
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
        return False
    return selected(name) or name in {"protocol_rust/KEY_RECOVERY.md", TEMPLATE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--output-parent", type=Path, required=True)
    args = parser.parse_args(argv)
    commit = git("rev-parse", "--verify", args.commit + "^{commit}").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        parser.error("expected a full immutable Git commit")
    subprocess.run(["git", "merge-base", "--is-ancestor", RUNTIME_BASE, commit], cwd=REPO, check=True)
    entries = git("ls-tree", "-r", "--name-only", "-z", commit).decode().split("\0")
    names = sorted(name for name in entries if name and selected_source(name))
    required = {COLLECTOR, "protocol_rust/validation/key_operations_platform.py",
                "protocol_rust/key_recovery_tests.py", "protocol_rust/key_ops_tests.py",
                "protocol_rust/interop.py", "protocol_v01/requirements.txt",
                "code/opt2/spiral_kem_toy_v031_opt2.py",
                "protocol_rust/KEY_RECOVERY.md",
                TEMPLATE,
                "protocol_rust/Cargo.lock", "protocol_rust/fuzz/Cargo.lock",
                "native_research/spiral_native.c", "third_party/rustcrypto/patch-manifest.json"}
    if not required.issubset(names):
        parser.error("commit omits required collection inputs: " + str(sorted(required - set(names))))
    # Every source byte and the launcher template come from the selected commit.
    # Working-tree changes, Git metadata, operational keys, and evidence stay out.
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
    manifest = (json.dumps({"schema": "spiral-key-operations-source/v1", "profile": "key-recovery",
                           "source_commit": commit, "runtime_base_commit": RUNTIME_BASE,
                           "files": files}, indent=2) + "\n").encode()
    manifest_hash = hashlib.sha256(manifest).hexdigest()
    template = git("show", commit + ":" + TEMPLATE).decode()
    launcher = (template.replace("__MANIFEST_SHA256__", manifest_hash)
                .replace("__COLLECTOR_SHA256__", files[COLLECTOR]).encode())
    name = "Spiral-key-recovery-" + commit[:7]
    readme = f"""# Portable encrypted key recovery validation

Immutable source commit: {commit}
Runtime baseline commit: {RUNTIME_BASE}
Trusted SOURCE.json SHA256: {manifest_hash}
Trusted collector SHA256: {files[COLLECTOR]}

Extract under the native Linux home filesystem. No Git/GitHub authentication is
needed. Run as a normal user. Required: Linux aarch64 (OCI) or x86_64 Microsoft
WSL kernel; Python 3.12; exact Rust/Cargo 1.99.1; cc, ar, OpenSSL, pkg-config and
libssl-dev. The collector creates a private temporary venv with pinned packages.

OCI Ubuntu ARM:
python3 "$HOME/{name}/run_checks.py" --platform oci

WSL Ubuntu x86-64:
python3 "$HOME/{name}/run_checks.py" --platform wsl

Use --python /absolute/venv/bin/python to reuse a Python 3.12 venv with the exact
requirements. Use --toolchain-dir /absolute/rust-prefix for an installed exact
toolchain. --offline requires --python and already cached Cargo dependencies.
--check-only checks source integrity and never records a platform test pass.
--output-parent selects an existing result directory outside the source tree.

Checks: 94 passing default Rust library tests, five ignored tests, release build,
11 baseline key-operation tests, and 20 encrypted backup/restore and cold
rotation recovery tests. Test credentials, BUILD and venv stay in private scratch
outside results. Success and failure preserve public reports and raw logs in
Spiral-key-recovery-{{platform}}-{{arch}}-{{UTC}}-{{unique}}.tar.gz and its checksum.
Return the result archive whose path is printed by the final JSON record.

This bounded run does not approve memory cleanup, constant time, whole Goal 2 or
Goal 5, or deployment. The OCI label records Linux ARM execution and a requested
environment label; it does not independently attest the cloud provider.
""".encode()
    args.output_parent.mkdir(parents=True, exist_ok=True)
    output = args.output_parent / (name + ".tar.gz")
    # Stable ordering and zero timestamps make identical-commit bundles identical.
    with output.open("xb") as stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                add(archive, name + "/README.md", readme)
                add(archive, name + "/SOURCE.json", manifest)
                add(archive, name + "/run_checks.py", launcher, 0o755)
                for path in names:
                    data, mode = source[path]
                    add(archive, name + "/source/" + path, data, mode)
    result = {"archive": str(output.resolve()), "root": name, "profile": "key-recovery",
              "source_commit": commit, "runtime_base_commit": RUNTIME_BASE, "source_files": len(files),
              "manifest_sha256": manifest_hash, "collector_sha256": files[COLLECTOR],
              "archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "bytes": output.stat().st_size}
    output.with_name("bundle.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
