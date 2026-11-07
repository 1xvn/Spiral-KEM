#!/usr/bin/env python3
"""Install the campaign's pinned official nightly into a fresh local directory.

Requires Python 3.12+, Linux x86_64 or aarch64, and an existing parent directory.
Downloads and logs remain in PREFIX.downloads. No rustup, sudo, or PATH edits are
used. A completed matching installation can be checked and reused by rerunning
the same command; incomplete directories are retained and require a fresh prefix.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request


DATE = "2026-11-07"
RUSTC_RELEASE = "1.101.0-nightly"
RUSTC_COMMIT = "c980177d81d16f843a500905ac98c0cf3af1fd8d"
DIST_URL = f"https://static.rust-lang.org/dist/{DATE}/"
MANIFEST_URL = DIST_URL + "channel-rust-nightly.toml"
PACKAGES = ("rustc", "cargo", "rust-std")
RECEIPT = ".spiral-toolchain.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class InstallError(Exception):
    """A failed prerequisite or installation; existing files are retained."""


def host_target() -> str:
    machine = platform.machine().lower()
    if platform.system() != "Linux" or machine not in ("x86_64", "aarch64"):
        raise InstallError("supported hosts are Linux x86_64 and aarch64")
    return machine + "-unknown-linux-gnu"


def require_official_url(url: str, expected_url: str) -> None:
    """Pin both the HTTPS origin and the complete dated artifact path."""
    if not isinstance(url, str):
        raise InstallError("manifest artifact URL is not a string")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "static.rust-lang.org"
            or parsed.query or parsed.fragment or url != expected_url
            or not parsed.path.startswith(f"/dist/{DATE}/")):
        raise InstallError(f"unexpected official artifact URL: {url!r}")


class _OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, expected_url: str):
        super().__init__()
        self.expected_url = expected_url

    def redirect_request(self, request, response, code, message, headers, newurl):
        # Check before urllib follows a redirect, including an HTTPS downgrade.
        require_official_url(newurl, self.expected_url)
        return super().redirect_request(request, response, code, message, headers, newurl)


def download(url: str, destination: Path, log_path: Path,
             expected_hash: str | None = None) -> str:
    """Stream a new file and reject a hash mismatch before its caller extracts it."""
    require_official_url(url, url)
    if expected_hash is not None and not _SHA256.fullmatch(expected_hash):
        raise InstallError("manifest contains an invalid SHA256")
    print(f"Downloading {destination.name}", flush=True)
    digest = hashlib.sha256()
    count = 0
    opener = urllib.request.build_opener(_OfficialRedirects(url))
    request = urllib.request.Request(url, headers={"User-Agent": "spiral-parser-fuzz-installer/1"})
    with log_path.open("x", encoding="utf-8") as log:
        log.write(f"url: {url}\nexpected_sha256: {expected_hash or 'HTTPS manifest'}\n")
        log.flush()
        try:
            with opener.open(request, timeout=60) as response:
                require_official_url(response.geturl(), url)
                with destination.open("xb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                        digest.update(chunk)
                        count += len(chunk)
            actual_hash = digest.hexdigest()
            log.write(f"bytes: {count}\nsha256: {actual_hash}\n")
            if expected_hash is not None and actual_hash != expected_hash:
                raise InstallError(f"SHA256 mismatch for {destination.name}")
            log.write("verified: yes\n")
        except Exception as error:
            log.write(f"failed: {error}\n")
            raise
    print(f"Verified {destination.name}: {count:,} bytes, SHA256 {actual_hash}", flush=True)
    return actual_hash


def manifest_packages(manifest_path: Path, target: str) -> list[dict[str, str]]:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest-version") != "2" or manifest.get("date") != DATE:
        raise InstallError("official nightly manifest has an unexpected version or date")
    try:
        rustc = manifest["pkg"]["rustc"]
        if (rustc["version"].split()[0] != RUSTC_RELEASE
                or rustc["git_commit_hash"] != RUSTC_COMMIT):
            raise InstallError("official nightly manifest does not match the pinned compiler")
        packages = []
        for name in PACKAGES:
            entry = manifest["pkg"][name]["target"][target]
            if entry.get("available") is not True:
                raise InstallError(f"{name} is unavailable for {target}")
            filename = f"{name}-nightly-{target}.tar.xz"
            url, digest = entry["xz_url"], entry["xz_hash"]
            require_official_url(url, DIST_URL + filename)
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise InstallError(f"invalid SHA256 for {name}")
            packages.append({"name": name, "url": url, "sha256": digest})
        return packages
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise InstallError(f"incomplete official nightly manifest for {target}") from error


def extract_package(archive: Path, unpack: Path) -> Path:
    """Require the expected package root and apply Python's safe data filter."""
    root_name = archive.name.removesuffix(".tar.xz")
    unpack.mkdir()
    with tarfile.open(archive, "r:xz") as package:
        members = package.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != root_name):
                raise InstallError(f"unsafe archive member: {member.name!r}")
        installers = [member for member in members if member.name == f"{root_name}/install.sh"]
        if len(installers) != 1 or not installers[0].isfile():
            raise InstallError("package does not contain one regular install.sh")
        package.extractall(path=unpack, filter="data")
    root = unpack / root_name
    script = root / "install.sh"
    if root.is_symlink() or script.is_symlink() or not script.is_file():
        raise InstallError("extracted package installer is not a regular local file")
    return root


def install_package(package: dict[str, str], workspace: Path, prefix: Path) -> None:
    name = package["name"]
    archive = workspace / package["url"].rsplit("/", 1)[1]
    download(package["url"], archive, workspace / f"{name}.download.log", package["sha256"])
    print(f"Installing {name} into {prefix}", flush=True)
    with (workspace / f"{name}.install.log").open("x", encoding="utf-8") as log:
        try:
            root = extract_package(archive, workspace / f"{name}.unpack")
            command = ["sh", str(root / "install.sh"), f"--prefix={prefix}", "--disable-ldconfig"]
            log.write(f"command: {json.dumps(command)}\n")
            log.flush()
            result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
            if result.returncode:
                raise InstallError(f"{name} installation failed; see {log.name}")
        except Exception as error:
            log.write(f"failed: {error}\n")
            raise


def check_installation(prefix: Path, target: str) -> dict[str, str]:
    versions = {}
    for name, arguments in (("rustc", ["-Vv"]), ("cargo", ["-V"])):
        executable = prefix / "bin" / name
        if (not executable.is_file() or not os.access(executable, os.X_OK)
                or not executable.resolve().is_relative_to(prefix)):
            raise InstallError(f"missing local executable: {executable}")
        result = subprocess.run([str(executable), *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                check=False, timeout=30, env={**os.environ, "LC_ALL": "C"})
        if result.returncode:
            raise InstallError(f"{name} version check failed: {result.stderr.strip()}")
        versions[name] = result.stdout.strip()
    details = dict(line.split(": ", 1) for line in versions["rustc"].splitlines() if ": " in line)
    if (details.get("release") != RUSTC_RELEASE or details.get("commit-hash") != RUSTC_COMMIT
            or details.get("host") != target):
        raise InstallError("installed rustc does not match the pinned release, full commit, and host")
    if not versions["cargo"].startswith("cargo "):
        raise InstallError("installed cargo did not report a Cargo version")
    library_dir = prefix / "lib" / "rustlib" / target / "lib"
    for library in ("std", "core", "alloc"):
        if not any(path.is_file() for path in library_dir.glob(f"lib{library}-*.rlib")):
            raise InstallError(f"installed rust-std is missing lib{library} for {target}")
    return versions


def reuse_installation(prefix: Path, target: str) -> None:
    try:
        receipt = json.loads((prefix / RECEIPT).read_text(encoding="utf-8"))
        if (receipt["date"] != DATE or receipt["target"] != target
                or receipt["rustc_release"] != RUSTC_RELEASE
                or receipt["rustc_commit"] != RUSTC_COMMIT):
            raise InstallError("completion receipt does not match the pinned nightly")
        check_installation(prefix, target)
    except (OSError, ValueError, KeyError, TypeError, InstallError, subprocess.SubprocessError) as error:
        raise InstallError(f"cannot reuse {prefix}: {error}; choose a fresh --prefix (nothing was deleted)") from error
    print(f"Verified existing toolchain: {prefix}\nReceipt: {prefix / RECEIPT}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path,
                        help="fresh installation directory, or a completed matching installation")
    args = parser.parse_args(argv)
    try:
        if sys.version_info < (3, 12):
            raise InstallError("Python 3.12 or newer is required for safe archive extraction")
        target = host_target()
        requested = args.prefix.expanduser().absolute()
        if requested.is_symlink():
            raise InstallError("--prefix must not be a symlink; choose a fresh directory")
        prefix = requested.resolve()
        if prefix.exists():
            reuse_installation(prefix, target)
            return 0
        workspace = prefix.with_name(prefix.name + ".downloads")
        if os.path.lexists(workspace):
            raise InstallError(f"download directory already exists: {workspace}; choose a fresh --prefix")
        if not prefix.parent.is_dir():
            raise InstallError(f"--prefix parent must already exist: {prefix.parent}")
        # Exclusive creation preserves prior installations, downloads, and logs.
        prefix.mkdir()
        workspace.mkdir()
        manifest_path = workspace / "channel-rust-nightly.toml"
        manifest_hash = download(MANIFEST_URL, manifest_path, workspace / "manifest.download.log")
        packages = manifest_packages(manifest_path, target)
        for package in packages:
            install_package(package, workspace, prefix)
        versions = check_installation(prefix, target)
        receipt = {
            "date": DATE, "target": target, "rustc_release": RUSTC_RELEASE,
            "rustc_commit": RUSTC_COMMIT, "manifest_url": MANIFEST_URL,
            "manifest_sha256": manifest_hash, "packages": packages,
            "rustc_version": versions["rustc"], "cargo_version": versions["cargo"],
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "downloads_and_logs": str(workspace),
        }
        with (prefix / RECEIPT).open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2)
            output.write("\n")
        print(f"Installed verified toolchain: {prefix}\nReceipt: {prefix / RECEIPT}\nLogs: {workspace}", flush=True)
        return 0
    except (InstallError, OSError, ValueError, tarfile.TarError, urllib.error.URLError,
            http.client.HTTPException, subprocess.SubprocessError) as error:
        print(f"Toolchain installation failed: {error}", file=sys.stderr)
        print("Existing files were retained. Use a fresh --prefix after an incomplete installation.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
