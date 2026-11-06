"""Compare public ring fixtures with a separate OpenSSL/Python oracle under Memcheck.

Build the aead_control and hash_control examples first. Errors are never suppressed.
This investigates definedness/correctness, not secret erasure or constant time.
"""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def aead_oracle(mode):
    key_size = 16 if mode == "aes128" else 32
    cipher = (ChaCha20Poly1305 if mode == "chacha" else AESGCM)(b"\x07" * key_size)
    aggregate = hashlib.sha256()
    case = 0
    for length in list(range(34)) + [
        63,
        64,
        65,
        119,
        120,
        121,
        127,
        128,
        129,
        255,
        256,
        257,
        16383,
        16384,
        16401,
    ]:
        for aad_length in [0, 5, 13, 32]:
            case_bytes = case.to_bytes(4, "big")
            message = bytes(i % 251 for i in range(length))
            aad = bytes([0x55]) * aad_length
            wire = cipher.encrypt(bytes(8) + case_bytes, message, aad)
            aggregate.update(case_bytes + wire)
            case += 1
    return {"cases": case, "ciphertext_sha256": aggregate.hexdigest()}


def hash_oracle():
    signing = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    aggregate = hashlib.sha256()
    case = 0
    for name in ["sha256", "sha384", "sha512"]:
        for length in list(range(261)) + [511, 512, 513, 1024, 4096]:
            message = bytes(i % 251 for i in range(length))
            case_bytes = case.to_bytes(4, "big")
            digest = hashlib.new(name, message).digest()
            prk = hmac.digest(b"\x55" * 37, message, name)
            key = hmac.digest(prk, b"control" + case_bytes + b"\x01", name)[:32]
            aggregate.update(case_bytes + digest + key + signing.sign(message))
            case += 1
    return {"cases": case, "sha256": aggregate.hexdigest()}


def prefixed_oracle(mode):
    cipher = (ChaCha20Poly1305 if mode == "chacha" else AESGCM)(
        b"\x07" * (16 if mode == "aes128" else 32)
    )
    aggregate = hashlib.sha256()
    case = 0
    for _offset in [0, 1, 5, 15, 16, 31]:
        for length in list(range(261)) + [16384]:
            case_bytes = case.to_bytes(4, "big")
            aad = bytes([23, 3, 3]) + (length + 16).to_bytes(2, "big")
            aggregate.update(
                case_bytes
                + cipher.encrypt(
                    bytes(8) + case_bytes, bytes(i % 251 for i in range(length)), aad
                )
            )
            case += 1
    return {"cases": case, "ciphertext_sha256": aggregate.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--examples", type=Path, required=True)
    parser.add_argument("--valgrind", default=shutil.which("valgrind"))
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--library-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.valgrind or bool(args.loader) != bool(args.library_path):
        parser.error("Valgrind is required; loader and library-path must be paired")
    args.output.mkdir(parents=True, exist_ok=True)
    prefix = (
        [str(args.loader), "--library-path", str(args.library_path)]
        if args.loader
        else []
    )
    observations = []
    for mode in [
        "aes128",
        "aes256",
        "chacha",
        "hash-hkdf-ed25519",
        "prefixed-aes128",
        "prefixed-aes256",
        "prefixed-chacha",
    ]:
        log = (args.output / f"{mode}.log").resolve()
        binary = args.examples.resolve() / (
            "hash_control"
            if mode == "hash-hkdf-ed25519"
            else "prefixed_control" if mode.startswith("prefixed-") else "aead_control"
        )
        command = [str(binary)] + (
            [] if mode == "hash-hkdf-ed25519" else [mode.removeprefix("prefixed-")]
        )
        process = subprocess.run(
            [
                str(args.valgrind),
                "--error-exitcode=99",
                "--track-origins=yes",
                "--leak-check=full",
                f"--log-file={log}",
                *prefix,
                *command,
            ],
            capture_output=True,
            text=True,
            timeout=180,
            env=os.environ.copy(),
        )
        actual = json.loads(process.stdout)
        oracle = (
            hash_oracle()
            if mode == "hash-hkdf-ed25519"
            else (
                prefixed_oracle(mode.removeprefix("prefixed-"))
                if mode.startswith("prefixed-")
                else aead_oracle(mode)
            )
        )
        match = re.search(r"ERROR SUMMARY: ([\d,]+) errors", log.read_text())
        errors = int(match[1].replace(",", "")) if match else None
        item = {
            "mode": mode,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "process_exit": process.returncode,
            "memcheck_errors": errors,
            "actual": actual,
            "oracle": oracle,
            "oracle_matches": all(actual[k] == v for k, v in oracle.items()),
            "stderr": process.stderr,
        }
        item["passed"] = (
            process.returncode == 0 and errors == 0 and item["oracle_matches"]
        )
        observations.append(item)
        print(json.dumps(item), flush=True)
    (args.output / "result.json").write_text(json.dumps(observations, indent=2) + "\n")
    raise SystemExit(not all(item["passed"] for item in observations))


if __name__ == "__main__":
    main()
