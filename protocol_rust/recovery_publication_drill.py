"""Linux-only cold recovery rehearsal with disposable keys and strace fault injection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import key_recovery_tests as recovery


class PublicationDrill(recovery.KeyRecovery):
    def test_directory_sync_failure_quarantines_partial_generation(self):
        source, pin = self.generation("approved")
        old, _ = self.generation("retired")
        # Stand in for an independent approval record using the original public
        # pin and leaf certificate before any backup exists.
        cert = x509.load_pem_x509_certificate((source / "cert.pem").read_bytes())
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        approved = {"auth": hashlib.sha256(bytes.fromhex(pin["public_key_hex"])).hexdigest(),
                    "tls": hashlib.sha256(spki).hexdigest()}
        custody = self.private_directory("custody")
        with self.in_folder(custody):
            key = self.recovery_key()
        archives = self.private_directory("backups")
        roles = {"auth": "auth.bin", "tls": "key.pem"}
        for role, name in roles.items():
            self.backup(role, source / name, key, archives / role, approved[role])
        self.backup("auth", old / "auth.bin", key, archives / "retired-auth")
        for name in roles.values():
            (source / name).unlink()

        partial = self.private_directory("uncertain")
        path = partial / "auth.bin"
        trace = self.folder / "fsync.log"
        args = self.restore_arguments("auth", path, key, archives / "auth", approved["auth"])
        failed = subprocess.run(
            ["strace", "-qq", "-yy", "-e", "trace=fsync",
             "-e", "inject=fsync:error=EIO:when=2", "-o", str(trace),
             str(recovery.BINARY), *map(str, args)],
            capture_output=True, timeout=recovery.keyops.WATCHDOG_SECONDS)
        self.assert_failed(failed, "auth-restore")
        calls = trace.read_bytes()
        self.audit_output(calls, b"")
        self.assertRegex(calls, rb"fsync\(\d+<" + re.escape(bytes(partial)) +
                         rb"/\.spiral-key-[0-9a-f]+\.tmp>\)\s+= 0")
        self.assertRegex(calls, rb"fsync\(\d+<" + re.escape(bytes(partial)) +
                         rb">\)\s+= -1 EIO .*\(INJECTED\)")
        self.assertEqual({p.name for p in partial.iterdir()}, {"auth.bin"})
        self.assert_private_file(path)
        inode = path.stat().st_ino
        self.assert_failed(self.invoke(args), "auth-restore")
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(self.public_fingerprint("auth", path.read_bytes()), approved["auth"])

        print("directory_sync_eio: restore failed; auth present, TLS absent; no-replace retry rejected")
        fresh = self.private_directory("fresh")
        with self.in_folder(fresh):
            self.reject_restore("auth", key, archives / "retired-auth", approved["auth"],
                                name="auth.bin")
        print("retired_auth: rejected under the approved generation fingerprint")
        for role, name in roles.items():
            self.restore(role, fresh / name, key, archives / role, approved[role])
        for name in ("ca.pem", "cert.pem", "pin.json"):
            shutil.copyfile(source / name, fresh / name)
        with patch.object(recovery.interop, "BINARY", recovery.BINARY, create=True):
            self.healthy_generation(fresh)
            print("fresh_generation: both roles restored; echo and authenticated close verified")
            # Simulate a newly distributed revocation. Even this matching key
            # must fail on a fresh connection after the client reads the pin.
            (fresh / "pin.json").write_text(json.dumps(pin | {"revoked": True}))
            with self.in_folder(fresh):
                server, port = self.start_server()
                client = self.invoke(self.protocol_args(
                    "client", port=port, connections=1, messages=1, payload=64, pipeline=1))
                report = self.decode_report(client.stdout)
                server_report = self.finish_server(server)
                self.assertNotEqual(client.returncode, 0)
                self.assertNotEqual(server.returncode, 0)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["kem"]["executed_jobs"], 0)
                self.assertEqual(server_report["status"], "failed")
                self.assertEqual(server_report["kem"]["live_keys"], 0)
                print("revoked_pin: connection rejected before client KEM; no fallback attempted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--binary", type=Path,
                        default=recovery.ROOT / "protocol_rust/target/release/spiral-lab")
    args, test_args = parser.parse_known_args()
    binary = args.binary.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"expected an executable spiral-lab at {binary}; build it or supply --binary")
    recovery.BINARY = recovery.keyops.BINARY = binary
    unittest.main(argv=[sys.argv[0], *test_args], defaultTest="PublicationDrill.test_directory_sync_failure_quarantines_partial_generation",
                  verbosity=2)
