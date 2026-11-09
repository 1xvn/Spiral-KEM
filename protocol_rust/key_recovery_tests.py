"""Encrypted key backup, strict CLI, and cold rotation checks on Linux.

Run this suite separately from the eleven baseline key_ops_tests.py checks.
Credentials exist only in private temporary lab directories. The drills use real
loopback TLS and never operate a service, a vault, or a compromised identity.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from protocol_rust import interop, key_ops_tests as keyops

BINARY = keyops.BINARY
MAGIC = b"SPBKUP00"
HEADER_SIZE = 58
MAX_PEM_SIZE = 65536
MAX_ARCHIVE_SIZE = HEADER_SIZE + MAX_PEM_SIZE + 16


def source_hashes():
    # Explicit public source inventory: do not inspect generated fixture trees.
    result = keyops.source_hashes()
    names = {
        "protocol_rust/key_recovery_tests.py",
        "protocol_rust/interop.py",
        "protocol_v01/requirements.txt",
        "code/opt2/spiral_kem_toy_v031_opt2.py",
    }
    names.update(str(path.relative_to(ROOT))
                 for path in (ROOT / "protocol_v01").glob("*.py"))
    result.update({name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                   for name in sorted(names)})
    return dict(sorted(result.items()))


class KeyRecovery(unittest.TestCase):
    # Reuse helpers without inheriting the baseline suite's eleven test methods.
    setUp = keyops.KeyOperations.setUp
    track_secret = keyops.KeyOperations.track_secret
    audit_output = keyops.KeyOperations.audit_output
    invoke = keyops.KeyOperations.invoke
    private_seed = keyops.KeyOperations.private_seed
    assert_private_file = keyops.KeyOperations.assert_private_file
    tls_fixture = keyops.KeyOperations.tls_fixture
    protocol_args = keyops.KeyOperations.protocol_args
    start_server = keyops.KeyOperations.start_server
    finish_server = keyops.KeyOperations.finish_server

    def stop_server(self, process):
        stdout, stderr = keyops.KeyOperations.stop_server(process)
        pending = self.server_stdout_pending.pop(process, b"")
        self.audit_output(pending + stdout, stderr)
        return stdout, stderr

    def decode_report(self, output):
        def unique_fields(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate JSON field")
                result[name] = value
            return result

        def nonfinite(_value):
            raise ValueError("non-finite JSON number")

        try:
            rows = output.splitlines()
            if len(rows) != 1:
                raise ValueError("expected one report")
            report = json.loads(rows[0], object_pairs_hook=unique_fields,
                                parse_constant=nonfinite)
            if not isinstance(report, dict):
                raise ValueError("expected a report object")
            return report
        except (ValueError, UnicodeError):
            self.fail("command did not produce exactly one strict JSON object")

    @contextmanager
    def in_folder(self, folder):
        previous = self.folder
        self.folder = folder
        try:
            yield
        finally:
            self.folder = previous

    def private_directory(self, name):
        path = self.folder / name
        path.mkdir(mode=0o700)
        return path

    def track_tls(self, pem):
        self.track_secret(pem)
        key = serialization.load_pem_private_key(pem, password=None)
        self.track_secret(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey,
                            X25519PrivateKey, X448PrivateKey)):
            self.track_secret(key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
        elif isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            self.track_secret(key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        return key

    def public_fingerprint(self, kind, raw):
        if kind == "auth":
            public = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes_raw()
        else:
            public = self.track_tls(raw).public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(public).hexdigest()

    def assert_private_blob(self, path, length):
        metadata = path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode), "output is not a regular file")
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_size, length)

    def assert_success(self, completed, expected):
        self.audit_output(completed.stdout, completed.stderr)
        self.assertEqual(completed.returncode, 0, "administrative command failed")
        self.assertFalse(completed.stderr, "successful administrative command wrote stderr")
        self.assertEqual(self.decode_report(completed.stdout), expected)

    def assert_failed(self, completed, operation):
        keyops.KeyOperations.assert_rejected(self, completed)
        report = self.decode_report(completed.stdout)
        self.assertEqual(report, {"status": "failed", "operation": operation})

    def assert_argument_rejected(self, completed, operation):
        # The shared argument parser rejects unknown/duplicate/missing options
        # before an administrative mode can emit its JSON failure report.
        keyops.KeyOperations.assert_rejected(self, completed)
        if completed.stdout:
            self.assertEqual(self.decode_report(completed.stdout),
                             {"status": "failed", "operation": operation})

    def private_blob(self, path, raw):
        # Ciphertext, headers and deliberately truncated public prefixes are not
        # plaintext secrets; tracking one-byte prefixes would create false leaks.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)

    def recovery_key(self, name="recovery.bin", *, umask=-1):
        path = self.folder / name
        completed = self.invoke(["recovery-keygen", "--recovery-key", path], umask=umask)
        self.assertTrue(path.is_file(), "recovery key was not created")
        raw = path.read_bytes()
        self.track_secret(raw)
        self.assert_private_file(path)
        self.assert_success(completed, {"status": "created", "operation": "recovery-keygen"})
        return path

    @staticmethod
    def source_option(kind):
        return "--auth" if kind == "auth" else "--key"

    @staticmethod
    def key_kind(kind):
        return "auth-seed" if kind == "auth" else "tls-private-key"

    def backup(self, kind, source, recovery, archive, fingerprint=None):
        fingerprint = fingerprint or self.public_fingerprint(kind, source.read_bytes())
        completed = self.invoke([
            kind + "-backup", self.source_option(kind), source,
            "--recovery-key", recovery, "--backup", archive,
        ])
        self.assert_success(completed, {
            "status": "backed-up", "key_kind": self.key_kind(kind),
            "public_key_sha256": fingerprint,
        })
        self.assert_private_blob(archive, HEADER_SIZE + source.stat().st_size + 16)
        return fingerprint

    def restore_arguments(self, kind, destination, recovery, archive, fingerprint):
        return [kind + "-restore", self.source_option(kind), destination,
                "--recovery-key", recovery, "--backup", archive,
                "--expected-public-key-sha256", fingerprint]

    def restore(self, kind, destination, recovery, archive, fingerprint):
        completed = self.invoke(self.restore_arguments(
            kind, destination, recovery, archive, fingerprint))
        self.assertTrue(destination.is_file(), "restore did not create its destination")
        raw = destination.read_bytes()
        self.track_secret(raw)
        if kind == "tls":
            self.track_tls(raw)
        self.audit_output(completed.stdout, completed.stderr)
        self.assert_success(completed, {
            "status": "restored", "key_kind": self.key_kind(kind),
            "public_key_sha256": fingerprint,
        })
        self.assert_private_blob(destination, len(raw))
        return raw

    def fixture(self):
        self.tls_fixture()
        recovery = self.recovery_key()
        return recovery, {"auth": self.folder / "auth.bin", "tls": self.folder / "key.pem"}

    def archived_fixture(self):
        recovery, sources = self.fixture()
        archives, fingerprints = {}, {}
        for kind, source in sources.items():
            archives[kind] = self.folder / (kind + ".backup")
            fingerprints[kind] = self.backup(kind, source, recovery, archives[kind])
        return recovery, sources, archives, fingerprints

    def reject_restore(self, kind, recovery, archive, fingerprint, name="rejected.key"):
        destination = self.folder / name
        before = set(self.folder.iterdir())
        self.assert_failed(self.invoke(self.restore_arguments(
            kind, destination, recovery, archive, fingerprint)), kind + "-restore")
        self.assertFalse(destination.exists(), "failed restore created a destination")
        self.assertEqual(set(self.folder.iterdir()), before,
                         "failed restore left a temporary or destination entry")

    def authenticated_archive(self, kind, plaintext, recovery, fingerprint):
        # Independent encryption exercises payload validation after AEAD succeeds.
        header = (MAGIC + bytes((1, 1 if kind == "auth" else 2)) + os.urandom(12)
                  + bytes.fromhex(fingerprint) + struct.pack(">I", len(plaintext)))
        return header + ChaCha20Poly1305(recovery.read_bytes()).encrypt(
            header[10:22], plaintext, header)

    def healthy_generation(self, folder):
        with self.in_folder(folder):
            process, port = self.start_server()
            client = self.invoke(self.protocol_args(
                "client", port=port, connections=1, messages=1, payload=64, pipeline=1))
            client_report = self.decode_report(client.stdout)
            server_report = self.finish_server(process)
            self.assertEqual(client.returncode, 0, "generation health check failed")
            self.assertEqual(process.returncode, 0, "server generation health check failed")
            self.assertFalse(client.stderr, "healthy client wrote stderr")
            for report in (client_report, server_report):
                self.assertEqual(report.get("status"), "passed")
                self.assertEqual(report.get("kem", {}).get("live_keys"), 0)
                self.assertEqual(len(report.get("sessions", [])), 1)
                self.assertTrue(report["sessions"][0].get("authenticated_close"))
                self.assertEqual(report["sessions"][0].get("messages"), 1)
            self.assertTrue(server_report.get("auth_key_closed"))
            self.assertTrue(server_report.get("admission_released"))
            for field in ("session_id", "binding_hash", "transcript_hash"):
                self.assertEqual(client_report["sessions"][0].get(field),
                                 server_report["sessions"][0].get(field))

    def generation(self, name):
        folder = self.private_directory(name)
        with self.in_folder(folder):
            _signing, pin = self.tls_fixture()
        return folder, pin

    def test_recovery_keygen_is_random_private_and_independent_of_umask(self):
        keys = []
        for mask in (0o000, 0o777):
            path = self.recovery_key("recovery-" + oct(mask), umask=mask)
            keys.append(path.read_bytes())
        self.assertFalse(hmac.compare_digest(*keys), "recovery key generation reused bytes")

    def test_auth_round_trip_accepts_read_only_inputs_and_preserves_exact_seed(self):
        recovery = self.recovery_key()
        source = self.folder / "auth.bin"
        raw = self.private_seed(source)
        fingerprint = self.public_fingerprint("auth", raw)
        os.chmod(source, 0o400)
        os.chmod(recovery, 0o400)
        archive = self.folder / "auth.backup"
        self.backup("auth", source, recovery, archive, fingerprint)
        self.assertEqual(archive.stat().st_size, 106)
        os.chmod(archive, 0o400)
        restored = self.restore("auth", self.folder / "restored.bin", recovery, archive, fingerprint)
        self.assertTrue(hmac.compare_digest(restored, raw), "restored authentication seed changed")
        public = self.invoke(["auth-public", "--auth", self.folder / "restored.bin"])
        self.assertEqual(public.returncode, 0)
        self.assertEqual(self.decode_report(public.stdout)["public_key_sha256"], fingerprint)
        for path in (source, recovery, archive):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

    def test_tls_public_and_round_trip_preserve_pem_and_external_spki_fingerprint(self):
        recovery, sources = self.fixture()
        source = sources["tls"]
        original = source.read_bytes()
        fingerprint = self.public_fingerprint("tls", original)
        self.assert_success(self.invoke(["tls-public", "--key", source]), {
            "status": "loaded", "key_kind": "tls-private-key", "public_key_sha256": fingerprint})
        os.chmod(source, 0o400)
        archive = self.folder / "tls.backup"
        self.backup("tls", source, recovery, archive, fingerprint)
        restored = self.restore("tls", self.folder / "restored.pem", recovery, archive, fingerprint)
        self.assertTrue(hmac.compare_digest(original, restored), "restored TLS PEM changed")
        self.assertEqual(self.public_fingerprint("tls", restored), fingerprint)
        padded = original + b"\n" * (MAX_PEM_SIZE - len(original))
        maximum_source = self.folder / "maximum.pem"
        self.private_seed(maximum_source, padded)
        self.track_tls(padded)
        maximum_archive = self.folder / "maximum.backup"
        self.backup("tls", maximum_source, recovery, maximum_archive, fingerprint)
        self.assertEqual(maximum_archive.stat().st_size, MAX_ARCHIVE_SIZE)
        maximum_restored = self.restore("tls", self.folder / "maximum-restored.pem",
                                        recovery, maximum_archive, fingerprint)
        self.assertTrue(hmac.compare_digest(maximum_restored, padded),
                        "maximum-length TLS restore changed the original PEM bytes")
        # Independent SPKI encoding checks cover the provider's other key
        # families and both PKCS8 and traditional PKCS1/SEC1 private encodings.
        keys = (("rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
                ("p256", ec.generate_private_key(ec.SECP256R1())),
                ("p384", ec.generate_private_key(ec.SECP384R1())))
        for label, private in keys:
            for encoding_name, encoding in (("pkcs8", serialization.PrivateFormat.PKCS8),
                                            ("traditional", serialization.PrivateFormat.TraditionalOpenSSL)):
                with self.subTest(algorithm=label, encoding=encoding_name):
                    stem = label + "-" + encoding_name
                    raw = private.private_bytes(serialization.Encoding.PEM, encoding,
                                                serialization.NoEncryption())
                    source = self.folder / (stem + ".pem")
                    self.private_seed(source, raw)
                    fingerprint = self.public_fingerprint("tls", raw)
                    self.assert_success(self.invoke(["tls-public", "--key", source]), {
                        "status": "loaded", "key_kind": "tls-private-key",
                        "public_key_sha256": fingerprint})
                    archive = self.folder / (stem + ".backup")
                    self.backup("tls", source, recovery, archive, fingerprint)
                    restored = self.restore("tls", self.folder / (stem + "-restored.pem"),
                                            recovery, archive, fingerprint)
                    self.assertTrue(hmac.compare_digest(restored, raw),
                                    "TLS algorithm/encoding round trip changed PEM")

    def test_backup_headers_and_fresh_nonces_for_both_roles(self):
        recovery, sources = self.fixture()
        for kind, source in sources.items():
            with self.subTest(kind=kind):
                archives = [self.folder / (kind + str(number)) for number in range(2)]
                fingerprint = self.public_fingerprint(kind, source.read_bytes())
                for archive in archives:
                    self.backup(kind, source, recovery, archive, fingerprint)
                    raw = archive.read_bytes()
                    self.assertEqual(raw[:8], MAGIC)
                    self.assertEqual(raw[8:10], bytes((1, 1 if kind == "auth" else 2)))
                    self.assertEqual(raw[22:54].hex(), fingerprint)
                    self.assertEqual(struct.unpack(">I", raw[54:58])[0], source.stat().st_size)
                    self.restore(kind, self.folder / (archive.name + ".restored"),
                                 recovery, archive, fingerprint)
                first, second = (path.read_bytes() for path in archives)
                self.assertFalse(hmac.compare_digest(first[10:22], second[10:22]),
                                 "backup reused its nonce")
                self.assertFalse(hmac.compare_digest(first, second), "backup reused its archive")

    def test_tampered_header_ciphertext_and_tag_fail_before_writing(self):
        recovery, _sources, archives, fingerprints = self.archived_fixture()
        for kind, archive in archives.items():
            original = archive.read_bytes()
            for offset in (0, 7, 8, 9, 10, 21, 22, 53, 54, 57, 58, len(original) - 17,
                           len(original) - 16, len(original) - 1):
                with self.subTest(kind=kind, byte_offset=offset):
                    changed = bytearray(original)
                    changed[offset] ^= 1
                    damaged = self.folder / "damaged.backup"
                    self.private_blob(damaged, bytes(changed))
                    try:
                        self.reject_restore(kind, recovery, damaged, fingerprints[kind])
                    finally:
                        damaged.unlink()

    def test_every_truncated_archive_prefix_fails_without_destination(self):
        recovery, _sources, archives, fingerprints = self.archived_fixture()
        damaged = self.folder / "truncated.backup"
        for kind, archive in archives.items():
            original = archive.read_bytes()
            for length in range(len(original)):
                with self.subTest(kind=kind, length=length):
                    self.private_blob(damaged, original[:length])
                    try:
                        self.reject_restore(kind, recovery, damaged, fingerprints[kind])
                    finally:
                        damaged.unlink()

    def test_declared_lengths_oversized_archives_and_trailing_bytes_are_rejected(self):
        recovery, _sources, archives, fingerprints = self.archived_fixture()
        damaged = self.folder / "invalid-length.backup"
        for kind, archive in archives.items():
            original = archive.read_bytes()
            lengths = (0, 31, 33, 0xFFFFFFFF) if kind == "auth" else (0, 65537, 0xFFFFFFFF)
            variants = [original[:54] + struct.pack(">I", length) + original[58:]
                        for length in lengths]
            variants.extend((original + b"\x00", original + b"trailing",
                             original + b"\x00" * (MAX_ARCHIVE_SIZE + 1 - len(original))))
            for number, raw in enumerate(variants):
                with self.subTest(kind=kind, variant=number):
                    self.private_blob(damaged, raw)
                    try:
                        self.reject_restore(kind, recovery, damaged, fingerprints[kind])
                    finally:
                        damaged.unlink()

    def test_wrong_recovery_key_expected_identity_and_role_leave_no_files(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        wrong = self.recovery_key("wrong-recovery.bin")
        for kind, archive in archives.items():
            with self.subTest(kind=kind):
                self.reject_restore(kind, wrong, archive, fingerprints[kind])
                self.reject_restore(kind, recovery, archive, "00" * 32)
                other = "tls" if kind == "auth" else "auth"
                self.reject_restore(other, recovery, archive, fingerprints[kind])
                authenticated_wrong_identity = self.folder / (kind + "-wrong-identity.backup")
                self.private_blob(authenticated_wrong_identity, self.authenticated_archive(
                    kind, sources[kind].read_bytes(), recovery, "00" * 32))
                self.reject_restore(kind, recovery, authenticated_wrong_identity, fingerprints[kind])

    def test_short_and_oversized_recovery_keys_reject_backup_and_restore(self):
        _recovery, sources, archives, fingerprints = self.archived_fixture()
        for length in (0, 31, 33, 1024 * 1024):
            invalid = self.folder / ("recovery-" + str(length))
            self.private_seed(invalid, os.urandom(length))
            for kind, source in sources.items():
                with self.subTest(kind=kind, length=length):
                    destination = self.folder / "new.backup"
                    self.assert_failed(self.invoke([
                        kind + "-backup", self.source_option(kind), source,
                        "--recovery-key", invalid, "--backup", destination]), kind + "-backup")
                    self.assertFalse(destination.exists())
                    self.reject_restore(kind, invalid, archives[kind], fingerprints[kind])

    def test_authentication_seed_cannot_equal_recovery_key_in_backup_or_restore(self):
        recovery = self.recovery_key()
        source = self.folder / "same-seed.bin"
        raw = self.private_seed(source, recovery.read_bytes())
        fingerprint = self.public_fingerprint("auth", raw)
        archive = self.folder / "same-seed.backup"
        self.assert_failed(self.invoke(["auth-backup", "--auth", source,
                                      "--recovery-key", recovery, "--backup", archive]), "auth-backup")
        self.assertFalse(archive.exists())
        self.private_blob(archive, self.authenticated_archive("auth", raw, recovery, fingerprint))
        self.reject_restore("auth", recovery, archive, fingerprint)

    def test_invalid_tls_payloads_are_rejected_consistently_before_restore_write(self):
        recovery, sources = self.fixture()
        original = sources["tls"].read_bytes()
        fingerprint = self.public_fingerprint("tls", original)
        unsupported = []
        for key in (X25519PrivateKey.generate(), X448PrivateKey.generate(), Ed448PrivateKey.generate()):
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            self.track_tls(pem)
            unsupported.append(pem)
        variants = (b"", b"not a PEM key", original + original,
                    original + b"\n-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n",
                    original + b"\n" * (MAX_PEM_SIZE + 1 - len(original)), *unsupported)
        for number, raw in enumerate(variants):
            with self.subTest(variant=number):
                source = self.folder / ("invalid-" + str(number) + ".pem")
                self.private_seed(source, raw)
                self.assert_failed(self.invoke(["tls-public", "--key", source]), "tls-public")
                archive = self.folder / ("invalid-" + str(number) + ".backup")
                self.assert_failed(self.invoke(["tls-backup", "--key", source,
                                              "--recovery-key", recovery, "--backup", archive]), "tls-backup")
                self.assertFalse(archive.exists())
                self.private_blob(archive, self.authenticated_archive("tls", raw, recovery, fingerprint))
                self.reject_restore("tls", recovery, archive, fingerprint)

    def test_input_modes_owner_and_hardlink_policy_are_preserved_on_rejection(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        for kind, source in sources.items():
            for path, operation in ((source, "source"), (recovery, "recovery"),
                                    (archives[kind], "archive")):
                original = path.read_bytes()
                for mode in (0o644, 0o660, 0o200, 0o700):
                    with self.subTest(kind=kind, input=operation, mode=oct(mode)):
                        os.chmod(path, mode)
                        try:
                            if operation != "archive":
                                destination = self.folder / "unsafe.backup"
                                self.assert_failed(self.invoke([
                                    kind + "-backup", self.source_option(kind), source,
                                    "--recovery-key", recovery, "--backup", destination]), kind + "-backup")
                                self.assertFalse(destination.exists())
                            if operation != "source":
                                self.reject_restore(kind, recovery, archives[kind], fingerprints[kind])
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                        finally:
                            os.chmod(path, 0o600)
                if os.geteuid() == 0:
                    with self.subTest(kind=kind, input=operation, owner="foreign"):
                        os.chown(path, 65534, -1)
                        try:
                            if operation != "archive":
                                self.assert_failed(self.invoke([
                                    kind + "-backup", self.source_option(kind), source,
                                    "--recovery-key", recovery, "--backup", self.folder / "foreign.backup"]),
                                    kind + "-backup")
                                self.assertFalse((self.folder / "foreign.backup").exists())
                            if operation != "source":
                                self.reject_restore(kind, recovery, archives[kind], fingerprints[kind])
                            self.assertEqual(path.stat().st_uid, 65534)
                        finally:
                            os.chown(path, os.geteuid(), -1)
                self.assertTrue(hmac.compare_digest(path.read_bytes(), original),
                                "input policy rejection changed file bytes")

    def test_symlink_hardlink_directory_and_fifo_inputs_fail_under_watchdog(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        for kind, source in sources.items():
            for original, role in ((source, "source"), (recovery, "recovery"), (archives[kind], "archive")):
                for entry in ("symlink", "hardlink", "directory", "fifo"):
                    path = self.folder / "unsafe-input"
                    with self.subTest(kind=kind, input=role, entry=entry):
                        if entry == "symlink":
                            path.symlink_to(original)
                        elif entry == "hardlink":
                            os.link(original, path)
                        elif entry == "directory":
                            path.mkdir(mode=0o700)
                        else:
                            os.mkfifo(path, 0o600)
                        try:
                            selected_source = path if role == "source" else source
                            selected_recovery = path if role == "recovery" else recovery
                            selected_archive = path if role == "archive" else archives[kind]
                            if role != "archive":
                                destination = self.folder / "unsafe.backup"
                                self.assert_failed(self.invoke([
                                    kind + "-backup", self.source_option(kind), selected_source,
                                    "--recovery-key", selected_recovery, "--backup", destination]), kind + "-backup")
                                self.assertFalse(destination.exists())
                            if role != "source":
                                self.reject_restore(kind, selected_recovery, selected_archive, fingerprints[kind])
                            if entry == "hardlink":
                                # Reject the original name as well: link count is inode policy.
                                if role == "source":
                                    self.assert_failed(self.invoke([
                                        kind + "-backup", self.source_option(kind), original,
                                        "--recovery-key", recovery, "--backup", self.folder / "unsafe.backup"]), kind + "-backup")
                                else:
                                    self.reject_restore(kind, recovery, archives[kind], fingerprints[kind])
                        finally:
                            path.rmdir() if entry == "directory" else path.unlink()

    def test_parent_symlinks_unsafe_modes_and_writable_ancestors_are_rejected(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        actual = self.private_directory("actual")
        linked = self.folder / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        nested = actual / "nested"
        nested.mkdir(mode=0o700)
        for kind, source in sources.items():
            copied = actual / (kind + ".key")
            self.private_seed(copied, source.read_bytes())
            for parent, label in ((linked, "symlink"), (actual, "mode")):
                modes = (0o700,) if label == "symlink" else (0o755, 0o770)
                for mode in modes:
                    with self.subTest(kind=kind, parent=label, mode=oct(mode)):
                        os.chmod(actual, mode)
                        try:
                            self.assert_failed(self.invoke([
                                kind + "-backup", self.source_option(kind), parent / copied.name,
                                "--recovery-key", recovery, "--backup", self.folder / "unsafe.backup"]), kind + "-backup")
                            destination = parent / "restored.key"
                            self.assert_failed(self.invoke(self.restore_arguments(
                                kind, destination, recovery, archives[kind], fingerprints[kind])), kind + "-restore")
                            self.assertFalse((actual / "restored.key").exists())
                        finally:
                            os.chmod(actual, 0o700)
            for mode in (0o500, 0o755, 0o770):
                with self.subTest(kind=kind, writer_parent=oct(mode)):
                    os.chmod(actual, mode)
                    try:
                        self.assert_failed(self.invoke([
                            kind + "-backup", self.source_option(kind), source,
                            "--recovery-key", recovery, "--backup", actual / "new.backup"]), kind + "-backup")
                        self.assertFalse((actual / "new.backup").exists())
                        self.assert_failed(self.invoke(self.restore_arguments(
                            kind, actual / "restored.key", recovery, archives[kind], fingerprints[kind])), kind + "-restore")
                        self.assertFalse((actual / "restored.key").exists())
                    finally:
                        os.chmod(actual, 0o700)
            os.chmod(actual, 0o770)
            try:
                self.assert_failed(self.invoke(self.restore_arguments(
                    kind, nested / "restored.key", recovery, archives[kind], fingerprints[kind])), kind + "-restore")
                self.assertFalse((nested / "restored.key").exists())
            finally:
                os.chmod(actual, 0o700)
        # Existing readers may use an owner-only non-writable parent.
        os.chmod(actual, 0o500)
        try:
            self.backup("auth", actual / "auth.key", recovery, self.folder / "read-only-parent.backup")
        finally:
            os.chmod(actual, 0o700)

    def test_all_writers_refuse_existing_files_and_special_destinations(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        sentinel = self.folder / "sentinel.key"
        original = self.private_seed(sentinel)
        for entry in ("file", "directory", "symlink", "dangling", "fifo"):
            destination = self.folder / "occupied"
            if entry == "file":
                self.private_seed(destination)
            elif entry == "directory":
                destination.mkdir(mode=0o700)
            elif entry == "symlink":
                destination.symlink_to(sentinel)
            elif entry == "dangling":
                destination.symlink_to(self.folder / "missing.key")
            else:
                os.mkfifo(destination, 0o600)
            before = destination.lstat()
            file_before = destination.read_bytes() if entry == "file" else None
            try:
                commands = [("recovery-keygen", ["--recovery-key", destination])]
                for kind, source in sources.items():
                    commands.extend((
                        (kind + "-backup", [self.source_option(kind), source,
                         "--recovery-key", recovery, "--backup", destination]),
                        (kind + "-restore", self.restore_arguments(
                            kind, destination, recovery, archives[kind], fingerprints[kind])[1:]),
                    ))
                for operation, arguments in commands:
                    with self.subTest(entry=entry, operation=operation):
                        self.assert_failed(self.invoke([operation, *arguments]), operation)
                        after = destination.lstat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_size),
                                         (before.st_ino, before.st_mode, before.st_size))
                        self.assertTrue(hmac.compare_digest(sentinel.read_bytes(), original),
                                        "rejected writer changed a symlink target")
                        if file_before is not None:
                            self.assertTrue(hmac.compare_digest(destination.read_bytes(), file_before),
                                            "rejected writer replaced an existing file")
                self.assertFalse((self.folder / "missing.key").exists())
            finally:
                destination.rmdir() if entry == "directory" else destination.unlink()

    def test_admin_modes_reject_missing_extra_duplicate_and_wrong_role_options(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        valid = {
            "recovery-keygen": ["--recovery-key", self.folder / "never-created"],
            "tls-public": ["--key", sources["tls"]],
        }
        for kind, source in sources.items():
            valid[kind + "-backup"] = [self.source_option(kind), source,
                "--recovery-key", recovery, "--backup", self.folder / "never-created"]
            valid[kind + "-restore"] = self.restore_arguments(
                kind, self.folder / "never-created", recovery, archives[kind], fingerprints[kind])[1:]
        for operation, arguments in valid.items():
            variants = [[], arguments[:-1], [*arguments, "--workers", "1"],
                        [*arguments, *arguments[:2]], [*arguments, "--unknown", "value"],
                        [*arguments, "unexpected-positional"]]
            wrong_option = "--auth" if operation.startswith("tls") else "--key"
            variants.append([*arguments, wrong_option, sources["auth"]])
            for number, options in enumerate(variants):
                with self.subTest(operation=operation, variant=number):
                    self.assert_argument_rejected(self.invoke([operation, *options]), operation)
                    self.assertFalse((self.folder / "never-created").exists())
        for kind in sources:
            for fingerprint in ("", "0" * 63, "0" * 65, "gg" * 32):
                with self.subTest(kind=kind, invalid_expected_length=len(fingerprint)):
                    self.reject_restore(kind, recovery, archives[kind], fingerprint)

    def test_public_reports_and_failure_reports_expose_no_private_material(self):
        recovery, sources, archives, fingerprints = self.archived_fixture()
        for kind, source in sources.items():
            with self.subTest(kind=kind):
                original = source.read_bytes()
                self.track_secret(original)
                if kind == "tls":
                    self.track_tls(original)
                    self.assert_success(self.invoke(["tls-public", "--key", source]), {
                        "status": "loaded", "key_kind": "tls-private-key",
                        "public_key_sha256": fingerprints[kind]})
                self.restore(kind, self.folder / (kind + ".public-audit-restored"),
                             recovery, archives[kind], fingerprints[kind])
                self.reject_restore(kind, recovery, archives[kind], "ff" * 32)
        # Every invocation and server output above is audited in raw, hex, base64,
        # PEM and PKCS#8 DER forms. Reports contain only exact public fields.
        self.assertGreater(len(self.secrets), 0)

    def test_cold_rotation_bad_candidate_modes_allow_planned_old_generation_restart(self):
        old, old_pin = self.generation("healthy-old")
        candidate, new_pin = self.generation("candidate")
        self.assertNotEqual(old_pin["public_key_hex"], new_pin["public_key_hex"])
        self.healthy_generation(old)
        for filename in ("auth.bin", "key.pem"):
            with self.subTest(candidate_secret=filename):
                path = candidate / filename
                original = path.read_bytes()
                os.chmod(path, 0o644)
                try:
                    with self.in_folder(candidate):
                        completed = self.invoke(self.protocol_args(
                            "server", port=0, connections=1, messages=1))
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertFalse(b'"listening"' in completed.stdout)
                    report = self.decode_report(completed.stdout)
                    self.assertEqual(report.get("status"), "failed")
                    self.assertEqual(report.get("kem", {}).get("executed_jobs"), 0)
                    self.assertEqual(report.get("kem", {}).get("live_keys"), 0)
                    self.healthy_generation(old)
                    self.assertTrue(hmac.compare_digest(path.read_bytes(), original),
                                    "failed candidate changed its private key")
                finally:
                    os.chmod(path, 0o600)

    def test_cold_rotation_process_loss_before_healthcheck_restarts_healthy_old(self):
        old, _old_pin = self.generation("healthy-old")
        candidate, _new_pin = self.generation("candidate")
        self.healthy_generation(old)
        with self.in_folder(candidate):
            process, _port = self.start_server()
            # Deliberate process loss after readiness, before any candidate client.
            stdout, stderr = self.stop_server(process)
            stdout = self.server_stdout_pending.pop(process, b"") + stdout
            self.audit_output(stdout, stderr)
            self.assertNotEqual(process.returncode, 0, "candidate was not terminated")
        self.healthy_generation(old)

    def test_lost_new_generation_restores_both_keys_and_rejects_stale_old_archives(self):
        old, old_pin = self.generation("old-generation")
        new, new_pin = self.generation("new-generation")
        self.assertNotEqual(old_pin["public_key_hex"], new_pin["public_key_hex"])
        archives = self.private_directory("offline-archives")
        recovery = self.recovery_key()
        fingerprints, originals = {}, {}
        for label, folder in (("old", old), ("new", new)):
            for kind, filename in (("auth", "auth.bin"), ("tls", "key.pem")):
                source = folder / filename
                raw = source.read_bytes()
                fingerprint = self.public_fingerprint(kind, raw)
                self.backup(kind, source, recovery, archives / (label + "-" + kind), fingerprint)
                if label == "new":
                    fingerprints[kind], originals[kind] = fingerprint, raw
        self.healthy_generation(new)
        for filename in ("auth.bin", "key.pem"):
            (new / filename).unlink()
        restored = self.private_directory("restored-new-generation")
        for filename in ("ca.pem", "cert.pem", "pin.json"):
            (restored / filename).write_bytes((new / filename).read_bytes())
        old_before = {filename: hashlib.sha256((old / filename).read_bytes()).hexdigest()
                      for filename in ("auth.bin", "key.pem", "pin.json", "cert.pem", "ca.pem")}
        raw = self.restore("auth", restored / "auth.bin", recovery,
                           archives / "new-auth", fingerprints["auth"])
        self.assertTrue(hmac.compare_digest(raw, originals["auth"]), "recovery changed new authentication bytes")
        # A partial multi-file recovery stays inactive. No server is started
        # until both files have passed their separately trusted identity checks.
        with self.in_folder(restored):
            self.reject_restore("tls", recovery, archives / "new-tls", "00" * 32,
                                name="key.pem")
        old_after = {filename: hashlib.sha256((old / filename).read_bytes()).hexdigest()
                     for filename in old_before}
        self.assertEqual(old_before, old_after, "partial recovery changed the healthy old generation")
        for kind, filename in (("tls", "key.pem"),):
            raw = self.restore(kind, restored / filename, recovery,
                               archives / ("new-" + kind), fingerprints[kind])
            self.assertTrue(hmac.compare_digest(raw, originals[kind]), "recovery changed new identity bytes")
        self.healthy_generation(restored)
        active_before = {filename: hashlib.sha256((restored / filename).read_bytes()).hexdigest()
                         for filename in ("auth.bin", "key.pem", "pin.json", "cert.pem", "ca.pem")}
        rejected = self.private_directory("stale-restore-rejections")
        with self.in_folder(rejected):
            for kind in ("auth", "tls"):
                self.reject_restore(kind, recovery, archives / ("old-" + kind), fingerprints[kind])
        active_after = {filename: hashlib.sha256((restored / filename).read_bytes()).hexdigest()
                        for filename in active_before}
        self.assertEqual(active_before, active_after, "stale backup rejection changed active files")
        self.healthy_generation(restored)


def main():
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=BINARY)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("key recovery integration tests require Linux")
    BINARY = arguments.binary.expanduser().resolve()
    if not BINARY.is_file():
        parser.error("build spiral-lab before running key recovery integration tests")
    keyops.BINARY = BINARY
    interop.BINARY = BINARY
    before = source_hashes()
    binary_before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(KeyRecovery)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = source_hashes()
    binary_after = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    unchanged = before == after and binary_before == binary_after
    passed = result.wasSuccessful() and result.testsRun == 20 and not result.skipped and unchanged
    summary = {
        "schema": "spiral-rust-key-recovery/v1",
        "status": "passed" if passed else "failed",
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "platform": platform.uname()._asdict(),
        "effective_uid": os.geteuid(),
        "foreign_owner_checks_exercised": os.geteuid() == 0,
        "binary_sha256_before": binary_before,
        "binary_sha256_after": binary_after,
        "binary_sha256": binary_before,
        "runner_sha256": before["protocol_rust/key_recovery_tests.py"],
        "source_sha256_before": before,
        "source_sha256_after": after,
        "source_sha256": before,
        "source_and_binary_unchanged": unchanged,
        "failed_tests": [test.id() for test, _traceback in result.failures],
        "error_tests": [test.id() for test, _traceback in result.errors],
        "scope": "Linux encrypted auth/TLS backup and externally pinned recovery, strict public CLI reports, private-file policy, and finite loopback TLS cold rotation drills",
        "baseline_key_operations": {"tests": 11, "execution": "separate suite; not run by this runner"},
        "drill_limits": "Temporary lab identities only; no service or vault integration, automatic production rollback, or rollback of a compromised identity is exercised.",
    }
    if arguments.json:
        arguments.json.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
