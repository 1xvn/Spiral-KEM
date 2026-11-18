"""Exercise the registered-client boundary over real loopback TLS with disposable identities."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from interop import NAME, SERVICE, identities, private_write
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU, NameOID
from protocol_v01.channel import Channel
from protocol_v01.handshake import Pin, client_handshake
from protocol_v01.records import CLOSE, DATA
from protocol_v01.tls import MTLS_ALPN, TLSTransport, context
from protocol_v01.wire import ProtocolError


def subject(name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


def issuer(label):
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(subject(label)).issuer_name(subject(label))
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(True, 0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                         critical=True).sign(key, None))
    return key, ca


def issue(directory, label, authority, usages, expired=False):
    key = Ed25519PrivateKey.generate()
    issuer_key, ca = authority
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject(label)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=2))
            .not_valid_after(now + timedelta(hours=-1 if expired else 1))
            .add_extension(x509.BasicConstraints(False, None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(usages), critical=False).sign(issuer_key, None))
    chain, private = directory / (label + ".pem"), directory / (label + ".key")
    chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private_write(private, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    return chain, private, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class Boundary(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.server, self.client = (Path(temp.name) / side for side in ("server", "client"))
        for directory in (self.server, self.client):
            directory.mkdir(mode=0o700)
        identities(self.server)
        for name in ("ca.pem", "pin.json"):
            shutil.move(self.server / name, self.client / name)
        ca = issuer("lab-client-ca")
        (self.server / "clients.pem").write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
        self.ids = {}
        for label in ("reader", "unlisted", "expired", "server-role", "mixed-role", "foreign"):
            usages = {"server-role": [EKU.SERVER_AUTH], "mixed-role": [EKU.CLIENT_AUTH, EKU.SERVER_AUTH]}
            authority = issuer("other-ca") if label == "foreign" else ca
            self.ids[label] = issue(self.client, label, authority, usages.get(label, [EKU.CLIENT_AUTH]),
                                    expired=label == "expired")

    def exchange(self, port, identity, action, name):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            ca = self.client / "ca.pem"
            if identity in ("absent", "legacy"):
                ctx = context(ca_file=ca)
                if identity == "absent":
                    ctx.set_alpn_protos([MTLS_ALPN])
                    transport = TLSTransport(sock, ctx, server_side=False, server_name=name,
                                             expected_alpn=MTLS_ALPN)
                else:
                    transport = TLSTransport(sock, ctx, server_side=False, server_name=name)
            else:
                chain, key, _ = self.ids[identity]
                transport = TLSTransport.mtls_client(sock, ca_file=ca, cert_file=chain, key_file=key,
                                                     server_name=name)
            try:
                pin = json.loads((self.client / "pin.json").read_text())
                raw = bytes.fromhex(pin["public_key_hex"])
                pins = {(pin["server_name"], pin["service"], hashlib.sha256(raw).digest()):
                        Pin(Ed25519PublicKey.from_public_bytes(raw), pin["not_before"], pin["not_after"])}
                requested_service = "other-service" if action == "wrong-service" else SERVICE
                if action == "wrong-pin":
                    pins.clear()
                keys = client_handshake(transport, name, requested_service, pins)
                channel = Channel(transport, keys, 0)
                try:
                    if action == "prior-session":
                        self.assertNotEqual(transport.binding, self.previous_binding)
                        self.assertNotEqual(keys.sid, self.previous_sid)
                        transport.send(self.previous_frame, time.monotonic() + 3)
                    elif action in ("capture", "duplicate"):
                        frame = channel.records.encode_data(b"READ /status")
                        transport.send(frame, time.monotonic() + 3)
                        self.assertEqual(channel.receive(), (DATA, b"lab-ready"))
                        if action == "duplicate":
                            transport.send(frame, time.monotonic() + 3)
                        else:
                            self.previous_frame, self.previous_binding, self.previous_sid = frame, transport.binding, keys.sid
                    else:
                        channel.send_data(action)
                    if action != "capture":
                        self.assertEqual(channel.receive(), (DATA, b"lab-ready"))
                    channel.send_close()
                    self.assertEqual(channel.receive()[0], CLOSE)
                    channel.shutdown()
                finally:
                    channel.abort()
            finally:
                transport.close()

    def server_args(self, legacy=False, messages=1):
        args = [str(BINARY), "server" if legacy else "mtls-server", "--name", NAME, "--service", SERVICE,
                "--port", "0", "--messages", str(messages), "--cert", str(self.server / "cert.pem"),
                "--key", str(self.server / "key.pem"), "--auth", str(self.server / "auth.bin")]
        if not legacy:
            args.extend(["--client-ca", str(self.server / "clients.pem"),
                         "--client-registry", str(self.server / "registry")])
        return args

    def test_invalid_configuration(self):
        for label, content in [
            ("missing-registry", None),
            ("unknown-role", f"{NAME} {SERVICE} {self.ids['reader'][2]} admin\n"),
            ("duplicate", 2 * f"{NAME} {SERVICE} {self.ids['reader'][2]} status-reader\n"),
            ("invalid-digest", f"{NAME} {SERVICE} short status-reader\n"),
        ]:
            with self.subTest(label=label):
                if content is not None:
                    (self.server / "registry").write_text(content)
                proc = subprocess.run(self.server_args(), capture_output=True, text=True, timeout=5)
                self.assertEqual(proc.returncode, 1)
                report = json.loads(proc.stdout)
                self.assertEqual(report, {"status": "failed", "kem": {"live_keys": 0, "executed_jobs": 0,
                                                                      "rejected_jobs": 0}})
                CONFIGS.append({"case": label, "server_report": report, "server_exit": proc.returncode})

    def run_case(self, label, events, *, identity="reader", grant="reader", role="status-reader",
                 host=NAME, service=SERVICE, sni=NAME, action=b"READ /status", legacy=False, jobs=None):
        registry = self.server / "registry"
        registry.write_text(f"{host} {service} {self.ids[grant][2]} {role}\n")
        args = self.server_args(legacy, 2 if action == "duplicate" else 1)
        success = action == "capture"
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            try:
                self.assertTrue(select.select([proc.stdout], [], [], 10)[0], "listener startup timeout")
                ready = json.loads(proc.stdout.readline())
                self.assertIs(ready["loopback_only"], True)
                if success:
                    self.exchange(ready["listening"], identity, action, sni)
                else:
                    with self.assertRaises(ProtocolError) as rejected:
                        self.exchange(ready["listening"], identity, action, sni)
                    self.assertNotIn("deadline", str(rejected.exception))
                stdout, stderr = proc.communicate(timeout=15)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0 if success else 1, (stdout, stderr))
        lines = [json.loads(line) for line in stdout.splitlines()]
        evidence, report = lines[:-1], lines[-1]
        expected = [{"event": name} for name in events]
        if not success and not legacy:
            expected.append({"event": "failure_cleanup", "role": "server", "active": 0, "pending": 0,
                             "auth_key_closed": True, "drained": True})
        self.assertEqual(evidence, expected)
        if jobs is None:
            jobs = 2 if "registry_admitted" in events else 0
        self.assertEqual(report["kem"], {"live_keys": 0, "rejected_jobs": 0,
                                         "executed_jobs": jobs})
        self.assertEqual(report["status"], "passed" if success else "failed")
        if success:
            self.assertEqual(report["sessions"], [{"messages": 1, "authenticated_close": True}])
            self.assertIs(report["admission_released"], True)
            self.assertIs(report["auth_key_closed"], True)
        ROWS.append({"case": label, "decision": "allow" if success else "deny",
                     "server_stdout_after_listen": lines, "server_exit": proc.returncode})

    def test_connections(self):
        admitted = ["registry_admitted"]
        tls = ["tls_peer_rejected"]
        self.run_case("read-status", admitted + ["status_read"], action="capture")
        for label, opts in [
            ("missing-certificate", {"identity": "absent"}),
            ("untrusted-issuer", {"identity": "foreign", "grant": "foreign"}),
            ("expired", {"identity": "expired", "grant": "expired"}),
            ("server-only-certificate", {"identity": "server-role", "grant": "server-role"}),
            ("dual-purpose-certificate", {"identity": "mixed-role", "grant": "mixed-role"}),
            ("wrong-sni", {"sni": "other.example"}),
            ("legacy-to-required", {"identity": "legacy"}),
        ]:
            with self.subTest(label=label):
                self.run_case(label, tls, **opts)
        for label, opts in [
            ("unregistered", {"identity": "unlisted"}), ("revoked-on-restart", {"role": "revoked"}),
            ("grant-for-other-server", {"host": "other.example"}),
            ("grant-for-other-service", {"service": "other-service"}),
        ]:
            with self.subTest(label=label):
                self.run_case(label, ["registry_denied"], **opts)
        for label, action in [("forbidden-write", b"WRITE /status"), ("forbidden-resource", b"READ /keys"),
                              ("self-declared-role", b"ADMIN READ /status")]:
            with self.subTest(label=label):
                self.run_case(label, admitted + ["operation_denied"], action=action)
        self.run_case("wrong-handshake-service", admitted, action="wrong-service", jobs=0)
        self.run_case("missing-spiral-server-pin", admitted, action="wrong-pin", jobs=1)
        self.run_case("other-session-record", admitted, action="prior-session")
        self.run_case("duplicate-record", admitted + ["status_read"], action="duplicate")
        self.run_case("required-to-legacy", [], legacy=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    ROWS, CONFIGS = [], []
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Boundary))
    if args.json:
        args.json.write_text(json.dumps({"schema": 1, "passed": result.wasSuccessful(), "tests": result.testsRun,
                                        "failures": len(result.failures), "errors": len(result.errors),
                                        "cases": ROWS, "configuration": CONFIGS},
                                        indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
