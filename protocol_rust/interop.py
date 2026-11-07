"""Real loopback TLS interoperability; fresh credentials in a private directory.

Run after cargo build: python protocol_rust/interop.py --binary .../spiral-lab
Requires the existing protocol_v01/requirements.txt Python environment.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from protocol_v01.channel import Channel
from protocol_v01.handshake import client_handshake, server_handshake, Pin
from protocol_v01.records import DATA, CLOSE
from protocol_v01.tls import context, TLSTransport
from protocol_v01.wire import ProtocolError

NAME = "spiral-lab.example"
SERVICE = "spiral-research"


def private_write(path, data):
    path.touch(mode=0o600, exist_ok=False)
    path.write_bytes(data)


def identities(folder, *, leaf_validity=None):
    now = datetime.now(timezone.utc)
    ca = Ed25519PrivateKey.generate()
    leaf = Ed25519PrivateKey.generate()
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Spiral private test CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca, algorithm=None)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
        .issuer_name(ca_name)
        .public_key(leaf.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            leaf_validity[0] if leaf_validity else now - timedelta(minutes=1)
        )
        .not_valid_after(
            leaf_validity[1] if leaf_validity else now + timedelta(hours=1)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(NAME)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca, algorithm=None)
    )
    (folder / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (folder / "cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    private_write(
        folder / "key.pem",
        leaf.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    signing = Ed25519PrivateKey.generate()
    private_write(folder / "auth.bin", signing.private_bytes_raw())
    pin = {
        "server_name": NAME,
        "service": SERVICE,
        "public_key_hex": signing.public_key().public_bytes_raw().hex(),
        "not_before": int(time.time()) - 60,
        "not_after": int(time.time()) + 3600,
        "revoked": False,
    }
    (folder / "pin.json").write_text(json.dumps(pin))
    return signing, pin


class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="spiral-rust-interop-")
        cls.folder = Path(cls.temp.name)
        cls.signing, cls.pin = identities(cls.folder)
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def args(self, mode, **kw):
        f = self.folder
        args = [
            str(BINARY),
            mode,
            "--name",
            NAME,
            "--service",
            SERVICE,
            "--workers",
            "2",
        ]
        if mode == "server":
            args += [
                "--cert",
                str(f / "cert.pem"),
                "--key",
                str(f / "key.pem"),
                "--auth",
                str(f / "auth.bin"),
            ]
        else:
            args += ["--ca", str(f / "ca.pem"), "--pin", str(f / "pin.json")]
        for k, v in kw.items():
            args += ["--" + k.replace("_", "-"), str(v)]
        return args

    def rust_server(self, **kw):
        p = subprocess.Popen(
            self.args("server", port=0, **kw),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.kill, p)
        self.assertTrue(
            select.select([p.stdout], [], [], 15)[0], "server startup timeout"
        )
        line = p.stdout.readline()
        if not line:
            raise AssertionError(p.communicate(timeout=2))
        return p, json.loads(line)["listening"]

    @staticmethod
    def kill(p):
        if p.poll() is None:
            p.kill()
        p.communicate(timeout=5)

    def report(self, p, ok=True):
        out, err = p.communicate(timeout=20)
        if not ok:
            self.assertNotEqual(p.returncode, 0, (out, err))
            if out.strip():
                self.assertEqual(
                    json.loads(out.strip().splitlines()[-1])["kem"]["live_keys"], 0
                )
            return None
        self.assertEqual(p.returncode, 0, (out, err))
        report = json.loads(out.strip().splitlines()[-1])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["kem"]["live_keys"], 0)
        if report["role"] == "server":
            self.assertTrue(report["auth_key_closed"])
        self.observations.append(report)
        return report

    def py_client(self, port, count=1, size=64, tamper=None):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        t = TLSTransport(
            sock,
            context(ca_file=self.folder / "ca.pem"),
            server_side=False,
            server_name=NAME,
        )
        ch = None
        try:
            if tamper:
                original = t.send

                def send(raw, deadline):
                    if raw[6] == 3 and tamper == "finished":
                        raw = raw[:-1] + bytes([raw[-1] ^ 1])
                    original(raw, deadline)

                t.send = send
            pub = self.signing.public_key()
            pins = {
                (NAME, SERVICE, hashlib.sha256(pub.public_bytes_raw()).digest()): Pin(
                    pub, time.time() - 60, time.time() + 3600
                )
            }
            keys = client_handshake(t, NAME, SERVICE, pins)
            info = {
                "session_id": keys.sid.hex(),
                "binding_hash": hashlib.sha256(t.binding).hexdigest(),
                "transcript_hash": keys.transcript_hash.hex(),
            }
            ch = Channel(t, keys, 0)
            del keys
            for i in range(count):
                value = bytes([i % 256]) * size
                ch.send_data(value)
                self.assertEqual(ch.receive(), (DATA, value))
            ch.send_close()
            self.assertEqual(ch.receive()[0], CLOSE)
            ch.shutdown()
            return info
        finally:
            if ch:
                ch.abort()
            t.close()

    def python_server(self, count=1, messages=1, tamper=False):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(count)
        listener.settimeout(10)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        ctx = context(
            cert_file=self.folder / "cert.pem", key_file=self.folder / "key.pem"
        )

        def serve(sock):
            t = TLSTransport(sock, ctx, server_side=True, server_name=NAME)
            ch = None
            try:
                if tamper:
                    original = t.send

                    def send(raw, deadline):
                        if raw[6] == (2 if tamper == "signature" else 4):
                            raw = raw[:-1] + bytes([raw[-1] ^ 1])
                        original(raw, deadline)

                    t.send = send
                keys = server_handshake(t, NAME, SERVICE, self.signing)
                info = {
                    "session_id": keys.sid.hex(),
                    "binding_hash": hashlib.sha256(t.binding).hexdigest(),
                    "transcript_hash": keys.transcript_hash.hex(),
                }
                ch = Channel(t, keys, 1)
                del keys
                for _ in range(messages):
                    kind, value = ch.receive()
                    self.assertEqual(kind, DATA)
                    ch.send_data(value)
                self.assertEqual(ch.receive()[0], CLOSE)
                ch.shutdown()
                return info
            except ProtocolError:
                if tamper:
                    return None
                raise
            finally:
                if ch:
                    ch.abort()
                t.close()

        def accept_all():
            try:
                with ThreadPoolExecutor(max_workers=count) as pool:
                    fs = [
                        pool.submit(serve, listener.accept()[0]) for _ in range(count)
                    ]
                    return [f.result(timeout=20) for f in fs]
            finally:
                listener.close()

        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(accept_all)
        self.addCleanup(pool.shutdown, wait=True)
        return port, future

    def compare(self, a, b):
        names = ("session_id", "binding_hash", "transcript_hash")
        self.assertEqual(
            sorted(tuple(x[n] for n in names) for x in a),
            sorted(tuple(x[n] for n in names) for x in b),
        )
        for name in names:
            self.assertEqual(len({x[name] for x in a}), len(a))

    def test_python_to_rust_four_sessions(self):
        p, port = self.rust_server(connections=4, messages=3)
        with ThreadPoolExecutor(max_workers=4) as pool:
            clients = list(pool.map(lambda _: self.py_client(port, 3, 1024), range(4)))
        self.compare(clients, self.report(p)["sessions"])

    def test_rust_to_python_four_sessions(self):
        port, servers = self.python_server(4, 3)
        p = subprocess.Popen(
            self.args(
                "client", port=port, connections=4, messages=3, payload=1024, pipeline=2
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.kill, p)
        report = self.report(p)
        self.compare(report["sessions"], servers.result(timeout=20))

    def test_rust_to_rust_sizes_and_parallel_senders(self):
        for size in (64, 1024, 16384):
            with self.subTest(payload=size):
                p, port = self.rust_server(connections=4, messages=32)
                client = subprocess.Popen(
                    self.args(
                        "client",
                        port=port,
                        connections=4,
                        messages=32,
                        payload=size,
                        pipeline=8,
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.addCleanup(self.kill, client)
                self.compare(
                    self.report(client)["sessions"], self.report(p)["sessions"]
                )

    def test_wrong_pin_expired_and_revoked(self):
        for change in (
            {"public_key_hex": bytes(32).hex()},
            {"not_after": 1},
            {"revoked": True},
        ):
            with self.subTest(change=list(change)):
                path = self.folder / "bad-pin.json"
                path.write_text(json.dumps(self.pin | change))
                p, port = self.rust_server(connections=1, messages=1)
                args = self.args("client", port=port)
                args[args.index("--pin") + 1] = str(path)
                client = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                self.addCleanup(self.kill, client)
                self.report(client, False)
                self.report(p, False)

    def test_wrong_tls_hostname(self):
        p, port = self.rust_server(connections=1, messages=1)
        args = self.args("client", port=port)
        args[args.index("--name") + 1] = "other.example"
        path = self.folder / "other-pin.json"
        path.write_text(json.dumps(self.pin | {"server_name": "other.example"}))
        args[args.index("--pin") + 1] = str(path)
        client = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self.addCleanup(self.kill, client)
        self.report(client, False)
        self.report(p, False)

    def test_client_finished_rejected(self):
        p, port = self.rust_server(connections=1, messages=1)
        with self.assertRaises(ProtocolError):
            self.py_client(port, tamper="finished")
        self.report(p, False)

    def test_server_finished_rejected_before_data(self):
        port, server = self.python_server(1, 1, tamper=True)
        p = subprocess.Popen(
            self.args("client", port=port),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.kill, p)
        self.report(p, False)
        self.assertEqual(server.result(timeout=20), [None])

    def test_wrong_alpn(self):
        p, port = self.rust_server(connections=1, messages=1)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        ctx = context(ca_file=self.folder / "ca.pem")
        ctx.set_alpn_protos([b"other-protocol"])
        with self.assertRaises(ProtocolError):
            TLSTransport(sock, ctx, server_side=False, server_name=NAME)
        self.report(p, False)

    def test_untrusted_tls_ca(self):
        with tempfile.TemporaryDirectory(prefix="spiral-other-ca-") as temp:
            folder = Path(temp)
            identities(folder)
            p, port = self.rust_server(connections=1, messages=1)
            args = self.args("client", port=port)
            args[args.index("--ca") + 1] = str(folder / "ca.pem")
            client = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.addCleanup(self.kill, client)
            self.report(client, False)
            self.report(p, False)

    def bad_record(self, variant):
        from protocol_v01.records import RecordState

        p, port = self.rust_server(connections=1, messages=2)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        t = TLSTransport(
            sock,
            context(ca_file=self.folder / "ca.pem"),
            server_side=False,
            server_name=NAME,
        )
        try:
            pub = self.signing.public_key()
            pins = {
                (NAME, SERVICE, hashlib.sha256(pub.public_bytes_raw()).digest()): Pin(
                    pub, time.time() - 60, time.time() + 3600
                )
            }
            keys = client_handshake(t, NAME, SERVICE, pins)
            records = RecordState(keys, 0)
            sid = keys.sid
            del keys
            raw = records.encode_data(b"tamper probe")
            end = time.monotonic() + 3
            if variant == "duplicate":
                t.send(raw, end)
                response = t.recv(kind=DATA, role=1, sid=sid, sequence=0, deadline=end)
                self.assertEqual(records.decode(response), (DATA, b"tamper probe"))
                t.send(raw, end)
                with self.assertRaises(ProtocolError):
                    t.recv(kind=DATA, role=1, sid=sid, sequence=1, deadline=end)
            elif variant == "tag":
                t.send(raw[:-1] + bytes([raw[-1] ^ 1]), end)
                with self.assertRaises(ProtocolError):
                    t.recv(kind=DATA, role=1, sid=sid, sequence=0, deadline=end)
            elif variant == "length":
                t.send(raw[:36] + bytes.fromhex("ffffffff"), end)
                with self.assertRaises(ProtocolError):
                    t.recv(kind=DATA, role=1, sid=sid, sequence=0, deadline=end)
            elif variant == "truncated":
                t.send(raw[:45], end)
            elif variant != "no-close":
                raise AssertionError(variant)
        finally:
            t.close()
        self.report(p, False)

    def test_duplicate_record(self):
        self.bad_record("duplicate")

    def test_corrupted_tag(self):
        self.bad_record("tag")

    def test_length_bomb(self):
        self.bad_record("length")

    def test_truncated_record(self):
        self.bad_record("truncated")

    def test_missing_authenticated_close(self):
        self.bad_record("no-close")

    def test_same_ip_connection_bursts_are_bounded(self):
        for count in (16, 64):
            with self.subTest(connections=count):
                p, port = self.rust_server(connections=count, messages=1)
                client = subprocess.Popen(
                    self.args("client", port=port, connections=count),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.addCleanup(self.kill, client)
                self.report(client, False)
                self.report(p, False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "protocol_rust/target/debug/spiral-lab"
    )
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    if not BINARY.is_file():
        raise SystemExit("Build spiral-lab first")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Interop)
    )
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "tests": result.testsRun,
                    "failures": len(result.failures),
                    "errors": len(result.errors),
                    "observations": Interop.observations,
                },
                indent=2,
            )
            + "\n"
        )
    print(
        json.dumps(
            {
                "interop_result": "passed" if result.wasSuccessful() else "failed",
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
            }
        ),
        flush=True,
    )
    raise SystemExit(not result.wasSuccessful())
