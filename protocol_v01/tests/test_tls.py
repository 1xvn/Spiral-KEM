"""Actual loopback TLS tests plus bounded admission checks; all keys are ephemeral."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from protocol_v01.demo import NAME, test_certificate
from protocol_v01.tls import ALPN, Admission, TLSTransport, context
from protocol_v01.wire import ProtocolError, make_frame, make_header


class TLSAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='spiral-tls-tests-')
        cls.cert, cls.key = test_certificate(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def contexts(self):
        return context(cert_file=self.cert, key_file=self.key), context(ca_file=self.cert)

    @contextmanager
    def connected(self, server_ctx=None, client_ctx=None, *, server_name=NAME, client_name=NAME):
        if server_ctx is None or client_ctx is None:
            default_server, default_client = self.contexts()
            server_ctx = default_server if server_ctx is None else server_ctx
            client_ctx = default_client if client_ctx is None else client_ctx
        sockets, transports = [], []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(2)
            client_sock = socket.create_connection(listener.getsockname(), timeout=2)
            server_sock, _ = listener.accept()
            sockets.extend((client_sock, server_sock))
        def connect(sock, ctx, server_side, name):
            transport = TLSTransport(sock, ctx, server_side=server_side, server_name=name)
            transports.append(transport)
            return transport
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                sf = pool.submit(connect, server_sock, server_ctx, True, server_name)
                cf = pool.submit(connect, client_sock, client_ctx, False, client_name)
                results, errors = [], []
                for future in (sf, cf):
                    try:
                        results.append(future.result(timeout=3))
                    except BaseException as error:
                        errors.append(error)
                if errors:
                    raise errors[0]
                yield results[0], results[1]
        finally:
            for transport in transports:
                transport.close()
            for sock in sockets:
                sock.close()

    def test_real_tls13_matching_exporter_and_new_connection_uniqueness(self):
        values = []
        for _ in range(2):
            with self.connected() as (server, client):
                self.assertEqual(server.connection.get_protocol_version_name(), 'TLSv1.3')
                self.assertEqual(server.binding, client.binding)
                self.assertEqual(len(server.binding), 32)
                self.assertNotEqual(server.binding, bytes(32))
                values.append(client.binding)
        self.assertNotEqual(*values)

    def test_wrong_ca_rejected(self):
        with tempfile.TemporaryDirectory(prefix='spiral-other-ca-') as directory:
            other_cert, _ = test_certificate(directory)
            bad_client = context(ca_file=other_cert)
            with self.assertRaises(ProtocolError):
                with self.connected(client_ctx=bad_client):
                    self.fail('untrusted certificate accepted')

    def test_wrong_hostname_rejected(self):
        with self.assertRaises(ProtocolError):
            with self.connected(server_name='wrong.example', client_name='wrong.example'):
                self.fail('wrong hostname accepted')

    def test_wrong_alpn_rejected(self):
        _, bad_client = self.contexts()
        bad_client.set_alpn_protos([b'wrong/1'])
        with self.assertRaises(ProtocolError):
            with self.connected(client_ctx=bad_client):
                self.fail('wrong ALPN accepted')

    def test_tls12_rejected(self):
        bad_client = SSL.Context(SSL.TLS_METHOD)
        bad_client.set_min_proto_version(SSL.TLS1_2_VERSION)
        bad_client.set_max_proto_version(SSL.TLS1_2_VERSION)
        bad_client.load_verify_locations(str(self.cert))
        bad_client.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
        bad_client.set_alpn_protos([ALPN])
        with self.assertRaises(ProtocolError):
            with self.connected(client_ctx=bad_client):
                self.fail('TLS1.2 accepted')

    def test_expired_certificate_rejected(self):
        with tempfile.TemporaryDirectory(prefix='spiral-expired-ca-') as directory:
            key = Ed25519PrivateKey.generate()
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), critical=False)
                    .sign(key, algorithm=None))
            cp, kp = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            kp.touch(mode=0o600)
            kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
            with self.assertRaises(ProtocolError):
                with self.connected(context(cert_file=cp, key_file=kp), context(ca_file=cp)):
                    self.fail('expired certificate accepted')

    def test_fragmented_and_coalesced_frames_preserve_exact_boundaries(self):
        first = make_frame(0x10, 0, b'S' * 16, 0, b'x' * 17)
        second = make_frame(0x10, 0, b'S' * 16, 1, b'y' * 19)
        with self.connected() as (server, client):
            deadline = time.monotonic() + .7
            client.send(first[:3], deadline)
            client.send(first[3:37], deadline)
            client.send(first[37:] + second, deadline)
            self.assertEqual(server.recv(kind=0x10, role=0, sid=b'S' * 16, sequence=0, deadline=deadline), first)
            self.assertEqual(server.recv(kind=0x10, role=0, sid=b'S' * 16, sequence=1, deadline=deadline), second)

    def test_partial_header_timeout_permanently_closes_and_releases_once(self):
        raw = make_frame(0x10, 0, b'S' * 16, 0, b'x' * 17)
        with self.connected() as (server, client):
            released = []
            server.add_close_callback(lambda: released.append(True))
            client.send(raw[:20], time.monotonic() + .5)
            start = time.monotonic()
            with self.assertRaises(ProtocolError):
                server.recv(kind=0x10, deadline=start + .06)
            self.assertLess(time.monotonic() - start, .6)
            self.assertTrue(server.closed)
            server.close()
            self.assertEqual(released, [True])
            with self.assertRaises(ProtocolError):
                server.recv(kind=0x10, deadline=time.monotonic() + .05)

    def test_slow_header_dribble_does_not_extend_absolute_deadline(self):
        raw = make_frame(0x10, 0, b'S' * 16, 0, b'x' * 17)
        with self.connected() as (server, client):
            def dribble():
                for octet in raw[:15]:
                    try:
                        client.send(bytes([octet]), time.monotonic() + .2)
                    except ProtocolError:
                        return
                    time.sleep(.008)
            start = time.monotonic()
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(dribble)
                with self.assertRaises(ProtocolError):
                    server.recv(kind=0x10, deadline=start + .05)
                future.result(timeout=.5)
            self.assertLess(time.monotonic() - start, .3)
            self.assertTrue(server.closed)

    def test_concurrent_reader_attempt_closes_connection(self):
        with self.connected() as (server, _):
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(server.recv, kind=0x10, deadline=time.monotonic() + .15)
                until = time.monotonic() + .08
                while not server.read_lock.locked() and time.monotonic() < until:
                    time.sleep(.001)
                self.assertTrue(server.read_lock.locked())
                with self.assertRaises(ProtocolError):
                    server.recv(kind=0x10, deadline=time.monotonic() + .1)
                # Closing a descriptor while select() is waiting may surface an
                # OS-level exception; either outcome must leave transport dead.
                with self.assertRaises((ProtocolError, OSError, ValueError)):
                    first.result(timeout=.5)
            self.assertTrue(server.closed)

    def test_clientkey_header_claims_key_before_payload_and_timeout_never_revives(self):
        header = make_header(3, 0, b'S' * 16, 1, 1192)
        with self.connected() as (server, client):
            client.send(header, time.monotonic() + .5)
            deadline = time.monotonic() + .12
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(server.recv, kind=3, role=0, sid=b'S' * 16, sequence=1, deadline=deadline)
                wait_until = time.monotonic() + .08
                while not server.claimed and time.monotonic() < wait_until:
                    time.sleep(.001)
                self.assertTrue(server.claimed)
                self.assertEqual(server.decapsulation_count, 0)
                with self.assertRaises(ProtocolError):
                    future.result(timeout=.5)
            self.assertTrue(server.closed)
            self.assertTrue(server.claimed)
            with self.assertRaises(ProtocolError):
                server.recv(kind=3, deadline=time.monotonic() + .05)

    def test_duplicate_clientkey_header_rejected_before_second_payload(self):
        raw = make_frame(3, 0, b'S' * 16, 1, bytes(1192))
        with self.connected() as (server, client):
            deadline = time.monotonic() + .5
            client.send(raw + raw[:40], deadline)
            self.assertEqual(server.recv(kind=3, role=0, sid=b'S' * 16, sequence=1, deadline=deadline), raw)
            self.assertTrue(server.claimed)
            start = time.monotonic()
            with self.assertRaises(ProtocolError):
                server.recv(kind=3, role=0, sid=b'S' * 16, sequence=1, deadline=deadline)
            self.assertLess(time.monotonic() - start, .2)
            self.assertEqual(server.decapsulation_count, 0)
            self.assertTrue(server.closed)

    def test_close_callback_registration_concurrent_with_close_exactly_once(self):
        with self.connected() as (server, _):
            barrier = threading.Barrier(2)
            calls = []
            def register():
                barrier.wait()
                server.add_close_callback(lambda: calls.append(True))
            def close():
                barrier.wait()
                server.close()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(register), pool.submit(close)]
                for future in futures:
                    future.result(timeout=1)
            server.close()
            self.assertEqual(calls, [True])


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.admission = Admission(clock=lambda: self.now)

    def test_ipv4_mapped_ipv6_same_peer_connection_limit_and_bucket(self):
        owners = [self.admission.acquire(('127.0.0.1' if i % 2 else '::ffff:127.0.0.1', 1)) for i in range(4)]
        self.assertEqual(self.admission.active['127.0.0.1'], 4)
        with self.assertRaises(ProtocolError):
            self.admission.acquire(('127.0.0.1', 1))
        for finish, release in owners:
            finish(); release(); release()
        self.assertFalse(self.admission.active)
        self.assertEqual(self.admission.pending, 0)
        with self.assertRaises(ProtocolError):
            self.admission.acquire(('::ffff:127.0.0.1', 1))
        self.now = 1
        finish, release = self.admission.acquire(('127.0.0.1', 1))
        finish(); release()
        self.assertFalse(self.admission.active)

    def test_global_pending_32_then_established_active_64(self):
        owners = [self.admission.acquire((f'10.0.0.{i + 1}', 1)) for i in range(32)]
        self.assertEqual(self.admission.pending, 32)
        with self.assertRaises(ProtocolError):
            self.admission.acquire(('10.0.1.1', 1))
        for finish, _ in owners:
            finish(); finish()
        self.assertEqual(self.admission.pending, 0)
        more = [self.admission.acquire((f'10.0.2.{i + 1}', 1)) for i in range(32)]
        self.assertEqual(sum(self.admission.active.values()), 64)
        with self.assertRaises(ProtocolError):
            self.admission.acquire(('10.0.3.1', 1))
        for _, release in owners + more:
            release(); release()
        self.assertFalse(self.admission.active)
        self.assertEqual(self.admission.pending, 0)


if __name__ == '__main__':
    unittest.main()
