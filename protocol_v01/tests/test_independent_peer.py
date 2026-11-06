"""Independent protocol test peer against the production server on real TLS."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from protocol_v01.channel import Channel
from protocol_v01.demo import test_certificate
from protocol_v01.handshake import server_handshake
from protocol_v01 import handshake as runtime_handshake
from protocol_v01.tls import TLSTransport, context
from protocol_v01.wire import ProtocolError
from protocol_v01.validation.independent_peer import TestPeer, NAME, SERVICE, header

OBSERVATIONS = []


class ServerHarness:
    def __init__(self, cert, key, signing):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(2)
        self.ctx = context(cert_file=cert, key_file=key)
        self.signing = signing
        self.transport = None
        self.channel = None
        self.delivered = []
        self.established = False
        self.error = None
        self.done = threading.Event()
        self.binding_hash = self.h2 = self.sid = None
        self.decap_count = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        sock = None
        try:
            sock, _ = self.listener.accept()
            self.transport = TLSTransport(sock, self.ctx, server_side=True, server_name=NAME)
            self.transport.handshake_deadline = time.monotonic() + 2
            self.binding_hash = hashlib.sha256(self.transport.binding).hexdigest()
            keys = server_handshake(self.transport, NAME, SERVICE, self.signing)
            self.established = True
            self.sid, self.h2 = keys.sid.hex(), keys.transcript_hash.hex()
            self.channel = Channel(self.transport, keys, 1)
            del keys
            # Bounded adversarial test harness timeout, stricter than 60s profile idle.
            original_deadline = self.channel.records.io_deadline
            self.channel.records.io_deadline = lambda: min(original_deadline(), time.monotonic() + 2)
            while True:
                kind, plaintext = self.channel.receive()
                if kind == 0x11:
                    self.channel.shutdown()
                    break
                if kind != 0x10:
                    raise AssertionError('non-DATA delivered to application')
                self.delivered.append(plaintext)
                self.channel.send_data(plaintext)
        except BaseException as exc:
            self.error = exc
        finally:
            if self.transport:
                self.decap_count = self.transport.decapsulation_count
            if self.channel:
                self.channel.abort()
            elif self.transport:
                self.transport.close()
            elif sock:
                sock.close()
            self.done.set()

    def wait(self):
        if not self.done.wait(3):
            if self.transport:
                self.transport.close()
            raise AssertionError('server did not finish bounded scenario')
        self.thread.join(1)
        if self.thread.is_alive():
            raise AssertionError('server worker leaked')
        if self.decap_count > 1:
            raise AssertionError('server key decapsulated more than once')

    def close(self):
        if self.transport:
            self.transport.close()
        self.listener.close()
        self.wait()


class IndependentPeerTests(unittest.TestCase):
    @contextmanager
    def connection(self, *, trusted_public=None):
        with tempfile.TemporaryDirectory(prefix='spiral-independent-peer-') as temp:
            cert, key = test_certificate(temp)
            signing = Ed25519PrivateKey.generate()
            server = ServerHarness(cert, key, signing)
            peer = None
            try:
                peer = TestPeer(server.listener.getsockname(), cert,
                                signing.public_key() if trusted_public is None else trusted_public)
                yield peer, server
            finally:
                if peer:
                    peer.close()
                server.close()
                OBSERVATIONS.append({'scenario': self.id().rsplit('.',1)[-1],
                                     'established': server.established,
                                     'decapsulations': server.decap_count,
                                     'application_deliveries': len(server.delivered),
                                     'closed': server.transport.closed if server.transport else False,
                                     'server_outcome': type(server.error).__name__ if server.error else 'clean_close',
                                     'server_reason': str(server.error) if server.error else 'authenticated_close'})

    def rejected(self, server, *, decaps, established=False, delivered=0):
        server.wait()
        self.assertIsInstance(server.error, ProtocolError)
        self.assertNotIn('deadline', str(server.error), 'Timeout cannot count as input validation rejection')
        self.assertTrue(server.transport.closed)
        self.assertEqual(server.decap_count, decaps)
        self.assertEqual(server.established, established)
        self.assertEqual(len(server.delivered), delivered)

    def test_independent_peer_boundary_data_and_authenticated_close(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish()
            for payload in (b'x', bytes(range(256)) * 64):
                peer.send_record(0x10, payload)
                self.assertEqual(peer.receive_record(0x10), payload)
            self.assertEqual(hashlib.sha256(peer.binding).hexdigest(), server.binding_hash)
            self.assertEqual(peer.h2.hex(), server.h2)
            peer.close_cleanly(); server.wait()
            self.assertIsNone(server.error)
            self.assertEqual(server.decap_count, 1)
            self.assertEqual([len(x) for x in server.delivered], [1,16384])

    def test_new_connections_change_session_exporter_and_kem_key(self):
        seen = []
        for _ in range(3):
            with self.connection() as (peer, server):
                peer.hello(); peer.finish()
                seen.append((peer.sid, peer.binding, hashlib.sha256(peer.sh[108:916]).digest()))
                peer.close_cleanly(); server.wait(); self.assertIsNone(server.error)
        for column in zip(*seen):
            self.assertEqual(len(set(column)),3)

    def test_wrong_binding_rejected_before_keygen(self):
        with patch.object(runtime_handshake, 'load_kem', wraps=runtime_handshake.load_kem) as loader:
            with self.connection() as (peer, server):
                try:
                    peer.hello(binding=bytes(32))
                except (EOFError, OSError):
                    pass
                except Exception as exc:
                    # pyOpenSSL reports TLS EOF as Error/SysCallError, not a parser success.
                    from OpenSSL import SSL
                    self.assertIsInstance(exc, SSL.Error)
                self.rejected(server, decaps=0)
                self.assertIn(str(server.error), ('TLS exporter mismatch', 'unregistered server identity'))
                loader.assert_not_called()

    def test_wrong_scoped_service_rejected_before_keygen(self):
        with patch.object(runtime_handshake, 'load_kem', wraps=runtime_handshake.load_kem) as loader:
            with self.connection() as (peer, server):
                peer.service='unregistered-service'
                try:
                    peer.hello()
                except Exception:
                    pass
                self.rejected(server, decaps=0)
                self.assertIn(str(server.error), ('TLS exporter mismatch', 'unregistered server identity'))
                loader.assert_not_called()

    def test_untrusted_additional_signing_pin_is_rejected(self):
        from protocol_v01.validation.independent_peer import PeerRejected
        with self.connection(trusted_public=Ed25519PrivateKey.generate().public_key()) as (peer, server):
            with self.assertRaises(PeerRejected): peer.hello()
            peer.close()
            self.rejected(server, decaps=0)

    def test_forged_client_finished_never_establishes(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.send(peer.client_key(bad_cf=True))
            self.rejected(server, decaps=1)

    def test_canonical_changed_ciphertext_never_establishes(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.send(peer.client_key(alter_ct=True))
            self.rejected(server, decaps=1)

    def test_early_data_never_decapsulates_or_delivers(self):
        with self.connection() as (peer, server):
            peer.hello()
            peer.send(header(0x10,0,peer.sid,0,17)+bytes(17))
            self.rejected(server, decaps=0)

    def test_previous_session_clientkey_is_rejected(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish(); previous_ck=peer.ck
            peer.close_cleanly(); server.wait(); self.assertIsNone(server.error)
        with self.connection() as (peer, server):
            peer.hello(); self.assertNotEqual(peer.sid,previous_ck[12:28])
            peer.send(previous_ck)
            self.rejected(server, decaps=0)

    def test_duplicate_clientkey_after_established_is_rejected(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish(); peer.send(peer.ck)
            self.rejected(server,decaps=1,established=True)

    def test_skipped_sequence_has_no_plaintext_delivery(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish()
            peer.send(peer.record(0x10,b'skipped',seq=1))
            self.rejected(server,decaps=1,established=True)

    def test_valid_record_replay_delivers_only_once(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish()
            raw=peer.send_record(0x10,b'once')
            self.assertEqual(peer.receive_record(0x10),b'once')
            peer.send(raw)
            self.rejected(server,decaps=1,established=True,delivered=1)

    def test_bad_tag_has_no_plaintext_delivery(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish()
            raw=peer.record(0x10,b'bad tag')
            peer.send(raw[:-1]+bytes([raw[-1]^1]))
            self.rejected(server,decaps=1,established=True)

    def test_wrong_direction_has_no_plaintext_delivery(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.finish()
            raw=bytearray(peer.record(0x10,b'wrong direction'));raw[7]=1
            peer.send(bytes(raw))
            self.rejected(server,decaps=1,established=True)

    def test_truncated_clientkey_claims_opportunity_without_decapsulation(self):
        with self.connection() as (peer, server):
            peer.hello(); peer.send(peer.client_key()[:80]); peer.close()
            self.rejected(server,decaps=0)
            self.assertTrue(server.transport.claimed)

    def test_eof_without_spiral_close_is_not_clean_shutdown(self):
        with self.connection() as (peer, server):
            peer.hello();peer.finish();peer.close()
            self.rejected(server,decaps=1,established=True)


def main():
    import io, platform, sys
    from datetime import datetime, timezone
    OBSERVATIONS.clear()
    output=io.StringIO()
    started=time.monotonic()
    result=unittest.TextTestRunner(stream=output,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(IndependentPeerTests))
    report={'tested_at_utc':datetime.now(timezone.utc).isoformat(),
            'python':platform.python_version(),'tests_run':result.testsRun,
            'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
            'elapsed_seconds':time.monotonic()-started,'real_tls_sessions':len(OBSERVATIONS),
            'observations':OBSERVATIONS,
            'client_implementation':'Independently written framing, transcript, HMAC/HKDF, AEAD and raw PyOpenSSL TLS client from spec; shared KEM algorithm and crypto primitives.',
            'scope':'Experimental test peer vs existing server on loopback; not independent audited production implementations, remote/WAN tests or full design security proof.'}
    dest=Path(__file__).parents[1]/'validation/results'
    dest.mkdir(parents=True,exist_ok=True)
    (dest/'interop.json').write_text(json.dumps(report,indent=2)+'\n')
    print(output.getvalue());print(json.dumps(report,indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    raise SystemExit(main())
