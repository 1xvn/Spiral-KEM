"""Core vector compatibility and rejection tests, without network fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import time
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from protocol_v01 import handshake as hs
from protocol_v01 import wire


FIXTURE = Path(__file__).parent / "fixtures" / "test_vectors_v0.1.json"


class ScriptedTransport:
    """Prevalidated synthetic TLS transport used only for byte-vector tests."""
    def __init__(self, incoming, binding):
        self.incoming = list(incoming)
        self.binding = binding
        self.closed = False
        self.sent = []
        self.callbacks = []

    def send(self, raw, deadline):
        if self.closed or time.monotonic() >= deadline:
            raise wire.ProtocolError("closed or deadline")
        self.sent.append(raw)

    def recv(self, *, kind, role, sid, sequence, deadline):
        raw = self.incoming.pop(0)
        # Model the real transport's header check before consuming its payload.
        wire.parse_header(raw[:40], kind=kind, role=role, sid=sid, sequence=sequence)
        if kind == 3:
            if self.claimed:
                raise wire.ProtocolError("duplicate CK")
            self.claimed = True
        return raw

    def add_close_callback(self, callback):
        if self.closed:
            callback()
        else:
            self.callbacks.append(callback)

    def close(self):
        self.closed = True
        callbacks, self.callbacks = self.callbacks, []
        for callback in callbacks:
            callback()


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads(FIXTURE.read_text())
        cls.frames = {name: bytes.fromhex(value) for name, value in cls.v['frames'].items()}
        cls.binding = bytes.fromhex(cls.v['inputs']['synthetic_exporter'])
        cls.name = cls.v['inputs']['server_name']
        cls.service = cls.v['inputs']['service']
        cls.auth = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(cls.v['inputs']['server_auth_seed']))
        cls.keyid = bytes.fromhex(cls.v['public']['auth_key_id'])

    def pin(self, **overrides):
        values = dict(public_key=self.auth.public_key(), not_before=0, not_after=time.time()+3600)
        values.update(overrides)
        return {(self.name, self.service, self.keyid): hs.Pin(**values)}

    def assert_keys(self, keys):
        self.assertEqual(keys.sid.hex(), self.v['public']['session_id'])
        for attr, vector in [('c_key','client_data_key'), ('s_key','server_data_key'),
                             ('c_prefix','client_nonce_prefix'), ('s_prefix','server_nonce_prefix'),
                             ('transcript_hash','h2')]:
            self.assertEqual(getattr(keys, attr).hex(), self.v['expected'][vector])

    def test_client_matches_supplied_vectors(self):
        transport = ScriptedTransport([self.frames['server_hello'],self.frames['server_finished']], self.binding)
        randoms = [bytes.fromhex(self.v['inputs']['client_random']),
                   bytes.fromhex(self.v['inputs']['kem_test_seeds']['message'])]
        with patch.object(hs.secrets, 'token_bytes', side_effect=randoms):
            keys = hs.client_handshake(transport, self.name, self.service, self.pin())
        self.assert_keys(keys)
        self.assertEqual(transport.sent, [self.frames['client_hello'], self.frames['client_key']])
        transport.close()

    def test_server_matches_supplied_vectors_and_releases_live_id(self):
        transport = ScriptedTransport([self.frames['client_hello'], self.frames['client_key']], self.binding)
        seeds = self.v['inputs']['kem_test_seeds']
        randoms = [bytes.fromhex(self.v['public']['session_id'])]
        randoms += [bytes.fromhex(seeds[name]) for name in ('matrix','secret','fallback')]
        randoms += [bytes.fromhex(self.v['inputs']['server_random'])]
        with patch.object(hs.secrets, 'token_bytes', side_effect=randoms):
            keys = hs.server_handshake(transport, self.name, self.service, self.auth)
        self.assert_keys(keys)
        self.assertEqual(transport.sent, [self.frames['server_hello'], self.frames['server_finished']])
        self.assertEqual(transport.decapsulation_count, 1)
        self.assertIn(keys.sid, hs._LIVE_IDS)
        transport.close()
        self.assertNotIn(keys.sid, hs._LIVE_IDS)

    def test_scoped_pins_rejected_before_kem(self):
        for overrides in [dict(revoked=True), dict(not_after=time.time()-1),
                          dict(not_before=time.time()+1000),
                          dict(public_key=Ed25519PrivateKey.generate().public_key())]:
            with self.subTest(overrides=tuple(overrides)):
                transport = ScriptedTransport([self.frames['server_hello']], self.binding)
                with patch.object(hs, 'load_kem') as loader:
                    with self.assertRaises(wire.ProtocolError):
                        hs.client_handshake(transport, self.name, self.service, self.pin(**overrides))
                    loader.assert_not_called()
                self.assertTrue(transport.closed)
        for pins in [{}, {(self.name, 'other-service', self.keyid): next(iter(self.pin().values()))}]:
            transport = ScriptedTransport([self.frames['server_hello']], self.binding)
            with patch.object(hs, 'load_kem') as loader:
                with self.assertRaises(wire.ProtocolError):
                    hs.client_handshake(transport, self.name, self.service, pins)
                loader.assert_not_called()

    def test_server_bad_binding_or_service_before_kem(self):
        for binding, service in [(b'x'*32, self.service),(self.binding,'other-service')]:
            transport = ScriptedTransport([self.frames['client_hello']], binding)
            with patch.object(hs, 'load_kem') as loader:
                with self.assertRaises(wire.ProtocolError):
                    hs.server_handshake(transport, self.name, service, self.auth)
                loader.assert_not_called()
            self.assertEqual(transport.sent, [])
            self.assertTrue(transport.closed)

    def test_invalid_signature_before_kem(self):
        bad = bytearray(self.frames['server_hello']); bad[-1] ^= 1
        transport = ScriptedTransport([bytes(bad)], self.binding)
        with patch.object(hs, 'load_kem') as loader:
            with self.assertRaises(wire.ProtocolError):
                hs.client_handshake(transport, self.name, self.service, self.pin())
            loader.assert_not_called()
        self.assertTrue(transport.closed)

    def test_core_checks_finished(self):
        bad = bytearray(self.frames['server_finished']); bad[-1] ^= 1
        transport = ScriptedTransport([self.frames['server_hello'], bytes(bad)], self.binding)
        randoms = [bytes.fromhex(self.v['inputs']['client_random']),
                   bytes.fromhex(self.v['inputs']['kem_test_seeds']['message'])]
        with patch.object(hs.secrets, 'token_bytes', side_effect=randoms):
            with self.assertRaises(wire.ProtocolError):
                hs.client_handshake(transport, self.name, self.service, self.pin())
        self.assertTrue(transport.closed)

    def test_server_bad_cf_and_ciphertext_are_one_shot(self):
        from dataclasses import replace
        original_ck = self.frames['client_key']
        bad_cf = bytearray(original_ck); bad_cf[-1] ^= 1
        malformed_ct = bytearray(original_ck); malformed_ct[40+5] = 1
        kem = hs.load_kem().SpiralKEM()
        ct = kem.deserialize_ciphertext_compact(original_ck[40:1200])
        changed = replace(ct, v=((ct.v[0]+1)%3329,) + ct.v[1:])
        canonical_bad = original_ck[:40] + kem.serialize_ciphertext_compact(changed) + original_ck[1200:]
        for candidate, expected_calls in [(bytes(bad_cf),1),(bytes(malformed_ct),0),(canonical_bad,1)]:
            transport = ScriptedTransport([self.frames['client_hello'], candidate], self.binding)
            seeds = self.v['inputs']['kem_test_seeds']
            randoms = [bytes.fromhex(self.v['public']['session_id'])]
            randoms += [bytes.fromhex(seeds[name]) for name in ('matrix','secret','fallback')]
            randoms += [bytes.fromhex(self.v['inputs']['server_random'])]
            with patch.object(hs.secrets, 'token_bytes', side_effect=randoms):
                with self.assertRaises(wire.ProtocolError):
                    hs.server_handshake(transport, self.name, self.service, self.auth)
            self.assertTrue(transport.claimed)
            self.assertEqual(transport.decapsulation_count, expected_calls)
            self.assertEqual(transport.sent, [self.frames['server_hello']])
            self.assertTrue(transport.closed)
            self.assertNotIn(bytes.fromhex(self.v['public']['session_id']), hs._LIVE_IDS)

    def test_one_shot_consumed_after_failure(self):
        transport = ScriptedTransport([], self.binding)
        with self.assertRaises(wire.ProtocolError):
            hs.client_handshake(transport, self.name, self.service, {})
        self.assertTrue(transport._handshake_used)
        with self.assertRaises(wire.ProtocolError):
            hs.client_handshake(transport, self.name, self.service, {})

    def test_concurrent_server_owner_and_late_receive_fail_closed(self):
        entered = threading.Event()
        release = threading.Event()
        outer = self

        class DelayedTransport(ScriptedTransport):
            def recv(self, **kwargs):
                entered.set()
                if not release.wait(2):
                    raise AssertionError("test release missing")
                # Deliberately emulate a late callback returning a valid CH
                # even after the other owner has permanently closed the socket.
                return outer.frames['client_hello']

        transport = DelayedTransport([], self.binding)
        outcomes = []

        def first_owner():
            try:
                result = hs.server_handshake(transport, self.name, self.service, self.auth)
                outcomes.append(('established', result))
            except BaseException as error:
                outcomes.append(('failed', error))

        worker = threading.Thread(target=first_owner, daemon=True)
        with patch.object(hs, 'load_kem') as loader:
            worker.start()
            try:
                self.assertTrue(entered.wait(2), "first owner did not reach receive")
                with self.assertRaises(wire.ProtocolError):
                    hs.server_handshake(transport, self.name, self.service, self.auth)
                self.assertTrue(transport.closed)
                self.assertTrue(transport._handshake_used)
                self.assertEqual(transport.decapsulation_count, 0)
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive(), "first owner failed to leave late callback")
            loader.assert_not_called()
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0][0], 'failed')
        self.assertIsInstance(outcomes[0][1], wire.ProtocolError)
        self.assertTrue(transport.closed)
        self.assertEqual(transport.sent, [])
        self.assertLessEqual(transport.decapsulation_count, 1)

    def test_successful_server_cannot_retry_or_reset_counter(self):
        transport = ScriptedTransport([self.frames['client_hello'], self.frames['client_key']], self.binding)
        seeds = self.v['inputs']['kem_test_seeds']
        randoms = [bytes.fromhex(self.v['public']['session_id'])]
        randoms += [bytes.fromhex(seeds[name]) for name in ('matrix','secret','fallback')]
        randoms += [bytes.fromhex(self.v['inputs']['server_random'])]
        with patch.object(hs.secrets, 'token_bytes', side_effect=randoms):
            result = hs.server_handshake(transport, self.name, self.service, self.auth)
        self.assert_keys(result)
        self.assertEqual(transport.decapsulation_count, 1)
        self.assertFalse(transport.closed)
        with patch.object(hs, 'load_kem') as loader:
            with self.assertRaises(wire.ProtocolError):
                hs.server_handshake(transport, self.name, self.service, self.auth)
            loader.assert_not_called()
        self.assertTrue(transport.closed)
        self.assertTrue(transport._handshake_used)
        self.assertEqual(transport.decapsulation_count, 1)
        self.assertEqual(transport.sent, [self.frames['server_hello'], self.frames['server_finished']])
        self.assertNotIn(result.sid, hs._LIVE_IDS)

    def test_expired_deadline_before_work(self):
        transport = ScriptedTransport([], self.binding)
        transport.handshake_deadline = time.monotonic()-1
        with patch.object(hs, 'load_kem') as loader:
            with self.assertRaises(wire.ProtocolError):
                hs.server_handshake(transport, self.name, self.service, self.auth)
            loader.assert_not_called()
        self.assertTrue(transport.closed)

    def test_kem_source_guard(self):
        with patch.object(Path, 'read_bytes', return_value=b'not the approved source'):
            with self.assertRaises(wire.ProtocolError):
                hs.load_kem()

    def test_ch_grammar(self):
        payload = self.frames['client_hello'][40:]
        parsed = hs.parse_client_hello(payload)
        self.assertEqual((parsed.server_name,parsed.service),(self.name,self.service))
        bads = [payload+b'\0', payload[:64]+b'\0'+payload[65:],
                payload[:65]+b'\0\0'+payload[67:],
                payload[:64]+b'\x02\0\1\0\1'+payload[67:]]
        for bad in bads:
            with self.assertRaises(wire.ProtocolError):
                hs.parse_client_hello(bad)
        for name, service in [('LOCALHOST','x'),('127.0.0.1','x'),('host.','x'),
                              ('-host','x'),('host','Upper'),('host','x'*65)]:
            with self.assertRaises(wire.ProtocolError):
                hs.validate_identity(name,service)

    def test_semantic_header_gaps_are_rejected(self):
        for name, start, end, value in [
            ('client_hello',7,8,b'\x01'), ('server_hello',7,8,b'\x00'),
            ('client_key',28,36,(99).to_bytes(8,'big')),
            ('server_finished',12,28,bytes(16)),
            ('client_data',28,36,(2**64-1).to_bytes(8,'big')),
            ('client_data',28,36,(2**20-1).to_bytes(8,'big')),
        ]:
            raw=bytearray(self.frames[name]); raw[start:end]=value
            with self.subTest(frame=name,offset=start), self.assertRaises(wire.ProtocolError):
                wire.parse_frame(bytes(raw))
        with self.assertRaises(wire.ProtocolError):
            wire.parse_frame(self.frames['client_data'], sequence=7)
        with self.assertRaises(wire.ProtocolError):
            wire.parse_frame(self.frames['client_data'], sid=b'x'*16)

    def test_all_fixture_frames_roundtrip(self):
        for name, raw in self.frames.items():
            with self.subTest(frame=name):
                frame=wire.parse_frame(raw)
                h=frame.header
                self.assertEqual(wire.make_frame(h.kind,h.role,h.sid,h.sequence,frame.payload),raw)
                with self.assertRaises(wire.ProtocolError):
                    wire.parse_frame(raw+b'\0')


if __name__ == '__main__':
    unittest.main()
