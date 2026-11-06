"""Record state tests use public synthetic keys, never service secrets."""
import concurrent.futures
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from protocol_v01 import records
from protocol_v01.records import RecordLimit, RecordState
from protocol_v01.wire import ProtocolError, make_header, parse_frame


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.keys = SimpleNamespace(sid=b'S' * 16, c_key=b'C' * 32, s_key=b'D' * 32,
                                    c_prefix=b'CPFX', s_prefix=b'SPFX', transcript_hash=b'T' * 32)
        self.client, self.server = self.pair()

    def pair(self):
        return (RecordState(self.keys, 0, clock=self.clock),
                RecordState(self.keys, 1, clock=self.clock))

    def raw(self, *, kind=records.DATA, sequence=0, plaintext=b'x', role=0):
        key = self.keys.c_key if role == 0 else self.keys.s_key
        prefix = self.keys.c_prefix if role == 0 else self.keys.s_prefix
        head = make_header(kind, role, self.keys.sid, sequence, len(plaintext) + 16)
        payload = ChaCha20Poly1305(key).encrypt(prefix + sequence.to_bytes(8, 'big'), plaintext, head)
        return head + payload

    def test_supplied_record_vectors_match_both_roles_byte_for_byte(self):
        vectors = json.loads((Path(__file__).parent / 'fixtures' / 'test_vectors_v0.1.json').read_text())
        expected = vectors['expected']
        keys = SimpleNamespace(
            sid=bytes.fromhex(vectors['public']['session_id']),
            c_key=bytes.fromhex(expected['client_data_key']),
            s_key=bytes.fromhex(expected['server_data_key']),
            c_prefix=bytes.fromhex(expected['client_nonce_prefix']),
            s_prefix=bytes.fromhex(expected['server_nonce_prefix']),
            transcript_hash=bytes.fromhex(expected['h2']))
        client, server = RecordState(keys, 0, clock=self.clock), RecordState(keys, 1, clock=self.clock)
        for sender, receiver, name, kind in (
            (client, server, 'client_data', records.DATA),
            (server, client, 'server_data', records.DATA),
            (client, server, 'client_close', records.CLOSE),
            (server, client, 'server_close', records.CLOSE),
        ):
            plaintext = bytes.fromhex(vectors['plaintexts'][name])
            raw = sender.encode_data(plaintext) if kind == records.DATA else sender.encode_close(plaintext[0])
            self.assertEqual(raw, bytes.fromhex(vectors['frames'][name]))
            self.assertEqual(receiver.decode(raw), (kind, plaintext))
        self.assertTrue(client.closed and server.closed)

    def test_bidirectional_data_and_authenticated_close(self):
        self.assertEqual(self.server.decode(self.client.encode_data(b'request')), (records.DATA, b'request'))
        self.assertEqual(self.client.decode(self.server.encode_data(b'response')), (records.DATA, b'response'))
        self.assertEqual(self.server.decode(self.client.encode_close()), (records.CLOSE, b'\0'))
        self.assertEqual(self.client.decode(self.server.encode_close()), (records.CLOSE, b'\0'))
        for state in (self.client, self.server):
            self.assertTrue(state.closed)
            self.assertFalse(state.failed)
            self.assertIsNone(state._send_key)
            self.assertIsNone(state._receive_key)

    def test_local_close_allows_peer_inflight_data_until_peer_close(self):
        inflight = self.server.encode_data(b'already queued')
        close = self.client.encode_close()
        self.assertEqual(self.client.decode(inflight), (records.DATA, b'already queued'))
        self.server.decode(close)
        self.client.decode(self.server.encode_close())
        self.assertTrue(self.client.closed)

    def test_peer_close_blocks_new_local_data(self):
        self.client.decode(self.server.encode_close())
        with self.assertRaises(ProtocolError):
            self.client.encode_data(b'late')
        self.assertTrue(self.client.failed)

    def test_local_duplicate_close_is_fatal(self):
        self.client.encode_close()
        with self.assertRaises(ProtocolError):
            self.client.encode_close()
        self.assertTrue(self.client.failed)

    def test_peer_data_after_close_is_fatal(self):
        self.server.decode(self.client.encode_close())
        with self.assertRaises(ProtocolError):
            self.server.decode(self.raw(sequence=1, plaintext=b'late'))
        self.assertTrue(self.server.failed)

    def test_unknown_authenticated_close_reason_is_fatal(self):
        with self.assertRaises(ProtocolError):
            self.server.decode(self.raw(kind=records.CLOSE, plaintext=b'\x03'))
        self.assertTrue(self.server.failed)
        self.assertEqual(self.server.receive_sequence, 0)

    def test_empty_oversized_and_wrong_type_data_are_fatal(self):
        for value in (b'', b'x' * 16385, bytearray(b'x'), 'text', None):
            with self.subTest(value_type=type(value).__name__, length=len(value) if hasattr(value, '__len__') else None):
                state, _ = self.pair()
                with self.assertRaises(ProtocolError):
                    state.encode_data(value)
                self.assertTrue(state.failed)
                self.assertEqual(state.send_sequence, 0)

    def test_maximum_data_roundtrip(self):
        plain = b'x' * 16384
        self.assertEqual(self.server.decode(self.client.encode_data(plain)), (records.DATA, plain))

    def test_ciphertext_tag_header_identity_and_sequence_tampering(self):
        for offset in (7, 12, 35, 39, -1):
            with self.subTest(offset=offset):
                client, server = self.pair()
                raw = bytearray(client.encode_data(b'private'))
                raw[offset] ^= 1
                with self.assertRaises(ProtocolError):
                    server.decode(bytes(raw))
                self.assertTrue(server.failed)
                self.assertEqual(server.receive_sequence, 0)
                self.assertIsNone(server._receive_key)

    def test_reflection_skipped_sequence_and_nonrecord_frame(self):
        raw = self.client.encode_data(b'x')
        with self.assertRaises(ProtocolError):
            self.client.decode(raw)
        _, server = self.pair()
        with self.assertRaises(ProtocolError):
            server.decode(self.raw(sequence=1))
        _, server = self.pair()
        handshake = make_header(3, 0, self.keys.sid, 1, 1192) + bytes(1192)
        with self.assertRaises(ProtocolError):
            server.decode(handshake)

    def test_duplicate_decode_atomic_one_delivery_then_permanent_failure(self):
        raw = self.client.encode_data(b'once')
        def receive():
            try:
                return self.server.decode(raw)
            except ProtocolError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: receive(), range(2)))
        self.assertEqual(results.count((records.DATA, b'once')), 1)
        self.assertEqual(results.count(None), 1)
        self.assertEqual(self.server.receive_sequence, 1)
        self.assertTrue(self.server.failed)
        with self.assertRaises(ProtocolError):
            self.server.decode(self.raw(sequence=1))

    def test_concurrent_encodes_have_unique_reserved_sequences(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            frames = list(pool.map(lambda i: self.client.encode_data(str(i).encode()), range(32)))
        frames.sort(key=lambda raw: parse_frame(raw).header.sequence)
        self.assertEqual([parse_frame(raw).header.sequence for raw in frames], list(range(32)))
        messages = [self.server.decode(raw)[1] for raw in frames]
        self.assertEqual(set(messages), {str(i).encode() for i in range(32)})

    def test_encryption_exception_burns_sequence_and_cannot_retry(self):
        with patch.object(records, 'ChaCha20Poly1305') as engine:
            engine.return_value.encrypt.side_effect = RuntimeError('injected encryption failure')
            with self.assertRaises(ProtocolError):
                self.client.encode_data(b'x')
        self.assertEqual(self.client.send_sequence, 1)
        self.assertTrue(self.client.failed)
        self.assertIsNone(self.client._send_key)
        with self.assertRaises(ProtocolError):
            self.client.encode_data(b'x')

    def test_cancellation_during_encrypt_burns_sequence_and_drops_keys(self):
        class Cancelled(BaseException):
            pass
        with patch.object(records, 'ChaCha20Poly1305') as engine:
            engine.return_value.encrypt.side_effect = Cancelled()
            with self.assertRaises(Cancelled):
                self.client.encode_data(b'x')
        self.assertEqual(self.client.send_sequence, 1)
        self.assertTrue(self.client.failed)
        self.assertIsNone(self.client._send_key)

    def test_abort_after_failed_transport_has_no_nonce_rollback(self):
        self.client.encode_data(b'x')
        self.client.abort()
        with self.assertRaises(ProtocolError):
            self.client.encode_data(b'retry')
        self.assertEqual(self.client.send_sequence, 1)
        self.assertTrue(self.client.closed)

    def test_final_record_sequence_reserved_for_close(self):
        self.client.send_sequence = self.server.receive_sequence = records.MAX_RECORDS - 2
        self.server.decode(self.client.encode_data(b'last data'))
        with self.assertRaises(RecordLimit) as error:
            self.client.encode_data(b'one too many')
        self.assertEqual(error.exception.reason, 2)
        self.assertFalse(self.client.failed)
        self.server.decode(self.client.encode_close(2))
        self.assertEqual(self.client.send_sequence, records.MAX_RECORDS)
        self.assertTrue(self.server.receive_closed)

    def test_incoming_data_on_reserved_close_sequence_is_fatal(self):
        self.server.receive_sequence = records.MAX_RECORDS - 1
        with self.assertRaises(ProtocolError):
            raw = bytearray(self.raw(kind=records.CLOSE, sequence=records.MAX_RECORDS - 1, plaintext=b"\0"))
            raw[6] = records.DATA
            self.server.decode(bytes(raw))
        self.assertTrue(self.server.failed)

    def test_data_byte_budget_preserves_one_byte_close(self):
        self.client.send_data_bytes = self.server.receive_data_bytes = records.MAX_DATA_BYTES - 1
        self.server.decode(self.client.encode_data(b'x'))
        with self.assertRaises(RecordLimit) as error:
            self.client.encode_data(b'x')
        self.assertEqual(error.exception.reason, 2)
        self.server.decode(self.client.encode_close(2))
        self.assertEqual(self.client.send_data_bytes, records.MAX_DATA_BYTES)

    def test_receive_byte_budget_overrun_is_fatal(self):
        self.server.receive_data_bytes = records.MAX_DATA_BYTES
        with self.assertRaises(ProtocolError):
            self.server.decode(self.raw())
        self.assertTrue(self.server.failed)
        self.assertEqual(self.server.receive_sequence, 0)

    def test_idle_expiry_blocks_retries_but_allows_close_within_grace(self):
        raw = self.client.encode_data(b'late')
        self.clock.now = 60
        for _ in range(2):
            with self.assertRaises(RecordLimit) as error:
                self.server.decode(raw)
            self.assertEqual(error.exception.reason, 1)
        self.assertEqual(self.server.receive_sequence, 0)
        self.assertEqual(parse_frame(self.server.encode_close(1)).header.kind, records.CLOSE)
        self.clock.now = 62
        with self.assertRaises(ProtocolError):
            self.server.decode(self.client.encode_close())
        self.assertTrue(self.server.failed)

    def test_age_expiry_independent_of_recent_activity(self):
        self.clock.now = 599
        self.client._last_activity = 599
        self.server._last_activity = 599
        self.server.decode(self.client.encode_data(b'fresh'))
        self.clock.now = 600
        with self.assertRaises(RecordLimit) as error:
            self.client.encode_data(b'too old')
        self.assertEqual(error.exception.reason, 1)
        close = self.client.encode_close(1)
        self.server.decode(close)

    def test_close_grace_expiry_is_fatal(self):
        self.client.encode_close()
        peer_close = self.server.encode_close()
        self.clock.now = 2
        with self.assertRaises(ProtocolError):
            self.client.decode(peer_close)
        self.assertTrue(self.client.failed)

    def test_io_deadline_tracks_idle_age_and_closing_grace(self):
        self.assertEqual(self.client.io_deadline(), 60)
        self.clock.now = 20
        self.client.encode_data(b'activity')
        self.assertEqual(self.client.io_deadline(), 80)
        self.client._last_activity = 590
        self.assertEqual(self.client.io_deadline(), 600)
        self.clock.now = 21
        self.client.encode_close()
        self.assertEqual(self.client.io_deadline(), 23)
        self.client.decode(self.server.encode_close())
        self.assertTrue(self.client.closed)
        self.assertEqual(self.client.io_deadline(), 23)

    def test_wrong_wire_type_and_invalid_reason_are_fatal(self):
        with self.assertRaises(ProtocolError):
            self.server.decode(bytearray(self.raw()))
        for reason in (True, -1, 3, b'0'):
            client, _ = self.pair()
            with self.assertRaises(ProtocolError):
                client.encode_close(reason)
            self.assertTrue(client.failed)


if __name__ == '__main__':
    unittest.main()
