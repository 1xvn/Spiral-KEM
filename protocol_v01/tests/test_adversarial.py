"""Deterministic adversarial regression corpus for the normal protocol entry points."""

from dataclasses import replace
import json
from pathlib import Path
import random
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol_v01 import handshake as hs, wire
from protocol_v01.records import RecordState
from protocol_v01.tls import TLSTransport
from test_core import ScriptedTransport


class AdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads(
            (Path(__file__).parent / "fixtures/test_vectors_v0.1.json").read_text()
        )
        cls.frames = {k: bytes.fromhex(v) for k, v in cls.vector["frames"].items()}
        e = cls.vector["expected"]
        cls.keys = SimpleNamespace(
            sid=bytes.fromhex(cls.vector["public"]["session_id"]),
            c_key=bytes.fromhex(e["client_data_key"]),
            s_key=bytes.fromhex(e["server_data_key"]),
            c_prefix=bytes.fromhex(e["client_nonce_prefix"]),
            s_prefix=bytes.fromhex(e["server_nonce_prefix"]),
        )
        cls.binding = bytes.fromhex(cls.vector["inputs"]["synthetic_exporter"])
        cls.auth = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(cls.vector["inputs"]["server_auth_seed"])
        )

    def test_every_truncated_frame_rejected(self):
        for frame_name, raw in self.frames.items():
            for size in range(len(raw)):
                with self.subTest(frame=frame_name, size=size):
                    with self.assertRaises(wire.ProtocolError):
                        wire.parse_frame(raw[:size])

    def test_all_header_bits_rejected_under_connection_expectations(self):
        raw = self.frames["client_key"]
        for byte in range(40):
            for bit in range(8):
                bad = bytearray(raw)
                bad[byte] ^= 1 << bit
                with self.subTest(byte=byte, bit=bit):
                    with self.assertRaises(wire.ProtocolError):
                        wire.parse_frame(
                            bytes(bad), kind=3, role=0, sid=self.keys.sid, sequence=1
                        )

    def test_all_data_frame_bits_fail_without_plaintext_release(self):
        for name, role in [("client_data", 1), ("server_data", 0)]:
            raw = self.frames[name]
            for byte in range(len(raw)):
                for bit in range(8):
                    bad = bytearray(raw)
                    bad[byte] ^= 1 << bit
                    state = RecordState(self.keys, role)
                    with self.subTest(frame=name, byte=byte, bit=bit):
                        with self.assertRaises(wire.ProtocolError):
                            state.decode(bytes(bad))
                        self.assertTrue(state.failed)
                        self.assertIsNone(state._receive_key)
                        self.assertEqual(state.receive_sequence, 0)

    def test_seeded_frame_mutation_corpus_is_canonical_if_accepted(self):
        rng = random.Random(20261106)
        corpus = list(self.frames.values())
        for case in range(4096):
            data = bytearray(rng.choice(corpus))
            operation = case % 5
            if operation == 0:
                for _ in range(rng.randrange(1, 9)):
                    data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
            elif operation == 1:
                del data[rng.randrange(len(data)) :]
            elif operation == 2:
                data.extend(rng.randbytes(rng.randrange(1, 129)))
            elif operation == 3:
                data[36:40] = rng.getrandbits(32).to_bytes(4, "big")
            else:
                data = bytearray(rng.randbytes(rng.randrange(0, 16441)))
            try:
                parsed = wire.parse_frame(bytes(data))
            except wire.ProtocolError:
                continue
            self.assertEqual(
                wire.make_frame(
                    parsed.header.kind,
                    parsed.header.role,
                    parsed.header.sid,
                    parsed.header.sequence,
                    parsed.payload,
                ),
                bytes(data),
            )

    def test_length_bomb_rejected_before_payload_read(self):
        import threading

        raw = bytearray(self.frames["client_key"][:40])
        for length in (0, 1191, 1193, 16441, 1 << 20, 0x7FFFFFFF, 0xFFFFFFFF):
            raw[36:40] = length.to_bytes(4, "big")
            transport = TLSTransport.__new__(TLSTransport)
            transport.read_lock = threading.Lock()
            transport.closed = False
            transport.claimed = False
            transport.close = lambda: setattr(transport, "closed", True)
            seen = []

            def read(size, deadline):
                seen.append(size)
                if len(seen) > 1:
                    self.fail("invalid header reached payload read")
                return bytes(raw)

            transport._read = read
            with self.assertRaises(wire.ProtocolError):
                transport.recv(
                    kind=3, role=0, sid=self.keys.sid, sequence=1, deadline=10**20
                )
            self.assertEqual(seen, [40])
            self.assertTrue(transport.closed)

    def test_clienthello_grammar_mutations_rejected(self):
        payload = self.frames["client_hello"][40:]
        for offset in (64, 67):
            for value in range(256):
                if value == 1:
                    continue
                edited = bytearray(payload)
                edited[offset] = value
                with self.subTest(offset=offset, value=value):
                    with self.assertRaises(wire.ProtocolError):
                        hs.parse_client_hello(bytes(edited))
        for extra in (b"\0", bytes(1024), bytes(1 << 20)):
            with self.assertRaises(wire.ProtocolError):
                hs.parse_client_hello(payload + extra)

    def server_case(self, raw):
        transport = ScriptedTransport([self.frames["client_hello"], raw], self.binding)
        inputs = self.vector["inputs"]
        seeds = inputs["kem_test_seeds"]
        randoms = (
            [self.keys.sid]
            + [bytes.fromhex(seeds[k]) for k in ("matrix", "secret", "fallback")]
            + [bytes.fromhex(inputs["server_random"])]
        )
        with patch.object(hs.secrets, "token_bytes", side_effect=randoms):
            with self.assertRaises(wire.ProtocolError):
                hs.server_handshake(
                    transport, inputs["server_name"], inputs["service"], self.auth
                )
        self.assertTrue(transport.closed)
        self.assertTrue(transport.claimed)
        self.assertEqual(transport.decapsulation_count, 1)
        self.assertEqual(transport.sent, [self.frames["server_hello"]])
        self.assertNotIn(self.keys.sid, hs._LIVE_IDS)
        with self.assertRaises(wire.ProtocolError):
            hs.server_handshake(
                transport, inputs["server_name"], inputs["service"], self.auth
            )
        self.assertEqual(transport.decapsulation_count, 1)

    def test_finished_each_byte_tampering_has_no_server_finished(self):
        raw = self.frames["client_key"]
        for position in range(32):
            bad = bytearray(raw)
            bad[1200 + position] ^= 1
            self.server_case(bytes(bad))

    def test_chosen_canonical_ciphertexts_cannot_retry_key(self):
        kem = hs.load_kem().SpiralKEM()
        raw = self.frames["client_key"]
        ct = kem.deserialize_ciphertext_compact(raw[40:1200])
        for row in range(3):
            for position in (0, 127, 255):
                for delta in (1, 832):
                    polys = [list(p) for p in ct.u + (ct.v,)]
                    polys[row][position] = (polys[row][position] + delta) % 3329
                    changed = replace(
                        ct, u=tuple(tuple(p) for p in polys[:2]), v=tuple(polys[2])
                    )
                    self.server_case(
                        raw[:40]
                        + kem.serialize_ciphertext_compact(changed)
                        + raw[1200:]
                    )

    def test_duplicate_data_permanently_invalidates_receiver(self):
        state = RecordState(self.keys, 1)
        self.assertEqual(
            state.decode(self.frames["client_data"])[1], b"research request"
        )
        with self.assertRaises(wire.ProtocolError):
            state.decode(self.frames["client_data"])
        self.assertTrue(state.failed)
        self.assertIsNone(state._receive_key)
        with self.assertRaises(wire.ProtocolError):
            state.decode(self.frames["client_close"])

    def test_nonce_reservations_unique_under_parallel_encoding(self):
        from concurrent.futures import ThreadPoolExecutor

        state = RecordState(self.keys, 0)
        with ThreadPoolExecutor(max_workers=16) as pool:
            frames = list(
                pool.map(lambda i: state.encode_data(i.to_bytes(4, "big")), range(1024))
            )
        sequences = [wire.parse_frame(raw).header.sequence for raw in frames]
        self.assertEqual(sorted(sequences), list(range(1024)))
        self.assertEqual(state.send_sequence, 1024)
        self.assertEqual(
            len({self.keys.c_prefix + seq.to_bytes(8, "big") for seq in sequences}),
            1024,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
