"""Acceptance, canonicality and state-oracle regressions without Atheris."""
from __future__ import annotations

import random
import unittest
from unittest.mock import patch

from fuzzing import targets
from protocol_v01 import records, wire


class TargetTests(unittest.TestCase):
    def test_corpus_is_public_deterministic_and_all_seeds_pass(self):
        first, second = targets.seed_inputs(), targets.seed_inputs()
        self.assertEqual(first, second)
        self.assertEqual(set(first), {"frame", "hello", "kem_pk", "kem_ct", "records"})
        for name, seeds in first.items():
            self.assertTrue(seeds, name)
            for index, seed in enumerate(seeds):
                with self.subTest(target=name, seed=index):
                    self.assertIs(type(seed), bytes)
                    targets.TARGETS[name](seed)

    def test_frame_expectations_are_supplied_by_selector_not_candidate(self):
        for selector, raw in enumerate(targets._FRAMES):
            with self.subTest(selector=selector):
                expected = {"kind": raw[6], "role": raw[7], "sid": raw[12:28],
                            "sequence": int.from_bytes(raw[28:36], "big")}
                wrong_role = raw[:7] + bytes([1 - raw[7]]) + raw[8:]
                self.assertFalse(targets.oracle.frame_oracle(wrong_role, expected))
                targets.fuzz_frame(bytes([selector]) + wrong_role)
                targets.fuzz_frame(bytes([selector]) + raw)

    def test_acceptance_oracles_detect_false_accepts_and_false_rejects(self):
        frame_seed = targets.seed_inputs()["frame"][0]
        good_frame = wire.parse_frame(frame_seed[1:])
        with patch.object(wire, "parse_frame", return_value=good_frame):
            with self.assertRaisesRegex(AssertionError, "reference-invalid frame accepted"):
                targets.fuzz_frame(frame_seed[:1] + b"invalid")
        with patch.object(wire, "parse_frame", side_effect=wire.ProtocolError("regression")):
            with self.assertRaisesRegex(AssertionError, "reference-valid frame rejected"):
                targets.fuzz_frame(frame_seed)
        good_hello = targets.handshake.parse_client_hello(targets._HELLO)
        with patch.object(targets.handshake, "parse_client_hello", return_value=good_hello):
            with self.assertRaisesRegex(AssertionError, "reference-invalid ClientHello accepted"):
                targets.fuzz_hello(b"invalid")

    def test_kem_positive_negative_and_canonicality_oracles(self):
        for name, raw, offset, decode_name, encode_name in (
            ("kem_pk", targets._PK, 40, "deserialize_public_key_compact", "serialize_public_key_compact"),
            ("kem_ct", targets._CT, 8, "deserialize_ciphertext_compact", "serialize_ciphertext_compact"),
        ):
            with self.subTest(target=name):
                kind = "pk" if name == "kem_pk" else "ct"
                invalid = targets.oracle.replace_coefficient(raw, offset, 0, 3329)
                self.assertTrue(targets.oracle.kem_oracle(raw, kind))
                self.assertFalse(targets.oracle.kem_oracle(invalid, kind))
                targets.TARGETS[name](raw)
                targets.TARGETS[name](invalid)
                valid_object = getattr(targets._KEM, decode_name)(raw)
                with patch.object(targets.KEM_MODULE.SpiralKEM, decode_name, return_value=valid_object):
                    with self.assertRaisesRegex(AssertionError, "reference-invalid KEM encoding accepted"):
                        targets.TARGETS[name](invalid)
                with patch.object(targets.KEM_MODULE.SpiralKEM, encode_name, return_value=b"wrong"):
                    with self.assertRaisesRegex(AssertionError, "not byte-canonical"):
                        targets.TARGETS[name](raw)

    def test_unexpected_exceptions_are_not_swallowed(self):
        with patch.object(wire, "parse_frame", side_effect=RuntimeError("unexpected")):
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                targets.fuzz_frame(b"invalid")
        with patch.object(targets.KEM_MODULE.SpiralKEM, "deserialize_public_key_compact",
                          side_effect=RuntimeError("unexpected")):
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                targets.fuzz_kem_pk(targets._PK)
        c = targets._command
        with patch.object(records.RecordState, "decode", side_effect=RuntimeError("unexpected")):
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                targets.fuzz_records(c(0, payload=b"x") + c(2, role=1))

    def test_record_oracle_detects_valid_path_regressions(self):
        c = targets._command
        program = c(0, payload=b"expected") + c(2, role=1)
        with patch.object(records.RecordState, "encode_data", side_effect=wire.ProtocolError("broken")):
            with self.assertRaisesRegex(AssertionError, "valid record operation rejected"):
                targets.fuzz_records(program)
        with patch.object(records.RecordState, "decode", return_value=(16, b"different")):
            with self.assertRaisesRegex(AssertionError, "wrong or out-of-order plaintext delivered"):
                targets.fuzz_records(program)

    def test_record_oracle_checks_terminal_key_reference_release(self):
        original = records.RecordState.abort

        def retain_reference(state):
            original(state)
            state._send_key = b"public-test-key-reference"

        with patch.object(records.RecordState, "abort", retain_reference):
            with self.assertRaisesRegex(AssertionError, "retains owned key references"):
                targets.fuzz_records(targets._command(7))

    def test_record_oracle_checks_sequence_reservation(self):
        original = records.RecordState.encode_data

        def roll_back_sequence(state, plaintext):
            raw = original(state, plaintext)
            state.send_sequence -= 1
            return raw

        with patch.object(records.RecordState, "encode_data", roll_back_sequence):
            with self.assertRaises(AssertionError):
                targets.fuzz_records(targets._command(0, payload=b"x"))

    def test_record_commands_are_bounded_and_trailing_bytes_ignored(self):
        c = targets._command
        commands = list(targets._commands(c(10) * 1000))
        self.assertEqual(len(commands), targets.MAX_COMMANDS)
        self.assertEqual(commands, list(targets._commands(c(10) * targets.MAX_COMMANDS)))
        targets.fuzz_records(c(10) * targets.MAX_COMMANDS + c(9))

    def test_arbitrary_small_inputs_and_structured_record_programs(self):
        rng = random.Random(2026110701)
        for target in targets.TARGETS.values():
            for size in (0, 1, 2, 3, 39, 40, 75, 255, 1024):
                target(rng.randbytes(size))
        for _ in range(400):
            program = b"".join(targets._command(rng.randrange(16), rng.randrange(256),
                                                  rng.randbytes(rng.randrange(12)), rng.randrange(2))
                               for _ in range(rng.randrange(1, 33)))
            targets.fuzz_records(program)


if __name__ == "__main__":
    unittest.main()
