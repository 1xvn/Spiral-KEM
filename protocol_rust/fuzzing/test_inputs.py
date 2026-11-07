"""Tests for public fuzz inputs and the independent stdlib wire references."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from protocol_rust.fuzzing import inputs


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "protocol_v01/tests/fixtures/test_vectors_v0.1.json"


def frame_bytes(kind=16, role=0, seq=0, payload=b"p" * 17, *, sid=b"s" * 16,
                magic=b"SPK1", version=1, suite=0xF001, flags=0, length=None):
    """Pack test inputs without calling the reference under test."""
    if length is None:
        length = len(payload)
    return (struct.pack(">4sHBBHH16sQI", magic, version, kind, role, suite, flags,
                        sid, seq, length) + payload)


def hello_bytes(name=b"a.example", service=b"svc", *, versions=(1,),
                suites=(0xF001,), prefix=bytes(range(64))):
    return (prefix + bytes([len(versions)])
            + b"".join(struct.pack(">H", value) for value in versions)
            + bytes([len(suites)])
            + b"".join(struct.pack(">H", value) for value in suites)
            + struct.pack(">H", len(name)) + name + bytes([len(service)]) + service)


class FrameReferenceTests(unittest.TestCase):
    def assert_accepted(self, raw):
        self.assertTrue(inputs.expected("frame", raw)["accepted"])
        parsed = inputs.parse_frame(raw)
        rebuilt = frame_bytes(parsed.kind, parsed.role, parsed.sequence, parsed.payload,
                              sid=parsed.sid, suite=0 if parsed.kind == 1 else 0xF001)
        self.assertEqual(rebuilt, raw)

    def assert_rejected(self, raw):
        self.assertEqual(inputs.expected("frame", raw), {"accepted": False})
        with self.assertRaises(ValueError):
            inputs.parse_frame(raw)

    def test_public_fixtures_and_result_fields(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        descriptions = {
            "client_hello": (1, 0, 0, 106), "server_hello": (2, 1, 0, 940),
            "client_key": (3, 0, 1, 1192), "server_finished": (4, 1, 1, 32),
            "client_data": (16, 0, 0, 32), "server_data": (16, 1, 0, 33),
            "client_close": (17, 0, 1, 17), "server_close": (17, 1, 1, 17),
        }
        for name, (kind, role, seq, length) in descriptions.items():
            with self.subTest(name=name):
                raw = bytes.fromhex(fixture["frames"][name])
                self.assert_accepted(raw)
                self.assertEqual(len(raw), fixture["lengths"][name])
                self.assertEqual(inputs.expected("frame", raw), {
                    "accepted": True, "kind": kind, "role": role, "sequence": seq,
                    "sid": "00" * 16 if kind == 1 else fixture["public"]["session_id"],
                    "length": length, "payload": raw[40:].hex(),
                })

    def test_payload_size_boundaries_for_every_kind(self):
        for kind, role, seq, lower, upper in (
            (1, 0, 0, 75, 418), (2, 1, 0, 940, 940), (3, 0, 1, 1192, 1192),
            (4, 1, 1, 32, 32), (16, 0, 0, 17, 16400), (17, 1, 0, 17, 17),
        ):
            for size in {lower - 1, lower, upper, upper + 1}:
                with self.subTest(kind=kind, size=size):
                    raw = frame_bytes(kind, role, seq, bytes(size),
                                      sid=bytes(16) if kind == 1 else b"s" * 16,
                                      suite=0 if kind == 1 else 0xF001)
                    if lower <= size <= upper:
                        self.assert_accepted(raw)
                    else:
                        self.assert_rejected(raw)

    def test_frame_does_not_interpret_hello_payload(self):
        payload = bytes(75)
        raw = frame_bytes(1, 0, 0, payload, sid=bytes(16), suite=0)
        self.assert_accepted(raw)
        self.assertFalse(inputs.expected("hello", payload)["accepted"])

    def test_constants_role_suite_and_session_identifier(self):
        for changes in ({"magic": b"SPK0"}, {"version": 0}, {"version": 2},
                        {"flags": 1}, {"flags": 0xFFFF}, {"kind": 0}, {"kind": 18},
                        {"role": 2}, {"suite": 0}, {"suite": 0xF002},
                        {"sid": bytes(16)}):
            with self.subTest(changes=changes):
                self.assert_rejected(frame_bytes(**changes))
        self.assert_rejected(frame_bytes(1, 0, 0, bytes(75), suite=0))
        self.assert_rejected(frame_bytes(1, 0, 0, bytes(75), sid=bytes(16)))
        self.assert_accepted(frame_bytes(role=1, sid=b"\0" * 15 + b"\1"))

    def test_handshake_role_and_sequence(self):
        for kind, role, seq, size in ((1, 0, 0, 75), (2, 1, 0, 940),
                                     (3, 0, 1, 1192), (4, 1, 1, 32)):
            options = {"sid": bytes(16) if kind == 1 else b"s" * 16,
                       "suite": 0 if kind == 1 else 0xF001}
            with self.subTest(kind=kind):
                self.assert_accepted(frame_bytes(kind, role, seq, bytes(size), **options))
                self.assert_rejected(frame_bytes(kind, 1 - role, seq, bytes(size), **options))
                self.assert_rejected(frame_bytes(kind, role, 1 - seq, bytes(size), **options))

    def test_record_counters_and_reserved_final_close(self):
        for role in (0, 1):
            for seq in (0, 1, 2**20 - 2, 2**20 - 1, 2**20, 2**64 - 1):
                for kind in (16, 17):
                    with self.subTest(role=role, seq=seq, kind=kind):
                        raw = frame_bytes(kind, role, seq)
                        if seq < 2**20 and (kind == 17 or seq < 2**20 - 1):
                            self.assert_accepted(raw)
                        else:
                            self.assert_rejected(raw)

    def test_exact_length_truncation_extension_and_length_bombs(self):
        raw = frame_bytes()
        for data in (b"", raw[:39], raw[:40], raw[:-1], raw + b"\0", raw + raw):
            with self.subTest(size=len(data)):
                self.assert_rejected(data)
        for length in (0, 16, 18, 16400, 16401, 2**31, 2**32 - 1):
            with self.subTest(length=length):
                self.assert_rejected(frame_bytes(length=length))


class HelloReferenceTests(unittest.TestCase):
    def assert_accepted(self, raw):
        self.assertTrue(inputs.expected("hello", raw)["accepted"])
        parsed = inputs.parse_hello(raw)
        rebuilt = hello_bytes(parsed.name.encode("ascii"), parsed.service.encode("ascii"),
                              versions=parsed.versions, suites=parsed.suites,
                              prefix=parsed.client_random + parsed.binding)
        self.assertEqual(rebuilt, raw, "parsed offers and identity must preserve original bytes")
        return parsed

    def assert_rejected(self, raw):
        self.assertEqual(inputs.expected("hello", raw), {"accepted": False})
        with self.assertRaises(ValueError):
            inputs.parse_hello(raw)

    def test_fixture_fields(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        raw = bytes.fromhex(fixture["frames"]["client_hello"])[40:]
        parsed = self.assert_accepted(raw)
        self.assertEqual(parsed.client_random.hex(), fixture["inputs"]["client_random"])
        self.assertEqual(parsed.binding.hex(), fixture["inputs"]["synthetic_exporter"])
        self.assertEqual(parsed.versions, (1,))
        self.assertEqual(parsed.suites, (0xF001,))
        self.assertEqual(inputs.expected("hello", raw), {
            "accepted": True, "name": fixture["inputs"]["server_name"],
            "service": fixture["inputs"]["service"],
        })

    def test_minimum_maximum_and_original_offer_lists(self):
        minimum = hello_bytes(b"a", b"a")
        self.assertEqual(len(minimum), 75)
        self.assert_accepted(minimum)
        max_name = b".".join((b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61))
        versions = (1, 2, 3, 4, 5, 6, 7, 65535)
        suites = (1, 2, 3, 4, 5, 6, 0xF001, 65535)
        maximum = hello_bytes(max_name, b"s" * 64, versions=versions, suites=suites,
                              prefix=bytes(reversed(range(64))))
        self.assertEqual(len(maximum), 418)
        parsed = self.assert_accepted(maximum)
        self.assertEqual(parsed.versions, versions)
        self.assertEqual(parsed.suites, suites)
        self.assertEqual(parsed.client_random + parsed.binding, bytes(reversed(range(64))))
        self.assert_rejected(minimum[:-1])
        self.assert_rejected(maximum + b"\0")
        self.assert_rejected(hello_bytes(max_name + b"d", b"s" * 64,
                                         versions=versions, suites=suites))

    def test_sorted_nonzero_required_offer_lists(self):
        for field, invalid_lists in (
            ("versions", ((), (0, 1), (1, 1), (2, 1), (2,), tuple(range(1, 10)))),
            ("suites", ((), (0, 0xF001), (0xF001, 0xF001), (0xF001, 1),
                        (1,), tuple(range(1, 9)) + (0xF001,))),
        ):
            for offers in invalid_lists:
                with self.subTest(field=field, offers=offers):
                    self.assert_rejected(hello_bytes(**{field: offers}))
        self.assert_accepted(hello_bytes(versions=(1, 65535), suites=(1, 0xF001, 65535)))

    def test_dns_label_identity_boundaries(self):
        for name in (b"a", b"123", b"a-b.example", b"xn--bcher-kva.example",
                     b"a" * 63, b"1.2.3.999"):
            with self.subTest(name=name):
                self.assert_accepted(hello_bytes(name))
        for name in (b"", b"A.example", b"a..example", b"-a.example", b"a-.example",
                     b".example", b"a.example.", b"a_b.example", b"a" * 64,
                     b"127.0.0.1", b"0.0.0.0", b"::1", b"a\0.example", b"a\x80.example"):
            with self.subTest(name=name):
                self.assert_rejected(hello_bytes(name))
        name253 = b".".join([b"a" * 63] * 3 + [b"a" * 61])
        self.assert_accepted(hello_bytes(name253))
        self.assert_rejected(hello_bytes(name253 + b"a"))

    def test_service_identity_boundaries(self):
        for service in (b"0", b"a", b"a._/-", b"test/path_1.0-svc", b"a" * 64):
            with self.subTest(service=service):
                self.assert_accepted(hello_bytes(service=service))
        for service in (b"", b"A", b"_a", b"-a", b"/a", b".a", b"a b", b"a\0",
                        b"a\x80", b"a" * 65):
            with self.subTest(service=service):
                self.assert_rejected(hello_bytes(service=service))

    def test_all_truncations_lengths_and_trailing_bytes(self):
        raw = hello_bytes(versions=(1, 2, 65535), suites=(1, 0xF001, 65535))
        for length in range(len(raw)):
            with self.subTest(length=length):
                self.assert_rejected(raw[:length])
        self.assert_rejected(raw + b"\0")
        # At offset 78, the V16 name length follows two three-entry lists.
        for length in (0, 1, 253, 254, 65535):
            with self.subTest(declared_name_length=length):
                self.assert_rejected(raw[:78] + length.to_bytes(2, "big") + raw[80:])
        base = hello_bytes()
        for count in (0, 9, 255):
            self.assert_rejected(base[:64] + bytes([count]) + base[65:])
            self.assert_rejected(base[:67] + bytes([count]) + base[68:])
        # A long service length cannot read beyond the end of an otherwise valid payload.
        self.assert_rejected(base[:-4] + b"\xff" + base[-3:])


class CorpusAndIsolationTests(unittest.TestCase):
    def test_seed_corpus_has_valid_invalid_and_maximum_inputs(self):
        corpora = inputs.seeds()
        self.assertEqual(tuple(corpora), inputs.TARGETS)
        self.assertEqual(corpora, inputs.seeds())
        for target, seeds in corpora.items():
            with self.subTest(target=target):
                self.assertTrue(seeds)
                self.assertEqual(len(seeds), len(set(seeds)))
                self.assertTrue(all(type(raw) is bytes for raw in seeds))
                self.assertLessEqual(max(map(len, seeds)), inputs.MAX_LEN[target])
                self.assertTrue(any(inputs.expected(target, raw)["accepted"] for raw in seeds))
                self.assertTrue(any(not inputs.expected(target, raw)["accepted"] for raw in seeds))
        self.assertTrue(any(len(raw) == 16440 and inputs.expected("frame", raw)["accepted"]
                            for raw in corpora["frame"]))
        self.assertTrue(any(len(raw) == 418 and inputs.expected("hello", raw)["accepted"]
                            for raw in corpora["hello"]))

    def test_nonbytes_rejected_and_unknown_target_reported(self):
        for target in inputs.TARGETS:
            for value in (None, bytearray(hello_bytes()), memoryview(hello_bytes()), "bad", 1):
                with self.subTest(target=target, kind=type(value).__name__):
                    self.assertEqual(inputs.expected(target, value), {"accepted": False})
        with self.assertRaisesRegex(ValueError, "unknown fuzz target"):
            inputs.expected("records", b"")

    def test_root_resolution_and_stdlib_only_from_unrelated_directory(self):
        self.assertEqual(inputs.ROOT, ROOT)
        self.assertEqual(inputs.FIXTURE, FIXTURE)
        # Isolated Python disables PYTHONPATH and site-packages. Running from an
        # unrelated directory also catches a fixture path dependent on the cwd.
        script = """
import json, runpy, sys
namespace = runpy.run_path(sys.argv[1])
corpora = namespace['seeds']()
assert all(corpora.values())
for name in sys.modules:
    assert not name.startswith(('protocol_v01', 'cryptography', 'OpenSSL', 'ssl', '_ssl'))
print(json.dumps({target: len(values) for target, values in corpora.items()}))
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
                                     str(Path(inputs.__file__).resolve())],
                                    cwd=directory, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(count > 0 for count in json.loads(result.stdout).values()))


if __name__ == "__main__":
    unittest.main()
