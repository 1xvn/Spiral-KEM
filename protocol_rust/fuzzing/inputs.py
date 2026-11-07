"""Public seeds and independent stdlib-only Spiral v0.1 wire references.

The grammar comes from ``protocol_v01/SPEC_v0.1.md`` sections 3, 4.1 and 6.
Acceptance checks adapt the small ``frame_oracle`` and ``ch_oracle`` references
in ``protocol_v01/validation/fuzz_campaign.py`` without importing that module,
the Python protocol implementation, TLS, cryptography, or the Rust target.

Frame inputs are complete raw frames, with no fixture-selector prefix. Hello
inputs are ClientHello payloads, without the 40-byte frame header. These are
stateless syntax checks: payload authentication and connection state are outside
their scope. All fixture material used here is public synthetic test data.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
from struct import Struct


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "protocol_v01/tests/fixtures/test_vectors_v0.1.json"
TARGETS = ("frame", "hello")
MAX_LEN = {"frame": 16500, "hello": 512}

_HEADER = Struct(">4sHBBHH16sQI")
_SIZES = {1: (75, 418), 2: (940, 940), 3: (1192, 1192),
          4: (32, 32), 16: (17, 16400), 17: (17, 17)}
_HANDSHAKE = {1: (0, 0), 2: (1, 0), 3: (0, 1), 4: (1, 1)}
_DNS_LABEL = re.compile(r"[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?", re.ASCII)
_SERVICE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,63}", re.ASCII)


@dataclass(frozen=True)
class Frame:
    kind: int
    role: int
    sid: bytes
    sequence: int
    length: int
    payload: bytes


@dataclass(frozen=True)
class ClientHello:
    client_random: bytes
    binding: bytes
    versions: tuple[int, ...]
    suites: tuple[int, ...]
    name: str
    service: str


def parse_frame(raw: bytes) -> Frame:
    """Parse the fixed wire grammar or raise ValueError for an invalid input."""
    if type(raw) is not bytes or len(raw) < 40:
        raise ValueError("short frame or non-bytes input")
    magic, version, kind, role, suite, flags, sid, seq, length = _HEADER.unpack(raw[:40])
    if magic != b"SPK1" or version != 1 or flags:
        raise ValueError("header constant")
    if kind not in _SIZES or role not in (0, 1):
        raise ValueError("kind or role")
    if suite != (0 if kind == 1 else 0xF001):
        raise ValueError("suite")
    lower, upper = _SIZES[kind]
    if not lower <= length <= upper or length != len(raw) - 40:
        raise ValueError("inexact payload length")
    if kind in _HANDSHAKE:
        if (role, seq) != _HANDSHAKE[kind]:
            raise ValueError("handshake role or sequence")
    elif seq >= 2**20 or (kind == 16 and seq == 2**20 - 1):
        raise ValueError("record counter")
    if (kind == 1) != (sid == bytes(16)):
        raise ValueError("session identifier")
    return Frame(kind, role, sid, seq, length, raw[40:])


def parse_hello(raw: bytes) -> ClientHello:
    """Parse all original fields, including offers, without normalizing bytes."""
    if type(raw) is not bytes or not 75 <= len(raw) <= 418:
        raise ValueError("ClientHello size or non-bytes input")
    at = 64

    def read(count: int) -> bytes:
        nonlocal at
        end = at + count
        if end > len(raw):
            raise ValueError("truncated ClientHello field")
        value = raw[at:end]
        at = end
        return value

    offers = []
    for required in (1, 0xF001):
        count = read(1)[0]
        if not 1 <= count <= 8:
            raise ValueError("offer count")
        values = tuple(int.from_bytes(read(2), "big") for _ in range(count))
        if (values[0] == 0 or any(left >= right for left, right in zip(values, values[1:]))
                or required not in values):
            raise ValueError("offer ordering or missing required offer")
        offers.append(values)
    name_length = int.from_bytes(read(2), "big")
    if not 1 <= name_length <= 253:
        raise ValueError("DNS name size")
    try:
        name = read(name_length).decode("ascii")
        service_length = read(1)[0]
        if not 1 <= service_length <= 64:
            raise ValueError("service size")
        service = read(service_length).decode("ascii")
    except UnicodeError as exc:
        raise ValueError("non-ASCII identity") from exc
    if at != len(raw):
        raise ValueError("trailing ClientHello bytes")
    if any(not 1 <= len(label) <= 63 or _DNS_LABEL.fullmatch(label) is None
           for label in name.split(".")):
        raise ValueError("DNS label grammar")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal")
    if _SERVICE.fullmatch(service) is None:
        raise ValueError("service grammar")
    return ClientHello(raw[:32], raw[32:64], offers[0], offers[1], name, service)


def expected(target: str, data: bytes) -> dict:
    """Return the JSON-safe result expected from the Rust differential driver."""
    if target not in TARGETS:
        raise ValueError(f"unknown fuzz target: {target}")
    try:
        if target == "frame":
            frame = parse_frame(data)
            return {"accepted": True, "kind": frame.kind, "role": frame.role,
                    "sid": frame.sid.hex(), "sequence": frame.sequence,
                    "length": frame.length, "payload": frame.payload.hex()}
        hello = parse_hello(data)
        return {"accepted": True, "name": hello.name, "service": hello.service}
    except ValueError:
        return {"accepted": False}


def _frame(kind: int, role: int, sid: bytes, seq: int, payload: bytes) -> bytes:
    return _HEADER.pack(b"SPK1", 1, kind, role, 0 if kind == 1 else 0xF001,
                        0, sid, seq, len(payload)) + payload


def _hello(name: bytes = b"a.example", service: bytes = b"service", *,
           versions: tuple[int, ...] = (1,), suites: tuple[int, ...] = (0xF001,),
           prefix: bytes = bytes(range(64))) -> bytes:
    return (prefix + bytes([len(versions)])
            + b"".join(value.to_bytes(2, "big") for value in versions)
            + bytes([len(suites)])
            + b"".join(value.to_bytes(2, "big") for value in suites)
            + len(name).to_bytes(2, "big") + name + bytes([len(service)]) + service)


def _replace(raw: bytes, offset: int, value: bytes) -> bytes:
    return raw[:offset] + value + raw[offset + len(value):]


def seeds() -> dict[str, list[bytes]]:
    """Build deterministic boundary corpora from the public fixture and grammar."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    frames = {name: bytes.fromhex(value) for name, value in fixture["frames"].items()}
    sid = bytes.fromhex(fixture["public"]["session_id"])
    frame_seeds = list(frames.values())

    # Full-size DATA and the record counter reserved for CLOSE are reachable
    # without waiting for mutations to grow a short fixture by sixteen KiB.
    frame_seeds += [
        _frame(16, 0, sid, 0, bytes(16400)),
        _frame(16, 1, sid, 2**20 - 2, bytes(17)),
        _frame(17, 0, sid, 2**20 - 1, bytes(17)),
        _frame(1, 0, bytes(16), 0, bytes(75)),
        _frame(1, 0, bytes(16), 0, bytes(418)),
        b"", frames["client_hello"][:39], frames["client_hello"][:-1],
        frames["client_hello"] + b"\0",
    ]
    base = frames["client_data"]
    for offset, value in (
        (0, b"SPK0"), (4, b"\0\0"), (4, b"\0\2"), (6, b"\x12"),
        (7, b"\x02"), (8, b"\0\0"), (10, b"\0\1"), (12, bytes(16)),
        (28, (2**20 - 1).to_bytes(8, "big")),
        (28, (2**20).to_bytes(8, "big")),
        (28, (2**64 - 1).to_bytes(8, "big")),
        (36, (0).to_bytes(4, "big")), (36, (16401).to_bytes(4, "big")),
        (36, (2**32 - 1).to_bytes(4, "big")),
    ):
        frame_seeds.append(_replace(base, offset, value))
    for name in ("client_hello", "server_hello", "client_key", "server_finished"):
        frame = frames[name]
        frame_seeds += [_replace(frame, 7, bytes([1 - frame[7]])),
                        _replace(frame, 28, (2).to_bytes(8, "big"))]
    frame_seeds += [_frame(16, 0, sid, 0, bytes(16)),
                    _frame(16, 0, sid, 0, bytes(16401)),
                    _frame(17, 1, sid, 2**20, bytes(17))]

    max_name = b".".join([b"a" * 63] * 3 + [b"b" * 61])
    versions = tuple(range(1, 9))
    suites = (1, 2, 3, 4, 5, 6, 0xF001, 0xFFFF)
    hello0 = frames["client_hello"][40:]
    hello_seeds = [
        hello0, _hello(b"a", b"0"),
        _hello(max_name, b"s" * 64, versions=versions, suites=suites),
        _hello(b"xn--bcher-kva.example", b"test/path_1.0-svc"),
        _hello(b"1.2.3.999", b"a"),  # DNS-shaped, but not an IP literal.
        _hello(b"a" * 63, b"a"),
        _hello(versions=versions, suites=suites),
        _hello(prefix=bytes(64)),
        b"", hello0[:63], hello0[:64], hello0[:-1], hello0 + b"\0",
        _hello(max_name + b"c", b"a"),
        _hello(b"a" * 64, b"a"),
        _hello(b"a.example", b"s" * 65),
    ]
    for name in (b"", b"A.example", b"a..example", b"-a.example", b"a-.example",
                 b"a.example.", b".example", b"a_b.example", b"127.0.0.1",
                 b"::1", b"a\x80.example", b"a\0.example"):
        hello_seeds.append(_hello(name, b"a"))
    for service in (b"", b"UPPER", b"-a", b"a b", b"a\0", b"a\x80"):
        hello_seeds.append(_hello(b"a.example", service))
    for offers in ((), (0, 1), (1, 1), (2, 1), (2,), tuple(range(1, 10))):
        hello_seeds.append(_hello(versions=offers))
    for offers in ((), (0, 0xF001), (0xF001, 0xF001), (0xF001, 1), (1,),
                   tuple(range(1, 9)) + (0xF001,)):
        hello_seeds.append(_hello(suites=offers))
    # Truncation inside both counted offer lists and the two identity lengths.
    long_offers = _hello(versions=versions, suites=suites)
    hello_seeds += [long_offers[:at] for at in (65, 66, 80, 81, 82, 97, 98, 99)]
    return {"frame": list(dict.fromkeys(frame_seeds)),
            "hello": list(dict.fromkeys(hello_seeds))}
