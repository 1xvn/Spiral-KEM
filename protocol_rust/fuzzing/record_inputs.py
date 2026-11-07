"""Independent finite DATA/CLOSE half-state reference and public fuzz seeds.

Only test helpers import this module. It does not use the production Python
RecordState (whose combined endpoint/timer lifecycle differs from Rust Tx/Rx),
Rust code, TLS, or a third-party AEAD package. reference_aead is slow test-only
RFC 8439 code, checked against published vectors and the public Spiral fixture.
The byte grammar is documented in FUZZ_RECORDS.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from struct import Struct

from protocol_rust.fuzzing.inputs import parse_frame
from protocol_rust.fuzzing import reference_aead


TARGETS = ("record",)
MAX_LEN = {"record": 258}
MAX_RECORDS = 1 << 20
MAX_BYTES = (1 << 30) - 1
LENGTHS = (0, 1, 2, 31, 16383, 16384, 16385)
PUBLIC_KEY = bytes(range(32))
PUBLIC_PREFIX = bytes(range(0xA0, 0xA4))
PUBLIC_SID = bytes(range(0x10, 0x20))
SCENARIOS = ((0, 0), (MAX_RECORDS - 2, 0), (MAX_RECORDS - 1, 0),
             (MAX_RECORDS, 0), (0, MAX_BYTES - 1), (0, MAX_BYTES),
             (0, MAX_BYTES - 16383))
_HEADER = Struct(">4sHBBHH16sQI")
_OPERATIONS = ("data", "close", "deliver", "mutate", "craft", "raw")


def _pattern(length: int, first: int, increment: int) -> bytes:
    period = bytes((first + index * increment) % 256 for index in range(256))
    return (period * ((length + 255) // 256))[:length]


def _seal(kind: int, role: int, sequence: int, plaintext: bytes,
          sid: bytes = PUBLIC_SID) -> bytes:
    # Intentionally encode syntax-invalid records too. These independent AEAD
    # candidates exercise rejection after/before authentication as appropriate.
    header = _HEADER.pack(b"SPK1", 1, kind, role, 0xF001, 0, sid,
                          sequence, len(plaintext) + 16)
    nonce = PUBLIC_PREFIX + sequence.to_bytes(8, "big")
    return header + reference_aead.encrypt(PUBLIC_KEY, nonce, plaintext, header)


def _success(payload: bytes, *, kind: int | None = None) -> dict:
    result = {"ok": True, "length": len(payload), "sha256": sha256(payload).hexdigest()}
    if kind is not None:
        result["kind"] = kind
    return result


def _error(name: str) -> dict:
    return {"ok": False, "error": name}


@dataclass
class _State:
    sequence: int
    bytes: int
    closed: bool = False
    key_live: bool = True

    def snapshot(self) -> dict:
        return {"sequence": self.sequence, "bytes": self.bytes,
                "closed": self.closed, "key_live": self.key_live}


def _send_data(state: _State, role: int, plaintext: bytes) -> tuple[dict, bytes | None]:
    if state.closed or not state.key_live:
        return _error("Closed"), None
    if not 1 <= len(plaintext) <= 16384:
        state.key_live = False
        return _error("Input"), None
    if state.sequence >= MAX_RECORDS - 1 or state.bytes + len(plaintext) > MAX_BYTES:
        return _error("Limit2"), None
    wire = _seal(16, role, state.sequence, plaintext)
    state.sequence += 1
    state.bytes += len(plaintext)
    return _success(wire), wire


def _send_close(state: _State, role: int, reason: int) -> tuple[dict, bytes | None]:
    # The low-level API validates the reason before checking usability.
    if reason > 2:
        return _error("Input"), None
    if state.closed or not state.key_live:
        return _error("Closed"), None
    if state.sequence >= MAX_RECORDS:
        state.key_live = False
        return _error("Input"), None
    wire = _seal(17, role, state.sequence, bytes([reason]))
    state.sequence += 1
    state.closed = True
    state.key_live = False
    return _success(wire), wire


def _receive(state: _State, sender_role: int, wire: bytes) -> dict:
    def reject(error: str) -> dict:
        state.closed = True
        state.key_live = False
        return _error(error)

    if state.closed or not state.key_live:
        return reject("Closed")
    try:
        frame = parse_frame(wire)
    except ValueError:
        return reject("Input")
    if (frame.kind not in (16, 17) or frame.role != sender_role
            or frame.sid != PUBLIC_SID or frame.sequence != state.sequence):
        return reject("Input")
    plaintext_length = len(frame.payload) - 16
    if frame.kind == 16 and state.bytes + plaintext_length > MAX_BYTES:
        return reject("Limit2")
    nonce = PUBLIC_PREFIX + frame.sequence.to_bytes(8, "big")
    try:
        plaintext = reference_aead.decrypt(PUBLIC_KEY, nonce, frame.payload, wire[:40])
    except ValueError:
        return reject("Authentication")
    if frame.kind == 17 and (len(plaintext) != 1 or plaintext[0] > 2):
        return reject("Input")
    state.sequence += 1
    if frame.kind == 16:
        state.bytes += len(plaintext)
    else:
        state.closed = True
        state.key_live = False
    return _success(plaintext, kind=frame.kind)


def _stored(stored: list[bytes], index: int) -> bytes:
    return stored[index % len(stored)] if stored else b""


def _mutate(wire: bytes, mutation: int, choice: int) -> bytes:
    mutation %= 8
    if mutation == 2:
        return wire + bytes([choice])
    if not wire:
        return wire
    if mutation == 1:
        return wire[:choice % len(wire)]
    changed = bytearray(wire)
    offset = (choice % len(wire), 0, 0, 7, 12, len(wire) - 1, 35, 6)[mutation]
    changed[offset] ^= 1
    return bytes(changed)


def _craft(state: _State, sender_role: int, a: int, b: int, c: int) -> bytes:
    kind = 17 if a & 1 else 16
    sequences = (state.sequence, state.sequence + 1,
                 max(state.sequence - 1, 0), MAX_RECORDS - 1)
    sequence = sequences[(a >> 1) % 4]
    role = sender_role ^ ((a >> 3) & 1)
    sid = bytes([PUBLIC_SID[0] ^ 1]) + PUBLIC_SID[1:] if a & 16 else PUBLIC_SID
    plaintext = bytes([c]) if kind == 17 else _pattern(LENGTHS[b % 7], c, 1)
    wire = _seal(kind, role, sequence, plaintext, sid)
    return wire[:-1] + bytes([wire[-1] ^ 1]) if a & 32 else wire


def expected(target: str, data: bytes) -> dict:
    """Compute the complete finite trace expected from native Rust replay."""
    if target != "record":
        raise ValueError("unknown record fuzz target: " + str(target))
    if type(data) is not bytes:
        raise ValueError("record fuzz input must be bytes")
    data = data[:MAX_LEN["record"]]
    scenario = data[0] % len(SCENARIOS) if data else 0
    role = data[1] & 1 if len(data) >= 2 else 0
    tx = _State(*SCENARIOS[scenario])
    rx = _State(*SCENARIOS[scenario])
    result = {"accepted": True, "scenario": scenario, "role": role,
              "initial": {"tx": tx.snapshot(), "rx": rx.snapshot()}, "steps": []}
    stored = []
    for at in range(2, len(data) - 3, 4):
        opcode, a, b, c = data[at:at + 4]
        opcode %= len(_OPERATIONS)
        if opcode == 0:
            answer, wire = _send_data(tx, role, _pattern(LENGTHS[a % 7], b, c))
            if wire is not None:
                stored.append(wire)
        elif opcode == 1:
            answer, wire = _send_close(tx, role, a)
            if wire is not None:
                stored.append(wire)
        else:
            if opcode == 2:
                wire = _stored(stored, a)
            elif opcode == 3:
                wire = _mutate(_stored(stored, a), b, c)
            elif opcode == 4:
                wire = _craft(rx, role, a, b, c)
            else:
                wire = bytes([a, b, c]) * (c % 17)
            answer = _receive(rx, role, wire)
        result["accepted"] = result["accepted"] and answer["ok"]
        result["steps"].append({"op": _OPERATIONS[opcode], "result": answer,
                                "tx": tx.snapshot(), "rx": rx.snapshot()})
    return result


def _program(scenario: int, role: int, *commands: tuple[int, int, int, int]) -> bytes:
    return bytes([scenario, role]) + b"".join(bytes(command) for command in commands)


def seeds() -> dict[str, list[bytes]]:
    """Exercise positive crypto, poison persistence, counters, sizes, and closure."""
    cases = [b"", b"\0", b"\0\0\xff", bytes(258)]
    for scenario in range(len(SCENARIOS)):
        for role in (0, 1):
            cases += [
                _program(scenario, role),
                _program(scenario, role, (0, 1, 42, 1), (2, 0, 0, 0),
                         (1, 0, 0, 0), (2, 1, 0, 0)),
                _program(scenario, role, (0, 1, 1, 1), (0, 1, 2, 1),
                         (2, 1, 0, 0), (2, 0, 0, 0)),
                _program(scenario, role, (0, 1, 0, 0), (2, 0, 0, 0),
                         (2, 0, 0, 0), (4, 0, 1, 0)),
                _program(scenario, role, (1, 2, 0, 0), (2, 0, 0, 0),
                         (0, 1, 0, 0), (1, 0, 0, 0), (2, 0, 0, 0)),
                _program(scenario, role, (1, 3, 0, 0), (0, 1, 7, 3),
                         (1, 0, 0, 0)),
            ]
            for length_index in range(len(LENGTHS)):
                cases += [
                    _program(scenario, role, (0, length_index, 23, 13),
                             (2, 0, 0, 0), (1, 1, 0, 0)),
                    _program(scenario, role, (4, 0, length_index, 11),
                             (4, 1, 0, 0)),
                ]
    for role in (0, 1):
        for mutation in range(8):
            for offset in (0, 7, 12, 35, 39, 40, 56, 255):
                cases.append(_program(0, role, (0, 3, 90, 1),
                    (3, 0, mutation, offset), (2, 0, 0, 0)))
        for selector in range(64):
            cases.append(_program(0, role, (4, selector, 1, selector % 5),
                                   (4, 0, 1, 1)))
        for size in range(17):
            cases.append(_program(0, role, (5, 0x53, 0x50, size), (4, 0, 1, 0)))
        # Fully populated positive paths and maximum plaintexts are seeded;
        # mutations need not first discover long successful histories.
        cases += [
            _program(0, role, *((0, 1, index, 1) if index % 2 == 0
                                else (2, index // 2, 0, 0) for index in range(64))),
            _program(0, role, (0, 5, 255, 1), (2, 0, 0, 0),
                     (1, 0, 0, 0), (2, 1, 0, 0)),
        ]
    return {"record": list(dict.fromkeys(cases))}
