"""Deterministic, public-input oracles for the coverage-guided fuzz driver.

This module deliberately has no Atheris import. The driver instruments selected
production functions, leaving these independent acceptance/state oracles outside
the reported coverage. Fixture key material is public, synthetic test data.

Frame inputs are a fixture-selector byte followed by a candidate frame. Other
stateless targets consume the bytes directly. Record inputs are at most 32
commands: opcode/role byte, operand byte, payload-size byte, then that many bytes
of payload. Bit 4 chooses the endpoint; the low nibble chooses the command.
Missing command-header bytes are zero. No command uses randomness or wall time.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from protocol_v01 import handshake, records, wire
from protocol_v01.validation import fuzz_campaign as oracle


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = json.loads((_ROOT / "protocol_v01/tests/fixtures/test_vectors_v0.1.json").read_text())
_FRAMES = tuple(bytes.fromhex(value) for value in _FIXTURE["frames"].values())
_HELLO = bytes.fromhex(_FIXTURE["frames"]["client_hello"])[40:]
_PK = bytes.fromhex(_FIXTURE["public"]["kem_public_key_skw1"])
_CT = bytes.fromhex(_FIXTURE["public"]["kem_ciphertext_skw1"])
KEM_MODULE = handshake.load_kem()
_KEM = KEM_MODULE.SpiralKEM()
MAX_COMMANDS = 32


def fuzz_frame(data: bytes) -> None:
    base = _FRAMES[data[0] % len(_FRAMES)] if data else _FRAMES[0]
    raw = data[1:]
    expected = {"kind": base[6], "role": base[7], "sid": base[12:28],
                "sequence": int.from_bytes(base[28:36], "big")}
    valid = oracle.frame_oracle(raw, expected)
    try:
        frame = wire.parse_frame(raw, **expected)
    except wire.ProtocolError:
        assert not valid, "reference-valid frame rejected"
    else:
        assert valid, "reference-invalid frame accepted"
        assert frame.raw == raw and frame.header.raw + frame.payload == raw
        assert wire.make_frame(frame.header.kind, frame.header.role, frame.header.sid,
                               frame.header.sequence, frame.payload) == raw


def fuzz_hello(data: bytes) -> None:
    valid = oracle.ch_oracle(data)
    try:
        hello = handshake.parse_client_hello(data)
    except wire.ProtocolError:
        assert not valid, "reference-valid ClientHello rejected"
    else:
        assert valid, "reference-invalid ClientHello accepted"
        # Re-encode the parsed fields independently; accepted bytes are canonical.
        rebuilt = (hello.client_random + hello.binding
                   + bytes([len(hello.versions)])
                   + b"".join(v.to_bytes(2, "big") for v in hello.versions)
                   + bytes([len(hello.suites)])
                   + b"".join(v.to_bytes(2, "big") for v in hello.suites)
                   + len(hello.server_name).to_bytes(2, "big")
                   + hello.server_name.encode("ascii") + bytes([len(hello.service)])
                   + hello.service.encode("ascii"))
        assert rebuilt == data, "ClientHello parse changed the wire identity"


def _fuzz_kem(data: bytes, kind: str) -> None:
    valid = oracle.kem_oracle(data, kind)
    decode = (_KEM.deserialize_public_key_compact if kind == "pk"
              else _KEM.deserialize_ciphertext_compact)
    encode = (_KEM.serialize_public_key_compact if kind == "pk"
              else _KEM.serialize_ciphertext_compact)
    try:
        value = decode(data)
    except KEM_MODULE.InputValidationError:
        assert not valid, "reference-valid KEM encoding rejected"
    else:
        assert valid, "reference-invalid KEM encoding accepted"
        assert encode(value) == data, "accepted KEM encoding is not byte-canonical"


def fuzz_kem_pk(data: bytes) -> None:
    _fuzz_kem(data, "pk")


def fuzz_kem_ct(data: bytes) -> None:
    _fuzz_kem(data, "ct")


def _public_keys():
    expected = _FIXTURE["expected"]
    return SimpleNamespace(sid=bytes.fromhex(_FIXTURE["public"]["session_id"]),
                           c_key=bytes.fromhex(expected["client_data_key"]),
                           s_key=bytes.fromhex(expected["server_data_key"]),
                           c_prefix=bytes.fromhex(expected["client_nonce_prefix"]),
                           s_prefix=bytes.fromhex(expected["server_nonce_prefix"]))


class _Clock:
    now = 0.0

    def __call__(self):
        return self.now


@dataclass
class _Endpoint:
    """Spec state, with fixed protocol limits independent of runtime constants."""

    send: int = 0
    receive: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0
    sent_close: bool = False
    received_close: bool = False
    failed: bool = False
    last_activity: float = 0.0
    close_at: float | None = None
    expired: bool = False
    send_limited: bool = False

    @property
    def terminal(self):
        return self.failed or (self.sent_close and self.received_close)


@dataclass(frozen=True)
class _Packet:
    raw: bytes
    sender: int
    sequence: int
    kind: int
    plaintext: bytes
    authenticated: bool = True
    well_formed: bool = True


def _failure(model):
    model.failed = True
    return "fail"


def _available(model, now, closing=False):
    if model.terminal or (model.close_at is not None and now >= model.close_at + 2):
        return _failure(model)
    if not closing:
        if model.expired:
            return "limit1"
        if model.close_at is None and (now >= 600 or now - model.last_activity >= 60):
            model.expired, model.close_at = True, now
            return "limit1"
    return "ok"


def _send(model, now, kind, plaintext):
    outcome = _available(model, now, closing=kind == 17)
    if outcome != "ok":
        return outcome
    if kind == 16:
        if model.sent_close or model.received_close or not 1 <= len(plaintext) <= 16384:
            return _failure(model)
        if model.send_limited or model.send >= 2**20 - 1 or model.sent_bytes + len(plaintext) > 2**30 - 1:
            model.send_limited = True
            return "limit2"
    elif model.sent_close or plaintext[0] not in (0, 1, 2):
        return _failure(model)
    if model.send >= 2**20:
        return _failure(model)
    model.send += 1
    model.last_activity = now
    if kind == 16:
        model.sent_bytes += len(plaintext)
    else:
        model.sent_close = True
        if model.close_at is None:
            model.close_at = now
    return "ok"


def _receive(model, role, now, packet):
    if model.terminal or not packet.well_formed or packet.sender != 1 - role or packet.sequence != model.receive:
        return _failure(model)
    if model.received_close:
        return _failure(model)
    outcome = _available(model, now, closing=packet.kind == 17)
    if outcome != "ok":
        return outcome
    if (model.receive >= 2**20 or (packet.kind == 16 and model.receive >= 2**20 - 1)
            or (packet.kind == 16 and model.received_bytes + len(packet.plaintext) > 2**30 - 1)
            or not packet.authenticated
            or (packet.kind == 17 and packet.plaintext[0] not in (0, 1, 2))):
        return _failure(model)
    model.receive += 1
    model.last_activity = now
    if packet.kind == 16:
        model.received_bytes += len(packet.plaintext)
    else:
        model.received_close = True
        if model.close_at is None:
            model.close_at = now
    return "ok"


def _invoke(outcome, operation):
    try:
        result = operation()
    except records.RecordLimit as error:
        assert outcome == "limit" + str(error.reason), "unexpected record-limit outcome"
    except wire.ProtocolError:
        assert outcome == "fail", "valid record operation rejected"
    else:
        assert outcome == "ok", "invalid record operation accepted"
        return result
    return None


def _check_state(state, model):
    assert (state.send_sequence, state.receive_sequence) == (model.send, model.receive)
    assert (state.send_data_bytes, state.receive_data_bytes) == (model.sent_bytes, model.received_bytes)
    assert (state.send_closed, state.receive_closed, state.failed) == (
        model.sent_close, model.received_close, model.failed)
    assert state.closed == model.terminal, "terminal record state revived"
    owned = (state._send_key, state._receive_key, state._send_prefix, state._receive_prefix)
    if model.terminal:
        assert all(value is None for value in owned), "terminal state retains owned key references"
    else:
        assert all(value is not None for value in owned), "live state lost key references"


def _commands(data):
    at = 0
    for _ in range(MAX_COMMANDS):
        if at >= len(data):
            return
        header = data[at:at + 3].ljust(3, b"\0")
        opcode, operand, size = header
        at += 3
        payload = data[at:at + size]
        at += size
        yield opcode & 15, (opcode >> 4) & 1, operand, payload


def fuzz_records(data: bytes) -> None:
    """Exercise production AEAD and state with a separate event/limit oracle.

    Commands 0/1 encode DATA/CLOSE; 2 delivers an indexed queued packet; 3
    replays the last received packet; 4 corrupts a queued tag; 5 feeds arbitrary
    wire bytes; 6 advances public fake time; 7 aborts; 8/9 send invalid DATA/CLOSE;
    10 checks the I/O deadline; 11 reflects a packet; 12 moves counters forward
    to usage boundaries; 13 authenticates an invalid CLOSE reason using public
    fixture keys; 14 feeds a handshake frame; 15 delivers the newest packet.
    Successful sends queue packets instead of automatically delivering them,
    allowing reordered, skipped, inflight and replayed records to be explored.
    """
    clock, keys = _Clock(), _public_keys()
    states = [records.RecordState(keys, role, clock=clock) for role in (0, 1)]
    models = [_Endpoint(), _Endpoint()]
    queues = [[], []]
    last_received = [None, None]
    nonces = set()

    def deliver(role, packet):
        outcome = _receive(models[role], role, clock.now, packet)
        value = _invoke(outcome, lambda: states[role].decode(packet.raw))
        if outcome == "ok":
            assert value == (packet.kind, packet.plaintext), "wrong or out-of-order plaintext delivered"
            last_received[role] = packet

    for opcode, role, operand, payload in _commands(data):
        state, model = states[role], models[role]
        if opcode in (0, 1, 8, 9):
            kind = 17 if opcode in (1, 9) else 16
            plaintext = (bytes([operand % 3]) if opcode == 1 else
                         bytes([3 + operand % 253]) if opcode == 9 else
                         (b"" if operand % 2 == 0 else b"x" * 16385) if opcode == 8 else
                         payload or b"x")
            if opcode == 0 and operand in (254, 255):
                size = 16383 if operand == 254 else 16384
                plaintext = (plaintext * (size // len(plaintext) + 1))[:size]
            sequence = model.send
            outcome = _send(model, clock.now, kind, plaintext)
            operation = (lambda: state.encode_data(plaintext)) if kind == 16 else (
                lambda: state.encode_close(plaintext[0]))
            raw = _invoke(outcome, operation)
            if outcome == "ok":
                expected = {"kind": kind, "role": role, "sid": keys.sid, "sequence": sequence}
                assert oracle.frame_oracle(raw, expected), "encoder emitted an invalid frame"
                prefix = keys.c_prefix if role == 0 else keys.s_prefix
                nonce = prefix + sequence.to_bytes(8, "big")
                assert nonce not in nonces, "record encoder reused a nonce"
                nonces.add(nonce)
                queues[role].append(_Packet(raw, role, sequence, kind, plaintext))
        elif opcode in (2, 4, 11, 15):
            sender = role if opcode == 11 else 1 - role
            if queues[sender]:
                packet = queues[sender][-1 if opcode == 15 else operand % len(queues[sender])]
                if opcode == 4:
                    packet = _Packet(packet.raw[:-1] + bytes([packet.raw[-1] ^ 1]),
                                     packet.sender, packet.sequence, packet.kind, packet.plaintext, False)
                deliver(role, packet)
        elif opcode == 3:
            if last_received[role] is not None:
                deliver(role, last_received[role])
        elif opcode in (5, 14):
            raw = payload if opcode == 5 else bytes.fromhex(_FIXTURE["frames"]["client_hello"])
            # Parse independently, then ask the AEAD library about the tag with
            # public fixture keys. Fuzz input can include authentic fixture
            # records; neither valid headers nor valid tags imply rejection.
            expected = {"kind": raw[6] if len(raw) > 6 else 0, "role": 1 - role,
                        "sid": keys.sid, "sequence": model.receive}
            is_record = expected["kind"] in (16, 17) and oracle.frame_oracle(raw, expected)
            plaintext, authenticated = b"x" * max(0, len(raw) - 56), False
            if is_record:
                key = keys.s_key if role == 0 else keys.c_key
                prefix = keys.s_prefix if role == 0 else keys.c_prefix
                try:
                    plaintext = ChaCha20Poly1305(key).decrypt(
                        prefix + model.receive.to_bytes(8, "big"), raw[40:], raw[:40])
                except InvalidTag:
                    pass
                else:
                    authenticated = True
            packet = _Packet(raw, 1 - role, model.receive, expected["kind"], plaintext,
                             authenticated, is_record)
            deliver(role, packet)
        elif opcode == 6:
            clock.now += (0, 0.001, 1.999, 2, 59.999, 60, 599.999, 600)[operand % 8]
        elif opcode == 7:
            model.failed = True
            state.abort()
        elif opcode == 10:
            expected = "fail" if model.failed else "ok"
            deadline = _invoke(expected, state.io_deadline)
            if expected == "ok":
                assert deadline == (model.close_at + 2 if model.close_at is not None
                                    else min(600, model.last_activity + 60))
        elif opcode == 12:
            # Direct counter placement exercises 2^20/2^30 limits without a
            # million records. Never lower sequence counters or reuse a nonce.
            field = operand % 4
            boundary = payload[0] % 3 if payload else 0
            if field < 2:
                value = 2**20 - 2 + boundary
                if field == 0:
                    model.send = state.send_sequence = max(model.send, value)
                else:
                    model.receive = state.receive_sequence = max(model.receive, value)
            elif field == 2:
                model.sent_bytes = state.send_data_bytes = max(model.sent_bytes, 2**30 - 2 + boundary)
            else:
                model.received_bytes = state.receive_data_bytes = max(model.received_bytes, 2**30 - 2 + boundary)
        elif opcode == 13 and model.receive < 2**20:
            sender, sequence = 1 - role, model.receive
            plaintext = bytes([3 + operand % 253])
            header = wire.make_header(17, sender, keys.sid, sequence, 17)
            key = keys.c_key if sender == 0 else keys.s_key
            prefix = keys.c_prefix if sender == 0 else keys.s_prefix
            raw = header + ChaCha20Poly1305(key).encrypt(prefix + sequence.to_bytes(8, "big"), plaintext, header)
            deliver(role, _Packet(raw, sender, sequence, 17, plaintext))
        for endpoint, reference in zip(states, models):
            _check_state(endpoint, reference)


def _command(opcode, operand=0, payload=b"", role=0):
    assert len(payload) <= 255
    return bytes([opcode | role << 4, operand, len(payload)]) + payload


def seed_inputs() -> dict[str, list[bytes]]:
    """Public valid, deep-state and rejection-boundary corpus entries."""
    frames = [bytes([i]) + raw for i, raw in enumerate(_FRAMES)]
    for i, raw in enumerate(_FRAMES):
        frames.extend((bytes([i]) + raw[:39], bytes([i]) + raw + b"\0",
                       bytes([i]) + raw[:7] + bytes([raw[7] ^ 1]) + raw[8:],
                       bytes([i]) + raw[:28] + (2**20).to_bytes(8, "big") + raw[36:]))
        if raw[6] == 16:
            frames.append(bytes([i]) + raw[:36] + (16400).to_bytes(4, "big") + bytes(16400))
    hello = [_HELLO, b"", _HELLO[:-1], _HELLO + b"\0", _HELLO[:64] + b"\0" + _HELLO[65:]]
    # Explicit identity and sorted-offer seeds reach past length/header checks.
    for host, service in ((b"a.example", b"test/valid"), (b"A.example", b"test"),
                          (b"127.0.0.1", b"test"), (b"a..example", b"test"),
                          (b"a" * 64 + b".example", b"test"), (b"a.example", b"UPPER")):
        hello.append(_HELLO[:70] + len(host).to_bytes(2, "big") + host + bytes([len(service)]) + service)
    versions, suites = tuple(range(1, 9)), (*range(1, 8), 0xF001)
    host, service = b".".join((b"a" * 63,) * 3 + (b"a" * 61,)), b"a" * 64
    hello.append(_HELLO[:64] + bytes([8]) + b"".join(v.to_bytes(2, "big") for v in versions)
                 + bytes([8]) + b"".join(v.to_bytes(2, "big") for v in suites)
                 + len(host).to_bytes(2, "big") + host + bytes([64]) + service)
    kem_seeds = {}
    for name, raw, offset in (("kem_pk", _PK, 40), ("kem_ct", _CT, 8)):
        kem_seeds[name] = [raw, b"", raw[:-1], raw + b"\0", bytes([raw[0] ^ 1]) + raw[1:]]
        for value in (0, 1, 3328, 3329, 4095):
            kem_seeds[name].append(oracle.replace_coefficient(raw, offset, 0, value))
    c = _command
    data0, data1 = c(0, payload=b"request"), c(0, payload=b"response", role=1)
    receive0, receive1 = c(2), c(2, role=1)
    record_seeds = [b"", data0 + receive1, data1 + receive0,
                    data0 + receive1 + data1 + receive0 + c(1) + c(15, role=1) + c(1, role=1) + c(15),
                    data0 + c(0, payload=b"second") + c(2, 1, role=1),
                    data0 + receive1 + c(3, role=1) + receive1,
                    data0 + c(4, role=1) + receive1,
                    data0 + c(11) + c(0), c(5, payload=b"invalid"),
                    c(13) + c(0), c(14), c(8), c(8, 1), c(9),
                    c(7) + data0 + c(1) + c(10),
                    c(6, 5) + data0 + c(1, 1) + c(6, 3) + c(1),
                    data1 + c(1) + receive0 + c(15, role=1) + c(1, role=1) + c(15),
                    c(1) + c(1) + data0, c(1) + c(6, 2) + c(10) + c(6, 1) + c(1),
                    c(12, 0, b"\0") + data0 + c(1),
                    c(12, 0, b"\1") + data0 + c(1),
                    c(12, 0, b"\2") + c(1), c(12, 2, b"\1") + data0 + c(1),
                    c(12, 3, b"\1", role=1) + data0 + receive1,
                    c(6, 7) + c(10) + data1 + c(1, role=1),
                    data0 + receive1 + c(0, payload=b"next") + c(2, 1, role=1),
                    c(0, 255, b"max") + receive1 + c(0, 254, b"edge") + c(2, 1, role=1),
                    c(5, payload=bytes.fromhex(_FIXTURE["frames"]["client_data"]), role=1)
                    + c(5, payload=bytes.fromhex(_FIXTURE["frames"]["client_close"]), role=1)
                    + c(1, role=1),
                    (c(6, 4) + data0) * 10 + c(6, 2) + data0 + c(1, 1) + c(10)]
    return {"frame": frames, "hello": hello, **kem_seeds, "records": record_seeds}


TARGETS = {"frame": fuzz_frame, "hello": fuzz_hello, "kem_pk": fuzz_kem_pk,
           "kem_ct": fuzz_kem_ct, "records": fuzz_records}
