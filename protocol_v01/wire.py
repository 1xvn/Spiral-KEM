"""Strict framing for the experimental Spiral OPT2 v0.1 protocol.

Header validation is deliberately usable before any network payload allocation.
Connection-state expectations remain explicit arguments supplied by the owner.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import Struct


class ProtocolError(ValueError):
    """An invalid protocol message or state transition."""


VERSION = 1
SUITE = 0xF001
HEADER_SIZE = 40
MAX_RECORDS = 1 << 20
_HEADER = Struct(">4sHBBHH16sQI")
_LENGTHS = {1: (75, 418), 2: (940, 940), 3: (1192, 1192),
            4: (32, 32), 0x10: (17, 16400), 0x11: (17, 17)}
_HANDSHAKE = {1: (0, 0), 2: (1, 0), 3: (0, 1), 4: (1, 1)}
_ZERO_ID = bytes(16)


@dataclass(frozen=True, slots=True)
class Header:
    kind: int
    role: int
    sid: bytes
    sequence: int
    length: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class Frame:
    header: Header
    payload: bytes
    raw: bytes


def parse_header(raw: bytes, *, kind: int | None = None,
                 role: int | None = None, sid: bytes | None = None,
                 sequence: int | None = None) -> Header:
    if type(raw) is not bytes or len(raw) != HEADER_SIZE:
        raise ProtocolError("invalid frame header")
    magic, version, actual_kind, actual_role, suite, flags, actual_sid, seq, length = _HEADER.unpack(raw)
    if magic != b"SPK1" or version != VERSION or flags != 0:
        raise ProtocolError("invalid header constant")
    if actual_kind not in _LENGTHS or actual_role not in (0, 1):
        raise ProtocolError("invalid message kind or direction")
    if suite != (0 if actual_kind == 1 else SUITE):
        raise ProtocolError("invalid suite")
    lower, upper = _LENGTHS[actual_kind]
    if not lower <= length <= upper:
        raise ProtocolError("invalid payload length")
    if actual_kind in _HANDSHAKE:
        expected_role, expected_seq = _HANDSHAKE[actual_kind]
        if actual_role != expected_role or seq != expected_seq:
            raise ProtocolError("invalid handshake direction or sequence")
    elif seq >= MAX_RECORDS or (actual_kind == 0x10 and seq == MAX_RECORDS - 1):
        raise ProtocolError("record sequence limit")
    if (actual_kind == 1 and actual_sid != _ZERO_ID) or (actual_kind != 1 and actual_sid == _ZERO_ID):
        raise ProtocolError("invalid session identifier")
    if ((kind is not None and actual_kind != kind)
            or (role is not None and actual_role != role)
            or (sid is not None and actual_sid != sid)
            or (sequence is not None and seq != sequence)):
        raise ProtocolError("unexpected message state")
    return Header(actual_kind, actual_role, actual_sid, seq, length, raw)


def make_header(kind: int, role: int, sid: bytes, sequence: int, length: int) -> bytes:
    if any(type(value) is not int for value in (kind, role, sequence, length)):
        raise ProtocolError("header integers required")
    if type(sid) is not bytes or len(sid) != 16:
        raise ProtocolError("invalid session identifier")
    if kind not in _LENGTHS or role not in (0, 1) or not 0 <= sequence < 2**64 or not 0 <= length < 2**32:
        raise ProtocolError("invalid header value")
    raw = _HEADER.pack(b"SPK1", VERSION, kind, role, 0 if kind == 1 else SUITE,
                       0, sid, sequence, length)
    parse_header(raw)
    return raw


def make_frame(kind: int, role: int, sid: bytes, sequence: int, payload: bytes) -> bytes:
    if type(payload) is not bytes:
        raise ProtocolError("bytes payload required")
    return make_header(kind, role, sid, sequence, len(payload)) + payload


def parse_frame(raw: bytes, *, kind: int | None = None,
                role: int | None = None, sid: bytes | None = None,
                sequence: int | None = None) -> Frame:
    if type(raw) is not bytes or len(raw) < HEADER_SIZE:
        raise ProtocolError("invalid frame")
    header = parse_header(raw[:HEADER_SIZE], kind=kind, role=role, sid=sid, sequence=sequence)
    if len(raw) != HEADER_SIZE + header.length:
        raise ProtocolError("inexact frame length")
    return Frame(header, raw[HEADER_SIZE:], raw)
