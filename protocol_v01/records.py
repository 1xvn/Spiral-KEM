"""Stateful v0.1 AEAD records; callers must serialize encoding and transport writes.

The lock below reserves nonces and serializes state, not socket writes. A transport
must hold its own single send-queue lock across encode and complete write. A
partial/failed write must call abort(); neither frame nor sequence can be retried.
"""
from __future__ import annotations

import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .wire import ProtocolError, make_header, parse_frame

DATA = 0x10
CLOSE = 0x11
MAX_DATA = 16_384
MAX_RECORDS = 1 << 20
MAX_DATA_BYTES = (1 << 30) - 1
MAX_AGE = 600.0
MAX_IDLE = 60.0
CLOSE_GRACE = 2.0


class RecordLimit(ProtocolError):
    """New DATA is blocked; the transport should send CLOSE with this reason."""

    def __init__(self, reason: int):
        super().__init__("record time limit" if reason == 1 else "record usage limit")
        self.reason = reason


class RecordState:
    def __init__(self, keys, role: int, *, clock=time.monotonic):
        if type(role) is not int or role not in (0, 1):
            raise ProtocolError("record role")
        attrs = ((keys.sid, 16), (keys.c_key, 32), (keys.s_key, 32),
                 (keys.c_prefix, 4), (keys.s_prefix, 4))
        if any(type(value) is not bytes or len(value) != length for value, length in attrs):
            raise ProtocolError("record key material")
        if keys.sid == bytes(16):
            raise ProtocolError("record session")
        self.sid = keys.sid
        self.role = role
        self._send_key = keys.c_key if role == 0 else keys.s_key
        self._receive_key = keys.s_key if role == 0 else keys.c_key
        self._send_prefix = keys.c_prefix if role == 0 else keys.s_prefix
        self._receive_prefix = keys.s_prefix if role == 0 else keys.c_prefix
        self._clock = clock
        self._started = self._last_activity = clock()
        self._close_started = None
        self._timed_out = False
        self._send_limit = False
        self._lock = threading.RLock()
        self.send_sequence = 0
        self.receive_sequence = 0
        self.send_data_bytes = 0
        self.receive_data_bytes = 0
        self.send_closed = False
        self.receive_closed = False
        self.failed = False

    @property
    def closed(self) -> bool:
        return self.failed or (self.send_closed and self.receive_closed)

    def io_deadline(self) -> float:
        """Absolute monotonic deadline for the next complete transport operation.

        Encoding marks activity before the write finishes, conservatively earlier
        than the specification's complete-write timestamp. Both CLOSE records may
        have released keys while TLS shutdown still uses the closing deadline.
        """
        with self._lock:
            if self.failed:
                raise ProtocolError("failed record state")
            if self._close_started is not None:
                return self._close_started + CLOSE_GRACE
            return min(self._started + MAX_AGE, self._last_activity + MAX_IDLE)

    def _release(self) -> None:
        # Dropping Python references is not guaranteed memory zeroization.
        self._send_key = self._receive_key = None
        self._send_prefix = self._receive_prefix = None

    def abort(self) -> None:
        """Permanently invalidate this state after transport failure/cancellation."""
        with self._lock:
            self.failed = True
            self._release()

    def _reject(self, reason: str):
        self.abort()
        raise ProtocolError(reason)

    def _usable(self, now: float, *, closing: bool = False) -> None:
        if self.closed:
            self._reject("closed record state")
        if self._close_started is not None and now - self._close_started >= CLOSE_GRACE:
            self._reject("close deadline")
        if closing:
            return
        if self._timed_out:
            raise RecordLimit(1)
        if self._close_started is None and (
            now - self._started >= MAX_AGE or now - self._last_activity >= MAX_IDLE
        ):
            self._timed_out = True
            # Conservatively start the cleanup grace when expiry is observed.
            self._close_started = now
            raise RecordLimit(1)

    def _begin_close(self, now: float) -> None:
        if self._close_started is None:
            self._close_started = now

    def _encode(self, kind: int, plaintext: bytes, now: float) -> bytes:
        if self.send_sequence >= MAX_RECORDS:
            self._reject("record count exhausted")
        sequence = self.send_sequence
        # Reservation occurs before cryptography; exceptions never roll it back.
        self.send_sequence += 1
        try:
            aad = make_header(kind, self.role, self.sid, sequence, len(plaintext) + 16)
            nonce = self._send_prefix + sequence.to_bytes(8, "big")
            payload = ChaCha20Poly1305(self._send_key).encrypt(nonce, plaintext, aad)
            encoded = aad + payload
        except BaseException as error:
            self.abort()
            if isinstance(error, Exception):
                raise ProtocolError("record encryption failed") from None
            raise
        self._last_activity = now
        if kind == DATA:
            self.send_data_bytes += len(plaintext)
        else:
            self.send_closed = True
            self._begin_close(now)
            if self.receive_closed:
                self._release()
        return encoded

    def encode_data(self, plaintext: bytes) -> bytes:
        with self._lock:
            now = self._clock()
            self._usable(now)
            if self.send_closed or self.receive_closed:
                self._reject("DATA after close")
            if type(plaintext) is not bytes or not 1 <= len(plaintext) <= MAX_DATA:
                self._reject("DATA plaintext")
            if self._send_limit or self.send_sequence >= MAX_RECORDS - 1 or (
                self.send_data_bytes + len(plaintext) > MAX_DATA_BYTES
            ):
                self._send_limit = True
                raise RecordLimit(2)
            return self._encode(DATA, plaintext, now)

    def encode_close(self, reason: int = 0) -> bytes:
        with self._lock:
            now = self._clock()
            self._usable(now, closing=True)
            if self.send_closed:
                self._reject("duplicate local CLOSE")
            if type(reason) is not int or reason not in (0, 1, 2):
                self._reject("CLOSE reason")
            return self._encode(CLOSE, bytes([reason]), now)

    def decode(self, raw: bytes) -> tuple[int, bytes]:
        with self._lock:
            now = self._clock()
            if self.closed:
                self._reject("closed record state")
            if type(raw) is not bytes:
                self._reject("record bytes")
            try:
                frame = parse_frame(raw, role=1 - self.role, sid=self.sid,
                                    sequence=self.receive_sequence)
                kind = frame.header.kind
                if kind not in (DATA, CLOSE):
                    self._reject("non-record frame")
                if self.receive_closed:
                    self._reject("record after peer CLOSE")
                self._usable(now, closing=kind == CLOSE)
                if self.receive_sequence >= MAX_RECORDS:
                    self._reject("record count exhausted")
                if kind == DATA and self.receive_sequence >= MAX_RECORDS - 1:
                    self._reject("reserved CLOSE sequence")
                if kind == DATA and self.receive_data_bytes + len(frame.payload) - 16 > MAX_DATA_BYTES:
                    self._reject("receive byte limit")
                nonce = self._receive_prefix + self.receive_sequence.to_bytes(8, "big")
                plaintext = ChaCha20Poly1305(self._receive_key).decrypt(
                    nonce, frame.payload, frame.header.raw)
                if kind == DATA and not 1 <= len(plaintext) <= MAX_DATA:
                    self._reject("DATA plaintext")
                if kind == CLOSE and (len(plaintext) != 1 or plaintext[0] not in (0, 1, 2)):
                    self._reject("CLOSE reason")
            except RecordLimit:
                raise
            except (ProtocolError, InvalidTag, ValueError, TypeError):
                self.abort()
                raise ProtocolError("record rejected") from None
            except BaseException as error:
                self.abort()
                if isinstance(error, Exception):
                    raise ProtocolError("record processing failed") from None
                raise
            self.receive_sequence += 1
            self._last_activity = now
            if kind == DATA:
                self.receive_data_bytes += len(plaintext)
            else:
                self.receive_closed = True
                self._begin_close(now)
                if self.send_closed:
                    self._release()
            return kind, plaintext
