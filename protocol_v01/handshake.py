"""One-shot blocking handshakes for the research-only Spiral OPT2 profile.

The transport must already provide authenticated, non-resumed TLS 1.3 and the
real connection exporter. This layer never substitutes a synthetic binding.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import importlib.util
import ipaddress
import math
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .wire import ProtocolError, SUITE, VERSION, make_frame, make_header, parse_frame

PID = b"SpiralOPT2-Proto-v0.1"
KEM_SHA256 = "74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118"
_KEM_NAME = "_spiral_protocol_v01_verified_kem_" + KEM_SHA256
_KEM_LOCK = threading.Lock()
_OWNER_LOCK = threading.Lock()
_ID_LOCK = threading.Lock()
_LIVE_IDS: set[bytes] = set()
_KEM_SLOTS = threading.BoundedSemaphore(2)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SERVICE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,63}", re.ASCII)


@dataclass(frozen=True, slots=True)
class SessionKeys:
    sid: bytes
    c_key: bytes
    s_key: bytes
    c_prefix: bytes
    s_prefix: bytes
    transcript_hash: bytes


@dataclass(frozen=True, slots=True)
class Pin:
    public_key: Ed25519PublicKey
    not_before: float
    not_after: float
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class ClientHello:
    client_random: bytes
    binding: bytes
    versions: tuple[int, ...]
    suites: tuple[int, ...]
    server_name: str
    service: str


def digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _v16(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def _v32(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def domain(label: bytes) -> bytes:
    return PID + b"\0" + _v16(label)


def info(label: bytes, length: int, transcript_hash: bytes) -> bytes:
    if type(label) is not bytes or type(length) is not int or not 1 <= length <= 32:
        raise ProtocolError("invalid key schedule label or length")
    if type(transcript_hash) is not bytes or len(transcript_hash) != 32:
        raise ProtocolError("invalid transcript hash")
    return (_v16(PID) + VERSION.to_bytes(2, "big") + SUITE.to_bytes(2, "big")
            + _v16(label) + length.to_bytes(2, "big") + transcript_hash)


def expand(root: bytes, label: bytes, length: int, transcript_hash: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info(label, length, transcript_hash)).derive(root)


def _mac(key: bytes, value: bytes) -> bytes:
    return hmac.digest(key, value, "sha256")


def validate_identity(server_name: str, service: str) -> None:
    if type(server_name) is not str or type(service) is not str:
        raise ProtocolError("invalid configured identity")
    try:
        host = server_name.encode("ascii")
        service_bytes = service.encode("ascii")
    except UnicodeEncodeError:
        raise ProtocolError("wire identity must be canonical ASCII") from None
    if not 1 <= len(host) <= 253 or not all(_HOST_LABEL.fullmatch(label) for label in server_name.split(".")):
        raise ProtocolError("invalid DNS name")
    try:
        ipaddress.ip_address(server_name)
    except ValueError:
        pass
    else:
        raise ProtocolError("IP literals are unsupported")
    if not 1 <= len(service_bytes) <= 64 or not _SERVICE.fullmatch(service):
        raise ProtocolError("invalid service name")


def client_hello_payload(server_name: str, service: str, binding: bytes) -> bytes:
    validate_identity(server_name, service)
    _validate_binding(binding)
    name, purpose = server_name.encode("ascii"), service.encode("ascii")
    return (secrets.token_bytes(32) + binding + b"\x01\x00\x01\x01\xf0\x01"
            + _v16(name) + bytes([len(purpose)]) + purpose)


def parse_client_hello(payload: bytes) -> ClientHello:
    if type(payload) is not bytes or not 75 <= len(payload) <= 418:
        raise ProtocolError("invalid ClientHello length")
    offset = 64

    def take(size: int) -> bytes:
        nonlocal offset
        if offset + size > len(payload):
            raise ProtocolError("truncated ClientHello")
        value = payload[offset:offset + size]
        offset += size
        return value

    def offers() -> tuple[int, ...]:
        count = take(1)[0]
        if not 1 <= count <= 8:
            raise ProtocolError("invalid offer count")
        values = tuple(int.from_bytes(take(2), "big") for _ in range(count))
        if values[0] == 0 or any(a >= b for a, b in zip(values, values[1:])):
            raise ProtocolError("noncanonical offer list")
        return values

    versions, suites = offers(), offers()
    host_size = int.from_bytes(take(2), "big")
    if not 1 <= host_size <= 253:
        raise ProtocolError("invalid DNS name length")
    try:
        host = take(host_size).decode("ascii")
        service_size = take(1)[0]
        if not 1 <= service_size <= 64:
            raise ProtocolError("invalid service length")
        service = take(service_size).decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("non-ASCII identity") from None
    if offset != len(payload):
        raise ProtocolError("trailing ClientHello bytes")
    validate_identity(host, service)
    if VERSION not in versions or SUITE not in suites:
        raise ProtocolError("unsupported negotiation")
    return ClientHello(payload[:32], payload[32:64], versions, suites, host, service)


def load_kem():
    """Load only the exact approved checkout source, not a sys.path namesake."""
    source = Path(__file__).resolve().parents[1] / "code" / "opt2" / "spiral_kem_toy_v031_opt2.py"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != KEM_SHA256:
        raise ProtocolError("KEM source hash differs from protocol profile")
    with _KEM_LOCK:
        module = sys.modules.get(_KEM_NAME)
        if module is None:
            spec = importlib.util.spec_from_file_location(_KEM_NAME, source)
            if spec is None or spec.loader is None:
                raise ProtocolError("KEM source cannot be loaded")
            module = importlib.util.module_from_spec(spec)
            sys.modules[_KEM_NAME] = module
            try:
                # Execute precisely the bytes whose digest was just checked.
                exec(compile(data, str(source), "exec"), module.__dict__)
            except BaseException:
                sys.modules.pop(_KEM_NAME, None)
                raise
        return module


def _validate_binding(binding: bytes) -> None:
    if type(binding) is not bytes or len(binding) != 32:
        raise ProtocolError("real TLS exporter binding required")


def _check_deadline(deadline: float, transport) -> None:
    if time.monotonic() >= deadline:
        raise ProtocolError("inner handshake deadline")
    if getattr(transport, "closed", False):
        raise ProtocolError("transport is closed")


@contextmanager
def _kem_slot(deadline: float, transport):
    _check_deadline(deadline, transport)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _KEM_SLOTS.acquire(timeout=remaining):
        raise ProtocolError("KEM work deadline")
    try:
        _check_deadline(deadline, transport)
        yield
        _check_deadline(deadline, transport)
    finally:
        _KEM_SLOTS.release()


def _begin(transport, server_name: str, service: str) -> float:
    validate_identity(server_name, service)
    _validate_binding(transport.binding)
    with _OWNER_LOCK:
        if getattr(transport, "_handshake_used", False):
            raise ProtocolError("transport handshake already consumed")
        transport._handshake_used = True
        transport.claimed = False
        transport.decapsulation_count = 0
    tls_name = getattr(transport, "server_name", server_name)
    if tls_name != server_name:
        raise ProtocolError("TLS and protocol names differ")
    deadline = min(time.monotonic() + 10.0,
                   getattr(transport, "handshake_deadline", float("inf")))
    if not math.isfinite(deadline):
        raise ProtocolError("invalid handshake deadline")
    _check_deadline(deadline, transport)
    return deadline


def _reserve_id(transport) -> bytes:
    if not callable(getattr(transport, "add_close_callback", None)):
        raise ProtocolError("transport must support close ownership")
    with _ID_LOCK:
        while True:
            sid = secrets.token_bytes(16)
            if sid != bytes(16) and sid not in _LIVE_IDS:
                _LIVE_IDS.add(sid)
                break

    def release():
        with _ID_LOCK:
            _LIVE_IDS.discard(sid)

    try:
        transport.add_close_callback(release)
    except BaseException:
        release()
        raise
    return sid


def _receive(transport, *, kind, role, sid, sequence, deadline):
    _check_deadline(deadline, transport)
    raw = transport.recv(kind=kind, role=role, sid=sid, sequence=sequence, deadline=deadline)
    frame = parse_frame(raw, kind=kind, role=role, sid=sid, sequence=sequence)
    _check_deadline(deadline, transport)
    return frame


def _send(transport, raw: bytes, deadline: float):
    _check_deadline(deadline, transport)
    transport.send(raw, deadline)
    _check_deadline(deadline, transport)


def _shared(ss: bytes) -> None:
    if type(ss) is not bytes or len(ss) != 32:
        raise ProtocolError("invalid KEM shared-secret result")


def _schedule(ch: bytes, sh: bytes, ck_header: bytes, ct: bytes, ss: bytes):
    _shared(ss)
    h0 = digest(ch + sh + ck_header + ct)
    prk = _mac(h0, ss)
    cf_key = expand(prk, b"client-finished", 32, h0)
    sf_key = expand(prk, b"server-finished", 32, h0)
    cf = _mac(cf_key, domain(b"client-finished") + h0)
    return prk, sf_key, cf


def _finish(prk: bytes, sid: bytes, ch: bytes, sh: bytes, ck: bytes,
            sf_frame: bytes) -> SessionKeys:
    h2 = digest(ch + sh + ck + sf_frame)
    master = expand(prk, b"application-master", 32, h2)
    return SessionKeys(sid,
                       expand(master, b"client-data-key", 32, h2),
                       expand(master, b"server-data-key", 32, h2),
                       expand(master, b"client-nonce-prefix", 4, h2),
                       expand(master, b"server-nonce-prefix", 4, h2), h2)


def _close_quietly(transport):
    try:
        transport.close()
    except Exception:
        pass


def client_handshake(transport, server_name: str, service: str,
                     pins: Mapping[tuple[str, str, bytes], Pin]) -> SessionKeys:
    ss = prk = sf_key = None
    try:
        deadline = _begin(transport, server_name, service)
        ch = make_frame(1, 0, bytes(16), 0,
                        client_hello_payload(server_name, service, transport.binding))
        _send(transport, ch, deadline)
        sh = _receive(transport, kind=2, role=1, sid=None, sequence=0, deadline=deadline)
        sid, body = sh.header.sid, sh.payload
        if body[:4] != b"\x00\x01\xf0\x01":
            raise ProtocolError("invalid selected negotiation")
        key_id = body[36:68]
        pin = pins.get((server_name, service, key_id))
        now = time.time()
        if (not isinstance(pin, Pin) or not isinstance(pin.public_key, Ed25519PublicKey)
                or type(pin.revoked) is not bool or pin.revoked
                or not isinstance(pin.not_before, (int, float))
                or not isinstance(pin.not_after, (int, float))
                or not math.isfinite(pin.not_before) or not math.isfinite(pin.not_after)
                or not pin.not_before <= now < pin.not_after):
            raise ProtocolError("server authentication unavailable")
        public_bytes = pin.public_key.public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw)
        if not hmac.compare_digest(digest(public_bytes), key_id):
            raise ProtocolError("pin identifier mismatch")
        sig_input = domain(b"server-signature") + _v32(ch) + _v32(sh.raw[:-64])
        try:
            pin.public_key.verify(body[-64:], sig_input)
        except InvalidSignature:
            raise ProtocolError("server signature failed") from None
        kem = load_kem().SpiralKEM()
        pk = kem.deserialize_public_key_compact(body[68:876])
        with _kem_slot(deadline, transport):
            ciphertext, ss = kem.encapsulate(pk)
        ct = kem.serialize_ciphertext_compact(ciphertext)
        ck_head = make_header(3, 0, sid, 1, 1192)
        prk, sf_key, cf = _schedule(ch, sh.raw, ck_head, ct, ss)
        ss = None
        ck = ck_head + ct + cf
        _send(transport, ck, deadline)
        sf = _receive(transport, kind=4, role=1, sid=sid, sequence=1, deadline=deadline)
        h1 = digest(ch + sh.raw + ck + sf.header.raw)
        expected_sf = _mac(sf_key, domain(b"server-finished") + h1)
        if not hmac.compare_digest(expected_sf, sf.payload):
            raise ProtocolError("server Finished failed")
        result = _finish(prk, sid, ch, sh.raw, ck, sf.raw)
        _check_deadline(deadline, transport)
        return result
    except Exception as exc:
        _close_quietly(transport)
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("client handshake failed") from None
    except BaseException:
        _close_quietly(transport)
        raise
    finally:
        ss = prk = sf_key = None


def server_handshake(transport, server_name: str, service: str,
                     signing_key: Ed25519PrivateKey) -> SessionKeys:
    sk = ss = prk = sf_key = None
    try:
        deadline = _begin(transport, server_name, service)
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ProtocolError("invalid server signing key")
        ch = _receive(transport, kind=1, role=0, sid=bytes(16), sequence=0, deadline=deadline)
        hello = parse_client_hello(ch.payload)
        if hello.server_name != server_name or hello.service != service:
            raise ProtocolError("unregistered server identity")
        if not hmac.compare_digest(hello.binding, transport.binding):
            raise ProtocolError("TLS exporter mismatch")
        sid = _reserve_id(transport)
        kem = load_kem().SpiralKEM()
        with _kem_slot(deadline, transport):
            pk, sk = kem.keygen()
        auth_public = signing_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw)
        core = (b"\x00\x01\xf0\x01" + secrets.token_bytes(32) + digest(auth_public)
                + kem.serialize_public_key_compact(pk))
        sh_head = make_header(2, 1, sid, 0, 940)
        signature = signing_key.sign(domain(b"server-signature") + _v32(ch.raw) + _v32(sh_head + core))
        sh = sh_head + core + signature
        _send(transport, sh, deadline)
        ck_deadline = min(deadline, time.monotonic() + 5.0)
        # The transport irreversibly claims the CK opportunity immediately
        # after validating its header, before waiting for its bounded payload.
        if transport.claimed or transport.decapsulation_count:
            raise ProtocolError("ClientKey opportunity consumed")
        ck = _receive(transport, kind=3, role=0, sid=sid, sequence=1, deadline=ck_deadline)
        if not transport.claimed:
            raise ProtocolError("transport did not consume ClientKey ownership")
        ct_wire, cf = ck.payload[:1160], ck.payload[1160:]
        ciphertext = kem.deserialize_ciphertext_compact(ct_wire)
        with _kem_slot(ck_deadline, transport):
            with _OWNER_LOCK:
                if transport.decapsulation_count != 0:
                    raise ProtocolError("duplicate decapsulation")
                transport.decapsulation_count += 1
            try:
                ss = kem.decapsulate(sk, ciphertext)
            finally:
                sk = None
        prk, sf_key, expected_cf = _schedule(ch.raw, sh, ck.header.raw, ct_wire, ss)
        ss = None
        if not hmac.compare_digest(expected_cf, cf):
            raise ProtocolError("client Finished failed")
        sf_head = make_header(4, 1, sid, 1, 32)
        h1 = digest(ch.raw + sh + ck.raw + sf_head)
        sf = sf_head + _mac(sf_key, domain(b"server-finished") + h1)
        # Keys cannot escape to the application until the complete SF send.
        _send(transport, sf, deadline)
        result = _finish(prk, sid, ch.raw, sh, ck.raw, sf)
        _check_deadline(deadline, transport)
        return result
    except Exception as exc:
        _close_quietly(transport)
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("server handshake failed") from None
    except BaseException:
        _close_quietly(transport)
        raise
    finally:
        sk = ss = prk = sf_key = None
