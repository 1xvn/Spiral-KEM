"""Independent experimental test client written from SPEC_v0.1.md.

Does not import the runtime framing, TLS adapter, handshake, schedule or record
implementation. It shares the supplied KEM algorithm and vetted crypto libraries.
This is a test peer, not an independently audited production implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
from pathlib import Path
import secrets
import select
import socket
import sys
import time

from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PID = b"SpiralOPT2-Proto-v0.1"
NAME = "spiral-lab.example"
SERVICE = "spiral-research"
KEM_DIGEST = "74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118"


def sha(value):
    return hashlib.sha256(value).digest()


def mac(key, message):
    return hmac.digest(key, message, "sha256")


def blob(value, size):
    return len(value).to_bytes(size, "big") + value


def domain(label):
    return PID + b"\0" + blob(label, 2)


def expand(root, label, length, transcript):
    # All outputs in this fixed profile fit in the first RFC5869 expansion block.
    assert 0 < length <= 32 and len(transcript) == 32
    info = blob(PID, 2) + b"\0\1\xf0\1" + blob(label, 2) + length.to_bytes(2, "big") + transcript
    return mac(root, info + b"\1")[:length]


def header(kind, role, sid, seq, length):
    return (b"SPK1\0\1" + bytes([kind, role]) + (b"\0\0" if kind == 1 else b"\xf0\1")
            + b"\0\0" + sid + seq.to_bytes(8, "big") + length.to_bytes(4, "big"))


def load_kem():
    source = Path(__file__).resolve().parents[2] / "code/opt2/spiral_kem_toy_v031_opt2.py"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != KEM_DIGEST:
        raise ValueError("unexpected KEM source")
    name = "_independent_protocol_test_kem"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(data, str(source), "exec"), module.__dict__)
    return sys.modules[name]


class PeerRejected(ValueError):
    pass


class TestPeer:
    """Fresh TLS client and independently implemented inner protocol peer."""

    __test__ = False

    def __init__(self, address, ca_file, auth_public, *, server_name=NAME, service=SERVICE):
        self.socket = socket.create_connection(address, timeout=2)
        self.closed = False
        self.name, self.service = server_name, service
        self.auth_public = auth_public
        self.tx = self.rx = 0
        self.key = self.peer_key = None
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_options(SSL.OP_NO_TICKET)
        ctx.set_session_cache_mode(SSL.SESS_CACHE_OFF)
        ctx.load_verify_locations(str(ca_file))
        ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
        ctx.set_alpn_protos([b"spiral-opt2/0.1"])
        self.tls = SSL.Connection(ctx, self.socket)
        self.tls.setblocking(False)
        self.tls.set_connect_state()
        self.tls.set_tlsext_host_name(server_name.encode("ascii"))
        try:
            self.io(self.tls.do_handshake)
            if self.tls.get_protocol_version_name() != "TLSv1.3":
                raise PeerRejected("TLS version")
            if self.tls.get_alpn_proto_negotiated() != b"spiral-opt2/0.1":
                raise PeerRejected("ALPN")
            if SSL._lib.SSL_session_reused(self.tls._ssl):
                raise PeerRejected("resumed TLS")
            cert = self.tls.get_peer_certificate().to_cryptography()
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if server_name not in names.get_values_for_type(x509.DNSName):
                raise PeerRejected("certificate name")
            if not cert.not_valid_before_utc <= datetime.now(timezone.utc) < cert.not_valid_after_utc:
                raise PeerRejected("certificate time")
            self.binding = self.tls.export_keying_material(b"EXPORTER-SpiralOPT2-v0.1", 32, context=b"")
            if len(self.binding) != 32:
                raise PeerRejected("exporter length")
        except BaseException:
            self.close()
            raise

    def io(self, function, deadline=None):
        deadline = time.monotonic() + 2 if deadline is None else deadline
        while True:
            if self.closed or time.monotonic() >= deadline:
                raise TimeoutError("peer I/O deadline")
            try:
                return function()
            except SSL.WantReadError:
                r, w = [self.socket], []
            except SSL.WantWriteError:
                r, w = [], [self.socket]
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not any(select.select(r, w, [], remaining)[:2]):
                raise TimeoutError("peer I/O deadline")

    def send(self, raw):
        deadline = time.monotonic() + 2
        offset = 0
        while offset < len(raw):
            n = self.io(lambda: self.tls.send(raw[offset:]), deadline)
            if not n:
                raise EOFError("zero write")
            offset += n

    def read_exact(self, size):
        data = bytearray()
        deadline = time.monotonic() + 2
        while len(data) < size:
            part = self.io(lambda: self.tls.recv(size - len(data)), deadline)
            if not part:
                raise EOFError("peer EOF")
            data.extend(part)
        return bytes(data)

    def receive(self, kind, seq):
        h = self.read_exact(40)
        if (h[:6] != b"SPK1\0\1" or h[6] != kind or h[7] != 1
                or h[8:12] != b"\xf0\1\0\0" or h[28:36] != seq.to_bytes(8, "big")):
            raise PeerRejected("server header")
        sid = h[12:28]
        if sid == bytes(16) or (kind != 2 and sid != self.sid):
            raise PeerRejected("server session")
        length = int.from_bytes(h[36:40], "big")
        valid = (length == 940 if kind == 2 else length == 32 if kind == 4 else
                 length == 17 if kind == 0x11 else 17 <= length <= 16400 if kind == 0x10 else False)
        if not valid:
            raise PeerRejected("server payload length")
        return h + self.read_exact(length)

    def hello(self, binding=None):
        host, service = self.name.encode("ascii"), self.service.encode("ascii")
        payload = (secrets.token_bytes(32) + (self.binding if binding is None else binding)
                   + b"\1\0\1\1\xf0\1" + blob(host, 2) + bytes([len(service)]) + service)
        self.ch = header(1, 0, bytes(16), 0, len(payload)) + payload
        self.send(self.ch)
        self.sh = self.receive(2, 0)
        self.sid = self.sh[12:28]
        body = self.sh[40:]
        if body[:4] != b"\0\1\xf0\1":
            raise PeerRejected("server selection")
        if body[36:68] != sha(self.auth_public.public_bytes_raw()):
            raise PeerRejected("unknown pinned key")
        self.auth_public.verify(body[876:], domain(b"server-signature") + blob(self.ch, 4) + blob(self.sh[:-64], 4))
        self.kem = load_kem().SpiralKEM()
        pk = self.kem.deserialize_public_key_compact(body[68:876])
        self.ct, self.ss = self.kem.encapsulate(pk)

    def client_key(self, *, alter_ct=False, bad_cf=False):
        ct = self.ct
        if alter_ct:
            from dataclasses import replace
            ct = replace(ct, v=((ct.v[0] + 1) % 3329,) + ct.v[1:])
        raw_ct = self.kem.serialize_ciphertext_compact(ct)
        head = header(3, 0, self.sid, 1, 1192)
        h0 = sha(self.ch + self.sh + head + raw_ct)
        self.prk = mac(h0, self.ss)
        self.sf_key = expand(self.prk, b"server-finished", 32, h0)
        cf = mac(expand(self.prk, b"client-finished", 32, h0), domain(b"client-finished") + h0)
        if bad_cf:
            cf = bytes([cf[0] ^ 1]) + cf[1:]
        self.ck = head + raw_ct + cf
        return self.ck

    def finish(self):
        self.send(self.client_key())
        sf = self.receive(4, 1)
        expected = mac(self.sf_key, domain(b"server-finished") + sha(self.ch + self.sh + self.ck + sf[:40]))
        if not hmac.compare_digest(expected, sf[40:]):
            raise PeerRejected("server Finished")
        self.h2 = sha(self.ch + self.sh + self.ck + sf)
        root = expand(self.prk, b"application-master", 32, self.h2)
        self.key = expand(root, b"client-data-key", 32, self.h2)
        self.peer_key = expand(root, b"server-data-key", 32, self.h2)
        self.prefix = expand(root, b"client-nonce-prefix", 4, self.h2)
        self.peer_prefix = expand(root, b"server-nonce-prefix", 4, self.h2)
        self.ss = self.prk = self.sf_key = None

    def record(self, kind, plaintext, *, seq=None):
        sequence = self.tx if seq is None else seq
        h = header(kind, 0, self.sid, sequence, len(plaintext) + 16)
        return h + ChaCha20Poly1305(self.key).encrypt(self.prefix + sequence.to_bytes(8, "big"), plaintext, h)

    def send_record(self, kind, plaintext):
        raw = self.record(kind, plaintext)
        self.tx += 1
        self.send(raw)
        return raw

    def receive_record(self, kind):
        raw = self.receive(kind, self.rx)
        plain = ChaCha20Poly1305(self.peer_key).decrypt(
            self.peer_prefix + self.rx.to_bytes(8, "big"), raw[40:], raw[:40])
        self.rx += 1
        return plain

    def close_cleanly(self):
        self.send_record(0x11, b"\0")
        if self.receive_record(0x11) != b"\0":
            raise PeerRejected("close reason")
        deadline = time.monotonic() + 2
        try:
            while not self.io(self.tls.shutdown, deadline):
                pass
        finally:
            self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            self.key = self.peer_key = self.ss = self.prk = self.sf_key = None
            self.socket.close()
