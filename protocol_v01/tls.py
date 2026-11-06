"""Deadline-bounded TLS 1.3 adapter; no plaintext or synthetic-exporter fallback."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import select
import socket
import threading
import time

from OpenSSL import SSL
from cryptography import x509

from .wire import ProtocolError, parse_header, parse_frame

ALPN = b"spiral-opt2/0.1"
EXPORTER_LABEL = b"EXPORTER-SpiralOPT2-v0.1"


def context(*, ca_file=None, cert_file=None, key_file=None):
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
    ctx.set_options(SSL.OP_NO_TICKET)
    ctx.set_session_cache_mode(SSL.SESS_CACHE_OFF)
    if ca_file is not None:
        ctx.load_verify_locations(str(ca_file))
        ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
        ctx.set_alpn_protos([ALPN])
    else:
        if cert_file is None or key_file is None:
            raise ValueError("server certificate and key required")
        ctx.use_certificate_chain_file(str(cert_file))
        ctx.use_privatekey_file(str(key_file))
        ctx.check_privatekey()

        def choose(conn, offered):
            if ALPN not in offered:
                raise ProtocolError("ALPN required")
            return ALPN

        ctx.set_alpn_select_callback(choose)
    return ctx


class Admission:
    """Per-listener TCP admission; actual peer IP only, bounded tracking table."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.active = Counter()
        self.buckets = {}
        self.pending = 0

    def acquire(self, address):
        ip = ipaddress.ip_address(address[0])
        peer = str(ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip)
        with self.lock:
            now = self.clock()
            # Forget only buckets that have naturally refilled and have no live connection.
            self.buckets = {p: b for p, b in self.buckets.items()
                            if self.active[p] or now - b[1] < 4}
            if peer not in self.buckets and len(self.buckets) >= 1024:
                raise ProtocolError("admission capacity")
            tokens, last = self.buckets.get(peer, (4.0, now))
            tokens = min(4.0, tokens + max(0, now - last))
            if sum(self.active.values()) >= 64 or self.active[peer] >= 4 or self.pending >= 32 or tokens < 1:
                self.buckets[peer] = (tokens, now)
                raise ProtocolError("admission limit")
            self.buckets[peer] = (tokens - 1, now)
            self.active[peer] += 1
            self.pending += 1
        released = False
        established = False

        def finish_handshake():
            nonlocal established
            with self.lock:
                if not released and not established:
                    established = True
                    self.pending -= 1

        def release():
            nonlocal released
            with self.lock:
                if not released:
                    released = True
                    self.active[peer] -= 1
                    if not self.active[peer]:
                        del self.active[peer]
                    if not established:
                        self.pending -= 1
        return finish_handshake, release


class TLSTransport:
    def __init__(self, sock, ctx, *, server_side, server_name):
        self.socket = sock
        self.connection = SSL.Connection(ctx, sock)
        self.connection.setblocking(False)
        self.closed = False
        self.callbacks = []
        self.close_lock = threading.RLock()
        self.ssl_call_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.read_lock = threading.Lock()
        self.claimed = False
        self.decapsulation_count = 0
        self.server_name = server_name
        deadline = time.monotonic() + 10
        try:
            if server_side:
                self.connection.set_accept_state()
            else:
                self.connection.set_connect_state()
                self.connection.set_tlsext_host_name(server_name.encode("ascii"))
            self._io(self.connection.do_handshake, deadline)
            if self.connection.get_protocol_version_name() != "TLSv1.3":
                raise ProtocolError("TLS 1.3 required")
            if self.connection.get_alpn_proto_negotiated() != ALPN:
                raise ProtocolError("ALPN required")
            # pyOpenSSL 26.4 does not expose this as a public Connection method.
            # Dependency pins and the real-TLS tests cover this fail-closed binding.
            if SSL._lib.SSL_session_reused(self.connection._ssl):
                raise ProtocolError("TLS resumption forbidden")
            if server_side:
                if self.connection.get_servername() != server_name.encode("ascii"):
                    raise ProtocolError("SNI mismatch")
            else:
                cert = self.connection.get_peer_certificate().to_cryptography()
                names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if server_name not in names.get_values_for_type(x509.DNSName):
                    raise ProtocolError("TLS hostname mismatch")
                now = datetime.now(timezone.utc)
                if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                    raise ProtocolError("TLS certificate validity")
            self.binding = self.connection.export_keying_material(EXPORTER_LABEL, 32, context=b"")
            if len(self.binding) != 32:
                raise ProtocolError("TLS exporter unavailable")
            self.tls_completed = time.monotonic()
            self.handshake_deadline = self.tls_completed + 10
        except BaseException:
            self.close()
            raise

    def _io(self, operation, deadline):
        while True:
            if self.closed or time.monotonic() >= deadline:
                raise ProtocolError("transport closed or deadline exceeded")
            try:
                # SSL objects must not be used by simultaneous native calls,
                # even though one reader and one writer may own the channel.
                with self.ssl_call_lock:
                    result = operation()
                if time.monotonic() >= deadline:
                    raise ProtocolError("deadline exceeded")
                return result
            except SSL.WantReadError:
                readers, writers = [self.socket], []
            except SSL.WantWriteError:
                readers, writers = [], [self.socket]
            except (SSL.Error, OSError) as exc:
                raise ProtocolError("TLS I/O failed") from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not any(select.select(readers, writers, [], remaining)[:2]):
                raise ProtocolError("deadline exceeded")

    def _read(self, size, deadline):
        chunks = bytearray()
        while len(chunks) < size:
            part = self._io(lambda: self.connection.recv(size - len(chunks)), deadline)
            if not part:
                raise ProtocolError("truncated frame")
            chunks.extend(part)
        return bytes(chunks)

    def recv(self, *, kind=None, kinds=None, role=None, sid=None, sequence=None, deadline):
        # A single reader owns a connection. Reentrant/parallel reads fail closed.
        if not self.read_lock.acquire(blocking=False):
            self.close()
            raise ProtocolError("concurrent reader")
        try:
            raw = self._read(40, deadline)
            h = parse_header(raw, kind=kind, role=role, sid=sid, sequence=sequence)
            if kinds is not None and h.kind not in kinds:
                raise ProtocolError("unexpected message state")
            if h.kind == 3:
                if self.claimed:
                    raise ProtocolError("ClientKey already claimed")
                self.claimed = True
            raw += self._read(h.length, deadline)
            parse_frame(raw, kind=kind, role=role, sid=sid, sequence=sequence)
            return raw
        except BaseException:
            self.close()
            raise
        finally:
            self.read_lock.release()

    def send(self, raw, deadline):
        try:
            with self.write_lock:
                position = 0
                while position < len(raw):
                    sent = self._io(lambda: self.connection.send(raw[position:]), deadline)
                    if sent <= 0:
                        raise ProtocolError("partial write")
                    position += sent
        except BaseException:
            self.close()
            raise

    def add_close_callback(self, callback):
        with self.close_lock:
            already_closed = self.closed
            if not already_closed:
                self.callbacks.append(callback)
        if already_closed:
            callback()

    def close(self):
        with self.close_lock:
            if self.closed:
                return
            self.closed = True
            self.binding = None
            callbacks, self.callbacks = self.callbacks, []
        try:
            self.socket.close()
        finally:
            for callback in callbacks:
                callback()

    def shutdown(self, deadline):
        """Invoke only after authenticating both Spiral CLOSE records."""
        if not self.read_lock.acquire(blocking=False):
            self.close()
            raise ProtocolError("concurrent reader during TLS shutdown")
        try:
            while not self._io(self.connection.shutdown, deadline):
                pass
        finally:
            self.close()
            self.read_lock.release()
