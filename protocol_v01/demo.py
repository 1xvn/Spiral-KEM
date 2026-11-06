"""Fresh local test identities and real loopback TLS; never a public service."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import argparse
import json
from pathlib import Path
import socket
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from .channel import Channel
from .handshake import client_handshake, server_handshake, Pin
from .records import DATA, CLOSE
from .tls import context, TLSTransport, Admission
from .wire import ProtocolError

NAME = "spiral-lab.example"
SERVICE = "spiral-research"


def test_certificate(directory, name=NAME):
    """Generate an ephemeral trusted local CA/leaf; no fixtures from uploaded seeds."""
    directory = Path(directory)
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, algorithm=None))
    cert_path, key_path = directory / "tls-cert.pem", directory / "tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # The enclosing TemporaryDirectory is private; restrict the key itself too.
    key_path.touch(mode=0o600, exist_ok=False)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cert_path, key_path


def run_demo(connections=2):
    if type(connections) is not int or not 1 <= connections <= 4:
        raise ValueError("loopback demo supports 1..4 concurrent connections")
    import hashlib
    import time
    with tempfile.TemporaryDirectory(prefix="spiral-tls-") as directory:
        cert, key = test_certificate(directory)
        server_ctx = context(cert_file=cert, key_file=key)
        client_ctx = context(ca_file=cert)
        signing = Ed25519PrivateKey.generate()
        public = signing.public_key()
        key_id = hashlib.sha256(public.public_bytes_raw()).digest()
        pins = {(NAME, SERVICE, key_id): Pin(public, time.time() - 60, time.time() + 3600)}
        admission = Admission()
        lock = threading.Lock()
        server_results = []

        def serve(sock, address):
            transport = channel = None
            release = lambda: None
            try:
                complete, release = admission.acquire(address)
                transport = TLSTransport(sock, server_ctx, server_side=True, server_name=NAME)
                transport.add_close_callback(release)
                keys = server_handshake(transport, NAME, SERVICE, signing)
                complete()
                # Only hashes of connection bindings are retained for local uniqueness checks.
                result = (keys.sid.hex(), hashlib.sha256(transport.binding).hexdigest(),
                          keys.transcript_hash.hex(), transport.decapsulation_count)
                channel = Channel(transport, keys, 1)
                del keys
                kind, plaintext = channel.receive()
                if kind != DATA or plaintext != b"research request":
                    raise ProtocolError("unexpected demo request")
                channel.send_data(b"research response")
                if channel.receive()[0] != CLOSE:
                    raise ProtocolError("expected authenticated CLOSE")
                channel.shutdown()
                with lock:
                    server_results.append(result)
            finally:
                if channel:
                    channel.abort()
                if transport:
                    transport.close()
                else:
                    sock.close()
                release()

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(10)
            port = listener.getsockname()[1]

            def client():
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                transport = channel = None
                try:
                    transport = TLSTransport(sock, client_ctx, server_side=False, server_name=NAME)
                    keys = client_handshake(transport, NAME, SERVICE, pins)
                    result = (keys.sid.hex(), hashlib.sha256(transport.binding).hexdigest(),
                              keys.transcript_hash.hex())
                    channel = Channel(transport, keys, 0)
                    del keys
                    channel.send_data(b"research request")
                    if channel.receive() != (DATA, b"research response"):
                        raise ProtocolError("unexpected demo response")
                    channel.send_close()
                    if channel.receive()[0] != CLOSE:
                        raise ProtocolError("expected authenticated CLOSE")
                    channel.shutdown()
                    return result
                finally:
                    if channel:
                        channel.abort()
                    if transport:
                        transport.close()
                    else:
                        sock.close()

            with ThreadPoolExecutor(max_workers=connections) as servers, ThreadPoolExecutor(max_workers=connections) as clients:
                client_tasks = [clients.submit(client) for _ in range(connections)]
                server_tasks = []
                for _ in range(connections):
                    sock, address = listener.accept()
                    server_tasks.append(servers.submit(serve, sock, address))
                client_results = [task.result(timeout=15) for task in client_tasks]
                for task in server_tasks:
                    task.result(timeout=15)
        if sorted(client_results) != sorted(result[:3] for result in server_results):
            raise ProtocolError("endpoint session/exporter/transcript mismatch")
        if any(result[3] != 1 for result in server_results):
            raise ProtocolError("one-shot decapsulation failed")
        if any(len({result[index] for result in server_results}) != connections for index in (0, 1, 2)):
            raise ProtocolError("connection material reused")
        if admission.active or admission.pending:
            raise ProtocolError("admission not released")
        return {"status": "passed", "connections": connections, "tls": "TLSv1.3",
                "real_exporter_matches": True, "unique_sessions_and_transcripts": True,
                "decapsulations_per_server_key": 1, "authenticated_echo_and_close": True,
                "client_identity_authenticated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connections", type=int, default=2, choices=range(1, 5))
    args = parser.parse_args()
    print(json.dumps(run_demo(args.connections), indent=2))


if __name__ == "__main__":
    main()
