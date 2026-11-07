"""Real-TLS negative tests against Rust, including a separately written peer.

The independent peer implements framing, transcript, schedule and records from
the v0.1 spec; it shares only KEM/crypto primitives. All traffic is loopback.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from OpenSSL import SSL
import interop
from interop import Interop, ROOT, NAME, context, TLSTransport, identities
from protocol_v01.validation.independent_peer import TestPeer, PeerRejected, header
from protocol_v01.wire import ProtocolError


class RustAdversarial(Interop):
    """Also inherits the original 15 interop methods; no Python server substitute."""

    def peer(self, **server_args):
        process, port = self.rust_server(connections=1, **server_args)
        peer = TestPeer(
            ("127.0.0.1", port), self.folder / "ca.pem", self.signing.public_key()
        )
        self.addCleanup(peer.close)
        return peer, process

    def closed_without_protocol_output(self, peer):
        # A timeout is not an accepted rejection. Unexpected output fails, too.
        try:
            value = peer.read_exact(1)
        except (SSL.Error, OSError, EOFError):
            return
        self.fail(f"unexpected protocol output before rejection: {value.hex()}")

    def rejected(self, process, *, jobs):
        stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0, (stdout, stderr))
        self.assertNotIn(
            "Deadline", stderr, "timeout cannot count as protocol rejection"
        )
        report = json.loads(stdout.strip().splitlines()[-1])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["kem"]["live_keys"], 0)
        self.assertEqual(report["kem"]["executed_jobs"], jobs)
        self.observations.append(
            {
                "scenario": self.id().split(".")[-1],
                "expected_jobs": jobs,
                "report": report,
            }
        )

    def test_independent_peer_boundary_data_and_authenticated_close(self):
        peer, server = self.peer(messages=2)
        peer.hello()
        peer.finish()
        for payload in (b"x", bytes(range(256)) * 64):
            peer.send_record(0x10, payload)
            self.assertEqual(peer.receive_record(0x10), payload)
        binding = hashlib.sha256(peer.binding).hexdigest()
        transcript = peer.h2.hex()
        peer.close_cleanly()
        report = self.report(server)
        self.assertEqual(report["sessions"][0]["binding_hash"], binding)
        self.assertEqual(report["sessions"][0]["transcript_hash"], transcript)
        self.assertEqual(report["kem"]["executed_jobs"], 2)

    def test_independent_new_connections_change_exporter_session_and_kem_key(self):
        seen = []
        for _ in range(3):
            peer, server = self.peer(messages=1)
            peer.hello()
            peer.finish()
            seen.append(
                (peer.sid, peer.binding, hashlib.sha256(peer.sh[108:916]).digest())
            )
            peer.send_record(0x10, b"unique")
            self.assertEqual(peer.receive_record(0x10), b"unique")
            peer.close_cleanly()
            self.report(server)
        for column in zip(*seen):
            self.assertEqual(len(set(column)), 3)

    def test_independent_wrong_binding_rejected_before_keygen(self):
        peer, server = self.peer(messages=1)
        with self.assertRaises((PeerRejected, SSL.Error, OSError, EOFError)):
            peer.hello(binding=bytes(32))
        peer.close()
        self.rejected(server, jobs=0)

    def test_independent_wrong_service_rejected_before_keygen(self):
        peer, server = self.peer(messages=1)
        peer.service = "unregistered-service"
        with self.assertRaises((PeerRejected, SSL.Error, OSError, EOFError)):
            peer.hello()
        peer.close()
        self.rejected(server, jobs=0)

    def test_independent_untrusted_signing_pin_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        peer, server = self.peer(messages=1)
        peer.auth_public = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(PeerRejected):
            peer.hello()
        peer.close()
        self.rejected(server, jobs=1)

    def test_independent_forged_client_finished_never_establishes(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.send(peer.client_key(bad_cf=True))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_canonical_changed_ciphertext_never_establishes(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.send(peer.client_key(alter_ct=True))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_early_data_never_decapsulates(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.send(header(0x10, 0, peer.sid, 0, 17) + bytes(17))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=1)

    def test_independent_previous_session_clientkey_is_rejected(self):
        old, first = self.peer(messages=1)
        old.hello()
        old.finish()
        previous = old.ck
        old.send_record(0x10, b"first")
        self.assertEqual(old.receive_record(0x10), b"first")
        old.close_cleanly()
        self.report(first)
        peer, server = self.peer(messages=1)
        peer.hello()
        self.assertNotEqual(peer.sid, previous[12:28])
        peer.send(previous)
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=1)

    def test_independent_duplicate_clientkey_never_decapsulates_twice(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        peer.send(peer.ck)
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_skipped_sequence_has_no_delivery(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        peer.send(peer.record(0x10, b"skipped", seq=1))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_valid_record_replay_delivers_only_once(self):
        peer, server = self.peer(messages=2)
        peer.hello()
        peer.finish()
        raw = peer.send_record(0x10, b"once")
        self.assertEqual(peer.receive_record(0x10), b"once")
        peer.send(raw)
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_bad_tag_has_no_delivery(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        raw = peer.record(0x10, b"bad tag")
        peer.send(raw[:-1] + bytes([raw[-1] ^ 1]))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_wrong_direction_has_no_delivery(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        raw = bytearray(peer.record(0x10, b"direction"))
        raw[7] = 1
        peer.send(bytes(raw))
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_independent_truncated_clientkey_never_decapsulates(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.send(peer.client_key()[:80])
        peer.close()
        self.rejected(server, jobs=1)

    def test_independent_eof_without_authenticated_close_is_not_clean(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        peer.close()
        self.rejected(server, jobs=2)

    def test_tls12_is_rejected_before_inner_kem(self):
        server, port = self.rust_server(connections=1, messages=1)
        ctx = context(ca_file=self.folder / "ca.pem")
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with self.assertRaises(ProtocolError):
            TLSTransport(sock, ctx, server_side=False, server_name=NAME)
        self.rejected(server, jobs=0)

    def test_invalid_server_signature_rejected_before_encapsulation(self):
        import subprocess

        port, server = self.python_server(1, 1, tamper="signature")
        client = subprocess.Popen(
            self.args("client", port=port),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.kill, client)
        self.rejected(client, jobs=0)
        self.assertEqual(server.result(timeout=20), [None])

    def test_independent_authenticated_unknown_close_reason_is_rejected(self):
        peer, server = self.peer(messages=1)
        peer.hello()
        peer.finish()
        peer.send_record(0x11, b"\x03")
        self.closed_without_protocol_output(peer)
        peer.close()
        self.rejected(server, jobs=2)

    def test_expired_tls_certificate_is_rejected_before_inner_kem(self):
        import subprocess

        with tempfile.TemporaryDirectory(prefix="spiral-expired-tls-") as tmp:
            self.folder = Path(tmp)
            now = datetime.now(timezone.utc)
            self.signing, self.pin = identities(
                self.folder,
                leaf_validity=(now - timedelta(hours=2), now - timedelta(hours=1)),
            )
            server, port = self.rust_server(connections=1, messages=1)
            client = subprocess.Popen(
                self.args("client", port=port),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(self.kill, client)
            self.report(client, False)
            self.rejected(server, jobs=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "protocol_rust/target/release/spiral-lab"
    )
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    interop.BINARY = args.binary.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RustAdversarial)
    )
    summary = {
        "schema": "spiral-rust-adversarial/v0.3",
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "observations": RustAdversarial.observations,
    }
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps({k: v for k, v in summary.items() if k != "observations"}),
        flush=True,
    )
    raise SystemExit(not result.wasSuccessful())
