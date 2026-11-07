"""Authenticated loopback TLS lifecycle checks using the independent test peer.

These finite scenarios distinguish inner Spiral CLOSE from TLS close_notify and
TCP EOF.  Application write fragmentation is observed at the independent peer;
it does not establish that Rust AsyncWrite returned a short write.  Temporary
credentials stay outside the result document and are removed after the run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import select
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

NAME = "spiral-lab.example"
SERVICE = "spiral-research"
CASE_IDS = (
    "independent_clean_close",
    "independent_fragmented_application_writes",
    "independent_abrupt_tcp_eof",
    "independent_tls_close_notify_without_record",
    "independent_close_without_tls_notify",
    "independent_trailing_after_close",
)
ERROR_LABEL = re.compile(r"(?m)^Error: ([A-Za-z0-9_]+)\s*$")
DIAGNOSTIC_ERROR = re.compile(
    r'(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)'
    r'|runtime error:|LeakSanitizer has encountered|Sanitizer CHECK failed'
    r'|thread .* panicked|[Aa]ssertion.*failed')


def fragmented_parts(raw: bytes, sizes=(1, 2, 7, 29, 31, 127, 1024)) -> list[bytes]:
    """Split a complete record into explicit bounded peer application writes."""
    if not sizes or any(type(size) is not int or size <= 0 for size in sizes):
        raise ValueError("fragment sizes must be positive integers")
    parts = []
    at = 0
    while at < len(raw):
        size = sizes[len(parts) % len(sizes)]
        parts.append(raw[at:at + size])
        at += size
    return parts


def parse_report(stdout: str, stderr: str, exit_code: int, *, clean: bool) -> tuple[dict, str | None]:
    """Require actual server completion and its structured native cleanup result."""
    if DIAGNOSTIC_ERROR.search(stdout + '\n' + stderr):
        raise AssertionError("server sanitizer/panic diagnostic cannot count as an expected rejection")
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise AssertionError("server did not return exactly one final report")
    report = json.loads(lines[0])
    if not isinstance(report, dict) or report.get("status") != ("passed" if clean else "failed"):
        raise AssertionError("server result does not match the lifecycle expectation")
    kem = report.get("kem")
    if (not isinstance(kem, dict) or type(kem.get("live_keys")) is not int
            or kem["live_keys"] != 0 or kem.get("executed_jobs") != 2):
        raise AssertionError("native KEM cleanup or authenticated-job count is missing")
    if clean:
        if exit_code != 0 or stderr.strip():
            raise AssertionError("clean server did not complete successfully")
        if report.get("auth_key_closed") is not True or report.get("admission_released") is not True:
            raise AssertionError("clean server resource release was not observed")
        return report, None
    if exit_code == 0:
        raise AssertionError("invalid shutdown was reported as a clean success")
    labels = ERROR_LABEL.findall(stderr)
    if len(labels) != 1:
        raise AssertionError("failed server did not expose one recognized error result")
    return report, labels[0]


def _server(binary: Path, fixture: Path) -> tuple[subprocess.Popen, int]:
    command = [str(binary), "server", "--name", NAME, "--service", SERVICE,
               "--port", "0", "--connections", "1", "--messages", "1", "--workers", "2",
               "--cert", str(fixture / "cert.pem"), "--key", str(fixture / "key.pem"),
               "--auth", str(fixture / "auth.bin")]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([process.stdout], [], [], 15)[0]:
            raise TimeoutError("server startup watchdog")
        line = process.stdout.readline()
        listening = json.loads(line)
        if (listening.get("loopback_only") is not True
                or type(listening.get("listening")) is not int
                or not 1 <= listening["listening"] <= 65535):
            raise AssertionError("invalid loopback listener report")
        return process, listening["listening"]
    except BaseException:
        _stop(process)
        raise


def _stop(process):
    if process is not None:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def _server_done(process, *, clean: bool):
    # A watchdog expiry raises and fails the case; it is never a rejection.
    stdout, stderr = process.communicate(timeout=6)
    report, error = parse_report(stdout, stderr, process.returncode, clean=clean)
    return report, error, stdout, stderr


def _notify_sent(peer, SSL):
    peer.io(peer.tls.shutdown)
    if not peer.tls.get_shutdown() & SSL.SENT_SHUTDOWN:
        raise AssertionError("peer TLS close_notify was not sent")


def _receive_tls_notify(peer, SSL):
    try:
        value = peer.io(lambda: peer.tls.recv(1))
    except SSL.ZeroReturnError:
        value = b""
    if value:
        raise AssertionError("application bytes appeared after server Spiral CLOSE")
    if not peer.tls.get_shutdown() & SSL.RECEIVED_SHUTDOWN:
        raise AssertionError("server TLS close_notify was not authenticated")


def run_case(binary: Path, fixture: Path, public_key, case_id: str, round_index: int,
             seed: int) -> dict:
    from OpenSSL import SSL
    from protocol_v01.validation.independent_peer import TestPeer

    if case_id not in CASE_IDS:
        raise ValueError("unknown lifecycle case")
    process = peer = None
    started = time.monotonic()
    row = {"id": case_id, "round": round_index, "status": "failed"}
    try:
        process, port = _server(binary, fixture)
        peer = TestPeer(("127.0.0.1", port), fixture / "ca.pem", public_key)
        peer.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        peer.hello()
        peer.finish()
        if len(peer.sid) != 16 or len(peer.h2) != 32 or peer.key is None or peer.peer_key is None:
            raise AssertionError("independent peer did not complete authentication")
        row.update(authenticated=True, session_id=peer.sid.hex(),
                   binding_hash=hashlib.sha256(peer.binding).hexdigest(),
                   transcript_hash=peer.h2.hex())
        rng = random.Random(seed ^ (round_index << 8) ^ CASE_IDS.index(case_id))
        length = 16384 if case_id == CASE_IDS[1] else (1, 64, 1024)[round_index % 3]
        payload = bytes(rng.randrange(256) for _ in range(length))
        if case_id == CASE_IDS[1]:
            raw = peer.record(0x10, payload)
            peer.tx += 1
            parts = fragmented_parts(raw)
            for part in parts:
                peer.send(part)
            row.update(fragmentation_layer="independent TLS application writes",
                       fragment_piece_lengths=[len(part) for part in parts],
                       rust_short_write_observed=False)
        else:
            peer.send_record(0x10, payload)
        if peer.receive_record(0x10) != payload:
            raise AssertionError("authenticated DATA echo differs")
        row.update(authenticated_echo=True, payload_bytes=length)
        clean = case_id in CASE_IDS[:2]
        if clean:
            peer.close_cleanly()
        elif case_id == CASE_IDS[2]:
            if peer.tls.get_shutdown() & SSL.SENT_SHUTDOWN:
                raise AssertionError("abrupt EOF case already sent close_notify")
            peer.close()
            row.update(tcp_closed_without_tls_notify=True, spiral_close_sent=False)
        elif case_id == CASE_IDS[3]:
            _notify_sent(peer, SSL)
            row.update(tls_close_notify_sent=True, spiral_close_sent=False)
        elif case_id == CASE_IDS[4]:
            peer.send_record(0x11, b"\0")
            if peer.receive_record(0x11) != b"\0":
                raise AssertionError("server CLOSE reason")
            _receive_tls_notify(peer, SSL)
            if peer.tls.get_shutdown() & SSL.SENT_SHUTDOWN:
                raise AssertionError("withheld close_notify was sent")
            if peer.closed or peer.socket.fileno() < 0:
                raise AssertionError("withheld-notify TCP must remain open")
            row.update(spiral_close_sent=True, peer_spiral_close_authenticated=True,
                       server_tls_close_notify_authenticated=True,
                       tls_close_notify_sent=False, tcp_held_open=True)
        else:
            close = peer.record(0x11, b"\0")
            peer.tx += 1
            peer.send(close + b"\xff")
            row.update(spiral_close_sent=True, trailing_application_bytes=1,
                       tls_close_notify_sent=False)

        termination_started = time.monotonic()
        report, error, stdout, stderr = _server_done(process, clean=clean)
        termination_seconds = time.monotonic() - termination_started
        if clean:
            if (report.get("role") != "server" or report.get("connections") != 1
                    or len(report.get("sessions", [])) != 1):
                raise AssertionError("clean server session evidence is incomplete")
            session = report["sessions"][0]
            for name in ("session_id", "binding_hash", "transcript_hash"):
                if session.get(name) != row[name]:
                    raise AssertionError("independent and Rust session evidence differs")
            if session.get("authenticated_close") is not True:
                raise AssertionError("clean server did not authenticate CLOSE")
        elif case_id == CASE_IDS[4]:
            # Exposed Closed can mask a timer's Deadline when I/O tasks signal
            # FAILED first. Observe the live TCP and the fixed grace phase too.
            if error not in ("Closed", "Deadline"):
                raise AssertionError("withheld-notify case ended for an unexpected reason")
            if termination_seconds < 1.0:
                raise AssertionError("held-open peer failed before close-grace phase")
            row.update(close_grace_termination_observed=True,
                       direct_deadline_error_observed=error == "Deadline")
        elif error not in ("Closed", "Transport", "Input"):
            raise AssertionError("invalid shutdown did not reject promptly without Deadline")
        row.update(status="passed", server_exit=process.returncode,
                   observed_error=error, server_report=report,
                   server_stdout=stdout, server_stderr=stderr,
                   server_auth_key_closed_observed=report.get("auth_key_closed"),
                   server_admission_released_observed=report.get("admission_released"),
                   termination_seconds=termination_seconds,
                   elapsed_seconds=time.monotonic() - started)
        return row
    finally:
        if peer is not None:
            peer.close()
        _stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261108)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 50 or not 0 <= args.seed <= 2**64 - 1:
        parser.error("rounds1..50 and seed0..2**64-1 are required")
    binary = args.binary.expanduser().resolve()
    output = args.output.expanduser().absolute()
    if not binary.is_file() or not output.parent.is_dir() or output.exists():
        parser.error("binary must exist; output must be a new file in an existing folder")
    result = {"status": "incomplete", "scope": "Real loopback TLS plus independent authenticated peer; finite lifecycle scenarios, no runtime coverage or constant-time claim",
              "rounds": args.rounds, "seed": args.seed, "case_ids": list(CASE_IDS),
              "expected_cases": len(CASE_IDS) * args.rounds, "tests": 0,
              "failures": 0, "errors": 0, "cases": []}
    try:
        from protocol_rust.interop import identities
        with tempfile.TemporaryDirectory(prefix="spiral-tls-lifecycle-") as temporary:
            fixture = Path(temporary)
            signing, _pin = identities(fixture)
            for round_index in range(args.rounds):
                for case_id in CASE_IDS:
                    try:
                        row = run_case(binary, fixture, signing.public_key(), case_id,
                                       round_index, args.seed)
                    except Exception as error:
                        # A watchdog timeout is an error, never evidence of a
                        # rejected message or successful resource cleanup.
                        row = {"id": case_id, "round": round_index, "status": "failed",
                               "error_type": type(error).__name__, "error": str(error)}
                        result["failures"] += 1
                    result["cases"].append(row)
                    result["tests"] += 1
                    print("LIFECYCLE_PEER_CASE " + json.dumps(row), flush=True)
        result["status"] = "passed" if result["failures"] == 0 and result["tests"] == result["expected_cases"] else "failed"
    except Exception as error:
        result.update(status="failed", error_type=type(error).__name__, error=str(error))
        result["errors"] += 1
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key:result[key] for key in ("status", "tests", "failures", "errors")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
