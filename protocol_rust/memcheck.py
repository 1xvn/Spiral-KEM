"""Optional Valgrind loopback checks, including a TLS-only diagnostic control.

No errors are suppressed. This does not prove erasure or constant-time execution.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import tempfile
import time
import interop
from interop import Interop, NAME, ROOT, TLSTransport, context
from protocol_v01.wire import ProtocolError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valgrind", default=shutil.which("valgrind"))
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "protocol_rust/target/release/spiral-lab"
    )
    parser.add_argument("--tls-control", type=Path)
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--library-path", type=Path)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "protocol_rust/local_memcheck"
    )
    args = parser.parse_args()
    if not args.valgrind or not args.binary.is_file():
        parser.error("Valgrind and a built spiral-lab binary are required")
    if bool(args.loader) != bool(args.library_path):
        parser.error("loader and library-path must be supplied together")
    args.output.mkdir(parents=True, exist_ok=True)
    prefix = (
        [str(args.loader), "--library-path", str(args.library_path)]
        if args.loader
        else []
    )
    interop.BINARY = args.binary.resolve()
    observations = []
    with tempfile.TemporaryDirectory(prefix="spiral-memcheck-") as temp:
        # Interop's helper asserts echoed bytes and authenticated CLOSE as well.
        fixture = Interop("test_client_finished_rejected")
        fixture.folder = Path(temp)
        fixture.signing, fixture.pin = interop.identities(fixture.folder)
        cases = ["success", "finished-failure"]
        if args.tls_control:
            cases += [
                "tls-only-default",
                "tls-only-aes128",
                "tls-only-aes256",
                "tls-only-chacha",
            ]
        for case in cases:
            log = args.output.resolve() / (case + ".log")
            if case.startswith("tls-only-"):
                command = [
                    str(args.tls_control.resolve()),
                    str(fixture.folder / "cert.pem"),
                    str(fixture.folder / "key.pem"),
                    case.removeprefix("tls-only-"),
                ]
            else:
                command = fixture.args("server", port=0, connections=1, messages=1)
            process = subprocess.Popen(
                [
                    str(args.valgrind),
                    "--error-exitcode=99",
                    "--track-origins=yes",
                    "--leak-check=full",
                    "--show-leak-kinds=all",
                    "--errors-for-leak-kinds=definite,possible",
                    f"--log-file={log}",
                    *prefix,
                    *command,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                if not select.select([process.stdout], [], [], 45)[0]:
                    raise RuntimeError("instrumented server startup timeout")
                first = process.stdout.readline()
                if not first:
                    raise RuntimeError(process.communicate(timeout=5))
                port = (
                    int(first)
                    if case.startswith("tls-only-")
                    else json.loads(first)["listening"]
                )
                if case.startswith("tls-only-"):
                    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                    tls = TLSTransport(
                        sock,
                        context(ca_file=fixture.folder / "ca.pem"),
                        server_side=False,
                        server_name=NAME,
                    )
                    try:
                        end = time.monotonic() + 10
                        tls.send(b"D" * 120, end)
                        assert tls._read(120, end) == b"D" * 120
                        tls.shutdown(end)
                    finally:
                        tls.close()
                elif case == "finished-failure":
                    with fixture.assertRaises(ProtocolError):
                        fixture.py_client(port, tamper="finished")
                else:
                    fixture.py_client(port)
                stdout, stderr = process.communicate(timeout=30)
                report = None
                if not case.startswith("tls-only-"):
                    report = json.loads(stdout.strip().splitlines()[-1])
                    assert report["kem"]["live_keys"] == 0
                contents = log.read_text()
                match = re.search(r"ERROR SUMMARY: ([\d,]+) errors", contents)
                errors = int(match[1].replace(",", "")) if match else None
                expected = 1 if case == "finished-failure" else 0
                item = {
                    "case": case,
                    "binary_sha256": hashlib.sha256(
                        Path(command[0]).read_bytes()
                    ).hexdigest(),
                    "process_exit": process.returncode,
                    "expected_exit": expected,
                    "memcheck_errors": errors,
                    "passed": process.returncode == expected and errors == 0,
                    "report": report,
                    "stderr": stderr,
                }
                observations.append(item)
                print(
                    json.dumps(
                        {k: v for k, v in item.items() if k not in ("report", "stderr")}
                    ),
                    flush=True,
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, 9)
                process.communicate(timeout=5)
    (args.output / "result.json").write_text(json.dumps(observations, indent=2) + "\n")
    raise SystemExit(not all(x["passed"] for x in observations))


if __name__ == "__main__":
    main()
