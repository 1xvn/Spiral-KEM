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


SPIRAL_CASES = ("success", "finished-failure")
TLS_ONLY_CASES = ("tls-only-default", "tls-only-aes128", "tls-only-aes256", "tls-only-chacha")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valgrind", default=shutil.which("valgrind"))
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "protocol_rust/target/release/spiral-lab"
    )
    parser.add_argument("--tls-control", type=Path)
    parser.add_argument("--case", choices=SPIRAL_CASES + TLS_ONLY_CASES, help="run only this case")
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
    cases = SPIRAL_CASES + (TLS_ONLY_CASES if args.tls_control else ())
    if args.case:
        if args.case not in cases:
            parser.error("TLS-only cases require --tls-control")
        cases = (args.case,)
    args.output.mkdir(parents=True, exist_ok=True)
    result_path = args.output / "result.json"
    if result_path.exists() or any((args.output / f"{case}.log").exists() for case in cases):
        parser.error("--output already contains results for this run; select a new directory")
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
        for case in cases:
            log = args.output.resolve() / (case + ".log")
            tls_only = case in TLS_ONLY_CASES
            negotiated = {"cipher": None, "protocol": None}

            def observe_tls(cipher, protocol):
                negotiated.update(cipher=cipher, protocol=protocol)

            if tls_only:
                command = [
                    str(args.tls_control.resolve()),
                    str(fixture.folder / "cert.pem"),
                    str(fixture.folder / "key.pem"),
                    case.removeprefix("tls-only-"),
                ]
            else:
                command = fixture.args("server", port=0, connections=1, messages=1)
            process = None
            binary_sha256 = None
            stderr = ""
            report = None
            case_error = None
            try:
                binary_sha256 = hashlib.sha256(Path(command[0]).read_bytes()).hexdigest()
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
                if not select.select([process.stdout], [], [], 45)[0]:
                    raise RuntimeError("instrumented server startup timeout")
                first = process.stdout.readline()
                if not first:
                    raise RuntimeError("instrumented server exited before reporting its listen port")
                port = (
                    int(first)
                    if tls_only
                    else json.loads(first)["listening"]
                )
                if tls_only:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                    tls = TLSTransport(
                        sock,
                        context(ca_file=fixture.folder / "ca.pem"),
                        server_side=False,
                        server_name=NAME,
                    )
                    try:
                        observe_tls(
                            tls.connection.get_cipher_name(),
                            tls.connection.get_protocol_version_name(),
                        )
                        end = time.monotonic() + 10
                        tls.send(b"D" * 120, end)
                        assert tls._read(120, end) == b"D" * 120
                        tls.shutdown(end)
                    finally:
                        tls.close()
                elif case == "finished-failure":
                    with fixture.assertRaises(ProtocolError):
                        fixture.py_client(port, tamper="finished", on_tls_negotiated=observe_tls)
                else:
                    fixture.py_client(port, on_tls_negotiated=observe_tls)
                stdout, stderr = process.communicate(timeout=30)
                if not tls_only:
                    report = json.loads(stdout.strip().splitlines()[-1])
                    assert report["kem"]["live_keys"] == 0
            except Exception as exc:
                case_error = f"{type(exc).__name__}: {exc}"
            finally:
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, 9)
                    except ProcessLookupError:
                        pass
                if process is not None and case_error is not None:
                    _, stderr = process.communicate(timeout=5)

            try:
                contents = log.read_bytes()
            except OSError as exc:
                contents = None
                if case_error is None:
                    case_error = f"{type(exc).__name__}: {exc}"
            match = re.search(rb"ERROR SUMMARY: ([\d,]+) errors", contents or b"")
            errors = int(match[1].replace(b",", b"")) if match else None
            expected = 1 if case == "finished-failure" else 0
            process_exit = process.returncode if process is not None else None
            item = {
                "case": case,
                "binary_sha256": binary_sha256,
                "tls": negotiated,
                "memcheck_log_path": log.name if contents is not None else None,
                "memcheck_log_sha256": hashlib.sha256(contents).hexdigest() if contents is not None else None,
                "process_exit": process_exit,
                "expected_exit": expected,
                "memcheck_errors": errors,
                "passed": case_error is None and process_exit == expected and errors == 0,
                "report": report,
                "stderr": stderr,
            }
            if case_error is not None:
                item["error"] = case_error
            observations.append(item)
            print(json.dumps({k: v for k, v in item.items() if k not in ("report", "stderr")}), flush=True)
    with result_path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(observations, indent=2) + "\n")
    raise SystemExit(not all(x["passed"] for x in observations))


if __name__ == "__main__":
    main()
