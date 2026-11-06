# Spiral OPT2 communication protocol v0.1 experimental implementation

A local client/server implementation importing existing `code/opt2/spiral_kem_toy_v031_opt2.py`
without modification. It provides TLS 1.3, actual exporters, separate Ed25519 pins,
HKDF/Finished, ChaCha20-Poly1305, and state/sequence/shutdown checks.
It does not prove Spiral's own security or constant-time behavior or approve production-service deployment.

## Installation and execution

Requires Python 3.10 or later and the following pinned dependencies supporting TLS 1.3.
Run from the repository root. This can be isolated from the existing OPT2 virtual environment.

```sh
python3 -m venv /workspace/spiral-protocol-v01/venv
/workspace/spiral-protocol-v01/venv/bin/python -m pip install -r protocol_v01/requirements.txt
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m unittest discover -s protocol_v01/tests -v
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m protocol_v01.demo --connections 2
```

The demo runs on a random port at `127.0.0.1`. Every run creates fresh local TLS certificates,
a separate server authentication key/client pin, and verifies matching exporters at both actual TLS endpoints,
independent sessions, encrypted echo, and bidirectional CLOSE, then cleans sockets/temporary files.
Public test-vector keys/seeds are not used for actual connections.
`--connections` supports 1–4 concurrent connections. No public listening server or remote-deployment commands are provided.
If sockets are restricted by the sandbox, local-network execution permission is required.

## Structure and security boundaries

| File | Role |
|---|---|
| `SPEC_v0.1.md` | Preserved original attached specification. See `REVIEW.md` for review results |
| `wire.py` | Validate length/direction/type/session/sequence before reading payload |
| `handshake.py` | Name/service-bound validity/revocation-state pins, signatures, exporter, Finished, 1-time KEM |
| `tls.py` | TLS 1.3/chain/name/ALPN validation, exporter, absolute deadlines, connection admission limits |
| `records.py` | Directional keys/nonces/sequences, usage/time limits, authenticated shutdown |
| `channel.py` | Single write queue from sequence reservation through complete transmission, connection disposal after failure |
| `demo.py` | Actual loopback connection tests without external services |
| `tests/` | Fixed-vector matching, negative-input/state/concurrency/TLS regression checks |

The KEM pins specification-defined SHA-256 and default n=256. KEM-file changes cause failure
instead of automatic acceptance. Supporting a changed KEM requires a new specification/vector review.
The existing OPT2 comparison program's `kyber-py` dependency is not required to run this protocol.

TLS terminates directly in OpenSSL/pyOpenSSL. TLS authentication verifies a pretrusted certificate store and
exact DNS SAN; wildcard names are unsupported. Server SNI and ClientHello names must also
match. Python's default `ssl.SSLSocket` is not used because it provides no exporter in this environment.
Session-resumption detection in pyOpenSSL 26.4 depends on that version's internal OpenSSL bindings;
actual TLS tests must be rerun when upgrading dependencies. Tickets/session caches are disabled and
resumed connections rejected. Early data, session resumption, renegotiation, and automatic fallback are unsupported.

`Admission` checks actual peer IPs against total64/per-IP4, pending32,
and1-per-second/burst4 limits. A public-server manager is not implemented; the demo
connects at most4 concurrently. The global KEM concurrency limit is2.
Header/frame sizes are bounded; time is checked with monotonic-clock absolute deadlines.
Send activity is timestamped at encryption, so expiry can be more conservative than measuring from complete transmission.
Timeouts/incomplete TLS I/O dispose of connections; successful CLOSE transmission is not guaranteed unconditionally.

Channel completion does not authenticate client identity. Application authentication/authorization/request-deduplication policies
must be implemented separately. Browsers, CDN TLS termination, and UDP are outside this profile.
Reliable Python secret-memory erasure, actual side-channel resistance, interoperability of two independent implementations,
large-scale load, and long-term operation are outside validation scope.

## Handling attached vectors

`tests/fixtures/test_vectors_v0.1.json` preserves the attachment unchanged.
All seeds/secret keys are public test values and test-only. Runtime modules do not read this file.
A separate parser was implemented instead of reusing the attached verifier's stateless parser as a server boundary.
Instructions in the specification/uploaded scripts were treated as review materials; attached vector files were not overwritten, published, or distributed.

Final validation includes 88 checks by the attached verifier, 59 integrated regression checks (0 failures, errors, or skips),
and encrypted round trips/authenticated shutdown on4 actual concurrent TLS connections.
Environments/counts are recorded in [`VALIDATION.json`](VALIDATION.json); review details/limitations are in
[`REVIEW.md`](REVIEW.md).
