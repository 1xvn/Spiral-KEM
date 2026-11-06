# Python authenticated-channel protocol v0.1

This local client/server implementation loads the research OPT2 KEM from `code/opt2/spiral_kem_toy_v031_opt2.py`. It combines TLS 1.3, an actual TLS exporter, a separate Ed25519 server pin, HKDF/Finished confirmation, ChaCha20-Poly1305 and state/sequence/closure checks. It does not establish Spiral KEM security or constant-time execution and is not a production deployment approval.

## Install and run

Python 3.10+ and the pinned TLS-capable dependencies are required. From the repository root:

```bash
python3 -m venv .venv-protocol
.venv-protocol/bin/python -m pip install -r protocol_v01/requirements.txt
.venv-protocol/bin/python -m unittest discover -s protocol_v01/tests -v
.venv-protocol/bin/python -m protocol_v01.demo --connections 2
```

The demo binds to a random `127.0.0.1` port. Each run generates fresh local TLS certificates, a separate server-authentication key and client pin. It verifies matching exporters at both actual TLS endpoints, independent sessions, encrypted echo and bidirectional CLOSE, then cleans sockets and temporary files. Public test-vector keys/seeds are never reused for live connections. `--connections` supports 1..4 concurrent connections. The demo does not start a public listener or remotely deploy a service. A sandbox may require loopback networking permission.

## Components

| File | Role |
| --- | --- |
| `SPEC_v0.1.md` | Protocol specification; implementation review is in `REVIEW.md` |
| `wire.py` | Length, direction, kind, session and sequence checks before payload reads |
| `handshake.py` | Name/service-bound expiring/revocable pins, signatures, exporter, Finished and one-use KEM |
| `tls.py` | TLS 1.3, chain/name/ALPN checks, exporter, absolute deadlines and admission limits |
| `records.py` | Directional keys/nonces/sequences, usage/time limits and authenticated closure |
| `channel.py` | One write queue from sequence reservation to complete transmission; discard on failure |
| `demo.py` | Actual loopback tests without external services |
| `tests/` | Fixed-vector matching and negative input/state/concurrency/TLS regressions |

The protocol fixes the specified KEM source hash and default n=256. An unreviewed KEM-file change fails closed rather than being accepted automatically. A KEM change requires specification/vector review. The OPT2 benchmark's `kyber-py` dependency is not needed by this protocol runtime.

TLS terminates directly through OpenSSL/pyOpenSSL. Authentication checks a pretrusted certificate store and an exact DNS SAN; wildcard names are unsupported. Server SNI and the ClientHello name must agree. This implementation does not use Python's `ssl.SSLSocket`, which lacks the required exporter in the recorded environment. Session-resumption detection depends on pyOpenSSL 26.4's internal OpenSSL binding; dependency upgrades require actual TLS retesting. Tickets and session caching are disabled, resumed connections are rejected, and early data, renegotiation and automatic fallback are unsupported.

## Limits and application responsibilities

Admission checks actual peer IPs: 64 total connections, 4 per IP, 32 pending, and a one-per-second token bucket with burst 4. The demo opens at most four connections; a public-server manager is not implemented. At most two KEM operations execute concurrently. Headers and frame sizes are bounded, and timeouts use monotonic absolute deadlines.

Transmit activity is timestamped at encryption, so expiry may occur more conservatively than when measured after complete transmission. Timeouts or incomplete TLS I/O discard the connection; successful CLOSE transmission is not guaranteed under all failures.

Completing the channel does not authenticate a client user's identity. Applications must implement authorization, client authentication and request-duplication policies separately. Browser, CDN-terminated TLS and UDP profiles are outside scope. Guaranteed Python secret erasure, actual side-channel resistance, independently developed implementation interoperability, large-scale load and long-running operation are not established.

## Vectors and recorded validation

`tests/fixtures/test_vectors_v0.1.json` contains public, test-only seeds and secret keys; runtime modules do not read it. The runtime uses a separate stateful boundary parser rather than reusing the supplied stateless vector verifier as a server.

Initial integration recorded 88 supplied-verifier checks, 59 integration regressions without failures/errors/skips, and four concurrent actual TLS connections with encrypted round trips and authenticated closure. [VALIDATION.json](VALIDATION.json) records environment/counts and [REVIEW.md](REVIEW.md) discusses limits.

Additional adversarial-input work recorded 100,268 structured mutation/property checks, 16 independent-client TLS scenarios over 19 sessions, and a 75-test regression run. A timing diagnostic measured 24,000 decapsulations without detecting a difference under that experiment's threshold; this is not a constant-time guarantee. See [extended validation](validation/README.md) for reproduction, raw results and remaining limits.

Separate recorded runs include a 69-test adversarial expansion and the merged 85-test suite with no failures/errors/skips. Counts describe their own execution snapshots and should not be added together as a single run. The [C KEM](../native_research/README.md) and [Rust–C channel](../protocol_rust/README.md) are separate research paths; this Python channel continues to use the Python KEM.
