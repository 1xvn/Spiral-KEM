# Spiral OPT2 Rust–C Communication Implementation v0.3

An executable research implementation connecting the Rust/Tokio/rustls communication layer to the existing C KEM.
The wire format is v0.1, identical to the existing Python `protocol_v01`; tests exercise actual TLS communication with Rust↔Python in both roles.
v0.2 in the design document does not indicate a wire version change.

Added opaque signing-key ownership, a simultaneous-shutdown bug fix, negative-test coverage, and secret-branch instrumentation.
Changes and remaining limitations are in the [v0.3 implementation report](HARDENING_v0.3.md), actual results in the [validation record](VALIDATION.md), and remeasurement commands in the [Ubuntu/WSL guide](RUN_UBUNTU_WSL.md).

The [2026-11-07 memory follow-up record](MEMORY_FOLLOWUP.md) adds user OCI/WSL results, controls investigating local AES-GCM warnings, and independent reproduction code. Production code and original memory-check verdicts are retained.

The [Rust frame and ClientHello fuzzing guide](FUZZ_PARSERS.md) uses a separately pinned nightly and
the disabled-by-default `parser-fuzz` entry points to check actual parser coverage and compare saved inputs
against the Python reference implementation. OCI ARM64 and WSL2 x86-64 results are collected separately.

The [Rust DATA/CLOSE state fuzzing guide](FUZZ_RECORDS.md) uses the disabled-by-default
`record-fuzz` entry points to compare sequence numbers, limits, tampering rejection, and post-shutdown state of actual `Tx`/`Rx`
against an independent model. It uses the same pinned nightly, and OCI/WSL execution results are
collected separately from the preceding parser checks. The submitted OCI 17,380 runs and WSL 34,543 runs and
rechecks of 702/702 and 718/718 saved inputs passed.

The [channel and TLS lifecycle check guide](LIFECYCLE.md) separately checks channel-loop tests combining partial writes, cancellation, simultaneous shutdown, and
timeouts, and the shutdown and resource release of actual authenticated TLS connections.
It uses the same pinned nightly and an independent Python peer, with separate runs on OCI and WSL.
run each separately.

## Quick start

Local v0.3 validation used Debian 13 x86-64, glibc 2.41, OpenSSL 3.5.7, Rust 1.99.1, and Python 3.12.14.
Build from source and check on each new target environment. Subsequently collected OCI ARM/WSL Ubuntu 24.04 memory-check results are in the follow-up record above.
On Windows, use Ubuntu 24.04 under WSL. Native Windows builds have not been validated.
Source builds require Rust 1.99 or later, a C11 compiler, OpenSSL development packages, and a Python venv.

```sh
# Required system packages on Ubuntu 24.04 / WSL
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev python3-venv

# Install Rust: https://rustup.rs
# Run from the repository root
bash protocol_rust/run_local.sh
```

The executable bundle ZIP includes the tested Linux x86-64 binary. To skip the source build in the same execution environment:

```sh
bash protocol_rust/run_local.sh --prebuilt
```

The prebuilt file is `bin/linux-x86_64/spiral-lab`. It was built on Debian 13 x86-64; ELF symbol requirements are at most GLIBC_2.34 and OPENSSL_3.0.0.
This file cannot be used on ARM. A normal source build is recommended on target Ubuntu/WSL systems; this binary has not completed full OS compatibility validation.
Build outputs are not committed to the Git repository. Use normal build commands for source checkouts without binaries.

The script installs pinned Python dependencies in a separate venv and runs tests.
It generates a fresh test CA, server certificate, separate Ed25519 authentication key, and pin in a private temporary directory for each run, then deletes them on exit.
TLS certificate and authentication-key test vectors are not reused for actual connections. Listening and connecting are restricted to `127.0.0.1`.
No actual service addresses or accounts are used.

## Implemented structure

| File | Role |
|---|---|
| `src/ffi.rs` | Sole direct-call boundary for the four reviewed C APIs. Key pointers cannot implement Send/Sync/Copy/Clone |
| `src/worker.rs` | Fixed workers, 32 running plus queued jobs, 32 stored keys, cancellation/deadline/lease management |
| `src/identity.rs` | Server signing-key owner exporting only the public key; revocation of shared references and serialization of signing/close |
| `src/secret.rs` | Fixed-size secret buffers, unexposed key bytes, explicit Drop zeroization |
| `src/buffer.rs` | At most 18 buffers per connection, 16,440 bytes each; waiting, reuse, and full-capacity zeroization before return |
| `src/wire.rs` | 40-byte header and canonical frames; length/role/session/sequence checks before reading payload |
| `src/schedule.rs` | Key schedule preserving existing SHA-256/HMAC/HKDF labels and transcript |
| `src/handshake.rs` | Name/purpose/exporter/validity/revocation-state pin, signature, and both Finished checks |
| `src/transport.rs` | TLS 1.3 only, actual exporter, ALPN/SNI/exact DNS SAN/trust-chain checks |
| `src/records.rs` | Rust AEAD, 1-time sequence reservation per direction, authenticated CLOSE, record/byte limits |
| `src/channel.rs` | One task per direction, 8 app queue slots each, preservation of partial-I/O progress and absolute deadlines |
| `src/admission.rs` | 64 active / 4 per IP / 32 pending / per-IP token bucket and cleanup |
| `src/main.rs` | Loopback-only client/server runner and public aggregate results |
| `interop.py` | Python↔Rust and Rust↔Rust actual TLS, tampering, and overload tests |
| `benchmark.py` | TLS round trips and peak RSS by worker/payload under fixed conditions |

Only a handshake-verified `Established` can open a data session with `start()`.
No constructor lets external apps open sessions by combining arbitrary SessionKeys and Transport.
Server session IDs are retained to prevent duplication among active connections and released at shutdown.
Client user-identity authentication is a separate application procedure.

C secret keys are decapsulated and freed on the worker that created them. Pointers are not sent to network tasks.
A worker is not occupied while awaiting a network response after keygen. Dropping a lease requests cleanup through a shared cancellation flag.
The cleanup flag is delivered even when the queue is full. Running C functions are not forcibly interrupted; buffers are cleaned after the job finishes.

There are no direct C KEM calls in the data path. Each direction owns one sequence and key, without re-encryption or sequence rollback after AEAD.
After writing fully to the socket, the code flushes and handles the next frame. Notifications received while waiting do not lose partial-header, payload, or transmission progress.
Once record I/O starts, activity in the opposite direction does not keep extending its deadline.

App queues have 8 slots per direction; the normal buffer pool is 18×16,440=295,920 bytes.
Received CLOSE uses a separate buffer of at most 57 bytes, and transmitted CLOSE uses a fixed 57-byte array, reducing the effect of normal-buffer saturation.
This figure is not a process memory bound covering TLS, kernel, provider, threads, or objects.
If the app retains received `Plaintext`, its buffer does not return to the pool. Drop it after use.
The application is responsible for managing lifetimes of any additional original-text, String, or Vec copies it creates.

`Sender::send(&[u8])` copies once after obtaining a queue slot. Receiving transfers buffer ownership and a view to the app.
Queued sends may already be transmitted even if the caller's waiting future is canceled. Apps should not automatically resend the same request after a lost response; use separate request IDs and duplicate-handling rules when needed.
No end-to-end zero-copy claim is made. The default prioritizes latency with a flush per frame and yields to the executor every four records.
Keys and plaintext are not logged. Output consists of local test aggregates such as session IDs, transcript/binding hashes, latency, and job counts.

## Key lifetimes and cryptographic implementation

- The server Ed25519 authentication key is owned by `ServerIdentity`. `Arc` shares the original owner; `close()` revokes all shared references after in-progress signing completes. Raw-key and arbitrary-signing APIs are not exposed externally.
- C KEM secret keys are zeroized and freed during success, failure, and cancellation cleanup.
- All callers of `KemPool::shutdown()` await the same worker join result. Cancellation of the first waiter does not cause other callers to return early.
- `ss` is output directly into a Rust heap secret buffer and zeroized after PRK derivation.
- PRK, Finished keys, and application master are zeroized by Drop after their final use.
- Directional data keys are tied to the corresponding record-state lifetime. The ChaCha20Poly1305 key state also provides Drop zeroization.
- Plaintext pool buffers have their full capacity wiped with `zeroize` before return. Secret types provide no Copy/Clone/content Debug.

No claim is made that all temporary state inside HKDF/HMAC, signing, or TLS providers, registers, previous copies, swap, or core dumps is erased.
mlock and dump-exclusion policies are outside this implementation. FFI operates in the same process and does not isolate C faults.
Proofs of cryptographic security, constant-time behavior, and forward secrecy, and production-service approval require separate review.

Default parameters, SKW1, authentication transcript, HKDF, ALPN, and exporter labels remain v0.1.
Early data, session resumption, and automatic fallback are disabled; TLS KeyUpdate does not reset Spiral counters.
The build verifies C source and header SHA-256 hashes and statically links only production APIs. OpenSSL 3 uses the system dynamic library.

## Tests and measurements

```sh
cargo test --locked --manifest-path protocol_rust/Cargo.toml
cargo clippy --all-targets --locked --manifest-path protocol_rust/Cargo.toml -- -D warnings
cargo build --release --locked --manifest-path protocol_rust/Cargo.toml

# In an environment with Python dependencies installed
python3 protocol_rust/adversarial.py --binary protocol_rust/target/release/spiral-lab --json protocol_rust/local_validation.json
python3 protocol_rust/benchmark.py --binary protocol_rust/target/release/spiral-lab --output protocol_rust/local_benchmark.json
```

Checks that signatures, h0/h1/h2, keys, and DATA/CLOSE match the existing public vectors.
Checks truncated frames, header-bit tampering, a reproducible 4,096-mutation corpus, ciphertext tampering, tampering with every Finished byte,
duplicates, reversed order, excessive lengths, reserved CLOSE sequence numbers, key expiry, queue saturation, cancellation, and partial I/O.
Public-API session-construction restrictions and native-key Send/Sync/Copy/Clone prohibitions are also checked at compile time.
Each test method contains multiple input cases. Parser acceptance is not counted as successful cryptographic authentication.

Interoperability tests use four connections each for Python→Rust and Rust→Python and four Rust↔Rust connections, with 64B/1KiB/16KiB,
eight senders, and 32 messages. They check actual exporters/transcripts at both ends, session independence, and normal/abnormal shutdown.
Bursts of 16/64 connections from the same IP are rejection/cleanup tests, not capacity tests of 16/64 successful connections.

The Python baseline for basic functional regression is 85 tests. Rust unit 52 + compile-fail 6 and 35 actual TLS negative/interoperability tests are recorded separately. See the separate guidance and evidence above for the latest subsequent fuzzing results.
The [mapping](REGRESSION_MAP.md) distinguishes 72 requirements with execution tests, 8 addressed structurally, and 5 with different API/test scope.
See `VALIDATION.json` and `evidence/` for final environments, counts, check logs, and performance figures.
The initial v0.3 validation bundle excludes coverage-guided fuzzing, long soaks, validation on other OS/CPU combinations, and independent code audits. Follow-up fuzzing and platform validation are recorded separately at the links above.

`examples/tls_control.rs` is TLS-only diagnostic code for distinguishing memory-check warnings. It does not run Spiral or C KEM and is not used as a runtime algorithm fallback.

**Memory validation status:** On 11/6, v0.3 normal TLS communication failed with 4 Valgrind errors in release and 6 in audit. TLS-only controls had 4 each for default/AES128/AES256 and 0 for ChaCha. Separately, 6,102 public AEAD/offset-buffer/hash/HKDF/signature vector cases matched OpenSSL/Python with 0 warnings. The 11/7 follow-up confirmed 6 user OCI passes and 2 WSL passes and isolated the definedness false-positive mechanism in local GHASH copies, branches, and XOR. The original WSL failure was not changed to a pass. See `MEMORY_FOLLOWUP.md` for evidence and scope.
Rust secret-branch instrumentation produced 0 secret-dependent branch/address warnings in inspected operations, but a 48-byte possibly-lost entry points to libtest thread state, so the full memory check remains failed. C branch instrumentation and memory checks passed. See `VALIDATION.md` for detailed scope and logs. The default cipher was not changed and warnings were not suppressed.

To reproduce optional memory checks, install Valgrind and Python test dependencies, then run. The script exits with failure if the unresolved warnings above recur.

```sh
cargo build --release --examples --bins --locked --manifest-path protocol_rust/Cargo.toml
python3 protocol_rust/memcheck.py --tls-control protocol_rust/target/release/examples/tls_control
```

Benchmarks use workers 1/2/4, payloads 64/1,024/16,384, four connections, 32 echoes per connection, and 8 sending producers.
Each profile measures five rounds by default (20 connection samples) after two warm-up rounds. Experimental processes restart for every round.
TLS, Spiral, and app-delivery time are distinguished from total payload throughput including process startup/shutdown.
When GNU time is available, per-process peak RSS is also collected. These are small local samples, not production capacity measurements or a ranking of languages.

## Running directly

Inputs created by `interop.py`'s `identities()` have the following formats.

- `ca.pem`: pretrusted test CA.
- `cert.pem`, `key.pem`: TLS server certificate chain and PKCS#8 key.
- `auth.bin`: 32-byte seed for the separate server Ed25519 authentication key. A secret file created with mode 0600.
- `pin.json`: independently delivered server authentication public key, name, purpose, start/end times, and revocation state.

Pins are not created by simply trusting values sent by the server during a connection.
Do not copy local test keys into service use.

```sh
protocol_rust/target/release/spiral-lab server --name spiral-lab.example --service spiral-research --port 0 --connections 1 --messages 1 --workers 2 --cert cert.pem --key key.pem --auth auth.bin
# Use the listening port printed by the server
protocol_rust/target/release/spiral-lab client --name spiral-lab.example --service spiral-research --port PORT --connections 1 --messages 1 --payload 64 --pipeline 1 --workers 2 --ca ca.pem --pin pin.json
```

The previous original design is preserved in `ARCHITECTURE_v0.2.md`. Its 'before implementation' status describes that time; this README describes the current implementation scope.

v0.2 evidence is preserved in `evidence/`. New v0.3 evidence is in `evidence/v03/`; hashes before and after removing trailing whitespace from logs are recorded in that folder's `LOG_FORMATTING.json`.
