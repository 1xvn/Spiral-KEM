# Rust–C authenticated channel

This research implementation connects the C Spiral KEM to a Rust/Tokio/rustls transport. It uses the same protocol v0.1 wire format as the [Python implementation](../protocol_v01/README.md), with actual Rust↔Python and Rust↔Rust TLS tests. The architecture document's v0.2 designation is a design revision, not a wire-version change.

The channel combines TLS 1.3 authentication and exporter binding with a separate Ed25519 server identity, KEM exchange, HKDF, Finished confirmation, directional AEAD records, sequence limits and authenticated closure. It does not establish Spiral KEM's cryptographic security, supply application-level client authentication, or authorize production deployment.

## Build and run

The recorded local v0.3 validation used Debian 13 x86-64, glibc 2.41, OpenSSL 3.5.7, Rust 1.99.1 and Python 3.12.14. OCI ARM64 and WSL Ubuntu 24.04 results are documented separately. Windows native builds have not been validated; use WSL for the documented Windows workflow.

Source builds require Rust 1.99+, a C11 compiler, OpenSSL development headers and Python venv support. On Ubuntu 24.04 / WSL:

```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev python3-venv
# Install the pinned Rust toolchain using https://rustup.rs, then run from the repository root:
bash protocol_rust/run_local.sh
```

The runner installs pinned Python dependencies into its own venv, generates fresh test CA/certificates and a separate Ed25519 authentication key/pin in a private temporary directory, runs loopback-only tests and deletes the temporary material. It does not reuse public-vector keys for live connections or use actual service accounts.

A separately packaged Linux x86-64 release can be run with:

```bash
bash protocol_rust/run_local.sh --prebuilt
```

That option requires `bin/linux-x86_64/spiral-lab` from the package. The recorded Debian 13 binary requires up to GLIBC_2.34 and OPENSSL_3.0.0 symbol versions. It cannot run on ARM. Build outputs are not committed to the source checkout; build from source if the binary is absent. This is not a claim of compatibility with every target OS.

## Architecture and ownership

| Component | Responsibility |
| --- | --- |
| `src/ffi.rs` | Sole direct boundary for four reviewed C API calls; key pointers are not Send/Sync/Copy/Clone |
| `src/worker.rs` | Fixed workers, at most 32 running/queued jobs and 32 key slots, cancellation, deadlines and leases |
| `src/identity.rs` | Opaque server signing-key ownership, public-key export, serialized signing/close and shared-reference invalidation |
| `src/keyfiles.rs` | Linux FD-based private-file policy, parent checks and no-replace creation |
| `src/secret.rs` | Fixed-size secret buffers with explicit Drop cleanup |
| `src/buffer.rs` | Up to 18 connection buffers of 16,440 bytes; full-capacity wiping before waiting, reuse and return |
| `src/wire.rs` | Canonical 40-byte headers; length, role, session and sequence checks before reading payloads |
| `src/schedule.rs` | SHA-256/HMAC/HKDF labels and transcript-preserving key schedule |
| `src/handshake.rs` | Name/service/exporter-bound pins, validity/revocation, signatures and both Finished checks |
| `src/transport.rs` | TLS 1.3, actual exporter, ALPN, SNI, exact DNS SAN and trust-chain validation |
| `src/records.rs` | Directional keys, one-time sequence reservation, AEAD, authenticated CLOSE and usage limits |
| `src/channel.rs` | One task per direction, two bounded application queues of 8, partial-I/O state and absolute deadlines |
| `src/admission.rs` | 64 active connections, 4 per IP, 32 pending, per-IP token bucket and cleanup |
| `src/main.rs` | Loopback client/server runner and public aggregate output |
| `interop.py` | Real Python↔Rust/Rust↔Rust TLS, tampering and overload tests |
| `key_ops_tests.py` | Key-file/CLI/recovery/cold-rotation tests and public provenance reports |
| `key_recovery_tests.py` | Encrypted-backup recovery and bounded failure drills |
| `benchmark.py` | Fixed-condition TLS round trips and peak RSS by worker/payload settings |

Only a handshake-verified `Established` value can start a data session. External callers cannot create sessions by combining arbitrary `SessionKeys` and `Transport` values. Active server session IDs are tracked for uniqueness and released on closure.

FFI runs in the same process and does not isolate faults in C.

KEM keys remain on their creating C worker for decapsulation and destruction; network tasks never receive key pointers. Workers are not held while waiting for network responses. Dropping a lease sets a shared cleanup flag, including when the queue is full. An executing C function is allowed to finish safely before cleanup rather than being forcibly interrupted.

TLS KeyUpdate does not reset the Spiral record counters or usage limits.

The data path makes no direct C KEM calls. Each direction owns its sequence and key; AEAD is not retried with a rolled-back sequence. Writes preserve progress across partial I/O and notifications, flush before the next frame and use deadlines that opposite-direction activity cannot extend indefinitely.

The normal buffer pool is `18 × 16,440 = 295,920` bytes per connection. Receive CLOSE uses a separate buffer of at most 57 bytes; transmit CLOSE uses a fixed 57-byte array. This is not a process-memory upper bound: TLS, kernel/provider state, threads and other objects are additional. A received `Plaintext` buffer returns to the pool only when dropped. Application-created copies, Strings and Vecs remain the application's responsibility.

`Sender::send(&[u8])` copies once after obtaining a queue slot. Receive passes buffer ownership and a view to the application. A queued send may still be transmitted after its caller cancels the waiting future; use application request IDs and duplicate-handling rules rather than automatically retrying an uncertain request. The implementation does not claim end-to-end zero-copy. It flushes per frame and yields after every four records.

## Secret lifecycle

- `ServerIdentity` owns the Ed25519 key. Arc references share the owner; `close()` waits for ongoing signing and invalidates shared references. Raw keys and arbitrary-signing APIs are not exported.
- C KEM keys are wiped and freed on success, failure and cancellation cleanup.
- Concurrent `KemPool::shutdown()` callers await the same worker-join result; cancellation of the first waiter does not cause other callers to return early.
- Shared-secret output is written directly into a Rust heap secret buffer and wiped after PRK derivation. PRK, Finished keys and application master material are dropped after final use.
- Directional data keys live with their record state. ChaCha20Poly1305 key state and the enabled Poly1305 0.8.0 cleanup feature provide scoped Drop cleanup.
- SHA2 0.11.1/HMAC 0.13.0 cleanup features cover HKDF state and the dalek 3 signing hasher. Release builds enforce required features. This does not erase every output array or nonce copy.
- Scoped local RustCrypto patches add ownership/guards for named digest, HMAC, HKDF and signing scratch slots. See [cleanup implementation](SECRET_COPY_CLEANUP.md) and [dependency scopes](../hardening/secret-copies-20261108/implementation/dependency-scopes.md).

## Validation guides

| Area | Guide |
| --- | --- |
| Architecture and implementation hardening | [Architecture](ARCHITECTURE_v0.2.md), [v0.3 report](HARDENING_v0.3.md) |
| Sustained concurrent TLS, overload rejection and process-resource observations | [Load testing](LOAD_TESTING.md) |
| Operator-run duration profiles, preparation and result collection on OCI/WSL | [Load commands](LOAD_COMMANDS.md) |
| Functional records and reproducible commands | [Validation](VALIDATION.md), [Ubuntu/WSL](RUN_UBUNTU_WSL.md), [regression map](REGRESSION_MAP.md) |
| Frame/ClientHello fuzzing | [Parser fuzzing](FUZZ_PARSERS.md) |
| DATA/CLOSE state-model fuzzing | [Record fuzzing](FUZZ_RECORDS.md) |
| Partial writes, cancellation, closure and resource return | [Lifecycle tests](LIFECYCLE.md) |
| Linux key-file policies, creation and cold rotation | [Key operations](KEY_OPERATIONS.md), [platform results](KEY_OPERATIONS_PLATFORMS.md) |
| Encrypted backup and recovery | [Recovery](KEY_RECOVERY.md) |
| Memory diagnostics and the 48-byte baseline | [Follow-up](MEMORY_FOLLOWUP.md), [minimal std/libtest comparison](LIBTEST_MEMORY.md) |
| Receive-buffer disposal and secret-flow diagnostics | [Memory scope](SECRET_MEMORY.md), [receive path](RECEIVE_SECRET.md) |
| HMAC/HKDF/signing cleanup | [Secret state](SECRET_STATE.md), [design](SECRET_COPY_DESIGN.md), [implementation](SECRET_COPY_CLEANUP.md) |
| ARM64 diagnostics | [ARM secret flow](ARM_SECRET_FLOW.md) |

Platform submissions are recorded separately by source and environment. Examples include 17,380 OCI and 34,543 WSL record-fuzz executions, saved-input replays of 702/702 and 718/718 cases, and lifecycle campaigns with 40 channel cases, 135 subconditions, 30 Rust TLS cases and 30 independent-peer TLS cases per platform. These are finite observations, not exhaustive proofs.

Current key-recovery evidence records 94 Rust tests (5 separately ignored), 11 key-operation tests and 20 recovery tests on each documented OCI/WSL submission. Check the linked records for exact source maps, commands and limitations rather than combining counts from different runs.

## Remaining limits

No complete constant-time, memory-erasure, cryptographic-security or production-deployment approval is claimed. Memory locking and core-dump prevention are not provided by these scoped cleanup mechanisms. Original authentication-related diagnostic warnings, raw exit 99 results and the 48-byte memory item remain evidence to assess. Named-slot cleanup does not establish erasure of all historical moves, arithmetic backend limbs, compiler temporaries, registers, OS/provider copies or abort paths.

Application authorization, vault/service integration, compromised-identity recovery policies, sustained load, long-running operations, native Windows support and independent cryptanalysis require additional work. The runnable programs intentionally bind to loopback and do not constitute a public service.
