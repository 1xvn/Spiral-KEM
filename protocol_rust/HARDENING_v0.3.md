# Spiral OPT2 Rust–C v0.3 Implementation Report

Baseline: main `7f3d987fd18b9b5d851f299d8d4234b447d5920f`. The four requested tasks are organized as code, execution evidence, and reviewable PR work. Functional validation and memory/constant-time validation statuses are distinguished. Existing designs and v0.2 evidence are preserved as historical material.

## 1. Server signing keys and secret lifetimes

`identity::ServerIdentity` is the sole public owner type for the Ed25519 authentication key. It reads an exactly 32-byte seed using native file I/O and erases temporary `Secret<32>` in Drop. Externally it exposes only the public key, state, and disposal; it offers no secret bytes, Clone/Copy/Debug, or arbitrary signing API. The API that returned raw `SigningKey` now returns `Arc<ServerIdentity>`, requiring caller type changes. The wire format is unchanged.

Cloning `Arc` does not copy secret bytes. A Mutex serializes signing and close; close removes the retained key after any in-progress signing finishes. Shared references cannot sign again, and repeated close is safe. Even if the lock is poisoned, the key is removed and an error returned. The last owner's Drop also removes the key. Executables use a disposal guard wrapping normal, error, and cancellation returns.

Uses the pinned ed25519-dalek 2.2.0 `zeroize` feature. Source inspection confirmed that `SigningKey::drop` erases the seed and `ExpandedSecretKey::drop` erases scalar/hash prefix. This does not mean all temporary internal hash, stack, and register copies are erased. TLS certificate private keys are rustls-owned state; the same disposal guarantees as this separate Spiral authentication-key wrapper are not claimed.

C outputs the shared secret directly into a Rust heap secret buffer. KDF, Finished, and data keys are derived and used within Rust; keys are not returned to Python. `Secret` owns a stable heap allocation and zeroizes in Drop. A test-only witness inspects still-owned memory immediately after erasure and before free, covering normal returns, errors, panic unwinding, task cancellation, and thread exit. It does not read freed addresses. This witness and fault injection are excluded from production binaries.

## 2. Failures, cancellation, concurrency, and shutdown

Fixed an actual bug. Previously, after the first shutdown caller took the join handles, another caller could see an empty list and immediately succeed. Cancellation of the first waiter caused the same problem. A separate join task now owns all workers, and all callers await one completion state and result. Other joins finish even if a worker failed. Applying the regression test to the previous shutdown function fails with assertion `second shutdown returned before native worker joined`; it passes after the fix.

Tests cover before/after RNG failure, ServerHello/ServerFinished send failure, cancellation awaiting ClientKey, invalid/expired leases, queue saturation, 16 live keys on 4 workers, and cancellation of shared shutdown waiters. After shutdown, native live key count is 0 and new operations are rejected. Executing C functions are not forcibly interrupted, nor is their memory freed early.

Record encryption is a synchronous single-owner operation that reserves a sequence number before transmission. Checks ensure keys cannot be reused after encryption/partial transmission failure. Transport shutdown is not called before all 57 CLOSE bytes are written; shutdown blocked at 56 bytes ends in a deadline error. Verified that slow-header activity notifications cannot extend the absolute deadline established at read start, and DATA is not delivered to the app after expiration.

If the app cancels waiting for a response after enqueueing a send request, the already queued send may complete. This does not permit key reuse. App-level duplicate request handling requires a separate request ID policy. Drop/unwind validation does not cover SIGKILL, abort, power loss, or erasure of kernel/provider copies.

## 3. Negative tests and constant-time/TLS diagnostics

Recorded 85 Python reference tests, 52 Rust unit tests + 4 compile-fail tests, and 35 real Rust TLS path tests separately. `adversarial.py` runs 15 existing interoperability tests plus 20 additional tests. The independent Python peer separately implements frames, transcript, KDF, and records, while sharing KEM/cryptographic primitives. Failures do not pass through mere timeout; native work counts and cleanup are checked.

`REGRESSION_MAP.json`/`REGRESSION_MAP.md` map all 85 requirements one row at a time. 72 map to executable tests, 8 to Rust ownership/type/build structure, and 5 explicitly document API semantics or scope differences from original scenarios. This is not described as executing 85 identical Rust tests. Coverage-guided fuzzing and long-running soak tests were not performed.

C fixed arithmetic and mask selection are unchanged, and C/H SHA-256 hashes are preserved. Reviewed GCC 14.2 -O2 multiply/sp_decaps_once and inline decode code; no integer divide instructions were found in that output. Fixed loops with public indices, public format checks, matrix sampling, and provider error branches remain. This review is not a constant-time proof for all CPUs/compilers.

Added C checks and Rust KDF/HMAC, bidirectional record seal, and Ed25519 generation/signing checks using Valgrind secret undefined markings. Only public Finished/signature/ciphertext outputs are declassified; PRK, directional keys, and seeds remain marked. Also verify detection of an intentionally branching positive control. Full Rust authenticated decryption, TLS, and all OpenSSL providers are outside this secret-branch check scope. x86-64 client requests are included only under cfg(test).

TLS warnings were not hidden and algorithms were not changed. They reproduce with AES128/AES256 even with only TLS remaining, and do not reproduce in standalone AEAD, offset-buffer, or public hash/KDF/signature vectors. The exact cause remains unresolved. Overall memory checking and constant-time validation are not marked complete. Detailed counts/logs and timing-control sensitivity are in `VALIDATION.md`.

## 4. Delivery and remeasurement

The PR includes executable code, negative tests, diagnostic tools, mappings, original-log hashes, and actual observations. The execution bundle includes sources, pinned Cargo.lock, test material, and optional x86-64 binaries. It excludes test certificates/private keys, venv/target directories, and large historical archives. Existing Python/C research code and historical repository material are not replaced.

Measurements for target Ubuntu 24.04, OCI ARM, and Windows 11 WSL environments require runs on those target systems. This local measurement used a Debian 13 x86-64 host. Values from v0.2 under different environments are not directly divided by these values to claim speedup factors. Reproduction commands are in `RUN_UBUNTU_WSL.md`.

No claim is made of completed independent cryptanalysis, production approval, RAM erasure of every copy, or side-channel safety on every OS/CPU.
