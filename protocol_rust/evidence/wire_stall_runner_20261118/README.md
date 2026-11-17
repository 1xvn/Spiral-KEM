# Underlying TCP write-stall runner preparation

Preparation date: 2026-11-18. This feature-only diagnostic adds a bounded raw
TCP read gate and an observer below TLS. Default transport settings and protocol
queue, buffer, idle and session-age limits remain unchanged.

Recorded checks:

- Verified Rust/Cargo 1.99.1 feature-enabled CLI compilation and release build.
- Default-feature CLI compilation.
- 201 Python collector/operator/verdict tests passing in 1.979 seconds.
- Three focused TCP observer tests and the full feature library suite:
  106 passing tests, five intentionally ignored diagnostics.
- Seven invalid opt-in CLI configurations rejected before endpoint execution.
- One real Rust/TLS read-release case and fresh ordinary recovery on one Linux
  x86-64 host, approximately 1.174 seconds combined.

The loopback TLS case recorded three verified baseline echoes, then a new
underlying TCP write Pending after bulk began. Both stable snapshots had the
same written-byte count (2,865,457), pending=true and pending poll count 2, above
baseline 0. The open-session stall persisted for approximately 202.226 ms.
At that point 170 of 1,021 bulk sends had completed, one producer was active,
and none was waiting for a pool buffer or send slot. This is actual socket write
pressure, distinct from the earlier retained-buffer test.

The gate's ciphertext read count remained 51,505 while reads were held. The
kernel returned an 8,192-byte receive buffer for the requested 4,096 bytes.
After resumption the client verified all 1,021 bulk messages; with the baseline,
the server delivered 1,024 messages of 16,384 bytes. Both peers completed
authenticated closure, returned all allocated buffers, finished both I/O tasks
and dropped the actual TCP transport. Both reported zero live native keys and
zero rejected jobs. Server admission and identity ownership were released.
Ordinary recovery then verified ten echoes with fresh identifiers.

This used a disposable local TCP relay with independent half-close handling,
not SSH. There was no OCI/WSL execution. **The actual 60-second timeout case was
not run during preparation.** Its contracts and existing channel deadline
regressions were checked; operator commands are in
[WIRE_STALL.md](../../WIRE_STALL.md).

The successful check used clean runtime source revision
`64b99e8136182f68f962f917abae637cd4ac4957`. All 175 selected runtime source hashes
and the executable hash stayed unchanged. Temporary credential directories were
removed; no private keys are included. `local-validation.tar.gz` contains the
original successful logs, driver, results, test/build records and verified
toolchain provenance. `SHA256.json` inventories this evidence directory.

A reset reported by a raw read becomes input EOF without dropping buffered
ciphertext. Sends and unrelated read errors still fail; a release verdict
requires both Rust endpoints to report authenticated closure. Regression tests
cover buffer preservation. These results do not certify capacity, latency,
WSL clock accuracy or cryptographic security.
