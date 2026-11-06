# Rust–C v0.3 validation results · 2026-11-06

This research implementation strengthens signing key ownership and concurrent shutdown. Functional tests passed; full memory checks and constant time validation remain incomplete. See `HARDENING_v0.3.md` for code/execution details and `REGRESSION_MAP.md` for individual requirements.

## Functional and cleanup results

| Item | Result |
|---|---|
| Rust unit / compile-fail documentation tests | 52 / 4, 0 failures |
| Real TLS negative/interoperability tests | 35, 0 failures/errors |
| Bundled binary and run_local.sh, new venv | 35, 0 failures/errors |
| Python baseline / C-Python comparison | 85 / 9, 0 failures |
| fmt / clippy all-targets -D warnings / release | Pass |
| Concurrent shutdown regression | Assertion failure with the previous function, passed after the fix |
| C ASan/UBSan / public input corpus | Passed with detect_leaks=0 / 20,000 cases |
| Separate C Memcheck | 0 errors |

LSan could not run in this host's ptrace environment, and the initial fatal result is also preserved. We do not claim LSan passed. C leak checking is the separate Memcheck result. The two taint methods excluded by regular Rust unit tests were instrumented separately in an optimized audit executable.

## Environment and speed

The host is Debian 13 x86-64 / glibc 2.41 / GCC 14.2 / OpenSSL 3.5.7 / Python 3.12.14 / Rust 1.99.1, with affinity to 9 CPUs. Valgrind instrumentation used the Ubuntu glibc 2.39-0ubuntu8.8 loader/libc with debug symbols and host libcrypto 3.5.7. This does not mean this version was tested on a full Ubuntu 24.04 system or WSL/OCI ARM.

For each of nine conditions, workers 1/2/4 × payload 64/1,024/16,384, there were 2 warmups followed by 5 measurements, using four connections per run, 32 echoes per connection, and 8 senders. That is 180 measured connections and 72 warmup connections. Throughput divides request+echo payload by wall time including process startup, connections, and shutdown. RSS is the peak for the entire process. With 20 connection samples per condition, interpretation of p95/p99 and capacity is limited.

| Workers/endpoint | Payload B | Median handshake ms | p95 ms | Median round-trip payload MiB/s | Median server RSS KiB |
|---|---|---|---|---|---|
| 1 | 64 | 13.539 | 20.216 | 0.48 | 6652 |
| 1 | 1,024 | 8.338 | 13.027 | 10.01 | 6852 |
| 1 | 16,384 | 7.504 | 14.785 | 173.00 | 6828 |
| 2 | 64 | 10.910 | 21.112 | 0.60 | 6616 |
| 2 | 1,024 | 10.173 | 13.177 | 9.80 | 6572 |
| 2 | 16,384 | 10.109 | 12.354 | 122.08 | 6572 |
| 4 | 64 | 11.919 | 14.413 | 0.56 | 6576 |
| 4 | 1,024 | 9.870 | 11.681 | 9.58 | 6444 |
| 4 | 16,384 | 10.054 | 11.876 | 154.26 | 6672 |

These values are not divided by v0.2, WSL, or OCI figures from different environments to claim an improvement factor. Target-device performance requires separate measurement. Originals are in `evidence/v03/benchmark_release.json`, including binary/Cargo.lock hashes.

## Memory and secret branch instrumentation

| Scope | Observation | Verdict |
|---|---|---|
| release success | 4 Memcheck errors | Not passed |
| release finished-failure | 0 Memcheck errors | Pass |
| audit tls-only-default | 4 errors | Not passed |
| audit tls-only-aes128 | 4 errors | Not passed |
| audit tls-only-aes256 | 4 errors | Not passed |
| audit tls-only-chacha | 0 errors | Pass |
| ring public vectors/offset buffers/hash/KDF/signing | 6,102 reference matches, 0 warnings | Sample passed |
| C secret taint | 0 secret-dependent branch/address warnings, 1 positive control detected | Sample passed |
| Rust secret taint | 0 secret branch/address warnings; libtest 48B possibly-lost | Full memory check not passed |

TLS warnings are reported in decrypt tag checks and writev. In debug symbols, origins point to hash context fork_finish or Ed25519 digest stack allocations. Optimization and stack reuse mean these symbols alone cannot establish the cause. Clean public primitive/offset-buffer controls without TLS do not prove TLS warnings are false positives. No warning suppressions, arbitrary marking of memory as defined, or production cipher changes were applied. Public output declassification for dynamic secret taint is separate test-only code.

The additional 48 bytes in Rust taint are reported on the libtest/thread initialization stack. Full check exit=99 remains a failure; we do not conclude that it is a key-path leak or a harmless false positive. Definite/indirect/possible leak totals are 0 in C memory and normal/failure release checks, while normal TLS uninitialized-value warnings remain separately. Nor do we claim completed erasure of Rust runtime's 548 reachable bytes.

## Limits of timing diagnostics

Each of two C diagnostics uses 6,000 fixed/variable secret samples and 6,000 sham decapsulations. The first run, under compilation load, had weak sensitivity with positive control |t|=3.15. Remeasurement after the work completed gave positive control t=-16.997, secret classification t=0.386, and sham t=-1.137. This means no large difference was found in these samples; it is neither execution of the dudect package nor proof of constant time. The first result is also retained in `native_timing.json`.

We jointly checked C fixed arithmetic and mask selection, optimized assembly, and secret marking instrumentation. Rust KDF/HMAC, record seal, and Ed25519 marking checks were added, but this does not evaluate side channels in all authenticated decryption, TLS, or all providers/compilers/CPUs.

## Evidence and reproduction

v0.3 logs are in `evidence/v03/`, source hashes in `SOURCE_SHA256.json`, and log hashes before/after trailing whitespace cleanup in `LOG_FORMATTING.json`. v0.2 results are preserved in `evidence/v02_VALIDATION.json`/`v02_VALIDATION.md` and existing logs. Diagnostic commands follow. If errors remain, memcheck.py/taint.py exit with failure; we do not turn this into a pass.

```bash
cargo build --profile audit --examples --bins --locked --manifest-path protocol_rust/Cargo.toml
cargo test --profile audit --lib --no-run --locked --manifest-path protocol_rust/Cargo.toml
python3 protocol_rust/memcheck.py --binary protocol_rust/target/audit/spiral-lab --tls-control protocol_rust/target/audit/examples/tls_control
python3 protocol_rust/crypto_probe.py --examples protocol_rust/target/audit/examples --output protocol_rust/local_crypto_probe
# For taint.py --rust-tests, specify the target/audit/deps/spiral_protocol-<hash> executable path printed by Cargo
# C diagnostic binaries: make -C native_research build/taint build/check_memcheck
python3 protocol_rust/taint.py --rust-tests protocol_rust/target/audit/deps/spiral_protocol-REPLACE_HASH --output protocol_rust/local_taint
```

The taint C build requires Valgrind development headers. Warnings and timing values can change with tool/CPU/libc/provider versions. For regular validation/benchmark commands on target environments, use `RUN_UBUNTU_WSL.md`.
