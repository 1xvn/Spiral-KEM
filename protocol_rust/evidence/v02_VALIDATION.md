# Rust–C communication implementation validation results (2026-11-06)

Actual Rust servers/clients were connected to the existing C KEM. Figures below are local loopback results and do not establish Spiral's cryptographic security or operational capacity.

## Functional and ownership checks

- 30 Rust unit tests and1 compile-fail documentation test:0 failures.
- 15 actual TLS interoperability tests:0 failures/errors.
- The executable intended for the ZIP passed the same15 tests again using a fresh venv and `run_local.sh --prebuilt`.
- `cargo clippy --all-targets --locked -- -D warnings`, formatting checks, and release build: passed.
- Checked C-key-pointer Send/Sync/Copy/Clone prohibitions, truncated inputs, canonical formats, Finished, AEAD, cancellation, queue saturation, and partial-I/O state.
- Confirmed Python↔Rust/Rust↔Rust use matching exporters/transcripts/test vectors and native-key counts reach0 after normal shutdown. Native-key cleanup was also checked on failure/connection bursts.
- Existing C/Python files were unchanged. Existing Python69 methods and Rust test counts are distinct.

## Speed and memory

Nine conditions: workers1/2/4 × payload64/1,024/16,384 bytes. Processes restarted per condition for2 warm-up rounds and5 measured rounds. Each round used four connections,32 echoes per connection, and8 senders. Total measured connections:180.

Handshake timing spans client TCP startup through completion of TLS and Spiral Finished. Throughput counts both request/echo payloads and divides by full-round duration including client process startup, handshake, and authenticated shutdown. RSS is the median of five server-process peaks measured by GNU time. It includes TLS/native heap/threads and differs from connection-buffer bounds. Clients also retain public test-payload copies for verification. Samples are small and affected by runner/host load.

| Workers/endpoint | payload B | Handshake median ms | Handshake p95 ms | Round-trip payload median MiB/s | Server peak RSS median KiB |
|---|---|---|---|---|---|
| 1 | 64 | 13.014 | 21.955 | 0.47 | 5760 |
| 1 | 1,024 | 10.310 | 17.715 | 7.12 | 5596 |
| 1 | 16,384 | 10.983 | 15.989 | 108.06 | 5916 |
| 2 | 64 | 11.561 | 15.821 | 0.56 | 5940 |
| 2 | 1,024 | 14.745 | 18.912 | 7.75 | 5788 |
| 2 | 16,384 | 12.758 | 23.887 | 80.49 | 5916 |
| 4 | 64 | 9.530 | 19.672 | 0.57 | 5660 |
| 4 | 1,024 | 10.886 | 12.240 | 8.26 | 5700 |
| 4 | 16,384 | 11.362 | 14.019 | 90.05 | 5852 |

Original per-round/per-connection figures are in `evidence/benchmark_release.json`. These results do not establish a general ranking of worker counts or speedup factors over Python/C. The16/64 same-IP connection tests check admission limits, not64-connection throughput performance.

## Memory checks: unresolved items

Valgrind 3.22.0 and3.28.0 reported uninitialized-value warnings on normal TLS AES-GCM paths. They also reproduce in TLS-only controls without Spiral/C KEM/app buffers. They were not classified as false positives. The default TLS cipher was not changed and warnings were not suppressed.

| Valgrind 3.28.0 case | Errors | Expected behavior |
|---|---|---|
| Actual normal Spiral communication | 5 | Communication complete, native keys0; memory check not passed |
| Incorrect client Finished | 0 | Handshake rejected, native keys0 |
| TLS-only default AES-GCM | 3 | 120-byte echo complete; warnings reproduced |
| TLS-only ChaCha | 0 | 120-byte echo complete |

All four cases had0 bytes of definite/indirect/possible leaks;548 bytes of Rust-runtime global state remained reachable. This does not mean all memory checks passed or prove all-path/secret-erasure/side-channel safety. Evidence is in `evidence/memcheck_322/` and `evidence/memcheck_328/`. Each run used a separate glibc 2.39-0ubuntu8.8 loader/libc with matching debug symbols. To avoid relying solely on an older tool,3.28.0 reproduced the issue under the same conditions.

Final executable/C source/Cargo.lock SHA-256, scope, and limitations are in `VALIDATION.json`. Use this as a local research implementation; do not treat it as a service-security standard before resolving these items and independent cryptanalysis.
