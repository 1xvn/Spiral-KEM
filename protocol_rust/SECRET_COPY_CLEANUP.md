# Ownership and cleanup implementation for temporary secret copies

We implemented dependency-internal lifetime guards, the recommended option in the
[erasure policy design](SECRET_COPY_DESIGN.md). The measured code is `7f26fed5b8176ddd009d44264fb5e9ab08fb8d31`.
Existing high-level APIs, wire format, KEM/signature bytes, and strict verification policy are preserved.
**This cleans the specified currently owned slots; it does not complete all of item 2 or erase all copies.**

## Actual improvement scope

| Path | Implemented cleanup |
|---|---|
| digest 0.11.3 | full_res in the fixed-output wrapper |
| HMAC 0.13.0 | pad/inner hash/long-key hash, owned pads and internal outputs in Simple/Reset |
| HKDF 0.13.0 | output/prev replacement/final termination/unwind, ignored PRK, PRK intended for return before constructor panic |
| Application key schedule | Drop guard borrowing the original returned raw PRK array. Cleanup on normal/error/unwind paths without additional output array copies |
| Ed25519-dalek 3.0.0 | In-use seed expansion digest/scalar bytes/clamped values/local prefix/scalar/nonce r/key_term |
| curve25519-dalek 5.0.0 | Directly owns and cleans from_hash digest output, removing the existing second 64-byte copy |

Private guards erase owned slices even without a Zeroize trait on Array itself.
HKDF adds an additive zeroize feature, explicitly enabled. Public returned PRK/OKM and
signatures transfer to callers and are not erased. With the feature OFF, the new cleanup contract is not provided.
Scalar Copy/Clone is preserved; cryptographic formulas, clamping, and nonce generation were not rewritten.
No optional new into API was added.

Complete upstream sources, licenses, and original archive checksums are in
`third_party/rustcrypto/upstream-provenance.json`; hashes of actually changed files and narrow diffs are in
`patch-manifest.json` and `cleanup.patch`. These are local patches distinguished from crates.io originals,
using the same 5 paths in both protocol/fuzz workspaces.
Installed Cargo caches were not modified.

## Validation results

| Check | Local x86-64 result |
|---|---|
| Functional CI | Python 85/diagnostics 24/C 9/Rust 70/docs 6/actual TLS 35 passed |
| Cleanup-only CI matrix | 7 runs/23 tests passed; 0 tests, omissions, and ignored/filtered tests rejected |
| HMAC/HKDF | SHA256/512 RFC4231, four HMAC variants/reset, RFC5869 and independent ring boundary/maximum length comparisons |
| Application KDF contract | Reject N=0/33 and oversized labels, preserve original key schedule vectors |
| Signing/cleanup | RFC8032 pure/prehash, ring 40 pairs and tampering/disposal rejection, cleanup of actual nonce slots on success/error/unwind |
| ASan/leaks | 70 passed. Initial sandbox LSan permission-interruption logs retained; rerun with identical settings confirmed exit0 |
| Actual deployment bundle without Git | 864 sources verified, 70 basic tests and 160 Memcheck collection runs completed |
| Optimized erasure instructions | Erasure writes/DWARF/call links confirmed in selected guard paths of the actual audit executable |
| Existing fuzz runner regressions | 67 passed. These results are not counted as a new long-term fuzzing run |

We connected the cleanup-only runner `protocol_rust/validation/scratch_cleanup.py` to functional CI.
It is a focused harness using original production sources and new cleanup tests. From the signing source copy,
it precisely excludes only two existing test-only modules requiring uninstalled upstream dev dependencies,
recording original/prepared hashes and substitutions. It is not complete validation of the full upstream dev suite or optional kdf feature.
no_std/feature OFF and actual production path scopes are also distinguished.
ASan results do not instrument all native C/OpenSSL or prebuilt std.

All 160 original Memcheck runs exit99, and each retains a std/libtest 48-byte possibly-lost entry.
The 134 receive-warning contexts are also retained as 64 authentication decisions, 64 result propagations, and 6 CLOSE-scope contexts.
Candidate classification is not a determination that they are permissible safe branches.
`constant_time_approved=false` and `production_memory_passed=false` remain.

## Performance and remaining scope

Under the same Rust 1.99.1, CPU affinity, and opt3/thin-LTO/codegen1 settings, we alternately measured
baseline/candidate with public synthetic inputs. Outputs for all 21 cases and 294 original samples match.
Median ratio ranges by input length were HMAC 1.003–1.208, HKDF 1.001–1.209,
and Ed25519 0.987–1.027. Some short inputs show additional cleanup-write
costs. These are primitive timings in a shared environment, not grounds for claims about significance, actual service TLS latency, peak RSS,
or performance budget approval.

Even after registered slots are erased, backend limbs, radix digits, by-value clamp copies, previous move copies,
registers, and OS retention remain separate. In unused public to_scalar_bytes/to_scalar conversions,
SHA512 local outputs are also excluded from this production signing path guarantee. Drop execution on abort/SIGKILL
is not guaranteed. Service key storage/rotation/disposal/recovery policies are separate tasks too.

## Material and target platforms

We retained [originals and review records](evidence/secret_copy_cleanup_20261108/README.md) and
a [remeasurement bundle including sources](../downloads/secret-copy-7f26fed/README.md).
We do not yet count this new patch as executed on actual OCI ARM/WSL. Previous material from both platforms
remains a record of the corresponding earlier sources; submitted results for the new bundle are reviewed separately.
