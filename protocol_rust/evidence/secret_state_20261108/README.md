# Validation evidence for new hash-state erasure features

Measured code `fe52b62a146850927bcc62c09395adac3fcaafb2`, local Linux x86-64.
Also see [coverage and remaining copies](../../SECRET_STATE.md).

| Evidence | Contents |
|---|---|
| `review.json` | Git blob comparisons for sources/runner/parser/CI, binary/ASan provenance, dependencies, aggregates |
| `functional/` | Original results for Python 85·diagnostics 20·C9·Rust 70·documentation 6·realTLS 35 |
| `stable-tests.log`, `state-tests-optimized.log`, `asan-tests.log` | Normal/optimized/ASan, RFC·40 ring pairs·104 tampered cases·216 buffer observations |
| `audit-build.jsonl`, `asan-build.jsonl`, `selected-compiler-artifacts.json` | Artifacts, selected features, executable paths |
| `sha2-features.txt`, `sha2-fuzz-features.txt` | dalek/SHA2 erasure feature unification in normal/fuzzing graphs |
| `old-sha2-public-build-tree.txt` | Separately remaining public source-hash build dependency |
| `probe/`, `probe-*.log`, `probe-result.json` | Same-trait feature OFF failure 101 / ON success 0 |
| `linked-state-symbols.txt`, `linked-state-disassembly.txt.gz` | Symbols/DWARF/full instructions for 10 selected functions; original text hash recorded in review |
| `linked-cleanup-excerpts.txt` | Actual 0 writes in HKDF/HMAC SHA256·dalek SHA512 state Drop |
| `dependency-source-excerpts.txt` | Limited source excerpts of erasure implementation and uncleaned output/nonce |
| `taint-and-wipe/` | KDF/send/signature taint·buffer Memcheck, original exit 99 |
| `receive-flow.tar.gz` | 78 receive pairs +2 positive controls, warnings/mapping; internal manifest 480 files verified |
| `record-fuzz.tar.gz` | ASan fuzzing/instrumentation audit/633 input rechecks; internal manifest 691 files verified |
| `cargo-update.log`, `fuzz-lock-update.log` | Stable dependency and related graph changes |
| `assemble-evidence.py` | Completed-evidence validation/copy code, preserving original logs |
| `SHA256.json` | Individual file hashes, excluding the list itself |

Of 16 additions/updates in both lockfiles, verified crate checksums for the 15 selected by the target and archive agreement for Rust
sources/Cargo.toml190 files. fiat-crypto0.3.0 is in the lockfile
but excluded from source verification/execution because this x86-64 graph does not select it.
These are not post-change OCI ARM/WSL execution results.

`constant_time_approved`, `production_memory_passed`, `all_temporary_secrets_erased`,
All `original_memory_findings_resolved` values are false. Of 158 receive runs, original exit 99 occurred
156 times and exit 0 twice; the existing 48-byte item was observed in 155. Public controls had 0 branch/address
warnings; secret receive authentication-related warning contexts totaled 134. KDF/signature taint retains the existing wire output
contract, and actual receive traces added no declassification or suppressions.

Only public synthetic fixtures and public tool/dependency information are retained; executables, operational keys, certificates, and accounts
are excluded. Paths/commands are provenance for this measurement, not installation paths for another PC.
Existing records and manifests were not modified.
