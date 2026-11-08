# Receive secret path and Poly1305 state erasure evidence

Measurement code: `832e996842b2d0c746dd7b65e388907207c5b72c`.
This directory contains local x86-64 results from 2026-11-08, not post-change OCI/WSL results.
Also read [interpretation/public result contract/reproduction](../../RECEIVE_SECRET.md).

| Evidence | Contents |
|---|---|
| `review.json` | Git blob/file/report hash comparisons, aggregation of 134 receive warning contexts, original exit 99, regression/dependency summary |
| `receive-flow-20261108.tar.gz` | Original Memcheck logs/stdout/stderr, result JSON, ELF mapping/instructions/tool hashes for 78 pairs + 2 positive controls |
| `receive-flow-record-fuzz-20261108.tar.gz` | ASan fuzzing/compiler instrumentation audit/637 inputs and independent rechecks/original logs |
| `functional/` | Final functional runner and original Python85/diagnostic20/C9/Rust66/documentation6/TLS35 logs |
| `audit-build.jsonl` | Cargo artifacts/features/executable paths for the optimized audit build |
| `receive-*.log` | 78 public functional controls, stable debug/ASan |
| `wipe-*.log`, `wipe-memcheck/` | Optimized/ASan/Memcheck results for 216 actual pooled buffer disposal observations |
| `poly1305/` | Before/after artifact/feature/needs_drop false→true comparison, small public diagnostic source |
| `dependencies/` | Checksums/features for 9 locked crates, matching verification for 76 source files, short excerpts, collection code |
| `diagnostic-gates.log`, `ci-gates.log` | 20/7 verdict regressions, respectively |
| `assemble-evidence.py` | Collection code that verified/copied already completed measurements. Does not rewrite original logs |
| `SHA256.json` | Individual SHA-256 file list for this directory, excluding the list itself |

We reverified 480 files in the receive archive's internal manifest and 695 files in the fuzzing archive.
`review.json` was written separately without modifying original archive results. After measurement,
even runner/parser/test code was compared against committed Git blobs, and executable hashes also matched.
`source_sha256_verified` refers to that comparison scope. The final functional runner adds 20 diagnostic verdict tests
to automatic execution; the actual executed file is preserved as `functional/validate.py`.

All 158 original Memcheck runs exited with 99. Of these, 156 contain the existing 48-byte entry;
the two secret DATA traces lack that entry but have authentication branch warnings. Public controls have
0 branch/address warnings, secret receive has 134 warning contexts, and actual receive has 0 unclassified warnings.
The two positive control warnings were not included in receive candidate categories. All warnings remain in the originals.
**Diagnostic completion and completed address mapping do not approve full memory checks or constant time.**

Only Poly1305 cleanup was enabled, and package versions/checksums in both lockfiles match the previous main.
We do not count all temporary state inside HMAC/HKDF/SHA/signing, registers, earlier copies,
ARM instrumentation, or service production key policies as completed.

Evidence contains only public synthetic fixtures and public tool/dependency source information. It excludes executables,
production keys/accounts/certificates/session secrets. Compilation commands and absolute paths in ASan logs
are provenance for this local run, not commands specifying installation paths in a new environment.
