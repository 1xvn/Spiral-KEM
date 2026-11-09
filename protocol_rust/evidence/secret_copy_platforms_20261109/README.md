# Temporary secret copy cleanup patch · OCI/WSL submission results

We reviewed OCI ARM and WSL2 submissions for the same patch source `7f26fed5b8176ddd009d44264fb5e9ab08fb8d31`.
**This round of basic functionality and secret flow collection is complete on both environments**.
We did not modify the originals or execute scripts/executables in the attachments.

| Item | OCI ARM | WSL2 x86-64 |
|---|---|---|
| Actual environment record | aarch64, 7.0.0-1013-oracle | x86_64, 6.18.54.1-microsoft-standard-WSL2 |
| Rust/Cargo · Valgrind | 1.99.1 · 3.22.0 | 1.99.1 · 3.22.0 |
| Basic Rust tests | 70 passed / 0 failed / 5 ignored | 70 passed / 0 failed / 5 ignored |
| Receive inputs/public-secret pairs | 78 types · 156 runs | 78 types · 156 runs |
| Branch/address positive controls | Detected in 2 runs | Detected in 2 runs |
| Key derivation/transmission/signing controls | 2 runs, 0 branch/address warnings | 2 runs, 0 branch/address warnings |
| Memcheck total | 160 runs completed, original exit 99 | 160 runs completed, original exit 99 |
| Receive warning contexts | Authentication 64/propagation 64/CLOSE 6 | Authentication 64/propagation 64/CLOSE 6 |
| possibly lost entry | 48 bytes/1 entry in all 160 runs | 48 bytes/1 entry in all 160 runs |
| Collection complete · CT/memory approved | true · false/false | true · false/false |

## Provenance, build, and integrity

The source commit, bundle manifest SHA, and collector-reported count of 864 verified files in both results
match the distributed pinned source bundle. Reported source hashes cover 189 campaign files and 179 trace files,
all checked against the pinned Git source and distribution manifest. Hash lists also match across environments.
We separately verified the hashes of the 864 files in the distribution bundle itself. All 864 actual measurement source files
are not included in the submissions, so we distinguish collector-reported counts from submitted hashes compared directly.

In Cargo build logs, we verified the local paths for digest/hmac/hkdf/ed25519-dalek/curve25519-dalek,
`third_party/rustcrypto`, and enabled `zeroize` features for each. A legacy digest path for public builds
also exists, but we distinguished it from the new secret hash path. The Rust compiler commit is
`58cf8f9c35b355199727627d07ae34a4e2846d67` in both environments.

Each original contains 499 regular files and 2 directories with safe paths. All 497 outer manifest entries and
486 trace manifest entries matched; the 487 files in the nested trace archive also match the outer trace copies.
trace/SHA256.json, excluded from the outer manifest, also matches the nested trace archive
whose hash is included. Executables and tool binaries are absent from the submissions, so we did not
recalculate recorded binary hashes or regenerate original disassembly here.

## Original logs and warnings

We verified exact completion markers, 1 successful test, and empty stderr in all 160 stdout logs per environment.
Original ERROR SUMMARY, warning messages, leak summaries, and JSON records have no mismatches.
We compared not only check order but roles 0/1, lengths 1/16/63/64/65/1024/16384, 16 tag positions at length 65,
and CLOSE reasons 0/3/255, totaling 78 input configurations. These are samples with limited synthetic keys/prefixes and initial receive sequence 0,
not tests exploring all arbitrary inputs, keys, or session states.

The 134 secret receive contexts are explanatory candidate categories: 64 authentication decisions, 64 result propagation, and 6 CLOSE range checks.
There are no branch/address warnings in 78 public receive cases, 14 secret public-header error cases, or key derivation/transmission/signing controls.
Warning counts are not vulnerability counts, and candidate categorization was not used as an acceptance verdict.

All 136 warning PCs, including positive controls, and five unique locations match the attached ELF-relative addresses/instructions.
ARM maps to authentication cbz, propagation tbz, and CLOSE b.hi; WSL maps to je, jne, and ja. The intentional positive
controls, 2 in total, remain unclassified; actual receive has 0 unclassified contexts. This mapping is limited to observed locations in selected receive/control functions;
it does not reverify erasure instructions in all cleanup functions on both CPUs.

The original total per environment is 296 errors/contexts: 134 receive + 2 positive + 160 48-byte entries.
Each of the 160 runs preserves the std::thread::current::init_current/ArcInner/libtest possibly lost
48-byte/1-entry report and still reachable 548-byte/2-entry report. Definite/indirect loss and
suppressions are 0, and no additional invalid read/write/free was observed.
`diagnostic_complete=true` and runner exit 0 mean collection is complete; individual Memcheck exit 99
is unchanged. We do not convert this to a clean-memory pass.

Reception marks the key/prefix secret before calling actual decode and performs no declassification.
The separate key derivation/transmission/signing controls use the existing contract that treats public wire output and
cleanup of synthetic seed shadow after operations as public, so we do not describe the entire campaign as free of declassification.

## Completion and remaining validation

We additionally confirmed this collection on both platforms for the [owned slot cleanup implementation](../../SECRET_COPY_CLEANUP.md).
These attachments do not represent new runs of
23 cleanup-only tests, ASan, 6 documentation tests, 35 real TLS tests, long fuzzing, service load, or performance/RSS on each platform.
Earlier local validation and previous platform results retain their respective source records.

Backend limbs/radix, copies before arguments/moves, registers, OS retention, outputs of unused dalek conversion APIs,
and production key lifetime policies remain separate. Independence from timing distributions, caches, and speculative execution is also unproven.
`whole_goal_2_complete=false`, `constant_time_approved=false`,
`production_memory_passed=false` remains. Model-assisted independent review does not replace
cryptographic design review by external researchers.

## Evidence

`oci_arm-review.json` and `wsl-review.json` review provenance, functionality, raw exits, memory, and features;
each instruction-review records observed PCs and instructions. `summary.json` combines both environments' scope
and completion verdicts. Independent review JSON and original archives are also preserved.

| Original archive | SHA-256 |
|---|---|
| Spiral-secret-flow-aarch64-20261109-071117-lw2ei7sl.tar.gz | 4e34fd8bf510277ed017f938afb2735659ddf0d825afdda4f29d3f8b3b5b8a85 |
| Spiral-secret-flow-x86_64-20261109-071708-4p3376tb.tar.gz | 7ce2a699163b4166065c1ddab6a1b4630a9a9b19cded3eb9192f2f47e2b92177 |
