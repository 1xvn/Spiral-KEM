# OCI ARM secret flow collection results · 2026-11-08

Actual OCI ARM collection for corrected source `7bff0e49132b76e6c4271ebb3c219f625a46d816`
is complete. The earlier submission stopped by the `.git` dependency error
remains a [separate original failure](../arm_standalone_fix_20261108/README.md).
These are results of a new run; they neither delete that failure nor turn it into a pass.

## Verified scope

| Item | Submission review result |
|---|---|
| Environment | OCI Ubuntu, aarch64, Rust/Cargo 1.99.1, Valgrind 3.22.0 |
| Basic Rust tests | 70 passed, 0 failed, 5 instrumentation-only ignored tests separate |
| Secret branch/address positive controls | Both detected, corresponding to ARM `cbz`/`ldrb` instructions |
| Actual reception | 78 public cases + 78 key/prefix secret-marked cases complete |
| Key derivation/transmission/signing | 2 public/secret controls complete, 0 branch/address warnings |
| Memcheck total | 160 runs, original exit 99 preserved for all |
| Receive warnings | 0 public, 134 secret contexts, 0 unclassified receive contexts |
| Memory | Existing std/libtest possibly-lost 48-byte 1-entry report in all 160 runs |
| Verdict | This ARM collection complete; no constant time/full memory approval |

`injected panic` in the basic tests is intentional disposal/poison test output. The 5 ignored tests
were not added to the basic pass count; for each of 160 individual instrumentation runs, the completion marker for 1 test,
success result, and empty stderr were checked against original stdout. Collection runner exit 0 and
individual Memcheck exit 99 have different meanings.

## Warnings and public result contract

The 134 secret receive warning contexts are categorized into authentication decisions, 64 (`cipher.rs:87`, `cbz`); result propagation,
64 (`records.rs:215`, `tbz`); and authenticated CLOSE reason range checks, 6
(`records.rs:216`, `b.hi`). This does not mean 134 vulnerabilities.
Categories are explanatory candidates based on source and linked instructions, not verdicts accepting these as safe branches.
Category counts match the local x86-64 record for the same source. That local run does not count as a WSL
run. The 14 secret controls for public header errors also had no branch/address warnings.

Reception marks the 32-byte key and 4-byte nonce prefix secret and does not declassify keys, tags, plaintext,
or results. It retains the existing contract that treats authentication success/failure and whether the CLOSE reason
is in the allowed range as one-bit public results. This does not mean disclosure of all plaintext or the entire reason.
The separate key derivation/transmission/signing controls treat wire output and synthetic seed shadow cleanup
after operations as public, so we do not claim the whole campaign has no declassification.

The 136 contexts of original warning PCs occupy five unique locations, all corresponding to PIE load bias `0x108000`,
recorded ELF-relative addresses, and attached ARM disassembly instructions. The 2 unclassified contexts are
intentional positive controls. Mapping is limited to selected linked functions and observed locations.

All 160 runs show 0 bytes definitely/indirectly lost, 48 bytes/1 entry possibly lost,
548 bytes/2 entries still reachable, and no suppressions. The 48-byte stack follows
the `std::thread::current::init_current`/`ArcInner`/libtest path. No additional invalid
read/write/free or similar usage errors were observed. Since the existing entry remains,
`production_memory_passed=false` and the strict memory gate are retained.

## Provenance, integrity, and limitations

Original archive SHA-256:
`b8aa054c786b038510d1051f517311606c7eb0b4c016ebeca463fee0dfbdb50b`.
All 497 outer manifest files and 486 trace manifest files were verified.
The nested `trace.tar.gz` and outer `trace/` files are also byte-identical.

All 65 source files recorded in campaign and 55 in trace match the pinned Git source.
The source commit, verified count of 641 files, and manifest SHA reported by both collectors match the
distributed pinned bundle's `SOURCE.json`. The submitted results include neither all 641 measurement source files nor
the original ELF, so we did not recalculate hashes of all those files or the executable
here. The executable hash is the same recorded value in both results.

`review.json`, `source-hash-review.json`, `instruction-review.json`, and independent review records
record verification counts and limitations. Warnings, stacks, tool hashes, and exit codes inside the original archive
were unchanged. Scripts in attachments were not executed; they were reviewed only as evidence.

## Next scope

What is complete is this finite ARM secret flow collection phase. **Item 2 as a whole remains incomplete**;
`constant_time_approved=false` and `production_memory_passed=false` remain.
next is to design alternatives for entries in the [remaining temporary secret inventory](../../SECRET_STATE.md#remaining-temporary-secrets-and-follow-up-criteria):
ownership/erasure APIs for HMAC/HKDF local outputs and Ed25519 nonce copies.
Do not arbitrarily rewrite validated cryptographic operations; changes require RFC checks, independent signatures/communication, optimized erasure instructions,
and taint regressions together. Timing/cache/speculative execution as a whole, production key lifetime policies,
WSL AES-GCM warnings, and long-running service load/recovery validation are also not completed by this collection.
