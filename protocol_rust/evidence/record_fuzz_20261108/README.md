# Rust DATA/CLOSE state fuzzing local record

Executed on pinned source `1ca44d6f3bab34bb83d3bdf6aa7c512975db43e9`.
The filename uses the recorded local date 2026-11-08; original log/JSON times are UTC.
The figures below are local Debian x86-64 results. OCI ARM64/WSL2 record results
have not yet been collected and are distinguished from earlier parser submissions.

| Check | Result |
|---|---|
| Python independent reference/instrumentation/preservation gates | 67 passed |
| Rust independent model/actual code comparison | 8 passed |
| All initial seeds Rust–Python comparison | 578 matched, 0 mismatches |
| DATA/CLOSE state fuzzing | 60-second limit, actual 35,054 runs, exit 0 |
| Final saved-input Python comparison | 717/717 matched, 103 successful paths/614 including rejection |
| Existing frame/ClientHello regression fuzzing | 2,000 runs each, saved inputs 74/74 and65/65 matched |
| Existing Python/diagnostic/C tests | 85/6/9 passed respectively |
| Default Rust library | 52 passed; 2 separate ignored taint tests not added |
| Default Rust compile-fail documentation | 6 passed |
| compile-fail documentation with only `record-fuzz` enabled | 5 passed |
| Default release build/actual TLS | Build succeeded, 35 passed |

State inputs are at most 258 bytes/64 commands. Checks cover both sending roles, normal sending/receiving, authenticated
CLOSE, replay/reordering/tampering/post-shutdown inputs, invalid metadata with valid tags,
CLOSE reasons, record/byte limits, and permanent receiver disposal after errors.
Limit-boundary counters are set only when constructing new test objects. These are not results of fuzzing actual long-term communication,
channel bidirectional-shutdown coordination, timers, or socket state.

For every command, actual Rust results were compared against a separate `ring` AEAD state model's complete wire/plaintext bytes,
errors, and state. Saved inputs were compared against a separate stdlib Python AEAD/state reference.
The Python AEAD is a test-only implementation validated with RFC 8439 public vectors and existing DATA/CLOSE vectors;
it is not used as service cryptography.
717 is the finite final saved-input count, distinct from35,054 live executions.
Live execution counts include initialization and duplicate inputs.

Of131 compilation commands, only1 protocol-library command received feedback instrumentation.
For the six actual functions `Header::parse`, `wire::parse`, `Tx::data`, `Tx::close`, `Tx::encode`,
and `Rx::decode`, IR counters/comparison callbacks and linkage evidence for both final executables were
checked. DWARF confirmed `wire::parse` inlined inside `Rx::decode`.
A local build retaining full IR/executables was read separately and rechecked against preserved evidence;
the full IR of both drivers had no feedback-instrumentation tokens.
Fixed-data adapters in the protocol library are also in instrumentation scope.

Live feedback was `cov` 494→499, final `ft` 2,608. These are not overall coverage percentages.
There were no ASan/leak errors, panics, verdict mismatches, or crash artifacts.
This does not establish coverage of native C/OpenSSL/prebuilt Rust standard libraries, overall memory checking,
constant-time implementation, or cryptographic-security approval. Existing memory-diagnostic
unresolved warnings were neither resolved nor converted to passes.

Preserved files:

- `local-60s.tar.gz`: Original state-fuzzing results/logs/inputs/re-execution output/instrumentation evidence.
- `parser-regression-2k.tar.gz`: Regression results for the two existing parsers.
- `functional/`: Existing functional-runner result JSON, original logs, and TLS results.
- `record-feature-doc.log`: Public-API compilation checks with only `record-fuzz` enabled.
- `local-result.json`: Scope/count/source-hash/archive-hash summary.
- `SHA256.json`: SHA-256 for files preserved in this folder.

Internal SHA256 lists and every file in both archives were reread and checked for agreement.
Original-log whitespace was not normalized. Build binaries and full IR are excluded from archives,
so recipients of the bundle alone cannot directly recompute full-IR/binary hashes.
For reproduction, use the [OCI/WSL guide](../../FUZZ_RECORDS.md).
A GitHub workflow was added, but successful GitHub execution was not confirmed in this environment.
