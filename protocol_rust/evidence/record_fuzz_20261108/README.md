# Rust DATA/CLOSE state fuzzing local/OCI/WSL records

Executed on pinned source `1ca44d6f3bab34bb83d3bdf6aa7c512975db43e9`.
The filename uses the recorded local date 2026-11-08; original log/JSON times are UTC.
The first table shows local Debian x86-64 results. Subsequently submitted OCI ARM64/WSL2 record
results are in a separate table below, distinct from earlier parser submissions.

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

## User-submitted OCI/WSL results

Both environments ran pinned commit `05162229db77ec56864fe223cec8a6e3a83f553e`.
This commit combines implementation and local evidence; the49 test-source hashes match the local run above.
It used official nightly-2026-11-07 with full compiler commit
`c980177d81d16f843a500905ac98c0cf3af1fd8d` and LLVM 23.1.5.

| Environment | Actual runs | Saved-input recheck | Successful / Including rejection | cov / final ft |
|---|---:|---:|---:|---|
| OCI ARM64 | 17,380 | 702/702 matched | 106 / 596 | 406→409 / 2,087 |
| WSL2 x86-64 | 34,543 | 718/718 matched | 112 / 606 | 494→499 / 2,615 |

Both runs reached the time limit before the maximum100,000 runs or60 seconds and exited normally.
These are not results of completing100,000 runs. Counts include initialization/duplicate inputs;
CPU/code-generation/time-limit differences may produce different execution counts and feedback figures.
These do not indicate different security levels or overall coverage percentages.

For each bundle, all file hashes, Git blob hashes for49 test-source files, official distribution manifests and
tool-installation records, preservation of578 initial inputs, completion of8 model checks, engine statistics/options,
re-execution paths, line counts, output fields, and values were verified. Preserved Rust re-execution
outputs, all 1,420, were recomputed against the trusted Python reference and matched.
Results also match for579 inputs sharing SHA-256 hashes across both platforms.
No sanitizer errors, leak errors, panics, or verdict mismatches were found in artifacts/logs.

Full compilation-audit records, OCI130/WSL131, preserved IR for6 actual functions,
and symbol/disassembly evidence for both executables were checked separately. OCI `wire::parse` is
a standalone function; WSL has precise DWARF evidence of inlining within `Rx::decode`.
Complete IR/binaries are excluded from submitted bundles, so their hashes and whole-driver-IR instrumentation
token counts could not be directly recomputed. This limitation and detailed checks are recorded in
[platform-review.json](platform-review.json). Submitted programs were not
rerun in this environment.

SHA-256 of original archives:

```text
OCI bcee22d697c1c85087824e8320bdedfa2223a71145c1c893572baf2b4e84921a
WSL 0c67e9d3b8de7d67256987655f3d199253b8718d69d1f4450caf7dda1abfadf8
```

This phase completes both-platform execution/result validation for low-level directional Tx/Rx state fuzzing.
The next expansion targets lifecycle behavior when combining partial writes, cancellation, simultaneous shutdown, and timeouts
on authenticated channels/TLS. Overall security and constant-time implementation require further evaluation.
