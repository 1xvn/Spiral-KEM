# Local channel and authenticated TLS lifecycle validation

Executed against pinned source `0c2609c82124f1984cada26ca3c6623ee667bcfb`.
The recorded local date is 2026-11-08; timestamps in original JSON and logs are UTC.
The first table shows local Debian x86-64 results. Later WSL2 submissions are recorded separately
below; OCI ARM64 lifecycle results have not yet been submitted.

| Check | Result |
|---|---|
| Runner·TLS result adjudication gate | 17 stdlib Python tests passed |
| Channel loop combination checks | 8 methods × 5 rounds = 40 cases, 135 detailed conditions passed |
| Real authenticated Rust TLS connections | 6 scenarios × 5 rounds = 30 cases passed |
| Real TLS with independent Python peer | 6 scenarios × 5 rounds = 30 cases passed |
| Existing Python·diagnostics·C comparison | 85·6·9 tests passed, respectively |
| Default Rust unit·compile-fail documentation tests | 60·6 passed; 2 ignored taint tests excluded from pass counts |
| Existing release build·real TLS | Build succeeded, 35 passed |

The new runner used official nightly-2026-11-07; existing functionality regression tests used Rust 1.99.1.
The new tests used ASan/leak checks, debug/overflow checks, and pinned Python dependencies.
67 source files matched their Git blobs and remained unchanged during execution.
127 compilation audit records verified source paths for four builds—library, libtest, TLS example, and server—
and their compiler, target CPU, and actual sanitizer options. ASan initialization symbols were found
in three executables. No libFuzzer feedback or runtime coverage was collected.

Synthetic channel I/O used write sizes of 1·7·31 bytes and explicit wait/release points.
Tests covered cancellation of waiting senders and writes in progress, races between shutdown and pending sends, shutdown failure/timeouts after fully flushed CLOSE,
receive queue saturation and shutdown/failure, and fragmented CLOSE/trailing bytes.
Complete frames emitted by the actual loop were decrypted by a receiver to verify sequence numbers, plaintext, CLOSE
completion, and processing without duplicates. These unit tests use internal state with shortened timeouts and public test
keys; they are not counted as executions of the real authentication path.

Rust TLS tests compared SID, transcript, and exporter on both sides after real TLS and Spiral authentication,
and opened sessions through public `Established::start`. They checked simultaneous shutdown, explicit cancellation of send, receive, and close futures,
rejection of remaining Senders after Session disposal, and delivery without duplicates or omissions from multiple senders.
Observed admission return, 90 KEM jobs across 30 sessions, final live key count 0,
and authentication-key owner close. Joining internal tasks of a discarded client was not directly observable through the public API;
the observed scope was peer failure and server admission return.

The independent peer distinguished normal CLOSE after authentication and DATA echo, split TLS application writes, abrupt
TCP EOF, TLS close_notify without Spiral CLOSE, Spiral CLOSE without close_notify,
and extra bytes after CLOSE. Observed 10 normal shutdowns, 15 expected `Closed` results,
and 5 `Deadline` results after a 2-second grace period. The final grace period was approximately 2.01 seconds each time,
and the process exited with failure on its own. External watchdog termination was not counted as success.
Where the upper API converts an error to `Closed`, do not rewrite the record as though the cause had been directly observed as Deadline
when it was not.

The independent peer's failed-server reports lack authentication-key/admission-return fields, so these
remain unobserved. Reports confirmed native live key count 0 for each server.
Original server stdout, stderr, and return codes were preserved and rechecked for each case.
Any sanitizer error or panic accompanying an expected connection failure fails the entire test.
TCP/TLS application fragmentation does not prove actual Rust short writes.

Across all 5 rounds, there were no unexpected failures, ASan/leak diagnostics, or panics.
These are finite repetitions under fixed conditions, not an exploration of every schedule. They do not change the adjudication of existing Valgrind
warnings or approve overall memory safety, constant-time implementation, or cryptographic security.

`local-5rounds.tar.gz` contains original execution results, compilation audits, logs, and case observations.
Reread and verified 21 files in the internal SHA256 list and checked that executables and certificates under `build/`,
private keys, and authentication seeds were excluded. Also checked that generated secret test material was absent from archived file
contents. Whitespace in original logs was not normalized.
Because complete binaries are excluded, recipients of only the archive cannot directly recompute binary hashes.

`functional/` contains original results/logs for existing functionality regression tests. `local-review.json`
summarizes counts, hashes, and revalidation; file hashes for this folder are in `SHA256.json`.
A GitHub workflow was added, but successful GitHub runner execution was not verified in this environment.
Use the [OCI·WSL guide](../../LIFECYCLE.md) for reproduction.

## Submitted WSL lifecycle results

Validated submitted evidence for pinned commit `9367c7688f3fac2e249b70e3439b3fcddc6e8060`.
The complete path list and hashes for 67 test source files match the corresponding Git blobs and
also match the local run's test sources. Used WSL2 x86-64, the same official nightly and LLVM 23.1.5, and pinned
Python dependencies.

| Check | Submitted record revalidation |
|---|---|
| Channel combination tests | 8 × 5 rounds = 40 cases, 135 detailed conditions matched |
| Real Rust authenticated TLS | 30 cases, cancellation/delivery/shutdown/admission-return observations matched |
| Independent Python peer TLS | 30 cases, original server stdout/stderr/return codes and verdicts matched |
| Native KEM cleanup | Rust peer total 90 jobs, final live key count 0; each independent server also had live key count 0 |
| Shutdown variants | 10 normal, 15 expected `Closed`, 5 `Deadline` after grace period |
| Compilation audit | Reparsed 127 records; sources, compiler, target, and ASan options matched for four required builds |
| Result file hashes | Internal list 21/21 matched |

Compared the 5 retained loop logs, Rust peer case/final summaries, independent peer cases, and original server
outputs against the result JSON separately. Also rechecked SID, transcript, and exporter for successful connections,
split application write lengths, and expected shutdown results. The five cases withholding close_notify
terminated directly with `Deadline` after approximately 2.015~2.018 seconds.
External watchdog termination was not counted as successful rejection.

Retained nm output for three executables contains ASan initialization symbols; all logs showed no unexpected
sanitizer, leak, or panic diagnostics. Executables were excluded from the submitted bundle,
so their binary hashes could not be directly recomputed. This is revalidation of submitted logs, observations, and audit records,
not the result of executing submitted programs. Detailed evidence and limitations are recorded in
[platform-review.json](platform-review.json).

WSL original bundle SHA-256:

```text
5631bab532e80b542f7547fa4b6b41412d6a22b65a301b84e5b5329bfd58fc32
```

The jointly submitted `Spiral-Rust-record-oci-20261108.tar.gz` concerns the previously verified record state
fuzzing bundle byte-for-byte and in SHA-256. Its internal tests use `suite: records`, commit
`0516222`; they are not added to this channel/TLS lifecycle result count. Previous OCI record
pass record, which is retained. The OCI file needed for this phase is
`Spiral-channel-lifecycle-oci-20261108.tar.gz`, which remains pending submission.
