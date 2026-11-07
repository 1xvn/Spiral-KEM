# Memory follow-up evidence, 2026-11-07

Read [the investigation](../../MEMORY_FOLLOWUP.md) for the verdict and scope.
Submitted WSL failures remain failures. Local controls do not certify production
memory safety, zeroization, constant time, or cryptographic security.

The OCI and WSL subdirectories preserve submitted values and exit codes.
`LOG_FORMATTING.json` identifies byte changes made only to trailing whitespace
and line endings for source control. Original archive hashes are in
`INPUT_ARCHIVES.json`; `initial_local/submitted_log_verification.json` retains
original log hashes and independently checked counts.

`local_tls/lab_source/` records the historical small experiment, including its
host-specific driver paths. Its stock manifest has no Cargo patch. The
instrumented experiment added the recorded instrumentation diff to a separate
ring 0.17.14 copy; the final comparison additionally added the scratch diff.
The diffs have zero context and are evidence for review, not production patches.
The original registry source and application were not changed. No private key,
certificate, vendored ring tree, compiled binary, or Cargo override is included.

`xor_runner_validation/` contains a fresh real run of the portable Linux x86-64
control in `../../diagnostics/`. Its exit 0 reports diagnostic consistency only;
the cancel child still exits 99 with 1,000 Memcheck errors and the clear child
exits 0. Both pass all 1,000 actual zero-byte output checks.

`ARTIFACT_SHA256.json` covers every stored file in this directory except itself
and also the investigation document and three diagnostic source files. It does
not replace the historical v0.3 `SOURCE_SHA256.json` or earlier validation data.
