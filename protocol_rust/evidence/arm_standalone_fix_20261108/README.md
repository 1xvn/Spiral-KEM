# Fix for ARM collector source-bundle execution error

The OCI submission for previous distributed source `26dd0d6` succeeded in the ARM optimized build and 70 normal Rust tests,
but `receive_flow.py` called `git rev-parse HEAD` in a folder without `.git`,
stopping before instrumentation began. Detection controls, key derivation/send/signature, and receive Memcheck ran 0 cases.
The `injected panic` message is intentional disposal/poison-test output, not an overall test failure.

This is a distribution collector bug, not a passing/failing result for actual ARM secret flow.
The previous archive and its failure verdict are preserved unchanged.

Both fixed collectors use shared `source_identity()`. If `SOURCE.json` exists,
verify all recorded file hashes without calling Git. Validation failure does not fall through to Git fallback.
For a Git checkout, the top level must match the source root; bundle and checkout
provenance types are recorded separately. Rust/C, ARM ABI, cryptographic operations, and dependencies are unchanged.

Regression tests cover bundles without Git calls, rejection of tampered/missing/empty-list/path-escape/invalid-commit inputs,
and Git top-level verification. 24 diagnostic tests passed. Extracted the actual fixed distribution source
`7bff0e4` into a non-Git folder under `/tmp`, verified 641 source hashes,70 default tests,
160 Memcheck runs, and automatic compression. Branch/address positive controls each detected their intended issue,
and 78 public/secret receive pairs plus 2 key-derivation/send/signature cases were recorded. These local results
are not counted as ARM execution; actual ARM collection requires a new submission from the fixed bundle.

Original exit 99 and the existing 48-byte possibly-lost item were preserved. `diagnostic_complete`
means collection completed. Candidate classifications of receive warnings also do not prove constant-time safety.
Also extracted the final archive into a new folder and verified prevalidation of normal sources and rejection of changed sources.

Use [downloads and OCI commands](../../../downloads/arm-secret-flow-7bff0e4/README.md).
Detailed counts for originals, review, and local reproduction are retained in this folder's JSON and archives.
`constant_time_approved=false` and `production_memory_passed=false` remain.
