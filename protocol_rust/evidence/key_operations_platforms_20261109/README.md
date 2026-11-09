# OCI·WSL validation record for operational key management

Reviewed the two originals submitted on 2026-11-09. For pinned source
`0b0db39d36b9a6f243486615ca2624a6b76ce02b` and runtime baseline
`486697682beb66db1af05bdc45867d122a25d145`, **key management platform functional validation is complete**.
Original archives are preserved unchanged, with each `.sha256` provided.

| Check | OCI ARM64 | WSL x86-64 |
|---|---|---|
| Rust library | 81 passed, failed0, ignored 5, measured/filtered0 | Same |
| Key management·real TLS rotation | 11 passed, failure/error/skip0 | Same |
| Source provenance | manifest 318·nested181 match Git, unchanged before/after execution | Same |
| Original result integrity | 40 file hashes match + SHA256.json =41 files | Same |
| Tools·execution | Rust/Cargo1.99.1, Python 3.12.3, 17 commands exit 0 | Same |
| Execution account·kernel | UID1001, 7.0.0-1013-oracle | UID1000, 6.18.54.1-microsoft-standard-WSL2 |

Compared names/statuses for the 86 original Rust tests (81 passed·5 ignored) against local originals from the same source.
Read names of the 11 key management tests from the pinned runner's AST and compared them against the 11 `ok` entries in original stderr,
then verified final `Ran 11 ... OK` and agreement between original stdout JSON and saved JSON.
The 5 ignored tests are 2 FFI taint tests and 3 receive audits; they are not counted as passes in this run.

The Rust compiler commit is `58cf8f9c35b355199727627d07ae34a4e2846d67`; the Cargo commit is
`5f94df4789f005f9a352888e8355ffc645b7ed0e`. Target hosts are respectively
`aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`; RustCrypto's 5 local patches
appear in actual compile logs, and compiled packages/versions match Cargo.lock.
Also compared the 5 pinned Python dependencies, venv, and pip check against original logs.

Recorded executable hashes follow; nested reports and before/after values match for each execution.

* OCI: `5b4962d85c7478fecbfe32649ca3a102167627186794dea385fca3ff6b36184f`
* WSL: `d472174fa9b5b88c983745db96d1b1394b83de13b18a2c8beddc5ddf9cc03525`

`platform-summary.json`, `oci-review.json`, and `wsl-review.json` record comparisons and archive hashes.
Run review from the repository root. This tool does not execute or
extract uploads; it reads tar, JSON, logs, and Git.

```bash
python3 -B protocol_rust/evidence/key_operations_platforms_20261109/review_uploaded_results.py --oci protocol_rust/evidence/key_operations_platforms_20261109/Spiral-key-ops-oci-aarch64-20261109T130652Z-rv8uq0i0.tar.gz --wsl protocol_rust/evidence/key_operations_platforms_20261109/Spiral-key-ops-wsl-x86_64-20261109T130652Z-m3oa5fpk.tar.gz --output-dir /tmp/spiral-key-ops-receipt-review
```

The reviewer's 3 status-parsing regression tests also passed (`receipt-verifier-tests.log`). They verify correct parsing of actual logs
and rejection of duplicates, additional failures, skips, and output after final OK. Rerun with
`python3 -B protocol_rust/evidence/key_operations_platforms_20261109/test_review_uploaded_results.py`.
These 3 reviewer tests are excluded from the target platforms' Rust 81 and key-management11 counts.

**Scope:** Finite tests of key-file access, creation, public output, public-value matching for copied recovery files, and loopback cold rotation.
Actual service UID configuration, encrypted backup/vault, approved pin distribution, long-term load/failure
recovery, deployment/rollback, and all of item 5 remain incomplete. Actual ELF files and tool binaries were not submitted, so their
physical hashes cannot be recomputed. Submitted metadata does not independently authenticate OCI provider identity or the remote machine,
or prove reproducible binary builds. Full functional CI, scratch
matrix, separate TLS 35, fuzzing, and Memcheck/ASan are not counted as rerun in these two executions.
Constant-time, overall memory, all of objectives 2/5, and deployment approval gates remain false.

## Earlier local prevalidation

Bundled pinned collection source `0b0db39d36b9a6f243486615ca2624a6b76ce02b` from Git, extracted it into a new path,
and executed it. Git diff confirmed runtime and existing test code match baseline main
`486697682beb66db1af05bdc45867d122a25d145`.

| Check | Actual result |
|---|---|
| Source manifest | 318 files, hashes unchanged before/after execution |
| Collector contract tests | 25 passed, failure/error0 |
| Rust library | 81 passed, 0 failed, 5 ignored, measured/filtered0 |
| Release build | Succeeded, using only a new BUILD directory, pinned Cargo.lock, and cache |
| Key management·loopback real TLS rotation | 11 passed, failure/error/skip0 |
| Executable | SHA256 unchanged before/after tests |
| Bundle regeneration | SHA256 matched for an independently generated archive from the same commit |
| Actual bundle tampering tests | Source changes rejected before command execution, failure archive retained; manifest changes rejected by launcher |
| Result archive | 31 public reports/logs/manifests, all SHA256 compared. BUILD/test keys/venv excluded |

Execution used normal Linux effective UID1000. Due to the prior sandbox's root directory ownership
mapping issue, ran with a normal UID view without relaxing key-file policy. Collection commands
follow. Paths here are specific to the local validation machine.

```bash
CARGO_HOME=/workspace/rust48-tools/cargo-cache python3 -B /workspace/key-ops-platform-validation/Spiral-key-operations-0b0db39/run_checks.py --platform local --python /workspace/spiral-protocol-v01/venv/bin/python --toolchain-dir /workspace/rust48-tools/rust --offline --output-parent /workspace/key-ops-platform-validation
```

Executable SHA256:
`aca25d3ca3e723a55e3f04b9fe2eaf953a84790d27391652a883f4b0baa333b2`.
Rust/Cargo1.99.1, compiler commit, host, tool versions, and original stdout/stderr are included in the local result archive.
Actual ELF files are excluded; no claim is made that binaries on all platforms have the same hash.
Input archive reproduction is distinct from reproducible binary builds.

* `local-result.json`: Original aggregate results from the actual local run.
* `Spiral-key-ops-local-*.tar.gz`: Original logs and source/binary hashes/manifests for that run.
* `collector-unit.log`: 25 collector tests executed from the actual bundle.
* `local-collector.log`: Stage/final result output from that run.
* `delivery-review.json`: Verification of matching hashes across two archives and tampering rejection.
* `Spiral-key-ops-local-*-83z3gk_0.tar.gz`: Rejection test with intentionally tampered sources.
  Not counted as an actual production-code failure or target-platform execution.

These local results and the actual OCI ARM/WSL submissions above are separate records. Local results do not count as approval on the two target
environments. Historical secret-flow results for pinned sources also remain preserved.
This run does not perform full functional CI, scratch matrix, separate TLS 35, fuzzing, Memcheck/ASan, long-term load,
or actual operational recovery. Memory/constant-time, all of objectives 2/5, and deployment approval gates
are all false. See [execution downloads and commands](../../../downloads/key-operations-0b0db39/README.md)
for details.
