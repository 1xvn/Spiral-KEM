# Local checks of the key management platform collector and validation bundle

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

**New OCI ARM·WSL key management results are still awaiting submission.** These local results do not count as approval on the two target
environments. Historical secret-flow results for pinned sources also remain preserved.
This run does not perform full functional CI, scratch matrix, separate TLS 35, fuzzing, Memcheck/ASan, long-term load,
or actual operational recovery. Memory/constant-time, all of objectives 2/5, and deployment approval gates
are all false. See [execution downloads and commands](../../../downloads/key-operations-0b0db39/README.md)
for details.
