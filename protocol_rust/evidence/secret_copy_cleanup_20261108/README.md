# Validation materials for the temporary secret-copy cleanup patch

Implementation/validation scope is in the [implementation report](../../SECRET_COPY_CLEANUP.md).
The production-code pinned revision is `7f26fed5b8176ddd009d44264fb5e9ab08fb8d31`.
Added CI runners, documents, and original records are committed separately on top.

- `review.json`: Review of original basic-functional/cleanup-matrix/ASan/standalone records and guarantee limitations.
- `functional-ci/`: Actual functional-CI execution results/logs. Cleanup matrix:7 runs/23 tests.
- `secret-copy-standalone-local.tar.gz`: Actual distribution-bundle execution validating864 source files outside Git.
  The two internal manifests and189 reported hashes of pinned Git source were compared independently.
- `secret-copy-asan.log`: ASan/leak checks exit0, 70 passed.
  `secret-copy-asan-sandbox.log` preserves the initial failure caused by LSan tracing-permission interruption unchanged.
- `linked-review/`: Review of selected actual optimized functions, zeroization instructions, and source/ELF hashes.
- `benchmark/`: Original294 samples/21 cases, code/tools/conditions/source hashes/figures/limitations.
- `secret-copy-fuzz-driver-tests.log`: 67 existing-runner regressions. These are not new long-term fuzzing results.

Original Memcheck exit99, 134 receive warnings, and the std/libtest48-byte item remain.
Collection/zeroization observations differ from constant-time/overall-memory approval. They do not establish erasure of backends, previous moves,
register/OS copies, or unused dalek conversion APIs.

Remeasurement bundles include third_party sources/licenses/provenance. Result materials excluding build executables from
archives are distinguished from source bundles built directly in the user's environment.
