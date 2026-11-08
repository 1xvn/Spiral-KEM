# Automated check guide

This configuration checks functional regressions when changes are submitted and preserves memory warnings separately.
Successful functionality checks do not mean overall memory, constant-time, or cryptographic security approval.

## What runs and when

| GitHub Actions name | Trigger | Checks and adjudication |
|---|---|---|
| Functional validation | push, Pull Request, manual | Python/C/Rust functionality and real TLS. Failures, 0 tests, and unexpected skips fail |
| Coverage-guided Python fuzzing | push, Pull Request, manual, every Monday 04:29 UTC | Fuzz 5 targets using Python runtime feedback. Exceptions, verdict mismatches, 0 executions, and initialization-only runs fail |
| Native C ciphertext fuzzing | push, Pull Request, manual | C ciphertext/key lifetime checks and Python differential checks of saved corpus. Uses ASan/UBSan/leak checks; OCI/WSL runs are separate |
| Rust parser coverage fuzzing | push, Pull Request, manual | Validate frame/ClientHello parser instrumentation with a separately pinned nightly, then fuzz and recheck with Python. OCI/WSL runs are separate |
| Rust record state coverage fuzzing | push, Pull Request, manual | Compare Rust DATA/CLOSE `Tx`/`Rx` state against an independent model and recheck saved inputs with Python. Full channel/TLS state and OCI/WSL runs are separate |
| Channel and TLS lifecycle validation | push, Pull Request, manual | Channel combination tests for partial writes/cancellation/shutdown/timeouts and actual authenticated TLS lifecycles. Uses ASan/leak checks; runtime coverage collection and OCI/WSL runs are separate |
| Runtime memory diagnostics | Manual, every Monday 02:17 UTC on default branch | Minimal std/libtest controls. Separate diagnostic completion from memory approval; reproduced warnings are failures |

For PRs, see **Checks** for functional results. Repository **Actions** provides per-run logs and
evidence artifacts. These do not run in repositories with GitHub Actions disabled.
Scheduled runs and the default branch's manual run list become available after the workflow is merged into the default branch.
See the [fuzzing guide](../fuzzing/README.md) for execution limits, reproduction, and check scope.
Rust record OCI/WSL commands are in the [DATA/CLOSE state fuzzing guide](../protocol_rust/FUZZ_RECORDS.md).
For channel shutdown/cancellation combination tests, see the [channel/TLS lifecycle guide](../protocol_rust/LIFECYCLE.md).

If the current 48-byte warning reproduces in the same environment, a red Runtime memory diagnostics failure is expected.
Completion of controls in the added [standard thread ownership/buffer disposal investigation](../protocol_rust/SECRET_MEMORY.md)
does not replace this clean-memory gate. Weekly/manual jobs also retain the ownership control bundle.
Do not turn results green using `continue-on-error` or suppressions. Functionality and memory jobs are separate.
Even if all 6 memory controls are clean, that is only a std control result for that environment, not resolution of the original warning or production system approval.
TLS AES-GCM, full Rust taint/memory checks, and long-running fuzzing are outside this minimal control workflow.

## Reproducible conditions

- Root `rust-toolchain.toml` and functional CI use Rust **1.99.1**. Rust parser/record fuzzing and channel lifecycle checks use **nightly-2026-11-07** in a separate folder. Install Cargo dependencies with `--locked`.
- Use Python **3.12** and existing exact-pin requirements.
- Actions checkout/setup-python/upload-artifact are pinned to commit SHAs verified in official repositories.
- Workflow permissions are `contents: read`; checkout credential persistence is disabled. `pull_request_target` is not used.
- Save each run's results in a new folder; do not overwrite existing evidence folders.
- Upload only dedicated logs/JSON/generated public test sources and public fuzz inputs; do not upload executables, temporary authentication keys, or certificates.

## Initial local validation on 2026-11-07

The GitHub runner itself was not run in this environment. Below are actual results from running the same `ci/validate.py`
in the current Linux environment with verified Rust 1.99.1 and the existing Python venv.

| Check | Result |
|---|---|
| Python protocol | 85 passed |
| Diagnostic result parser | 6 passed |
| C–Python comparison | 9 passed |
| Rust library | 52 passed; 2 ignored separate taint targets excluded from pass counts |
| Rust compile-fail documentation | 4 passed |
| Release build·real Rust TLS | Build succeeded, 35 passed |
| CI memory adjudication regression checks | 7 passed |
| Applying CI gate to actual 48-byte result | Exit 1: expected behavior retaining the known warning as failure |

The initial local run uncovered a runner bug that resolved the venv executable symlink and ran system Python.
After fixing it to preserve the venv path, the full run passed. Original failure logs and post-fix results
are both preserved in `local_ci_20261107/`. These local results are distinct from actual successful execution on GitHub.

The final functional runner in the November 8 [receive follow-up validation](../protocol_rust/RECEIVE_SECRET.md)
passed Python 85·diagnostic adjudication 20·C 9·Rust unit 66·documentation 6·real TLS 35 tests.
The 5 ignored x86-64 tests are taint-only and excluded from normal pass counts. Diagnostic adjudication includes
address mapping, missing data, suppression, and original exit code checks, and runs in push/PR functional CI.
The full actual receive taint run is a separate manual diagnostic. Completion is not treated as memory/constant-time
approval, and the weekly clean-memory gate above remains.

The subsequent [HMAC·HKDF·signature state cleanup](../protocol_rust/SECRET_STATE.md)
raised the minimum Rust pass count to 70, including new RFC and independent ring signature regressions.
Rerunning the same functional runner passed Python 85·diagnostics 20·C9·Rust 70·documentation 6·TLS 35.

The subsequently submitted [OCI ARM·WSL2 functional results](../protocol_rust/evidence/secret_state_platforms_20261108/README.md) also
each passed those counts on the same `fcf7ff0` source. Compared 21 internal manifest entries per platform and
launcher/source verification records/runner/lock hashes. The 5 WSL ignored tests and instrumentation targets
for x86-64 that are not compiled on ARM were excluded from functionality pass counts.

## When manual reproduction is needed

In a normal environment, install pinned Python requirements and use the runner below.
The functional runner requires loopback TCP socket permissions, C/OpenSSL development tools, and Rust/Cargo 1.99.1.
Use a new output path. The runner does not automatically install missing tools or hide failures.

```bash
python ci/validate.py --output ci-results/functional-new
python -m unittest discover -s ci -p 'test_checks.py' -v
python protocol_rust/diagnostics/libtest_memory.py \
  --rustc "$(command -v rustc)" --valgrind "$(command -v valgrind)" \
  --output ci-results/memory-new
python ci/check_memory_result.py ci-results/memory-new/result.json
```

The final command fails on Memcheck errors, leaks, suppressions, or incomplete diagnostics.
Observing the currently known warning again does not count that execution as a memory success.
