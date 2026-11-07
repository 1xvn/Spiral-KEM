# Local validation of the first C public key target · OCI/WSL results pending

This records initial local validation of shared tooling intended for OCI and WSL.
This directory contains no new C fuzzing results from OCI or WSL.

Actual conditions for `local-clang19/result.json` are Debian 13 x86-64 / Clang 19.1.7 / OpenSSL 3.5.7.
These differ from the shared runner's default comparison conditions, Ubuntu 24.04 / Clang 18.
Checked commit `61ad591`, confirming SHA-256 for 5 sources matches that commit.

libFuzzer executed 100,000 times against the public-key parsing/fixed-message encapsulation target.
Initialization executions 10, final cov 73 / ft 79, engine exit 0, overall status passed.
ASan, UBSan, and leak checks were enabled; there were no failure inputs.
Shared OpenSSL machine code was not instrumented; decapsulation, Rust transport, constant-time, and full security assessment are excluded.

Also passed 4 result-adjudication tests and 9 existing C–Python regression tests.
This is a finite execution starting from fixed seeds, not a general proof of error absence.

`sandbox-lsan-failure/` preserves an initial failure during runner preparation unchanged.
After 2,000 executions, LeakSanitizer stopped due to ptrace environment restrictions; the engine exited 77.
The log shows a crash input, but the cause was a leak-check tool restriction at termination.
Completed by rerunning in a permitted execution environment without disabling leak checks.
The initial run preceded source commit, so `sources_match_head` is false and the runner hash also
differs from the final version. This record is not used as passing validation of the final version.

The local validation environment lacks sudo, so system packages were unchanged.
Used the previously signature-verified Debian Release and matching-hash Packages index,
verified SHA-256 for the 4 official .deb files in `compiler-packages.json`, and extracted into the working folder.
Used them with existing system libLLVM19; package extracts and executable binaries are not committed.

On OCI ARM64 and WSL2 x86-64, run separately according to the [shared instructions](../../FUZZ_PLATFORMS.md)
and assess both original result bundles. Existing results from other OCI/WSL tests are
not counted as passes for this new check.
