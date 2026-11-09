# Local validation of encrypted backup/recovery and replacement-failure drills

Pinned source is `d4c46bc81012e095ab8c78ac6e362ce2b6a63798`, based on main
`d2f19b9e733359f14331d7064a41697c851a1d80`. The new key-management module encrypts authentication seeds and TLS
PEM with a separate 32-byte recovery key; recovery compares fingerprints derived from plaintext against both the header and external
expected values before publishing only to new files using the existing private-file writer.
See [operating procedures and limitations](../../KEY_RECOVERY.md).

## Observed results

| Check | Result |
|---|---|
| Full functional CI | Python85, diagnostics24, C9, Rust94, cleanup matrix23, documentation6, existing key management11, recovery20, TLS35 passed |
| Rust exclusions | 5 ignored in the default library, separate and not added to passes |
| Final expanded recovery tests | 20 passed with the same CI release binary, failure/error/skip0 |
| Final pinned bundle run | Extracted to a new path: Rust94/ignored5, key management11, recovery20 passed; release succeeded |
| Pinned bundle provenance | 324 source hashes compared against Git, unchanged before/after execution |
| nested inputs | Existing key management182 and recovery193 hashes match pinned manifests |
| Collector contract checks | 13 passed in the final bundle |
| Archive regeneration/tampering rejection | Independently generated archive SHA256 matches; manifest/helper changes rejected before execution |
| Final result archive | 34 public files (33 hashes + SHA256.json), excluding BUILD, venv, and test keys |

Recovery20 counts methods and includes subtests for tampering, length, permissions, role, and algorithm.
Final tests independently compare PKCS8/PKCS1/SEC1 public fingerprints for Ed25519, RSA2048, and ECDSA P256/P384
against Python cryptography SPKI and verify PEM byte equality. They include maximum 65536B
TLS PEM/65610B archives; incorrect keys, fingerprints, roles, headers/ciphertexts/tags; truncation/appending/oversized input;
existing-destination preservation; and output checks for raw/hex/base64 and PEM/DER secret values.

Actual loopback TLS drills verified rejecting startup of an invalid new generation then restarting a valid previous generation, terminating a new
process before healthcheck then restarting a valid previous generation, encrypted recovery of both new-generation keys and
authenticated CLOSE with the new pin, and preservation of active files when rejecting a partially recovered inactive generation and previous backups.
No actual service, vault, distributed pin delivery, or rollback to compromised keys was exercised.

Execution used a normal Linux effective UID1000, Rust/Cargo1.99.1, and pinned Python requirements.
The branch actually using chown for a file owner with a separate UID was not run; the runner retains
`foreign_owner_checks_exercised=false`. Numeric UID rejection checks in the existing Rust file policy
are included separately. This does not establish full isolation between OS users.

## Original materials and provenance

* `functional-ci/`: Actual full CI results, logs, and JSON. The scratch build target was not copied.
* `recovery-final.json/log`: Final20 with expanded TLS algorithm/encoding subtests. The 193 source files and binary were unchanged before/after execution.
* `standalone-result.json`, `standalone-collector.log`, `Spiral-key-recovery-local-*.tar.gz`: Actual execution of the final bundle itself.
* `local-review.json`: Results of comparing 324 source files against Git and confirming matching nested hashes, archive files, and binary hashes.
* `collector-contract.log`, `delivery-review.json`: Checks of 13 collector tests, archive regeneration, and tampering rejection.

TLS algorithm subtests were expanded after the initial recovery20 in full CI. With the same
release binary as the current runner, the final20 were rerun; separately, the pinned bundle also confirmed all94/11/20.
The initial CI `key-recovery.json` was not revised to represent the final runner execution.

Executable SHA256 for CI and final expanded tests:
`f4dcfabf0fdd7a842ac5b50074eae9a589a80609bb486f2261a3781fdec75c62`.
SHA256 for the separate pinned-bundle build:
`7bd1f1cf698a8896afd74e7f433cdb2b4ac4552ec580738a352a9e7f343d8542`.
Before/after values for each execution match nested reports. ELFs from different build paths are not claimed to have the same
hash; the final archive does not include ELF/tool binaries.
Reproducing the pinned input archive is distinct from demonstrating a reproducible binary build.

## Preserved initial failures

* `focused-sandbox-transcript.log`: Initial verdicts for 13 focused tests rejected by the protection boundary because sandbox root/tmp UID mapped to65534.
* `focused-normal-transcript.log`: Verdicts showing the same13 passing under a normal UID view without relaxing policy. Both files preserve tool-output transcripts, not full dependency compilation output.
* `recovery-format-error.json/log`: Initial20 results failing because an added encoding subtest read `.name`, which cryptography's PrivateFormat lacks. After changing test code to explicit names, the final20 passed.
* `initial-bundle-contract.log`: Original result where 1 of13 failed because the initial323-source bundle omitted the launcher template for optional collector tests. The final324 bundle includes that template and passed all13.

These materials are not converted to successes, and failed initial runs are not added to completed counts.

## Target environments and remaining scope

New-code OCI ARM/WSL results are still awaiting submission.
Use the [execution bundle and commands](../../../downloads/key-recovery-d4c46bc/README.md).
Previous `0b0db39` key-management results or local runs are not counted as execution of new code on both platforms.

Final-bundle collection runs only Rust94, key management11, and recovery20; it does not establish execution of full CI, scratch matrix, documentation, separate
TLS35, fuzzing, Memcheck/ASan, or long-term load. Production service accounts,
separate encrypted storage/vault for recovery keys, approved pin distribution, power/storage failures, actual service recovery and
deployment/rollback, and all of item5 remain outstanding. Constant-time, overall memory, overall goals2/5, and deployment approval
gates all remain false.
