# v0.3 memory investigation follow-up record · 2026-11-07

All 6 submitted memory checks passed on OCI ARM, while only 2 passed on WSL x86-64.
We reproduced the same AES-GCM warning pattern as WSL locally and identified a false-positive mechanism in
Valgrind definedness tracking for GHASH copy/branch/XOR operations. **The original WSL check remains a failure.**
This follow-up record includes no changes to production code, dependencies, TLS cipher policy, or warning handling rules.

## Submitted target environment results

| Case | OCI aarch64 error count | WSL x86-64 error count |
|---|---:|---:|
| Normal Spiral/TLS session | 0 | 5 |
| Invalid client Finished rejection | 0 | 0 |
| TLS only, default selection | 0 | 4 |
| TLS only, AES128 | 0 | 4 |
| TLS only, AES256 | 0 | 4 |
| TLS only, ChaCha | 0 | 0 |

The originals are under [evidence/memory_followup_20261107/](evidence/memory_followup_20261107/),
in `oci/` and `wsl/`. Both environments report Ubuntu 24.04, Valgrind 3.22.0,
glibc 2.39-0ubuntu8.9, and OpenSSL 3.0.13. CPU, architecture, and virtualization conditions differ.
`driver_exit.txt` is 0 and 1, respectively. Child processes for the WSL warning cases exited with 99.
Exit code 1 and the Authentication error for Finished rejection are expected behavior, so that case passes.

Both normal sessions reported authenticated CLOSE, `auth_key_closed=true`, `admission_released=true`,
and native `live_keys=0`. All 12 cases reported 0 definite/indirect/possible loss,
548 bytes still reachable, and 0 suppressions. These totals do not prove that all secret copies were erased.
The earlier Rust libtest 48-byte possibly-lost entry was not included in this submission and remains separate.

## Evidence for the cause

The WSL warnings appear in ring's authentication tag comparison and TLS `writev`.
The transmission warning is at offset 126 of a 142-byte allocation, the final 16-byte tag region.
The Ed25519 digest or hash `fork_finish` stacks in the origin are provenance information for reused state.
These symbols alone do not establish a defect in signing/hash functions or disclosure of KEM secrets.

We observed the same pattern in a small Rust TLS server containing neither Spiral nor the C KEM.
It used rustls 0.23.46 / ring 0.17.14 / tokio-rustls 0.26.6 / Tokio 1.54.1,
and a certificate-verifying Python ssl client confirmed TLS 1.3, a 120-byte echo, and normal TLS shutdown.

| Local TLS control | Unmodified public package | Definedness checks added | Checks + scratch initialization |
|---|---:|---:|---:|
| TLS_AES_128_GCM_SHA256 | 4 | 44 | 0 |
| TLS_AES_256_GCM_SHA384 | 4 | 44 | 0 |
| TLS_CHACHA20_POLY1305_SHA256 | 0 | 0 | 0 |

The 44 reports include 40 failures of the added `CHECK_MEM_IS_DEFINED`. This does not mean 44 independent defects.
The inspected inputs, AES round keys, and GHASH table were defined; the first failure was Xi after
the `gcm_ghash_avx` call for one block of AAD. The state then propagated to the tag and transmission buffer.

The GHASH short path in public ring 0.17.14 copies a temporary register value and XORs it with the original after a branch.
The actual values cancel to 0, but if Valgrind cannot track equality of the two register values across the branch,
it leaves the state undefined. We confirmed this with independent [XOR control code](diagnostics/xor_definedness.py).

| Public fixture control | Actual 0 output confirmed | Valgrind undefined reports |
|---|---:|---:|
| Copy → branch → XOR with original | 1,000 each native/instrumented | 1,000 |
| Direct XOR with itself | 1,000 each native/instrumented | 0 |

The control program first records definedness, then marks the public output defined solely to compare its byte values.
This treatment was not applied to TLS or the protocol. The new runner's `production_memory_passed` is always false,
and exit code 0 means the control conditions were consistent. If a future tool does not reproduce the false positive, it records `not_reproduced`.

When initialization of three caller-clobbered scratch registers was added to the GHASH entry in a separate copy of ring,
both the AES warnings and internal check failures disappeared. We also checked the actual linked instructions.
This is a diagnostic control, not a proposed production cryptographic library change.
It is also not a remeasurement applying the same change to the user's original WSL binary.

## Package provenance and upstream check

The SHA-256 of the ring `.crate` used matches
`a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` in Cargo.lock.
The original pregenerated assembly also matched that package byte for byte.
Detailed values are in `initial_local/ring_provenance.json`.

The [GHASH source on ring main](https://github.com/briansmith/ring/blob/57f81b455c30d55e3c92b55255cb0410abbb0dee/crypto/fipsmodule/aes/asm/ghash-x86_64.pl), checked on 2026-11-07,
contains the same short path. That development commit's manifest version is 0.17.16000.
This does not indicate a validated distribution version or a fixed release. This record does not conclude that upgrading resolves it.
We did not contact upstream or researchers.

## Contents and scope of the evidence

- `oci/`, `wsl/`: submitted logs, environment, driver results, and JSON.
- `initial_local/`: independent recalculation of submitted logs, package provenance, and initial XOR controls.
- `local_tls/`: results and logs for stock/intermediate-value checks/scratch initialization, diagnostic diffs, and source at the time.
- `xor_runner_validation/`: results actually confirmed with the new reproduction runner and full logs.
- `INPUT_ARCHIVES.json`: unchanged original ZIP hashes.
- `LOG_FORMATTING.json`: hashes before and after trimming trailing whitespace and normalizing line endings. Values, error counts, and exit codes were unchanged.
- `ARTIFACT_SHA256.json`: SHA-256 of all evidence and diagnostic code preserved here.

The local experiment used Debian 13 x86-64 / Rust 1.99.1 / GCC 14.2 / Valgrind 3.28.0,
with the Ubuntu glibc 2.39 debug loader/libc and host OpenSSL 3.5.7.
`local_tls/lab_source/host_specific_driver.py` is the original record containing host paths at the time.
`instrumentation.patch` and `scratch-initialization.patch` are separate diagnostic diffs against the ring 0.17.14 public package.
The latter is a control added on top of the former and is not applied to this repository's build. No Cargo patch configuration or modified ring is distributed.

This follow-up PR verified evidence recalculation and independent XOR reproduction. The unchanged full functional suite of 52 Rust tests and 35 real TLS tests
is not claimed to have been rerun in this PR. Existing `VALIDATION.json` and `evidence/v03/` preserve results from that time.
Validation of the full public package vectors, all message lengths, CPUs, compilers, constant time, and performance, and independent cryptanalysis, is incomplete.

## Remaining research and validation

The archived OCI/WSL benchmark results support review of this record; further experiments must retain their own source and environment provenance.
After this record has been reviewed, separate the libtest 48-byte warning into small shutdown/thread controls as a distinct task,
and check whether a maintained library offers a response that can be reviewed. A production GHASH change requires separate scope and regression validation.

To optionally recheck only the independent control, run the following in a repository containing the PR source.

**WSL Ubuntu 24.04 · x86-64** — Uses existing Valgrind and C compiler. No external Python packages are needed.

```bash
(
  set -euo pipefail
  cd "$HOME/spiral_v03_wsl/Spiral-KEM-main"
  python3 protocol_rust/diagnostics/xor_definedness.py \
    --output benchmark_results/xor_definedness
  tar -czf "$HOME/Spiral_v03_WSL_xor_20261107.tar.gz" \
    -C benchmark_results xor_definedness
  cp -- "$HOME/Spiral_v03_WSL_xor_20261107.tar.gz" \
    /mnt/c/Users/windows-user/Downloads/
)
```

If the output directory already exists, execution stops to protect existing evidence. Change both `--output` and the tar path to a new name.
The Valgrind child exit code 99 in cancel mode is the behavior this control aims to reproduce and remains unchanged in the original log.
The regular `memcheck.py` continues to treat warnings as failures.

**OCI Ubuntu 24.04 · ARM** — Do not run the x86-64 control above. Retain the 6 submitted passing results.

**Windows PowerShell · Check files transferred from WSL**

```powershell
Get-Item "$HOME\Downloads\Spiral_v03_WSL_xor_20261107.tar.gz"
```

The final `cp` in the WSL command transfers an archive of the results directory to the Windows Downloads directory.
This optional test has no step to upload code to OCI or download results again.
