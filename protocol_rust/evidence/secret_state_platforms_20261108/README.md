# OCI·WSL functional regression after hash-state cleanup · 2026-11-08

Reviewed user-submitted results for source `fcf7ff07ecba260f6b446baa7f1efd55bbe11ec2`.
**Functional regressions passed on both platforms.** This does not approve overall memory safety, constant-time behavior, Spiral's own cryptographic
security, or completion of all of item 2.

| Check | OCI ARM | WSL2 x86-64 |
|---|---:|---:|
| Python protocol | 85 passed | 85 passed |
| Diagnostic adjudication | 20 passed | 20 passed |
| C KEM | 9 passed | 9 passed |
| Rust unit | 70 passed | 70 passed |
| Separate ignored instrumentation targets | 0 | 5 |
| Compile-fail documentation | 6 passed | 6 passed |
| Release build | Succeeded | Succeeded |
| Real TLS negative/interoperability | 35 passed | 35 passed |

Both environments had 0 failures/errors. The 5 ignored tests are x86-64-only instrumentation targets, excluded from normal functionality
pass counts. ARM ignored 0 also does not mean ARM secret-branch instrumentation was performed.

## Evidence

Compared each archive's internal manifest against 21 files, with no missing/extra files or hash mismatches.
Compared JSON pass indicators against execution counts in original unittest/Rust/TLS logs.
Attachments were neither executed nor extracted; only regular JSON/log files inside tar were read.

The supplied pinned launcher's SHA-256 and source manifest/CI/Cargo.lock hashes all match.
The launcher records comparing 603 source files to the same commit and confirming no changes after execution.
Submitted logs themselves do not contain full sources or a trusted remote host signature.
This limitation is also stated in `platform-review.json`.

- Rust/Cargo: exact 1.99.1, rustc commit `58cf8f9c35b355199727627d07ae34a4e2846d67`.
- Python: both environments 3.12.3; 5 existing pinned requirements and pip check passed.
- OCI: aarch64, kernel `7.0.0-1013-oracle`.
- WSL: x86-64, kernel `6.18.54.1-microsoft-standard-WSL2`.
- Both compilation logs: HMAC0.13.0·HKDF0.13.0·SHA2 0.11.1·dalek3.0.0·curve5.0.0 verified.
- Binary hashes differ across CPUs; each was built from the same sources, lockfile, and tool versions.

## Files

| Evidence | Contents |
|---|---|
| `Spiral-check-oci-aarch64-20261108-055618-lw5nw5c4.tar.gz` | Accepted OCI original, SHA-256 `09728bbae70fcb1b5bd7a74fc8d55dd573c2b3969c902b00132a52f6241bbebe` |
| `Spiral-check-wsl-x86_64-20261108-060144-gyjqohv_.tar.gz` | Accepted WSL original, SHA-256 `a4826110c6c8ad94948aee8a300efe65b493256aaf58cbf3f2212ef75c3a605e` |
| `platform-review.json` | Cross-review/provenance/counts/adjudication scope for the two results above |
| `review_archives.py` | stdlib-only review code that neither executes nor extracts files |
| `reviewer-controls.json` | Controls ensuring old evidence, empty archives, and hash tampering do not count as completion |
| `earlier-submissions/` | 2 previously excluded old-source results, empty WSL45-byte tar, and review records from that time |
| `SHA256.json` | Individual file hashes in this folder, excluding the list itself |

Earlier OCI evidence used an old runner with a fixed ignored 2 condition; even though Rust 60 tests passed,
the runner stopped. Earlier WSL evidence passed within its scope at that time. The later
WSL45-byte file had 0 members. These materials are excluded from validation counts for the latest changes,
and originals are preserved unchanged. New results did not overwrite previous failures as corrected versions.

## Review

Run the following in this directory to generate new JSON. The output path must be a new file.

```bash
python3 review_archives.py \
  --oci Spiral-check-oci-aarch64-20261108-055618-lw5nw5c4.tar.gz \
  --wsl Spiral-check-wsl-x86_64-20261108-060144-gyjqohv_.tar.gz \
  --output platform-review-new.json
```

Review of the submitted results is complete. This record concerns functional checks.
Existing WSL AES-GCM/48-byte memory warnings, ARM secret branch/address instrumentation, library internal
output/nonce copies, and operational key policies remain separate unfinished scope.
