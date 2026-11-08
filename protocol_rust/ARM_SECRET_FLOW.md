# ARM64 secret-branch and address-access instrumentation

Added the Valgrind client-request ABI for Linux ARM64. It uses a test-only common module,
preserving production keys/wire/cryptographic operations. x86-64 tests use the same module.
Passing existing ARM functional tests is separate from completion of this secret-flow instrumentation.
We reviewed the [OCI ARM submission results](evidence/arm_secret_flow_20261108/README.md) for corrected source `7bff0e4`
and confirmed **70 basic tests and 160 Memcheck collection runs complete**.
We do not approve constant time or full memory checks.

We confirmed that the collector in the earlier `26dd0d6` OCI submission required `.git` and stopped before instrumentation
began. The originals are retained in the [fix record](evidence/arm_standalone_fix_20261108/README.md),
and both collectors were fixed to share verified `SOURCE.json`.
The 70 regular Rust tests passed, but there were 0 actual Memcheck runs at that time, so that failure evidence does not count as completed ARM instrumentation.
The [corrected download bundle](../downloads/arm-secret-flow-7bff0e4/README.md) was verified outside Git:
641 source files verified, 70 basic tests, and 160 Memcheck collection runs. This revalidation is
a local x86-64 run; actual ARM completion is supported by the subsequent OCI submission above.

## Collection scope

1. Check70 Rust public-fixture tests and5 separate ignored tests.
2. Intentional secret-branch and secret-address-read controls must each be detected.
3. Run key derivation, transmission seal, and signing with public-reference/secret-shadow states separately.
4. Mark actual Rx32-byte keys and4-byte nonce prefixes secret, then execute78 public and78 secret cases.
   Packets are constructed before marking; production decode is called.
5. Preserve original exit codes, stacks, runtime PCs, ELF mappings, linked instructions, and source/binary hashes.

Receive cases include both roles, lengths1/16/63/64/65/1024/16384, valid/tampered DATA, public-header
errors, valid CLOSE, and authenticated invalid CLOSE reasons. At length65, each of16 tag
bytes is tampered individually. Total Memcheck runs:160.

Receiving does not declassify keys, tags, results, or plaintext. It retains the public-result contract for authentication success/failure and CLOSE-reason
range validity. Warnings are classified as explanatory
candidates only when linked instructions correspond to source; others remain unclassified. Existing key-derivation/transmission/signing controls retain the existing contract declassifying only wire
Finished, ciphertext, public-key, and signature outputs.
Those controls are not included in the receiving no-declassification claim.

Existing controls also restore synthetic input-seed shadows to
defined state after all signing operations/identity disposal finish. Seed/derived-key taint remains during operations. This test-exit
cleanup is included in declassification scope; actual receive tracing has no such processing.

All warnings, memory items, and original exit99 are preserved; no suppressions are added.
`diagnostic_complete=true`/runner exit0 indicates collection completion, not constant-time approval.
`constant_time_approved=false` and `production_memory_passed=false` remain.
Address-mapping completion/unclassified warnings are checked separately. Failed/missing positive controls and unexpected memory
access errors do not count as diagnostic completion. Unsupported CPU instructions in tools are also
preserved in originals and distinguished from actual secret-dependent behavior.

## ABI and validation status

Based on `PLAT_arm64_linux` in Valgrind3.24 `valgrind.h`. X4=request pointer,
X3=default/result, X12 rotates by3/13/51/61 bits, using `orr x10,x10,x10`.
Rust asm assumes neither memory nor flags preservation. Test ABI is absent from normal binaries.

We performed local x86-64 functional/instrumentation regressions and cross-compiled the ARM request module with official Rust 1.99.1.
Later OCI submissions confirmed an actual ARM audit build and 70 passing regular tests,
but Memcheck did not run then because of the collector error.
The corrected bundle was subsequently rerun on actual OCI ARM and reviewed. The 78 public/secret receive pairs,
2 positive controls, and 2 key derivation/transmission/signing cases completed. ARM also adds 5 ignored instrumentation tests,
which are not added to the 70 regular functional passes.

On ARM, public reception has 0 branch/address warnings; secret reception has candidate categories of 64 authentication decisions, 64 result propagation contexts,
and 6 CLOSE reason range checks, totaling 134 contexts. There are 0 unclassified receive contexts,
and all warning PCs, including 2 intentional positive controls, map to ARM instructions.
All 160 runs preserve original exit 99 and the std/libtest possibly-lost 48-byte entry.
This is **completion of this ARM collection phase**, not completion of all of item 2, constant time, or full memory checks.

## Execution

Reproduction instructions follow.
Pinned source-download bundles verify hashes within their own folder before running the collector.
Extract under OCI home and run the bundle's `run_checks.py --platform oci`.
Requires exact Rust1.99.1, Valgrind, binutils, and C/OpenSSL development environments. On Ubuntu,
install the following if system packages are missing.

```bash
sudo apt-get update &&
sudo apt-get install -y valgrind libc6-dbg binutils build-essential pkg-config libssl-dev
```

Source checkouts can run directly.

```bash
python3 protocol_rust/diagnostics/secret_flow_campaign.py
```

No external Python packages are required. The first Cargo build may download dependencies.
Creates new results/`.tar.gz` in home every time and displays the final archive path. Detailed progress
is retained in the result folder's `secret-flow.log` and `trace/`. Failures/timeouts are also preserved.
`build/` executables are excluded from archives. Installed tools can be selected with `--toolchain-dir`
and `--valgrind`.

This does not prove safety of all cache/power/speculative-execution/timing distributions or zeroization of registers/previous copies.
Rust-path results do not establish ARM safety for the entire C KEM or TLS provider.
