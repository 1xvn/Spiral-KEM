# Timing a 64-byte authenticated DATA receive

The diagnostic calls the crate's real `Rx::decode` on disposable public fixtures. Two independent libtest processes run the same predeclared comparisons with different fixture sets. Use the results to decide which host and comparison need more measurements. A threshold crossing alone cannot identify a key leak.

## Measurement contract

| Held constant within a pair | Changes between classes |
| --- | --- |
| 64-byte DATA, sender role 0, receiver role 1, session ID, sequence 0, nonce prefix, plaintext and execution CPU | For the **key** comparison, class A uses one fixed synthetic key. Class B uses a different deterministic synthetic key per pair. Encryption produces a valid frame for each key, so ciphertext and tag bytes can differ between classes. |
| Each class attempts the same decision within its stream | **Accept** verifies DATA and plaintext after the timer stops. **Reject** flips the last tag byte before measurement and requires `Error::Authentication`. The collector computes separate statistics for accept and reject. |
| The **sham** and **positive** comparisons use the same key and frame for both classes in a pair | The sham changes only the class label and execution order. The positive adds 128 spin hints inside B's timed interval to test sensitivity to deliberate extra work. |

Each trial runs six streams (three comparisons × two decisions), with 128 warm-up pairs followed by 2,000 measured pairs per stream. AB and BA order alternate within randomized two-pair blocks; the first order in a block is selected by a public deterministic digest. Trial two reverses the stream order. Trial and pair IDs give separate nonce prefixes across pairs and domains separate the fixture material from the ordering. Each observation creates fresh sender, receiver, record and pool state. The harness retains all measured durations in order and writes CSV after all streams. The resulting 48,000 observations across both trials exclude warm-ups.

The interval uses `std::time::Instant` in one process pinned to a single available CPU. It begins after fixture construction, sender sealing, receiver setup and tag modification. It covers record decoding, including terminal key disposal on rejection; on success the returned plaintext and the still-live receiver drop outside the interval. This is a warm, same-host operation. CPU frequency, VM scheduling and clock quality may affect it. Network delays, TLS I/O, key generation and absolute Windows/OCI timestamps do not enter the calculation.

## Decision rule fixed before collection

For each stream compute the paired differences in nanoseconds (B minus A) and `t = mean(d) / (sd(d) / sqrt(n))`. Keep every measured pair. The collector rejects incomplete, duplicated or unbalanced data. Zero variance in the differences leaves the statistic undefined.

Each decision needs a positive-control t of at least +4.5 and a sham |t| below 4.5 in **both** trials. If either control fails or any statistic is undefined, that decision is inconclusive. Otherwise flag a repeatable threshold crossing only if both key-comparison statistics reach 4.5 in the same direction. Report a single or opposed crossing separately. A completed collection can be inconclusive. This screening threshold does not establish a formal significance level for noisy dependent samples. The JSON always leaves constant-time approval false.

## Local x86-64 measurements

The Linux x86-64 collection on CPU 0 (Intel Xeon Platinum 8573C) used clean source `2bc7e44f15fbaafa450f857c6ebf9474c9d8aee1`. Each trial produced 24,000 raw observations. The recorded binary hash, CPU affinity mask, tool versions, build log, sample CSVs and full-precision results are in the [original archive](evidence/receive_timing_20261119/linux-x86_64.tar.gz).

| Decision | Trial | Positive t | Sham t | Fixed/varied key t |
| --- | ---: | ---: | ---: | ---: |
| accept | 1 | +5.664 | +0.437 | +0.230 |
| accept | 2 | +8.257 | -0.110 | +1.433 |
| reject | 1 | +2.077 | +0.840 | +0.668 |
| reject | 2 | +4.028 | +0.510 | +0.463 |

Accept met the control criteria in both trials and the key comparison stayed below the threshold in both. Reject was inconclusive because its positive control missed +4.5 in both trials. The gate was fixed before measurement and both raw runs were retained. No observation was removed. These samples do not establish constant-time behavior or resolve the earlier Memcheck warnings. OCI AArch64 and WSL measurements of this probe are pending.

The first local invocation failed before compilation because its Cargo wrapper lacked execute permission. The completed collection used the pinned Cargo executable directly. [Original setup failure](evidence/receive_timing_20261119/initial-setup-failure.json)

## WSL Ubuntu or OCI SSH Ubuntu

Use Ubuntu with Git, Rust 1.99.1, a C toolchain, OpenSSL development headers, util-linux taskset and Python 3.11 or later. Run once per host. Both trials use the lowest-numbered logical CPU in the collector's allowed affinity mask. Each measurement process has a 120-second deadline and compilation has a separate 30-minute limit. Each run creates a new directory under the user's home.

```bash
(
  set -eu
  umask 077
  if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
  run=$(mktemp -d "$HOME/Spiral-rx-timing-XXXXXXXX")
  git init -q "$run/source"
  cd "$run/source"
  pin=2bc7e44f15fbaafa450f857c6ebf9474c9d8aee1
  git fetch -q --depth=1 https://github.com/1xvn/Spiral-KEM.git "$pin"
  git checkout -q --detach FETCH_HEAD
  test "$(git rev-parse HEAD)" = "$pin"
  export CARGO_TARGET_DIR="$run/target"
  RUSTUP_TOOLCHAIN=1.99.1 python3 -B protocol_rust/diagnostics/receive_timing.py \
    --output "$run/Spiral-rx-timing-$(uname -m)"
)
```

The last line prints the archive path, including on a handled build or collection failure. The archive contains the report and available build log, trial logs and raw measurements. A zero collector exit means both trials were collected, validated and summarized. The decision is in `result.json`.

**Windows PowerShell, WSL result.** Enter the full archive path printed by the collector.

```powershell
$path = Read-Host 'WSL timing archive path'
$src = (wsl.exe -d Ubuntu-24.04 -- wslpath -w "$path").Trim()
$dest = Join-Path "$env:USERPROFILE\Downloads" "Spiral-rx-timing-wsl.tar.gz"
Copy-Item -LiteralPath $src -Destination $dest -ErrorAction Stop
Get-FileHash -Algorithm SHA256 -LiteralPath $dest
```

**Windows PowerShell, OCI result.** Use the same SSH alias and identity as for a successful login. If the working SSH command uses an explicit key path, add the same `-i` option to scp.

```powershell
$oci = Read-Host 'OCI SSH alias or ubuntu@host'
$path = Read-Host 'OCI timing archive path'
$dest = Join-Path "$env:USERPROFILE\Downloads" "Spiral-rx-timing-oci.tar.gz"
scp "${oci}:$path" "$dest"
if ($LASTEXITCODE -eq 0) { Get-FileHash -Algorithm SHA256 -LiteralPath $dest }
```
