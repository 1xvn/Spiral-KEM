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

Accept met the control criteria in both trials and the key comparison stayed below the threshold in both. Reject was inconclusive because its positive control missed +4.5 in both trials. The gate was fixed before measurement and both raw runs were retained. No observation was removed. These samples do not establish constant-time behavior or resolve the earlier Memcheck warnings.

The first local invocation failed before compilation because its Cargo wrapper lacked execute permission. The completed collection used the pinned Cargo executable directly. [Original setup failure](evidence/receive_timing_20261119/initial-setup-failure.json)

## OCI and WSL measurements

Both operators' archives report the same clean probe revision, `2bc7e44f15fbaafa450f857c6ebf9474c9d8aee1`. Each host contributed 48,000 observations. The review verified the trial CSV digests, pair order and source hashes for the probe, collector and lockfile. It recomputed the statistics from the four CSVs. The archives include operator-reported test executable hashes.

| Host | Decision | Trial 1 key t | Trial 2 key t |
| --- | --- | ---: | ---: |
| OCI AArch64 | accept | +1.292 | +0.296 |
| OCI AArch64 | reject | +0.471 | -1.047 |
| WSL2 x86-64 | accept | -1.090 | -0.256 |
| WSL2 x86-64 | reject | -0.285 | +0.441 |

For each decision on both hosts, the positive control reached +4.5 and the absolute sham statistic stayed below 4.5 in both trials. The fixed/varied key comparison stayed below the absolute threshold in each case. This finding applies to 64-byte synthetic DATA, role 0, and the conditions of each run. The earlier cloud x86-64 reject result remains inconclusive.

- [OCI AArch64 original timing archive](evidence/receive_timing_20261119/platforms/Spiral-rx-timing-oci.tar.gz)
- [WSL2 x86-64 original timing archive](evidence/receive_timing_20261119/platforms/Spiral-rx-timing-wsl.tar.gz)
- [Independent review with archive digests and recomputed control and key statistics](evidence/receive_timing_20261119/platforms/review.json)

## Cloud scheduler follow-up

The Linux test harness now brackets each wall-clock measurement with two readings from the same thread's `CLOCK_THREAD_CPUTIME_ID`. The v2 CSV adds `thread_cpu_ns` to each original row. An empty value represents an unavailable or regressed reading. The report preserves signed wall-minus-CPU differences and the three largest absolute paired wall-time differences per stream, with CPU readings for both observations. The CPU window brackets the wall interval, so the extra clock calls and boundary work can yield small negative gaps. A positive gap can include time when the guest thread did not execute and effects of the clock boundaries. The gap alone cannot identify a scheduler or hypervisor cause.

A separate scheduler JSON captures raw `/proc/thread-self/schedstat` snapshots before and after each stream, including its warm-up and fixture setup. Its three counters describe CPU runtime in nanoseconds, run-queue waiting time in nanoseconds and timeslices. The report also records whether the kernel's `sched_schedstats` flag was visible. Unavailable, disabled, regressed and reported-zero counters are distinguished. A reported zero without confirmation of the flag gives limited evidence. Stream counters cannot attribute time to an individual pair. All wall samples still enter the original paired statistic and control gate.

The follow-up at `ac0662350d7b3a1ddd874fdabbac34dc9f8c6206` ran two trials on cloud Linux x86-64, CPU 0, with CPU readings for all 48,000 observations. The guest did not expose the sysctl flag. The sum of reported per-stream run-queue wait was 141.6 μs in trial one and 117.7 μs in trial two.

| Decision | Trial 1 positive t | Trial 2 positive t | Trial 1 key t | Trial 2 key t | Screen |
| --- | ---: | ---: | ---: | ---: | --- |
| accept | +7.350 | +29.404 | +1.023 | −0.876 | Both draws below the key threshold with working controls |
| reject | +14.158 | +4.478 | −1.109 | +1.499 | Inconclusive because trial two missed the positive-control threshold |

In reject-positive trial two, the largest absolute paired wall delta was −428.102 μs. The longer sample recorded 434.280 μs of wall time and 434.749 μs in the wider CPU window. The stream reported 16.841 μs of run-queue wait. Those observations give little support for attributing that outlier to run-queue delay. The earlier cloud run lacks these counters, so the new measurements cannot explain its outlier. Both cloud reject collections still retain their inconclusive verdicts. [Raw CSVs, scheduler snapshots and report](evidence/receive_timing_20261121/cloud-x86_64.tar.gz)

To reproduce the new collector from its source commit, run the following on a Linux host with the dependencies listed below. Pass the pinned Cargo executable via `--cargo` when using a standalone toolchain.

```bash
RUSTUP_TOOLCHAIN=1.99.1 python3 -B protocol_rust/diagnostics/receive_timing.py \
  --output "$HOME/Spiral-rx-scheduler-$(date -u +%Y%m%dT%H%M%SZ)"
```

## Focused authentication-reject control run

The optional `--reject-controls` mode measures the same 64-byte synthetic DATA and forces a bad tag at the final byte. It runs four streams in each of two trials with reversed stream order. Each stream has 128 warm-up pairs and 2,000 measured pairs, for 32,000 raw durations across both trials. The paired groups use matched public conditions and retain CPU-time and scheduler observations.

| Stream | Class B change relative to A |
| --- | --- |
| `positive` | 128 additional spin hints inside the timed interval, matching the original control workload |
| `positive_large` | 512 additional spin hints inside the timed interval |
| `sham` | Same fixture, with the original balanced execution order |
| `key` | Varied synthetic key with a matching freshly generated bad-tag record |

The two fixed workloads are set before collection. Their observed median paired deltas describe the signal sizes on the measured host. Spin hints cannot specify a fixed nanosecond difference across machines. Each positive t must reach +4.5 and the absolute sham t must stay below 4.5 in both trials before the fixed-versus-varied key result can be interpreted. This is a two-workload sensitivity check. All samples enter the original wall-time statistic and constant-time approval remains false.

Run from the focused collector checkout on Linux with the pinned Rust toolchain, `taskset` and Python 3.11 or later.

```bash
RUSTUP_TOOLCHAIN=1.99.1 python3 -B protocol_rust/diagnostics/receive_timing.py \
  --reject-controls --output "$HOME/Spiral-rx-reject-controls-$(date -u +%Y%m%dT%H%M%SZ)"
```

The printed `.tar.gz` path contains the raw timing CSVs, scheduler snapshots and `result.json`. The report includes the median paired deltas and the verdict. Review the controls and the `interpretation.reject` field even when collection exits successfully.

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
