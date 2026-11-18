# Short clock observations and expected-failure checks

Use this operator-run companion after preparing the existing load runner. It
records Linux UTC, CLOCK_MONOTONIC and CLOCK_BOOTTIME together and checks short
interruption and experimental resource-ceiling cases. The protocol runtime and
its production limits are unchanged. Running help, setup or CI does not start
these workloads. The operator chooses when to run them.

## Update the existing checkout

On both OCI Ubuntu and WSL Ubuntu:

```bash
cd "$HOME/Spiral-clock" &&
bash protocol_rust/run_load_test.sh --prepare
```

Use the same clock-observation revision on both hosts. The commands use
`~/Spiral-clock` for that checkout. The preparation command builds and checks
dependencies; it does not start a load test.

## One command per platform

The default clock campaign lasts five traffic minutes. After startup, the
interruption case runs traffic for about five seconds before automatically
sending one SIGINT to the collector. The three low-ceiling cases stop as soon as
the measured process exceeds the selected experimental guard. A healthy full
batch normally finishes in several minutes; reconnects and preparation add time.
Each non-clock case has a 60-second execution deadline plus bounded cleanup.
The clock case derives its stop bound from the existing collector watchdog and
allows 30 seconds for launch/archive overhead.

WSL Ubuntu:

```bash
cd "$HOME/Spiral-clock" &&
python3 -B protocol_rust/validation/short_operations.py --platform wsl --case all --windows-clock
```

OCI Ubuntu:

```bash
cd "$HOME/Spiral-clock" &&
python3 -B protocol_rust/validation/short_operations.py --platform oci --case all
```

Run one batch at a time on each host. Keep the machine awake. During the clock
case, `--windows-clock` asks the existing WSL `powershell.exe` integration for
Windows UTC every 30 seconds. Windows queries run separately from the Linux
sampler and have a three-second subprocess timeout. The load wrapper also
enables Windows queries for `--platform wsl`. Linux samples and functional
checks continue when Windows interop is unavailable.

## Individual cases

Use these from the repository directory. Replace `wsl` with `oci` and omit
`--windows-clock` for the OCI clock case.

| Purpose | Command |
| --- | --- |
| Five-minute clock observation | `python3 -B protocol_rust/validation/short_operations.py --platform wsl --case clock --windows-clock` |
| Collector interruption after verified traffic starts | `python3 -B protocol_rust/validation/short_operations.py --platform wsl --case interrupt` |
| Small experimental RSS guard, 1 MiB | `python3 -B protocol_rust/validation/short_operations.py --platform wsl --case rss` |
| Small experimental descriptor guard, 16 FDs | `python3 -B protocol_rust/validation/short_operations.py --platform wsl --case fds` |
| Small experimental thread guard, 2 threads | `python3 -B protocol_rust/validation/short_operations.py --platform wsl --case threads` |

The three limits apply to the measured probe process. They do not intentionally
exhaust the host's memory, file descriptors or threads. They are sampled collector
guards, not kernel RLIMIT enforcement. RSS uses the sampled high-water mark.

The interruption case is automated. Do not manually press Ctrl+C to cause that
case. Pressing Ctrl+C stops the operator batch itself, retains available evidence
and prevents later cases from starting. SIGTERM or SIGKILL against the collector
can bypass its evidence-writing cleanup and are not equivalent to this test.

## Expected outcomes

| Case | Collector result | Expected reason | Operator case result |
| --- | --- | --- | --- |
| `clock` | `passed`, exit 0 | Requested traffic completed | `passed` if evidence and cleanup checks pass |
| `interrupt` | `failed`, exit 1 | `KeyboardInterrupt` | `passed` if the intended failure, evidence and cleanup checks pass |
| `rss` | `failed`, exit 1 | `process RSS ceiling exceeded` | Same |
| `fds` | `failed`, exit 1 | `sampled descriptor ceiling exceeded` | Same |
| `threads` | `failed`, exit 1 | `sampled thread ceiling exceeded` | Same |

Expected failures are not counted as completed load campaigns. The operator
wrapper requires the exact expected reason, unchanged selected source/executable,
matching raw and archived evidence hashes, no surviving fixture-scoped probe,
and removal of each case's private temporary fixtures. Early guard failures can
occur before a start/PID event is logged; cleanup is checked using the exact
binary and unique private fixture-directory scope. No unrelated probes are
stopped. Private fixture directories are outside the published evidence tree.

Forced termination validates process cleanup and failure recording. It does not
prove authenticated protocol closure or memory zeroization before process exit.
Passing `clock` means collection and the normal campaign succeeded; it does not
automatically mean that the clocks agreed or that suspension was absent.

## Time sources

| Value | Source and scope |
| --- | --- |
| Event timestamps, console dates and filenames | Linux UTC (realtime). Useful for labeling and correlation. Do not subtract UTC labels to obtain elapsed time. |
| Windows UTC comparison | Windows PowerShell returns Unix milliseconds. WSL records Linux UTC, CLOCK_MONOTONIC and CLOCK_BOOTTIME immediately before and after the call. WSL monotonic measures the entire query, including process startup and scheduling. |
| Load collector watchdog and duration | Python `time.monotonic` on the collector host. `collector_monotonic_elapsed_seconds` describes the collector interval, including setup and probe shutdown. The legacy `wall_elapsed_seconds` field uses the same monotonic value. |
| TLS and Spiral handshake budgets | Rust `Instant` and Tokio timers on the endpoint. TLS has a 10-second timeout. The Spiral handshake uses an `Instant` deadline and a bounded server ClientKey stage. TLS certificate and Spiral pin validity use realtime UTC. A UTC error can affect authentication even when the timeout clock is stable. See [transport](src/transport.rs) and [handshake](src/handshake.rs). |
| Channel, admission and worker limits | Rust `Instant` and Tokio timers measure age, idle and closing deadlines (600, 60 and 2 seconds), operation budgets, admission refill and KEM job expiry. The Linux monotonic clock excludes Linux suspend time. WSL host sleep can also delay execution and event collection. See [channel](src/channel.rs), [admission](src/admission.rs) and [worker](src/worker.rs). |
| Load probe traffic duration | Rust `Instant` measures total process time, soak time and accumulated traffic epochs independently. A local test rate, when supported, uses the verified echo count or echoed bytes divided by `traffic_epoch_elapsed_seconds`. Setup, reconnect and close are different intervals. See [load probe](examples/load_probe.rs). |
| Isolation progress and expiry | A healthy-peer progress gap uses the WSL controller's monotonic journal and includes scheduling and pacing. The stall-to-expiry interval uses the OCI server's `Instant`. Neither uses subtraction between hosts. See [isolation](SESSION_ISOLATION.md). |
| Suspend-sensitive elapsed comparison | Linux CLOCK_BOOTTIME includes time accounted as suspend by the Linux kernel. Its relation to CLOCK_MONOTONIC is observable on one host. It does not directly establish Windows host sleep. |

## Quality of time measurements

`campaign/clocks.jsonl` contains run-source IDs, sequence numbers, start and end
markers, Linux readings and Linux monotonic read spans, and, on request,
a raw Linux clock pair for each Windows query. `clock_assessment` and
`timing_scope` in `campaign/result.json` and `operator-result.json` describe
measurement quality separately from functional results. Standalone load
captures put the same trace beside their `result.json`.

The assessment rejects mixed sources, missing records, missing start/end,
interruption, nonincreasing elapsed clocks, sampling gaps above 2.5 seconds
and Linux reads wider than 20 ms. A per-sample UTC/monotonic or
boottime/monotonic residual beyond 50 ms plus read spans flags divergence.
A run-wide excursion beyond 90 ms also flags divergence. The thresholds
screen for visible discrepancies. A clean sampled interval gives no absolute
clock calibration, and jumps within sample gaps can go unseen.

A Windows offset interval is reported only for a stable Linux query bracket.
A query longer than one second, a different source, a missing timestamp, or
a Linux UTC/boottime residual above 5 ms plus the read spans invalidates its
offset estimate. The report still carries the measured query time when the
Linux monotonic pair is valid. The conservative offset bounds include the
full query bracket, read spans, stability allowance and Windows millisecond
quantization. A bracket entirely outside ±100 ms records a disagreement.
A bracket overlapping the tolerance boundary is indeterminate. Observed
agreement requires at least two valid queries, gaps of at most 35 seconds,
and an interval wholly within ±100 ms for every query. These are Windows
versus WSL observations. OCI time is not aligned by this query.

| Metric | Report interpretation |
| --- | --- |
| Functional completion and timeout | Preserve verified echoes, resource cleanup and explicit server `Deadline` even if clock coverage is insufficient. Describe each recorded duration by its own clock. |
| Precise RTT | The load and isolation collectors do not time individual requests from send to verified response. An isolation progress gap is a controller observation, so use it only for the functional bound. |
| One-way delay | The runner has no independently bounded sender-to-receiver clock alignment. Query round-trip time is also distinct from protocol latency. |
| Throughput | Keep raw counts. A locally consistent trace supports a test rate per recorded monotonic traffic second. With incomplete or diverging observations, treat the rate as time-unverified. |
| Long duration | A locally consistent trace supports sampled local elapsed time for that specific run. Missing coverage or divergence limits the report to recorded monotonic durations and functional milestones. Separate short observations do not validate a longer run. |

### Existing measurements

The original WSL short-operations trace (314 samples) reached +24.670 seconds
of Linux UTC elapsed minus monotonic elapsed. Boottime minus monotonic stayed
within 2 microseconds. The 11 Windows query latencies were 0.657–0.886 seconds.
The OCI trace (313 samples) kept UTC minus monotonic within 8 microseconds.
The later WSL chrony-only capture stayed within 6 microseconds over 192.757
monotonic seconds. These are comparison intervals, and they leave the earlier
disagreement unresolved.

In the WSL 24-hour result, the collector recorded 86,664.568 monotonic seconds
(the legacy `wall_elapsed_seconds` field), while its UTC labels differed by
89,903.649 seconds. The probe recorded 86,400.002 monotonic traffic seconds.
The OCI 24-hour result recorded 86,474.194 collector monotonic seconds and
86,474.199 seconds between UTC labels. Both functionally passed. These
older runs lack the new continuous clock assessment.

The verified isolation timeout of about 59.79 seconds comes from the OCI
server stall-to-expiry observation. The WSL controller's observed healthy
echo gaps support the five-second functional progress bound. That existing run
does not provide calibrated latency or throughput.

## Collect and transfer a short clock receipt

Use the same updated revision on both hosts. Prepare the existing probe as
shown above. Choose a collection window spanning at least two Windows
queries. The following short examples use 90 traffic seconds.

**OCI SSH Ubuntu**

```bash
cd "$HOME/Spiral-clock" &&
python3 -B protocol_rust/validation/short_operations.py   --platform oci --case clock --clock-seconds 90
```

**WSL Ubuntu**

```bash
cd "$HOME/Spiral-clock" &&
python3 -B protocol_rust/validation/short_operations.py   --platform wsl --case clock --clock-seconds 90 --windows-clock
```

The final archive includes each case result and a SHA-256 inventory. Keep archives with an insufficient
clock verdict or a failed functional verdict too. Copy the OCI receipt to WSL
using the existing SSH alias and the exact remote archive path.

```bash
read -r -p 'OCI SSH alias: ' spiral_oci
read -r -p 'OCI archive absolute path: ' spiral_oci_archive
scp "${spiral_oci}:${spiral_oci_archive}" "$HOME/"
```

**Windows PowerShell**

Repeat for the two archive paths now in WSL. Copy the output into Windows
Downloads and record its SHA-256.

```powershell
$archive = Read-Host 'Full archive path in WSL'
$src = (wsl.exe -d Ubuntu-24.04 -- wslpath -w "$archive").Trim()
$dest = Join-Path "$env:USERPROFILE\Downloads" (Split-Path -Leaf $src)
Copy-Item -LiteralPath $src -Destination $dest -ErrorAction Stop
Get-FileHash -Algorithm SHA256 -LiteralPath $dest
```
