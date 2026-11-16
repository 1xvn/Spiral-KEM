# Short clock observations and expected-failure checks

Use this operator-run companion after preparing the existing load runner. It
records Linux UTC, CLOCK_MONOTONIC and CLOCK_BOOTTIME together and checks short
interruption and experimental resource-ceiling cases. The protocol runtime and
its production limits are unchanged. Running help, setup or CI does not start
these workloads. The operator chooses when to run them.

## Update the existing checkout

On both OCI Ubuntu and WSL Ubuntu:

```bash
cd "$HOME/Spiral-load-hours" &&
git pull --ff-only &&
bash protocol_rust/run_load_test.sh --prepare
```

The checkout should be on `spiral-load-validation-20261111`. If it is elsewhere,
substitute its actual directory. The preparation command builds and checks
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
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/short_operations.py --platform wsl --case all --windows-clock
```

OCI Ubuntu:

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/short_operations.py --platform oci --case all
```

Run one batch at a time on each host. Keep the machine awake. During the clock
case, `--windows-clock` asks the existing WSL `powershell.exe` integration for
Windows UTC about every 30 seconds. It records only timestamps, timing bounds
and availability/error types, without collecting account names, hostnames or
event messages. If Windows interop is unavailable, the Linux clock observations
continue and Windows availability is explicitly recorded. No Windows programs
are installed by the runner.

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

## Interpret the clocks

`clocks.jsonl` records the absolute clock readings, elapsed deltas and Linux
clock-read span. Windows UTC queries include a round-trip duration and a bounded
Windows-minus-Linux UTC interval, allowing for millisecond precision and query
latency. Interpret that interval only when Linux UTC was stable during the query.

| Observation | Interpretation |
| --- | --- |
| UTC minus monotonic changes; boottime minus monotonic stays near zero | UTC adjustment or clock-rate disagreement is possible |
| Boottime minus monotonic increases | Linux suspend-time accounting differs; correlate with host observations |
| Windows UTC and Linux UTC diverge | WSL/host clock disagreement is a candidate; inspect time-service history |
| No difference during this short check | No discrepancy was observed in this interval; the previous long-run difference remains unexplained |

CLOCK_BOOTTIME includes Linux suspend time, but WSL virtualization may affect
how host suspension appears. These measurements do not establish the cause by
themselves. Avoid changing system time or disabling time synchronization as a
test. The runner neither forces host sleep nor changes clock configuration.

If needed, inspect Windows Event Viewer locally: **Windows Logs > System**,
around the affected run, for Kernel-Power, Power-Troubleshooter, Kernel-General
and Time-Service events. Share timestamps/provider/event IDs if relevant;
complete event messages can contain personal machine/account details.

## Collect the evidence

The final line prints a new archive under your Ubuntu home directory, such as
`Spiral-short-ops-wsl-YYYYMMDDTHHMMSSZ-PID.tar.gz`. Use the actual printed path.
Send one WSL archive and one OCI archive, including batches that report failure.

The outer `summary.json` reports the expected-failure verdicts; each case has
`operator-result.json`, `clocks.jsonl`, a console log and the original collector
evidence/archive. The outer SHA-256 inventory covers all included files, and the
wrapper records its own hash separately from the existing collector source
snapshot. Existing long-duration archives remain unchanged.

No new real workload was executed while preparing this companion. Validation
consists of 11 bounded contract tests plus syntax/help checks; clock and
failure-path outcomes on OCI and WSL remain for operator execution.
