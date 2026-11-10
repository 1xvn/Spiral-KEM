# Bounded long-duration load and resource validation

This campaign exercises the existing Spiral channel through public Rust APIs,
using real loopback TCP, TLS 1.3, exporter-bound Spiral handshakes, directional
AEAD records, verified echoes and authenticated closure. It keeps one process,
listener, admission gate and KEM worker pool alive across session rotations.

The server and clients share **one process**. RSS, descriptor, thread and CPU
measurements therefore include both endpoints and the harness. They are finite
laboratory observations, not independent server capacity or production approval.

## Scenarios

| Scenario | Required observation |
| --- | --- |
| Per-IP admission | Four authenticated sessions from one actual source IP are held; a fifth socket is rejected; a later session works after release/refill |
| Pending admission | 32 raw TCP peers occupy pending slots; peer 33 is rejected; the original 10-second TLS accept deadline releases idle peers; a new authenticated exchange works |
| Global admission | 64 authenticated sessions from distinct actual `127/8` source addresses are held; connection 65 is rejected without disturbing them |
| Sustained traffic | 64 simultaneous sessions exchange and verify payloads for the requested traffic-epoch duration |
| Session rotation | New sessions replace completed groups within the existing age, record and byte limits; the runtime limits are not increased |
| Shutdown | Every authenticated pair closes, sends fail after closure, admission counts and native live-key count return to zero, the identity closes and worker threads join |

The production gate remains 64 active / 32 pending / 4 per IP, with a four-token
burst and one token per second refill. Actual sockets use source addresses in
`127/8`; the test does not pass invented peer labels to the admission gate.
Handshakes are sequential during group setup, so this is not a handshake-flood
capacity measurement.

Each client reuses a bounded payload buffer and checks the received echo before
incrementing the completed-message counter. Payloads of at least 16 bytes include
the full sequence and lane identifiers. Smaller payloads do not carry the full
identity. The default collector profile uses 16 KiB for the recorded full-size
campaign; specify it explicitly as below.

Groups rotate after at most 240 seconds or 32,768 messages per connection, below
the unchanged 600-second session age and per-key usage limits. Traffic-epoch time
excludes rotation setup but includes bounded authenticated closure. The report
also records rotation time and total wall time separately. Individual sockets are
not claimed to remain open for 30 minutes.

## Build

Use a Linux source checkout, Rust/Cargo 1.99.1, a C11 toolchain, OpenSSL development
headers and the pinned Python protocol dependencies. Windows users should run the
commands inside WSL Ubuntu, not PowerShell. Native Windows execution is outside
this collector's scope.

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev python3-venv
python3 -m venv .venv-load
.venv-load/bin/python -m pip install -r protocol_v01/requirements.txt
cargo build --release --locked --manifest-path protocol_rust/Cargo.toml \
  --example load_probe
```

The collector reads source provenance from Git, so run it in the checkout. It
records the Git HEAD, the dirty-worktree flag, exact runtime/probe/collector/C/Cargo/
local-dependency file hashes and pre/post binary hashes. A dirty development run
is identified as such; a base commit is not presented as the exact tested source.

## Execute a smoke test, then a 30-minute campaign

Always use a new output directory. Test credentials are freshly generated in a
separate private temporary directory and removed on completion; they are not
included in evidence.

```bash
.venv-load/bin/python -B protocol_rust/validation/load_campaign.py \
  --binary protocol_rust/target/release/examples/load_probe \
  --output "$HOME/Spiral-load-smoke-new" \
  --duration-seconds 10 --connections 64 --payload 16384 --interval-ms 50

.venv-load/bin/python -B protocol_rust/validation/load_campaign.py \
  --binary protocol_rust/target/release/examples/load_probe \
  --output "$HOME/Spiral-load-30m-new" \
  --duration-seconds 1800 --connections 64 --payload 16384 --interval-ms 50
```

The collector supports 10..1800 seconds and 4..64 connections. All three admission
checks are mandatory for the 64-connection profile. Runs below 64 do not claim to
exercise the global admission boundary. Fresh helper credentials are valid for
one hour; the collector does not advertise an unattended 24-hour test profile.

For an OCI host, add `--platform oci`; this is an environment label, not independent
cloud-provider attestation. For WSL, add `--platform wsl`, which also checks for a
Microsoft kernel. `--platform local` is the default. OCI and WSL need their own
executions; a local cloud run does not substitute for either platform.

The pacing interval is a target, with missed timer ticks skipped under load. The
workload is closed-loop and verifies actual completions. Do not interpret the
configured pacing as a guaranteed arrival rate or the measured rate as maximum
service capacity.

## Resource guards and outputs

Default process guards are 512 MiB peak RSS, 256 sampled descriptors and 64 sampled
threads. These are declared experimental stop thresholds, not kernel RLIMITs or
claims that the channel enforces those process-wide limits. Linux `/proc` is
sampled approximately once per second; subsecond descriptor/thread peaks can be
missed. `VmHWM` records the process high-water RSS when sampled.

The collector stops on an exceeded guard, a 30-second probe heartbeat stall,
15 seconds without verified echo progress during traffic, or a bounded overall
watchdog. A successful exit code alone is insufficient: it rejects missing/short
final reports, incomplete limit checks, mismatched handshake/key/closure counts,
live keys, unreleased admission slots and descriptor counts above the initialized
baseline. The baseline includes the listening socket; inspect the final count
against baseline minus that closed listener for a stronger exact recovery check.

| File | Contents |
| --- | --- |
| `result.json` | Verdict, requested/actual duration, final probe report, source/binary checks and resource summary |
| `probe.stdout.jsonl` | Full phase, limit-case, progress, rotation and final JSON events |
| `probe.stderr.log` | Original probe errors, including failures |
| `resources.jsonl` | Monotonic elapsed time, RSS/high-water RSS, FD/thread counts, CPU and page faults |
| `source-before.json`, `source-after.json` | Exact source hashes and Git/worktree metadata |
| `SHA256.json` | File-integrity inventory of the collected evidence |

Failures retain available evidence and clean up the child process and temporary
credentials. RSS warm/tail medians are observational: allocator retention and
host effects can change RSS, and a stable finite trace does not prove the absence
of small or rarely triggered leaks. No key material or plaintext contents are
logged.

## Focused resource regressions

The new unit tests supplement existing exact buffer-cap and full-capacity wipe
coverage. They check 64 established leases independent of the pending limit,
pending rejection without token/counter mutation, repeated mixed lease release,
registered buffer-waiter cancellation/wakeup, the shared 32-job request bound,
32 live native keys, cancellation drain and subsequent reuse.

```bash
cargo test --locked --lib --manifest-path protocol_rust/Cargo.toml
.venv-load/bin/python -B -m unittest discover \
  -s protocol_rust/validation -p test_load_campaign.py -v
```

Private-file regressions require the real Linux UID and supported file ownership.
A UID-mapping sandbox must not be made to pass by weakening key-file policies.

## Interpretation limits

This phase does not test separate hosts or networks, a sustained hostile handshake
flood, maximum throughput, authenticated 60-second idle expiry, 600-second age
expiry, or a genuine slow reader. Session rotation deliberately respects those
limits. Existing lifecycle/backpressure tests are separate evidence. A 30-minute
run is not a day-long soak, memory-erasure proof, cryptographic security assessment
or approval to deploy Spiral KEM as a service.

## Recorded runs

- [Local x86-64, 30 minutes, 64 authenticated connections](evidence/load_20261111/README.md): finite combined-endpoint results and raw provenance.
