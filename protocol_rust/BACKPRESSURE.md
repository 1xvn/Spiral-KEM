# Cross-host slow-consumer and buffer-pressure checks

This operator-run companion uses the existing OCI server / WSL client SSH setup
to observe the real receive-queue and buffer-pool bounds, then exercise release,
producer cancellation and idle expiry. The `flow-diagnostics` Cargo feature is
off by default. It adds observations and opt-in CLI scenarios; the production
queue capacity, pool size, 60-second idle limit and 600-second session-age limit
remain unchanged.

## OCI: update, rebuild and prepare fresh test state

Use the normal OCI Ubuntu SSH terminal:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab &&
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

Both the feature-enabled rebuild and fresh preparation are required. Preparation
records the selected source, runner and executable hashes and creates a new
24-hour test identity. `--rotate-test-state` retains the old private test state
in a `Spiral-cross-host-server-previous-...` directory before creating the new
state. Those backups still contain private keys; rotation does not erase them.
The previous directory remains available if fresh preparation fails. Only the
public CA, pin and provenance are exported to WSL.

## WSL: update and rebuild

Use the usual WSL Ubuntu terminal, not PowerShell or the WSL debug shell:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab
```

Use the existing SSH access from the earlier cross-host checks. The runner
prompts for the OCI SSH target and the existing WSL private-key path; it does not
copy that private key. See [CROSS_HOST.md](CROSS_HOST.md) for that setup.

## WSL: run the checks

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/slow_consumer.py run
```

The default runs `release`, `cancel` and `timeout`, then a fresh ordinary-session
recovery. Allow approximately one minute plus SSH authentication and setup time.
The timeout case waits for the unchanged production idle deadline. The runner
starts each remote server and SSH forwarder automatically; no manual server
command or public application port is needed.

To run one pressure case followed by its fresh-session recovery:

```bash
python3 -B protocol_rust/validation/slow_consumer.py run --case release
python3 -B protocol_rust/validation/slow_consumer.py run --case cancel
python3 -B protocol_rust/validation/slow_consumer.py run --case timeout
```

The release and cancellation cases should take seconds after SSH setup. Each
pressure session uses one connection, one KEM worker per endpoint, eighteen
1,024-byte server seed messages and ten 1,024-byte client requests. It is a
bounded functional exercise, not a long-duration load test.

## What must be observed

Each case establishes TLS and the authenticated Spiral session before applying
the same pressure sequence:

1. The server pushes eighteen tagged seed messages while the client application
   initially receives none. A snapshot must show eight actual messages in the
   receive queue and one blocked delivery operation, continuously for at least
   200 milliseconds.
2. The client receives and verifies all eighteen seeds and retains their
   `Plaintext` owners. A snapshot must show eighteen allocated buffers, eighteen
   in use and zero free. Each pool buffer has a capacity of 16,440 bytes.
3. Ten concurrent client send tasks start. Eight reserve the send channel's
   eight slots and wait for a pool buffer; two wait for a send slot. The observed
   state must persist for at least 200 milliseconds, with ten active sends and
   zero completed sends.

The eight send slots are **reserved permits**. Plaintext is copied only after a
buffer becomes available, so this observation does not mean eight DATA payloads
are queued behind a blocked network writer. Fixed sleeps without the required
snapshots cannot produce a passing saturation verdict.

The cases then take different paths:

- **Release:** the client drops exactly one retained seed, keeping seventeen.
  It concurrently drains and drops echoes while joining the producers. All ten
  sends and all ten verified echoes must complete using the available buffer.
  It then drops the remaining seeds and completes authenticated closure.
- **Cancel:** the client cancels and joins all ten blocked producers while
  retaining all eighteen seeds. All producer counters and reserved slots must
  return to zero without a successful send. It releases the seeds, starts ten
  ordinary sends, verifies ten echoes and completes authenticated closure.
- **Timeout:** the client retains all eighteen seeds and waits. All ten blocked
  sends must finish with `Deadline` or `Closed`, with no successful send. Either
  peer may expire first: a sender deadline or a peer's recorded timeout close
  reason must demonstrate production deadline expiry. The elapsed observation
  and a terminal client error alone are insufficient. Authenticated successful
  closure is not claimed for this failed session.

After each pressure session, both endpoints must demonstrate that their reader
and writer tasks finished, no producers or delivery waiters remain, and every
allocated pool buffer is free. The client must return all eighteen seed buffers.
Final native KEM metrics must show zero live keys and zero rejected jobs, with
the completed handshake accounted for. The server must release admission and
close its authentication identity, including on timeout.

After all selected pressure cases pass, a fresh ordinary session must verify
ten echoes and authenticated closure. Its session, TLS binding and transcript
identifiers must differ from every selected pressure session.

## Bounds and collected evidence

The diagnostic setup phases have short observation bounds. Collection is bounded
to 25 seconds for release/cancellation and 100 seconds for timeout after client
launch. The opt-in remote server has a 90-second emergency watchdog plus a
five-second termination allowance. A watchdog, SSH failure, controller kill,
missing checkpoint or incomplete cleanup cannot count as a pass. Cancellation
retains available evidence and stops owned local processes; the remote watchdog
bounds an abandoned listener.

The last line prints one combined WSL archive named
`$HOME/Spiral-backpressure-....tar.gz`. Retain the complete archive, including
failed results. It contains the public credential bundle, selected-source and
executable provenance, raw endpoint JSONL and error logs, controller observations,
pressure snapshots, cleanup and KEM accounting, fresh recovery results and a
SHA-256 file inventory. Server TLS and authentication private keys remain on OCI.
SSH diagnostics may contain host names, user names or local key paths; review
them before public redistribution.

WSL timing discrepancies remain unresolved. These results demonstrate the
observed functional behavior under the recorded workload, not trustworthy WSL
timing, throughput or capacity. They do not establish actual TCP/TLS/network-write
saturation, application-level client authentication or cryptographic security.
