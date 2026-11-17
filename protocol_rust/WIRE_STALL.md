# Cross-host socket-write stall and recovery

This operator-run companion pauses an owned TCP gate after authenticated traffic
has succeeded, then requires positive evidence that the server's underlying TCP
write is pending. It exercises read resumption and the existing server deadline,
followed by a fresh ordinary session. It extends the earlier retained-buffer
pressure and server-crash checks.

The `flow-diagnostics` Cargo feature is required on both hosts. It is off by
default. The probe keeps the normal eight-slot queues, eighteen-buffer pool,
60-second idle limit and 600-second session-age limit.

## OCI: update, rebuild and prepare

Run in the normal OCI Ubuntu SSH terminal:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab &&
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

The feature implementation and selected source hashes have changed, so rebuilding
and fresh preparation are required. Preparation generates a new 24-hour test
identity and records the source, collector and executable hashes.

`--rotate-test-state` retains an existing private test-state directory in a
`Spiral-cross-host-server-previous-...` backup. These backups still contain
private keys; rotation does not erase them. Only the public CA, pin and provenance
are exported to WSL. Apply your test-key retention policy to previous backups.

## WSL: update and rebuild

Run in the usual WSL Ubuntu terminal, not PowerShell or the WSL debug shell:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab
```

Use the existing OCI SSH target and WSL private-key path from the preceding
cross-host checks. See [CROSS_HOST.md](CROSS_HOST.md) for that setup.

## WSL: execute

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/wire_stall.py run
```

The default runs `release` and `timeout`, then a fresh ordinary ten-echo recovery.
The runner prompts for the existing OCI SSH target and WSL SSH private-key path.
It starts the remote test server, TCP gate and SSH forwarder automatically.

To run one stall case followed by ordinary recovery:

```bash
python3 -B protocol_rust/validation/wire_stall.py run --case release
python3 -B protocol_rust/validation/wire_stall.py run --case timeout
```

The timeout case deliberately waits for the existing 60-second server deadline.
Allow approximately one minute plus SSH authentication, preparation and bulk
transfer time; allow several minutes overall on a slower connection. This is a
bounded functional experiment, not a long-duration load campaign.

## Injection and positive stall evidence

The remote gate listens only on OCI loopback port 39402 and connects to the owned
Rust test server on loopback port 39401. The SSH forwarder carries the client
connection to the gate. No public application port or host-wide network setting
needs changing.

1. TLS and the authenticated Spiral handshake complete. The client verifies
   three full 16,384-byte echoes. Both peers report matching session, binding
   and transcript identifiers at the ready checkpoint.
2. The controller asks the gate to pause reads from its backend server socket.
   The acknowledgment records that backend reading is disabled, no downstream
   userspace buffer is pending, and the ciphertext read-byte count is frozen.
3. Only after that acknowledgment does the controller allow the client to send
   the authenticated GO message. The server validates GO and starts a bounded
   bulk transfer of 1,021 tagged messages, each 16,384 bytes. Including the three
   baseline echoes, the server sends at most 16 MiB of DATA payload.
4. The gate holds reverse reads after GO is received. In the timeout case this
   prevents the client's earlier idle CLOSE or socket EOF from reaching the
   server before its own write deadline can be observed.
5. A diagnostic wrapper beneath TLS must observe a new underlying TCP
   `poll_write` or vectored-write `Pending`. The pending flag must remain set
   with no written-byte progress for at least 200 milliseconds while the Spiral
   session remains open and bulk transfer is incomplete. The gate must confirm
   that its backend read counter stayed frozen and both read directions remain
   held.

Reserved send permits, a sleeping application or a pending TLS-level operation
alone cannot satisfy this test. If the entire bounded transfer completes without
the required socket-write observation, the test fails to establish a stall.
The gate does not keep increasing the workload until a failure appears.

The gate requests `SO_RCVBUF=4096` on its own backend socket before connecting;
the actual value returned by the kernel is recorded. This changes only that
owned socket, not a host sysctl. The release path increases that socket's receive
buffer again so the remaining bounded transfer can drain promptly.

## Release and timeout outcomes

- **Release:** after the socket-write witness and frozen-read confirmation, the
  gate resumes both read directions. The server completes all 1,021 bulk sends,
  the client verifies every tagged payload and sends the completion acknowledgment,
  and both peers finish authenticated closure.
- **Timeout:** the gate keeps both read directions held until the server exits.
  The server must report its own blocked-send `Deadline`, or a blocked-send
  `Closed` error accompanied by its local timeout close reason. The client's
  independent idle expiry is insufficient proof of a server deadline. Both
  peers follow their expected failure paths; endpoint exit code 1 is expected
  for this case and does not itself mean the experiment failed.

Both paths require reader and writer tasks to finish, all allocated pool buffers
to be returned, all producer and delivery waiters to clear, and the actual TCP
transport to be dropped with no pending write. Native KEM metrics must show zero
live keys and zero rejected jobs, with the handshake jobs accounted for. The
server must release admission and close its authentication identity, including
on the timeout path.

After the selected cases pass, an ordinary server and client must verify ten
echoes and authenticated closure using fresh session, binding and transcript
identifiers. Recovery uses the prepared public identity; it does not replay the
interrupted bulk stream.

## Containment and evidence

The remote supervisor owns only its directly spawned test server and its gate
sockets. Linux parent-death protection terminates that child if the supervisor
dies. Normal cancellation, control-input EOF and failures kill and reap the
owned child and close the owned sockets. Internal collection bounds and an outer
110-second watchdog with a five-second termination allowance bound abandoned
operation. A watchdog or controller termination cannot produce a passing verdict.

The SSH forwarder and its owned local listener are observed before the pause,
after the stall witness and after the endpoints finish. The remote controller
also reports the server child's reaping and gate-listener removal.

The last line prints one combined WSL archive named
`$HOME/Spiral-wire-stall-....tar.gz`. Send the complete archive, including failed
verdicts. It contains the public credential bundle, selected-source and executable
provenance, endpoint and gate JSONL/error logs, pause/resume and byte-counter
observations, underlying TCP write diagnostics, cleanup, fresh recovery and a
SHA-256 file inventory. Server TLS and authentication private keys stay on OCI.
SSH diagnostics may contain host names, account names or local key paths; review
them before public redistribution.

The injected read stall is at the gate's loopback socket adjacent to the Rust
server. It demonstrates the recorded socket-write and session behavior under
this controlled condition. One connection and the bounded payload do not certify
service capacity, resistance to general denial of service, persistent-state
recovery, application-level client authorization or cryptographic security.
WSL clock accuracy remains unresolved, so recorded elapsed values are observations
rather than latency, throughput or real-time deadline certification.
