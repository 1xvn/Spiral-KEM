# Cross-host server crash and fresh-session recovery

This operator-run companion checks an abrupt test-server process death while an
authenticated request is awaiting its reply. It then starts another server with
the same prepared identity and requires a fresh successful session. It follows
the completed backpressure exercise and uses the existing OCI server / WSL
client SSH access.

The probe uses the existing `--fault-checkpoint 3` CLI instrumentation. It does
not change the Rust protocol, resource limits or timeouts. The build commands
below retain the optional `flow-diagnostics` feature used by the previous
exercise; this crash scenario does not require that feature.

## OCI: update and prepare fresh test state

Run in the normal OCI Ubuntu SSH terminal:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab &&
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

Fresh preparation is required because the selected collector source hashes have
changed. It generates a new 24-hour test identity and records the selected source,
runner and executable hashes. The crashed server and its recovery server use
this same prepared identity.

`--rotate-test-state` retains any previous private test-state directory as a
`Spiral-cross-host-server-previous-...` backup. These backups still contain
private keys; rotation does not erase them. Follow your test-key retention
policy. Only the public CA, pin and provenance are exported to the client.

## WSL: update and build

Run in the usual WSL Ubuntu terminal, not PowerShell or the WSL debug shell:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab
```

Use the existing SSH connection from the earlier cross-host checks. See
[CROSS_HOST.md](CROSS_HOST.md) if that connection needs preparation.

## WSL: execute

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/server_crash.py run
```

The runner prompts for the OCI SSH target and the existing WSL SSH private-key
path. It does not copy that private key. It starts the remote supervisor, test
server and SSH forwarder automatically. No manual server, public application
port, SSH-service change or clock-service change is needed.

The exercise uses one connection, one KEM worker per endpoint and 1,024-byte
messages. Healthy execution should take seconds after SSH authentication and
setup. This is a bounded crash/restart check, not another long-duration soak.

## Injection point and passing evidence

1. The peers complete TLS and the authenticated Spiral handshake, then exchange
   and verify three full echoes.
2. The client sends a fourth request. The server authenticates it, retains its
   plaintext and deliberately withholds the reply.
3. Both peers emit flushed pending-request checkpoints with matching session,
   binding and transcript identifiers. The client must report sent=4/verified=3;
   the server must report received=4/echoed=3 and a 1,024-byte pending payload.
4. Only after both checkpoints match does the controller authorize the remote
   supervisor to send `SIGKILL` to its own direct Rust child. The probe accepts
   no operator-supplied process identifier or signal.
5. The supervisor must observe the child exit from `SIGKILL`, reap it and
   demonstrate that the remote test listener disappeared. The SSH forwarder
   must remain alive with its local listener present, distinguishing server
   death from the earlier forwarding-process interruption test.
6. The client must fail with `Closed` or `Transport`, account for the completed
   KEM handshake, and report zero live native keys and zero rejected jobs.
   A timeout or unrelated authentication failure cannot pass.
7. A newly started ordinary server uses the same prepared identity. A fresh
   session must verify ten echoes, finish authenticated closure, release server
   admission and close that recovery server's identity. Its session, binding and
   transcript identifiers must differ from the interrupted session.

The remote supervisor's successful control result is distinct from a successful
Rust server result. The killed Rust server is not expected to produce a final
application report or run its normal cleanup hooks.

## Supervision and scope

The local controller bounds pending-checkpoint collection to 35 seconds after
client launch and post-injection collection to 15 seconds. The remote supervisor
has an outer 60-second watchdog with a five-second forced-termination allowance.
It also applies a Linux parent-death guard to its owned Rust child, covering
supervisor death before an outer watchdog would otherwise reach its deadline.
Normal cancellation and control-channel EOF terminate and reap the owned child.
Watchdog expiry, early child exit, a missing checkpoint, an invalid control
command or incomplete termination evidence produces a failed test verdict.

Only the disposable server child created by this run is an injection target.
The probe does not terminate SSH services, other servers or arbitrary processes.
The parent-death guard and watchdog are containment mechanisms, not evidence
that the intended checkpoint-triggered injection occurred.

`SIGKILL` bypasses userspace cleanup. The interrupted server therefore makes no
claim about explicit secret zeroization, executed admission cleanup hooks or
authenticated protocol closure. Process reaping and listener release are the
observed crash-side properties. A clean recovery server does not prove that the
crashed server's cleanup hooks ran.

The pending request has already been authenticated when the crash occurs. This
does not establish rollback of side effects, persistent-state recovery,
exactly-once delivery or a partial-frame crash. Recovery starts a new session
and does not replay the interrupted request. SSH controls access; this test does
not add application-level client authorization or establish cryptographic
security. WSL clock accuracy remains unresolved, so recorded elapsed values
are observations rather than timing certification.

## Collected evidence

The last line prints one combined WSL archive named
`$HOME/Spiral-server-crash-....tar.gz`. Retain and send the complete archive,
including failed verdicts. It includes the public credential bundle, selected
source and executable provenance, raw endpoint and supervisor logs, checkpoint
and injection observations, child termination and listener evidence, client
cleanup metrics, fresh recovery results and a SHA-256 file inventory.

Server TLS and authentication private keys remain on OCI. SSH diagnostics may
contain host names, account names or local key paths; review those diagnostics
before public redistribution.

## Recorded preparation checks

The [preparation evidence](evidence/server_crash_runner_20261117/README.md)
records 159 passing collector tests and short real-process/TCP control-path
checks, including direct-child termination and rejection of an unhealthy
forwarder. Those checks use synthetic endpoints and metrics, not Rust/TLS/KEM.
The actual OCI/WSL authenticated crash/recovery campaign has not been run during
preparation; use the operator commands above to collect it.
