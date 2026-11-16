# Cross-host interruption with an authenticated request pending

This operator-run companion extends the SSH-tunneled OCI server / WSL client
exercise. It verifies DATA progress before injecting a transport failure and
then requires a fresh successful session. It does not change library protocol,
admission, key-usage or session-time limits. Optional CLI instrumentation is
enabled only by `--fault-checkpoint` and is not a service mode.

## OCI: update, rebuild and prepare fresh test state

Use the normal OCI Ubuntu SSH terminal:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --bin spiral-lab &&
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

Rebuilding is required: the opt-in checkpoint events are new CLI behavior.
Fresh preparation is required because selected source and runner hashes changed.
`--rotate-test-state` renames an existing private test-state directory to a
`Spiral-cross-host-server-previous-...` backup, then generates a new 24-hour test
identity. It retains the old private keys; it does not erase them. Follow your
test-key retention policy for those backups. No private key enters the public
bundle. If preparation fails after rotation, the previous state remains intact.

## WSL: update and rebuild

Use the usual WSL Ubuntu terminal, not PowerShell or the WSL debug shell:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --bin spiral-lab
```

Use the existing SSH access that passed the previous cross-host smoke. The
runner prompts for the same OCI SSH target and WSL private-key path. See
[`CROSS_HOST.md`](CROSS_HOST.md) if that connection needs preparation.

## WSL: execute

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/inflight_disconnect.py run
```

The controller prepares the SSH tunnel and remote server automatically. No
manual server command, public application port, or clock-service change is
needed. The workload is one session, ten requested 1,024-byte messages and one
KEM worker per endpoint. A healthy execution should take seconds after SSH
authentication; it is not a long-duration soak.

## Exact injection point

1. Both endpoints complete TLS and the authenticated Spiral handshake.
2. The client sends and verifies three full echoes sequentially.
3. The client sends a fourth DATA request. The server receives and authenticates
   it, keeps its plaintext buffer alive, and intentionally withholds the reply.
4. Both emit flushed `request_pending` events with matching session, binding and
   transcript identifiers. The client reports sent=4/verified=3; the server
   reports received=4/echoed=3 and the expected payload length.
5. Only after observing both events while both peers and the tunnel remain
   alive, the controller terminates its own SSH forwarding process. The separate
   server-control SSH connection stays open to collect the server's result.
6. The endpoints must fail with Closed or Transport, release native keys, and
   the server must report drained admission counts and a closed identity.
7. A new tunnel and ordinary server/client pair must complete ten echoes and
   authenticated closure with identifiers different from the interrupted session.

This is a pending-response interruption after an authenticated DATA request
arrived at the server. It is not a partial TLS/AEAD frame cut, an application
exactly-once guarantee, or proof that the interrupted request had no side effect.
Recovery starts a fresh session; it does not replay the interrupted request.

## Passing requires positive evidence

- Both pending checkpoints must exist and match before the cut. Early network,
  authentication or process failure cannot count as a successful injection.
- The owned forwarding process must exit and its local listener must disappear.
- Both Rust endpoints must exit 1 and report failed with exactly the expected
  Closed/Transport terminal error, rather than a timeout, authentication error,
  SSH exit or controller kill.
- The complete KEM handshake is accounted for (two server jobs, one client job),
  with zero live keys and zero rejected jobs.
- The fault-only server `failure_cleanup` event must report active=0, pending=0,
  drained=true and auth_key_closed=true. Closure of the transport is a failure;
  authenticated protocol CLOSE is not claimed for that interrupted session.
- The recovery case must independently satisfy the original normal-case checks.

The controller bounds pending readiness to 30 seconds after client launch and
post-cut result collection to 15 seconds. The remote server retains the existing
60-second watchdog with five seconds of forced-termination allowance. A watchdog
exit does not pass this test. Cancellation retains available evidence and stops
owned local processes; a remote orphan is still bounded by the server watchdog.
SIGKILL and host shutdown cannot be handled by a Python cleanup block.

## Evidence

The last line prints `$HOME/Spiral-inflight-....tar.gz` on WSL. Send that complete
archive, including failed verdicts. It includes:

- Public CA/pin/provenance only; server TLS/authentication private keys stay on OCI.
- Raw server/client JSONL and error logs, plus `controller.jsonl` with checkpoint
  observations, cut intent and cut completion.
- Server cleanup counts, native KEM metrics, fresh-session recovery verdict and
  local before/after selected-source and executable hashes.
- A complete SHA-256 file inventory.

The two controller scripts are now included in the selected source map, while
the cross-host runner also records its own hash. Existing evidence from earlier
source revisions remains unchanged. Review SSH logs before public redistribution
because connection/key-path diagnostics may contain personal details.

WSL clock discrepancies remain unresolved. The test demonstrates functional
fault handling under the recorded workload, not trustworthy real-time deadlines,
capacity, application-level client authentication or cryptographic security.
Slow readers and server crashes remain separate next cases.

## Recorded preparation checks

The [local preparation evidence](evidence/inflight_runner_20261117/README.md)
records a release build, 103 collector contract tests, four invalid-checkpoint
CLI rejections, and one short real-loopback TLS pending-request cut followed by
normal recovery. The relay in that check is local TCP, not SSH or OCI/WSL.
Cross-host operator results remain to be collected.
