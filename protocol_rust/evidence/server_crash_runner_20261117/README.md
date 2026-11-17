# Server-crash runner preparation checks

Preparation date: 2026-11-17. The new runner uses existing Rust checkpoint
instrumentation; no Rust source was changed for this stage.

The collector suite completed **159 tests successfully in 1.548 seconds**. New
coverage includes nineteen crash-verdict contracts, eleven supervisor command
and ownership tests, and two coordinator integration tests. The supervision
tests include actual disposable-child reaping on input failure and a Linux
parent-death test where killing the supervisor also terminates its direct child.

A separately recorded control-path check completed in approximately 0.638
seconds. It used synthetic Python server/client endpoints over a real local TCP
relay. The supervisor killed its own direct child and observed exit code -9,
reaping, stdout EOF and listener disappearance. The relay process and its owned
listener remained alive before the request, after the kill acknowledgment and
after client exit. A second case supplied an unhealthy-forwarder observation
and verified that the coordinator refused crash authorization.

**The endpoint checkpoint assertions and KEM metrics in this fixture are
synthetic. This is not a Rust, TLS, KEM, SSH or OCI/WSL execution.** No private
credentials were used. The restored cloud workspace did not have the pinned
Rust 1.99.1 toolchain, so neither full functional CI nor another Rust/TLS campaign
was run during this preparation. The actual cross-host experiment is left for
the operator commands in [SERVER_CRASH.md](../../SERVER_CRASH.md).

The recorded process checks used clean source revision
`57afafb4cb0e641ae9d1dc251167aa2060383558`. All 171 selected runtime source-file
hashes remained unchanged. The fixture's separate source hash is also recorded.
`local-validation.tar.gz` contains the original logs, structured results, test
log and fixture source. `SHA256.json` inventories this evidence directory.

To repeat the bounded collector checks from the repository with its Python
dependencies installed:

```bash
python3 -B -m unittest discover -s protocol_rust/validation -p 'test_*.py' -v
```

Linux loopback socket access is required for the coordinator integration tests.
These results verify controller behavior and containment; the real operator
campaign must still verify authenticated checkpoints and recovery with Rust.
