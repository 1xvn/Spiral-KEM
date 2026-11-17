# Backpressure runner preparation checks

Preparation on 2026-11-17 recorded:

- A successful release build with `flow-diagnostics`, plus a successful
  default-feature CLI compile check.
- 127 Python collector/operator/verdict contract tests passing.
- 100 default-feature Rust library tests passing, with five intentionally
  ignored diagnostic tests; three additional focused flow-diagnostic tests pass.
- Five invalid diagnostic CLI configurations rejected with `Input` before
  worker or network initialization.
- One real loopback TLS release case, one cancellation case and one fresh
  ordinary-session recovery, in approximately 1.312 seconds combined.

Both pressure cases recorded an actual receive queue of eight messages with one
blocked delivery, then eighteen retained pool buffers and zero free buffers.
Ten producers held eight reserved send slots with eight buffer waiters and two
slot waiters, with no completed sends. Release of one buffer restored ten sends
and ten verified echoes. Cancellation joined all ten blocked tasks and returned
their reservations before another ten sends and echoes. Both peers completed
authenticated closure, returned every allocated buffer and reported zero live
native keys. The server released admission and closed its identity. The fresh
ordinary recovery session used different session, binding and transcript values.

`local-validation.tar.gz` contains the original driver, raw endpoint/controller
logs, selected-source provenance, guard checks and structured results. The
checkout was clean at implementation revision
`9be289cec0824c5c1a7c3b04256e453afafbaef8`; all 168 selected file hashes and the
tested executable hash stayed unchanged during traffic. Temporary test credential
directories were removed. No private key is included. `SHA256.json` inventories
the evidence directory.

This was one Linux x86-64 host with separate server and client processes. There
was no SSH, OCI/WSL or long-duration execution. **The 60-second timeout case was
not executed locally.** Its verdict contracts were checked with synthetic events;
the actual unchanged production deadline remains an operator-run test. Reserved
send slots are not evidence of a blocked network writer or queued DATA frames.
These records do not establish timing accuracy, throughput, client authorization
or cryptographic security.

Operator commands: [BACKPRESSURE.md](../../BACKPRESSURE.md).
