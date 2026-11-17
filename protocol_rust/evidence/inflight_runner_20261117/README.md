# Pending-request interruption runner: local preparation evidence

Tested source commit: `5175bde` (full revision in the raw report).

Preparation checks passed:

- Pinned Rust/Cargo 1.99.1 release build of `spiral-lab`.
- 103 Python collector contract tests in 1.100 seconds, including twelve new
  interruption-verdict contracts and thirteen cross-host/rotation contracts.
- Four invalid CLI configurations rejected with Input, exit 1, zero executed KEM
  jobs and zero live keys: checkpoint zero, checkpoint equal to message count,
  multiple connections, and pipelined fault traffic.
- One local real-TCP/TLS pending-request interruption and one normal recovery;
  total recorded driver elapsed time about 0.304 seconds.

The local cut used a disposable TCP relay. The server and client were separate
processes on one Linux x86-64 host. There was no SSH connection, external host,
OCI/WSL execution or long-duration workload. These checks do not substitute for
operator-run cross-host results.

Both pending checkpoints match: three verified echoes; the fourth authenticated
request received with 1,024 bytes and its reply withheld. The relay was stopped
only after both events. Both Rust endpoints exited 1 with Closed and reported
zero live KEM keys. Server cleanup recorded active=0, pending=0, drained=true and
auth_key_closed=true. The fresh normal session then verified ten echoes,
authenticated closure, admission release and zero live keys. No authenticated
protocol CLOSE is claimed for the interrupted session.

The source checkout was clean and all 165 selected source-file hashes remained
unchanged. The tested executable hash is in `result.json`. Temporary credential
directories were removed; no private keys are in the archive. The validation
driver and original raw JSONL/error logs are included for reproducibility.

`local-validation.tar.gz` contains the raw preparation evidence.
`SHA256.json` inventories this directory. The source revision and controller
hashes in the raw report identify the tested code; later documentation/evidence
commits do not change that selected source.

Operator commands are in [INFLIGHT_DISCONNECT.md](../../INFLIGHT_DISCONNECT.md).
