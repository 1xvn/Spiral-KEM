# Duration-profile runner: short validation only

Tested source: `7424a0a00cd1dd3a99cabe4ab20367f27fdd783c`.

The operator launcher prepares `30m`, `1h`, `2h`, `6h`, `12h` and `24h` profiles.
**No long-duration campaign was executed for this change.** This evidence checks
runner readiness; it is not a passed one-hour or day-long soak, an OCI/WSL result,
a capacity assessment or cryptographic security approval. The prior 30-minute
campaign in `../load_20261111/` predates these changes and remains unchanged.

## Checks performed

- Offline release build of `load_probe` with the pinned Rust/Cargo 1.99.1 passed.
- 29 collector contract tests passed, including bounded day-sized resource
  aggregation, duration validation, fixed reconnect/close deadlines, resumed
  echo-progress checks, lifetime coverage for CA/leaf/pin and listener-adjusted
  descriptor recovery.
- Bash syntax, profile listing and no-argument rejection passed. No-argument
  invocation returned 2 and did not start traffic.
- One local Linux x86-64 real-loopback TLS smoke used 64 connections, 16 KiB
  payloads and 50 ms pacing. Requested traffic duration: 10 seconds.
- Evidence manifest hashes and all seven archive members matched the collected
  files. No credentials or executable were archived.

## Smoke observations

| Observation | Result |
| --- | --- |
| Verdict | Passed |
| Traffic epoch / total collector wall time | 10.001559 s / 21.392093 s |
| Verified echo round trips | 12,736 |
| Peak authenticated connections | 64 |
| Admission checks | 4/IP, 32 pending, 64 active; rejection and recovery passed |
| Authenticated pairs / closes | 70 / 70 |
| Endpoint handshakes / native KEM jobs | 140 / 210 |
| Final active / pending / live native keys | 0 / 0 / 0 |
| File descriptors, initialized / final | 8 / 7 |
| Sampled peak RSS / FDs / threads | 17,452 KiB / 135 / 5 |
| Source / executable unchanged | Both true; clean source checkout |

Resources include server, clients and harness in one process. A 10-second smoke
does not reach the default 240-second session rotation. Phase transitions and
their watchdogs are covered by focused contract tests; actual multi-rotation,
hourly and platform campaigns remain operator work.

## Files and reproduction

- `smoke-64-10s.tar.gz`: complete raw smoke evidence and exact source hashes.
- `collector-contracts.log`: 29-test output.
- `profiles.log`, `no-arguments.log`: launcher interface checks.
- `smoke-console.log`: collector console output.
- `archive-audit.json`: archive integrity check and concise observed resources.
- `SHA256.json`: integrity inventory for this evidence directory.

Archive SHA-256:
`a2d1c2976f5a2bcfdec4610282dfc513820d80b7a7b1b2f607a975aebf1d392f`.

```bash
python -B -m unittest discover -s protocol_rust/validation -p test_load_campaign.py -v
bash -n protocol_rust/run_load_test.sh
bash protocol_rust/run_load_test.sh --list-profiles
python -B protocol_rust/validation/load_campaign.py \
  --binary /path/to/release/examples/load_probe --output /new/evidence/directory \
  --duration 10s --connections 64 --payload 16384 --interval-ms 50 --platform local
```

Use a Python environment with `protocol_v01/requirements.txt`. See
[`LOAD_COMMANDS.md`](../../LOAD_COMMANDS.md) for operator-run OCI and WSL campaigns.
