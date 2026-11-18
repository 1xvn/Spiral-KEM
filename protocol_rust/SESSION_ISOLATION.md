# Four-session isolation on a shared server

Run one WSL client controller against one OCI server per scenario. All four peers finish the real TLS and Spiral handshakes before the gate pauses. One session goes through the existing gated TCP relay. Three go directly to the same loopback test listener through a second SSH forward. All share the server process, listener, admission object, signing identity and one KEM worker pool. The worker count is one. The fifth *lifetime* accept opens after the target is reclaimed. At most four sessions are active. The ordinary protocol deadlines, per-IP cap, token bucket, queue capacities and key limits apply.

| Scenario | Terminal condition |
| --- | --- |
| Hold | Keep both relay reads held for at least five seconds after the actual stall witness. Verify continued sibling traffic and release for orderly cleanup. |
| Release | Resume after an acknowledgment barrier and a further round of socket observations. Verify all 1,021 bulk records, the three baseline records and authenticated CLOSE. |
| Timeout | Hold reads through the server's own idle deadline (about 60 seconds). Require the server's timeout record, local failure cleanup and the expected stalled-client failure. Keep healthy peers exchanging through recovery. |

Each healthy challenge is 1,024 public bytes binding its lane, sequence, session ID, exporter binding and transcript. The sender checks the entire echo. The server checks every challenge before echoing. Zero progress, missing events, identity reuse, sequence gaps, unexpected failure and watchdog termination fail the verdict. Raw stderr retains the expected timeout error.

The stall witness requires a new underlying socket write Pending and unchanged written bytes on an open session for at least 200 ms. The controller waits for all three healthy acknowledgments in each round before issuing the next. A further round samples the stalled socket after the previous acknowledgments, while the gate is still held. All three must advance within a five-second observed gap throughout the case. After cleanup the server records admission (3 active, 0 pending) and zero live native keys. Native KEM keys are ephemeral handshake objects. A replacement must complete a fresh handshake, take slot four and exchange a verified echo before the original healthy peers close. The final worker shutdown must report ten executed server jobs, zero rejections and zero live keys.

Budget: 120 seconds per case after SSH setup, with a 115-second remote watchdog and five seconds of kill grace. A watchdog exit fails. The local three-case run took about 70 seconds of case time. Build and SSH setup add time. Local event order and controller monotonic gaps establish functional progress. These observations do not calibrate WSL clocks or measure service capacity.

## Local results already collected

At clean source `e09e63111f91182a52efe26df48a15507dfcb655`, one Linux x86-64 host ran both endpoints without SSH. Each row has one server and five distinct lifetime sessions.

| Case | Echoes on each of the three healthy sessions | Longest healthy gap observed | Initial stalled-server sample | End |
| --- | ---: | ---: | --- | --- |
| Hold | 30 | 258 ms | 170/1,021 bulk done, write Pending | 5.37 s to the overlap fence, then released |
| Release | 17 | 236 ms | 170/1,021 bulk done, write Pending | All bulk verified and target closed |
| Timeout | 271 | 304 ms | 170/1,021 bulk done, write Pending | Server Deadline at 59.791 s after witness, close reason 1 |

The three stall witnesses each recorded 2,865,457 written bytes with the TCP Pending poll counter rising from 0 to 2. Every replacement verified one echo. All three runs passed reclamation and final shutdown checks. The operator pin adds offline replay, tighter evidence checks and the cross-host architecture check. The Rust runtime and original evidence remain traceable to their execution commit. The stricter verifier accepted all three original runs and a fresh release on the operator pin. OCI/WSL collection for this experiment is pending.

[Local raw archive](evidence/session_isolation_20261118/local-linux.tar.gz) · [Operator-pin release archive](evidence/session_isolation_20261118/operator-pin-release.tar.gz) · [Regression and build logs](evidence/session_isolation_20261118/)

## Prepare the pinned checkout on each host

In **OCI SSH Ubuntu** and **WSL Ubuntu**, run this block once on each machine. It uses the existing repository at `~/Spiral-load-hours` and creates a separate worktree. A previously created checkout must already match the pin. The pinned Rust toolchain, C compiler and OpenSSL build dependencies used for wire stall are prerequisites.

```bash
(
  set -eu
  pin=786bf0a1a69a18b20c17fdaa687605b2b8b12180
  repo="$HOME/Spiral-load-hours"
  dest="$HOME/Spiral-isolation"
  git -C "$repo" fetch origin refs/heads/spiral-session-isolation-20261118
  if [ ! -e "$dest" ]; then git -C "$repo" worktree add --detach "$dest" "$pin"; fi
  cd "$dest"
  test "$(git rev-parse HEAD)" = "$pin"
  test -z "$(git status --porcelain)"
  cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml \
    --target-dir protocol_rust/target --features flow-diagnostics --bin spiral-lab
)
```

**OCI SSH Ubuntu** · Prepare a fresh 24-hour test identity. This uses the existing cross-host preparation workflow. Any earlier test identity is moved to a dated backup directory. Only public fixture data is fetched via SSH.

```bash
cd "$HOME/Spiral-isolation" &&
"$HOME/Spiral-load-hours/.venv-load/bin/python" -B \
  protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

**WSL Ubuntu** · Start the three cases after OCI preparation. Enter the existing SSH alias or target and key path if prompted. The WSL controller creates and stops the remote supervisor and SSH forwards. Keep loopback ports 39401 and 39402 free on OCI.

```bash
(
  set -eu
  cd "$HOME/Spiral-isolation"
  output="$HOME/Spiral-isolation-results-$(date -u +%Y%m%dT%H%M%SZ)"
  python3 -B protocol_rust/validation/isolation.py run --case all --output "$output"
  python3 -B protocol_rust/validation/verify_isolation.py "$output.tar.gz"
  sha256sum "$output.tar.gz"
)
```

The operator prints the archive path. Case directories contain each client stdout/stderr, gate stdout/stderr (including server events), the ordered controller journal and the case result. The archive includes these, summary, public preparation data and a SHA-256 inventory. Failed cases retain partial logs and stop the batch. SSH setup failures precede case collection. Evidence from both hosts travels through the existing SSH channels to WSL. To send a result, use the printed archive.

**Windows PowerShell** · Copy that exact WSL archive into Downloads. Paste the printed Linux path when prompted.

```powershell
$archive = Read-Host 'Paste the full /home/user/...tar.gz path from WSL'
$src = (wsl.exe -d Ubuntu-24.04 -- wslpath -w "$archive").Trim()
$dest = Join-Path "$env:USERPROFILE\Downloads" (Split-Path -Leaf $src)
Copy-Item -LiteralPath $src -Destination $dest -ErrorAction Stop
Get-FileHash -Algorithm SHA256 -LiteralPath $dest
```
