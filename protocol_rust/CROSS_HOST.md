# OCI–WSL functional checks over SSH forwarding

For an interruption after verified DATA progress with a response pending, use
the [in-flight interruption runner](INFLIGHT_DISCONNECT.md).

This operator-run exercise places the Rust server on OCI Ubuntu ARM64 and the
Rust client on WSL Ubuntu x86-64. OpenSSH forwards a private local TCP listener
to the existing loopback-only server on OCI. Existing SSH access controls entry;
the Spiral channel still verifies its own TLS server certificate, Ed25519 pin,
exporter binding, KEM handshake, echoed data and authenticated closure.

This is a functional experiment. It does not supply application-level client
authentication, public-service authorization, independent server capacity or
cryptographic-security approval. WSL clock discrepancies remain a qualification
on elapsed-time and latency observations. No clock services are modified.

## 1. OCI server terminal: update and build

Use the existing SSH connection to OCI and the checkout used for duration tests:

```bash
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --bin spiral-lab
```

Rust/Cargo 1.99.1 is pinned in `rust-toolchain.toml`. The load-test preparation
already installed the Python requirements into `.venv-load`. If that environment
is absent, run `bash protocol_rust/run_load_test.sh --prepare` first, then build
`spiral-lab` with the command above. That preparation does not start a campaign.

## 2. OCI server terminal: create fresh test identities

```bash
cd "$HOME/Spiral-load-hours" &&
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server
```

The new `$HOME/Spiral-cross-host-server` directory is private. Its `private`
subdirectory owns `key.pem` and `auth.bin`; those files remain on OCI. Fresh CA,
leaf and pin validity is 24 hours. These are test identities, not service keys.
Only `ca.pem`, `pin.json` and public source/build provenance enter `public.tar.gz`.

Without an explicit rotation option the command refuses to overwrite an existing state directory. Existing state
can serve repeated cases during its validity. If it expired or the selected
source/binary changed, retain or remove the old test state according to your key
policy before generating a new one. For example, an explicit local backup is:

```bash
.venv-load/bin/python -B protocol_rust/validation/cross_host_smoke.py prepare-server --rotate-test-state
```

This retains the old private test keys in a timestamped backup and generates a
fresh identity; it does not erase the old keys. Let WSL fetch the new public bundle.

## 3. WSL client terminal: update and build

Run inside the normal Ubuntu terminal, not PowerShell or the WSL debug shell:

```bash
sudo apt-get install -y openssh-client
cd "$HOME/Spiral-load-hours" &&
git switch spiral-load-validation-20261111 &&
git pull --ff-only &&
cargo build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml --target-dir protocol_rust/target --bin spiral-lab
```

Keep both checkouts at the same selected source and runner revision. Do not edit
the selected files or rebuild their binaries during a case. Endpoint executable
hashes naturally differ across ARM64 and x86-64.

## 4. WSL: SSH setup and first normal case

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/cross_host_smoke.py run --case normal
```

The runner prompts for:

1. The existing OCI SSH target, such as `ubuntu@YOUR_OCI_ADDRESS`, or an existing
   SSH configuration alias.
2. The existing SSH private-key path **as seen by WSL**, or an empty line when
   SSH config/agent supplies it. A Windows `C:\...` path is not a WSL path.

Use the same working SSH access used for earlier OCI tests. The key is passed
only to OpenSSH and is never copied into result archives. If it has a passphrase,
OpenSSH may prompt again for each separate connection. Host-key verification is
preserved. A GitHub password is unrelated to these prompts.

If the existing private key is only on Windows, copy it into WSL's Linux home
filesystem with private permissions. This is a local copy; it is not included
in result archives. Enter the real Windows key path without surrounding quotes:

```bash
read -r -p 'Existing Windows SSH key path: ' spiral_windows_key
spiral_key_source="$(wslpath -u "$spiral_windows_key")"
install -d -m 700 "$HOME/.ssh"
test ! -e "$HOME/.ssh/spiral-oci.key" &&
install -m 600 "$spiral_key_source" "$HOME/.ssh/spiral-oci.key"
```

Then enter `~/.ssh/spiral-oci.key` at the runner's key-path prompt. Reuse an
existing working WSL SSH setup when one is already available.

The runner performs the following automatically:

- Fetches only the three-file public bundle over the authenticated SSH channel.
- Compares selected source and runner hashes across the two machines.
- Starts its own SSH forwarding process on an available `127.0.0.1` port.
- Checks that the listening socket belongs to that SSH process.
- Starts the remote server and reads its flushed JSON readiness line.
- Immediately launches the local client for one session, ten 1,024-byte echoes.
- Compares both final reports and stops its SSH connections.

No OCI application port needs to be opened. The server remains on
`127.0.0.1:39401`. No DNS or hosts-file change is needed for the TLS test name
`spiral-lab.example`. Do not start the server manually: it accepts a connection
for only ten seconds, and an `nc` or browser readiness connection would consume
its single allowed connection.

## 5. WSL: expected failures and reconnection

After the normal case works, run:

```bash
cd "$HOME/Spiral-load-hours" &&
python3 -B protocol_rust/validation/cross_host_smoke.py run --case all
```

| Case | Required observation |
| --- | --- |
| `normal` | Both endpoints pass, verify ten echoes and authenticate closure |
| `wrong-pin` | Client reports authentication failure; both endpoints fail and release native keys |
| `unavailable` | The runner closes its tunnel before a new client; client reports transport failure |
| `recovery` | A fresh tunnel/server completes another normal case with a different session ID |

The unavailable case is a closed transport before connection. It does not prove
behavior during interruption of an established session. Active-session cuts,
slow readers and server-restart recovery require separate instrumentation.
Individual `--case wrong-pin` or `--case unavailable` runs are also available.

## Verdicts and cleanup

A normal result requires zero exit status from both Rust endpoints, one session,
ten messages, authenticated closure, zero live KEM keys, released server admission
and closed server identity. Session ID, transcript hash and TLS binding hash must
match across endpoints. The Rust client verifies the echoed payload bytes itself.
These fields do not make timing measurements reliable on the current WSL setup.

The server is bounded by a 60-second remote watchdog plus five seconds of forced
termination allowance. After controller cancellation or SSH loss, the remote
listener can remain briefly until that bound; immediate remote cleanup is not
claimed. Ctrl+C and SIGTERM invoke local cleanup. SIGKILL/host shutdown cannot be
handled by a Python finally block. If an interrupted remote server still owns
the port, allow that bound to expire before trying again.

## Results to submit

The last line prints `$HOME/Spiral-cross-host-....tar.gz` on **WSL**. Send that
archive, including failed cases. It contains public fixture data, selected source
provenance, per-case server/client/SSH logs, verdicts and a SHA-256 inventory.
SSH error logs can contain connection/key-path details; review them before any
public redistribution. Do not upload the OCI state directory or private keys.

On a preflight SSH/credential/source error, the tool exits before starting a case;
send the terminal error so that access or preparation can be corrected.

Preparation of this tool used eleven pure contract tests and help/syntax checks.
No SSH, sockets, TLS workloads or cross-host tests were executed for those checks.
Actual OCI–WSL outcomes remain for operator execution.
