# Registered clients on the research channel

The opt-in Rust `mtls-server` accepts one connection on loopback. Its only application operation reads a fixed public lab status. A Python client opts in with `TLSTransport.mtls_client`. The ordinary Rust and Python research endpoints continue to use server authentication and their existing application behavior.

## Trust contract

| Decision | Authority and rule |
| --- | --- |
| Issue a test credential | A designated lab issuer signs a short-lived client certificate. The client controls its private key. Certificate validity is checked against the server clock at the TLS handshake. Correct wall time is a prerequisite. |
| Enroll and authorize | A separate server-side operator verifies the intended holder and leaf certificate through an independent provisioning channel. The operator grants the SHA-256 digest of the exact leaf DER the role `status-reader` for one configured DNS name and service. A renewed leaf needs its own grant. The peer supplies neither the trust root nor the grant. |
| Revoke | The operator changes the applicable row to `revoked` or removes it. Stop the old listener and terminate its session before restarting with the new snapshot. The policy and certificate lifetime are evaluated on admission. There is no live reload, per-message expiry, OCSP or CRL service. |
| Authenticate the server | The client receives the server TLS CA and Spiral Ed25519 pin independently of the connection. The server keeps its TLS key and Spiral signing key. The client CA and registry travel separately to the server. The two CA signing keys belong with their respective issuers. |
| Trust the endpoint | The server process, host, clock, issuer, operator and integrity of the provisioned files are trusted. Restrict registry/root writes to administrators and private keys to their owners. SSH and port forwarding give network reachability. Only the client certificate proof and server-side grant establish the application principal. A stolen enrolled key can exercise its grant until effective revocation or credential expiry on a new handshake. |

The registry is UTF-8, at most 65,536 bytes, with four whitespace-separated fields per line. An empty registry grants nothing. Invalid digests, unknown roles and duplicate rows for the configured audience fail startup. Example layout (replace the digest placeholder with 64 hex digits):

```text
spiral-lab.example spiral-research <leaf-DER-SHA256> status-reader
```

## Choice and enforcement

| Choice | Fit for this deployment |
| --- | --- |
| TLS 1.3 mutual authentication with rustls/WebPKI | The listener already terminates TLS. rustls validates the chain, proof of private-key possession, and validity. The listener additionally requires explicit clientAuth usage and excludes serverAuth and anyExtendedKeyUsage. It looks up the authenticated leaf on the same connection before submitting any KEM job. |
| An identity exchange inside the Spiral channel | Useful when application identities must survive a TLS terminator, or dispatch needs end-user tokens. It would require provisioning an issuer, defining message and audience validation, expiry, binding and replay rules, and updating both peers. Those requirements exceed the single-listener status-read experiment. |

The required profile negotiates only `spiral-opt2/0.1-mtls-lab`. The ordinary profile negotiates only `spiral-opt2/0.1`. TLS tickets, resumption and early data stay disabled. The exporter, Spiral wire encoding, KEM, server pin, Finished checks, record sequence rules and authenticated close are shared. After successful registration **and** Spiral establishment, the handler accepts exactly the DATA bytes `READ /status` and responds `lab-ready`. Every other request terminates the session before an operation runs. No client-supplied role, resource path or payload appears in the audit events.

A TLS CertificateVerify signature covers a specific handshake transcript. There is no application bearer credential to replay. The connection tests below exercise replay of actual Spiral DATA on the same and another authenticated connection. A fresh authorized read with a fresh sequence is a new, idempotent operation.

## Decisions observed on real connections

| Condition | Expected and observed boundary |
| --- | --- |
| Registered, correct audience and pin, allowed read | One response verified by the client, one `status_read`, authenticated close on both ends. |
| Missing certificate, foreign issuer, expired leaf, server-only or mixed server/client certificate, wrong SNI, ordinary client to required listener | TLS/profile rejection, zero KEM jobs. Foreign, expired and wrong-role leaves had explicit grants to isolate the TLS decision. |
| Trusted but unregistered leaf, revoked grant on restart, grant for another DNS name or service | `registry_denied`, zero KEM jobs. The revocation case uses the same credential that succeeded earlier. |
| Correct grant but wrong Spiral service in ClientHello | Registry admits, Spiral handshake fails before key generation. |
| Correct grant but client lacks the Spiral server pin | Client rejects server before sending its KEM ciphertext. One server key-generation job, zero live keys after shutdown. |
| Write status, read another resource, declare an admin role in DATA | `operation_denied`, zero status responses. |
| First DATA from an earlier session with the same enrolled leaf | Fresh exporter and session ID checked in memory. The old record produces zero status responses on the new connection. |
| Duplicate the exact accepted DATA record on one session | One verified response and one `status_read` for the original, then rejection. |
| Required client to ordinary Rust server | Incompatible ALPN ends the connection before KEM. |
| Missing registry, invalid digest, unknown role, duplicate matching row | Startup fails before a listener is announced. |

Each required-mode connection rejection checks the server exit, active and pending admission counts of zero, closed Spiral signing identity, and zero live native keys after worker shutdown. These observations cover the application's owned handles. TLS-provider memory erasure, identity proofing of people, an account directory and production revocation propagation are outside the experiment. Operators should retain the public decision logs and keep private credential directories local.

## Evidence and reproduction

The local Linux x86-64 run used implementation commit `d31e0ff0db5b52559ef8a15ef2c16912b1758b3d`, rustc 1.99.1, rustls 0.23.46, Python 3.12.14 and pyOpenSSL 26.4.0. The release binary exercised 20 real connection cases and four startup cases. The functional CI runner includes this suite. The ordinary profile passed all 15 interoperability tests, including both Rust/Python directions. The diagnostic-feature configuration also compiled. OCI, WSL and hosted CI are separate runs.

- [Per-case server decision events, exit status, cleanup counts and configuration results](evidence/client_auth_20261118/connections.json)
- [Client test log](evidence/client_auth_20261118/client-auth.log)
- [Ordinary-profile interop log](evidence/client_auth_20261118/default-interop.log)

**WSL Ubuntu or OCI SSH Ubuntu.** Run the following from a Git checkout of the public repository with the pinned Rust toolchain, C build tools and Python venv support. It creates a fresh checkout and private result directory without changing the current working tree. Both endpoints run on loopback on the host executing the commands. The runner provisions fresh keys and removes its credential directory when finished.

```bash
(
  set -eu
  umask 077
  pin=d31e0ff0db5b52559ef8a15ef2c16912b1758b3d
  git fetch origin refs/heads/spiral-client-auth-lab-20261118
  out=$(mktemp -d "$HOME/Spiral-client-auth-XXXXXXXX")
  git worktree add --detach "$out/source" "$pin"
  cd "$out/source"
  python3 -m venv "$out/venv"
  "$out/venv/bin/python" -m pip install -r protocol_v01/requirements.txt
  CARGO_TARGET_DIR="$out/target" cargo +1.99.1 build --release --locked --bin spiral-lab --manifest-path protocol_rust/Cargo.toml
  "$out/venv/bin/python" protocol_rust/client_auth_tests.py --binary "$out/target/release/spiral-lab" --json "$out/result.json"
  printf 'Result: %s/result.json\n' "$out"
)
```

**Windows PowerShell, for the WSL result.** Paste the complete Linux result path printed above at the prompt.

```powershell
$path = Read-Host 'WSL result.json path'
$src = (wsl.exe -d Ubuntu-24.04 -- wslpath -w "$path").Trim()
$dest = Join-Path "$env:USERPROFILE\Downloads" "Spiral-client-auth-wsl.json"
Copy-Item -LiteralPath $src -Destination $dest -ErrorAction Stop
Get-FileHash -Algorithm SHA256 -LiteralPath $dest
```

**Windows PowerShell, for the OCI result.** Use the SSH host alias configured on Windows and the full result path printed on OCI.

```powershell
$oci = Read-Host 'OCI SSH alias or ubuntu@host'
$path = Read-Host 'OCI result.json path'
$dest = Join-Path "$env:USERPROFILE\Downloads" "Spiral-client-auth-oci.json"
scp "${oci}:$path" "$dest"
if ($LASTEXITCODE -eq 0) { Get-FileHash -Algorithm SHA256 -LiteralPath $dest }
```

For an independently provisioned fixture, launch the server as follows. Select its printed loopback port on the client, then open `TLSTransport.mtls_client(sock, ca_file=..., cert_file=..., key_file=..., server_name=...)` before the normal pinned Spiral client handshake. The binary's `client` command and the Python server remain ordinary research endpoints. To remove the experiment from a deployment, stop this listener and remove its grant and trust configuration. Keep protected operations off the ordinary echo listener.

```bash
spiral-lab mtls-server --name spiral-lab.example --service spiral-research --port 0 \
  --cert server-chain.pem --key server-private.pem --auth spiral-signing.bin \
  --client-ca client-ca.pem --client-registry grants.txt --messages 1
```
