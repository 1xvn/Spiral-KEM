# Operational key management phase 1: file boundaries, generation, replacement, and recovery

Key-file loaders and management CLI were improved from baseline source `956785c`. File-policy/CLI
implementation code is `789eb37`. **This is the first phase of operational readiness item 5, not service-deployment approval or
completion of all of item 5.** Network runners remain for existing loopback research use.

## Storage and access boundaries

| Item | Applied policy |
|---|---|
| Authentication key | Exactly 32-byte Ed25519 seed, retaining original length/EOF validation |
| TLS private key | At most 64KiB, 1 recognized private-key entry. Raw read buffers cleaned |
| Key file | Open FD must be a regular file, owned by effective UID, link count1, exact0400/0600 |
| Immediate parent | effective UID-owned0700;0500 also allowed for reading. Creation requires0700 |
| Ancestor paths | Owned by root or effective UID, no group/other writes. Exception only for root-owned sticky public ancestors |
| Path traversal | Directory-FD-relative openat, reject all symlinks and ancestor .. paths |
| Special files | Open with NONBLOCK/NOFOLLOW and check FD type. Reject FIFO/directory/hardlink, etc. |
| Management output | Public key, SHA256 fingerprint, and status only. No seed/PEM/DER/secret-value output |

Uses pinned rustix 1.1.6 safe APIs; no custom unsafe code added.
Reads through the checked FD, avoiding races from reopening after path checks. The loader does not automatically fix existing files'
permissions/owners. Root and service UID are trusted principals; this is not an isolation boundary preventing those principals
from reading or modifying files.

Root-owned sticky `/tmp` is allowed as an earlier ancestor, but the actual key's immediate parent must be a service-UID-owned
private directory. This rule also supports existing0700 temporary test directories.
Store WSL keys on the Linux home filesystem. Unix-mode checks do not guarantee DrvFS/Windows ACL behavior or prevent host-administrator access.
Non-Linux platforms are rejected before file access.

Public certificates, CAs, and pins are separate from private-key0600 rules. Public files also require modification controls and distribution-path
integrity. Current pin/CA files are not checked by this new private-file loader.

## Key generation and public-value inspection

Build from the repository root. The example below creates a fresh key directory for the current execution account.
Keep files outside the Git repository. Do not reuse paths for an active generation.

```bash
set -euo pipefail
cargo build --locked --release --manifest-path protocol_rust/Cargo.toml
umask 077
install -d -m 0700 "$HOME/.spiral-keys"
SPIRAL_KEY_DIR="$HOME/.spiral-keys/v1"
mkdir -m 0700 "$SPIRAL_KEY_DIR"
protocol_rust/target/release/spiral-lab auth-keygen \
  --auth "$SPIRAL_KEY_DIR/auth.bin" > "$SPIRAL_KEY_DIR/public.json"
protocol_rust/target/release/spiral-lab auth-public \
  --auth "$SPIRAL_KEY_DIR/auth.bin"
```

`auth-keygen` creates a seed with OS randomness, writes a new temporary file with0600 under the same parent FD,
then publishes via file fsync → NOREPLACE rename → directory fsync. Restrictive umask is also
handled by fchmod on the created FD. Existing files/symlinks/FIFOs/directories are not overwritten.
Unused temporary files are removed best-effort on failure.

If directory fsync fails after publication, a final file may exist despite a failure return.
After an error, inspect the file and storage state without automatic deletion/regeneration. Public values can be inspected
with `auth-public`. Public output contains only `public_key_hex`,
`public_key_sha256`, and status. Neither management command creates a KEM pool or listener.

Install TLS private keys through a trusted deployment procedure in a new private directory under the same policy, confirming service UID and
0600/0400. TLS certificate issuance and external secret-manager integration are separate.
The new loader rejects multiple private keys and large files. It does not guarantee complete erasure of parser/provider internal key copies;
certificate, wire, and signature algorithms are unchanged.

## Key inventory and records

Operational records include generation(v1/v2), public fingerprint, generation/activation/replacement/revocation times, pin validity, and
operation results. Do not record raw seeds, hex/base64 seeds, private-key blocks, or session keys.
Server authentication and TLS keys are managed as separate roles. KEM leases/session keys remain short-lived under existing memory
owners and are disposed of; do not make them disk-backup targets.

Pin `public_key_hex` is the public value above; `server_name`, `service`, `not_before`,
`not_after`, and `revoked` use the existing pin format. Operators must define replacement windows and expiry times and
deliver pins to clients through a separate trusted distribution path. Do not automatically trust new pins based solely on network responses
or fall back to previous keys/algorithms on errors.

## Replacement and revocation

Current pins trust a single public key, so use cold rotation during a maintenance window.
This does not implement uninterrupted dual-pin/hot reload.

1. Generate a new seed in a new0700 generation directory and check its public fingerprint.
2. Prepare a pin with the new public key/validity period and coordinate client distribution.
3. Stop new connections and confirm shutdown of existing sessions and the server process.
4. Apply the new key path and pin, then restart. The old pin must be rejected; communication/authenticated CLOSE with the new pin must succeed.
5. Dispose of old keys/backups under the retention policy and update public records.

`ServerIdentity::close()` waits for in-progress signing and rejects new signatures. It does not automatically revoke already-established
session keys, other processes, or backups. Pin revoked status applies to clients reading and verifying the new pin;
it does not remotely terminate existing sessions.
Do not reactivate suspected compromised keys for recovery/rollback; replace them with new keys/pins.

File unlink or chmod does not prove secret erasure on SSDs, snapshots, copy-on-write storage, or backups.
Define encrypted-storage and recovery-key lifetime policies, retention periods, and access controls separately for the deployment environment.

## Recovery

Keep backups in separately access-controlled encrypted storage, outside operational Git/logs.
Recover into0400/0600 files in a new0700 generation directory and compare the `auth-public` fingerprint
against an independent trusted record. Local tests confirm matching public values of copied recovery files.
They do not exercise external-vault encryption/recovery-key management or actual production disaster recovery.

## Validation and reproduction

Local Linux passed81 Rust tests (existing70+file-boundary11) and11 management-CLI/actual TLS replacement tests.
These include matching public values, umask000/777, a single concurrent-creation winner, existing-entry preservation, permission/path rejection,
FIFO watchdog, rejection of over64KiB/duplicate/invalid PEM, old-pin rejection, and new-pin success.
Management output is checked for secrets; failure messages also exclude keys.

```bash
python3 protocol_rust/key_ops_tests.py \
  --binary protocol_rust/target/release/spiral-lab \
  --json "$HOME/Spiral-key-operations-result.json"
```

JSON includes public source hashes, executable hashes, platform, and test results. It creates private temporary test keys
without reading actual operational keys and removes them on exit. Tests are integrated with full functional CI,
checking exact counts, omissions, and skips. The existing secret-flow collector's minimum default count was also updated to81;
historical70-test materials remain records of their pinned source.

In this cloud sandbox's UID namespace, root-owned directories may appear as65534,
causing strict-policy rejection. Tests ran outside the sandbox with a normal UID view, without relaxing policy.
Actual OCI ARM/WSL key-operations tests for the new code require separate submissions.
See [original validation records and scope](evidence/key_operations_20261109/README.md).

## Remaining operational readiness

Actual service-account/OS-permission/vault/encrypted-backup application, approved pin distribution, operational audit/monitoring,
long-term load, disaster recovery, and platform revalidation remain outstanding. This file policy does not establish completion of all item 5 or
approval of cryptographic design, constant time, or overall memory. Existing warnings/gates remain.
