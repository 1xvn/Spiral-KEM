# Operational key management phase 2: encrypted backup/recovery and replacement-failure drills

Baseline main is `d2f19b9` (PR #30). Server authentication seeds and TLS private keys are encrypted with a separate recovery key,
recovered to new private paths, and checked using actual loopback TLS. This phase
exercises recovery of temporary research keys and valid keys during maintenance. Overall operational-readiness item5, production-service
deployment, external-vault configuration, constant-time behavior, and overall memory-safety approval remain separate.

## Targets and trust criteria

| Target | Input | Public fingerprint to retain externally |
|---|---|---|
| Server authentication key | Exactly32-byte Ed25519 seed | SHA256(raw Ed25519 public key32 bytes), same as existing auth-public |
| TLS private key | 1 private-key entry accepted by the existing loader, at most65536-byte PEM | SHA256(RFC5280 DER SubjectPublicKeyInfo), distinct from whole-certificate hash |
| Recovery key | 32-byte file generated with OS randomness | Secret; never passed through output/logs/command-line arguments |

Generate recovery keys with `recovery-keygen`. Do not reuse human-created32-character passwords or authentication seeds
as recovery keys. Identical authentication-seed/recovery-key bytes are also rejected.
The code checks file boundaries; it does not prove physically separate storage.

Actual storage policy must keep recovery keys under an access boundary separate from backups/active keys and retain approved
service/generation/role public fingerprints in independent records. A principal possessing both the recovery key and backup
can recover the original key. Encrypted storage, recovery authorization, loss
handling, and retention periods for recovery keys require separate operational configuration. This implementation does not register recovery keys in KMS/vault.

## Management commands

| Command | Required options | Output |
|---|---|---|
| recovery-keygen | --recovery-key new-path | created status only |
| tls-public | --key PEM-path | TLS SPKI public fingerprint |
| auth-backup | --auth seed-path --recovery-key path --backup new-path | backed-up, role, public fingerprint |
| tls-backup | --key PEM-path --recovery-key path --backup new-path | Same, TLS role |
| auth-restore | --auth new-path --recovery-key path --backup path --expected-public-key-sha256 fingerprint | restored, role, public fingerprint |
| tls-restore | --key new-path --recovery-key path --backup path --expected-public-key-sha256 fingerprint | Same, TLS role |

Fingerprints are64-digit public hex values. Recovery commands must obtain the expected fingerprint from an approved independent record.
Using a value read directly from the backup header as expected removes the generation-selection trust boundary.
Management commands run before KEM worker/listener creation and do not print seeds, PEM, DER, or recovery keys.
Errors also exclude secret-file contents. Unknown/duplicate/options unnecessary for the command are rejected.

## Backup format v1

Uses ChaCha20-Poly1305 from existing pinned dependencies. No new cryptographic primitive or password KDF
was added; the recovery key is used directly as a32-byte symmetric key.

```text
offset  size  field
0       8     magic = SPBKUP00
8       1     version = 1
9       1     kind = 1(auth seed) / 2(TLS PEM)
10      12    OS-random nonce
22      32    public fingerprint
54      4     plaintext length, big endian
58      N     ciphertext
58+N    16    authentication tag
```

The entire58-byte header is authenticated as AAD. Every backup gets a fresh OS-random nonce.
Version1 permits only this algorithm and format. Unknown magic/version/kind, invalid lengths,
truncation, appended bytes, and oversized inputs are rejected. Authentication-seed backups are106 bytes; TLS PEM
backups are at most65610 bytes. Accepted TLS PEM original bytes are preserved exactly.

Do not reuse nonces with the same recovery key. This does not implement a bulk-backup service or nonce-tracking storage;
operators must maintain per-recovery-key backup inventories and rotation policies.

Recovery completes AEAD authentication and plaintext-format checks, then rederives the public fingerprint from plaintext.
A new file is created only if this fingerprint matches both the authenticated header and external expected value.
Incorrect recovery keys, tampering, role confusion, and different keys from previous generations are rejected before creation.
Fingerprints alone cannot distinguish older valid backups of the same key. Disposal, revoked status, expiry, and generation
approval must be determined through external operational records and pin policy.

## File boundaries and recovery sequence

All inputs/outputs use the existing Linux FD-based private-file policy. Private files must be
owned by effective UID, exact0400/0600, regular, and link count1; immediate parents must be0700 (0500 also
allowed for reading). Symlinks, FIFOs, hardlinks, and unsafe ancestors are rejected. Creation proceeds in the same directory as
temporary0600 file → file fsync → NOREPLACE rename → directory fsync.
Existing active keys, backups, recovery keys, and special paths are not overwritten.

1. Check approved public fingerprints, generations, and pins against separate records. Do not select compromised/revoked keys for recovery.
2. Recover the authentication key and TLS private key separately into a new0700 generation directory distinct from active paths.
3. Check both public fingerprints, TLS certificate/private-key matching, pin, validity, and service settings.
4. Start the new generation during a maintenance window and verify communication/authenticated CLOSE with the trusted new pin.
5. On failure, do not activate an incomplete new generation. Restart only a valid, unrevoked previous generation under approved procedures.

The two files are created atomically individually; generation-wide multi-file transactions, distributed pin delivery, and
uninterrupted reload are not implemented. If the second recovery fails, the first recovered file may remain in the new
inactive directory. Operators must activate only after all checks finish.
If directory fsync fails after NOREPLACE publication, the final file may exist alongside an error.
After an error, inspect file/storage state instead of automatically deleting or regenerating.

TLS certificates, CAs, pins, and service settings are separate public/operational materials. This backup does not store that entire configuration or
service data. unlink does not prove erasure on SSDs, snapshots, or backups.
On WSL, use the Linux home filesystem. Windows ACLs and host-administrator access fall outside the boundary guaranteed by this file
policy.

## Tests and completion criteria

Checks cover encryption/recovery round trips, incorrect keys/fingerprints/roles, header/ciphertext/tag tampering, truncation/appending/oversized
inputs, input-key formats/permissions/paths, existing-destination preservation, and secret-free output. Actual
loopback TLS confirms new-generation startup failure/process termination/valid previous-generation restart, recovery of both new-generation
keys and authenticated CLOSE with the new pin, previous-backup rejection, and active-file preservation.

Process termination in these drills is distinct from physical power loss, storage corruption, or distributed-service disaster recovery.
Cleanup of owned buffers is also distinct from erasing all parser/provider/OS/previous memory copies.
No secret-export method is added to the server authentication key's opaque owner.

Actual test counts/completion are recorded after reviewing execution results, pinned source, tool versions, and original logs.
OCI ARM/WSL execution of this new code is confirmed through separate submissions after local validation.

Local functional CI passed Python85, diagnostics24, C9, Rust94 (separate ignored5), cleanup matrix23, documentation6, existing
key management11, recovery20, and actual TLS35. Subsequently, expanded recovery tests also passed with the same release binary:
20 tests compared PKCS8/PKCS1/SEC1 fingerprints and original-byte recovery for Ed25519/RSA/ECDSA P256/P384.
These20 count individual methods, with additional algorithm/tampering/boundary subtests.
Results from both target environments are still pending.

We provide [local originals and pinned bundle validation](evidence/key_recovery_20261110/README.md),
and [OCI/WSL downloads and commands](../downloads/key-recovery-d4c46bc/README.md).
