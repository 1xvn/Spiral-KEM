# Operational key-file boundary and management CLI validation materials

See [operating procedures/scope](../../KEY_OPERATIONS.md). Runtime code789eb37
improved file-access boundaries, atomic creation, and public CLI from baseline956785c. Subsequently, public source/executable hashes
were added to test reports, and11 tests were reconfirmed with the same release binary.

| Check | Result |
|---|---|
| Rust library | 81 passed,5 ignored separate. Existing70 + file-boundary11 |
| Key-management CLI/actual TLS replacement | 11 passed, failure/error/skip0 |
| Functional CI | Python85, diagnostics24, C9, cleanup matrix23, documentation6, actualTLS35 passed; release succeeded |
| nested fuzz workspace | Same4 new dependencies in both locks, record_replay compiled successfully |
| New dependency provenance | rustix1.1.6 and linux-raw-sys/errno/bitflags archive SHA compared against both locks |
| Execution principal | Validated under normal Linux effective UID1000, using private temporary keys only |

`functional-ci/` contains actual full CI results. `key-ops-provenance-result.json` contains
11 focused tests in the updated report format; its binary hash matches CI release, and181 source files/binary were
confirmed unchanged before/after testing. These181 are public build/test inputs; generated secret files were not
collected into hash lists. Private temporary fixtures are removed on test completion.

File loaders/writers check Unix mode/UID, regular/nlink, symlinks, and parent paths. They use checked FDs without
reopening paths; NOREPLACE publication preserves existing names.
Numeric policy tests reject different UIDs/permissions and validate actual file/path/rename behavior.
Privileged chown to change owners or skips were not prerequisites for tests.

Public output/server errors were checked for absence of seed raw/hex/base64, PEM, and DER. Deadlines/read sizes are bounded
so the startup watchdog remains active even when only some stdout bytes arrive.
Management commands run before KEM initialization; invalid server secret files are rejected before listening/KEM-job execution.
This does not mean normal server KEM-pool creation itself is skipped.

The initial cloud sandbox mapped root-directory UID to65534, triggering strict-policy rejection.
Without relaxing policy, revalidation used a normal UID view showing actual root-owned ancestors.
`review.json` records observed UIDs/review scope. Full CI logs are results from the normal view.

Recovery tests verify matching public values for a seed copied into a0400 file in a new0700 directory. They do not approve encrypted
external backups, actual operational disaster recovery, or restoration after key compromise. TLS raw buffers
cleanup is also distinct from erasing all parser/provider internal copies.

The new operational-readiness phase1 is implemented/validated locally; it does not establish all item5, service deployment, actualOCI/WSL new
key-operations tests, long-term load, constant-time behavior, or overall memory approval.
Earlier two-platform cryptographic-source materials and unresolved warnings/gates are preserved unchanged.
