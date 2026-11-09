# Scoped RustCrypto cleanup patches

These are local source patches, not unmodified crates.io releases. Upstream
versions, archive URLs, SHA-256 checksums and original file hashes are recorded
in `upstream-provenance.json`. Original licenses and attribution are retained.
The installed Cargo registry cache is not modified.

The protocol and its nested fuzz workspace both opt into these sources using
`[patch.crates-io]`. HKDF explicitly enables its additive `zeroize` feature.
The patch manifest records modified/added files and current hashes.

The patches own named digest output, HMAC pad/inner output, HKDF block/ignored
PRK, and Ed25519 seed/nonce/scalar scratch slots. Guards wipe their current owned
bytes on scope exit and unwind when the `zeroize` feature is enabled. Public
returned outputs, algorithms, signature bytes and Scalar's Copy/Clone contract
are preserved. The app separately guards its original returned PRK slot.

This is not a claim that all historical stack moves, arithmetic backend limbs,
radix digits, registers, OS/provider copies or abort paths are erased. Feature
OFF does not provide the new cleanup contract. Existing memory warnings, raw
exit 99, constant-time and memory approval gates are preserved.

For rollout/rollback and validation, see
`hardening/secret-copies-20261108/implementation/dependency-scopes.md` in the
repository and the implementation report in `protocol_rust`.
