# Implementation Plan: Dependency-internal lifetime guards

## Selected Design And Constraints

The implementation applies the recommended dependency-scopes option from the design. Public APIs, wire format,
deterministic signature bytes, and verify_strict policy are preserved. The phase 1 guarantee covers the specified owning slots and
does not extend to backend limbs/radix, copies before moves, registers, or OS retention.

## Source Revision And Drift Check

The design input collection is `53d3287b300e4c39a5cee0347b1ff19710d1ce25575657418a874603246bf944`.
The latest default branch `31c0fe9` added only design documents after the design baseline `47c80c7`; before implementation,
we confirmed no differences in protocol Rust/C sources or the two manifests/locks.

## Affected Components

Under `third_party/rustcrypto/`, we retain archive-checksum-verified digest 0.11.3, hmac/hkdf 0.13.0,
ed25519-dalek 3.0.0, and curve25519-dalek 5.0.0. We connect the respective patch paths in the protocol and fuzz manifests,
respective patch paths in the protocol and fuzz manifests, both lockfiles, schedule raw PRK lifetime, and diagnostic source hash lists.

## Ordered Work Packages

- Hash phase: Clean digest full_res, HMAC pad/inner/long-key hash, and Simple/Reset pads.
- HKDF phase: Clean output/prev on replacement and final termination, ignored PRK, and expansion constructor unwind.
- Signing phase: Private owners for seed digest, scalar bytes/clamped values, from_hash output, r, and key_term.
- Application/provenance phase: Borrowed wipe guard for the original raw PRK slot, both Cargo patches/locks, and vendored source identification.
- Validation phase: Feature matrix, live-slot witnesses, RFC/ring, functional/TLS, ASan, taint, and optimized instruction inspection.

## Compatibility And Migration

Existing return APIs are preserved, so no optional new into API is added in this change.
Scalar public Copy/Clone and existing key owner/close serialization are also preserved. Local patches are
distinguished from crates.io releases; cache files are not edited and registry checksums are not impersonated.

## Tactical Protections During Migration

Secret/SigningKey/hash-state Drop and Poly1305 zeroize are preserved. The new hkdf/zeroize feature is
explicitly enabled. We do not pass checks through suppressions, automatic algorithm fallback, or reclassification of original warnings.

## Tests And Security Validation

We check RFC4231 SHA256/512 × four HMAC variants, RFC5869 and independent ring HKDF boundaries, RFC8032 and ring signatures
for 40 pairs, application N/label rejection, and live-slot cleanup on normal/error/unwind paths. Generic callback failures are
internal fault injection; the current pure try_sign callback always succeeds. We preserve runtime warnings and
exit99, and do not substitute taint warning count0 or needs_drop alone for cleanup evidence.

## Performance And Resource Benchmarks

We compare baseline and candidate KDF/signing processing times with public synthetic inputs on the same toolchain/CPU.
We record repetition counts, optimization conditions, and results, without arbitrarily granting operational latency/RSS budgets or
approval under actual service loads. Guards introduce no new IPC.

## Rollout And Rollback

We first validate on a bounded implementation branch with pinned sources. New measurements on actual OCI ARM/WSL
are not replaced by past measurements. On rollback, local source patches, both manifests/locks, and application calls are
reverted together, along with the cleanup-complete list. No wire/state data migration is needed.

## Acceptance Criteria

Criteria are 0 mismatches in public vectors, functional behavior, and signature bytes; guard-owned slot cleanup on normal/error/unwind paths;
erasure instructions in selected optimized binaries; complete local functional/taint collection; and preservation of original warnings.
New unclassified warnings, invalid access, and definite/indirect loss are investigated. Actual platform, full memory, and
constant-time approvals are recorded separately for each validation scope.

## Open Decisions

Complete backend scratch cleanup and operational key policy are separate tasks. If the full upstream dev suite or
unselected optional features cannot be run, the exact scope is recorded and not counted as passing.
