# Security Hardening Review: Spiral Temporary Secret Copies

This design addresses the remaining tasks in item 2: HMAC/HKDF temporary outputs and Ed25519 nonce copies.
I directly inspected pinned dependency sources and application calls. The Drop cleanup of key owners
we already have and the cleanup of outputs/nonces created briefly inside functions are separate contracts.
This document designs explicit ownership for the latter; it declares neither a new disclosure vulnerability nor completed remediation.

The subsequent implementation selected option 2 and strengthened named owned slots. Implementation code is
`7f26fed5b8176ddd009d44264fb5e9ab08fb8d31`; scope and validation criteria are linked in the [implementation plan](implementation/dependency-scopes.md).
We checked local functionality, the focused matrix, ASan, standalone collection, and selected
optimized erasure instructions. Subsequent OCI ARM/WSL submissions using the same source each also
confirmed collection of 70 basic tests and 160 instrumented runs. Backend/past copies, registers, constant-time and
full memory approval remain separate.

## Evidence Basis

The baseline is `47c80c75cc93934836b2893905752fb3f13a0c23`. We pinned 13 Git inputs and
9 dependency archives, and compared 170 source files in them against the archives.
We retain the [source list](evidence/source-manifest.json) and [input collection identification](evidence/input-inventory.json).
The previous OCI ARM collection of 70 basic tests and 160 Memcheck runs is observation of existing paths.
It does not substitute for testing a new cleanup patch or for full constant-time/memory approval.

The synthetic [API compilation control](evidence/api-probe-result.json) under the current feature configuration
confirmed that owning guards for byte slices and guards for Scalar are feasible at the type level.
In contrast, the Zeroize bound on the output Array itself was rejected with two E0277 errors. Type controls
do not measure actual erasure instructions or performance; they justify avoiding an unconditional Zeroizing<Array> assumption in the design.

## Constraints

We preserve wire v0.1, KEM parameters, Ed25519 deterministic signature bytes, and strict verification policy.
High-level SigningKey::try_sign, opaque owners, and close/poison serialization are also preserved.
We add neither a new public hazmat/nonce-export API nor custom cryptographic algorithms.
No performance or memory budget was specified, so we assumed balanced incremental changes. Performance effects have not yet been measured.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
|---|---|---|---|---|
| Assign erasure responsibility to the layer creating temporary secrets | Source review of hash/HMAC/HKDF outputs, signing nonces, and backend copies; API type controls | 1. Retain caller output cleanup / 2. Dependency-internal lifetime guards / 3. Separate provider process | Conditional option 2: Incrementally improve the specified temporaries first | [Detailed design](proposals/secret-scratch-ownership.md) |

## Recommendation Summary

I recommend **option 2, dependency-internal lifetime guards**. Applications cannot access private local outputs, so
assigning cleanup responsibility to the function creating the value fits the current boundary. digest full_res must
also be included; wrapping only HMAC/HKDF does not cover this path.
Handling the hash layer first and named signing temporaries next narrows the change scope and possible regression causes.

What we aim to guarantee with this option is cleanup of registered owning slots on normal return, errors, and unwind.
Scalar Copy/Clone, backend scratch, and complete erasure of past move copies/registers are separate matters.
Even after cleaning the specified slots, we will not mark all nonce copies erased or item 2 fully complete.
A separate process is useful when application/key isolation matters more, but it does not automatically prove this internal cleanup contract.

## Next Decisions

The [detailed design work packages](proposals/secret-scratch-ownership.md#implementation-work-packages)
describe dependency patch boundaries, additive APIs, feature propagation, validation, and rollback criteria.
The first implementation candidate is private temporary cleanup in digest → HMAC → HKDF. Fixing the entire signing backend
in one change or replacing the provider is outside the scope.
In the implementation following this design record, local dependency patches and both Cargo.lock files were connected together.
Existing diagnostic gates, original warnings, and the determination that overall approval remains incomplete are preserved.
