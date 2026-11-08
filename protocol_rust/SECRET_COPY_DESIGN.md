# Zeroization design for HMAC/HKDF and signing temporary secret copies

At baseline source `47c80c75cc93934836b2893905752fb3f13a0c23`, dependency-local outputs and
nonce lifetimes were investigated and three alternatives compared. This deliverable is a design and type-compilation
comparison, not a zeroization patch or a declaration that all item2 is complete.

| Alternative | Scope and assessment |
|---|---|
| 1. Retain caller-output cleanup | Can narrow app-owned output error paths, but dependency-internal copies remain |
| 2. Dependency-internal lifetime guards | **Recommended**. Own/clean temporary buffers registered by generating functions. Preserve existing APIs/wire |
| 3. Separate provider process | Consider when long-term-key isolation is the priority. Provider-internal zeroization contracts and IPC operations still needed |

The recommended first scope improves `digest` fixed-output temporaries, HMAC pads/inner hashes, and HKDF output/prev.
Then handle named ownership slots for seed digests, scalar bytes, and signing nonces
in a separate change. Scalar backends, previous moves, and register copies
are excluded from these phase1 guarantees.

- [Design summary](../hardening/secret-copies-20261108/hardening.md)
- [APIs, cleanup scope, validation, and work packages](../hardening/secret-copies-20261108/proposals/secret-scratch-ownership.md)
- [Structured alternatives comparison](../hardening/secret-copies-20261108/hardening.json)
- [Dependency provenance/checksum verification](../hardening/secret-copies-20261108/evidence/source-manifest.json)
- [Output-type compilation comparison](../hardening/secret-copies-20261108/evidence/api-probe-result.json)

HMAC/HKDF output-argument APIs alone do not erase internal hash outputs. Some Array types under current features
were also confirmed not to satisfy Zeroize bounds, requiring private ownership-guard
slice cleanup or verified feature propagation. This compilation comparison does not measure actual zeroization instructions or
performance.

Retain high-level `SigningKey::try_sign`, opaque ownership, close serialization, strict verification policy, and
existing wire/signature bytes. Rewriting hash/nonce formulas or adding public hazmat
APIs is excluded. Original warnings/exit99 and strict memory gates remain.

After an actual patch, RFC/independent ring comparisons, functional/TLS tests, optimized zeroization instructions, and ARM/x86-64 diagnostics
must be rechecked. Currently `constant_time_approved=false`,
`production_memory_passed=false`.
