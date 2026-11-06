# Security Hardening Review: Spiral OPT2 Constant-Time Implementation and Secret Management

## Evidence Basis

We design the implementation boundary for item 2 using code that has completed tests for items 3 and 4. The latest test materials were
uploaded to the GitHub `spiral-opt2-protocol-v0.1` branch in commit `7c859d9`.
This document is a **design proposal** written afterward, not results from native implementation, performance, or constant-time validation.

I identified two key points: OPT2 secret operations depend on Python large integers and conditionals,
and the protocol also passes shared secrets and AEAD keys as Python `bytes`.
Replacing KEM multiplication alone therefore does not complete the secret-management boundary we wanted.
The recent failure to detect a difference in 24,000 timing diagnostics is also not evidence that this issue has been resolved.
Materials and hashes are in [context.md](context.md); detailed evidence and options are linked in the proposal below.

## Constraints

- Preserve baseline parameters n=256, k=2, q=3329, eta=1, key_bytes=32.
- Preserve SKW1, legacy internal hashing, and protocol v0.1 frames, labels, Finished, and key derivation outputs.
- Retain the Python reference implementation and existing results as comparison baselines.
- This is currently the design stage. Rust/Cargo were not found in this environment, and no new toolchain was installed or built.
- Independent evaluation of the cryptographic design remains incomplete. Implementation and validation progress does not establish independent cryptographic review.
- With no latency, memory, or supported CPU budget specified, we propose starting with correctness and observable validation on one platform, Linux x86_64.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
|---|---|---|---|---|
| Consolidate secret operations and lifetime ownership within one boundary | Python bigint and branches, SessionKeys transfer, reference release, limited timing diagnostics | 1. Stricter Python restrictions / 2. Native engine / 3. Separate-process engine | Recommend option 2, then reevaluate based on resource and validation results after initial implementation | [Secret ownership proposal](proposals/native-secret-boundary.md) |

Option 1, retaining the current structure, can reduce query and logging exposure with the least work.
However, this option cannot control erasure of Python objects or secret-dependent execution.
Option 3 separates keys from the Python process but adds costs for IPC, process supervision, and fault handling.

## Recommendation Summary

I recommend **option 2: a Rust native secret engine with opaque handles** as the first implementation target.
The key point is the API under which secrets are operated on and disposed of by one owner without being returned to Python, rather than the Rust name itself.
Include fixed-size arithmetic, secret state for KEM, KDF, Finished, and AEAD, and authentication key use within this boundary.

We should first validate this engine independently of the Python reference, then connect the protocol.
Even if an intermediate KEM port matches byte outputs, do not mark item 2 complete while session keys remain in Python.
If actual requirements include process memory separation, or the fault impact of a Python extension module is unacceptable,
prioritize option 3. A memory-safe language also does not automatically guarantee constant time or reliable erasure of every copy.

## Next Decisions

For the next implementation, I recommend starting with option 2's first stage: **a fixed-size arithmetic and KEM compatibility port**.
Review and pin toolchain and cryptographic library versions and licenses, verify minimal operation, then expand to an opaque session boundary.
Do not change executable code or the existing protocol before an option is selected and implementation is instructed.
Detailed APIs, failure, cancellation, and disposal rules, and staged acceptance criteria are in the [proposal](proposals/native-secret-boundary.md).
