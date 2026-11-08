# HMAC, HKDF, and signing-state cleanup improvements · 2026-11-08

Migration to stable RustCrypto versions enables zeroization of key-dependent hash state and block buffers.
**This expands cleanup of owned state; it does not establish zeroization of all temporary outputs,
nonces, or copies, or completion of all of item 2.**

Measured code: `fe52b62a146850927bcc62c09395adac3fcaafb2`.
[Original evidence, hashes, and re-review records](evidence/secret_state_20261108/README.md) are preserved.
The earlier [receive record](RECEIVE_SECRET.md) remains a result for previous dependencies/executables.

The additionally submitted [OCI/WSL functional regression](evidence/secret_state_platforms_20261108/README.md)
passed on both platforms at merge commit `fcf7ff07ecba260f6b446baa7f1efd55bbe11ec2`.

## Changes and zeroization contracts

| Dependency | Previous → Current | Actual improvement |
|---|---|---|
| sha2 | 0.10.9 → **0.11.1**, `zeroize` | SHA-256/512 state and block_len cleanup |
| hmac | 0.12.1 → **0.13.0**, `zeroize` | Recursive Drop of inner/outer SHA cores and buffers |
| hkdf | 0.12.4 → **0.13.0** | Drop cleanup of owned/cloned HMAC state |
| digest / block-buffer | 0.11.3 / 0.12.1 on secret paths | Buffered-byte/position cleanup and zeroization trait contracts |
| ed25519-dalek | 2.2.0 → **3.0.0**, `zeroize` | Uses the same SHA2 0.11.1 to clean seed-expansion/nonce-hash hashers |
| curve25519-dalek | 4.1.3 → **5.0.0** | dalek3 dependency. Not counted as improved nonce Scalar zeroization |

The four directly selected stable versions are pinned exactly; both lockfiles were updated together.
Built with Rust1.99.1. sha2 0.10 remains in public source-hash builds and fuzzing aggregation.
The secret key schedule and dalek signing hasher use **the same sha2 0.11.1** with zeroization enabled.
Cryptographic operations were not reimplemented, the wire format was not changed, and the high-level signing API is retained.

dalek3's `zeroize` alone does not enable SHA2 features. Feature unification through the direct sha2 dependency
and compiler artifacts were checked. SHA2 has an empty Drop even with the feature OFF, so
`needs_drop=true` alone does not establish feature status. Normal release builds also have
`Sha256/Sha512: ZeroizeOnDrop` compile conditions. This wrapper trait
also verifies core/buffer zeroization contracts. Under identical conditions in a separate synthetic crate, OFF
exited101 with `E0277`, while ON exited0.

The actual optimized executable links zero writes in HKDF/HMAC's SHA256VarCore Drop (`block_api.rs:97`,
relative address `0xc5c6a`) and dalek signing's SHA512VarCore Drop (`block_api.rs:222`,
`0xa25ae`) as 0 writes. Addresses apply only to that binary. DWARF, complete
instructions for selected functions, and binary hashes are preserved; these do not establish zeroization of all outputs/registers.

In the app, the array checking the authentication-key file's 33rd byte was changed to `Zeroizing<[u8;1]>`,
so it is disposed of even on length/read errors. The seed was already zeroized on return by `Secret`;
it is now dropped immediately after SigningKey construction to shorten retention of the original. Ownership, mutex, and serialization of in-progress
signing with close are retained. `try_sign` failures propagate as `Error::Crypto`.
Seed-export, arbitrary-signing, and hazmat APIs are not exposed.

## Validation results

| Check | Actual result |
|---|---|
| Normal Rust and pinned-nightly ASan/leak checks | **70 passed** each, with 5 ignored x86-64 instrumentation-only tests separate |
| Functional CI | Python85, diagnostics20, C9, documentation6, actualTLS35 passed; release build succeeded |
| RFC4231 | SHA256/512 case1/6 each, matching independent constants for short and 131-byte keys |
| RFC5869 | SHA256 case1/3, matching PRK, 42-byte OKM, and from_prk |
| Independent ring Ed25519 comparison | 4 public seeds × 10 lengths = **40 pairs**, matching public-key/signature bytes and verification on both sides |
| Tampering/revocation | Both reject 40 message cases and 64 per-signature-byte cases; signing rejected after owner close |
| KDF/transmission/signing Memcheck | 0 branch/address warnings; original exit99 due to one existing48-byte item |
| Actual receive-buffer disposal Memcheck | 4 tests/216 observations passed; exit99 due to one existing48-byte item |
| Actual receive tracing | Public/key and prefix78 pairs + 2 positive controls completed, all mapped to instruction addresses |
| ASan record fuzzing/independent Python recheck | 2,435 execution units, **633/633 match** (95 accepted/538 rejected) |

Signature lengths are0/1/63/64/65/127/128/129/1,024/16,384. dalek/curve are major
version changes. Normal vectors, tampering samples, and pin/TLS regression do not establish identical acceptance policies
for every noncanonical signature or weak public key.

KDF/transmission/signing taint retains the existing contract declassifying only wire Finished, ciphertext, public keys, and signatures.
No declassification or suppression was added to actual receive tracing.
Authentication decisions64, result propagation64, and CLOSE-reason checks6 retain **134 warning contexts**;
actual receive has0 unclassified warnings. This is not a vulnerability count; the public-result contract is unchanged from the earlier record.

Among158 receive runs, original exits were99 for156 and0 for2. The existing48-byte item was observed in155
runs. Its absence in a few controls does not establish resolution of the original issue.
Overall memory/constant-time verdicts remain incomplete; the WSL AES-GCM failure and strict CI gates remain.

The ASan/taint/fuzzing results above were measured on local Linux x86-64 with stable1.99.1 and nightly-2026-11-07.
ASan does not instrument all prebuilt std or native C/OpenSSL code.

### OCI/WSL functional regression

Functional checks on both environments were additionally confirmed using pinned source with updated dependencies.

| Item | OCI ARM | WSL2 x86-64 |
|---|---|---|
| Python/diagnostics/C | 85/20/9 passed | 85/20/9 passed |
| Rust unit/documentation | 70/6 passed | 70/6 passed |
| ignored instrumentation targets | 0 | 5, excluded from passes |
| release/actual TLS | Build succeeded/35 passed | Build succeeded/35 passed |
| Pinned source/tools | Same fcf7ff0/Rust/Cargo1.99.1 | Same fcf7ff0/Rust/Cargo1.99.1 |

Each original archive manifest was compared against21 files; actual execution counts, errors, and exit codes were
reviewed. Pinned-launcher records verifying603 source files and runner/Cargo.lock hashes also match.
Old-source materials and an empty WSL archive were excluded from this verdict and stored separately.

Thus **this functional regression on both target platforms after dependency updates is complete**. These results do not
establish renewed completion of ASan, fuzzing, secret-branch, or overall memory checks on
both platforms. Actual GitHub runner results are also separate from these user submissions.

## Remaining temporary secrets and follow-up criteria

This scope was checked in actual new-version source; it has not been established as an observable leakage vulnerability.

| State | Remaining scope |
|---|---|
| HMAC key pad/inner hash output | Ordinary local Arrays in `block_api.rs:56–68,84–92`, no explicit zeroization |
| Hash output for long HMAC keys | Ordinary output in `utils.rs`. Current PRK/Finished keys are32 bytes; long keys are covered separately by RFC tests |
| HKDF output/prev | `lib.rs:135–169`, ordinary output copies separate from state Drop |
| seed SHA512 output/scalar_bytes | dalek `signing.rs:866`, `hazmat.rs:86–93`; hasher cleanup does not erase outputs |
| Signing nonce/64-byte reduction input | dalek `signing.rs:924`, curve5 `scalar.rs:663–669`. Scalar has Copy/Clone/Zeroize but no zeroizing Drop |
| Previous stack/register/provider/OS retention | Type Drop and limited instruction checks do not guarantee complete zeroization |

Public challenge `k`, signature output `s`, and wire Finished are not classified the same as secret nonce `r`.
App raw PRK explicit zeroization and existing `Secret` disposal remain.
Public API callers cannot erase private local copies by accessing arbitrary addresses.

Further improvements require APIs providing explicit output/nonce ownership and zeroization, or reviewable dependency
changes. They must jointly satisfy actual-path source review, optimized zeroization instructions, RFC, independent signature/communication, and taint regressions.
App wrappers or tests reading freed memory do not substitute for these.
ARM instrumentation for the new features and service-key storage/permission/rotation/revocation/recovery policies remain outstanding.

## Optional reproduction

Commands assume the repository root in an environment with existing Rust1.99.1, C/OpenSSL, and pinned Python requirements installed.

```bash
cargo test --locked --manifest-path protocol_rust/Cargo.toml --lib
cargo test --locked --profile audit --manifest-path protocol_rust/Cargo.toml \
  --lib state_tests:: -- --test-threads=1 --nocapture
python3 ci/validate.py --output ci-results/secret-state-new
```

For the independent feature comparison, copy the evidence `probe/` to a fresh temporary folder and check with Cargo.
The OFF failure is intentional. For receive tracing, follow the [receive guide](RECEIVE_SECRET.md#optional-reproduction),
using a fresh executable and output path.
Existing records retain their original source and environment provenance.
