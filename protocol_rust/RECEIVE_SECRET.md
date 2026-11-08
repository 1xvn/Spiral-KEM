# Actual receive path and temporary secret state validation · 2026-11-08

Added key and nonce-prefix instrumentation to actual `Rx::decode`, and enabled the existing Poly1305 0.8.0
`zeroize` feature. Completed 78 receive functionality comparisons, 78 public baseline comparisons,
78 key/prefix taint traces, and 2 branch/address positive controls.
**This does not mark all of item 2, constant-time validation, or overall memory checking complete.**

The measured code commit is `832e996842b2d0c746dd7b65e388907207c5b72c`.
[Evidence and review record](evidence/receive_flow_20261108/README.md) retains original warnings,
executable/source hashes, linked commands, regression results, and dependency rationale together.

## Scope of public results

Record opening treats the following results as observable.

| Value | Scope |
|---|---|
| Header·length·role·sequence number·limits | Public inputs and state under existing wire/state rules |
| AEAD authentication decision | One success/failure bit from tag verification |
| Authenticated CLOSE reason check | One bit indicating whether the value is in the allowed range 0..2 |
| DATA plaintext·full CLOSE reason·keys·key derivation state | Not made public by this instrumentation |

The mere presence of branches returning the authentication result and propagating that result does not establish a vulnerability.
Conversely, this does not permit all receive branches. This contract does not
prove timing, cache, or address-access independence for the entire input.

Construct packets first with public synthetic keys; mark **a separately created 32-byte receive key and
4-byte prefix secret in Memcheck shadow before `Rx::new`**.
Valid DATA, modified tags, and authenticated CLOSE pass through the actual production decryption and discard paths.
Drop results without reading or serializing them; do not declassify keys, tags, results, or plaintext.
The receive check was not replaced with a send test that taints plaintext and then makes the ciphertext public.
Functional correctness is checked separately using defined public inputs.

## Observations

Use both roles and lengths 1·16·63·64·65·1,024·16,384. Modified tags at length
65 cover all 16 byte positions. The valid CLOSE reason is 0;
authenticated invalid reasons are 3 and 255.

| Input | Public / secret traces, each | Branch warning contexts in secret traces |
|---|---:|---|
| Valid DATA | 14 cases | Authentication decision 14 + result propagation 14 |
| Invalid tag | 44 cases | Authentication decision 44 + result propagation 44 |
| Invalid public header | 14 cases | 0 |
| Valid CLOSE | 2 cases | Authentication decision 2 + result propagation 2 + reason check 2 |
| Authenticated invalid CLOSE reason | 4 cases | Authentication decision 4 + result propagation 4 + reason check 4 |

The 78 public baseline comparisons had no branch/address warnings. Secret receive traces had
**134 warning contexts in total**. This is the sum of context counts across processes;
it does not mean 134 vulnerabilities. There were 0 unclassified receive warning contexts.
The branch and address positive controls each detected their intended warning.

In the pinned executable, the relative addresses below, actual conditional instructions, and DWARF inline locations
all matched. Obtained load bias from per-PID mappings and converted original runtime PCs to ELF
relative addresses. This mapping cannot be reused for addresses from other builds.

| ELF relative address | Instruction | Original location·candidate classification |
|---|---|---|
| `0x13c130` | `je` | `chacha20poly1305/src/cipher.rs:87`, authentication decision |
| `0x13033f` | `jne` | `Result::map_err`, `records.rs:215`, authentication result propagation |
| `0x130360` | `ja` | `records.rs:216`, CLOSE reason range check |

These classifications are explanatory candidates, not suppressions or a passing allowlist.
Unknown warnings remain unclassified. Also mapped the actual memory read instruction in the address positive control,
recording it separately from conditional instruction verification.

Original exit codes for all 158 Memcheck executions were **99**. 156 executions had
the existing std/libtest 48-byte item; that item was not observed in two secret DATA traces.
This difference does not establish resolution of the original warning.
Those two runs also exited 99 due to authentication-related warnings; all original logs are preserved.
`diagnostic_complete=true` and `instruction_mapping_complete=true` mean only that collection and mapping
are complete. Retain `constant_time_approved=false`, `production_memory_passed=false`,
and leave the existing WSL AES-GCM verdict and strict CI memory gate unchanged.

## Poly1305 state erasure

ChaCha20Poly1305 key-owner Drop already existed. For the separately created
Poly1305 authentication state, the existing version's optional `zeroize` feature was not enabled.
Added direct dependency `poly1305 = { version = "=0.8.0", features = ["zeroize"] }`
to unify the feature in the same package instance as AEAD. Package versions and checksums
in both lockfiles are unchanged from previous main.

| Evidence | Result |
|---|---|
| `needs_drop::<Poly1305>()` comparison using the same 0.8.0 rlib | Before false → after true |
| Normal·fuzzing dependency feature trees | Both enable `poly1305/zeroize` |
| Verified crate sources | Drop erases all x86 autodetect State and r/h/pad in soft State |
| Actual optimized decryption instructions | Poly1305 State Drop zeroize writes are linked |
| New default regression test | Checks that Poly1305 requires Drop cleanup |

This supplement enables cleanup for authentication state previously lacking erasure. It does not prove complete erasure of past stack copies,
registers, or all temporary outputs, or actual leakage from the previous state.

## Regression tests and remaining work

| Check | Actual result |
|---|---|
| Functional CI | Python 85·diagnostic adjudication 20·C 9·Rust unit 66·documentation 6·real TLS 35 passed |
| Ignored tests | 5 x86-64 taint-only tests, excluded from normal functionality pass counts |
| ASan receive functionality comparisons | 2 tests·78 inputs passed |
| Actual buffer disposal | Optimized and ASan: 4 tests·216 observations each passed |
| Same buffer tests under Memcheck | One 48-byte item, no additional usage errors, original exit 99 |
| ASan record fuzzing | 2,496 execution units, production path coverage verified |
| Independent Python recheck of saved inputs | 637/637 matched, 97 accepted·540 rejected |
| Existing CI memory adjudication tests | 7 passed, failures not converted to successes |

Performed November 8 on local Linux x86-64 with Rust 1.99.1. ASan and record fuzzing use
pinned nightly-2026-11-07. No claim is made that the same tests ran after the change on GitHub runners, OCI ARM, or WSL.
Existing evidence from both platforms remains results for the source
at that time.

Compared archive checksums for 9 pinned dependencies against the lockfiles, and verified the Rust sources and
Cargo.toml files used—76 in total—against archive contents. The inventory of temporary secrets follows.

| Path | Current evidence and unfinished scope |
|---|---|
| HMAC 0.12.1 | HmacCore has key-dependent inner/outer hash state and Clone. No Drop erases all of that state |
| HKDF 0.12.4 | HMAC state cloning and expand output/prev remain under review. Erasing caller outputs does not guarantee erasure of internal copies |
| SHA2 0.10.9 / digest 0.10.7 | No Drop guarantees erasure of all key-dependent hash state, block buffers, and outputs |
| Ed25519-dalek 2.2.0 | SigningKey/ExpandedSecretKey erasure features enabled. Do not cover local SHA-512 hash and intermediate state during seed expansion |
| ChaCha20 0.9.1 / ChaCha20Poly1305 0.10.1 | Existing key/core cleanup retained. No guarantee of cleanup for all past copies, providers, or registers |
| Poly1305 0.8.0 | State Drop enabled here. Separate CPU execution and verification of all copies remain |

The next implementation scope is to define lifetime policies for temporary HMAC/HKDF/SHA and signature state, and review validated
interfaces, alternative dependencies, and compatibility. This record does not rewrite cryptographic operations
or change package versions. ARM secret branch/address instrumentation,
and service-key storage, access permissions, rotation, disposal, and recovery policies must also be completed separately.

## Optional reproduction

For reproduction on Linux x86-64 with Rust
1.99.1, C/OpenSSL development tools, Valgrind, binutils, and matching libc debug symbols already
are installed on Linux x86-64, run the following from the repository root.

```bash
SPIRAL_RX_BUILD=$(mktemp)
cargo test --locked --profile audit --manifest-path protocol_rust/Cargo.toml \
  --lib --no-run --message-format=json-render-diagnostics > "$SPIRAL_RX_BUILD" &&
SPIRAL_RX_TESTS=$(python3 - "$SPIRAL_RX_BUILD" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
paths = [r['executable'] for r in rows if r.get('reason') == 'compiler-artifact'
         and r.get('target', {}).get('name') == 'spiral_protocol'
         and r.get('profile', {}).get('test') and r.get('executable')]
assert len(paths) == 1, paths
print(paths[0])
PY
) &&
python3 protocol_rust/diagnostics/receive_flow.py \
  --rust-tests "$SPIRAL_RX_TESTS" --valgrind "$(command -v valgrind)" \
  --output "$HOME/Spiral-receive-flow-new"
```

The output folder and adjacent `.tar.gz` must be new paths. Tools are not installed automatically, and original
evidence is not overwritten. Runner exit 0 means diagnostics completed, including original exit 99,
not constant-time or memory approval. Environments requiring a separate loader must specify both `--loader` and
`--library-path`. Do not run this x86-64 client-request ABI on ARM.
