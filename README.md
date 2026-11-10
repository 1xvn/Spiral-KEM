# Spiral KEM

Spiral KEM is an experimental key encapsulation mechanism and a research platform for studying lattice-style arithmetic, lossless wire encodings, authenticated channels, and secret-state ownership.

The current Python implementation is **v0.3.1 OPT2**. The repository also includes a C implementation, a Python TLS protocol, and a Rust/Tokio/rustls channel backed by the C KEM.

> **Research use only.** Spiral KEM has no established security level or IND-CCA proof. It is not ML-KEM and has not been approved for protecting real data. Functional tests, benchmarks, and fuzzing do not establish cryptographic security or constant-time execution.

## How the KEM works

The v0.3 family operates over $R_q = ℤ_q[x]/(x^n + 1)$. Its default research parameters are $n=256$, $k=2$, $q=3329$, $\eta=1$, and a 32-byte shared key.

- **Key generation:** expand a public matrix $\mathbf{A}$ from a seed, sample small secret/error vectors $\mathbf{s}$, $\mathbf{e}$, and publish $\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e}$ with the matrix seed.
- **Encapsulation:** sample a message, derive encryption randomness from that message and the public-key hash, and form $\mathbf{u} = \mathbf{A}^T \mathbf{r} + \mathbf{e}_1$ and $\mathbf{v} = \mathbf{t}^T \mathbf{r} + \mathbf{e}_2 + \text{Encode}(m)$
- **Decapsulation:** decode $\mathbf{v} - \mathbf{s}^T \mathbf{u}$, deterministically re-encrypt the recovered message, and compare canonical ciphertext encodings. Valid encodings that fail verification produce a deterministic fallback key; malformed inputs are rejected.

The project name comes from earlier experiments with public spiral transforms. Those transforms were removed from the v0.3 cryptographic core after algebraic analysis showed that the public invertible coordinate change could be eliminated. See the [mathematical specification](originals/spiral_kem_v03_math_spec.md).

## What OPT2 changes

OPT1 specializes the fixed $\eta = 1$ sampler. OPT2 uses `Struct` for byte conversion/integer packing and adds the **SKW1** lossless 12-bit transport format. It preserves coefficients, parameters, the legacy serialization API, and internal KEM hash inputs.

| Default profile | Legacy encoding | SKW1 compact encoding |
| --- | ---: | ---: |
| Public key | 1,109 bytes | 808 bytes |
| Ciphertext | 1,589 bytes | 1,160 bytes |
| Shared key | 32 bytes | 32 bytes |

The compact format has an 8-byte header. Both peers must select the compact API explicitly; it does not silently negotiate or guess encodings. See the [wire specification](code/opt2/COMPACT_WIRE_SPEC.md) and [implementation guide](code/opt2/README.md).

## Run the Python implementation

Python 3.10 or newer is required. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r code/opt2/requirements.txt
cd code/opt2
../../.venv/bin/python verify_equivalence.py
../../.venv/bin/python verify_opt2.py
../../.venv/bin/python compare_spiral_opt2_mlkem.py --rounds 3 --warmup 1
```

On Windows, use `.venv\Scripts\python.exe` in place of `.venv/bin/python`. The comparison dependency is pinned to `kyber-py==1.2.0`; the KEM itself uses the Python standard library. A short run is a functional smoke check, not performance evidence. Omit the round/warmup flags for the default 30 warmups and 300 measured exchanges.

The benchmark compares the baseline, OPT1, OPT2 compact API, and the educational Python ML-KEM-512 implementation in one process. Read the [benchmark methodology and results](code/opt2/RESULTS.md) before interpreting timings.

## Authenticated-channel implementations

[Python protocol v0.1](protocol_v01/README.md) combines TLS 1.3, an actual TLS exporter, a separate Ed25519 server pin, HKDF, Finished confirmation, directional ChaCha20-Poly1305 records, sequence limits, and authenticated closure.

[The Rust–C implementation](protocol_rust/README.md) uses Tokio and rustls with bounded workers for C KEM operations, opaque key ownership, bounded queues, cancellation/deadline handling, and explicit secret-buffer cleanup. It exercises Rust↔Python and Rust↔Rust traffic over actual loopback TLS connections. Server authentication does not supply application-level client authentication or authorization.

[Key operations](protocol_rust/KEY_OPERATIONS.md) and [encrypted backup/recovery](protocol_rust/KEY_RECOVERY.md) cover Linux private-file policies, key creation, cold rotation, external-fingerprint recovery, and bounded laboratory drills. They do not constitute a deployed service or vault integration.

## Repository map

| Directory | Contents |
| --- | --- |
| [`code/opt2/`](code/opt2/) | Baseline, OPT1, OPT2, equivalence checks, compact encoding, benchmarks |
| [`native_research/`](native_research/README.md) | C KEM, adversarial-input tests, fuzzing and memory diagnostics |
| [`protocol_v01/`](protocol_v01/README.md) | Python protocol, specification, vectors and TLS tests |
| [`protocol_rust/`](protocol_rust/README.md) | Rust–C channel, ownership model, key operations and validation |
| [`fuzzing/`](fuzzing/README.md) | Python coverage-guided fuzzing and saved regressions |
| [`hardening/`](hardening/) | Threat-boundary and secret-copy design analyses |
| [`downloads/`](downloads/) | Reproducible platform-validation bundles |
| [`ci/`](ci/README.md) | Functional CI and separate memory-diagnostic workflows |
| [`originals/`](originals/) | Earlier implementations, mathematical analysis and comparisons |
| [`archives/`](archives/) | Packaged research and benchmark materials |
| [`results/`](results/) | Recorded measurements and supporting artifacts |

## Validation and open research questions

The recorded functional suite includes Python protocol tests, C regressions, Rust unit/doc tests, key-operation/recovery tests, and real TLS scenarios. Platform evidence includes OCI ARM64 and WSL x86-64 runs. Parser/record fuzzing, lifecycle tests, ASan, Memcheck, and secret-flow diagnostics are documented alongside their exact scopes and limitations.

Use the [CI guide](ci/README.md), [Rust validation record](protocol_rust/VALIDATION.md), and [regression map](protocol_rust/REGRESSION_MAP.md) to distinguish individual historical runs from the current combined suite.

Open work includes independent cryptanalysis, independent validation and extension of the recorded attack-cost and decryption-failure estimates for the research parameters, constant-time assessment across supported targets, and complete secret-copy/lifecycle coverage. Cleanup observations for named buffers do not imply erasure of every compiler temporary, backend limb, register, TLS-provider copy, or OS copy. Original diagnostic failures remain relevant; a passing functional run does not override them.

## Usage terms

Original materials require separate permission under the [reserved-rights terms](LICENSE). Public access does not grant an open-source license. [Third-party components](THIRD_PARTY_NOTICES.md) retain their own licenses. Statutory quotation and other applicable legal rights are unaffected. Contact the repository owner through GitHub for permission requests.
