# Public-instance lattice cost review of Spiral-KEM OPT2

**Review question.** Can the published generic-LWE work estimates be reproduced for the equations the default implementation actually exposes? At public revision `eb4d613f9a038b6c065b44e1784a9aade186a292`, the answer is yes for the tested models. All 11 Spiral rows reproduced in the pinned estimator, including the result with no finite cost. All 11 comparison rows also reproduced. An independent calculation recovered the primal uSVP dimensions and costs for both profiles. The work estimates are conditional on a generic-LWE model of structured data. The review did not identify a new critical structural defect. The actual cost of exploiting the structure or an observable implementation response remains open. [Machine-readable comparison](../../results/lattice_cost_review/comparison.json) · [Fresh raw outputs](../../results/lattice_cost_review/sage-replay.zip)

## What is public in the default implementation?

| Item | What the code supplies | Treatment in the estimates |
| --- | --- | --- |
| Ring and module | R = F₃₃₂₉[x]/(x²⁵⁶+1), rank 2. The public 32-byte seed ρ deterministically expands four matrix polynomials. Sixteen-bit candidates below 63,251 are accepted before reduction mod 3,329. | Ring degree 256 and scalar secret dimension 512. A single seed selects the entire matrix. Its 512×512 scalar entries have signed, shifted block relations. |
| Key-generation samples | Public key (ρ,t) with t = As+e, where s and e each contain two polynomials. Separate labels expand one 32-byte secret seed σ. | The 512 coefficients of t give 512 scalar equations about the **same s**. Inputs are n=512, q=3329, m=512 and Xs=Xe=CBD(1). Treating this as generic LWE discards block structure and seed dependence. |
| Sampling law | For η=1 the sampler subtracts the low bits of successive XOF bytes, then reduces mod q. In the centered lift 3328 means −1. Under independent fair bits the weights at −1,0,+1 are 1/4,1/2,1/4 with variance 1/2. | The tool models independent centered binomials. For fixed SHAKE the s,e pair lies in an image of at most 2²⁵⁶ seeds. The same qualification applies to the encryption-side seed. |
| Ciphertext | u=Aᵀr+e₁, v=tᵀr+e₂+Encode(m). An honest 32-byte m and the canonical public-key hash determine the 32-byte coin seed. Distinct labels derive r,e₁,e₂. | u gives a second mapping with n=m_samples=512, this time about **r**. Aᵀ transposes polynomial blocks. The t and u equations cannot be pooled as 1,024 same-secret samples. The 256 coefficients of v carry information coupled to t,r,m,e₂. They were omitted from these estimates. |
| Transport and decoding | The two bit centers are 0 and 1664. Residues 833…2496 decode to one. SKW1 losslessly packs canonical coefficients into 12 bits, giving 808-byte public keys and 1,160-byte ciphertexts. Legacy lengths are 1,109 and 1,589 bytes. | No extra compression noise. There is no estimator input for message encoding, v, the key derivation function or reencryption. |
| CBD3 comparison | The archived comparison inputs use n=m_samples=512, q=3329 and Xs=Xe=CBD(3), with variance 3/2. The historical driver checked equality with the tool's Kyber512 public-key parameter object after aligning its tag. | Only the scalar public-key problem is compared. Standard ML-KEM includes its own sampling, ciphertext compression, encoding, transform and security analysis. |

For a polynomial a, the scalar entry of its multiplication block at (i,j) is a[i−j] if i≥j and −a[256+i−j] otherwise. With one fixed public synthetic fixture, direct scalar sums matched every coefficient of t (512), u (512) and v (256) from current OPT2. This establishes the mapping on that fixture. The ring identity derives the general formula. The old driver pinned historical v0.3.1 source SHA-256 `898e540b4aded14e3710b591c6aa03a44bf5774c1d591f630e488b041655fd6c`. The tested current OPT2 source has SHA-256 `74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118`. [Python source](spiral_kem_toy_v031_opt2.py) · [Mathematical specification §§3–7](../../originals/spiral_kem_v03_math_spec.md) · [Compact format](COMPACT_WIRE_SPEC.md)

## Reproduction and differences

The unit in the next table is log₂ of the tool's `rop` field. “Re-run” is fresh Sage output rounded to the six places used by the historical CSV. For the six-candidate archive, A has the same scalar inputs as Spiral and C has the same scalar inputs as the CBD3 reference. Those earlier jobs use the same estimator implementation. They are a consistency check across runs. The independent GSA calculation is described below.

| Cost model | Method | Spiral archived | Spiral re-run | CBD3 re-run | Check |
| --- | --- | ---: | ---: | ---: | --- |
| MATZOV classical | primal uSVP | 126.823073 | 126.823073 | 143.771733 | Matches, independent GSA check |
| MATZOV classical | primal BDD | 123.537624 | 123.537624 | 140.199473 | Matches |
| MATZOV classical | primal BDD hybrid | 123.563066 | 123.563066 | 140.208243 | Matches |
| MATZOV classical | primal BDD MITM hybrid | 174.077792 | 174.077792 | 262.070429 | Matches |
| MATZOV classical | plain dual | 131.571253 | 131.571253 | 149.884251 | Cost matches, shape label differs |
| MATZOV classical | dual hybrid | 120.875640 | 120.875640 | 139.656041 | Cost matches, shape label differs |
| Separate algorithm in classical batch | coded BKW | 154.190230 | 154.190230 | 178.760167 | Cost matches, shape label differs |
| Separate algorithm in classical batch | Arora–GB | ∞ | ∞ | ∞ | Completed, no finite estimate. Shape label differs. |
| Core-SVP classical | primal uSVP | 100.740000 | 100.740000 | 118.552000 | Matches, independent GSA check |
| Core-SVP classical | dual hybrid | 97.901991 | 97.901991 | 115.509894 | Cost matches, shape label differs |
| Core-SVP quantum | primal uSVP only | 91.425000 | 91.425000 | 107.590000 | Matches, independent GSA check |

**Within-model interpretation.** Of the six selected MATZOV-classical lattice rows the smallest Spiral work exponent was 120.875640 (dual hybrid). Of the two classical Core-SVP rows the smaller was 97.901991 (dual hybrid). The single quantum uSVP row provides a sensitivity calculation for a different reduction price. These values cannot be combined into a security interval. Finite versus infinite refers to the return of the chosen model. No actual key recovery, attack success rate, conventional security level or IND-CCA reduction was measured.

**Archive metadata discrepancy.** The primary driver wrote `shape_model=GSA` for every job. The six-candidate driver wrote `not applicable / algorithm specific` for plain dual, dual hybrid (both prices), BKW and Arora–GB. These five rows per profile differ in metadata. Only the primal calls actually receive the GSA option. Both historical labels and the fresh label are retained for every row in the JSON.

**Precision and coverage.** All fresh `log2_metrics` dictionaries match the main archive's stored metrics. Where present, β, lattice dimension d, m, N, mem and the checked hybrid search parameters also agree. The original text prints some mantissas at lower precision. For example, evaluating the printed classical Core-SVP dual-hybrid expression independently gives 97.9019910310 versus the stored 97.9019910457. This rounds to the same published value. The comparison retains the per-row values and treats a raw-text difference above 0.0000005 in log₂ units as a discrepancy. There were 20 finite results, two infinite results and zero timeouts across the two profiles. Estimator elapsed times are recorded for provenance only. [Historical CSV, JSON, text logs and runner](../../archives/research/Spiral_v031_n256_eta1_attack_costs.zip) · [Six-candidate records](../../archives/research/Spiral_KEM_six_candidates_results.zip)

## What each estimate prices

| Family | Model used in this run | Source |
| --- | --- | --- |
| Primal uSVP | Small-secret embedding with GSA basis lengths and an estimated BKZ success condition. The classical and quantum Core-SVP work exponents use 0.292β and 0.265β. The selected MATZOV list-decoding model also prices dimension-dependent overhead. | [Alkim et al., USENIX 2016](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/alkim) · [Official primal documentation at the measured commit](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/docs/algorithms/lwe-primal.rst) |
| Primal BDD and hybrid | BKZ preprocessing followed by decoding. The driver selects the hybrid and its MITM/Babai variant separately. Guessing probabilities, repetitions and lattice shape are heuristic. | [Wunderer, hybrid analysis](https://doi.org/10.1515/jmc-2016-0044) · [Upstream primal formulas and bibliography, including Liu–Nguyen and Howgrave-Graham](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/estimator/lwe_primal.py) |
| Plain dual and dual hybrid | Plain dual prices a short-vector distinguisher. The public name `LWE.dual_hybrid` in this revision aliases the **MATZOV** implementation. Its reduction price changes between the MATZOV and Core-SVP runs. The module also exposes an Espitau–Joux–Kharchenko-style variant under a similar name. | [MATZOV report](https://doi.org/10.5281/zenodo.6412487) · [Espitau, Joux and Kharchenko](https://eprint.iacr.org/2020/515) · [Upstream alias](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/estimator/lwe.py) · [Official dual documentation](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/docs/algorithms/lwe-dual.rst) |
| Coded BKW and Arora–GB | The driver calls these without a BKZ reduction price. BKW internally amplifies its inputs with a changed error model. Arora–GB returns no finite work here. | [Coded BKW](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/docs/algorithms/lwe-bkw.rst) · [Algebraic estimation](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/docs/algorithms/gb.rst) |

**Independent numerical path.** A standard-library implementation enumerates integer β and embedding dimension d against the published GSA inequality for the equal-noise profiles. It uses the first feasible d for each β since all three prices are nondecreasing in d there. Spiral gives β=345 and d=928, CBD3 gives β=406 and d=998. Inserting these into the two Core-SVP price functions and the classical list-decoding price reproduces all six reported primal uSVP exponents. For other families the independent checker evaluates the raw work expressions and compares the two historical campaigns and the fresh Sage run. This supplies arithmetic and reproducibility checks. It does not independently validate the dual or decoding heuristics themselves. [Independent checker](review_lwe_costs.py) · [Pinned reduction prices](https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/estimator/reduction.py)

**Resources and success.** For Spiral, plain dual reports log₂ mem **84.040477** in elements mod q, m=472 out of 512. Coded BKW reports log₂ mem **132.879530** in its own table-size model and an internal sample count around 2.73×10⁴² after amplification. The headline MATZOV dual-hybrid result reports log₂ N **67.709636** internal vectors and m=512, with total memory unspecified. Missing mem is unknown. No conversion to bytes, machines, latency, energy or dollars was validated. The Core-SVP quantum uSVP price includes no end-to-end logical-qubit, circuit-depth, error-correction or QRAM budget. Success probabilities and advantages follow individual estimator defaults and are not normalized across families. The plaintext protocol, optimized code, and a device's physical time do not enter these work factors.

## Unpriced structure and oracle boundaries

| Surface | Verified boundary | Remaining uncertainty |
| --- | --- | --- |
| Ring, module, seeds | x²⁵⁶+1 is the 512th cyclotomic polynomial. Since 3329 ≡ 257 mod 512 has multiplicative order 2, it splits modulo 3329 into 128 irreducible quadratics. The coefficient blocks share shifts and signs. The old public spiral transform was removed in v0.3. | The estimator does not price additional structure-aware algorithms, CRT projections with their induced error, or correlations from fixed SHAKE. Factorization alone supplies no work estimate. Splitting into factors does not justify treating projected errors as independent small noise. |
| Public ciphertext and multiple targets | The generic input covers one key or the u part of one ciphertext; v, the deterministic coins, repeated messages, and cross-target preprocessing are outside the input. | No quantitative bound for joint PK/CT information, many sessions/keys, chosen inputs or time–memory tradeoffs. |
| KEM API | Normal Python decapsulation rejects malformed encodings and returns 32 bytes for canonical inputs. A failed reencryption selects a deterministic fallback bound to z, the public-key hash and ciphertext hash. The explicit `SpiralKEMTestHarness` exposes the validity flag; the regular Python key can be reused by its caller. In C, `sp_decaps_once` claims the key before parsing, distinguishes input/reuse errors, and selects the fallback on a canonical mismatch. Rust FFI consumes the key handle. | Public parse errors, timing and other observable behavior are outside the estimator. The implementation can compute an internal validity bit. Its existence alone does not establish a remote validity oracle. |
| Authenticated channel | Server decapsulates a fixed-size ciphertext and checks the client's transcript-bound Finished before sending its Finished. Parsing, one-use state, TLS and peer-visible handshake success or closure constrain the actual interface. | An IND-CCA game gives the adversary decapsulation results on permitted queries and excludes querying the challenge ciphertext after challenge. The peer sees protocol outcomes instead of that game interface. Error/timing distinguishability, faults, leakage and a proof for the concrete reencryption/fallback transform need their own evidence. The existing 64-byte receive timing study covers a record path. |
| Correctness versus hardness | The key-weight study tested a sufficient decoding condition. | Its statistical confidence limit does not measure hardness; conversely these work factors do not bound decryption failures. |

A security grade would require more than these single-instance heuristic prices. The immediate external review questions are whether the generic mapping adequately covers the structured public instance, and what formal assumptions and losses the concrete transform incurs with its seeded coins, decryption errors and oracle interface. The current evidence gives no basis for parity with ML-KEM-512. [C KEM](../../native_research/spiral_native.c) · [Rust FFI](../../protocol_rust/src/ffi.rs) · [Rust handshake](../../protocol_rust/src/handshake.rs) · [Key-weight evidence](KEY_WEIGHT.md) · [Standard ML-KEM specification](https://doi.org/10.6028/NIST.FIPS.203)

## Evidence and replay

Upstream lattice-estimator commit `e4333d9bf9ef42fd8a29651b0c559fba7ce0d834`, Git tree `947f64fd61ff83273908827cd21669da9f100b87`. All 63 vendored paths and contents matched the official Git object. For the fresh run, 386 installed package names, versions and builds and the SHA-256 of every downloaded package matched the archived conda-forge manifest. The runtime was SageMath 10.8 with Python 3.14.8 on x86-64 Linux. The driver SHA-256 is `b99d141c09e857fc497101313acd544fa050139d5d4d689fc4af553aba361b26`. Explicit package URLs/digests, the two historical drivers and their raw results are in the original ZIPs. The new ZIP contains the controller output, actual per-job commands/metadata, raw TXT/JSON, run manifest, results and provenance. [Official estimator revision](https://github.com/malb/lattice-estimator/tree/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834) · [Fresh job records](../../results/lattice_cost_review/sage-replay.zip)

**Offline verification** from the repository or extracted review-bundle root requires Python 3.10+.

```bash
python3 -B code/opt2/review_lwe_costs.py > /tmp/spiral-reviewed-costs.json
diff -u results/lattice_cost_review/comparison.json /tmp/spiral-reviewed-costs.json
```

**Fresh model run** on a compatible x86-64-v4 Linux host with micromamba (2.0.5 was used here). The explicit file restores the recorded builds. Run from the repository or extracted review-bundle root.

```bash
work=$(mktemp -d)
unzip -q archives/research/Spiral_v031_n256_eta1_attack_costs.zip -d "$work"
cd "$work/spiral-v031-cost-assessment"
micromamba create --yes --prefix "$work/env" --file environment-linux-64.explicit.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 micromamba run --prefix "$work/env" \
  python run_estimates.py --jobs 2 --timeout 300 --out "$work/fresh"
```

Inspect `$work/fresh/raw/` and `$work/fresh/results.json`. Each job starts from the public scalar parameters. No target keys, ciphertext oracle, or attack execution is used. The original archives and their upstream license notices are preserved.
