**How to Compare Spiral-KEM 0.3.1 and ML-KEM**

Written and checked: 2026-10-23. The first comparison targets original Spiral-KEM 0.3.1(A) and ML-KEM-512. They were selected because matching n, k, q makes structural comparison easier. Equivalent security levels were not assumed.

Spiral timings, attack costs, and trial counts are cited from the 2026-10-21 evaluation records. Timing environment: AMD EPYC 9V74, Linux, Python 3.12.14.

The comparison proceeds in three stages: compare structure and settings, check actual byte sizes, then evaluate performance and security under matched conditions. This document reports the first two stages.

**1. Comparison Table Currently Supported by Evidence**

| Item | Spiral-KEM original A | ML-KEM-512 | How to read |
|---|---|---|---|
| Purpose | Generate 32-byte shared key | Generate 32-byte shared key | Compares the same function. |
| Base structure | Module-LWE-style noisy linear equations | Based on Module-LWE | The core mathematical structures are close. |
| n, k, q | 256, 2, 3329 | 256, 2, 3329 | Dimensions and modulus match. |
| Small secret/error distributions | CBD(1) for all s,e,r,e1,e2 | CBD(3) for s,e,y; CBD(2) for e1,e2 | Matching dimensions do not establish equal attack costs or correctness. ML-KEM's y corresponds to Spiral's r. |
| Multiplication | Kronecker substitution: pack coefficients into large integers and multiply | NTT-domain operations | Different computation and representation methods. Changing multiplication methods alone does not create a new hard problem. |
| Public-key storage | 16 bits per coefficient, including a custom 53-byte header | 12 bits per NTT coefficient, 32-byte matrix seed | Public-key comparison can start with lossless bit packing. |
| Ciphertext storage | Stores u,v directly at 16 bits per coefficient | Compresses u to 10 bits and v to 4 bits | Standard ciphertext compression adds rounding error. |
| Normal shared-key derivation | Puts message, public-key hash, and ciphertext hash in custom SHAKE256 frames | Derives key and encryption randomness together from G(m ∥ H(ek)) | Different hash procedures require separate treatment of standards compatibility and security claims. |
| Decapsulation | Reencryption comparison and custom fallback-key return | Reencryption comparison and fallback-key return using J(z ∥ c) | Similar defensive principles do not make the complete transforms identical. |

The ML-KEM column is based on FIPS 203 §4.1–4.3, Algorithms 13–18, Tables 2–3.[1] The Spiral column was checked against actual functions in the supplied original source. No standards-conformance testing to classify security or independent cryptanalysis was performed.

The original explanation and `_base_matrix` comment state that public U·A·V spiral transforms were removed from the core in v0.3. Thus, the spiral structure of earlier ideas is not included among verified security distinctions of current 0.3.1. Differences visible in current code are the multiplication, error settings, sampling, serialization, and hash procedures in the table above.

**2. Wire Sizes Can Already Be Compared Numerically**

| Item | Spiral A actual format | Spiral A minus 53-byte header | ML-KEM-512 standard format |
|---|---:|---:|---:|
| Public key | 1,109 bytes | 1,056 bytes | 800 bytes |
| Ciphertext | 1,589 bytes | 1,536 bytes | 768 bytes |
| Shared key | 32 bytes | Not applicable | 32 bytes |

The 309-byte public-key difference consists of a custom 53-byte header and a 256-byte coefficient-storage difference. The 821-byte ciphertext difference consists of a 53-byte header and a 768-byte coefficient representation/compression difference. Neither scheme's figures include external transmission headers such as IP/TLS. Subtracting the header is arithmetic to explain size contributors, not the result of changing the actual protocol.

Spiral A's sizes were also checked in this comparison using the original serialize functions. Standard sizes were checked against FIPS 203 Table 3.[1] This evidence supports only the statement that “ML-KEM-512 has a smaller wire size under the current formats.”

**3. How Should the Six Candidates Be Mapped?**

| Spiral candidates | Structural comparator | Caution |
|---|---|---|
| A·B·C: k=2 | ML-KEM-512 | C matches the CBD widths for s,e,r, but differs for e1,e2. |
| D·E·F: k=3 | ML-KEM-768 | E matches n,k,q and all CBD widths. Compression, sampling byte procedures, hashes, and representations still differ. |

Original A can remain the baseline, with experimental candidate E, which also matches error widths, and ML-KEM-768 as a second comparison pair. E's actual public key/ciphertext sizes are 1,621/2,101 bytes; ML-KEM-768's standard format uses 1,184/1,088 bytes.[1] This mapping does not indicate equivalent security levels.

**4. Three Items Not Yet Ready for Side-by-Side Scoring**

| Item | Evidence currently available | How to complete the comparison |
|---|---|---|
| Execution time | Spiral A medians: key generation 1.952ms, encapsulation 2.958ms, decapsulation 4.096ms | Measure ML-KEM on the same hardware and record implementation version, language, optimization, warmups, repetitions, and measurement scope. Label Python versus optimized C as an implementation performance comparison. Do not generalize it into algorithmic speed superiority. |
| Attack costs | General LWE cost estimates for Spiral | Reevaluate using the same estimator version, cost model, attack list, and input assumptions. Do not directly equate NIST security categories with estimator log2 work. |
| Failure probability | 2,000 normal trials per candidate and mathematical bounds under ideal CBD/SHAKE model | Compare with matched distributions, compression errors, decoding, and probability assumptions. Do not judge higher correctness from a small bound or 0 observed failures alone. |

ML-KEM was not run and its attack costs were not newly calculated in this task. This comparison alone also does not establish whether integer-packing multiplication or NTT is faster. Official security-category explanations are in FIPS 203 §8.[1]

**5. If Choosing One Next Task**

A narrow research question could be: “What benefits does integer-packing multiplication provide in this research implementation?” Prepare an experiment comparing output agreement, time, and memory against exact NTT-based multiplication using the same Python, hardware, and polynomial inputs. This is a follow-up experiment not yet performed. Explain it separately from procedures establishing actual KEM security or standards compatibility.

This comparison table supports review of ① assumptions applying general LWE estimates, ② security analysis of the changed key-derivation and fallback-key procedures, and ③ implementation differences with research value.

**Evidence and Scope**

- [1] NIST, final FIPS 203 PDF (2024-08-13), especially §4–8 and Tables 2–3: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- Official publication and errata information: https://csrc.nist.gov/pubs/fips/203/final . The comparison uses the final PDF above; the page was checked for its notice of future corrections.
- Original Spiral source: `source/spiral_kem_toy_v031.py` in the existing `Spiral_KEM_six_candidates_results.zip`.
- Original SHA-256: `898e540b4aded14e3710b591c6aa03a44bf5774c1d591f630e488b041655fd6c`.
- Supporting functions: `keygen`, `_encrypt_message`, `_poly_mul`, `_small_poly`, `_uniform_poly`, `_coin_seed`, `_derive_valid_key`, `_decapsulate_core`, `serialize_public_key`, `serialize_ciphertext`.
- Numerical evidence for the six candidates: `profiles.json` and `results/comparison.json` in the same ZIP. B–F are experimental variants extending the original parameter checks.
- This task did not modify the original or existing evaluation records. A separate comparison explanation was written and original public-key/ciphertext lengths rechecked.
