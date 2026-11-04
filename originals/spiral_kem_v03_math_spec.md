# Spiral KEM v0.3 Mathematical Specification and Rationale for Changes

Written: 2026-10-20 (Korea time)
Reference code: `spiral_kem_toy_v03.py`, VERSION 0.3
Status: research implementation specification. Records only the scope in which mathematical simplification and correctness verification are complete.

## 1. Decisions in This Revision

The public spiral transform was removed from the core, simplifying it to `t = A s + e`. Existing v0.2 code is preserved in `legacy/` so the rationale for the change can be reproduced. The project retains the name Spiral KEM, but v0.3 cryptographic computations contain no spiral transform.

| Item | v0.2 | v0.3 | Rationale |
|---|---|---|---|
| Public matrix | B = U A V | A | Removable through a public invertible change of coordinates |
| Public key | (ρ,ω,t) | (ρ,t) | Transform seed ω is no longer needed |
| 1-bit decoding region | 833…2495 | 833…2496 | Circular distance to centers 0,1664 |
| SHAKE input | Focused on version and purpose | Version, full configuration, label length, and purpose | Prevent input reuse between profiles and ambiguity at label boundaries |
| Error analysis | Future work | Reproducible analysis using integer arithmetic provided | Separate algebraic bounds from the ideal probability model |
| Baseline small coefficient width | η=1 | η=1 | Not arbitrarily changed without attack-cost estimates |

This change is not an independent new security proof. In particular, lattice attack costs for η=1, IND-CCA security of the complete KEM, and the exact decryption failure probability of actual SHAKE-based distributions remain unverified. Documents and tests do not justify declaring it secure.

## 2. Mathematical Rationale for Removing the Public Spiral Transform

In v0.2, U,V are sign, monomial, and permutation matrices determined by public seed ω. The ring is Rq = Zq[x]/(xⁿ+1). `±xᵃ` is invertible, and for 1≤a<n, (±xᵃ)⁻¹ = ∓xⁿ⁻ᵃ. For a=0, the inverse is the constant with the same sign.

The existing public-key relation can be rewritten as follows.

$$
t=UAVs+e,
\qquad t'=U^{-1}t,
\quad s'=Vs,
\quad e'=U^{-1}e.
$$

Thus t′ = As′ + e′ exactly. Including the ciphertext, the following definitions hold.

$$
r'=U^Tr,\quad u'=V^{-T}u,\quad e_1'=V^{-T}e_1,
$$
$$
u'=A^Tr'+e_1',\qquad
v=t'^Tr'+e_2+\operatorname{Encode}(m),
$$
$$
v-s^Tu=v-s'^Tu',\qquad
e^Tr+e_2-s^Te_1=e'^Tr'+e_2-s'^Te_1'.
$$

Here V⁻ᵀ=(V⁻¹)ᵀ. U,V and their inverses can be computed from public information. When polynomial coefficients are expanded in centered representation, this transform changes only coefficient signs and positions, preserving the multiset of absolute values and all ℓp norms. It also preserves the distribution in the ideal independent symmetric small-coefficient model. Once s′ is found, recover s=V⁻¹s′.

**Scope of the conclusion:** There is no evidence that the public spiral layer adds independent difficulty to this algebraic core. However, these equations alone do not prove security equivalence of the two complete versions, including actual seeds, hashes, and reencryption checks. Nor is this a recovery of the baseline secret key.

## 3. Baseline Profile and Three Algorithms

The baseline parameters are (n,k,q,η,key_bytes)=(256,2,3329,1,32). Only explicit LAB mode permits n∈{8,16,32,64,128,256}; all other parameters remain fixed. The length of m is n/8 bytes. The small message space in reduced modes is a target for educational exhaustive search.

- Ring: Rq = Zq[x]/(xⁿ+1), with coefficients stored as integers 0…q−1.
- A∈Rqᵏˣᵏ, s,e,r,e₁,t,u∈Rqᵏ, e₂,v∈Rq.
- Public key pk=(ρ,t), secret key sk=(s,pk,z), ciphertext c=(u,v).
- ρ,σ,z are each 32 bytes, and σ is the temporary secret seed used during key generation.

**KeyGen**: Generate ρ,σ separately using system randomness. Compute A=ExpandA(ρ), s=SmallVec(σ,`key/s`), e=SmallVec(σ,`key/e`), and set t=As+e. Generate z as a fresh 32-byte system random value and return pk,sk. Generated e,σ are not retained in secret key fields. Secure erasure from Python memory is not guaranteed.

**Encaps**: Validate the public key format, then generate m as n/8 bytes of system randomness. Compute coins using the formula below and generate r,e₁,e₂ with distinct labels. Compute u=Aᵀr+e₁, v=tᵀr+e₂+Encode(m), c=(u,v), and return c,K.

**Decaps**: Validate ciphertext and secret key formats. Compute m′=Decode(v−sᵀu), then deterministically reencrypt m′ to obtain c′. If SerCT(c)=SerCT(c′), select the normal key for m′; otherwise select the fallback key bound to z. The normal API returns only a 32-byte key. Format errors are rejected with InputValidationError. Constant-time Python execution is not guaranteed.

Public key format validation is neither peer authentication nor proof of key generation. The assumption is that pk,c and the algorithms are public, while s,z, temporary randomness, and shared keys are secret.

## 4. XOF Input Frames and Sampling

Concatenation is `||`; LEᵣ is an r-byte unsigned little-endian integer. All labels use the exact ASCII bytes and integer encodings below.

```
D = b"Spiral-KEM-v0.3/research-only/"     # 30 bytes, not a web address
P = LE4(n)||LE4(k)||LE4(q)||LE4(eta)||LE4(key_bytes)  # 20 bytes
F(label, payload, L) = SHAKE256(D||P||LE2(len(label))||label||payload)[:L]
```

The label length defines input boundaries, and P distinguishes profiles. Each field in the internal call payload layouts below has a fixed length. Different profiles have different SHAKE inputs. This does not imply that output collisions are impossible.

**SmallPoly(seed,label)**: Read F(`small/`||label,seed,2ηn). For each coefficient, subtract the sum of the lowest bits of the next η bytes from the sum of the lowest bits of η bytes, and store mod q. For η=1, the probabilities of −1,0,1 in the ideal independent-bit model are 1/4,1/2,1/4, respectively.

**SmallVec(seed,label)**: Call SmallPoly(seed,label||`/`||LE₂(i)) for i=0,…,k−1.

**UniformPoly(seed,label)**: Starting at ctr=0, read F(`uniform/`||label, seed||LE₄(ctr),256) sequentially and increment ctr. Split each block into 16-bit LE integers, accept only candidates below 63251, and store `candidate mod 3329`. Stop after obtaining n coefficients. Under ideal uniform 16-bit input, each remainder has exactly 19 accepted preimages. In practice, the byte stream is deterministically generated by SHAKE.

**ExpandA(ρ)**: Aᵢⱼ=UniformPoly(ρ,`matrix/`||LE₂(i)||LE₂(j)). i,j=0,…,k−1. Construct the matrix in row-major order.

KeyGen labels for s,e are `key/s`, `key/e`. Encaps labels for r,e₁,e₂ are `enc/r`, `enc/e1`, `enc/e2`, with coins as the input seed.

## 5. Byte Formats and Key Derivation

PackPoly concatenates coefficients encoded individually as LE₂ in exponent order. PackVec concatenates vector polynomials through PackPoly in order. Check canonical input 0≤coefficient<3329; do not correct input values with `%q`.

```
SerPK(pk) = D||b"pk/"||P||rho||PackVec(t)
SerCT(c)  = D||b"ct/"||P||PackVec(u)||PackPoly(v)
```

The baseline public key is 30+3+20+32+2kn=1109 bytes, and the ciphertext is 30+3+20+2(k+1)n=1589 bytes. The public key is 32 bytes smaller than in v0.2. No secret key wire format is defined.

Let H=SHA3-256, hpk=H(SerPK(pk)), hct=H(SerCT(c)):

```
coins    = F(b"coins/",       m||hpk,           32)
K_valid  = F(b"shared-key/",  m||hpk||hct,      32)
K_reject = F(b"fallback/",    z||hpk||hct,      32)
```

Decaps computes hct from serialization of the received input ciphertext. Compute both the normal and fallback keys and select using the reencryption comparison result. The same sk and same invalid canonical ciphertext return the same fallback key.

Byte inputs are checked for exact bytes type, header, profile, length, and canonical coefficients. Object inputs are checked for the exact class and immutable tuple/int formats, rejecting bools and floating-point values. Only 0,1,3328 are allowed as coefficients of s. Format validation still does not prove that sk and pk were actually generated by KeyGen.

## 6. Encode, Decode, and Decryption Error

Read each byte from its lowest bit. Encode bᵢ∈{0,1} as 1664bᵢ. Decode uses nearest-center classification for a mod q with circular distance d_q(a,b)=min((a−b) mod q,(b−a) mod q). Return 1 if d_q(a,1664)<d_q(a,0), otherwise 0; ties return 0.

The equivalent fixed inequality is **1 when 833≤a≤2496**. a=832 is a tie and returns 0. a=2496 is at distance 832 from 1664 and 833 from 0, so 1 is correct. v0.2 classified the latter as 0. This correction does not mean that the set of failure events shrinks for every input bit; it aligns the implementation with the defined distance rule.

The cancellation relation holds exactly in the ring as follows.

$$
v-s^Tu=\operatorname{Encode}(m)+E,\qquad E=e^Tr+e_2-s^Te_1.
$$

Consider Eᵢ obtained by integer negacyclic multiplication of small coefficients in centered representation. Near 0, the correct interval is [−832,832] for bit=0 and [−831,832] for bit=1. Thus recovery succeeds if −831≤Eᵢ≤832 for every bit. A simpler sufficient condition is |Eᵢ|≤831. Outside this range, classification uses mod q, so the general exact failure event is Decode((1664b+Eᵢ) mod q)≠b.

For η=1, each product term has absolute value at most 1. Each coefficient sums 2kn products from two inner products and one e₂ term, so |Eᵢ|≤2kn+1. For the baseline n=256, this is 1025, so this worst-case bound alone cannot guarantee no failures. For n≤128, the maximum is 513, so this bound alone guarantees PKE decryption for correctly generated small coefficients. This is separate from security at small n.

Without claiming to have found actual SHAKE seeds, an algebraic example with E₀=1025 within the support of allowed small coefficients was also tested. Thus the claim that the error is always within the decryption region is unsupported for the baseline configuration.

## 7. Exact Error Distribution in the Independent CBD1 Model

This section idealizes every coefficient of s,e,r,e₁,e₂ as mutually independent CBD1 samples. This assumption is not equated with the exact joint distribution of the actual finite-seed implementation.

The product of independent CBD1 coefficients X,Y has probabilities 1/8,3/4,1/8 at −1,0,1. For one fixed output coefficient, symmetry is preserved even with negacyclic signs, and the 2kn product terms can be counted as independent because their input pairs do not overlap. Different output coefficients share inputs and are not assumed independent.

The probability-generating Laurent polynomial for one coefficient is as follows.

$$
G(z)=\left(\frac{z^{-1}+6+z}{8}\right)^{2kn}
       \left(\frac{z^{-1}+2+z}{4}\right).
$$

The mean is 0 and the variance is kn/2+1/2. For k=2,n=256, it is 256.5. The analysis script computes the integer-coefficient polynomial `(z^-1+6+z)^(2kn)(z^-1+2+z)` using dynamic programming. The common denominator is 2^(6kn+2), or 2^3074 for the baseline configuration. It neither accumulates floating-point probabilities nor replaces tails with a normal approximation.

Compute p₀,p₁ as exact fractions by summing coefficients for failing Eᵢ values. In this model, message failure probability is at most `min(1,n max(p₀,p₁))`. This union bound does not require independence between output coefficients.

The run gives log₂(max(p₀,p₁))≈−1863.0628 at n=256 and log₂≈−1855.0628 for the message union bound. **Do not read this as '1855-bit security' or a failure-probability bound for the actual implementation.** Actual SHAKE inputs are finite-length seeds, differing from the independent-sample model. These numbers cannot be transferred directly to the actual implementation without computational analysis of that difference. This calculation also does not determine the failure rate of a particular key or an adaptive attacker's cost of inducing failures.

Fixing the actual function and key leaves 2^256 messages in the baseline profile. The actual decryption error probability for uniformly random messages has the form integer/2^256. This is a concrete reason why the model's extremely small positive value cannot be transferred directly as the actual probability.

Exact numerators and denominators are in `analysis/results.json`. The log₂ displays are approximate. Results of 0 for n≤128 are also explained by the deterministic small-coefficient bound.

## 8. Checks Performed and Reproduction

| Check | Result | Scope verified |
|---|---|---|
| Built-in regression checks | 19 passed | Inputs and byte formats, normal recovery, tampering, fallback keys, suppression of secret output |
| Baseline normal exchanges | 50 succeeded | Functional regression across multiple key pairs; not an estimate of rare failure rates |
| LAB regression checks | 19 checks and 25 normal exchanges passed | Reduced modes and exhaustive-search examples |
| `python -O` regression checks | 19 checks and 2 normal exchanges passed | Checks still execute with assert statements removed |
| Separate mathematical checks | 18 passed | Independent multiplication, cancellation identities, samplers, error distribution, fixed-input results |
| Exhaustive decoding boundary check | All 0…3328 matched | Compared against a circular-distance reference function |
| Existing spiral transform | 13 relations × 10 sets = 130 passed | 8 sets at n=8, 2 sets at n=256 |
| CLI | 4 cases passed | Baseline/LAB execution, rejection of invalid modes and repetition counts |

The exhaustive-search example is an educational check that finds the shared key using 256 message candidates at n=8. It means neither that the baseline is broken nor that it is secure. Fixed-input results are for internal regression and are not official NIST test vectors. Random-test counts are empirical successes and do not replace cryptographic probabilities or security proofs.

Run from the extracted project folder.

```bash
python spiral_kem_toy_v03.py --self-test --trials 50
python -m unittest discover -s tests -v
python analysis/analyze_math.py --output analysis/results.json
```

No external Python packages are required; use Python 3.10 or later. `legacy/` is for comparative analysis. v0.2 keys and ciphertexts cannot be used; generate fresh keys in v0.3. The former public methods `spiral_descriptor` and `regenerate_path_seed` were removed. Core KeyGen/Encaps/Decaps methods and separation of test diagnostics are retained.

## 9. Remaining Decisions and Research Priorities

The next task is security validation. Arbitrarily reducing η may ease decryption while reducing the attack difficulty of the public problem. Conversely, increasing η also increases noise and failure rates. Retain the baseline for comparison and change it only after specifying classical and quantum lattice attack costs, attacks exploiting the secret distribution, and multi-target conditions. These results do not list unestimated security-bit counts.

The complete KEM requires separate treatment of seed expansion, security models for hashes/KDFs, assumptions and security losses of the reencryption-based transform, and the relationship between decryption failures and chosen-ciphertext attacks. Mathematical cancellation does not solve side channels in the Python implementation. No claim is made that this replaces external review.

The immediate goal is to use **v0.3 as a research model that can be explained and reproduced**. Analysis scripts, checks, and rationale for changes accompany the implementation to support independent reproduction and continued research.

## 10. Comparison References

NIST, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203, 2024. [Official document](https://doi.org/10.6028/NIST.FIPS.203), [official publication page](https://csrc.nist.gov/pubs/fips/203/final). Accessed 2026-10-20. The publication page announces forthcoming corrections, so consult the latest errata when making implementation decisions.

Sections 4.2.2 (sampling), 5 (PKE construction), 6–7 (KEM), and 8 (parameter sets) of the standard were used for comparison. ML-KEM-512's η₁=3,η₂=2 and compression rules, among other details, differ from this code. This project neither implements standard ML-KEM nor inherits its security rating. Removing the public spiral transform and the project's probability calculations are direct derivations in this document, not results quoted from that standard.
