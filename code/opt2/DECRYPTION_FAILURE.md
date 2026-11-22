# Honest decryption failure at the OPT2 defaults

Source baseline: public main `5e9a80380681c31b0276301d59021d8254dcefe5`.
For `(n,k,q,eta,key_bytes)=(256,2,3329,1,32)`, the two published ideal-model bounds reproduce. For the fixed SHAKE implementation the overall honest decryption-failure rate remains unknown. A deterministic sufficient condition does establish decoding for every honest message on each of the 2,000 archived baseline A fixture keys.

## Which event is being counted

For one correctly generated key and an honestly generated ciphertext, count a message failure if at least one recovered bit differs from the original. A correct message makes deterministic reencryption and valid key derivation agree. Thus the probability of an honest shared-key mismatch is bounded above by the probability of message failure. Historical exchange logs measured shared-key mismatch. All calculations assume correct execution and lossless transmission of canonical inputs.

## Source and error derivation

| Operation | OPT2 Python and native C paths | Consequence |
| --- | --- | --- |
| Key sampling | `keygen`, `_small_vector`, `_small_poly`; C `keygen_seeded`, `small_vector`, `small_poly` | One 32-byte secret seed supplies the distinct `key/s` and `key/e` labels. For each polynomial the XOF frame includes version/domain, parameters, label length, label and seed. Vectors append the little-endian polynomial index. Each coefficient consumes two successive bytes and subtracts their low bits, positive minus negative, modulo 3329. Centering maps 3328 to −1. Only under independent fair output bits are the masses at −1, 0, +1 exactly 1/4, 1/2, 1/4. |
| Encryption coins | `_coin_seed`, `_encrypt_message`; C `encrypt_message` | A 32-byte message and SHA3-256 of the canonical public key feed the `coins/` XOF. Its 32-byte output feeds all `enc/r`, `enc/e1` and `enc/e2` samples under separate labels. Repeating a message under the same key repeats the coins. |
| Ring arithmetic | `_base_matrix`, `_poly_mul`, `_dot`; C `base_matrix`, `multiply`, `dot` | The public matrix accepts 16-bit words below 63251 and reduces modulo 3329. Python normalizes operands and packs base-2³² digits, with each ordinary convolution digit at most 256·3328² = 2,835,349,504. It subtracts the upper half modulo q. C uses signed wrap terms represented by q²−product, with accumulator bounded by 256·3329² < 2³², then reduces. Both give xⁿ = −1. |
| Encoding and recovery | `_encode_message`, `_decode_message`, `_decapsulate_core`; C `encode`, `decode`, `sp_decaps_once` | Each byte is read least-significant bit first. Centers are 0 and 1664. Canonical residues 833 through 2496 inclusive decode to one. Residue 832 is a tie and decodes to zero. SKW1 packs all 12 bits of each canonical coefficient and introduces zero rounding error. |

In the commutative quotient ring, substitution of `t=As+e`, `u=Aᵀr+e1` and `v=tᵀr+e2+Encode(m)` cancels `(As)ᵀr=sᵀ(Aᵀr)`. Hence the decoder input is `Encode(m)+E (mod q)` with `E=eᵀr−sᵀe1+e2`. Matrix uniformity plays no part in this identity. For a centered integer lift before reduction,

```text
E[i] = e2[i] + Σ(j,h) sign(i,h) ·
       ( e[j,h]·r[j,(i−h) mod n] − s[j,h]·e1[j,(i−h) mod n] )
sign(i,h) = +1 for h ≤ i, −1 for h > i.
```

Each of the 1,024 products and the single additive noise coefficient has magnitude at most one. On the resulting support [−1025,1025], the exact success intervals are [−832,832] for bit zero and [−831,832] for bit one. The asymmetric endpoint matters to the tail. Outside this support a general calculator must still reduce modulo q before deciding. [Python source](spiral_kem_toy_v031_opt2.py) · [C source](../../native_research/spiral_native.c)

## Recalculation of published theory

Assume **all** coefficient samples of s, e, r, e1, e2 are independent CBD1, including the encryption noise for each fixed message. For a fixed output index, h ↦ (i−h) mod n is a permutation. Each product uses a disjoint input pair within its polynomial, and the vectors and polynomial slots are distinct. Negacyclic signs preserve the symmetric product masses (1,6,1)/8. Different output indices share inputs. Only a union bound is used across the 256 bits.

The single-coefficient generating polynomial in ascending signed-error order, shifted to start at degree zero, is `(1+6x+x²)^1024 (1+2x+x²)` with denominator 2³⁰⁷⁴. The new calculator gets its integer coefficients using the derivative identity for the power of the quadratic, then sums exactly over failing residues. The document's historical `analysis/results.json` path is absent from the current public tree. The exact numerators and common denominator from this recalculation are in the linked output.

| Quantity | Recalculated log₂ (rounded) | Prior evidence and interpretation |
| --- | ---: | --- |
| Bit 0 marginal failure | −1866.830888 | Exact integer sum, displayed on a log scale |
| Bit 1 marginal failure | −1863.062787 | Larger marginal, agrees with the specification's −1863.0628 |
| Any bit fails, union bound | −1855.062787 | 256·max(p₀,p₁), agrees with the published −1855.0628. Whole-message probability can be smaller. |
| Any bit fails, Chernoff union bound | −1850.135767 | Reuses the two exact positive tilts in archived baseline A. Independently reproduces the archived −1850.14 and its conservative upper bound 2⁻¹⁸⁵⁰. |

For each archived tilt t and threshold a in {832,833}, the one-sided bound is `B(a)=exp(−a·t) ((exp(t)+6+exp(−t))/8)^1024 ((exp(t)+2+exp(−t))/4)`. Symmetry and the decoder endpoints give the worst-bit message bound `256·(B(832)+B(833))`. The calculator brackets the exponentials by adjacent 110-digit Decimal numbers around the correctly rounded result, then rounds positive additions, multiplications and divisions outwards. Both endpoints lie inside the archived Sage rational interval and above the exact-marginal union bound. The logs in the table are displays. The exact counts and the interval carry the bound. These are reproductions of earlier calculations. No tail sampling or fit was used. [Original specification §§6–8](../../originals/spiral_kem_v03_math_spec.md) · [Six-candidate archive, results/failure-bounds/A_k2_eta1.json](../../archives/research/Spiral_KEM_six_candidates_results.zip) · [Recalculated results](../../results/opt2_dfr_recheck.json)

## What applies to the actual seeded implementation

Let W be the total number of nonzero coefficients in the four key-side polynomials s and e. Every key-side coefficient appears once per output index and its encryption-side partner has magnitude at most one. Consequently `|E[i]| ≤ W+1` for **every** honest message and any permitted encryption noise. If **W ≤ 830**, that key always decodes correctly, even with dependent coins. Above 830 the test gives no verdict on an individual key. This is an offline property of generated fixture keys. No key filtering or sampler change is involved.

For freshly sampled keys the implementation therefore satisfies `P(message failure) ≤ P_secret_seed(W ≥ 831)`. The actual fixed-SHAKE key-weight tail on the right is unknown. Under the weaker model where only the 1,024 key-side nonzero indicators are independent fair bits, W is binomial and this upper bound is exactly `Σ[j=831..1024] binom(1024,j)/2^1024`, with log₂ about **−313.559832**. It imposes no independence condition on encryption coins. This number still depends on the key-side assumption.

For a fixed key and uniform 32-byte message, the true probability is an integer multiple of 2⁻²⁵⁶. Even averaging over independent uniform 32-byte matrix seeds, secret seeds and messages gives a multiple of 2⁻⁷⁶⁸ for the decoding event, since the fallback seed does not enter it. The ideal-model fractional tails therefore cannot be substituted for a positive fixed-SHAKE rate. Resolving the actual population bound needs a justified upper bound on the fixed sampler's fraction of heavy keys, or a quantified argument relating the full seeded construction to an ideal experiment. Domain labels and distinct seed observations alone supply neither. For multiple exchanges the union bound on events applies given their marginals, while shared keys or repeated messages can correlate outcomes. No independent session assumption or cryptographic security level follows here.

The [fixed-SHAKE key-weight follow-up](KEY_WEIGHT.md) gives the all-seed random-oracle calculation and a separate, predeclared statistical bound from direct uniform seed draws.

## Historical exchange observations

| Source and event | Recorded mismatches / measured exchanges | Interpretation |
| --- | ---: | --- |
| Six-candidate archive, A only, original v0.3.1 | 0 / 2,000 | Checked all indexed JSONL rows against the summary (zero exceptions). If these are iid Bernoulli trials under the public fixture generator, the single-profile one-sided 95% upper limit on shared-key mismatch is 1−0.05^(1/2000) = 0.001496745. |
| OPT2 compact API, Linux benchmark | 0 / 300 | Measured rounds only, fresh OS randomness. The release ZIP and results ZIP contain the same named Linux run. |
| OPT2 compact API, Windows benchmark | 0 / 300 | Separate benchmark record. |
| Original specification's default regression | 0 / 50 reported | The self-test rotates keys every five trials. Only the historical summary is cited. |

The A experiment used one public 32-byte fixture seed per trial. In the archived `common.py`, a **single 128-byte SHAKE output** is split into rho, sigma, fallback seed and message. This refines the archive narrative's description of separate streams. The calculator regenerated only the key-side material for these saved seeds and matched all 2,000 archived canonical public-key SHA-256 values. W ranged from **454 to 574**. The sufficient condition covers every honest message for each of these specific keys, including messages never tried in the archive. These checks add zero random exchanges. Replay, duplicate archives, benchmark warmups and small-profile tests are excluded from the historical counts. [Baseline A JSONL and fixture generator](../../archives/research/Spiral_KEM_six_candidates_results.zip) · [Linux and Windows benchmark JSONs](../../results/results.zip)

## Reproduction from the repository root

```bash
python3 -B -m unittest discover -s code/opt2 -p 'test_recheck_failure.py' -v
python3 -B code/opt2/recheck_failure.py > /tmp/opt2-dfr.json
diff -u results/opt2_dfr_recheck.json /tmp/opt2-dfr.json
```

The independent reference enumerates the entire n=2, k=1, q=5 coefficient space for a fixed nonzero matrix. The 3¹⁰ polynomial coefficient assignments, weighted by the exact number of fair-bit preimages, cover all 4¹⁰ elementary sampler outcomes. It computes the public key and ciphertext for all four messages, checks cancellation and the key-weight inequality, compares both complete marginal histograms with the calculator, and checks the message union bound against actual joint enumeration. A separate check covers all 3,329 default decoder residues and the entire supported signed error range for both bits. A fixed public OPT2 example checks SHAKE framing, centered schoolbook cancellation and compact ciphertext round-tripping. The C path was source-reviewed. These checks exercise the analysis without rerunning platform or random campaigns. [Calculator](recheck_failure.py) · [Regression checks](test_recheck_failure.py)
