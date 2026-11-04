# Spiral-KEM 0.3.1 opt2 — PC Measurement Summary

Written: 2026-10-23 (Korea time)
Data status: based on submitted Windows console output. Original JSON has not yet been reaggregated.

**Measurement results:** On the same PC in the same process, opt2's total processing time was approximately 50.0% shorter than the original and 31.3% shorter than opt1. The lossless compact wire format used 808-byte public keys and 1,160-byte ciphertexts.

## Measurement Conditions and Results

`compare_spiral_opt2_mlkem.py` compared four implementations. Each received 30 warmups and 300 measurements; times below are medians including byte input/output. The console reported passing original, opt1, and opt2 regression checks and lossless wire-format verification.

| Item | Original | opt1 | opt2 (compact) | ML-KEM-512 (kyber-py 1.2.0) |
|---|---:|---:|---:|---:|
| Key generation (ms) | 3.580 | 2.328 | 1.669 | 2.521 |
| Encapsulation (ms) | 5.775 | 4.163 | 2.885 | 3.610 |
| Decapsulation (ms) | 7.614 | 6.012 | 3.989 | 5.141 |
| Total (ms) | 17.299 | 12.599 | **8.658** | 11.339 |
| Public key (bytes) | 1,109 | 1,109 | **808** | 800 |
| Ciphertext (bytes) | 1,589 | 1,589 | **1,160** | 768 |
| Key mismatches | 0/300 | 0/300 | 0/300 | 0/300 |

Total time is the median of each round's sum of the three operations. It can differ from the sum of individual operation medians and excludes network transmission time.

## Meaning and Remaining Limitations

- opt2's total processing time was **23.6% shorter** than `kyber-py 1.2.0` in this comparison. This does not imply superiority over ML-KEM implementations in other languages or at other optimization levels.
- Compared with original/opt1, public keys shrank by **27.1%** and ciphertexts by **27.0%**. Compared with ML-KEM-512, public keys are 8 bytes (1.0%) larger and ciphertexts 392 bytes (51.0%) larger.
- opt2 improves computation and storage methods while preserving Spiral's base parameters `(n,k,q,η)=(256,2,3329,1)` and lossless coefficient values. 808/1,160 bytes are wire sizes through the explicit compact API; existing 16-bit API sizes are 1,109/1,589 bytes.
- 0/300 means no key mismatches were observed in these measurements. It does not establish an extremely small decryption-failure probability, attack resistance, security equivalent to ML-KEM, or commercial suitability.

## Completed and Next Goals

**Completed:** Observed opt2 speed and wire-size improvements on the measured Windows PC and prepared a comparison table.
**Next:** Archive this opt2 source together with measurement JSON, reaggregate the JSON, and finalize this summary as review material. Further attack and red-team research remains outstanding.

Review questions: which aspects of this research KEM with measured performance improvements should be examined first: structure and parameter selection, decryption-failure analysis, or implementation side channels?

Original measurement filename: `Spiral_opt2_MLKEM_comparison_20261023_100742_001fedf0.json`
Ratios were calculated using console times displayed to three decimal places, so recalculation from JSON may change the last digit.
