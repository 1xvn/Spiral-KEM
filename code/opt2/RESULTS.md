# OPT2 validation and recorded Linux benchmark

The benchmark completed on 2026-10-23 at 09:26:09 UTC+09:00. All rows were measured in the same Linux process.

| Implementation | Keygen ms | Encapsulation ms | Decapsulation ms | Total ms | Public-key bytes | Ciphertext bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline 0.3.1 | 2.450 | 3.895 | 5.141 | 11.567 | 1109 | 1589 |
| OPT1 | 1.651 | 2.874 | 4.137 | 8.725 | 1109 | 1589 |
| OPT2 compact | 1.273 | 2.195 | 3.061 | 6.591 | 808 | 1160 |
| ML-KEM-512 / kyber-py 1.2.0 | 1.956 | 2.729 | 3.865 | 8.668 | 800 | 768 |

Each implementation received 30 warmups and 300 measured exchanges using fresh OS randomness. Per-round implementation order was shuffled. Times are medians including byte I/O; total is the median of the three-operation sum per round. Network time is excluded. CPU affinity was not fixed and garbage collection remained enabled. All four implementations had 0/300 measured key mismatches.

OPT2 reduced measured total time by 24.5% versus OPT1 and 43.0% versus the baseline in this run. These values are not combined with previous Windows measurements. Re-run `python3 compare_spiral_opt2_mlkem.py` to measure another platform.

## Sizes and compatibility

- Public-key transport: 1109 → 808 bytes, a 27.1% reduction.
- Ciphertext transport: 1589 → 1160 bytes, a 27.0% reduction.
- Shared key: 32 bytes; secret/error distributions and `n,k,q` are unchanged.
- Lossless 12-bit coefficients and the 8-byte SKW1 header are specified in [COMPACT_WIRE_SPEC.md](COMPACT_WIRE_SPEC.md).
- Legacy 16-bit serialization and internal KEM hash encodings remain available.
- Both peers must explicitly use compact methods for SKW1; legacy readers cannot parse it directly.

## Recorded checks

- An AST check restricted OPT2 changes to `__init__`, `_poly_mul`, `_pack_poly`, `_unpack_polys` and added compact methods; DOMAIN, parameters, hash framing, re-encryption and fallback paths remained equivalent.
- Every supported n used a 4-byte multiplication packing width, with the convolution coefficient bound below `2^32`.
- 1,668 12-bit polynomial cases, covering the coefficient range, matched an independent big-integer encoding and round-tripped.
- 1,534 noncanonical 12-bit cases rejected values 3329..4095 rather than reducing them modulo q.
- 24 exchanges using public fixed test randomness matched legacy bytes, secret polynomials and shared keys across baseline/OPT1/OPT2, including compact round trips.
- 144 tampered ciphertexts preserved fallback behavior.
- 828 header/type/length cases and additional range/profile cases were rejected.
- Baseline, OPT1 and OPT2 each passed 21 regression tests with `trials=50`, including independent O(n²) multiplication comparisons.
- All 1,200 measurement records and 160 summary statistics were recalculated, including source hashes, order, time sums and comparison ratios.

These are implementation and performance experiments. They do not prove constant-time execution, rare decryption-failure bounds, or cryptographic security. The educational Python ML-KEM comparison uses different noise and ciphertext-compression settings.

## Reproduction materials

Recorded data: `validation_linux/Spiral_opt2_MLKEM_comparison_20261023_082609_578e471a.json`. The JSON includes validation logs, environment details and source hashes. `validation_linux/audit.json` contains the recalculation summary; `opt2_changes.diff` records implementation changes.

Use `python3 verify_opt2.py` for validation or `python3 compare_spiral_opt2_mlkem.py` for a new benchmark. New measurements use a distinct filename rather than overwriting the recorded run.

Recorded environment: Linux-6.18.55-x86_64-with-glibc2.39, CPython 3.12.14, 9 logical CPUs. The execution source was identified by SHA-256 `74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118` before later documentation-language changes.
