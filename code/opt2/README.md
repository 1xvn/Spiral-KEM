# Spiral KEM v0.3.1 OPT2

OPT2 is a research implementation that reduces Python conversion overhead and adds a lossless compact wire format. It does not change the secret/error distributions or the default `n,k,q,eta` parameters.

## Run

Use Python 3.10+ and install the pinned comparison dependency:

```bash
python3 -m pip install "kyber-py==1.2.0"
cd code/opt2
python3 verify_equivalence.py
python3 verify_opt2.py
python3 compare_spiral_opt2_mlkem.py
```

From Windows PowerShell, use `py` instead of `python3`. Run in the directory containing the implementation and comparison scripts. The default benchmark performs 30 warmups and 300 measured exchanges per implementation. Use `--rounds 3 --warmup 1` only for a functional smoke check.

The runner first checks baseline/OPT1/OPT2 regressions and wire-format correctness, then alternates the baseline, OPT1, OPT2 compact API and ML-KEM-512 in one process. It records source hashes, environment details, order and all 1,200 measurements in a uniquely named `Spiral_opt2_MLKEM_comparison_*.json`; normal measurements do not record secret keys, shared keys or messages.

## Implementation changes

- OPT1 specializes the `eta=1` sampler using direct bit subtraction.
- OPT2 batches canonical 16-bit conversion and 32-bit integer packing through standard-library `Struct` objects. Input and re-encryption checks remain in place.
- SKW1 adds an 8-byte header and lossless 12-bit coefficients. At `n=256`, public keys shrink from 1,109 to 808 bytes and ciphertexts from 1,589 to 1,160 bytes. Shared keys remain 32 bytes.

The existing `serialize_public_key` / `serialize_ciphertext` methods retain the legacy 16-bit encoding used by internal KEM hashes. Compact methods change transport only. Given identical random inputs, the implementations are tested for identical coefficients, legacy public-key/ciphertext bytes and shared keys.

```python
from spiral_kem_toy_v031_opt2 import SpiralKEM

kem = SpiralKEM()
pk, sk = kem.keygen()
pk_wire = kem.serialize_public_key_compact(pk)       # 808 bytes
received_pk = kem.deserialize_public_key_compact(pk_wire)
ct, sender_key = kem.encapsulate(received_pk)
ct_wire = kem.serialize_ciphertext_compact(ct)       # 1160 bytes
received_ct = kem.deserialize_ciphertext_compact(ct_wire)
receiver_key = kem.decapsulate(sk, received_ct)
if sender_key != receiver_key:
    raise RuntimeError("Key mismatch")
```

Both peers must use the compact API for SKW1. Legacy readers cannot directly parse SKW1 bytes; a compact-decoded object can be reserialized through the legacy API explicitly.

## Interpret results

Reported medians include byte I/O conversion. Total time is the median of each round's three-operation sum and excludes network time. See [RESULTS.md](RESULTS.md) for the recorded Linux run and [COMPACT_WIRE_SPEC.md](COMPACT_WIRE_SPEC.md) for byte layout and validation rules.

The comparison uses an educational Python ML-KEM implementation with different noise/compression choices. Timings are not security-equivalent parameter comparisons. Python constant-time behavior, rare decryption-failure probability and cryptographic strength have not been established.
