# Spiral OPT2 low-level research implementation and adversarial-input regression checks

A separate C11 KEM experimental implementation preserving existing OPT2 operations, hashes, and SKW1 results.
Protocol regression checks were expanded first; low-level implementations were compared on that validation framework.
**This does not establish constant-time behavior, Spiral's cryptographic security, or approval for production-service use.**

The baseline repository commit is `31cacb8fa0daddb9d0e162edb58f346bb15abc72`; the comparison target
`code/opt2/spiral_kem_toy_v031_opt2.py` has SHA-256
`74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118`.
The profile is fixed at n=256, k=2, q=3329, eta=1, with a 32-byte shared secret.
Only canonical SKW1 encoding with an 808-byte public key and 1160-byte ciphertext is accepted.

## Implementation scope

| Item | Behavior in this implementation |
|---|---|
| Secret polynomial operations | Negacyclic multiplication with fixed loops/indices, modular reduction without division |
| Hashing/randomness | OpenSSL EVP SHAKE256/SHA3-256, failure-checked `RAND_priv_bytes` |
| Ciphertext checking | Parse only canonical formats, then compare re-encryption using `CRYPTO_memcmp` |
| implicit rejection | Compute both valid candidate and fallback key, select with a mask; expose no validity flag |
| Secret-key lifetime | Atomic state transitions allow only 1 decapsulation; format errors also consume the key |
| Secret buffers | `OPENSSL_cleanse` / `OPENSSL_clear_free` after success, parse failure, and crypto-API failure |
| Test APIs | Public fixed-seed/polynomial-check functions exist only in separate `libspiral_testing.so` |

Matrix rejection-sampling iterations vary with the public matrix seed.
The code is written to avoid secret-dependent branches or addresses, but actual behavior including compiler, CPU, and OpenSSL providers
requires separate review. Multiplication is O(n²); speed optimization is not claimed complete.
It preserves existing Python legacy hash inputs; it is not a different KEM hashing only a changed compact wire format.

`protocol_v01` default KEM loading, hash pinning, and TLS paths continue to use the existing Python implementation.
An adapter connecting this C module to the protocol and C-side HKDF/AEAD/Finished-key management are not implemented.
Thus these changes should not be interpreted as improving whole-Python-process secret zeroization or end-to-end constant-time communication.

## Build and reproduction

Procedures for running the new C coverage-guided checks on both platforms are in
the [OCI ARM64 / WSL2 x86-64 guide](FUZZ_PLATFORMS.md).
The first targets are public-key parsing and common encapsulation, separate from existing fixed-input checks.

Linux x86-64 requires a C11 compiler, make, and OpenSSL 3 development headers/libraries.
Run Python checks in an environment with the pinned dependencies from `protocol_v01/requirements.txt` installed.
Commands below assume the repository root.

```sh
make -C native_research all
python3 -m unittest discover -s protocol_v01/tests -v
make -C native_research check PYTHON=python3
make -C native_research sanitize
make -C native_research timing
python3 -m protocol_v01.demo --connections 4
```

`sanitize` requests AddressSanitizer, UndefinedBehaviorSanitizer, and leak checks by default.
In this execution environment, LeakSanitizer could not start due to `/proc`/ptrace restrictions.
Separately from leak checks, ASan/UBSan were run with the following command and passed.

```sh
make -C native_research sanitize SANITIZER_OPTIONS=detect_leaks=0
```

On a host with Valgrind and debug symbols matching the installed glibc, run:
The main check proceeds only if the positive control's intentional secret branch produces error exit 99.

```sh
make -C native_research taint
make -C native_research memcheck
```

On this host, Valgrind could not start due to symbol mismatch with default glibc 2.39-0ubuntu8.6.
Without replacing host libraries, checks used glibc 2.39-0ubuntu8.8 prepared in a separate directory and
matching symbols. Tracing covered key-generation secret seeds, encapsulation messages,
and decapsulation secret polynomials/fallback keys. Public-key, ciphertext, and shared-secret outputs were marked as deliberate disclosure boundaries;
four normal/tampered paths had 0 errors and 0 allocated blocks at exit.
This checks secret branches/addresses on executed paths, not CPU instruction latency, caches, or unexecuted paths.

`build/` contains generated outputs and is not committed. No distribution binaries are provided.
Do not load the testing `.so` in production services.

## C API and caller responsibilities

`spiral_native.h` exposes four functions.

| Function | Contract |
|---|---|
| `sp_keygen(pk, &key)` | Generate keys with fresh randomness; `key` initially NULL; caller owns it after success |
| `sp_encaps(pk, pk_len, ct, ss)` | Validate canonical public key, then encapsulate with fresh randomness |
| `sp_decaps_once(key, ct, ct_len, ss)` | Only one call claims the key; returns a shared-secret-shaped fallback key even for canonically formatted tampered ciphertext |
| `sp_key_destroy(&key)` | Erase secret memory, free it, and set the pointer to NULL |

Return values are `SP_OK=0`, `SP_INPUT=1`, `SP_CRYPTO=2`, and `SP_USED=3`.
`SP_OK` does not indicate ciphertext validity. The communication layer must verify Finished with the returned key.
Do not expose internal failure types directly in remote responses or logs.

Callers must provide live, nonoverlapping buffers of sufficient size.
Decapsulation calls on the same key may overlap, but every call requires a distinct output buffer.
Call destroy only after all calls finish; do not copy, serialize, or reuse key pointers.
A NULL output pointer is a caller error and is not counted as a key-consuming decapsulation attempt.
Callers are responsible for erasing returned `ss` and application keys.
Memory locking and complete erasure of swap, core dumps, CPU registers, or internal OpenSSL provider state are not guaranteed.

## Observed results

Execution environments and logs are in [VALIDATION_2026-11-06.json](VALIDATION_2026-11-06.json),
[evidence/](evidence/). Counts are unittest methods, each containing multiple inputs.
Only trailing whitespace was removed from logs for review; results and error messages were preserved.

| Check | Result |
|---|---|
| Existing protocol regression checks | 59/59 passed |
| After adding adversarial-input checks | 69/69 passed, 0 failures/errors/skips |
| Separate C comparison/lifetime/concurrency checks | 9/9 passed |
| Python ↔ C fixed seeds | 32 sets with matching public keys/ciphertexts/shared secrets |
| Canonically formatted tampered ciphertext | 96 cases matched Python fallback keys |
| Concurrent key claiming | 1 success among 32 calls; remaining 31 `SP_USED` |
| ASan/UBSan | Failure injection and 20,000-public-input corpus passed; separate LSan limitation |
| Valgrind secret tracing | Detected 1 positive-control error; main check 0 errors/0 allocated blocks at exit |
| Valgrind memory checks | Failure injection/20,000-input corpus: 0 errors/0 allocated blocks at exit |
| Existing TLS 1.3 concurrent connections | 4 actual exporters, independent sessions, encrypted echo, and authenticated shutdown passed |

Additional protocol checks include 2,689 truncated frames, 320 header-bit mutations,
1,160 DATA-frame bit mutations, a 4,096-entry reproducible mutation corpus,
pre-read length bounds, ClientHello grammar, 32 Finished mutations,
18 canonical ciphertext mutations, duplicate records, and 1,024 concurrent nonce reservations.
Parser acceptance of a canonical frame is not counted as successful ciphertext/Finished authentication.
These are not results from running a coverage-guided fuzzer.

Timing measurements ran a custom two-group Welch t test twice with 6,000 samples each.
With identical public matrix seeds and canonical ciphertexts, fixed-secret-seed and varying-seed groups were compared;
key generation was outside the measured interval. The positive control deliberately used different loop iteration counts;
the sham control used identical keys/ciphertexts in both groups. The dudect package was not run.

| Run | Secret-group t | Positive-control t | sham t |
|---|---:|---:|---:|
| A | -0.40371712 | -6.53530076 | -0.89239711 |
| B | 0.18487245 | -18.80531540 | 0.73305123 |

Measurements for selected inputs/environments did not observe a large timing-difference signal.
Small samples and substantial host noise prevent establishing constant-time behavior; nondetection is insufficient evidence of security.
GCC `-O2` output was also checked for absence of division instructions and retention of erasure calls; this does not replace a complete assembly audit.

Remaining steps include expanding dynamic tracing to other secrets/error paths, independent low-level code review,
measurements on other compilers/OSes/CPUs, coverage-guided fuzzing, and C protocol-adapter design.
Spiral's own attack costs, failure probabilities, and cryptographic proofs remain separate research topics.

## References

- [OpenSSL EVP digest](https://docs.openssl.org/3.0/man3/EVP_DigestInit/)
- [OpenSSL RAND_bytes / RAND_priv_bytes](https://docs.openssl.org/3.0/man3/RAND_bytes/)
- [Valgrind Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)
- [BearSSL constant-time coding](https://www.bearssl.org/constanttime.html)
