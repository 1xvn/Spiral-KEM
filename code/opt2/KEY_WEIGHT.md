# Fixed-SHAKE key-weight check

## Sampling plan

Source revision `f6592270607cac68641752069a730538a88d390d`. For the default OPT2 parameters, W counts the nonzero coefficients in the four key-generation polynomials s and e. For honest inputs the centered decryption error in every coordinate has magnitude at most W+1. Therefore W ≤ 830 guarantees correct decoding for every message under that key. W ≥ 831 is the event that this sufficient condition does not cover the key. [Derivation](DECRYPTION_FAILURE.md)

For the fixed SHAKE function, define p as the fraction of all 32-byte key seeds with W ≥ 831. The honest decryption-failure probability under uniform key seeds is at most p. We do not have a deterministic count of that population. In a random-oracle model for key expansion, each fixed seed addresses four distinct framed inputs. Each nonzero indicator is the XOR of two independent low bits. The previous single-seed model gives `b = sum(comb(1024,j), j=831..1024)/2^1024`. By a union bound over the entire seed space, the probability **over the choice of oracle** that even one seed exceeds the cutoff is at most `2^256 b` (log₂ about −57.559832). This last step needs no independence between seeds. Its probability space differs from drawing keys from the one real SHAKE function. [Single-seed exact numerator and denominator](../../results/opt2_dfr_recheck.json)

For one short local run, use 2,995 independent uniform 32-byte public test seeds sampled with replacement from the OS. Draw each seed directly, call the OPT2 sampler under its two key labels, and retain every seed and its integer weight. Every draw counts, including repeats. Stop at the fixed budget. Keep any interrupted file for diagnosis and reject incomplete or invalid evidence. No exchanges, matrix generation, alternate seeds, importance weighting or tail extrapolation are needed. These synthetic seeds are created only for this public experiment.

The target is a one-sided 95% upper confidence limit at or below 0.001 in the zero-event case. The smallest N is `ceil(log(0.05)/log(1−0.001)) = 2995`. If the completed sample has zero events, report `1−0.05^(1/N)`. If it contains events, report their count and keep the zero-event limit unavailable. Coverage assumes iid uniform **seed draws** for a fixed sampler. There is no assumption about independence among the 1,024 coefficients inside a real key. Replaying observations adds zero independent draws. The previous 2,000 archived keys used a different fixture-to-seed map and are excluded from this count.

## Replay

From the repository root, Python 3.10 or newer can verify every saved weight with an independent implementation of the SHAKE frames and low-bit count.

```sh
python3 -B code/opt2/key_weight.py review results/key_weight/seeds.csv.gz
```

For a separately budgeted independent run, use `python3 -B code/opt2/key_weight.py collect NEW.csv.gz` once, then use `review` on that file. Collection requires a new output filename.

## Observed result

The sampling plan and collector were committed at `9312a32` before the first draw. All 2,995 stored weights matched the independent replay. The range was **457–584**, with **0/2,995** at or above 831. Each sampled seed therefore meets the sufficient decoding condition. The one-sided 95% upper confidence limit on the fixed sampler's heavy-seed fraction is **0.000999744421** (about **0.0999744%**) under the uniform independent seed-draw assumption. The same confidence upper limit conservatively covers the honest message-failure rate through the deterministic inequality. The number of actual exchanges in this experiment was zero. Neither the exact fraction across all 2²⁵⁶ seeds nor a cryptographically small bound for fixed SHAKE has been established. [Raw public test seeds and weights](../../results/key_weight/seeds.csv.gz) · [Verified summary and digests](../../results/key_weight/summary.json)
