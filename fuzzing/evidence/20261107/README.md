# 2026-11-07 Coverage-Guided Fuzzing Validation

Run on Linux x86-64, Python 3.12.14, Atheris 3.1.0, and cryptography 50.0.2.
These are local results, not GitHub runner results. Production protocol/KEM source was not changed;
the baseline branch commit is `d37675b`.

## Actual Run Results

```bash
python -m fuzzing.campaign --runs 100000 --seconds 60 --output /workspace/atheris-evidence-20261107
```

| Target | Engine executions | Executions through initialization | Initial → final cov | Final ft | Failing input |
| --- | ---: | ---: | ---: | ---: | ---: |
| frame | 100,000 | 43 | 57 → 63 | 91 | 0 |
| hello | 100,000 | 12 | 37 → 48 | 63 | 0 |
| kem_pk | 100,000 | 10 | 35 → 35 | 51 | 0 |
| kem_ct | 100,000 | 10 | 36 → 36 | 56 | 0 |
| records | 100,000 | 29 | 155 → 166 | 752 | 0 |

The total of 500,000 is the engine execution count, including initial seed evaluations and duplicate evaluations.
It does not mean 500,000 distinct inputs. Total elapsed time was approximately 20.5 seconds,
and all targets reached the run-count limit. `cov` and `ft` are internal engine metrics, not the proportion
of all code checked. Normal termination, rejection of invalid inputs, and agreement with expected outcomes
were checked; no crashes or verdict mismatches were found within this scope.

The final run started from public seeds generated in code, without carrying over a previous experimental corpus.
`result.json` records commands, environment, and SHA-256 hashes of 16 source files;
each target's `instrumentation.json` records actual instrumented functions and runtime file hashes.
At archival time, the current source was confirmed to match these 16 hashes.

`corpus.zip` stores 353 final inputs under `<target>/corpus/<filename>`.
libFuzzer's SHA-1 names and initial SHA-256 names are retained unchanged.
These are public vectors, public fixed keys, and fuzzer-mutated inputs; they contain no operational secrets.
After extraction, reuse them through `--corpus-from` or reproduce individual files with
`python -m fuzzing.replay --target target filename`.
All 353 were rerun without Atheris, confirming no verdict failures;
results are recorded in `corpus-replay.json`.

## Control Check of Success Verdicts

`initialization-only-control/` is a deliberately failing record
for a run that did not execute enough input mutations. Reusing the existing records corpus
with `--runs 100`, libFuzzer performed 169 executions for initialization alone and returned exit 0.
The supervisor confirmed that total executions equaled initialization executions,
recorded the overall status as `failed`, and returned exit 1. This control checks that insufficient testing
is not displayed as green success; it is neither a discovered vulnerability nor a crash.

This control ran while the initialization-verdict unit test file was being extended,
so that file's hash in the control record may differ from the final record. Runtime and runner
behavior were not changed to fit the results. Original JSON and logs were not modified.

The 24 tests in `harness-tests.log` verify that the validator actually catches incorrect acceptance/rejection, tampered normal decryption results,
and sequence-number/key-reference regressions, and check the supervisor's failure verdicts.
`saved-regressions.log` explicitly records 0 saved actual failing inputs
as `no_saved_regressions`.

## Existing Functional Regression

`functional/` contains original records from rerunning the existing `ci/validate.py` in the same environment.
With local loopback sockets allowed, the run passed the following.

| Check | Result |
| --- | --- |
| Python protocol | 85 passed |
| Diagnostic result parser | 6 passed |
| C–Python comparison | 9 passed |
| Rust library | 52 passed, 2 separate taint tests ignored |
| Rust compile-fail documentation | 4 passed |
| Rust release build and real TLS | Build succeeded, 35 passed |

Memory diagnostics, constant-time measurements, and cryptographic security evaluation were excluded from this run.
C, Rust, and OpenSSL machine-code coverage was not collected. This does not resolve the existing 48-byte memory
warning or declare full completion of adversarial-input checks under item 3.

`SHA256.json` covers record files in this directory. Whitespace in engine logs and
absolute paths from execution time are preserved unchanged.
