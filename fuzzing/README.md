# Coverage-guided Python fuzzing

Atheris 3.1.0 and libFuzzer mutate inputs using feedback from actual Python runtime branches and comparisons.
This runs separately from the fixed-mutation checks in the existing `protocol_v01/validation/fuzz_campaign.py`.
Branches in checking code or test oracles are
excluded from coverage.

## Automatic runs

See **Coverage-guided Python fuzzing** in GitHub Actions.

- push/PR: Up to 2,000 runs or 10 seconds per target.
- Every Monday at UTC 04:29 and **Run workflow**: Up to 100,000 runs or 60 seconds per target.
- Run counts may be lower because of time limits. Actual counts are
  recorded in `feedback.executed` in `result.json`.
- Unexpected exceptions, oracle failures, process failures/timeouts,
  missing instrumentation, and missing execution/coverage feedback are treated as failures.
- Runs that only read the initial corpus and stop are also failures. Engine statistics confirm
  that input mutation actually ran after initialization.
- No coverage increase is normal if starting seeds already covered the branches.
  Runs with execution, coverage, or feature counts of 0 are not treated as successes.

The `python-fuzz-...` artifact on the run page retains original logs, per-target instrumentation lists,
mutated input corpora (`corpus/`), failing inputs (`artifacts/`), and `result.json`
for 14 days. Scheduled runs take effect once the workflow is merged into the default branch.

## Check scope

| Target | Validation | Maximum input length |
| --- | --- | ---: |
| `frame` | Compare frame acceptance/rejection with an independent oracle, byte reserialization | 16,500 |
| `hello` | ClientHello length/identifiers/offer lists, byte reserialization | 512 |
| `kem_pk` | OPT2 public key packed format, coefficient ranges/canonical encoding | 1,024 |
| `kem_ct` | OPT2 ciphertext packed format, coefficient ranges/canonical encoding | 1,280 |
| `records` | Bidirectional DATA/CLOSE, ordering/replay/tampering, usage/time limits, closed state | 4,096 |

The first byte of frame input selects the expected type, role, session, and sequence number from
public test vectors; the rest is the actual frame. Maximum DATA frame seeds are also included.
`records` is a state check executing up to 32 commands. After each command, it compares actual state with
a separate model's sequence numbers, transfer volume, and closed status, and checks successful decryption results, nonce
uniqueness, and release of owned key references after termination. Public fixed test keys and
a virtual clock allow exact reproduction of failing inputs.

Current feedback is limited to Python bytecode. Named nested functions and lambdas are
instrumented, but Atheris may skip some comprehension/generator code.
These checks do not validate C/Rust/OpenSSL machine-code coverage, KEM attack costs/decryption failure probability,
complete erasure of secret memory, or constant-time behavior.
Success in these runs alone therefore does not establish full completion of item 3 adversarial input checks or
cryptographic safety for production services.

## Local execution

On Linux x86-64 with Python 3.12, from the repository root:

```bash
python3.12 -m venv .fuzz-venv
.fuzz-venv/bin/python -m pip install --only-binary=:all: -r fuzzing/requirements.txt
.fuzz-venv/bin/python -m pip check
.fuzz-venv/bin/python -m unittest discover -s fuzzing -p 'test_*.py' -v
.fuzz-venv/bin/python -m fuzzing.replay_regressions
.fuzz-venv/bin/python -m fuzzing.campaign --runs 20000 --seconds 30 --output fuzz-results/local
```

The output directory must be a new path. A single target can be selected, such as `--target records`.
Running Python with `-O` removes assertions and is explicitly rejected.
Per-target input size limits and libFuzzer's 5-second per-input/1,536MB memory limits apply,
with an additional execution time limit enforced by the supervisor process. These limits are not an isolation sandbox.

To reuse inputs learned in a previous run:

```bash
.fuzz-venv/bin/python -m fuzzing.campaign --runs 100000 --seconds 60 --corpus-from fuzz-results/local --output fuzz-results/long
```

`cov` is the number of instrumented branch sites; `ft` is the engine's feature count. These are not
percentages (%) of total code checked, and figures from different targets/instrumentation configurations are not added together.
The execution environment, source SHA-256, and actual instrumented functions are recorded in JSON files.

## Reproduce failing inputs and run regressions

```bash
.fuzz-venv/bin/python -m fuzzing.replay --target records fuzz-results/local/records/artifacts/crash-actual-filename
```

Expected rejection of malformed input is normal. Before changing code to
unconditionally ignore exceptions or assertion failures, first reproduce and analyze
whether the defect is in the runtime or the oracle. Confirmed failing inputs are retained with their fixes
under [`regressions/`](regressions/README.md), named by SHA-256.
If there are no saved inputs, the regression runner reports `no_saved_regressions`
and does not invent pass counts.

## Validation records

[2026-11-07 local validation](evidence/20261107/README.md) retains original engine logs,
instrumentation lists, execution results, and hashes. Results executed on GitHub must be checked separately
on the corresponding Actions run page.
