# Regression Corpus of Failing Inputs

After reviewing an actual failure, store its input bytes as `<target>/<sha256>.bin`.
Current targets are frame, hello, kem_pk, kem_ct, records. Use public test fixtures only.
After fixing the failure's cause, verify that the input receives the correct verdict without weakening the oracle.
The fuzzing runner includes this corpus in its next run. It can also be replayed without the engine using `python -m fuzzing.replay_regressions`.
If no failures have been saved yet, the replayer reports the 0-input status separately and does not count it as passing regression tests.
