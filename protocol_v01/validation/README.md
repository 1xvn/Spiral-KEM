# Additional test results for items 3 and 4

On 2026-11-06 (Korean time), additional test code was written and run against baseline commit `660014afea4e8353b6e5bfbfd91c845b06a35c29`.
Existing runtime and KEM source were unchanged.
This document records test results; it is not service-adoption approval or an independent security-audit report.

## Results

| Test | Actual execution | Observations |
|---|---:|---|
| Structure-based mutation/property checks | 100,268 cases | 0 unexpected exceptions/reference-verdict mismatches |
| Separately written test client ↔ existing server | 16 scenarios, 19 actual TLS sessions | 0 failures/errors/skips |
| Full regression checks | Existing 59 + new 16 = 75 | 0 failures/errors/skips |
| Full decapsulate-call timing diagnostics | 24,000 calls, 4 comparison groups, 3 repetitions each | No repetition exceeded the exploratory threshold `abs(paired t)>4.5` |

Raw results are in `results/fuzz.json`, `interop.json`, `regression.json`, and `timing.json`.
The original 24,000 timing measurements are in `results/timing.csv`; full regression logs are in `results/regression.log`.
`RESULTS.json` links a summary of execution evidence and file hashes.

## Item 3: adversarial inputs and timing diagnostics

Fuzzing here means finite structure-based mutation/property checks with fixed seed `2026110603`.
It does not use coverage feedback; branch/line coverage was not measured.
Actual parser output was compared with acceptance/canonical-encoding criteria written separately from the specification.
Valid inputs were included so an implementation rejecting everything could not pass.

| Main target | Checks | Accepted | Rejected |
|---|---:|---:|---:|
| SKW1 public key | 20,000 | 7,178 | 12,822 |
| SKW1 ciphertext | 20,000 | 7,182 | 12,818 |
| Frame/expected-state header | 20,000 | 5,078 | 14,922 |
| ClientHello grammar | 20,000 | 5,438 | 14,562 |
| AEAD records/replay | 20,000 | 2,500 | 17,500 |

An additional 12 cases rejected inputs up to 8 MiB. The 256 canonically formatted tampered ciphertexts
returned the specified deterministic fallback keys, differing from valid shared keys. Fallback-key checks used
513 decapsulations: 1 baseline plus 2 per input. Keys/seeds are public test fixtures.
Checks also confirmed that record rejection disposes of connection state/key references and subsequent valid input does not revive them.
Observed input acceptance means validity under the parser grammar, not authentication of forged signatures/ciphertexts.

Timing diagnostics pinned affinity to CPU 4 and used adjacent measurement pairs in randomized order.
Each comparison group repeated 1,000 measurements per class 3 times. The full public `decapsulate` call was measured;
warm-up was separate and no outliers were removed. GC was disabled during measurement.
The environment was virtualized Linux with Python 3.12.14; other system activity and frequency changes were not fully controlled.

- **Negative control:** Identical valid key/ciphertext calls were split into two labels. Paired t by repetition was approximately −0.13, 0.52, −1.09.
- **Public-input comparison:** Valid/canonically tampered ciphertexts under the same key were compared. This alone cannot establish secret leakage.
- **KeyGen-consistent secret comparison:** The same s/public key/canonical tampered ciphertext were retained, changing only fallback_secret, which KeyGen generates independently. Both are normally permitted secret-key states.
- **Synthetic secret stress diagnostic:** s was changed arbitrarily under the same public input/public key. These keys pass input-type checks but are not KeyGen-consistent, so results do not indicate successful attacks against actual keys.

Maximum `abs(paired t)` across 12 measurement blocks was approximately 2.07. Auxiliary Welch t and
mean/median/max/min/pair differences were also recorded in JSON. A positive control added an actual
50 μs CPU wait to one side of a simple function and detected a difference exceeding the exploratory threshold.
This positive control checks whether the analyzer detects an obvious difference; it does not evaluate sensitivity
to 50 μs leakage in full decapsulation.

`abs(t)>4.5` is an exploratory threshold, not a multiple-comparison-adjusted significance claim or leakage bound;
measurements may be correlated. Effect signs changed between repetitions, and system noise was observed.
**Failure to find a signal here does not prove constant-time behavior.** This local diagnostic repeatedly
calling the same key also differs from the protocol's 1-query-per-key model. These measurements cannot exclude physical/cache/WAN leakage or
attacks against the full s of actual keys.

## Item 4: independent test client and actual TLS

`independent_peer.py` is a test client written separately from the specification.
It does not import runtime wire/handshake/records/TLS client helpers; frames,
transcripts, HMAC-based HKDF, Finished, AEAD, and raw pyOpenSSL connection handling are calculated separately.
It shares the KEM algorithm and cryptographic libraries. Thus it is more independent than tests where both existing roles call the same protocol
helpers, but it is not an independently operated implementation audited by an external team.

Actual loopback TLS 1.3 confirmed:

- 1-byte and 16 KiB plaintext round trips, matching final transcript/exporter, authenticated CLOSE in both directions.
- Separate sessions/TLS exporters/KEM public keys for every new connection.
- Incorrect exporter/service rejected before key generation; incorrect additional server pin rejected.
- Forged client Finished/canonical tampered ciphertext do not establish sessions.
- Early DATA, another session's ClientKey, duplicate ClientKey, and truncated ClientKey rejected.
- Tag/direction/skipped-sequence errors rejected without plaintext delivery. Replayed valid records delivered only the initial 1 time.
- EOF without Spiral CLOSE not treated as normal shutdown.
- Every server key decapsulated at most 1 time. Rejection tests were also checked not to pass merely due to timeout.

Including existing regression checks for TLS trust failure, absolute deadlines, send-queue/shutdown races, usage limits,
admission limits, pin revocation/validity, and nonce-reuse prevention, 75 tests passed in total.
External networks, long-term load, client-role testing against an independent server, formal verification, and external audits remain outstanding.

## Reproduction

Use Python with pinned dependencies from the repository root. Paths below are examples for the current cloud environment.
File hashes are recorded in result files; preserve new results separately if scripts change.

```sh
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m protocol_v01.validation.fuzz_campaign
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m protocol_v01.tests.test_independent_peer
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m protocol_v01.validation.timing_probe --pairs 1000 --repetitions 3
PYTHONDONTWRITEBYTECODE=1 /workspace/spiral-protocol-v01/venv/bin/python -m unittest discover -s protocol_v01/tests -v
```

TLS tests require loopback-socket permissions. Run timing diagnostics separately without overlapping other tests.
Fixed seeds generate test inputs only; actual TLS test keys/randomness are freshly generated for each connection.

## Completion assessment

Additional tests and reproduction tools for items 3 and 4 are prepared. No new input-validation/protocol
bypass was reproduced in this scope. However, absence of secret leakage in item 3 and service-level security in item 4 are not
declared complete. Next steps are long-term coverage-guided fuzzing, side-channel evaluation on more controlled equipment and
low-level implementations, bidirectional interoperability with an independent full implementation, and external protocol review.
