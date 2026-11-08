# Local cleanup-patch microbenchmark

Same Rust 1.99.1, opt-level 3, thin LTO, one codegen unit, panic=unwind.
Baseline uses registry versions; candidate uses the five pinned local patches.
SHA state/HMAC/Ed25519 zeroize is enabled for both; HKDF internal scratch
zeroize is the additive candidate feature. Package versions are identical.

HMAC-SHA256 initialization/update/finalize, HKDF-SHA256 extract+expand32, and
Ed25519 try_sign use public constant seed 0x42 and payload byte 0x5a. Input
lengths: 0, 1, 63, 64, 65, 1024, 16384 bytes. Each case warms up 100 operations.
Timed iterations are 20000/10000/2000 respectively. Repetitions: seven. Binary
process order alternates baseline/candidate and candidate/baseline by trial.
The same fixed stack result normalization and black_box overhead is included.
Payload allocation and SigningKey construction are outside the timed body.
Each run pins to CPU 4; available affinity and load averages are in result.json.

All 21 public outputs match across both variants and every repeated run.
Raw JSONL and aggregated raw-samples.json preserve per-case elapsed time.
result.json contains min/median/max and raw seven samples for each case.
Source hashes before/after, binary hashes, toolchain, package versions and
profile are retained. No repository source or registry source files were edited; Cargo was offline.

This is warm-cache primitive timing in a shared environment, not a service/TLS
latency or peak memory benchmark. Ratios are descriptive and no p-value,
statistical significance, performance budget acceptance or security approval
is claimed. Values from different input lengths should not be collapsed into
a single workload result. summary.json's range/median is for quick navigation.
