# Local concurrent TLS load evidence — 2026-11-11

Status: **passed** for the bounded local campaign. The raw execution records,
source hashes, JSON events, process samples and independent reviews are packaged
with this record. The server and clients ran in one persistent Linux process;
process measurements include both endpoints.

## Measured profile

| Item | Result |
| --- | ---: |
| Verified traffic-epoch duration | 1800.007949 seconds |
| Total wall time including setup and cleanup | 1812.892 seconds |
| Concurrent authenticated connections | 64 |
| Payload per message | 16,384 bytes |
| Pacing target per connection | 50 ms; missed ticks skipped |
| Verified echoed round trips | 2,235,147 |
| Bidirectional payload | 73,241,296,896 bytes / 68.211273 GiB |
| Completed traffic epochs | 8 |
| Authenticated pairs / endpoint handshakes | 518 / 1,036 |
| Native KEM jobs / final live keys | 1,554 / 0 |
| Final active / pending admission leases | 0 / 0 |
| Maximum observed process RSS | 17.910156 MiB |
| Maximum sampled descriptors / threads | 135 / 5 |
| Self-observed descriptor baseline / final | 8 / 7 |

All 1,797 steady traffic samples recorded 64 active and zero pending connections.
The maximum sampled echo-progress gap was 2.808 seconds. Warm-to-tail RSS medians
increased by 544 KiB; this is an observed finite trend and does not establish
absence of small leaks. The listener is present in the initial FD baseline and
closed at completion, so the stronger baseline-minus-one recovery check passes.

The actual per-IP combined admission rule accepted four authenticated sessions
and rejected a fifth; after release/refill, a fresh exchange succeeded. A separate
pending case held 32 real TCP peers, rejected peer 33, observed the production
10-second TLS accept deadlines, then recovered. The global case retained 64
established sessions while rejecting connection 65. No runtime limit was widened.

Separate public-API integration tests isolate the per-IP active guard after token
refill and the rate guard below the active limit; the live four/five case alone
exercises the combined rule. Unit tests also cover established 64 vs pending 32,
32 shared worker jobs, 32 live native keys, cancellation/reuse and bounded buffer
waiter wakeup. Existing exact 18-buffer and full-capacity cleanup tests remain.

## Provenance and reproduction

The experiment ran a dirty working tree based on
`d611077b2c08662b2cc2e63673bb5ea0081ce9be`. All 162 selected source files
were later committed unchanged as
`04ce7d7a7deaea1ca8e6c215bd735fd83e88fd23`. Raw reports retain the original execution HEAD
and dirty flag. The later commit is a source-byte correspondence, not a relabeled
historical execution. Source and binary hashes stayed unchanged throughout the run.

Source tree SHA-256: `908aedf7ab2f74579cef539aa264f14e7433117b194e18edef42f8fd935ac3a7`.

Use [LOAD_TESTING.md](../../LOAD_TESTING.md) to build and execute the collector.
The evidence records an Intel Xeon Platinum 8573C x86-64 cloud Linux host with
five CPUs in the affinity mask and a four-CPU cgroup quota. This is neither an OCI
ARM execution nor a WSL execution; each needs its own result set.

## Functional regression validation

The updated functional runner passed after the soak:

| Check | Result |
| --- | --- |
| python-protocol | passed (85 tests) |
| diagnostic-parser | passed (24 tests) |
| load-collector-contracts | passed (18 tests) |
| native-kem | passed (9 tests) |
| rustc-version | passed |
| cargo-version | passed |
| rust-unit | passed (100 tests); 5 ignored instrumentation tests excluded |
| rust-admission-boundaries | passed (2 tests) |
| rust-scratch-cleanup | passed |
| rust-doc | passed (6 tests) |
| rust-release | passed |
| rust-key-operations | passed (11 tests) |
| rust-key-recovery | passed (20 tests) |
| rust-tls | passed (35 tests) |

An initial UID-mapped sandbox attempt refused private-file operations. The policies
were retained; the real-UID library rerun and full functional runner passed. The
initial attempt remains in the package as an environment diagnostic.

## Evidence files

- `review.json`: independent file/hash/count/duration/FD checks.
- `peer-review.json`: separate read-only event/sample/provenance audit.
- `source-commit-review.json`: selected source bytes matched against the committed source.
- `Spiral-load-local-x86_64-20261111.tar.gz`: raw collection, public source copies,
  environmental/build records and functional-check outputs.
- `SHA256.json`: integrity inventory for this evidence directory.

Fresh test credentials lived outside the result directory and were removed.
The package contains no private-key files, authentication seeds or executable
probe binary. Source copies and hashes identify the executed instrumentation.

## Scope

This is a 30-minute closed-loop laboratory workload with sequential handshake
setup and periodic session replacement. Traffic time includes bounded close and
excludes replacement setup. Individual connections do not exceed the unchanged
session age. The workload does not establish maximum service capacity, hostile
handshake-flood resilience, authenticated idle/age expiry behavior, slow-reader
resistance, day-long stability, memory-erasure guarantees or cryptographic security.

Resource ceilings (512 MiB RSS, 256 sampled FDs, 64 sampled threads) were experiment
stop thresholds. They were not operating-system RLIMITs or production capacity
contracts. Original strict memory and constant-time approval gates remain unchanged.
