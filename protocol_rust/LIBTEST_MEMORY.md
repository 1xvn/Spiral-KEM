# Minimal control results for the 48-byte memory warning

2026-11-07, baseline main `adfc055d3531f62dfb9f8e04de69530619f0a9ac`.
Wrote direct reproducers and a runner, then executed six controls.
This record documents the local investigation and the tools and commands used.

## Actual results

| Control program | Normal exit | Memcheck exit | possibly lost | Verdict |
|---|---:|---:|---:|---|
| Empty normal program | 0 | 0 | 0 B | No warning in this run |
| Query current thread information | 0 | 99 | 48 B | Warning reproduced |
| Create thread then join | 0 | 0 | 0 B | No warning in this run |
| Exit after channel receive | 0 | 99 | 48 B | Warning reproduced |
| One empty libtest test | 0 | 99 | 48 B | Warning reproduced |
| One empty libtest test, nocapture | 0 | 99 | 48 B | Warning reproduced |

Each warning case has 1 error and 1 context, with `std::thread` in the allocation stack.
Both libtest cases also have test-runner frames. These can be compared against the existing secret-processing test log's
`std::thread::current::init_current` → `std::sync::mpmc` → `test::run_tests` path.
All controls have 0 definitely/indirectly lost bytes and suppressions,
and 548 bytes still reachable each. Do not combine distinct categories into a 'no leaks' label.

All programs use only the Rust standard library and public constants.
They contain no Spiral, C KEM, TLS, cryptographic libraries, or real secrets.
The channel control gates sending and makes receive time out once to avoid exercising only the fast path.
That timeout is an intentional internal program condition, not a test-process timeout counted as success.

## What was established

**A standard thread/test-runner warning of the same size was reproduced without Spiral code.**
Therefore, the 48-byte observation alone cannot establish a Spiral key-buffer leak;
current-thread, channel, and test-runner initialization are priorities for further root-cause analysis.

This does not prove the existing warning harmless or pass overall memory checking.
Establishing the exact cause in the original environment, live interior-pointer/shutdown lifetime policies, and tool tracking behavior
requires further analysis of the Rust/tool implementations and original conditions.
Original v0.3 failure records, WSL AES-GCM items, and production sources are unchanged.

New result JSON retains `production_memory_passed=false`, `original_finding_resolved=false`.
Runner exit 0 means 'diagnostics completed without omissions'. Child Memcheck exit 99
is preserved as a failure status recording warnings. Unknown errors, incomplete summaries, warning suppression,
malformed output, 0 tests, and process timeouts do not qualify as diagnostic completion.

## Environment and provenance

- Rust **1.99.1**, LLVM 23.1.1: the same Rust version as the existing report.
- New Memcheck uses Debian **Valgrind 3.24.0**; original records used **3.28.0**.
- New controls ran with a **Debian glibc 2.41-12+deb13u4** loader/libc and matching debug symbols.
  The original used Ubuntu glibc 2.39; this environment difference is disclosed.
- Verified downloaded compiler/standard library/Cargo using SHA-256 from the official Rust TLS manifest.
- Verified Debian InRelease signatures using the system trust keyring, then verified the signed Release → package index →
  `.deb` hashes before extracting only into the working folder. No system packages were installed or security settings changed.
- Loader/libc executable bytes were unchanged; matching debug files were placed alongside them according to original GNU debuglink.
  No TLS dependency patches or memory warning suppressions were used.

Provenance and hashes are in `evidence/libtest_memory_20261107/TOOL_PROVENANCE.json`.
Logs, stdout, exit codes, and generated Rust sources are preserved in the same directory.
Built executables are excluded from committed evidence; their hashes are in the results.
All 6 diagnostic result parsing regression checks also passed. All 132 hashes of existing sources/memory follow-up evidence remained unchanged.

## Rerunning

To view existing results only, open `evidence/libtest_memory_20261107/result.json`.
The recorded results and reproduction instructions are available for independent review.

To reproduce on Linux/WSL with tools installed, run the following from the repository root.
Use a new output folder name: an existing folder causes a stop to protect original evidence.

```bash
python3 protocol_rust/diagnostics/libtest_memory.py \
  --rustc "$(command -v rustc)" \
  --valgrind "$(command -v valgrind)" \
  --output benchmark_results/libtest_memory_new
```

To compare using Rust 1.99.1, provide that version's actual `rustc` path.
When using a specific loader/libc, specify both `--loader` and `--library-path`.
The runner does not download tools; both normal and Memcheck runs use the same loader.

## Next work

This stage prepared minimal reproducers and actual control evidence.
Next, connect these diagnostics to automated checks separate from functional tests,
and trace the standard library's 48-byte ownership structure and shutdown lifetime.
Do not change Spiral key cleanup or production TLS algorithms to eliminate this warning.
