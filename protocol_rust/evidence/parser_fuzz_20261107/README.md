# Rust frame/ClientHello fuzzer local validation · 2026-11-07

The official nightly-2026-11-07 / Rust 1.101.0-nightly commit
`c980177d81d16f843a500905ac98c0cf3af1fd8d` was installed separately on Debian 13 x86-64 and run.
We also actually ran the user installation script that verifies the official manifest and component SHA-256 hashes.
Installation was confined to the working directory, preserving the existing Rust 1.99.1 configuration.
New Rust results for OCI ARM64/WSL2 are not yet available.

## Actual campaigns

| Run / target | Actual engine executions | Initial → final cov | Final ft | Final saved inputs compared with Python | Verdict |
| --- | ---: | --- | ---: | --- | --- |
| Short run / frame | 2,000 | 69 → 69 | 99 | 74/74 matched | Pass |
| Short run / hello | 2,000 | 139 → 142 | 231 | 65/65 matched | Pass |
| Long run / frame | 100,000 | 69 → 69 | 99 | 129/129 matched | Pass |
| Long run / hello | 100,000 | 139 → 149 | 266 | 107/107 matched | Pass |

Initialization execution counts were 42 for frame and 54 for hello, and execution continued afterward.
Execution counts include initialization and evaluation of duplicate inputs. They are not counts of distinct inputs.
Both campaigns enabled ASan, leak checks, debug checks, and overflow checks,
with no errors, crashes, or independent oracle mismatches. Python comparison checks the
finite inputs in the final saved corpus; it does not mean Python ran every live mutation.

The short run used code commit `0fa91a2`; the long run used
`443c6c3`, which adds four progress output lines. The actual Rust parser, oracle, and driver logic are identical.
The source hashes in each bundle were checked against the corresponding immutable commit.

`smoke-2k.tar.gz` and `local-100k.tar.gz` are the original automatically generated bundles.
They include engine logs, saved corpora, Rust rerun JSON for Python comparison, compilation commands,
and coverage evidence. They contain no build/compiler binaries.
When archiving, we verified that the internal SHA256.json covers all other files and every hash matches.
`local-result.json` is a copy for reading the original long-run verdict without decompression.

## Evidence of actual parser feedback

Only the `spiral_protocol` library receives sancov passes, 8-bit counters, PC tables,
and comparison tracing from the compilation wrapper. The Rust driver and independent oracle crate do not receive them.
ASan is applied separately. LTO is disabled.

The runner passes only when all the following evidence is present.

- Verification of actual rustc arguments, LLVM IR paths, and SHA-256 hashes for the library and three drivers.
- Verification of counter accesses in the actual IR definitions of `Header::parse`, `wire::parse`, the two test entry points, `parse_hello`, and `validate_identity`.
  Comparison tracing in the substantive parser definitions is also checked.
- Verification that driver/independent oracle IR contains no counter sections, generated counters, or tracing callbacks.
- Matching hashes for the final ELF and audited link output, and verification of parser symbols, disassembly, and tracing calls.
  Optimized, inlined `wire::parse` is verified through the DWARF inline chain in the final executable.

The bundle's `coverage/` retains full IR hashes, excerpts from six parser definitions, and final disassembly.
Although the entire protocol library was instrumented, these results cover the frame/ClientHello paths
reached by the inputs. They do not represent coverage of the C KEM, OpenSSL, or prebuilt Rust standard library.
Do not interpret `cov` or `ft` as an overall code coverage percentage or add counts from different targets.

## Regression checks and boundaries

All 38 new tests of the Python reference, installation, execution, and instrumentation verdicts passed.
The 7 independent Rust oracle tests also passed. These include controls rejecting false instrumentation claims, missing verdicts,
invalid fields/duplicate JSON keys, initialization-only runs, sanitizer errors, and incomplete archives.

Using stable Rust 1.99.1, the existing functional runner passed 85 Python tests, 9 C–Python tests,
52 Rust library tests (2 separate ignored taint tests), 5 default feature-off compile-fail documentation tests,
35 real TLS tests, and 6 diagnostic parser tests. Original logs are in `functional/`.
With the test feature enabled, 56 library tests (2 ignored) and the 4 existing authentication boundary compile-fail tests
passed, as recorded in `feature-unit.log` and `feature-doc.log`.

`parser-fuzz` is disabled by default and exposes only two thin entry points calling the parsers.
No APIs that construct sessions/keys or an authenticated state were added.
We checked the GitHub workflow YAML syntax, conditions, and read permissions, but actual GitHub runner results
must be checked separately in the corresponding Actions run.

These results are finite runs of the frame/ClientHello parsers. They do not approve all record states, all TLS authentication,
constant time behavior, resolution of existing memory diagnostic warnings, or Spiral's own security.
Execution procedures for both platforms are in the [Rust parser fuzzing guide](../../FUZZ_PARSERS.md).
