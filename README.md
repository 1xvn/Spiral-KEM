# Spiral KEM Research Repository

This repository organizes research code, experimental materials, and documentation for each version of Spiral KEM.

> **Research implementation.** This is not cryptography validated for production services; do not use it to protect real secrets. Constant-time behavior is also not guaranteed for the Python implementation.

## Directory Guide

| Path | Contents |
| --- | --- |
| [code/opt2/](code/opt2/) | Original v0.3.1, opt1, and opt2 code; comparison and verification scripts |
| [protocol_rust/](protocol_rust/README.md) | Rust/Tokio/rustls–C KEM communication implementation, Python interoperability tests, and measurements |
| [native_research/](native_research/README.md) | C KEM research implementation and adversarial-input and memory-check records |
| [originals/](originals/) | Earlier code versions, benchmark scripts, mathematical specifications, and explanatory materials |
| [archives/releases/](archives/releases/) | Original opt1 and opt2 release ZIPs |
| [archives/benchmarks/](archives/benchmarks/) | Original ML-KEM comparison ZIPs |
| [archives/research/](archives/research/) | Original ZIPs evaluating 6 candidates and estimating attack costs |
| [results/](results/) | Saved measurement-result ZIP |
| [imports/](imports/) | Files saved under temporary names and incomplete fragments from earlier uploads |

The research notes site is available at [Spiral KEM Research Notes](https://spiral-kem-research.ideal-goose-1500.chatgpt.site/). Its source is not currently included in this repository.

## Running opt2

After downloading the repository in Windows PowerShell:

```powershell
cd code/opt2
py -m pip install -r requirements.txt
py compare_spiral_opt2_mlkem.py
```

Python 3.10 or later is required. After regression checks, the comparison script runs 30 warmups and 300 measurements by default and saves the result JSON in the script directory. See the [opt2 guide](code/opt2/README.md), [wire format specification](code/opt2/COMPACT_WIRE_SPEC.md), and [experimental results](code/opt2/RESULTS.md) for details.

## Research Communication Protocol v0.1

[`protocol_v01/`](protocol_v01/README.md) contains a local experimental implementation integrating OPT2 with real TLS 1.3 connections.
It includes server pin authentication, TLS exporter binding,
Finished verification, directional AEAD keys and sequence numbers, 1 decapsulation per key, and shutdown handling.
See its guide for instructions and validation scope. Security validation for production services and
interoperability validation between independent implementations have not been completed.

## Constant-Time Implementation and Secret Management Design

[Design proposal 2](hardening/item2/hardening.md) reviews Python secret-processing paths and
key lifetimes and compares a native secret engine with process-isolation alternatives.
The recommendation is a native engine using fixed-size arithmetic and opaque handles.
This document is a design proposal as of `7c859d9`. For the C KEM and Rust–C communication path
later added as separate research implementations, see the running instructions above.
Neither the design proposal nor the research implementations indicate completed constant-time validation.

## Archive Status

[Automated checks guide](ci/README.md): provides functional checks on pushes and PRs and separate scheduled memory diagnostics.
Passing functional checks is not treated as approval of overall memory safety, constant-time behavior, or cryptographic security.

The 48-byte `possibly lost` item was reproduced without Spiral in the [minimal standard-library/test-runner control](protocol_rust/LIBTEST_MEMORY.md).
The original failure verdict and incomplete overall memory-safety status are retained.

Rust–C v0.3 provides [running instructions](protocol_rust/README.md), an [implementation report](protocol_rust/HARDENING_v0.3.md), and a [validation record](protocol_rust/VALIDATION.md). It strengthens signing-key ownership and cancellable concurrent shutdown and passed 52 unit, 4 compile-rejection, and 35 real TLS tests. The [November 7 memory investigation](protocol_rust/MEMORY_FOLLOWUP.md) records 6 passes on OCI and 2 on WSL and reproduces a local Valgrind false-positive mechanism for the AES-GCM warning. The original WSL failure and the 48-byte possibly-lost item in Rust instrumentation tests are retained. These results do not establish production-service security validation or Spiral's own security.

`results/results.zip` is a previously uploaded result bundle and does not imply that all measurement results are included. Only some fragments of the large original design files are retained, so they cannot be reconstructed from this repository alone. See the [temporary upload guide](imports/README.md).
