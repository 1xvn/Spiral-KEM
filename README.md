# Spiral KEM Research Repository

This repository organizes research code, experimental materials, and documentation for each version of Spiral KEM.

> **Research implementation.** This is not cryptography validated for production services; do not use it to protect real secrets. Constant-time behavior is also not guaranteed for the Python implementation.

## Directory Guide

| Path | Contents |
| --- | --- |
| [code/opt2/](code/opt2/) | Original v0.3.1, opt1, and opt2 code; comparison and verification scripts |
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

## Archive Status

`results/results.zip` is a previously uploaded result bundle and does not imply that all measurement results are included. Only some fragments of the large original design files are retained, so they cannot be reconstructed from this repository alone. See the [temporary upload guide](imports/README.md).
