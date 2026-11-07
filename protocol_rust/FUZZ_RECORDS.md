# OCI ARM64 · WSL2 x86-64 Rust DATA/CLOSE state fuzzing

This check targets the Rust record transmitter `Tx` and receiver `Rx`.
It checks normal DATA/CLOSE processing, replay/reordering/tampering, input after shutdown/failure,
record count/byte limits, and reservation of the final CLOSE.
Previously submitted frame/ClientHello results and these state check results are recorded separately.

## 1. Prepare the same source in both environments

Run separately in an Ubuntu terminal reached through existing SSH for OCI, and the Ubuntu app's Linux terminal for WSL.
Use the earlier Rust parser working directory and the Git authentication already configured.
Place the new WSL working directory in the Linux home `~/`.

```bash
git -C "$HOME/Spiral-rust-parser-fuzz-20261107" fetch origin refs/heads/spiral-rust-record-fuzz-20261108 &&
git -C "$HOME/Spiral-rust-parser-fuzz-20261107" worktree add --detach "$HOME/Spiral-rust-record-fuzz-20261108" FETCH_HEAD &&
cd "$HOME/Spiral-rust-record-fuzz-20261108" &&
git rev-parse HEAD
```

Proceed **after verifying that output from both environments matches the campaign's recorded source commit**.
If a command fails, inspect that output before continuing with tests. If the new working directory already
exists, keep it and use a new name such as `Spiral-rust-record-fuzz-20261108-v2`.
in both `worktree add` and `cd`.

```bash
uname -m
python3 --version
command -v cc c++ make nm objdump pkg-config
```

OCI ARM64 is `aarch64`, WSL x86-64 is `x86_64`, and Python 3.12 or later is required.
Use the existing Git/Python/LLVM 18/OpenSSL development environment. If build/evidence tools
are missing, install the packages below.

```bash
sudo apt-get update &&
sudo apt-get install -y build-essential binutils libssl-dev pkg-config llvm-18
```

## 2. Check pinned Rust tools and run unit tests

Reuse the dedicated official **nightly-2026-11-07** installation from the earlier parser checks.
The commands below verify the completion record, version, and CPU. On environments where it is not yet installed,
they install `rustc`, Cargo, and the standard library for the current CPU in a new directory.

```bash
python3 -S protocol_rust/fuzzing/install_toolchain.py --prefix "$HOME/Spiral-rust-parser-tools-20261107"
```

The compiler is `1.101.0-nightly`, commit
`c980177d81d16f843a500905ac98c0cf3af1fd8d`. Installation requires neither `sudo` nor rustup,
and changes no existing Rust installation, `PATH`, or repository default toolchain settings.
If you used a different name for the earlier installation, change both `--prefix` above and `--toolchain-dir` below
to the actual installation directory. For an incomplete installation, preserve its files and adjacent `.downloads`
directory and install with a new `--prefix` name.

Once installation verification succeeds, run the unit tests below.
No additional Python packages or venv are required.

```bash
python3 -S -m unittest discover -s protocol_rust/fuzzing -p 'test_*.py' -v
```

If the tests end with `OK`, run the next command for that environment.

## 3. Run on OCI

```bash
python3 -S protocol_rust/fuzzing/campaign.py --suite records --label oci --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --runs 100000 --seconds 60 --output "$HOME/Spiral-Rust-record-oci-20261108"
```

## 4. Run on WSL

```bash
python3 -S protocol_rust/fuzzing/campaign.py --suite records --label wsl --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --runs 100000 --seconds 60 --output "$HOME/Spiral-Rust-record-wsl-20261108"
```

The single `record` target runs **up to 100,000 executions or 60 seconds**, stopping at whichever limit
comes first. This does not mean all 100,000 executions occur. Downloading dependencies and
compiling the initial build may take several minutes or more. Total time includes model unit tests, building,
instrumentation verification, fuzzing, saved input comparison, and archiving.

The following `.tar.gz` file is generated automatically beside the results directory, so no separate archiving is needed.

- OCI: `~/Spiral-Rust-record-oci-20261108.tar.gz`
- WSL: `~/Spiral-Rust-record-wsl-20261108.tar.gz`

The bundle contains result JSON, original logs, instrumentation evidence, public input corpora, and comparison output.
Executables under `build/` and the separately installed Rust tools are excluded. Preserve bundles
from failed runs too. Existing result directories or archives with the same name are not overwritten.
For a rerun, use a new name, for example by appending `-v2` to `--output`,
and change the download filename below accordingly.

## 5. Results and scope

Check the following in `result.json` in each results directory.

- `commit` in both environments must match the final instructions, and their `source_sha256` values must match each other.
- `sources_match_head` and `sources_unchanged_during_run` must be `true`.
- Overall `status` must be `passed`; `coverage.status` must be `verified`.
- The `record` entry under `targets` must have `status: passed` and `engine_exit: 0`.
- `feedback.executed` is the actual execution count and must exceed `initialization_executed`.
- `differential.status` must be `passed`, and `checked_files` must equal `expected_files`.
  `mismatches` and failure input `artifacts` must be empty.

Each input consists of an initial boundary scenario/role and up to 64 commands.
It combines DATA/CLOSE transmission, delivery of saved frames, replay/reordering/tampering,
frames constructed with separate authentication tags, and raw bytes. It includes maximum and oversized DATA,
states just before/at record count/byte limits, and invalid CLOSE reasons.
Boundary scenarios set counters at the start of the test to check both transmitting roles.
They do not mean communication actually ran long enough to reach the limits.
The input format and output schema are in the [record input specification](fuzz/RECORD_GRAMMAR.md).

During live checks, each input compares actual Rust send/receive code against a separate Rust state model.
Transmitted wire data, received plaintext, error types, sequence numbers, byte counts, close state, and key ownership state
must match after every command. The model AEAD uses `ring`, separate from production's
`chacha20poly1305` implementation. Rerun output includes wire/plaintext lengths and SHA-256 hashes,
and all final saved inputs are compared again against independent Python test reference values.
The Python reference uses only the standard library and is a test AEAD validated against RFC 8439 public
vectors. Do not use it as a service cryptographic implementation.
The number of saved input comparisons differs from the live fuzzing execution count.

The test-only `record-fuzz` feature is disabled by default. It uses fixed public synthetic keys, prefixes,
session IDs, and limit boundary states, and adds no entry point to construct authenticated `Established` or `Session`
values with arbitrary keys. Boundary states are set only at the start of checks,
and sequence numbers used during execution are not rolled back.

Instrumentation feedback is added only to the Rust protocol crate, not to the driver, model, or `ring`.
We verify and preserve compilation commands, LLVM IR, and function evidence from the final executable.
`cov`/`ft` are not overall code coverage percentages (%), and counts are not added across CPUs.
ASan errors, leaks, panics, verdict mismatches, and missing instrumentation evidence are recorded as failures.

The scope is directional low-level `Tx`/`Rx` record state. Bidirectional channel shutdown coordination,
timeouts, sockets/partial writes, and the full handshake/TLS state require separate checks.
Do not interpret this as coverage of native C, OpenSSL, or the prebuilt Rust standard library, or as approval of constant time behavior
This is not interpreted as cryptographic security approval. These OCI/WSL record results must be newly
collected; preceding parser results are not used in their place.

## 6. Transfer result files to Windows

Open the home directory from the WSL Ubuntu terminal and
copy `Spiral-Rust-record-wsl-20261108.tar.gz` to Windows.

```bash
explorer.exe "$(wslpath -w "$HOME")"
```

Download OCI results using the existing SSH key. Run the following command in **Windows PowerShell**.
Enter the full path of the existing SSH key file, host, and username;
do not add quotation marks around the path or enter the key contents.

```powershell
$OciKey = Read-Host "Full path to existing OCI SSH key file"
$OciHost = Read-Host "Existing OCI IP or host"
$OciUser = Read-Host "Existing OCI SSH username (usually ubuntu)"
scp -i "$OciKey" "${OciUser}@${OciHost}:~/Spiral-Rust-record-oci-20261108.tar.gz" "$HOME\Downloads\Spiral-Rust-record-oci-20261108.tar.gz"
```

Submitting both `.tar.gz` files allows verification of matching source/tools/options, actual execution counts,
saved input comparisons, and instrumentation evidence together.

Locally, the same runner with a 60-second limit completed 35,054 actual executions and passed comparisons for
717/717 final saved inputs. Existing parser/functional regressions also passed; detailed evidence is in
the [local record](evidence/record_fuzz_20261108/README.md).
