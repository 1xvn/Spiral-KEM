# OCI ARM64 · WSL2 x86-64 Rust parser fuzzing

Use the existing `~/Spiral-native-ct-fuzz-20261107` working folder and already configured Git authentication.
Run separately on OCI Ubuntu 24.04 ARM64 and WSL2 Ubuntu 24.04 x86-64,
using **the same recorded source commit for the campaign on both platforms**.
These checks target Rust's two frame/ClientHello parsers.

## 1. Prepare the same source in both environments

Run in the Ubuntu terminal reached through existing SSH on OCI, or in the Ubuntu app's
Run the following in a Linux terminal. Place the WSL working folder in Linux home `~/`.

```bash
git -C "$HOME/Spiral-native-ct-fuzz-20261107" fetch origin refs/heads/spiral-rust-parser-fuzz-20261107 &&
git -C "$HOME/Spiral-native-ct-fuzz-20261107" worktree add --detach "$HOME/Spiral-rust-parser-fuzz-20261107" FETCH_HEAD &&
cd "$HOME/Spiral-rust-parser-fuzz-20261107" &&
git rev-parse HEAD
```

Proceed **after confirming that the displayed commit matches the campaign's recorded source commit**.
If a command fails or the commit differs, inspect that output first. If the new working folder already
exists, do not delete it; use a new name such as `Spiral-rust-parser-fuzz-20261107-v2`
in both `worktree add` and `cd`.

```bash
uname -m
python3 --version
clang-18 --version
command -v cc c++ make nm objdump pkg-config
```

OCI must report `aarch64`, WSL `x86_64`, and Python must be 3.12 or later.
Use the previously prepared Git, Python, Clang 18, LLVM 18, and `libssl-dev`.
If the checks above show missing build tools, add only the following packages.

```bash
sudo apt-get update &&
sudo apt-get install -y build-essential binutils pkg-config
```

## 2. Install dedicated Rust tools and run unit checks in both environments

Run from the new working folder. From the official Rust distribution server's **2026-11-07 nightly**,
install `rustc`, Cargo, and the standard library for the current CPU into a separate folder.
The pinned Rust version is `1.101.0-nightly`, with compiler commit
`c980177d81d16f843a500905ac98c0cf3af1fd8d`.

```bash
python3 -S protocol_rust/fuzzing/install_toolchain.py --prefix "$HOME/Spiral-rust-parser-tools-20261107"
```

This installation requires neither `sudo` nor rustup, and does not change the existing Rust installation, `PATH`, or repository
default toolchain setting. Verify download hashes, installed versions, and CPU,
and retain a completion record. Repeating the same command validates the completion record and installation
and reuses it. If installation fails, preserve existing files and the adjacent `.downloads` folder,
and change `--prefix` to a new name such as `Spiral-rust-parser-tools-20261107-v2`.
The fuzzing commands' `--toolchain-dir` below must use that same name.

After installation succeeds, run unit checks. No additional Python packages or venv are needed.

```bash
python3 -S -m unittest discover -s protocol_rust/fuzzing -p 'test_*.py' -v
```

If checks end with `OK`, run the next command for that environment.
Record unit check success and actual fuzzing results separately.

## 3. Run on OCI

```bash
python3 -S protocol_rust/fuzzing/campaign.py --label oci --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --runs 100000 --seconds 60 --output "$HOME/Spiral-Rust-parser-oci-20261107"
```

## 4. Run on WSL

```bash
python3 -S protocol_rust/fuzzing/campaign.py --label wsl --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --runs 100000 --seconds 60 --output "$HOME/Spiral-Rust-parser-wsl-20261107"
```

Run `frame` and `hello` sequentially. **Each target is limited to 100,000 executions or 60 seconds**,
whichever comes first. This does not mean all 100,000 executions will run.
The first Cargo build may take several minutes or longer for dependency downloads and compilation.
Total work also includes building, fuzzing both targets, comparing saved inputs, and compression.

The following **`.tar.gz` file is automatically created** next to the result folder. No separate compression command is needed.

- OCI: `~/Spiral-Rust-parser-oci-20261107.tar.gz`
- WSL: `~/Spiral-Rust-parser-wsl-20261107.tar.gz`

The bundle contains result JSON, logs, coverage evidence, and public inputs.
It excludes `build/` artifacts and separately installed compiler binaries.
Preserve failed-run results too. If the result folder or same-named archive already exists,
the runner stops without overwriting; change `--output` to something like `Spiral-Rust-parser-oci-20261107-v2`
or `Spiral-Rust-parser-wsl-20261107-v2`. Change the download filename accordingly.

## 5. Result checks and scope

Check `result.json` in each results directory.

- Both `commit` values must match the final instructions' commit; `source_sha256` must match each other.
- `sources_match_head` and `sources_unchanged_during_run` must be `true`.
- Overall `status` must be `passed`; `coverage.status` must be `verified`.
- `targets` must include both `frame` and `hello`, each with `status` `passed` and `engine_exit` 0.
- Each `feedback.executed` is the actual execution count. It must exceed `initialization_executed`,
  with coverage/feature feedback present.
- Each `differential.status` must be `passed`, `checked_files` must equal `expected_files`,
  and `mismatches` and failure-input `artifacts` must be empty.

During live fuzzing, **for every input, an independent Rust oracle** is compared with the actual Rust parser for acceptance/rejection
and accepted fields; frame comparisons also include reserialized bytes.
After completion, **the final saved corpus** is
rerun in Rust and compared against a separate Python oracle using only the standard library.
Python comparison counts are finite saved input counts, separate from live execution counts.
This does not mean every live mutation also ran in Python.

Frames receive original bytes including the 40-byte header, with no selector prefix byte.
ClientHello receives payload excluding the header. Checks cover role, length, sequence number, suite,
DNS name, service, sorted proposal lists, and canonical byte representations.

Coverage feedback instruments only the Rust protocol crate, not drivers or oracles.
The runner checks compiler commands, LLVM IR, and parser disassembly in the final executable
to retain actual parser instrumentation evidence. `cov` and `ft` are not percentages of total code checked,
and values are not summed across targets or CPUs. Do not interpret this as measured coverage of native C, OpenSSL, or the prebuilt
Rust standard library.

The dedicated `parser-fuzz` feature is disabled by default and exposes only thin entry points calling existing parsers.
It adds no API that opens authentication or session creation boundaries.
These checks do not approve full authentication/session state, constant-time behavior, or cryptographic security.
ASan/leak diagnostics, panics, verdict mismatches, and missing instrumentation evidence remain execution failures.

In user-submitted results dated 2026-11-07, OCI ARM64 and WSL2 x86-64 each executed both targets
100,000 times. OCI saved inputs were frame 125 and hello 108;
WSL saved frame 142 and hello 106. Original replay output was independently compared with Python,
and all matched. Verified the same `fe2cdc1` commit, 39 source files, and pinned Rust tools,
with no sanitizer errors, crashes, panics, or verdict mismatches.
Evidence is recorded in the [submitted result validation summary](evidence/parser_fuzz_20261107/platform-review.json).
Earlier C fuzzing, Python fuzzing, local runs, and these two platform runs are recorded separately.
In local Debian validation, each target executed 100,000 times; final saved inputs
all matched Python: frame 129 and hello 107.
Validation evidence and existing functionality regression results are in the [local record](evidence/parser_fuzz_20261107/README.md).

## 6. Transfer archives to Windows

In WSL's **Ubuntu terminal**, open the home folder
and copy `Spiral-Rust-parser-wsl-20261107.tar.gz` to Windows.

```bash
explorer.exe "$(wslpath -w "$HOME")"
```

Download the OCI file using the existing SSH key. Run the following in **Windows PowerShell**.
When prompted, enter the full key-file path, host, and username used for existing SSH access.
Do not add quotes around the entered path. Do not enter key contents.

```powershell
$OciKey = Read-Host "Full path to existing OCI SSH key file"
$OciHost = Read-Host "Existing OCI IP or host"
$OciUser = Read-Host "Existing OCI SSH username (usually ubuntu)"
scp -i "$OciKey" "${OciUser}@${OciHost}:~/Spiral-Rust-parser-oci-20261107.tar.gz" "$HOME\Downloads\Spiral-Rust-parser-oci-20261107.tar.gz"
```

The two `.tar.gz` files allow checking source, tool-version, and option consistency,
along with actual execution counts, saved-input comparisons, and instrumentation evidence for each target.
