# OCI ARM64 · WSL2 x86-64 channel/TLS lifecycle checks

These checks verify channel behavior when partial writes, waits, cancellation, concurrent shutdown, and timeouts overlap,
and shutdown/resource return for actual authenticated TLS connections. Run separately from previous parser/DATA/CLOSE state
fuzzing results. Use the same pinned source and tool versions on OCI Ubuntu 24.04 ARM64 and WSL2 Ubuntu 24.04
x86-64.

## 1. Prepare the same source in both environments

Run separately in an Ubuntu terminal reached through existing SSH for OCI, and the Ubuntu app's Linux terminal for WSL.
Run the following. Use the previous record working folder and already configured Git authentication;
Place the new WSL working directory in the Linux home `~/`.

```bash
git -C "$HOME/Spiral-rust-record-fuzz-20261108" fetch origin refs/heads/spiral-channel-lifecycle-20261108 &&
git -C "$HOME/Spiral-rust-record-fuzz-20261108" worktree add --detach "$HOME/Spiral-channel-lifecycle-20261108" FETCH_HEAD &&
cd "$HOME/Spiral-channel-lifecycle-20261108" &&
git rev-parse HEAD
```

Proceed **after verifying that output from both environments matches the campaign's recorded source commit**.
if a command fails, inspect that output first. If the new working folder already exists, do not delete
it; use a new name such as `Spiral-channel-lifecycle-20261108-v2` in both `worktree add` and
`cd`.

```bash
uname -m
python3 --version
command -v cc c++ make nm objdump pkg-config openssl
```

OCI ARM64 is `aarch64`, WSL x86-64 is `x86_64`, and Python 3.12 or later is required.
Use existing Git, LLVM 18, and OpenSSL development tools. If build/venv tools are missing,
install the following packages.

```bash
sudo apt-get update &&
sudo apt-get install -y build-essential binutils libssl-dev pkg-config openssl llvm-18 python3-venv
```

## 2. Verify Rust tools and prepare Python test environment

Reuse the dedicated official **nightly-2026-11-07** installation from previous parser/record checks.
The command below verifies the completion record, version, and CPU; if not yet installed, it installs
`rustc`, Cargo, and the standard library for the current CPU into a separate folder.

```bash
python3 -S protocol_rust/fuzzing/install_toolchain.py --prefix "$HOME/Spiral-rust-parser-tools-20261107"
```

The compiler is `1.101.0-nightly`, commit
`c980177d81d16f843a500905ac98c0cf3af1fd8d`. Installation requires neither `sudo` nor rustup,
and changes no existing Rust installation, `PATH`, or repository default toolchain settings.
If a different folder name was used previously, update both `--prefix` above and `--toolchain-dir` below
to the actual folder. Preserve incomplete installation files and the adjacent `.downloads` folder,
and install with a newly named `--prefix`.

These real TLS tests require the independent Python peer's cryptographic library.
Create a dedicated venv and install the repository's pinned requirements.

```bash
python3 -m venv "$HOME/Spiral-channel-lifecycle-venv-20261108" &&
"$HOME/Spiral-channel-lifecycle-venv-20261108/bin/python" -m pip install --disable-pip-version-check -r protocol_v01/requirements.txt &&
"$HOME/Spiral-channel-lifecycle-venv-20261108/bin/python" -m unittest discover -s protocol_rust/lifecycle -p 'test_*.py' -v
```

Requirements use `cryptography==50.0.2`, `pyOpenSSL==26.4.0`, and matching pinned dependencies.
Once installation/unit checks succeed and end with `OK`, run the next command for the relevant environment.
The runner uses the `--python` venv path, so `activate` is unnecessary.

## 3. Run on OCI

```bash
python3 -S protocol_rust/lifecycle/campaign.py --label oci --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --python "$HOME/Spiral-channel-lifecycle-venv-20261108/bin/python" --rounds 5 --seed 20261108 --output "$HOME/Spiral-channel-lifecycle-oci-20261108"
```

## 4. Run on WSL

```bash
python3 -S protocol_rust/lifecycle/campaign.py --label wsl --toolchain-dir "$HOME/Spiral-rust-parser-tools-20261107" --python "$HOME/Spiral-channel-lifecycle-venv-20261108/bin/python" --rounds 5 --seed 20261108 --output "$HOME/Spiral-channel-lifecycle-wsl-20261108"
```

`--rounds 5` executes the fixed scenario set five times. This is a finite repeated test,
not coverage-guided fuzzing or exploration of all possible schedules. Some shutdown
tests wait for an actual 2-second grace period. Initial dependency download/compilation may take
several minutes or longer; total time includes building, checks, result preservation, and compression.

Automatically creates the following `.tar.gz` next to the result folder. No separate compression is needed.

- OCI: `~/Spiral-channel-lifecycle-oci-20261108.tar.gz`
- WSL: `~/Spiral-channel-lifecycle-wsl-20261108.tar.gz`

Existing result folders and same-named archives are not overwritten. On rerun,
use a new name, such as appending `-v2` to `--output`, and update the download filename too.
Preserve failed-run results as well.

## 5. Check contents and result verification

The runner records these test types separately.

| Type | Behavior checked |
|---|---|
| Synthetic channel loop I/O | Directly inject short writes/waits into actual `write_loop`/`read_loop`. Retain in-progress frames after cancellation; shutdown/pending-send races; shutdown failure/timeouts after CLOSE completion; receive queue saturation and shutdown |
| Actual authenticated Rust TLS connections | After TLS/Spiral authentication on both sides: concurrent shutdown, handling after cancellation of send/receive/close futures, rejection of Sender use after Session disposal, concurrent sends and resource return |
| Actual TLS connections with independent Python peer | Normal shutdown, split application writes, abrupt TCP EOF, TLS shutdown without Spiral CLOSE, Spiral CLOSE without TLS shutdown, extra bytes after CLOSE |

Synthetic I/O tests use fixed public test keys and internal unit-test state.
Real TLS tests use the `Transport` → authenticated handshake → `Established::start` path,
without adding a public API that constructs authenticated sessions using arbitrary keys.
Record actual connection SID/transcript/TLS exporter agreement and observable resource returns.
When the upper API delivers an internal error as `Closed`, do not relabel it as a directly observed
underlying timeout.

Split TCP/TLS transmissions do not prove that Rust `AsyncWrite` returned short writes.
Direct short-write observations are limited to synthetic I/O tests. A test terminated by an external watchdog
is not counted as successful protocol rejection. Normal shutdown verifies authenticated Spiral CLOSE and
TLS shutdown order; abnormal shutdown is recorded as a separate expected-failure scenario.

Check `result.json` and original logs in each result folder.

- Both `commit` values must match the final instructions' commit; `source_sha256` must match each other.
- Test sources must match the commit and remain unchanged during execution.
- Overall `status` and each test suite must be `passed`.
- Each suite's actual scenario list/execution count must match the requested round count.
- Unexpected process failures, panics, sanitizer errors, external watchdog timeouts, and missing tests must be recorded as failures.

Rust test builds use ASan/leak checks and debug/overflow checks.
These results do not collect libFuzzer instrumentation or runtime coverage. They evaluate functionality/cleanup
for tested scenarios; overall memory safety, constant-time implementation, and cryptographic security approval
require separate evaluation. Original adjudication of existing Valgrind warnings is unchanged.

Bundles contain result JSON, original logs, public test observations, and hashes. They exclude `build/`
executables, temporary certificates, private keys, signing seeds, and separately installed Rust tools.
Test credentials are generated fresh during execution and must not be reused for services.
Lifecycle results are collected separately from the preceding record results. The 5 submitted WSL runs
passed record revalidation for all 40 channel cases (135 detailed conditions), 30 Rust TLS cases, and 30 independent peer TLS cases.
OCI lifecycle results await submission; the accompanying previous record bundle
is not added to this phase. For details,
the [submitted result validation summary](evidence/lifecycle_20261108/platform-review.json).

Locally, the same runner passed 5 rounds with 40 channel tests (135 detailed conditions),
30 actual Rust TLS cases, and 30 independent peer TLS cases. Also checked compilation audits,
result bundles, hashes, and exclusion of secret test material.
Actual results and limitations are recorded in the [local validation record](evidence/lifecycle_20261108/README.md).

## 6. Transfer result files to Windows

Open the home directory from the WSL Ubuntu terminal and
Copy `Spiral-channel-lifecycle-wsl-20261108.tar.gz` to Windows.

```bash
explorer.exe "$(wslpath -w "$HOME")"
```

Download OCI results using the existing SSH key. Run the following in **Windows PowerShell**.
Enter the full existing SSH key-file path, host, and username; do not add quotes around the path
or enter key contents.

```powershell
$OciKey = Read-Host "Full path to existing OCI SSH key file"
$OciHost = Read-Host "Existing OCI IP or host"
$OciUser = Read-Host "Existing OCI SSH username (usually ubuntu)"
scp -i "$OciKey" "${OciUser}@${OciHost}:~/Spiral-channel-lifecycle-oci-20261108.tar.gz" "$HOME\Downloads\Spiral-channel-lifecycle-oci-20261108.tar.gz"
```

Submitting both `.tar.gz` files allows comparison of sources/tools/options and actual completion counts/verdicts/cleanup evidence for each suite.
Short GitHub CI runs and OCI/WSL runs are recorded separately.
