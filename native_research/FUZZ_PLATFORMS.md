# First OCI ARM64 / WSL2 x86-64 C fuzzing comparison

Existing submission environments are OCI Ubuntu 24.04 ARM64 and WSL Ubuntu 24.04 x86-64.
Since both are supported targets, the same source must be built/tested separately on each.
Generic GitHub x86-64 Linux checks or local Debian checks do not substitute for either environment.
CPU architecture, virtualization, and kernel differ together; result differences alone cannot identify the cause.

## Scope of this phase

`fuzz_pk.c` and `fuzz_pk.py` check the first C target: **public-key parsing and common encapsulation paths**.
They call `sp_test_encaps` with fixed public test messages.
They use the same `parse_pk`/`encaps_message` as production, but the randomness wrapper
`sp_encaps`, ciphertext decapsulation, and Rust communication state are excluded from this target.

Acceptance/rejection results are compared against a separate oracle for length/prefix/12-bit coefficient ranges;
error-output-buffer erasure and successful ciphertext canonical formatting are checked.
The oracle is excluded from coverage; actual `spiral_native.c` is instrumented for coverage.
ASan/UBSan/leak checks are enabled; the OpenSSL shared library itself is not instrumented.

## Where to run

| Environment | Terminal | Existing target architecture |
| --- | --- | --- |
| OCI | Ubuntu terminal connected to the instance over SSH | `uname -m` is `aarch64` |
| WSL2 | Linux terminal opened through the Ubuntu app on Windows | `uname -m` is `x86_64` |

For WSL, first run `wsl --list --verbose` in Windows PowerShell and confirm the Ubuntu distribution's
VERSION is2. Preserve actual values if architecture/distribution differs from the table.
Keep WSL repositories/results on the Linux filesystem under `~/`.

## 1. Prepare tools on both environments

Run separately in OCI and WSL Ubuntu terminals.

```bash
sudo apt-get update
sudo apt-get install -y git python3 build-essential clang-18 llvm-18 libclang-rt-18-dev libssl-dev openssl
uname -m
clang-18 --version
openssl version
```

Both use Clang 18. Match patch/Ubuntu-package versions as closely as possible;
compare actual versions through result logs. Build ARM/x86-64 binaries on their respective environments.
Matching sources/seeds/options does not require identical execution counts or `cov`/`ft` values.

## 2. Prepare fresh work folders at the same commit

Start in each environment's existing `Spiral-KEM` repository folder.
The example below assumes the existing copy is `~/Spiral-KEM`.
When reproducing a campaign pinned to a specific source commit, use that hash instead of `FETCH_HEAD`
to match both environments' versions exactly.

```bash
cd "$HOME/Spiral-KEM"
git fetch origin refs/heads/spiral-native-fuzz-platforms-20261107
git worktree add --detach "$HOME/Spiral-native-fuzz-20261107" FETCH_HEAD
cd "$HOME/Spiral-native-fuzz-20261107"
git rev-parse HEAD
python3 -m unittest native_research.test_fuzz_pk_runner -v
```

If the `worktree` target folder already exists, preserve existing results and use another fresh folder name.
Fetching the specified branch into `FETCH_HEAD` also supports repository configurations tracking only main.
The same method applies.

## 3. Run/archive on OCI

```bash
python3 native_research/fuzz_pk.py --label oci --cc clang-18 --runs 100000 --seconds 60 --output "$HOME/Spiral-C-fuzz-oci-20261107"
```

After the process finishes, preserve results even on failure. Run the archive command below separately.

```bash
tar --exclude='build' -czf "$HOME/Spiral-C-fuzz-oci-20261107.tar.gz" -C "$HOME" Spiral-C-fuzz-oci-20261107
```

## 4. Run/archive on WSL

```bash
python3 native_research/fuzz_pk.py --label wsl --cc clang-18 --runs 100000 --seconds 60 --output "$HOME/Spiral-C-fuzz-wsl-20261107"
```

After completion, archive separately even on failure.

```bash
tar --exclude='build' -czf "$HOME/Spiral-C-fuzz-wsl-20261107.tar.gz" -C "$HOME" Spiral-C-fuzz-wsl-20261107
```

Exclude `build/`, which contains executables/objects, from archives.
To copy WSL archives through Windows, open the current Linux folder with `explorer.exe .` or
open the home folder with `explorer.exe "$(wslpath -w "$HOME")"`.
Download OCI files using existing SSH SFTP or `scp`.
The two archives support comparison of the results.

## 5. Verdict and failure reproduction

Check the following in the result's `result.json`.

- `commit` and all5 `source_sha256` entries match on both sides; `sources_match_head` is `true`.
- `platform`, `os-release.txt`, `compiler.log`, and `openssl.log` record each environment's actual conditions.
- `status` is `passed`, `engine_exit` is0, and execution count/`cov`/`ft` are greater than0.
- Execution count exceeds `initialization_executed`, so execution did not end after reading initial seeds only.
- No error/crash inputs. Normal time-limit termination before maximum runs is recorded with actual counts.

LeakSanitizer ptrace/`/proc` restrictions and tool-installation/link failures are not converted to passes.
The runner retains failure exits; it does not automatically disable leak checks or add suppressions.
When failing inputs occur, use logs/reproduction to distinguish tool-environment issues, oracle issues,
and actual runtime defects.

Reproduce failing inputs with `build/fuzz-pk` retained in the same environment.

```bash
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  /actual/result-folder/build/fuzz-pk /actual/result-folder/artifacts/crash-actual-filename
```

First preserve original failing inputs/logs. After fixing confirmed defects, retain them as fixed regression inputs.
A60-second run is an initial compatibility/behavior check, not a criterion for long-term fuzzing, cryptographic security,
constant-time behavior, or completion of all item3.

In submissions received2026-11-07, OCI ARM64 and WSL2 x86-64 each completed100,000 runs.
The same `c9e4075` commit,5 source files, and Clang 18.1.3 were confirmed, with no sanitizer errors or crashes.
All21 OCI result-file hashes and36 WSL result-file hashes matched.
The validation summary is [platform-review.json](evidence/fuzz_platforms_20261107/platform-review.json).
The initially submitted WSL archive was empty; a new file containing valid results was checked.
This verdict is limited to public-key parsing/encapsulation targets and recorded separately from earlier Valgrind/Python checks.
