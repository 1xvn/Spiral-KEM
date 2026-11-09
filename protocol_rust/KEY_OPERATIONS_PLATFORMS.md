# Operational key management: OCI ARM/WSL validation collection

Revalidate PR #28's key file policy and management CLI in two Linux environments. Existing secret-flow
material's Rust70 or Memcheck160 counts are not reused as results for the new key management code.
This collector does not modify the runtime, cryptographic algorithms, or wire format.

## Execution scope

* Rust1.99.1 normal library tests: **81 passed, 0 failed, 5 ignored, 0 filtered**.
  The 5 ignored tests are explicitly recorded and not counted as passing in this run.
* Build new release executables from the same pinned sources.
* Key management and actual loopback TLS cold rotation: **11 passed, failure/error/skip0**.
  Includes key file permission/path/link rejection, concurrent creation/overwrite prevention, checking output for secret values,
  matching public values of copied recovery files, rejection of old pins, and success with new pins.
* Collect the pinned source manifest, source/binary hashes before and after execution, tool versions, original logs, and results.
  Refuse execution if the source manifest changes.

This does not run full functional CI, the scratch matrix, the separate 35 TLS tests, Memcheck/ASan, fuzzing, long-term load,
external vaults, encrypted backups, or actual operational recovery. It also grants no constant-time, full memory,
full goal2/5, or production deployment approval.

The OCI label is a user-assigned name for ARM64 Linux runs. The collector does not verify OCI accounts or
cloud provider identity. The WSL label requires x86-64 Linux and a Microsoft
kernel identifier. Local preliminary checks must use `--platform local`.

## Preparation

Run as a normal Ubuntu24.04 user on the Linux home filesystem. Do not run as root or
place sources/builds/results under WSL's Windows `/mnt/c` path. Do not supply actual service keys.
Tests use keys in a separate0700 temporary directory and exclude that path from results.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv build-essential pkg-config libssl-dev openssl
rustup which --toolchain 1.99.1 rustc
```

Reuse Rust/Cargo1.99.1 from the previous validation. Do not automatically substitute another version or
install a new toolchain. If you have a standalone installation instead of rustup, add
`--toolchain-dir /absolute/path/to/rust-prefix` to the execution command.

Pinned Python dependencies are in `protocol_v01/requirements.txt`. The default run creates, installs into, and removes a private temporary
venv. To reuse an existing venv, add the `--python /absolute/venv/bin/python`
option. Version mismatches and `pip check` failures are retained as failed results.
To use only a fully prepared cache, use `--python ... --offline` together.

## Create a pinned validation bundle

Run the following on a preparation machine with repository access. It reads only from the pinned Git commit, so
uncommitted files, existing builds, past evidence, and operational keys are not included.

```bash
python3 tools/build_key_operations_bundle.py --commit HEAD --output-parent /tmp/spiral-key-operations-delivery
```

This creates `Spiral-key-operations-<commit7>.tar.gz` and `bundle.json`. `bundle.json` contains
the full source commit, runtime baseline commit, source count, and manifest/archive SHA256.
The bundle can run without `.git` or GitHub authentication. File order and timestamps are fixed so
archives of the same commit can be regenerated with the same hash. **This is separate from proof of binary
reproducible builds.** Build dependencies are pinned by Cargo.lock, and actual compiler/executable hashes are recorded.

## Run on target machines

Transfer and extract the validation bundle in the Ubuntu home directory on both OCI and WSL. Replace `<commit7>` below
with the value in the actual provided filename. Download instructions for each validation bundle use
pinned filenames. The first run requires a Rust dependency cache or Cargo registry network access.

OCI Ubuntu ARM:

```bash
tar -xzf "$HOME/Spiral-key-operations-<commit7>.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-operations-<commit7>/run_checks.py" --platform oci
```

WSL Ubuntu x86-64:

```bash
tar -xzf "$HOME/Spiral-key-operations-<commit7>.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-operations-<commit7>/run_checks.py" --platform wsl
```

To check only sources before execution, add `--check-only` to the same command. This result is not counted as a functional
pass. Repeated runs use new result directories and new builds. Existing results are
not overwritten. Compilation may continue even if logs stop appearing briefly.

## Submit and interpret results

Both successful and failed runs report a `Spiral-key-ops-*.tar.gz` result bundle at completion. The archive includes only result
JSON, manifests, public tool/source/binary hashes, and original test logs. It excludes test private keys,
temporary venvs, Cargo build directories, and actual ELF files. Reviews requiring ELF reanalysis
need a separate binary submission procedure. Result file SHA256 is for checking transfer corruption;
it does not independently authenticate remote machine identity or result authenticity.

Review result `status`, actual test counts/skips, source commit and manifest hash, Rust host/version,
binary hash, and original logs together before deciding whether both platforms are complete. Do not convert failed
runs or check-only results to successes or count local runs as OCI/WSL runs.

See [operational key management phase1](KEY_OPERATIONS.md) for current file policies and operational scope.
