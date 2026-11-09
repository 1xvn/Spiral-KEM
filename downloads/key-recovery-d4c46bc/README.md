# OCI·WSL encrypted backup/recovery validation bundle

Download [Spiral-key-recovery-d4c46bc.tar.gz](Spiral-key-recovery-d4c46bc.tar.gz).
Use **Download raw file** on the GitHub file page and keep the filename unchanged.
On Windows, save to Downloads. Transfer to `/home/ubuntu/` on OCI using the existing scp method.
No repository clone or GitHub terminal password is required.

Pinned source: `d4c46bc81012e095ab8c78ac6e362ce2b6a63798`.
Baseline main: `d2f19b9e733359f14331d7064a41697c851a1d80`(PR #30).
Archive SHA256:

```text
fafa96381b1cca98b9ae9e87e04880f84d19440bfbc93df3e5c7c149878dbc10
```

Use the previous validation's Python 3.12, Rust/Cargo1.99.1, and C/OpenSSL environment. Default execution
installs pinned Python dependencies in a private temporary venv and removes it on exit. If venv support is missing,
prepare it with `sudo apt-get install -y python3-venv`. To reuse an existing venv,
add `--python /absolute/venv/bin/python`. For a standalone installation instead of rustup,
add `--toolchain-dir /absolute/rust-prefix`. Another Rust version is not selected automatically.

## OCI Ubuntu ARM

Run after transferring the file to Ubuntu home.

```bash
(
set -e
cd "$HOME"
test -f "$HOME/Spiral-key-recovery-d4c46bc.tar.gz"
printf '%s\n' 'fafa96381b1cca98b9ae9e87e04880f84d19440bfbc93df3e5c7c149878dbc10  Spiral-key-recovery-d4c46bc.tar.gz' | sha256sum -c -
tar -xzf "$HOME/Spiral-key-recovery-d4c46bc.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-recovery-d4c46bc/run_checks.py" --platform oci
)
```

## WSL Ubuntu

If the file is absent from Ubuntu home, the following locates the exact filename in Windows Downloads and copies it.
Do not extract in Windows first; test in Linux home.

```bash
(
set -e
cd "$HOME"
if [ ! -f "$HOME/Spiral-key-recovery-d4c46bc.tar.gz" ]; then
  SPIRAL_WINDOWS_BUNDLE="$(find /mnt/c/Users -maxdepth 4 -type f -path '*/Downloads/Spiral-key-recovery-d4c46bc.tar.gz' -print -quit 2>/dev/null || true)"
  if [ -z "$SPIRAL_WINDOWS_BUNDLE" ]; then
    printf '%s\n' 'First download the validation bundle to Windows Downloads.' >&2
    exit 1
  fi
  cp -- "$SPIRAL_WINDOWS_BUNDLE" "$HOME/Spiral-key-recovery-d4c46bc.tar.gz"
fi
printf '%s\n' 'fafa96381b1cca98b9ae9e87e04880f84d19440bfbc93df3e5c7c149878dbc10  Spiral-key-recovery-d4c46bc.tar.gz' | sha256sum -c -
tar -xzf "$HOME/Spiral-key-recovery-d4c46bc.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-recovery-d4c46bc/run_checks.py" --platform wsl
)
```

## Execution and submission

A new build checks Rust 94 tests (5 separately ignored), 11 existing key-management tests, and encrypted backup/recovery/rotation-failure
drills—20 tests. Authentication seeds, TLS PEM, and recovery keys use temporary test files only.
Actual operational keys, services, and vaults are neither read nor modified. BUILD, venv, and test keys are excluded from results.

Both successful and failed runs generate `Spiral-key-recovery-oci-aarch64-*.tar.gz` and
`Spiral-key-recovery-wsl-x86_64-*.tar.gz` in the home paths shown in final output. Their names differ from the input file.
If the launcher rejects input source integrity, tests do not start; inspect that error message and
check the downloaded file. `--check-only` checks sources only and does not count as passing tests.

Local validation and both platform results are separate records. New-code OCI/WSL results were submitted,
and [review of originals is complete](../../protocol_rust/evidence/key_recovery_20261110/README.md).
Each passed 94 Rust tests (5 separately ignored),11 existing key-management tests, and 20 recovery tests, with 0 failures/skips.
For backup format, key custody, external fingerprints, and recovery scope, see the [operating procedures](../../protocol_rust/KEY_RECOVERY.md).
These checks exclude overall operational readiness, deployment, constant-time, and overall memory approval.
