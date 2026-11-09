# OCI/WSL production key management validation bundle

Download [Spiral-key-operations-0b0db39.tar.gz](Spiral-key-operations-0b0db39.tar.gz).
Use **Download raw file** on the GitHub file page. On Windows, save it in Downloads
with the same filename. No full repository clone or GitHub terminal authentication is needed.
Transfer this file to `/home/ubuntu/` on OCI using the existing scp method.

The pinned source is `0b0db39d36b9a6f243486615ca2624a6b76ce02b`; runtime matches PR #28's
`486697682beb66db1af05bdc45867d122a25d145`. Only a new collector and documentation were added.
archive SHA256:

```text
ef11e2be82944e7cad1fea88cea09f4c8f2de1319367860786dbae4107f054bd
```

Reuse the Python3.12/Rust/Cargo1.99.1/C/OpenSSL environment from previous validation. If Python venv creation
is unavailable, prepare it with `sudo apt-get install -y python3-venv`. Full preparation and scope are in
the [detailed guide](../../protocol_rust/KEY_OPERATIONS_PLATFORMS.md).

## On OCI Ubuntu ARM

Run the following after transferring the file to the Ubuntu home directory. Failure stops only inside the parentheses,
so it does not close the current terminal session.

```bash
(
set -e
cd "$HOME"
test -f "$HOME/Spiral-key-operations-0b0db39.tar.gz"
printf '%s\n' 'ef11e2be82944e7cad1fea88cea09f4c8f2de1319367860786dbae4107f054bd  Spiral-key-operations-0b0db39.tar.gz' | sha256sum -c -
tar -xzf "$HOME/Spiral-key-operations-0b0db39.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-operations-0b0db39/run_checks.py" --platform oci
)
```

## On WSL Ubuntu

If the file is absent from the Ubuntu home directory, the following finds and copies the exact filename
from Windows users' Downloads. Do not extract it on Windows first. Do not test under `/mnt/c`.

```bash
(
set -e
cd "$HOME"
if [ ! -f "$HOME/Spiral-key-operations-0b0db39.tar.gz" ]; then
  SPIRAL_WINDOWS_BUNDLE="$(find /mnt/c/Users -maxdepth 4 -type f -path '*/Downloads/Spiral-key-operations-0b0db39.tar.gz' -print -quit 2>/dev/null || true)"
  if [ -z "$SPIRAL_WINDOWS_BUNDLE" ]; then
    printf '%s\n' 'First download the validation bundle to Windows Downloads.' >&2
    exit 1
  fi
  cp -- "$SPIRAL_WINDOWS_BUNDLE" "$HOME/Spiral-key-operations-0b0db39.tar.gz"
fi
printf '%s\n' 'ef11e2be82944e7cad1fea88cea09f4c8f2de1319367860786dbae4107f054bd  Spiral-key-operations-0b0db39.tar.gz' | sha256sum -c -
tar -xzf "$HOME/Spiral-key-operations-0b0db39.tar.gz" -C "$HOME"
python3 "$HOME/Spiral-key-operations-0b0db39/run_checks.py" --platform wsl
)
```

## Files to submit

The generated result archives are the home-directory files `Spiral-key-ops-oci-aarch64-*.tar.gz` and
`Spiral-key-ops-wsl-x86_64-*.tar.gz` shown in each environment's final output. Their names differ from the input bundle.
Preserve result files even on failure. Review raw logs and failure verdicts without altering them.

Expected tests are 81 Rust tests (5 ignored separately) and 11 key management/real TLS rotation tests.
Results from both target environments were submitted, and [original log/source hash comparison is complete](../../protocol_rust/evidence/key_operations_platforms_20261109/README.md).
Each passed 81 Rust tests (5 ignored separately) and 11 key management/real TLS rotation tests.
Local prevalidation and both target runs are recorded separately; all of production readiness item 5 and deployment approval remain incomplete.
