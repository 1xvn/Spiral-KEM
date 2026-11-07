# OCI ARM64 · WSL2 x86-64 C ciphertext fuzzing

Reuse the `~/Spiral-native-fuzz-20261107` working directory and Git authentication
from the existing PK check. Run separately on OCI Ubuntu 24.04 ARM64 and WSL2 Ubuntu 24.04 x86-64,
and **both must use the same recorded source commit for the campaign**.
Existing tools such as Clang 18 and Python 3 are used, so no `pip` installation is required.

This target is C ciphertext format validation and one-shot key decapsulation, consumption, and erasure.
Each input generates a fresh key using a public fixed test seed. A separate oracle checks the 1160-byte length,
prefix, and 12-bit coefficient range, and also tests zero initialization of error output,
input preservation, rejection of reuse, and key erasure.

Canonical ciphertext returns `SP_OK`, but this does not mean authentication succeeded.
Tampered canonical ciphertext can produce a normal rejection shared secret,
and saved input results are compared against the existing pinned Python OPT2 implementation.
This check is not an approval criterion for Rust communication state, constant time behavior, or mathematical/cryptographic security.

## 1. Prepare the same source in both environments

Run in the Ubuntu terminal reached through existing SSH on OCI, or in the Ubuntu app's
Linux terminal on WSL. Keep the WSL working directory and results under `~/`.

```bash
git -C "$HOME/Spiral-native-fuzz-20261107" fetch origin refs/heads/spiral-native-ct-fuzz-20261107 &&
git -C "$HOME/Spiral-native-fuzz-20261107" worktree add --detach "$HOME/Spiral-native-ct-fuzz-20261107" FETCH_HEAD &&
cd "$HOME/Spiral-native-ct-fuzz-20261107" &&
git rev-parse HEAD
```

Proceed **after verifying that the printed hash matches the campaign's recorded source commit**.
If any command fails or the hash differs, inspect that output before starting fuzzing.
If the new working directory already exists, preserve it and use a new name such as `Spiral-native-ct-fuzz-20261107-v2`,
changing both paths in `worktree add` and `cd` accordingly.

```bash
uname -m
clang-18 --version
python3 -m unittest native_research.test_ct_oracle native_research.test_fuzz_ct_runner -v
```

Verify OCI's architecture is `aarch64` and WSL's is `x86_64`. If the unit tests end with `OK`,
run the next command for that environment. Passing unit tests alone does not mean fuzzing is complete.

## 2. Run on OCI

```bash
python3 native_research/fuzz_ct.py --label oci --cc clang-18 --runs 100000 --seconds 60 --output "$HOME/Spiral-C-ct-oci-20261107"
```

## 3. Run on WSL

```bash
python3 native_research/fuzz_ct.py --label wsl --cc clang-18 --runs 100000 --seconds 60 --output "$HOME/Spiral-C-ct-wsl-20261107"
```

`100000` is the requested maximum execution count. If the 60-second limit is reached first, the actual count
may be lower. The 60 seconds limit the live fuzzing phase; the full job including building, Python comparison
of saved inputs, and archiving may take longer.

When the runner finishes, it **automatically creates a `.tar.gz`** beside the results directory.
For example, OCI results are `~/Spiral-C-ct-oci-20261107.tar.gz`.
The archive contains logs, verdicts, and public test inputs; `build/`, which contains executables, is excluded.
No separate archiving command is needed. Preserve the results directory and archive even on failure.

If the results directory or an archive with the same name already exists, the runner refuses to overwrite it.
For retries, change the end of `--output` to, for example, `Spiral-C-ct-oci-20261107-v2` or
`Spiral-C-ct-wsl-20261107-v2`. Change the archive name to download accordingly.

## 4. Check and submit results

Check `result.json` in each results directory.

- Both `commit` values must match the final instructions, and `source_sha256` must also match.
- `sources_match_head`, `sources_unchanged_during_run`, and `fixture_header_unchanged` must be `true`.
- Overall `status` and `differential.status` must be `passed`, and `engine_exit` must be 0.
- `feedback` contains actual execution counts and coverage results, and execution must have continued after initial input checks.
- `differential.checked_files` must equal `expected_files`, and `mismatches` must be empty.

The live libFuzzer execution count and Python comparison input count are separate.
Python comparison checks the entire finite corpus saved at the end;
it does not mean every live mutation was checked with Python.
ASan/UBSan/leak check errors or environment problems are not converted into passes.

Open the home directory from the WSL Ubuntu terminal and copy the archive to Windows.

```bash
explorer.exe "$(wslpath -w "$HOME")"
```

Download the OCI archive with the existing SSH key and connection address. The following is a **Windows PowerShell**
example. Replace the key **file path** and host variables with existing SSH connection values;
Result bundles must exclude key contents and credentials.

```powershell
$OciKey = "C:\existing-key-folder\existing-OCI-key.key"
$OciHost = "Existing OCI IP or host"
$OciUser = "ubuntu"
scp -i "$OciKey" "${OciUser}@${OciHost}:~/Spiral-C-ct-oci-20261107.tar.gz" "$HOME\Downloads\Spiral-C-ct-oci-20261107.tar.gz"
```

If the existing SSH username is not `ubuntu`, also change `$OciUser` to the existing value.
The two `.tar.gz` files allow verification that both environments used the same commit and options.

OCI/WSL results are not yet available for this C ciphertext check. Earlier PK check results
are not counted as passes for this target; local results also do not replace runs in both environments.
Local preparation validation is in the [ct_fuzz_20261107 record](evidence/ct_fuzz_20261107/README.md),
with 21,253 actual executions within a 60-second budget and successful Python comparisons for 52 final saved inputs.
