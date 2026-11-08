# OCI ARM rerun bundle

[Download archive including source](Spiral-arm-secret-flow-7bff0e4.tar.gz?raw=true)

Both collectors in pinned source `7bff0e4` were fixed to use verified `SOURCE.json` without `.git`.
It includes 641 source files and a verification launcher. The original earlier failure and fix validation are in
the [review record](../../protocol_rust/evidence/arm_standalone_fix_20261108/README.md).

The subsequent [actual OCI ARM results](../../protocol_rust/evidence/arm_secret_flow_20261108/README.md)
confirmed completion of 70 basic tests and 160 Memcheck collection runs.
Reproduction commands follow. Preserve the archive as-is.

Transfer the file to the OCI Ubuntu home directory, then run it.

```bash
cd "$HOME" &&
tar -xzf "$HOME/Spiral-arm-secret-flow-7bff0e4.tar.gz" -C "$HOME" &&
python3 "$HOME/Spiral-arm-secret-flow-7bff0e4/run_checks.py" --platform oci
```

Use the existing Rust 1.99.1/Valgrind/C/OpenSSL/binutils environment. When execution finishes,
the final `archive` path identifies `Spiral-secret-flow-aarch64-*.tar.gz` for result review.
Retain the earlier failure evidence as-is. New source and results directories are created for this run.

The actual source bundle was run locally on x86-64 outside Git, confirming 70 basic tests and
160 Memcheck collection runs. The subsequent ARM submission above also confirmed collection completion,
but constant time and full memory checks were not approved.

SHA-256: `8e710c56e4b6c74d7d4f1864151e334ade419005bf425bf29987a5269e24d649`
