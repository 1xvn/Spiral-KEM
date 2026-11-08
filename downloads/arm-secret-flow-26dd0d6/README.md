# OCI ARM instrumentation bundle

[Download](Spiral-arm-secret-flow-26dd0d6.tar.gz?raw=true)

Includes pinned source26dd0d6 and618 file hashes. In a browser signed into GitHub, click Download raw file on the file page.

After placing it in OCI home:

```bash
cd "$HOME" &&
tar -xzf Spiral-arm-secret-flow-26dd0d6.tar.gz &&
python3 "$HOME/Spiral-arm-secret-flow-26dd0d6/run_checks.py" --platform oci
```

If Valgrind/libc debug symbols/binutils are missing, run `sudo apt-get update && sudo apt-get install -y valgrind libc6-dbg binutils`. Use the previous functional-check environment for Rust1.99.1/C/OpenSSL. No external Python packages are required.

The final archive path identifies Spiral-secret-flow-aarch64-....tar.gz. Failures are preserved too. Exit 0 means collection completed, not constant-time or memory approval. Actual ARM execution is assessed by reviewing the collected evidence.

Existing derivation/transmission/signing controls retain public wire outputs and synthetic seed-shadow cleanup after all operations complete. Actual receiving does not declassify keys, results, tags, or plaintext.
