# Temporary secret copy cleanup patch · OCI/WSL remeasurement

[Download archive including source](Spiral-secret-copy-7f26fed.tar.gz?raw=true)

Includes measurement code `7f26fed5b8176ddd009d44264fb5e9ab08fb8d31`, 864 source files, and pinned third_party
patches. We extracted the actual archive locally without Git and verified collection of 70 basic tests and 160 Memcheck runs.
See [implementation/scope/validation](../../protocol_rust/SECRET_COPY_CLEANUP.md).

The subsequent [actual OCI ARM/WSL results](../../protocol_rust/evidence/secret_copy_platforms_20261109/README.md)
confirmed collection of 70 basic tests and 160 Memcheck runs each.
Reproduction commands follow. Preserve the pinned archive as-is.

Place the archive in each Ubuntu home directory and run it. Use the existing Rust 1.99.1/Valgrind/binutils/
C/OpenSSL development environment; no external Python packages are required.

OCI ARM Ubuntu:

```bash
cd "$HOME" &&
tar -xzf "$HOME/Spiral-secret-copy-7f26fed.tar.gz" -C "$HOME" &&
python3 "$HOME/Spiral-secret-copy-7f26fed/run_checks.py" --platform oci
```

WSL Ubuntu:

```bash
cd "$HOME" &&
tar -xzf "$HOME/Spiral-secret-copy-7f26fed.tar.gz" -C "$HOME" &&
python3 "$HOME/Spiral-secret-copy-7f26fed/run_checks.py" --platform wsl
```

The final `archive` path identifies the result `.tar.gz`. Preserve evidence even on failure.
Leave earlier results as-is. Original warnings/exit 99 are preserved, and this is not labeled as approval of constant time
or full memory checks. The follow-up record above describes verified collection scope on both platforms and remaining limits.

SHA-256: `9d892ca31154a210640a4ce89bd2fe85311699e515ec78715daef8af0eba0a3a`.
