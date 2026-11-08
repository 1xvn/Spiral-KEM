# Secret-buffer and standard-thread memory follow-up evidence

Local validation of code commit `063d090219af0367eb6631d76283d32a78c47f67`.
The recorded local date is 2026-11-08; original times are UTC.
Full interpretation/environments/reproduction/remaining scope are in the [follow-up record](../../SECRET_MEMORY.md).

- `thread-ownership-controls.tar.gz`: Generated sources and normal runs for10 std-only controls,
  original Memcheck logs, hashes, and tool versions. Internal hashes for66 files were revalidated.
  Executables/staticlib in `build/` are excluded; child exit99 remains unchanged.
- `stdlib-source/`: Official rust-src download provenance/hashes, actual file hashes and short excerpts,
  disassembly of Thread creation/TLS storage in current control executables, and corresponding binary hashes.
  Rust upstream MIT/Apache licenses are also preserved.
- `wipe/`: Normal/optimized/ASan/Memcheck logs for4 buffer-disposal tests/216 observations and
  binary hashes. Memcheck retains exit99 due to std/libtest48 bytes.
- `functional/`: Original results/logs for existing Python/C/Rust/actual TLS regressions.
- `base-tools-provenance.json`: Provenance records for previously signature/hash-verified
  Rust 1.99.1, Valgrind 3.24.0, and matching glibc/debug loader extracted into the work folder.
- `review.json`: Summary of observations, exit codes, validation scope, and incomplete items.
- `SHA256.json`: Complete hashes of materials preserved in this folder.

Memory controls used Debian x86-64, Rust 1.99.1, Valgrind 3.24.0, and matching glibc
2.41 debug loader/libc. This is not counted as the same environment as original WSL/OCI results.
ASan used a separately pinned nightly; both executables/options were recorded distinctly.

Original-log whitespace was not normalized. Full binaries, official tools, and rust-src
bundles are excluded from preserved materials, so recipients of the materials alone cannot
recompute those binary hashes. The supplied scope is static provenance, excerpts, logs, and reproduction procedures.

Completion of new controls does not indicate production memory/constant-time approval. Earlier48-byte
failure records, WSL AES-GCM failure, strict memory-CI gates, and the `production_memory_passed=false`
verdict remain. pthread_exit controls ran only in C after Rust calls returned.
