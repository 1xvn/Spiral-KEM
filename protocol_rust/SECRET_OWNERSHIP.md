# Secret ownership in the Rust–C channel

Baseline `4267653bd3079ffd8e20b6482b070a9b12673e7c` includes the registered-client lab. The code change at `4821b13` concerns the two HKDF-derived, four-byte record nonce prefixes. The receive audit already treats the prefix and key as secret inputs. The finding concerns erasure of an owned slot. It does not establish disclosure of a data key or a break of AEAD.

## Lifetime map

| Material and origin | Owner, use and copies | Disposal and remaining boundary |
| --- | --- | --- |
| Native generation seeds, polynomial secret vector and fallback seed | OpenSSL `RAND_priv_bytes` fills the 96-byte C seed array. `keygen_seeded` builds a separate OpenSSL heap object holding the vector, public key and fallback. Polynomial arithmetic uses C stack temporaries. Only the public key crosses the ABI during generation. | C cleans named seeds and intermediates. The unique worker-local `NativeKey` calls `sp_key_destroy` / `OPENSSL_clear_free`. Compiler spills, RNG and EVP provider state require separate observation. [C implementation](../native_research/spiral_native.c) · [Rust ABI](src/ffi.rs) |
| KEM message, candidate/fallback and shared secret | Encapsulation draws a private random message. Decapsulation consumes one handle, recomputes the ciphertext and selects the candidate/fallback. Native code writes the shared secret directly into the Rust heap allocation of `Secret<32>`. The worker transfers that owner through a reply. A lease contains an ID and cancellation flag. | C wipes named message, polynomial, candidate and fallback scratch. `Stored::drop` drops the key before decrementing the live count. Cancellation requests cleanup without freeing a running C operation. An undeliverable result drops its owner. Shutdown joins workers. [Worker](src/worker.rs) · [Heap owner](src/secret.rs) |
| Handshake PRK, Finished keys, application master | Both handshake roles feed the KEM output and public transcript into HKDF. `schedule` copies the returned PRK into a unique heap owner and guards the original output by reference. Finished keys feed HMAC. The Finished MACs and transcript hashes travel on or derive from the public transcript. `finish` expands the master into two data keys and two prefixes. | Secret owners zeroize before freeing. Specific hash pads, previous blocks, digest outputs and signing scratch have guards in the resolved packages. A guarded source owner covers neither compiler move copies nor all intermediate outputs in generic APIs. [Handshake](src/handshake.rs) · [Schedule](src/schedule.rs) · [Internal scratch inventory](SECRET_COPY_CLEANUP.md) |
| Directional record key and nonce | Session startup routes the client/server owners to one Tx and one Rx. Each constructs the AEAD state from a borrowed key, then drops the original key owner. Baseline `finish` dereferenced each derived prefix into a plain array, then the record stored it separately from the cipher. Clearing the cipher left this array in the live terminal record. | The patch keeps the original `Secret<4>` through handoff. One optional record key owns cipher and prefix. Existing close, poison and task-drop paths dispose of both. Each call fills a guarded 12-byte nonce in place from the borrowed prefix and public sequence. Limit paths that still permit authenticated CLOSE retain both until terminal disposal. [Records](src/records.rs) · [Session](src/channel.rs) |
| Application plaintext | Sender copies the application slice into its pooled allocation. Receive reads a frame and opens it in place. Only authenticated DATA becomes a `Plaintext` owner. A consumer may keep that owner or copy its contents. | Dropping the buffer zeroizes the Vec including spare capacity before pool reuse, also on invalid tag/header or rejected CLOSE. The application owns any further copies. Earlier tests observed the same live allocation before reuse. [Buffer](src/buffer.rs) · [Receive observations](SECRET_MEMORY.md) |
| Server signing seed and Ed25519 intermediates | OS generation or protected file read fills a unique 32-byte owner. dalek constructs a signing key held behind `Mutex<Option<_>>`. Arc sharing grants access to the same owner. Signing uses expanded scalar/prefix, nonce and scalar products inside dalek. | Revocation takes the key under the mutex after in-flight access. Drop and enabled dependency guards cover named seed/hash/scalar slots. Backend limb arrays, radix digits, by-value scalar temporaries, SIMD lanes and registers have no blanket erasure evidence. [Identity](src/identity.rs) · [Signing scratch](../third_party/rustcrypto/ed25519-dalek/src/hazmat.rs) |
| TLS private key, session traffic secrets and exporter | Server PEM enters a fixed zeroizing allocation. Parsing produces DER and transfers ownership into rustls/ring. The TLS handshake and record keys are provider-owned. The same boundary applies with client verification enabled. The lab's Python mTLS client loads its key via OpenSSL on the other endpoint. | Loader guards cover Rust-owned input and rejected DER. The exporter binds Spiral to TLS. No independent instrumentation here covers provider-internal key copies, TLS plaintext buffers, Python objects or the peer. Registry fingerprints are public identifiers. [Transport](src/transport.rs) · [TLS client](../protocol_v01/tls.py) |
| Recovery key and backed-up private material | OS randomness or a protected file fills a unique wrapping-key owner. Backup/restore uses bounded zeroizing storage for the private input and authenticated plaintext, then atomically publishes a file. | File contents, filesystem retention and offline backups have independent lifetimes. Status counters cannot attest their deletion. [Recovery](src/key_backup.rs) · [File boundary](src/keyfiles.rs) |

Rust Drop covers ordinary returns, errors and destruction of an unwound or canceled future. SIGKILL, process abort and panic-abort can skip destructors. CPU registers, kernel buffers, swap, dumps and former allocator locations are outside the live-slot witness.

## Dependency resolution

The [locked runtime feature tree](evidence/nonce_owner_20261119/runtime-features.txt) resolves the default Linux x86-64 channel. The build links the pinned C source with system libcrypto and compiles it at O2. Build-time sha2 0.10 hashes the C sources. Runtime SHA-256 uses sha2 0.11.1.

| Active path | Resolution and interpretation |
| --- | --- |
| HKDF / HMAC / hash | Local hkdf 0.13.0, hmac 0.13.0 and digest 0.11.3 plus sha2 0.11.1 with zeroize. The internal output guards apply only to their named owner slots. |
| Ed25519 | Local ed25519-dalek 3.0.0 and curve25519-dalek 5.0.0 with zeroize. Precomputed tables and optimized backend dispatch remain active. A feature declaration cannot establish register erasure. |
| Record AEAD | chacha20poly1305 0.10.1, chacha20 0.9.1 and poly1305 0.8.0, the latter two with zeroize. The channel's new guard covers its caller nonce while the AEAD runs. Dependency copies have separate lifetimes. |
| TLS | rustls 0.23.46 with ring and std, tokio-rustls 0.26.6 with ring, ring 0.17.14. This is distinct from the C KEM's OpenSSL RNG/hash/cleanse path. |

The five path-patched packages are selected by the manifest and lock. The [patch manifest](../third_party/rustcrypto/patch-manifest.json) records changed vendor file hashes. The audit profile uses release optimization with debug symbols. A test executable also includes libtest and test-only witnesses. The linked application has no such witness.

## Evidence by method

**Source and lifecycle.** The existing `Secret::drop` witness inspects initialized synthetic bytes after zeroization and before deallocation. The new tests attach it to the same prefix allocation supplied to the record owner. They cover successful Tx/Rx CLOSE, authentication failure, rejection during construction, and canceling an owned reader task while a writer is scheduled to close. They do not read freed memory. Existing worker and channel tests cover shutdown join, cancellation, queued data and partial writes. The optimized library run passed 102 tests with 5 specialist instrumented tests ignored by the ordinary harness. Real Rust/Python TLS interop passed 15 tests, including connections in both Rust/Python directions. The library suite checked the original schedule and record vectors. The all-features build was type-checked. [Functional results](evidence/nonce_owner_20261119/functional.log) · [Interop results](evidence/nonce_owner_20261119/interop.log)

A separate temporary source copy skipped only the four-byte owner wipe in `Secret::drop` and ran the two new tests in the default test profile. Both failed with witness value 2 (nonzero) instead of 1 (zero), exit 101. This mutation checks that the tests detect the missing overwrite. The mutation was never linked into the audited application. [Mutation control](evidence/nonce_owner_20261119/wipe-mutation.log)

**Optimized linked code.** In the audit-profile application, the occupied record-key destructor loads the prefix heap pointer, zeros the inline cipher key, emits four byte stores through the pointer at offsets 0–3 (`1caf2f..1caf3a`), then jumps to free. In `Rx::decode`, the caller passes the nonce at stack offset 0x14 to open and clears offsets 0x14 through 0x1f on the examined path. These observations belong to this x86-64 binary and those slots. They do not track prior register values, all paths through the provider, or emitted instructions on ARM. [Destructor](evidence/nonce_owner_20261119/record-key-drop.asm) · [Receive disassembly](evidence/nonce_owner_20261119/receive-nonce.asm)

**Dynamic marking.** On the optimized test binary, the existing receive harness marks the live 32-byte key and four-byte prefix before constructing Rx. A separate public sender constructs the input. The tracer drops the result without branching on plaintext or marking any receive output defined. All six paired trials used sender role 0, 64-byte DATA and tag index 15. Counts below are reported Memcheck warning contexts per process. The 48-byte entry is counted separately.

| Input | Public branch / address | Marked branch / address |
| --- | --- | --- |
| Valid DATA | 0 / 0 | 2 / 0 |
| Invalid tag | 0 / 0 | 2 / 0 |
| Bad public header | 0 / 0 | 0 / 0 |

The independent positive branch and indexed-load fixtures each triggered their intended diagnostic once. Public inputs did not trigger either diagnostic in these runs. In the marked valid/bad-tag cases the stacks point to AEAD verification and propagation of its result into Rx. This localization neither proves a key leak nor establishes harmless timing. All eight child processes completed their selected test and exited **99** with 48 bytes possibly lost on the std thread/libtest allocation stack. No suppression was used. [Machine counts](evidence/nonce_owner_20261119/memcheck.json) · [Raw warning logs](evidence/nonce_owner_20261119/)

**Historical evidence.** The six minimal libtest controls and later thread-lifetime controls explain how a similar allocation can occur without the KEM. They do not resolve the original warning. The older patched-source OCI/WSL campaign retained all 320 exit-99 statuses and observed 134 receive warning contexts per platform across its broader matrix. The earlier 216 buffer observations covered actual receive-buffer capacity before reuse. Those experiments belong to their recorded source and target. [Libtest](LIBTEST_MEMORY.md) · [Thread and buffer controls](SECRET_MEMORY.md) · [Receive evidence](RECEIVE_SECRET.md) · [Patched dependency campaign](SECRET_COPY_CLEANUP.md)

**Timing.** Earlier native decapsulation diagnostics compared fixed/varying seeds in two 6,000-sample trials. Their deliberately different-work positive controls gave Welch t of −6.54 and −18.81, and identical-input sham groups −0.89 and 0.73. That demonstrates sensitivity to the chosen gross difference on those runs. The patch-era HMAC/HKDF/signature benchmark used public inputs to compare cleanup costs. Neither dataset measures the timing of this Rust receive change. The later [paired receive timing experiment](RECEIVE_TIMING.md) records 64-byte DATA measurements on cloud x86-64, OCI AArch64 and WSL2 x86-64. [Native timing](../native_research/README.md) · [Benchmark inputs and samples](evidence/secret_copy_cleanup_20261108/benchmark/)

### OCI AArch64 follow-up

The submitted Linux 7.0.0-1013-oracle AArch64 build at merge commit `aba5b7c157fe33d9d3f138c263a3eff7dcb94818` used rustc 1.99.1 and Valgrind 3.22.0. Both ownership regressions passed, covering close, rejection and canceled reader ownership during writer shutdown. The archive contains the application disassembly, test logs and operator-reported ELF digests. The application and libtest ELF files were not submitted. [Original archive](evidence/nonce_owner_20261119/oci-aarch64/Spiral-nonce-arm-AG3BYGHO.tar.gz) · [Review with archive and per-log hashes](evidence/nonce_owner_20261119/oci-aarch64/review.json)

In the application disassembly, four byte stores of the zero register at `0x1043f8–0x104404` clear the heap prefix before the branch to `free@plt` at `0x104408`. In `Rx::decode`, the AEAD open call uses the nonce at frame-pointer offset −60. The reviewed success and error paths clear all twelve bytes through offset −49.

The eight Memcheck runs comprised two positive controls and three public/marked pairs for role 0, 64-byte DATA and tag index 15. Each positive control detected its intended branch or indexed access. All public inputs and the marked bad header had zero branch/address warnings. Marked valid DATA and the bad tag each had two branch contexts. In the **test executable**, the stacks at `0x1FE0B0` and `0x1E4A80` point to AEAD verification and propagation of its result. Every run retained exit 99 and one 48-byte possibly-lost allocation with `std::thread::current::init_current` in its stack. Suppressed errors were zero.

This completes the scoped ARM receive-owner check. In the [OCI and WSL timing review](RECEIVE_TIMING.md#oci-and-wsl-measurements), both decisions met the control criteria and neither key comparison crossed the threshold on either host. The earlier cloud x86-64 reject comparison remains inconclusive because the positive control missed its threshold. Backend limbs, register retention, TLS-provider internals and process abort also remain open.

## Reproducing this scope

Use the pinned Rust toolchain and the checked-in lock. Build the application and test harness separately. In the commands below, set `bin` to the exact libtest executable printed by Cargo, and `vg` to a working Memcheck executable with debug information for the matching loader/libc.

```bash
cargo test --locked --profile audit --manifest-path protocol_rust/Cargo.toml --lib -- --test-threads=1
cargo build --locked --profile audit --manifest-path protocol_rust/Cargo.toml --bin spiral-lab
cargo tree --locked --manifest-path protocol_rust/Cargo.toml --target x86_64-unknown-linux-gnu -e normal,features --format '{p} features=[{f}]'
```

For one paired case, execute the following Bash command once with `mark=public` and once with `mark=secret`. Substitute `data-bad-tag` or `data-bad-header` for the other inputs. Exercise the positive controls with the same flags and the exact test names `receive_audit::positive_secret_branch` and `receive_audit::positive_secret_address`. Exit 99 alone does not distinguish leak-only output from a detected branch. Retain stdout, stderr and the actual child status.

```bash
mark=secret
SPIRAL_RX_TRACE_MODE=data-valid SPIRAL_RX_TRACE_TAINT="$mark" \
SPIRAL_RX_TRACE_ROLE=0 SPIRAL_RX_TRACE_LENGTH=64 \
"$vg" --tool=memcheck --default-suppressions=no --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 --num-callers=24 \
  "$bin" --exact receive_audit::trace_actual_receive --ignored --test-threads=1 --nocapture
```

The local run invoked the matching extracted loader with `--library-path` between the Valgrind options and test binary. Input package SHA-256 values were checked against the earlier Debian package provenance. [Environment and artifact hashes](evidence/nonce_owner_20261119/environment.json)
