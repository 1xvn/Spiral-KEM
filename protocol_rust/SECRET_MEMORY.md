# Constant time and secret management follow-up validation · 2026-11-08

We narrowed down ownership and shutdown lifetime of the 48-byte std/libtest warning and checked whether actual buffers
are wiped after receive decryption. Basic functionality and new disposal tests passed.
**We do not deem the full memory checks or constant time validation complete.**

The latest [HMAC/HKDF/signing state cleanup](SECRET_STATE.md) enables hash-state
zeroization in stable dependencies and adds new regressions. Below is the record from the earlier ownership/buffer observations.

The next-stage [actual receive path and temporary secret state validation](RECEIVE_SECRET.md)
adds 78 key/prefix taint cases and 78 public controls, enables Poly1305 state zeroization, and lists lifetimes
inside dependencies. Below are the earlier measurement results; see the follow-up record for the latest scope.

## Ownership and lifetime of the 48 bytes

We verified the pinned Rust 1.99.1 source against the SHA-256 in the official manifest.
The compiler commit is `58cf8f9c35b355199727627d07ae34a4e2846d67`, and the rust-src bundle is
`e485a88c45db546b73571df7bebfcb4454ba4fb552c492e25fc5b00eeb5bf22d`.

`std::thread::current()` creates a `Thread` and stores an Arc clone's data pointer in thread-local
storage (TLS). In the inspected x86-64 build,
the allocation is 48 bytes and the pointer points
16 bytes inside the allocation's start. We also verified reference count increment, `+0x10`, and TLS storage
in a new executable. The `Inner` fields are name, ID, and Parker; this is not a Spiral key storage structure.

When the pthread TLS destructor runs `thread_cleanup` → `drop_current`, it restores the raw pointer
to an owned Thread and drops it. The Rust source does not always guarantee this cleanup
and explicitly states that memory can remain if it is skipped. The interior pointer and shutdown lifetime
explain the `possibly lost` classification, but do not mean every allocation was actually freed.

We ran 10 new controls without Spiral, cryptographic libraries, or secret values.

| Control | Memcheck exit | possibly lost |
|---|---:|---:|
| Empty Rust main | 0 | 0 B |
| current called once in main | 99 | 48 B, 1 entry |
| current called 10,000 times in main | 99 | 48 B, 1 entry |
| All 1/8/64 workers calling current joined in each case | 0 each | 0 B each |
| Empty C main normal return / pthread_exit | 0 each | 0 B each |
| C → Rust current call → return to C → C main return | 99 | 48 B, 1 entry |
| pthread_exit in C after the same Rust call returns | 0 | 0 B |

The last two cases changed only the termination path **in C after all Rust frames had returned**.
We did not call pthread_exit across Rust frames. These local controls provide evidence that the main
thread's TLS ownership and shutdown path affect the warning. Increasing the query count
still leaves one retained allocation, and none remained in the joined workers checked.
This does not guarantee identical behavior on other CPUs, libc versions, or Valgrind versions.

We preserved the original exit 99 in all three warning cases. `diagnostic_complete=true` denotes completion
of the controls; `production_memory_passed=false` and `original_finding_resolved=false`
remain unchanged. We neither converted earlier failures to passes nor added suppressions.
Nor did we remeasure the entire original environment and resolve it. WSL AES-GCM retains the verdict
and scope of the separate [earlier investigation](MEMORY_FOLLOWUP.md).

## Actual receive buffer disposal

The new `secret_audit` tests inspect the same allocation returned to the pool after actual `Rx::decode`
success/failure. They use both roles and lengths 1/16/63/64/65/1,024/16,384.

| Case | Buffer observations |
|---|---:|
| Successful DATA and subsequent CLOSE | 28 |
| Direct CLOSE and input after shutdown | 12 |
| Invalid tag/header/truncation and input after permanent disposal | 168 |
| Valid authentication tag but invalid CLOSE reason and repeated input | 8 |
| Total | 216 |

The full capacity was initialized with public data before shortening the length to inspect the tail region too.
After disposal, the buffer was reacquired with the same pointer/capacity and length 0, and we checked that the entire buffer was 0 **before resize**.
The restricted test-only unsafe reads observe only live, already initialized memory,
and never read freed addresses. This observation facility is not exposed outside tests.

| Execution mode | Result |
|---|---|
| Rust 1.99.1 regular / optimized audit | 4 tests/216 observations passed each |
| Memcheck on the same audit executable | 4 tests/216 observations passed, overall memory verdict exit 99 |
| Pinned nightly ASan/leak checks | 4 tests/216 observations passed, exit 0 |

Memcheck's sole error was one 48-byte entry on the std/libtest stack. The new observations
had no additional memory usage errors, but we do not erase that warning and
claim a full check pass. Nor do we count the ASan results as resolution of the existing Valgrind warning.

## Current scope of item 2

| Item | Evidence and remaining scope |
|---|---|
| Native C secret branch/address instrumentation | Earlier sample evidence retained. Not proof of overall cryptographic security |
| Rust KDF/MAC, transmission seal, signing instrumentation | Existing x86-64 samples. Not counted as extending to OCI ARM instrumentation |
| Buffer disposal after reception | Adds observations of 216 actual allocations here |
| Secret branch instrumentation of receive open | Requires separate validation. Must distinguish public authentication decisions from secret-dependent branches |
| All temporary key copies/registers | Not proven by these observations. Disposal policies for internal HMAC/HKDF/SHA state also need review |
| Production key storage/rotation/recovery policy | Service integration work separate from memory ownership tests |

Thus item 2 as a whole remains incomplete. The next step is to document the public authentication result
boundary in receive-side instrumentation, lifetimes of temporary secrets inside libraries, and service key management policies.
We do not conclude that a vulnerability exists solely from success/failure branches in authenticated decryption with tainted keys,
and do not eliminate warnings through arbitrary declassification.

## Evidence and reproduction

The [evidence directory](evidence/secret_memory_20261108/README.md) contains the original 10 controls,
source provenance/excerpts/linked instructions, buffer test logs/binary hashes, and functional regression results.
Baseline regressions passed 85 Python tests, 6 diagnostic tests, 9 C tests, 64 Rust unit tests (2 ignored separately),
6 compile-fail tests, and the existing 35 real TLS tests. The 13 diagnostic verdict tests and CI gate
tests, 7 in total, also passed.

For reproduction on Linux equipped with Rust 1.99.1, Valgrind,
a C compiler, and matching libc debug symbols,
use actual installation paths and a new output directory. The runner does not download tools.

```bash
python3 -S protocol_rust/diagnostics/thread_ownership.py \
  --rustc /actual/1.99.1/bin/rustc \
  --valgrind /actual/valgrind \
  --output "$HOME/Spiral-thread-ownership-20261108"
```

Existing evidence is not overwritten, and a `.tar.gz` is created alongside the output automatically. Child exit codes and
warnings are preserved; unknown errors, omissions, and process timeouts do not count as diagnostic completion.
For a separate loader, specify both `--loader` and `--library-path`.

```bash
cargo test --locked --profile audit --manifest-path protocol_rust/Cargo.toml \
  --lib secret_audit:: -- --test-threads=1 --nocapture
```

The new ownership controls and verdict tests are connected to the existing weekly/manual memory workflow.
The strict clean-memory gate remains, so the job continues to fail when the warning is reproduced.
We did not verify actual execution results of this change on GitHub runners from this environment.
