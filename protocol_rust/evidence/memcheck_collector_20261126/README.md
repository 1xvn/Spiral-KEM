# Finished rejection collector evidence

The [collector source hashes](collector.sha256) identify the two Python files used in the recorded run. The release server was built from `cbaf58de6d67178b1262156c7356f9cecb946956` with Rust 1.99.1. The run used Valgrind 3.22.0 and glibc `2.39-0ubuntu8.12` on Ubuntu x86-64.

| Record | Observed result |
|---|---|
| [Finished rejection result](result.json) | The connection negotiated TLS 1.3 and `TLS_AES_256_GCM_SHA384`. The server reported `Error: Authentication` and `live_keys=0`. Memcheck exited 99, and the collector exited 1. |
| [Same-run Memcheck log](finished-failure.log) | One warning in `Transport::accept_profile` with a `fork_finish` origin. The recorded digest matches the raw bytes. |
| [Startup failure with no TLS observation](unobserved-result.json) | The collector exited 1. The cipher, TLS protocol, Memcheck log path and log hash are JSON `null`. |

Finished 2, the `FrameIo::recv` context from the earlier investigation, remains **insufficient evidence**. This run reproduced only the `accept_profile` context. The original archive `Spiral-memory-6-evidence.tar.gz` retains SHA-256 `6e9a77e837b657f9127dc7d33de594c7b6fc47257736b0d16043f1a450fb0484` and the original strict failure verdicts.

From the repository root, run the collector with the existing release binary and the pinned Python dependencies. Each command creates a separate output directory.

```bash
python3 -B protocol_rust/memcheck.py --case finished-failure \
  --binary /path/to/release/spiral-lab --valgrind /usr/bin/valgrind \
  --output "$(mktemp -d)"

python3 -B protocol_rust/memcheck.py --case finished-failure \
  --binary /usr/bin/true --valgrind /usr/bin/true \
  --output "$(mktemp -d)"
```

The second command uses `true` to model an instrumented process that exits before reporting a listening port. See the [client callback](../../interop.py#L202), [evidence collector](../../memcheck.py) and [original GitHub Actions run](https://github.com/1xvn/Spiral-KEM/actions/runs/45623074577).
