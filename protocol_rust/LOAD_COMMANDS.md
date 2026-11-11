# Operator commands for duration-based load tests

Run these commands separately on OCI Ubuntu ARM64 and WSL Ubuntu x86-64. The
runner uses loopback TCP/TLS; it does not connect OCI to WSL. Choose one duration
per execution. Preparation never starts a load test. Long tests are run by the
operator; submit the generated evidence archives for review afterward.

## 1. Install prerequisites on each host

Run inside the Ubuntu terminal, including on WSL:

```bash
sudo apt-get update
sudo apt-get install -y git curl ca-certificates build-essential pkg-config libssl-dev python3-venv openssl tmux
```

This checkout pins Rust/Cargo 1.99.1. If Rust is not installed, install rustup
from its official distribution after reviewing the installer:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/spiral-rustup-init.sh
sh /tmp/spiral-rustup-init.sh -y --profile minimal --default-toolchain 1.99.1
. "$HOME/.cargo/env"
```

If rustup is already installed, use:

```bash
rustup toolchain install 1.99.1 --profile minimal
. "$HOME/.cargo/env"
```

## 2. Get the runner and prepare it

Use a new directory for this review branch. This public repository does not
require a GitHub password:

```bash
git clone --single-branch --branch spiral-load-validation-20261111 https://github.com/1xvn/Spiral-KEM.git "$HOME/Spiral-load-hours" &&
cd "$HOME/Spiral-load-hours" &&
bash protocol_rust/run_load_test.sh --prepare
```

If that directory already contains this branch, update it instead of cloning:

```bash
cd "$HOME/Spiral-load-hours" &&
git pull --ff-only &&
bash protocol_rust/run_load_test.sh --prepare
```

Do not edit this checkout while a campaign is running. The collector verifies
the selected source files and the probe binary before and after execution.

## 3. Keep the terminal session alive

On each host, start a tmux session:

```bash
tmux new -s spiral-load
```

Inside tmux, use one of the run commands below. Detach with **Ctrl+B**, then **D**.
Reconnect later with `tmux attach -t spiral-load`. Tmux survives an SSH disconnect;
it does not prevent host suspension, VM shutdown or WSL termination. Keep the
host awake and powered throughout the test.

## 4. Run on OCI Ubuntu ARM64

Choose **one** row. The command includes the platform label and workload defaults.

| Traffic duration | Command, after `cd "$HOME/Spiral-load-hours"` |
| --- | --- |
| 30 minutes | `bash protocol_rust/run_load_test.sh --platform oci --duration 30m` |
| 1 hour | `bash protocol_rust/run_load_test.sh --platform oci --duration 1h` |
| 2 hours | `bash protocol_rust/run_load_test.sh --platform oci --duration 2h` |
| 6 hours | `bash protocol_rust/run_load_test.sh --platform oci --duration 6h` |
| 12 hours | `bash protocol_rust/run_load_test.sh --platform oci --duration 12h` |
| 24 hours | `bash protocol_rust/run_load_test.sh --platform oci --duration 24h` |

For example, start a one-hour test:

```bash
cd "$HOME/Spiral-load-hours" &&
bash protocol_rust/run_load_test.sh --platform oci --duration 1h
```

## 5. Run on WSL Ubuntu x86-64

Choose **one** row, inside WSL Ubuntu. The runner rejects the WSL label on a kernel
without the Microsoft identifier.

| Traffic duration | Command, after `cd "$HOME/Spiral-load-hours"` |
| --- | --- |
| 30 minutes | `bash protocol_rust/run_load_test.sh --platform wsl --duration 30m` |
| 1 hour | `bash protocol_rust/run_load_test.sh --platform wsl --duration 1h` |
| 2 hours | `bash protocol_rust/run_load_test.sh --platform wsl --duration 2h` |
| 6 hours | `bash protocol_rust/run_load_test.sh --platform wsl --duration 6h` |
| 12 hours | `bash protocol_rust/run_load_test.sh --platform wsl --duration 12h` |
| 24 hours | `bash protocol_rust/run_load_test.sh --platform wsl --duration 24h` |

For example:

```bash
cd "$HOME/Spiral-load-hours" &&
bash protocol_rust/run_load_test.sh --platform wsl --duration 1h
```

Start with a one-hour execution on each platform, then review its results before
choosing a longer duration. Do not start several campaigns on the same host at
once: they would compete for resources and complicate interpretation.

## 6. Collect the results

The runner prints progress approximately once per minute. Total wall time exceeds
the selected traffic duration because admission checks, reconnects and closure
take additional time. Under the default pacing, the 24-hour profile has an overall
watchdog of 100,900 seconds (about 28 hours); this is a stop bound, not a promise
that a healthy run needs 28 hours.

The last line identifies the archive to send, for example:

```text
/home/ubuntu/Spiral-load-oci-aarch64-1h-YYYYMMDDTHHMMSSZ-PID.tar.gz
/home/user/Spiral-load-wsl-x86_64-1h-YYYYMMDDTHHMMSSZ-PID.tar.gz
```

Use the actual printed path. Submit one OCI archive and one WSL archive, including
failed results. Do not send the repository, virtual environment or temporary
credentials. The archive contains result JSON, full probe/resource traces and
integrity/provenance files. A failed or interrupted run does not count as a passed
duration. The separate `.console.log` can help diagnose a preflight failure.

List profiles without starting traffic:

```bash
bash protocol_rust/run_load_test.sh --list-profiles
```

For a short installation check, replace the duration with `10s`. No long test is
part of setup or CI. See [LOAD_TESTING.md](LOAD_TESTING.md) for the exact workload,
stop conditions and interpretation limits. These measurements include server and
clients in one process; passing them does not establish production capacity or
cryptographic security.
