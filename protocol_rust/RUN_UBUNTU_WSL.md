# v0.3 Ubuntu 24.04 / Windows 11 WSL remeasurement

Run this guide in an Ubuntu 24.04 terminal. On Windows 11, check registered distribution names with PowerShell's `wsl -l -v`, then open the corresponding Ubuntu. Both OCI ARM and WSL x86-64 build from source. Shell functions below stop at a failed step, preventing subsequent commands from cascading.

Extract downloaded `Spiral_OPT2_Rust_C_v0.3.zip` into Ubuntu home, then run from that directory. The Windows Downloads path under WSL is `/mnt/c/Users/windows-user/Downloads`.

```bash
unzip -n /mnt/c/Users/windows-user/Downloads/Spiral_OPT2_Rust_C_v0.3.zip -d "$HOME"
cd "$HOME/Spiral_OPT2_Rust_C_v0.3"
```

On OCI, extract the uploaded ZIP from home with `unzip -n "$HOME/Spiral_OPT2_Rust_C_v0.3.zip" -d "$HOME"`. Initial packages are `build-essential pkg-config libssl-dev python3-venv time unzip`. Use already-installed Rust 1.99.1 and preserve v0.2 directories/results. If apt DNS errors remain, proceed only after successful package installation.

```bash
spiral_v03_check() (
  set -euo pipefail
  source "$HOME/.cargo/env"
  python3 -m venv protocol_rust/.venv
  source protocol_rust/.venv/bin/activate
  python -m pip install -r protocol_v01/requirements.txt
  cargo +1.99.1 test --locked -j 1 --manifest-path protocol_rust/Cargo.toml
  cargo +1.99.1 build --release --locked -j 1 --manifest-path protocol_rust/Cargo.toml
  mkdir -p benchmark_results
  python protocol_rust/adversarial.py \
    --binary protocol_rust/target/release/spiral-lab \
    --json benchmark_results/validation_v03.json
  python protocol_rust/benchmark.py \
    --binary protocol_rust/target/release/spiral-lab \
    --time /usr/bin/time --trials 10 \
    --output benchmark_results/benchmark_v03.json
  uname -a > benchmark_results/environment_v03.txt
  lscpu >> benchmark_results/environment_v03.txt
  rustc +1.99.1 -Vv >> benchmark_results/environment_v03.txt
  cc --version >> benchmark_results/environment_v03.txt
  openssl version >> benchmark_results/environment_v03.txt
)
spiral_v03_check
```

Reduce other builds, memory instrumentation, and background load during measurement. Nine conditions ×10 rounds ×four connections yield360 measured connections plus72 separate warm-up connections. After normal completion, check tests=35, failures=0, errors=0 in validation_v03.json. Results are saved in benchmark_results/.

Sharing archived files enables platform-specific figures and v0.2 regression comparisons on the same machines. Native Windows and WSL results are not labeled as equivalent.
