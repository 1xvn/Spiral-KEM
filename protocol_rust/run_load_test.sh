#!/usr/bin/env bash
# Long campaigns are started explicitly by the operator, never during setup.
set -euo pipefail
umask 077
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
    cat <<'EOF'
Usage:
  bash protocol_rust/run_load_test.sh --prepare
  bash protocol_rust/run_load_test.sh --list-profiles
  bash protocol_rust/run_load_test.sh --platform oci|wsl|local --duration 30m|1h|2h|6h|12h|24h [--output DIRECTORY]

--prepare installs pinned Python dependencies and builds the release probe.
It does not start a load test. A campaign requires an explicit --duration.
10s is also accepted for a smoke test. Linux and a Git checkout are required.
Default workload: 64 connections, 16 KiB payloads, 50 ms pacing.
Default guards: 512 MiB peak RSS, 256 sampled FDs, 64 sampled threads.
Results and a .tar.gz evidence archive are written under your home directory.
EOF
}

mode=run
platform=local
duration=''
output=''
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --prepare|--list-profiles)
            if [[ "$mode" != run ]]; then echo 'Choose one action.' >&2; exit 2; fi
            mode="${1#--}"; shift ;;
        --platform|--duration|--output)
            if (($# < 2)); then echo "Missing value for $1" >&2; exit 2; fi
            case "$1" in
                --platform) platform="$2" ;;
                --duration) duration="$2" ;;
                --output) output="$2" ;;
            esac
            shift 2 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
if [[ "$mode" == list-profiles ]]; then
    exec python3 -B protocol_rust/validation/load_campaign.py --list-profiles
fi
if [[ "$mode" == run && -z "$duration" ]]; then
    usage >&2
    echo 'No test started: --duration is required.' >&2
    exit 2
fi
case "$platform" in local|oci|wsl) ;; *) echo 'Platform must be local, oci or wsl.' >&2; exit 2 ;; esac
if [[ "$(uname -s)" != Linux ]]; then echo 'Run inside Linux or WSL Ubuntu.' >&2; exit 2; fi
if [[ "$platform" == wsl ]] && ! python3 -c 'from pathlib import Path; raise SystemExit("microsoft" not in Path("/proc/sys/kernel/osrelease").read_text().lower())'; then
    echo 'The WSL label requires a Microsoft kernel.' >&2; exit 2
fi
if ! command -v cargo >/dev/null; then
    echo 'Install Rust 1.99.1 using rustup, then reopen your terminal.' >&2; exit 2
fi
case "$(cargo --version)" in
    'cargo 1.99.1 '*) ;;
    *) echo 'This checkout requires Cargo/Rust 1.99.1 (see rust-toolchain.toml).' >&2; exit 2 ;;
esac
if [[ "$mode" == prepare ]]; then
    if [[ -n "$duration" || -n "$output" ]]; then
        echo '--prepare cannot be combined with --duration or --output.' >&2; exit 2
    fi
    python3 -m venv .venv-load
    .venv-load/bin/python -m pip install -r protocol_v01/requirements.txt
    .venv-load/bin/python -m pip check
elif [[ ! -x .venv-load/bin/python ]]; then
    echo 'Run bash protocol_rust/run_load_test.sh --prepare first.' >&2; exit 2
fi
if [[ "$mode" == run ]]; then
    .venv-load/bin/python -B -c 'import sys; sys.path.insert(0,"protocol_rust/validation"); from load_campaign import duration_value; duration_value(sys.argv[1])' "$duration"
fi

# Use one known target path and rebuild incrementally to avoid stale probes.
export CARGO_TARGET_DIR="$repo_root/protocol_rust/target"
cargo build --release --locked --manifest-path protocol_rust/Cargo.toml --example load_probe
if [[ "$mode" == prepare ]]; then
    echo 'Preparation complete. No load test was started.'
    exit 0
fi
if [[ -z "$output" ]]; then
    output="$HOME/Spiral-load-${platform}-$(uname -m)-${duration}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
# Resolve the destination before creating output files.
output="$(.venv-load/bin/python -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$output")"
if [[ -e "$output" || -e "$output.tar.gz" || -e "$output.console.log" ]]; then
    echo 'Output already exists. Choose a new directory.' >&2; exit 2
fi
mkdir -p -- "$(dirname -- "$output")"
echo "Evidence directory: $output"
echo 'Keep the host awake. Traffic time excludes setup, reconnects and closure.'
set +e
.venv-load/bin/python -B protocol_rust/validation/load_campaign.py \
    --binary protocol_rust/target/release/examples/load_probe \
    --output "$output" --platform "$platform" --duration "$duration" \
    --connections 64 --payload 16384 --interval-ms 50 2>&1 | tee "$output.console.log"
codes=("${PIPESTATUS[@]}")
set -e
if ((codes[0] != 0 || codes[1] != 0)); then
    echo "Campaign failed or was interrupted. Keep the evidence in $output" >&2
    exit 1
fi
echo "Send this evidence archive for review: $output.tar.gz"
