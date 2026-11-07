#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "${1:-}" == "--prebuilt" ]]; then
    binary="$repo_dir/bin/linux-x86_64/spiral-lab"
    if [[ ! -f "$binary" ]]; then
        echo "The source checkout has no bundled binary. Run without --prebuilt."
        exit 1
    fi
    chmod +x "$binary"
else
    cargo build --release --locked --manifest-path protocol_rust/Cargo.toml
    binary="$repo_dir/protocol_rust/target/release/spiral-lab"
fi
python3 -m venv protocol_rust/.venv
protocol_rust/.venv/bin/python -m pip install -r protocol_v01/requirements.txt
PYTHONDONTWRITEBYTECODE=1 protocol_rust/.venv/bin/python protocol_rust/adversarial.py \
    --binary "$binary" --json protocol_rust/local_validation.json
