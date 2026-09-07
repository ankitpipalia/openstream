#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' "openstream-linux-host --preflight is a Linux-only check" >&2
  exit 2
fi

cd "$repo_dir/engine/lowlat"
printf '%s\n' "Running the native Linux host preflight; hardware availability is reported, not fabricated." >&2
cargo run --locked -p openstream-linux-host -- --preflight
