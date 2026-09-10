#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
lowlat_root="$repo_root/engine/lowlat"
result_log="$(mktemp)"
trap 'rm -f "$result_log"' EXIT

printf '%s\n' 'portable transport smoke: loopback/synthetic only'
printf '%s\n' 'portable transport smoke: running focused authenticated suite'

(
    cd "$lowlat_root"
    cargo test -p openstream-client-core --test portable_transport --all-features --locked -- --test-threads=1
) | tee "$result_log"

summary="$(sed -n '/^test result:/p' "$result_log" | tail -n 1)"
if [[ -n "$summary" ]]; then
    printf 'portable transport smoke: %s; loopback/synthetic only\n' "$summary"
else
    printf '%s\n' 'portable transport smoke: completed; loopback/synthetic only'
fi

printf '%s\n' 'portable transport smoke does not claim external coturn, public NAT, WAN, hardware, native-media, or Parsec/BUD acceptance.'
