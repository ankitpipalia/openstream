#!/usr/bin/env bash
set -euo pipefail

# Verify the truthful ICE migration boundary on a loopback full-ICE session.
# This deliberately proves only the typed UnsupportedIceRestart result; it
# does not claim TURN/public-NAT migration support.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
lowlat_dir="$repo_dir/engine/lowlat"

pick_port() {
    python3 -c 'import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])'
}

signal_port="${OPENSTREAM_ICE_MIGRATION_SIGNAL_PORT:-$(pick_port)}"
server_log="$(mktemp -t openstream-ice-migration-server.XXXXXX)"
pairing_file="$(mktemp -t openstream-ice-migration-pairing.XXXXXX)"
host_log="$(mktemp -t openstream-ice-migration-host.XXXXXX)"
client_log="$(mktemp -t openstream-ice-migration-client.XXXXXX)"
server_pid=""
host_pid=""
client_pid=""

cleanup() {
    if [[ -n "$client_pid" ]]; then
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
    fi
    if [[ -n "$host_pid" ]]; then
        kill "$host_pid" 2>/dev/null || true
        wait "$host_pid" 2>/dev/null || true
    fi
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -f "$server_log" "$pairing_file" "$host_log" "$client_log"
}
trap cleanup EXIT INT TERM

cd "$lowlat_dir"
cargo build -q --locked -p openstream-signal-server -p openstream-reference-peer

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$signal_port" \
    target/debug/openstream-signal-server >"$server_log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:$signal_port/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "signal server did not become ready" >&2
    exit 1
fi

curl -fsS -X POST "http://127.0.0.1:$signal_port/v1/session" \
    -H 'content-type: application/json' \
    -d '{"ttl_seconds":120}' >"$pairing_file"
pairing_json="$(tr -d '\n' <"$pairing_file")"
common_env=(
    "OPENSTREAM_ICE=1"
    "OPENSTREAM_ICE_INCLUDE_LOOPBACK=1"
    "OPENSTREAM_ICE_MIGRATION_PROBE=1"
    "OPENSTREAM_SIGNAL_ORIGIN=http://127.0.0.1:$signal_port"
    "OPENSTREAM_PAIRING_JSON=$pairing_json"
    "OPENSTREAM_PATH_MIGRATION=1"
)

env "${common_env[@]}" target/debug/openstream-reference-peer --migration host >"$host_log" 2>&1 &
host_pid=$!
env "${common_env[@]}" target/debug/openstream-reference-peer --migration client >"$client_log" 2>&1 &
client_pid=$!

host_status=0
client_status=0
wait "$host_pid" || host_status=$?
wait "$client_pid" || client_status=$?
host_pid=""
client_pid=""

if [[ "$host_status" != 0 || "$client_status" != 0 ]]; then
    echo "ICE capability peers failed (host=$host_status client=$client_status)" >&2
    sed -E 's/(host_token|client_token|relay_host_ticket|relay_client_ticket|password)[=:][^ ,}]*/\1=[redacted]/Ig' "$host_log" >&2
    sed -E 's/(host_token|client_token|relay_host_ticket|relay_client_ticket|password)[=:][^ ,}]*/\1=[redacted]/Ig' "$client_log" >&2
    exit 1
fi

grep -Fqx 'ice migration capability: UnsupportedIceRestart' "$host_log"
[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$host_log")" == 1 ]]
[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$client_log")" == 1 ]]
if grep -Eiq 'host_token|client_token|relay_host_ticket|relay_client_ticket|turn.*password|second key exchange|second session|migration committed' "$host_log" "$client_log"; then
    echo "ICE capability logs contain credentials or a simulated migration" >&2
    exit 1
fi

printf '%s\n' 'ICE migration capability check passed: UnsupportedIceRestart'
