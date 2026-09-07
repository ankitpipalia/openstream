#!/usr/bin/env bash
set -euo pipefail

# Run from any directory after building the OpenStream development binaries.
# The script intentionally uses loopback and emits only success/failure text;
# pairing JSON contains bearer capabilities and is never printed.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../engine/lowlat" && pwd)"
port="${OPENSTREAM_SMOKE_PORT:-18083}"
server_log="$(mktemp -t openstream-signal.XXXXXX)"
pairing_file="$(mktemp -t openstream-pairing.XXXXXX)"
host_log="$(mktemp -t openstream-host.XXXXXX)"
client_log="$(mktemp -t openstream-client.XXXXXX)"
server_pid=""
host_pid=""

cleanup() {
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

cd "$repo_dir"
cargo build -q --locked -p openstream-signal-server -p openstream-reference-peer

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$port" target/debug/openstream-signal-server \
    >"$server_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
curl -fsS -X POST "http://127.0.0.1:$port/v1/session" \
    -H 'content-type: application/json' \
    -d '{"ttl_seconds":120}' >"$pairing_file"

pairing_json="$(tr -d '\n' <"$pairing_file")"
common_env=(
    OPENSTREAM_ICE=1
    OPENSTREAM_SIGNAL_ORIGIN="http://127.0.0.1:$port"
    OPENSTREAM_PAIRING_JSON="$pairing_json"
)
if [[ -n "${OPENSTREAM_ICE_URLS:-}" ]]; then
    # With an external STUN/TURN profile, leave loopback out so a successful
    # local host candidate cannot mask the configured relay path.
    common_env+=(OPENSTREAM_ICE_URLS="$OPENSTREAM_ICE_URLS")
    if [[ -n "${OPENSTREAM_TURN_USERNAME:-}" ]]; then
        common_env+=(OPENSTREAM_TURN_USERNAME="$OPENSTREAM_TURN_USERNAME")
    fi
    if [[ -n "${OPENSTREAM_TURN_PASSWORD:-}" ]]; then
        common_env+=(OPENSTREAM_TURN_PASSWORD="$OPENSTREAM_TURN_PASSWORD")
    fi
else
    common_env+=(OPENSTREAM_ICE_INCLUDE_LOOPBACK=1)
fi

env "${common_env[@]}" target/debug/openstream-reference-peer host >"$host_log" 2>&1 &
host_pid=$!
if ! env "${common_env[@]}" target/debug/openstream-reference-peer client >"$client_log" 2>&1; then
    cat "$client_log" >&2
    cat "$host_log" >&2
    exit 1
fi
wait "$host_pid"

grep -q 'client received authenticated fragmented video payload' "$client_log"
grep -q 'host sent an authenticated fragmented video frame and received its ack' "$host_log"
printf '%s\n' 'full ICE loopback smoke passed: authenticated fragmented frame and ACK'
