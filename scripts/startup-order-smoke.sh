#!/usr/bin/env bash
set -euo pipefail

# Prove that direct-v2 establishment is independent of startup order. The host
# is started first and must remain alive while the client is deliberately held
# back for more than the historical 15-second candidate deadline. This is a
# local reference-peer test, not a public-NAT, coturn, hardware, or media
# acceptance test.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd "$script_dir/.." && pwd -P)"
lowlat_dir="$repo_dir/engine/lowlat"

startup_delay="${OPENSTREAM_STARTUP_DELAY_SECONDS:-16}"
max_runtime="${OPENSTREAM_STARTUP_MAX_RUNTIME_SECONDS:-60}"
signal_port="${OPENSTREAM_STARTUP_SIGNAL_PORT:-}"

case "$startup_delay" in
    ''|*[!0-9]*)
        echo "OPENSTREAM_STARTUP_DELAY_SECONDS must be an integer" >&2
        exit 2
        ;;
esac
if (( startup_delay < 16 )); then
    echo "OPENSTREAM_STARTUP_DELAY_SECONDS must be at least 16 to exceed the old 15-second phase deadline" >&2
    exit 2
fi
case "$max_runtime" in
    ''|*[!0-9]*)
        echo "OPENSTREAM_STARTUP_MAX_RUNTIME_SECONDS must be an integer" >&2
        exit 2
        ;;
esac
if (( max_runtime <= startup_delay )); then
    echo "OPENSTREAM_STARTUP_MAX_RUNTIME_SECONDS must exceed the startup delay" >&2
    exit 2
fi

if [[ -z "$signal_port" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is required when OPENSTREAM_STARTUP_SIGNAL_PORT is unset" >&2
        exit 2
    fi
    signal_port="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
fi
case "$signal_port" in
    ''|*[!0-9]*)
        echo "OPENSTREAM_STARTUP_SIGNAL_PORT must be a numeric TCP port" >&2
        exit 2
        ;;
esac
if (( signal_port < 1 || signal_port > 65535 )); then
    echo "OPENSTREAM_STARTUP_SIGNAL_PORT is outside the TCP port range" >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for startup-order smoke" >&2
    exit 2
fi

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/openstream-startup.XXXXXX")"
server_log="$tmp_dir/signal-server.log"
host_log="$tmp_dir/host.log"
client_log="$tmp_dir/client.log"
pairing_file="$tmp_dir/pairing.json"
server_pid=""
host_pid=""
client_pid=""

redact_log() {
    local path=$1
    sed -E \
        's/(host_token|client_token|relay_host_ticket|relay_client_ticket|turn_password|password)[=:][^[:space:],}]*/\1=[redacted]/Ig' \
        "$path" 2>/dev/null || true
}

stop_pid() {
    local pid=${1:-}
    [[ -z "$pid" ]] && return 0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    stop_pid "$client_pid"
    stop_pid "$host_pid"
    stop_pid "$server_pid"
    rm -rf "$tmp_dir"
}

failure_report() {
    local status=$?
    if (( status != 0 )); then
        echo "startup-order smoke failed; redacted diagnostics follow" >&2
        echo "signal server:" >&2
        redact_log "$server_log" >&2
        echo "host:" >&2
        redact_log "$host_log" >&2
        echo "client:" >&2
        redact_log "$client_log" >&2
    fi
    cleanup
    return "$status"
}
trap failure_report EXIT
trap 'exit 130' INT TERM

wait_for_pid() {
    local pid=$1
    local label=$2
    local deadline=$((SECONDS + max_runtime))
    while kill -0 "$pid" 2>/dev/null; do
        local state
        state="$(ps -p "$pid" -o state= 2>/dev/null | tr -d '[:space:]')"
        [[ "$state" == Z* || -z "$state" ]] && break
        if (( SECONDS >= deadline )); then
            echo "$label exceeded ${max_runtime}s timeout" >&2
            kill "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
    done
    wait "$pid"
}

cd "$lowlat_dir"
cargo build -q --locked -p openstream-signal-server -p openstream-reference-peer

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$signal_port" \
    target/debug/openstream-signal-server >"$server_log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS --connect-timeout 1 --max-time 2 \
        "http://127.0.0.1:$signal_port/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "signal server did not become ready" >&2
    exit 1
fi

curl -fsS --connect-timeout 5 --max-time 10 \
    -X POST "http://127.0.0.1:$signal_port/v1/session" \
    -H 'content-type: application/json' \
    -d '{"ttl_seconds":120}' >"$pairing_file"
pairing_json="$(<"$pairing_file")"
if [[ -z "$pairing_json" ]]; then
    echo "signal server returned an empty pairing" >&2
    exit 1
fi

common_env=(
    "OPENSTREAM_SIGNAL_ORIGIN=http://127.0.0.1:$signal_port"
    "OPENSTREAM_PAIRING_JSON=$pairing_json"
    "OPENSTREAM_UDP_BIND=127.0.0.1:0"
)

# Start only the host. It must remain in WAITING_FOR_PEER while this shell
# sleeps past the old candidate deadline; no second session or reconnect is
# allowed to mask a failed first attempt.
env "${common_env[@]}" target/debug/openstream-reference-peer host >"$host_log" 2>&1 &
host_pid=$!
sleep "$startup_delay"
if ! kill -0 "$host_pid" 2>/dev/null; then
    echo "host exited before the delayed client joined" >&2
    wait "$host_pid" 2>/dev/null || true
    exit 1
fi

env "${common_env[@]}" target/debug/openstream-reference-peer client >"$client_log" 2>&1 &
client_pid=$!

host_status=0
client_status=0
wait_for_pid "$client_pid" client || client_status=$?
wait_for_pid "$host_pid" host || host_status=$?
client_pid=""
host_pid=""

if (( host_status != 0 || client_status != 0 )); then
    echo "reference peers failed (host=$host_status client=$client_status)" >&2
    exit 1
fi

grep -Fqx 'host sent an authenticated fragmented video frame and received its ack' "$host_log"
grep -Fq 'client received authenticated fragmented video payload:' "$client_log"
[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$host_log")" == 1 ]]
[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$client_log")" == 1 ]]
if grep -Eiq \
    'host_token|client_token|relay_host_ticket|relay_client_ticket|turn_password|new cipher|second session|second key exchange' \
    "$server_log" "$host_log" "$client_log"; then
    echo "startup-order logs contain credentials or a second-session indicator" >&2
    exit 1
fi

printf '%s\n' "startup-order smoke passed: host waited ${startup_delay}s, direct-v2 encrypted control/media completed"
