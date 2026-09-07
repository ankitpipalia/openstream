#!/usr/bin/env bash
set -euo pipefail

# Start the self-hosted signal service, a real FFmpeg test-pattern host, and a
# headless OpenStream client. Pairing JSON and logs remain in private temporary
# files and are never printed. Override OPENSTREAM_FFMPEG_ARGS to use a real
# display/device input instead of the synthetic source.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
engine_dir="$repo_dir/engine/lowlat"
port="${OPENSTREAM_DEMO_PORT:-18084}"
seconds="${OPENSTREAM_DEMO_SECONDS:-8}"
output_file="${OPENSTREAM_DEMO_OUTPUT:-$repo_dir/openstream-demo.h264}"
server_log="$(mktemp -t openstream-demo-signal.XXXXXX)"
host_log="$(mktemp -t openstream-demo-host.XXXXXX)"
client_log="$(mktemp -t openstream-demo-client.XXXXXX)"
pairing_file="$(mktemp -t openstream-demo-pairing.XXXXXX)"
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
    rm -f "$server_log" "$host_log" "$client_log" "$pairing_file"
}

on_exit() {
    status=$?
    if [[ "$status" != 0 ]]; then
        echo "OpenStream local demo failed; diagnostic logs follow" >&2
        echo "signal server:" >&2
        sed -n '1,120p' "$server_log" >&2 || true
        echo "host:" >&2
        sed -n '1,160p' "$host_log" >&2 || true
        echo "client:" >&2
        sed -n '1,160p' "$client_log" >&2 || true
    fi
    cleanup
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

if ! command -v ffmpeg >/dev/null 2>&1; then
    echo "ffmpeg is required for the local demo" >&2
    exit 2
fi

cd "$engine_dir"
cargo build -q --locked \
    -p openstream-signal-server \
    -p openstream-ffmpeg-host \
    -p openstream-client

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$port" target/debug/openstream-signal-server \
    >"$server_log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "signal server did not become ready" >&2
    exit 1
fi

curl -fsS -X POST "http://127.0.0.1:$port/v1/session" \
    -H 'content-type: application/json' \
    -d '{"ttl_seconds":120}' >"$pairing_file"
pairing_json="$(tr -d '\n' <"$pairing_file")"

ffmpeg_args="${OPENSTREAM_FFMPEG_ARGS:--f lavfi -i testsrc2=size=1280x720:rate=30}"
common_env=(
    OPENSTREAM_SIGNAL_ORIGIN="http://127.0.0.1:$port"
    OPENSTREAM_PAIRING_JSON="$pairing_json"
    OPENSTREAM_UDP_BIND="127.0.0.1:0"
    OPENSTREAM_HOST_SECONDS="$seconds"
    OPENSTREAM_CLIENT_SECONDS="$seconds"
    OPENSTREAM_FFMPEG_ARGS="$ffmpeg_args"
)

env "${common_env[@]}" target/debug/openstream-ffmpeg-host \
    >"$host_log" 2>&1 &
host_pid=$!

if ! env "${common_env[@]}" OPENSTREAM_OUTPUT="$output_file" \
    target/debug/openstream-client >"$client_log" 2>&1; then
    cat "$client_log" >&2
    cat "$host_log" >&2
    exit 1
fi
wait "$host_pid"

test -s "$output_file"
grep -q 'OpenStream client wrote' "$client_log"
grep -Eq 'OpenStream FFmpeg host (sent|ended after peer disconnect)' "$host_log"
printf '%s\n' "OpenStream local demo passed; H.264 output: $output_file"
