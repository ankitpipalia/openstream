#!/usr/bin/env bash
set -euo pipefail

unset OPENSTREAM_PAIRING_JSON OPENSTREAM_DEVELOPER_OVERRIDE

# One-process-per-role acceptance test for the OpenStream-owned path switch.
# Pairing material is kept in a private temporary file and passed by path; it
# is never printed or copied into a log.

umask 077
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
lowlat_dir="$repo_dir/engine/lowlat"

pick_port() {
    python3 -c 'import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])'
}

signal_port="${OPENSTREAM_MIGRATION_SIGNAL_PORT:-$(pick_port)}"
relay_port="${OPENSTREAM_MIGRATION_RELAY_PORT:-$(pick_port)}"
server_log="$(mktemp -t openstream-migration-server.XXXXXX)"
pairing_file="$(mktemp -t openstream-migration-pairing.XXXXXX)"
host_log="$(mktemp -t openstream-migration-host.XXXXXX)"
client_log="$(mktemp -t openstream-migration-client.XXXXXX)"
server_pid=""
host_pid=""

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

client_pid=""
trap cleanup EXIT INT TERM

cd "$lowlat_dir"
cargo build -q --locked -p openstream-signal-server -p openstream-reference-peer

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$signal_port" \
OPENSTREAM_RELAY_BIND="127.0.0.1:$relay_port" \
OPENSTREAM_RELAY_ENDPOINT="127.0.0.1:$relay_port" \
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

python3 - "$pairing_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as pairing_file:
    pairing = json.load(pairing_file)
required = ("session_id", "host_token", "client_token", "relay_address",
            "relay_host_ticket", "relay_client_ticket")
missing = [field for field in required if not pairing.get(field)]
if missing:
    raise SystemExit("pairing is missing relay migration fields: " + ",".join(missing))
PY

common_env=(
    "OPENSTREAM_SIGNAL_ORIGIN=http://127.0.0.1:$signal_port"
    "OPENSTREAM_PAIRING_FILE=$pairing_file"
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
    echo "path migration peers failed (host=$host_status client=$client_status)" >&2
    sed -E 's/(host_token|client_token|relay_host_ticket|relay_client_ticket|password)[=:][^ ,}]*/\1=[redacted]/Ig' "$host_log" >&2
    sed -E 's/(host_token|client_token|relay_host_ticket|relay_client_ticket|password)[=:][^ ,}]*/\1=[redacted]/Ig' "$client_log" >&2
    exit 1
fi

require_line() {
    local line=$1
    local file=$2
    grep -Fqx "$line" "$file" || {
        echo "missing migration milestone: $line" >&2
        exit 1
    }
}

require_line 'migration committed generation=2 path=opaque_relay' "$host_log"
require_line 'migration committed generation=3 path=direct_udp' "$host_log"
require_line 'client acknowledged frame at generation=1' "$client_log"
require_line 'client acknowledged frame at generation=2' "$client_log"
require_line 'client acknowledged frame at generation=3' "$client_log"
require_line 'migration acceptance passed: one cipher session, three committed generations' "$host_log"

[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$host_log")" == 1 ]]
[[ "$(grep -Fc 'OpenStream peer identity fingerprint' "$client_log")" == 1 ]]
if grep -Eiq 'host_token|client_token|relay_host_ticket|relay_client_ticket|turn.*password|new cipher|second session|second key exchange' "$host_log" "$client_log"; then
    echo "migration logs contain credentials or a second-session indicator" >&2
    exit 1
fi
if grep -Eiq 'migration committed generation=2.*before|application.*before.*commit|duplicate.*cleanup|duplicate.*recovery' "$host_log" "$client_log"; then
    echo "migration logs contain an invalid ordering or duplicate recovery" >&2
    exit 1
fi

printf '%s\n' 'path migration acceptance passed: one cipher session, three committed generations'
