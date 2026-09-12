#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
helper="$script_dir/openstream-local-session.sh"

if [[ ! -x "$helper" ]]; then
    echo "openstream-local-session helper is not implemented" >&2
    exit 1
fi

if grep -Eq '^[[:space:]]*set[[:space:]]+[^#]*x' "$helper"; then
    echo "openstream-local-session must not enable shell tracing" >&2
    exit 1
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/openstream-local-session-test.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

pairing_secret='pairing-secret-sentinel'
pairing_json=$(printf '%s' '{"session_id":"session-test","host_token":"pairing-secret-sentinel","client_token":"client-token","websocket_path":"/v1/signal/session-test/client","expires_in_seconds":60}')
pairing_file="$test_root/pairing.json"
printf '%s\n' "$pairing_json" >"$pairing_file"
chmod 600 "$pairing_file"

fake_client="$test_root/fake-client.sh"
cat >"$fake_client" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${OPENSTREAM_PAIRING_FILE:-}" || ! -f "$OPENSTREAM_PAIRING_FILE" ]]; then
    exit 64
fi
if [[ -n "${OPENSTREAM_PAIRING_JSON:-}" ]]; then
    exit 65
fi
if [[ -n "${OPENSTREAM_LOCAL_SESSION_MARKER:-}" ]]; then
    printf '%s\n' started >"$OPENSTREAM_LOCAL_SESSION_MARKER"
fi
shutdown() {
    if [[ -n "${OPENSTREAM_LOCAL_SESSION_MARKER:-}" ]]; then
        printf '%s\n' terminated >>"$OPENSTREAM_LOCAL_SESSION_MARKER"
    fi
    exit 0
}
trap shutdown TERM INT
while :; do
    sleep 1
done
EOF
chmod 700 "$fake_client"

assert_no_secret() {
    local output=$1
    if [[ "$output" == *"$pairing_secret"* ]]; then
        echo "local session helper leaked pairing material" >&2
        exit 1
    fi
}

assert_private_temp_state_clean() {
    if find "$test_root" -maxdepth 1 -type d -name 'openstream-local-session.*' -print -quit | grep -q .; then
        echo "local session helper left private temporary state behind" >&2
        exit 1
    fi
}

printf '%s\n' 'test: missing pairing file is rejected'
missing_output=''
if missing_output=$(TMPDIR="$test_root" "$helper" \
    --role client \
    --pairing-file "$test_root/missing.json" \
    --client-command "$fake_client" 2>&1); then
    echo "missing pairing file was accepted" >&2
    exit 1
fi
assert_no_secret "$missing_output"

printf '%s\n' 'test: over-permissive pairing file is rejected'
chmod 644 "$pairing_file"
permissions_output=''
if permissions_output=$(TMPDIR="$test_root" "$helper" \
    --role client \
    --pairing-file "$pairing_file" \
    --client-command "$fake_client" 2>&1); then
    echo "over-permissive pairing file was accepted" >&2
    exit 1
fi
assert_no_secret "$permissions_output"
chmod 600 "$pairing_file"

printf '%s\n' 'test: stdin pairing reaches child without secret output'
stdin_marker="$test_root/stdin.marker"
stdin_output=$(printf '%s\n' "$pairing_json" | \
    TMPDIR="$test_root" \
    OPENSTREAM_LOCAL_SESSION_MARKER="$stdin_marker" \
    "$helper" \
    --role client \
    --pairing-stdin \
    --duration 1 \
    --client-command "$fake_client" 2>&1)
assert_no_secret "$stdin_output"
grep -q '^started$' "$stdin_marker"
grep -q '^terminated$' "$stdin_marker"
assert_private_temp_state_clean

printf '%s\n' 'test: session duration is bounded and child is terminated'
duration_marker="$test_root/duration.marker"
duration_start=$(date +%s)
duration_output=$(TMPDIR="$test_root" \
    OPENSTREAM_LOCAL_SESSION_MARKER="$duration_marker" \
    "$helper" \
    --role client \
    --pairing-file "$pairing_file" \
    --duration 1 \
    --client-command "$fake_client" 2>&1)
duration_end=$(date +%s)
duration_elapsed=$((duration_end - duration_start))
if (( duration_elapsed > 5 )); then
    echo "local session exceeded its bounded duration" >&2
    exit 1
fi
assert_no_secret "$duration_output"
grep -q '^terminated$' "$duration_marker"
assert_private_temp_state_clean

printf '%s\n' 'local session helper tests passed'
