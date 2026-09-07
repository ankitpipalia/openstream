#!/bin/sh
# Create one OpenStream host/client pairing from the self-hosted service.
# The JSON response contains bearer capabilities; protect stdout and any
# terminal/log that captures it.
set -eu

origin=${OPENSTREAM_SIGNAL_ORIGIN:-http://127.0.0.1:8080}
ttl=${OPENSTREAM_SESSION_TTL:-3600}

case "$ttl" in
    ''|*[!0-9]*)
        echo "OPENSTREAM_SESSION_TTL must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$ttl" -lt 1 ]; then
    echo "OPENSTREAM_SESSION_TTL must be a positive integer" >&2
    exit 2
fi

url="${origin%/}/v1/session"
if [ -n "${OPENSTREAM_ADMIN_TOKEN:-}" ]; then
    # Feed the bearer header through stdin so it does not appear in `ps`
    # output. The pairing response itself is still treated as a secret.
    pairing=$(printf 'Authorization: Bearer %s\n' "$OPENSTREAM_ADMIN_TOKEN" | curl -fsS -X POST \
        --connect-timeout 5 --max-time 20 -H @- \
        -H 'Content-Type: application/json' \
        --data "{\"ttl_seconds\":${ttl}}" \
        "$url")
else
    pairing=$(curl -fsS -X POST \
        --connect-timeout 5 --max-time 20 \
        -H 'Content-Type: application/json' \
        --data "{\"ttl_seconds\":${ttl}}" \
        "$url")
fi

# When the service mints session-scoped TURN credentials, fetch one set per
# role. TURN usernames are role-bound; embedding only the host credential in a
# shared pairing made the client present the wrong authorization to coturn.
# A service without TURN configured answers 503; that is not an error here.
if [ "${OPENSTREAM_FETCH_TURN:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
    session_id=$(printf '%s' "$pairing" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')
    host_token=$(printf '%s' "$pairing" | python3 -c 'import sys,json; print(json.load(sys.stdin)["host_token"])')
    client_token=$(printf '%s' "$pairing" | python3 -c 'import sys,json; print(json.load(sys.stdin)["client_token"])')
    host_turn=''
    client_turn=''
    fetch_turn() {
        token=$1
        endpoint=$2
        response_file=$(mktemp "${TMPDIR:-/tmp}/openstream-turn.XXXXXX") || return 1
        if ! status=$(printf 'Authorization: Bearer %s\n' "$token" | curl -sS \
                --connect-timeout 5 --max-time 20 -H @- -o "$response_file" \
                -w '%{http_code}' "$endpoint"); then
            rm -f "$response_file"
            return 1
        fi
        case "$status" in
            200)
                cat "$response_file"
                rm -f "$response_file"
                return 0
                ;;
            503)
                rm -f "$response_file"
                return 2
                ;;
            *)
                cat "$response_file" >&2
                rm -f "$response_file"
                return 1
                ;;
        esac
    }
    if turn=$(fetch_turn "$host_token" "${origin%/}/v1/session/${session_id}/turn"); then
        host_turn=$turn
    else
        status=$?
        if [ "$status" -ne 2 ]; then
            echo "failed to fetch host TURN credentials" >&2
            exit 1
        fi
    fi
    if turn=$(fetch_turn "$client_token" "${origin%/}/v1/session/${session_id}/turn"); then
        client_turn=$turn
    else
        status=$?
        if [ "$status" -ne 2 ]; then
            echo "failed to fetch client TURN credentials" >&2
            exit 1
        fi
    fi
    pairing=$(printf '%s\n%s\n%s' "$pairing" "$host_turn" "$client_turn" | python3 -c '
import sys, json
pairing = json.loads(sys.stdin.readline())
host_line = sys.stdin.readline().strip()
client_line = sys.stdin.readline().strip()
if host_line:
    pairing["turn_host"] = json.loads(host_line)
    if not pairing.get("turn"):
        pairing["turn"] = pairing["turn_host"]
if client_line:
    pairing["turn_client"] = json.loads(client_line)
print(json.dumps(pairing))')
fi
printf '%s\n' "$pairing"
