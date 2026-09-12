#!/usr/bin/env bash
set -euo pipefail

# Launch one local OpenStream role without putting pairing JSON in an ordinary
# command line, config file, or inherited environment. The pairing file is
# only exposed to the child through OPENSTREAM_PAIRING_FILE and is validated
# again by the Rust client-core loader.

usage() {
    cat >&2 <<'EOF'
usage: openstream-local-session.sh --role host|client|both \
    (--pairing-file ABSOLUTE_PATH | --pairing-stdin) [options]

options:
  --duration SECONDS       bounded session duration (default: 60, max: 86400)
  --host-command PATH      host/agent executable (default: openstream-ffmpeg-host)
  --client-command PATH    client executable (default: openstream-desktop-client)
  --signal-command PATH    optional signal-server executable to supervise
  --help

The pairing JSON read from --pairing-stdin is stored in a private temporary
file and never printed. Use OPENSTREAM_SIGNAL_ORIGIN and the normal OpenStream
policy environment variables to select the service and media backend.
OPENSTREAM_PAIRING_JSON remains available only through the explicitly marked
OPENSTREAM_DEVELOPER_OVERRIDE=1 developer path in the binaries themselves.
EOF
}

role=""
pairing_file=""
pairing_stdin=0
duration=60
host_command="${OPENSTREAM_HOST_COMMAND:-openstream-ffmpeg-host}"
client_command="${OPENSTREAM_CLIENT_COMMAND:-openstream-desktop-client}"
signal_command="${OPENSTREAM_SIGNAL_COMMAND:-}"

while (($# > 0)); do
    case "$1" in
        --role)
            (($# >= 2)) || { echo "--role requires a value" >&2; exit 2; }
            role=$2
            shift 2
            ;;
        --pairing-file)
            (($# >= 2)) || { echo "--pairing-file requires a path" >&2; exit 2; }
            pairing_file=$2
            shift 2
            ;;
        --pairing-stdin)
            pairing_stdin=1
            shift
            ;;
        --duration)
            (($# >= 2)) || { echo "--duration requires a value" >&2; exit 2; }
            duration=$2
            shift 2
            ;;
        --host-command)
            (($# >= 2)) || { echo "--host-command requires a path" >&2; exit 2; }
            host_command=$2
            shift 2
            ;;
        --client-command)
            (($# >= 2)) || { echo "--client-command requires a path" >&2; exit 2; }
            client_command=$2
            shift 2
            ;;
        --signal-command)
            (($# >= 2)) || { echo "--signal-command requires a path" >&2; exit 2; }
            signal_command=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

case "$role" in
    host|client|both) ;;
    *)
        echo "--role must be host, client, or both" >&2
        exit 2
        ;;
esac

case "$duration" in
    ''|*[!0-9]*)
        echo "--duration must be an integer" >&2
        exit 2
        ;;
esac
if (( duration < 1 || duration > 86400 )); then
    echo "--duration must be between 1 and 86400 seconds" >&2
    exit 2
fi

if (( pairing_stdin == 1 )) && [[ -n "$pairing_file" ]]; then
    echo "--pairing-file and --pairing-stdin are mutually exclusive" >&2
    exit 2
fi
if (( pairing_stdin == 0 )) && [[ -z "$pairing_file" ]]; then
    echo "one of --pairing-file or --pairing-stdin is required" >&2
    exit 2
fi

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/openstream-local-session.XXXXXX")"
child_pids=()
child_labels=()

stop_children() {
    local index pid remaining
    for index in "${!child_pids[@]}"; do
        pid=${child_pids[$index]:-}
        [[ -z "$pid" ]] && continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        remaining=0
        for index in "${!child_pids[@]}"; do
            pid=${child_pids[$index]:-}
            [[ -z "$pid" ]] && continue
            if kill -0 "$pid" 2>/dev/null; then
                remaining=1
            fi
        done
        (( remaining == 0 )) && break
        sleep 0.1
    done
    for index in "${!child_pids[@]}"; do
        pid=${child_pids[$index]:-}
        [[ -z "$pid" ]] && continue
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        child_pids[$index]=""
    done
}

cleanup() {
    stop_children
    if [[ -n "$tmp_dir" ]]; then
        rm -rf "$tmp_dir"
    fi
}

finish() {
    local status=$?
    trap - EXIT INT TERM
    cleanup
    if (( status != 0 )); then
        echo "OpenStream local session failed; pairing and child output were not printed" >&2
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM

if (( pairing_stdin == 1 )); then
    pairing_file="$tmp_dir/pairing.json"
    cat >"$pairing_file"
fi

if [[ "$pairing_file" != /* ]]; then
    echo "pairing file path must be absolute" >&2
    exit 2
fi
if [[ ! -f "$pairing_file" || -L "$pairing_file" ]]; then
    echo "pairing file must be a regular non-symlink file" >&2
    exit 2
fi

if ! command -v stat >/dev/null 2>&1 || ! command -v id >/dev/null 2>&1; then
    echo "stat and id are required to validate the pairing file" >&2
    exit 2
fi
if stat -c '%a %u' "$pairing_file" >/dev/null 2>&1; then
    pairing_stat="$(stat -c '%a %u' "$pairing_file")"
else
    pairing_stat="$(stat -f '%Lp %u' "$pairing_file" 2>/dev/null)" || {
        echo "could not inspect pairing-file ownership" >&2
        exit 2
    }
fi
read -r pairing_mode pairing_uid <<<"$pairing_stat"
mode_value=$((0$pairing_mode))
if (( (mode_value & 077) != 0 || (mode_value & 0400) == 0 )); then
    echo "pairing file must be readable only by its owner" >&2
    exit 2
fi
if [[ "$pairing_uid" != "$(id -u)" ]]; then
    echo "pairing file must be owned by the current user" >&2
    exit 2
fi

pairing_bytes="$(wc -c <"$pairing_file" | tr -d '[:space:]')"
case "$pairing_bytes" in
    ''|*[!0-9]*)
        echo "could not inspect pairing-file size" >&2
        exit 2
        ;;
esac
if (( pairing_bytes < 1 || pairing_bytes > 65536 )); then
    echo "pairing file is empty or exceeds 65536 bytes" >&2
    exit 2
fi

if [[ "$role" == host || "$role" == both ]]; then
    command -v "$host_command" >/dev/null 2>&1 || {
        echo "host command is unavailable" >&2
        exit 2
    }
fi
if [[ "$role" == client || "$role" == both ]]; then
    command -v "$client_command" >/dev/null 2>&1 || {
        echo "client command is unavailable" >&2
        exit 2
    }
fi
if [[ -n "$signal_command" ]]; then
    command -v "$signal_command" >/dev/null 2>&1 || {
        echo "signal command is unavailable" >&2
        exit 2
    }
fi

launch() {
    local label=$1
    local command=$2
    local log_file="$tmp_dir/$label.log"
    shift 2
    # The helper deliberately captures child output in private temporary
    # state. A child must not be able to echo the pairing through this
    # launcher, including on a failed session.
    env -u OPENSTREAM_PAIRING_JSON \
        -u OPENSTREAM_DEVELOPER_OVERRIDE \
        OPENSTREAM_PAIRING_FILE="$pairing_file" \
        OPENSTREAM_HOST_SECONDS="$duration" \
        OPENSTREAM_CLIENT_SECONDS="$duration" \
        "$command" "$@" >"$log_file" 2>&1 &
    child_pids+=("$!")
    child_labels+=("$label")
}

if [[ -n "$signal_command" ]]; then
    launch signal "$signal_command"
fi
if [[ "$role" == host || "$role" == both ]]; then
    launch host "$host_command"
fi
if [[ "$role" == client || "$role" == both ]]; then
    launch client "$client_command"
fi

deadline=$((SECONDS + duration))
active=${#child_pids[@]}
failure=0
while (( active > 0 && failure == 0 )); do
    for index in "${!child_pids[@]}"; do
        pid=${child_pids[$index]:-}
        [[ -z "$pid" ]] && continue
        if ! kill -0 "$pid" 2>/dev/null; then
            if wait "$pid"; then
                child_pids[$index]=""
                active=$((active - 1))
            else
                failure=1
                echo "OpenStream ${child_labels[$index]} process exited unsuccessfully" >&2
                break
            fi
        fi
    done
    (( active == 0 || failure != 0 )) && break
    if (( SECONDS >= deadline )); then
        break
    fi
    sleep 0.1
done

if (( failure != 0 )); then
    exit 1
fi

# A child that is still running at the deadline receives SIGTERM through the
# EXIT trap. A clean early exit is also accepted, but a non-zero exit above is
# always fatal.
exit 0
