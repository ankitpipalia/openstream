#!/usr/bin/env bash
# Prove the shipped Linux configuration can actually start the broker.
#
# Every bug this exists to catch was invisible to every check the repository
# had. The units parsed, the package built, the binaries were tested -- and the
# pair could not start, because:
#
#   Environment=OPENSTREAM_BROKER_SOCKET_GID=     the broker parses "" and exits
#   OPENSTREAM_BROKER_SERVICE_UID unset           it admits uid 0, not the
#                                                 unprivileged account it is
#                                                 packaged with
#   Environment=OPENSTREAM_SIGNAL_ORIGIN=         replaces the program's default
#                                                 with an unusable origin
#   Environment=OPENSTREAM_PAIRING_FILE=          "no pairing" becomes "pairing
#                                                 at a path that cannot open"
#
# The common shape: `Environment=NAME=` is not an unset variable. The process
# sees NAME set to the empty string and reads it as a value. So there are two
# checks here -- a static one for that shape, which runs anywhere, and a
# functional one that starts the real binary with the real configuration, which
# needs Linux.
#
# Usage: scripts/test-linux-packaging.sh [path-to-openstream-host-broker]
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
units_dir="$repo_dir/packaging/linux"
broker_unit="$units_dir/openstream-host-broker.service"
service_unit="$units_dir/openstream-machine-service.service"
failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

pass() {
    printf 'ok: %s\n' "$1"
}

# ---------------------------------------------------------------------------
# 1. No variable is assigned the empty string.
#
# Runs on any platform, which is the point: the maintainer works on macOS and
# this is the check that would have caught four of the bugs above.
# ---------------------------------------------------------------------------
for unit in "$broker_unit" "$service_unit"; do
    empty="$(grep -nE '^Environment=[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*$' "$unit" || true)"
    if [ -n "$empty" ]; then
        fail "$(basename "$unit") assigns an empty value; comment the line out instead:
$empty"
    else
        pass "$(basename "$unit") assigns no empty values"
    fi
done

# ---------------------------------------------------------------------------
# 2. The pieces that have to agree between the two units and the package.
# ---------------------------------------------------------------------------
# Assert a file contains a pattern, saying what breaks if it does not.
require() {
    local file="$1" pattern="$2" what="$3" why="$4"
    if grep -qE "$pattern" "$file"; then
        pass "$what"
    else
        fail "$why"
    fi
}

require "$broker_unit" '^RuntimeDirectoryGroup=openstream$' \
    "the runtime directory is group-owned by the service account" \
    "the broker does not set RuntimeDirectoryGroup, so /run/openstream is
root-owned 0750 and the machine service cannot traverse it to reach the socket"

require "$broker_unit" '^EnvironmentFile=-/etc/openstream/broker\.env$' \
    "the broker reads its environment file" \
    "the broker does not read /etc/openstream/broker.env, so the uid and gid the
installer resolved have nowhere to go"

require "$service_unit" '^EnvironmentFile=-/etc/openstream/machine-service\.env$' \
    "the machine service reads its environment file" \
    "the machine service does not read its environment file"

socket_in_unit="$(sed -n 's/^Environment=OPENSTREAM_BROKER_SOCKET=//p' "$service_unit")"
if [ "$socket_in_unit" = "/run/openstream/broker.sock" ]; then
    pass "both halves agree on the socket path"
else
    fail "the machine service looks for the socket at '$socket_in_unit', which is
not under the broker's RuntimeDirectory"
fi

# ---------------------------------------------------------------------------
# 3. postinst writes the two numbers only the install knows.
# ---------------------------------------------------------------------------
build_deb="$units_dir/build-deb.sh"
if bash -n "$build_deb"; then
    pass "build-deb.sh is valid shell"
else
    fail "build-deb.sh is not valid shell"
fi

require "$build_deb" 'OPENSTREAM_BROKER_SERVICE_UID=\$service_uid' \
    "postinst writes the service uid" \
    "postinst does not write the service uid; the broker would fall back to
admitting uid 0 and refuse the unprivileged service it ships with"

require "$build_deb" 'OPENSTREAM_BROKER_SOCKET_GID=\$service_gid' \
    "postinst writes the socket gid" \
    "postinst does not write the socket gid"

require "$build_deb" 'if \[ ! -e /etc/openstream/broker\.env \]' \
    "postinst does not clobber the environment file on upgrade" \
    "postinst would overwrite broker.env on upgrade, silently discarding
whatever capability ceiling the operator configured"

# ---------------------------------------------------------------------------
# 4. systemd's own opinion, where systemd exists.
# ---------------------------------------------------------------------------
if command -v systemd-analyze >/dev/null 2>&1; then
    for unit in "$broker_unit" "$service_unit"; do
        # `verify` reports missing ExecStart binaries and unknown users as
        # warnings on a machine where the package is not installed; those are
        # expected here. Directives it does not understand are what matter.
        output="$(systemd-analyze verify "$unit" 2>&1 || true)"
        bad="$(printf '%s\n' "$output" | grep -iE 'unknown|invalid|failed to parse' || true)"
        if [ -n "$bad" ]; then
            fail "systemd-analyze rejected $(basename "$unit"):
$bad"
        else
            pass "systemd-analyze accepts $(basename "$unit")"
        fi
    done
else
    printf 'skip: systemd-analyze is not available here\n'
fi

# ---------------------------------------------------------------------------
# 5. The real binary, with the real configuration.
#
# The static checks above describe the shape of the bug. This one runs it: the
# broker either starts and listens, or it does not, and no amount of reading
# the unit file settles that.
# ---------------------------------------------------------------------------
broker="${1:-}"
if [ -z "$broker" ]; then
    for candidate in \
        "$repo_dir/engine/lowlat/target/release/openstream-host-broker" \
        "$repo_dir/engine/lowlat/target/debug/openstream-host-broker"; do
        [ -x "$candidate" ] && broker="$candidate" && break
    done
fi

if [ "$(uname -s)" != "Linux" ]; then
    printf 'skip: the broker only runs on Linux; static checks above are what this platform can do\n'
elif [ -z "$broker" ] || [ ! -x "$broker" ]; then
    fail "no openstream-host-broker binary found; build it with
  cargo build -p openstream-host-broker
or pass its path as the first argument"
else
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    mkdir -p "$work/etc" "$work/run"
    chmod 0700 "$work/etc"

    # The environment postinst writes, with this user's real ids standing in for
    # the openstream account's.
    cat >"$work/etc/broker.env" <<ENV
OPENSTREAM_BROKER_SERVICE_UID=$(id -u)
OPENSTREAM_BROKER_SOCKET_GID=$(id -g)
#OPENSTREAM_BROKER_CEILING=capture,keyboard,mouse
ENV
    chmod 0600 "$work/etc/broker.env"

    start_broker() {
        # systemd applies EnvironmentFile by exporting each line; `env` with the
        # file's contents is the same thing.
        (
            set -a
            # shellcheck disable=SC1090
            . "$1"
            set +a
            export OPENSTREAM_BROKER_SOCKET="$work/run/broker.sock"
            exec "$broker"
        ) >"$work/out" 2>&1 &
        echo $!
    }

    pid="$(start_broker "$work/etc/broker.env")"
    ready=0
    for _ in $(seq 1 50); do
        if [ -S "$work/run/broker.sock" ]; then
            ready=1
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if [ "$ready" = 1 ]; then
        pass "the broker starts and listens with the configuration the package writes"
    else
        fail "the broker did not start with the configuration the package writes:
$(cat "$work/out")"
    fi

    # Negative control. Without this the test above passes just as happily
    # against a broker that ignores its configuration entirely.
    cat >"$work/etc/empty-gid.env" <<'ENV'
OPENSTREAM_BROKER_SOCKET_GID=
ENV
    rm -f "$work/run/broker.sock"
    pid="$(start_broker "$work/etc/empty-gid.env")"
    still_up=0
    for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        [ -S "$work/run/broker.sock" ] && still_up=1 && break
        sleep 0.1
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if [ "$still_up" = 1 ]; then
        fail "an empty OPENSTREAM_BROKER_SOCKET_GID did not stop the broker, so
the check above proves nothing about the configuration"
    else
        pass "an empty gid is still rejected, so the check above is measuring something"
    fi
fi

if [ "$failures" -gt 0 ]; then
    printf '\n%d packaging check(s) failed\n' "$failures" >&2
    exit 1
fi
printf '\nLinux packaging configuration is coherent\n'
