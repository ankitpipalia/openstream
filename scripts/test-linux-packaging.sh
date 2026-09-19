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
# What this does NOT do: start either systemd unit, and exercise the
# machine-service -> Unix socket -> broker path as the unprivileged user. It
# launches the broker binary directly with the environment the package writes.
# That is enough to catch every problem listed above and is not an install test.
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

# One cleanup for every scratch directory this script makes.
#
# There is only ever one EXIT trap: a second `trap ... EXIT` silently replaces
# the first, which is what happened here -- the postinst scratch directory was
# registered, the broker's working directory replaced it, and the first was
# left behind on every run.
scratch=""
work=""
pkg_scratch=""
cleanup() {
    [ -n "$scratch" ] && rm -rf -- "$scratch"
    [ -n "$work" ] && rm -rf -- "$work"
    [ -n "$pkg_scratch" ] && rm -rf -- "$pkg_scratch"
    return 0
}
trap cleanup EXIT

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

require "$broker_unit" '^Group=openstream$' \
    "the runtime directory is group-owned by the service account" \
    "the broker does not set Group=, so systemd gives its RuntimeDirectory the
unit's default ownership -- root:root 0750 -- and the unprivileged machine
service cannot traverse it to reach the socket"

# The directive that does not exist. systemd ignores an unknown key with a log
# line nobody reads, so this file looked correct and shipped a directory the
# service could not enter.
if grep -q '^RuntimeDirectoryGroup=' "$broker_unit"; then
    fail "the broker uses RuntimeDirectoryGroup=, which systemd has no such
directive for; it is silently ignored. RuntimeDirectory ownership comes from
User= and Group=."
else
    pass "no RuntimeDirectoryGroup= (systemd has no such directive)"
fi

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
# 3b. Run the postinst, rather than reading it.
#
# The env files are written by shell heredocs whose delimiters are deliberately
# unquoted, so that `$service_uid` expands. That also means every other `$` and
# backtick expands, and a stray one produces a file that is subtly wrong in a
# way no grep of the generator would notice. `bash -n` does not catch it either:
# the script is valid, its output is not.
#
# So the postinst is extracted and executed against a scratch directory, with
# the account tools stubbed, and the files it produces are inspected.
# ---------------------------------------------------------------------------
scratch="$(mktemp -d)"
mkdir -p "$scratch/etc" "$scratch/bin"

# getent is what the postinst asks for the account's numeric ids.
cat >"$scratch/bin/getent" <<'STUB'
#!/bin/sh
case "$1" in
    passwd) echo "openstream:x:995:990::/nonexistent:/usr/sbin/nologin" ;;
    group)  echo "openstream:x:990:" ;;
esac
STUB
for stub in addgroup adduser systemctl; do
    printf '#!/bin/sh\nexit 0\n' >"$scratch/bin/$stub"
done
chmod 0755 "$scratch/bin/"*

# Extract the postinst exactly as build-deb.sh emits it, and point the one
# absolute path it writes to at the scratch tree.
sed -n "/^cat >\"\$stage\/DEBIAN\/postinst\" <<'POSTINST'$/,/^POSTINST$/p" "$build_deb" |
    sed '1d;$d' |
    sed "s#/etc/openstream#$scratch/etc/openstream#g" >"$scratch/postinst"
mkdir -p "$scratch/etc/openstream"

if PATH="$scratch/bin:$PATH" sh "$scratch/postinst" configure >"$scratch/notice" 2>&1; then
    pass "postinst runs to completion"
else
    fail "postinst failed: $(cat "$scratch/notice")"
fi

env_file="$scratch/etc/openstream/broker.env"
if [ -f "$env_file" ]; then
    pass "postinst wrote broker.env"
    # The ids it resolved, not the names of the variables holding them.
    grep -q '^OPENSTREAM_BROKER_SERVICE_UID=995$' "$env_file" ||
        fail "broker.env does not carry the resolved uid:
$(grep -i uid "$env_file" || echo '  (no uid line at all)')"
    grep -q '^OPENSTREAM_BROKER_SOCKET_GID=990$' "$env_file" ||
        fail "broker.env does not carry the resolved gid"
    # An unexpanded variable, or a heredoc that swallowed one.
    unexpanded="$(grep -n '\$service_\|\$(' "$env_file" || true)"
    [ -z "$unexpanded" ] || fail "broker.env contains unexpanded shell:
$unexpanded"
    # Optional settings must be commented, never assigned empty -- the whole
    # class of bug this file exists to prevent.
    empty_env="$(grep -nE '^[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*$' "$env_file" || true)"
    [ -z "$empty_env" ] || fail "broker.env assigns an empty value:
$empty_env"
    mode="$(ls -l "$env_file" | cut -c1-10)"
    [ "$mode" = "-rw-------" ] || fail "broker.env is $mode, not 0600"
    [ -n "$unexpanded$empty_env" ] || pass "broker.env is fully expanded, 0600, with no empty assignments"
else
    fail "postinst did not write broker.env"
fi

service_env="$scratch/etc/openstream/machine-service.env"
if [ -f "$service_env" ]; then
    empty_env="$(grep -nE '^[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*$' "$service_env" || true)"
    [ -z "$empty_env" ] || fail "machine-service.env assigns an empty value:
$empty_env"
    [ -n "$empty_env" ] || pass "machine-service.env has no empty assignments"
else
    fail "postinst did not write machine-service.env"
fi

# An upgrade must not discard what the operator configured. Nothing else in
# this file tests that claim; the grep above only proves the guard is written.
if [ -f "$env_file" ]; then
    printf 'OPENSTREAM_BROKER_CEILING=capture,keyboard\n' >>"$env_file"
    PATH="$scratch/bin:$PATH" sh "$scratch/postinst" configure >/dev/null 2>&1 || true
    if grep -q '^OPENSTREAM_BROKER_CEILING=capture,keyboard$' "$env_file"; then
        pass "a second configure leaves the operator's settings alone"
    else
        fail "re-running postinst discarded the configured ceiling, which on a
package upgrade would silently stop the machine granting anything"
    fi
fi

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
    # The broker stays up until the connection below has been attempted.
    # Killing it here and then connecting -- which is what this did -- tests
    # nothing except that a dead process does not accept connections: the
    # socket file outlives the process, so the connect always failed and the
    # check could never pass. It had never run, because the workflow step that
    # invokes this script only runs on a pull request and the branch had none.
    if [ "$ready" = 1 ]; then
        pass "the broker starts and listens with the configuration the package writes"
        # A socket file is not a listener. `RuntimeDirectory` would leave one
        # behind after a crash, and the bind can succeed on a path nothing is
        # accepting on -- so connect to it.
        if python3 - "$work/run/broker.sock" <<'CONNECT'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sys.argv[1])
s.close()
CONNECT
        then
            pass "the socket accepts a connection"
        else
            fail "the socket exists but refused a connection, so nothing is
listening on the path the machine service is configured to use"
        fi
    else
        fail "the broker did not start with the configuration the package writes:
$(cat "$work/out")"
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

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

# ---------------------------------------------------------------------------
# 6. The headless package contains what a server needs, and nothing else.
#
# Built here from stub binaries rather than real ones. What is being checked is
# the packaging decision -- which files are chosen, what the control file
# claims -- and that does not need a compiler. Building it for real is the
# install test on a machine, which is a separate exercise.
#
# The bug this exists to catch: a headless host package that declares
# `Depends: ffmpeg`, or carries the desktop shell, pulls a graphical stack onto
# every server for a component the accepted media path does not use.
# ---------------------------------------------------------------------------
if ! command -v dpkg-deb >/dev/null 2>&1; then
    printf 'ok: (skipped) headless package contents need dpkg-deb\n'
else
    pkg_scratch="$(mktemp -d "${TMPDIR:-/tmp}/openstream-deb-test.XXXXXX")"
    mkdir -p "$pkg_scratch/bin"
    # Real binaries when this machine has them, stubs otherwise.
    #
    # Which files a package chooses needs no compiler, so stubs are enough for
    # the contents checks. What it declares it links against cannot be asked of
    # a shell script: dpkg-shlibdeps reads ELF headers, so a stub package
    # correctly declares no libraries and the dependency assertion below is
    # skipped rather than made to pass on something it did not measure.
    real_bin_dir=""
    for candidate in "$repo_dir/engine/lowlat/target/release" \
        "$repo_dir/engine/lowlat/target/debug"; do
        if [ -x "$candidate/openstream-host-broker" ] &&
            [ -x "$candidate/openstream-machine-service" ] &&
            [ -x "$candidate/openstream-enrol" ]; then
            real_bin_dir="$candidate"
            break
        fi
    done
    if [ -z "$real_bin_dir" ]; then
        # Stubs used to do for the contents checks, and cannot any more: the
        # build requires dpkg-shlibdeps to find real library dependencies, and
        # a shell script has none. Skipping is honest; passing on a package
        # built from stubs would not measure what this section claims to.
        printf 'ok: (skipped) package contents need the three binaries built\n'
        printf '     build them with: cargo build -p openstream-host-broker \\\n'
        printf '       -p openstream-machine-service -p openstream-enrol\n'
        rm -rf -- "$pkg_scratch"
        pkg_scratch=""
        real_bin_dir=""
    fi
    pkg_bin_dir="$real_bin_dir"
    deb="$pkg_scratch/headless.deb"
    if [ -z "$real_bin_dir" ]; then
        :
    elif OPENSTREAM_ARTIFACT_DIR="$pkg_bin_dir" \
        bash "$build_deb" --profile headless "$deb" >/dev/null 2>"$pkg_scratch/err"; then
        pass "the headless profile builds a package"

        contents="$(dpkg-deb -c "$deb")"
        control="$(dpkg-deb -f "$deb")"

        for wanted in usr/bin/openstream-host-broker \
            usr/bin/openstream-machine-service \
            usr/bin/openstream-enrol \
            usr/lib/systemd/system/openstream-host-broker.service \
            usr/lib/systemd/system/openstream-machine-service.service; do
            if printf '%s' "$contents" | grep -q "$wanted"; then
                pass "headless package ships $wanted"
            else
                fail "headless package is missing $wanted"
            fi
        done

        for unwanted in openstream-desktop openstream-signal-server \
            openstream-host-agent openstream-ffmpeg-host openstream-linux-host \
            openstream.desktop; do
            if printf '%s' "$contents" | grep -q "$unwanted"; then
                fail "headless package carries $unwanted, which a server never runs"
            else
                pass "headless package does not carry $unwanted"
            fi
        done

        if printf '%s' "$control" | grep -qi '^Depends:.*ffmpeg'; then
            fail "the headless package declares a dependency on ffmpeg; the
accepted media path does not use it, so this pulls a large dependency onto
every server for a fallback 1.0 does not exercise"
        else
            pass "the headless package does not depend on ffmpeg"
        fi

        if printf '%s' "$control" | grep -q '^Package: openstream-headless-host'; then
            pass "the headless package has its own name"
        else
            fail "the headless package is not named openstream-headless-host"
        fi

        # What the programs link against, not just what the maintainer scripts
        # call. Declaring only adduser was true of postinst and false of the
        # binaries, so a machine missing the C runtime installed the package
        # happily and then could not run it.
        if printf '%s' "$control" | grep -qE '^Depends:.*libc'; then
            pass "the headless package declares the libraries its binaries need"
        else
            fail "the headless package declares no C library dependency:
$(printf '%s' "$control" | grep '^Depends:')
dpkg-shlibdeps needs a debian/control in its working directory and the
binaries at the paths it is given, and produces nothing, quietly, without
both."
        fi

        # Both profiles install the same three binaries and the same two units
        # into the same paths. Without a declared relationship that is a dpkg
        # file-overwrite error at install time rather than a clear refusal.
        if printf '%s' "$control" | grep -q '^Conflicts: openstream$' &&
            printf '%s' "$control" | grep -q '^Replaces: openstream$'; then
            pass "the headless package says it cannot be co-installed with the desktop one"
        else
            fail "the headless and desktop packages own the same paths and declare
no relationship, so installing one over the other fails on overlapping files"
        fi

        host_arch="$(dpkg --print-architecture)"
        if printf '%s' "$control" | grep -q "^Architecture: $host_arch"; then
            pass "the package is labelled $host_arch, the architecture it was built for"
        else
            fail "the package is not labelled $host_arch: $(printf '%s' "$control" |
                grep '^Architecture:')
An arm64 package labelled amd64 installs nowhere and blames the machine."
        fi
    else
        fail "the headless profile did not build: $(cat "$pkg_scratch/err")"
    fi

    # The desktop profile's own dependency metadata, which the headless
    # package cannot speak for: the shell is installed separately and was left
    # out of the analysis entirely, so a desktop package could omit its GTK and
    # WebKit runtime while looking automatically generated.
    #
    # Built from stand-ins. The desktop profile wants seven engine binaries and
    # this machine may only have the three headless ones, so the rest are
    # copies of a real one; what matters is that they are real ELF objects. The
    # shell stand-in is a system binary chosen because it links something the
    # Rust binaries do not, so the assertion cannot pass on a dependency the
    # engine contributed.
    if [ -n "$real_bin_dir" ] && [ -x /bin/ls ]; then
        desk="$(mktemp -d "${TMPDIR:-/tmp}/openstream-desktop-deps.XXXXXX")"
        mkdir -p "$desk/bin" "$desk/shell" "$desk/probe/debian"
        for b in openstream-host-broker openstream-machine-service openstream-enrol; do
            cp "$real_bin_dir/$b" "$desk/bin/$b"
        done
        for b in openstream-host-agent openstream-ffmpeg-host openstream-linux-host \
            openstream-signal-server; do
            cp "$real_bin_dir/openstream-enrol" "$desk/bin/$b"
        done
        cp /bin/ls "$desk/shell/openstream-desktop"

        # What the shell needs that the engine does not. If this comes out
        # empty the test cannot distinguish anything and says so.
        printf 'Source: t\n\nPackage: t\nArchitecture: %s\n' "$(dpkg --print-architecture)" \
            >"$desk/probe/debian/control"
        cp /bin/ls "$desk/probe/shell-probe"
        cp "$real_bin_dir/openstream-enrol" "$desk/probe/engine-probe"
        shell_deps="$(cd "$desk/probe" && dpkg-shlibdeps -O --ignore-missing-info \
            ./shell-probe 2>/dev/null | sed -n 's/^shlibs:Depends=//p' |
            tr ',' '\n' | awk '{print $1}' | sort -u)"
        engine_deps="$(cd "$desk/probe" && dpkg-shlibdeps -O --ignore-missing-info \
            ./engine-probe 2>/dev/null | sed -n 's/^shlibs:Depends=//p' |
            tr ',' '\n' | awk '{print $1}' | sort -u)"
        only_shell="$(comm -23 <(printf '%s\n' "$shell_deps") <(printf '%s\n' "$engine_deps"))"

        if [ -z "$only_shell" ]; then
            printf 'ok: (skipped) the shell stand-in shares every library with the engine\n'
        elif OPENSTREAM_ARTIFACT_DIR="$desk/bin" OPENSTREAM_SHELL_DIR="$desk/shell" \
            bash "$build_deb" --profile desktop "$desk/desktop.deb" \
            >/dev/null 2>"$desk/err"; then
            desktop_depends="$(dpkg-deb -f "$desk/desktop.deb" Depends)"
            missing=""
            for dep in $only_shell; do
                printf '%s' "$desktop_depends" | grep -q -- "$dep" || missing="$missing $dep"
            done
            if [ -z "$missing" ]; then
                pass "the desktop package analyses its shell binary too"
            else
                fail "the desktop package omits what only its shell links against:$missing
The shell is installed separately from the engine binaries, so leaving it out
of dpkg-shlibdeps ships a package without its GUI runtime while the metadata
still looks generated."
            fi
        else
            fail "the desktop profile did not build: $(cat "$desk/err")"
        fi
        rm -rf -- "$desk"
    fi
fi

if [ "$failures" -gt 0 ]; then
    printf '\n%d packaging check(s) failed\n' "$failures" >&2
    exit 1
fi
printf '\nLinux packaging configuration is coherent\n'
