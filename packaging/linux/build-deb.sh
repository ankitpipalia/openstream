#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned local Debian package from an already-built release tree.
# Signing and repository publication remain protected release-environment work.
#
# Two profiles, because two different machines are being served.
#
#   desktop   the workstation package: the product shell and the per-user host,
#             plus the machine-level subsystem for an operator who wants it.
#   headless  a server or an unattended host: the privileged broker, the
#             network-facing machine service, and the enrolment tool. Nothing
#             else. No shell, no signal server, no FFmpeg host, and no
#             `Depends: ffmpeg` -- a headless host has no graphical session to
#             run a shell in, and the accepted media path does not use FFmpeg,
#             so declaring it would pull a large dependency onto every server
#             for a fallback that 1.0 does not exercise.
#
# The profile is an argument rather than an environment switch, because which
# files land in a package is not a detail to be discovered by reading the
# script that built it.

usage() {
    cat <<'USAGE'
usage: build-deb.sh [--profile desktop|headless] [--arch DEB_ARCH] [OUTPUT]

  --profile  desktop (default) or headless
  --arch     Debian architecture; defaults to `dpkg --print-architecture`
  OUTPUT     path of the .deb to write; defaults to a name under dist/
USAGE
}

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0}"
profile=desktop
arch=""
output=""

while (($# > 0)); do
    case "$1" in
        --profile)
            profile="${2:-}"
            shift 2 || { usage >&2; exit 2; }
            ;;
        --arch)
            arch="${2:-}"
            shift 2 || { usage >&2; exit 2; }
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
        *)
            output="$1"
            shift
            ;;
    esac
done

case "$profile" in
    desktop|headless) ;;
    *)
        printf 'unknown profile: %s\n' "$profile" >&2
        usage >&2
        exit 2
        ;;
esac

# Never guess the architecture. An arm64 package labelled amd64 installs
# nowhere useful and fails in a way that blames the machine rather than the
# build, so the label comes from dpkg on the machine doing the building unless
# an explicit one is supplied.
if [[ -z "$arch" ]]; then
    command -v dpkg >/dev/null 2>&1 || {
        echo "dpkg is required to determine the architecture; pass --arch" >&2
        exit 2
    }
    arch="$(dpkg --print-architecture)"
fi
[[ "$arch" =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
    printf 'not a Debian architecture: %s\n' "$arch" >&2
    exit 2
}

artifact_dir="${OPENSTREAM_ARTIFACT_DIR:-$repo_dir/engine/lowlat/target/release}"
# openstream.desktop launches the Tauri product shell, which is built from
# desktop/src-tauri and so lands in its own target directory. Packaging the
# desktop entry without this binary produced a menu item that did nothing.
shell_dir="${OPENSTREAM_SHELL_DIR:-$repo_dir/desktop/src-tauri/target/release}"

# The two profiles install the same three binaries and the same two system
# units into the same paths, so they cannot be co-installed. Saying so is what
# turns a confusing dpkg file-overwrite error into "installing this removes
# that", which is the truth: the desktop package is a superset.
if [[ "$profile" == headless ]]; then
    package_name="openstream-headless-host"
    package_depends="adduser"
    package_breaks="openstream"
else
    package_name="openstream"
    package_depends="ffmpeg, adduser"
    package_breaks="openstream-headless-host"
fi
output="${output:-$repo_dir/dist/${package_name}_${version}_${arch}.deb}"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the Linux package" >&2
    exit 2
}

# The per-user host agent and the machine-level pre-login subsystem. The three
# pre-login binaries were built and tested for months without ever being in a
# package, which is what kept machine-level hosting an experiment rather than
# something an installer could turn on.
if [[ "$profile" == headless ]]; then
    # Exactly the three programs machine-level hosting needs, and nothing a
    # server would never run.
    binaries=(
        openstream-host-broker
        openstream-machine-service
        openstream-enrol
    )
else
    binaries=(
        openstream-host-agent
        openstream-ffmpeg-host
        openstream-linux-host
        openstream-signal-server
        openstream-host-broker
        openstream-machine-service
        openstream-enrol
    )
fi
for binary in "${binaries[@]}"; do
    [[ -x "$artifact_dir/$binary" ]] || {
        echo "missing release binary: $artifact_dir/$binary" >&2
        exit 1
    }
done
if [[ "$profile" != headless ]]; then
    [[ -x "$shell_dir/openstream-desktop" ]] || {
        echo "missing product shell binary: $shell_dir/openstream-desktop" >&2
        echo "build it with: cd desktop && npm run tauri build" >&2
        echo "or set OPENSTREAM_SHELL_DIR to the directory that holds it" >&2
        exit 1
    }
fi

stage="$(mktemp -d "${TMPDIR:-/tmp}/openstream-deb.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/systemd/system" \
    "$stage/etc/openstream"
# Only the desktop profile has a shell to launch or a menu entry to launch it
# from; a headless package that created these would own two empty directories
# on every server.
if [[ "$profile" != headless ]]; then
    mkdir -p "$stage/usr/lib/systemd/user" "$stage/usr/share/applications"
fi

# What the programs actually link against, asked of the programs.
#
# Declaring only `adduser` was true of the maintainer scripts and false of the
# binaries: they need the C library and libgcc_s at least, and a machine
# missing those installed the package happily and then could not run it.
#
# Required, not best effort. A warning that still produces a package recreates
# exactly the condition this exists to prevent, and the package looks as though
# its metadata were generated when it was not.
command -v dpkg-shlibdeps >/dev/null 2>&1 || {
    echo "dpkg-shlibdeps is required to compute library dependencies" >&2
    echo "install dpkg-dev, or the package would claim dependencies it has not measured" >&2
    exit 2
}

# The desktop shell is analysed too. It is installed separately from the engine
# binaries and was left out of this, so the desktop package could omit its GTK
# and WebKit runtime while appearing to have generated metadata -- and the
# headless CI job cannot see that, because it never builds the desktop profile.
shlib_sources=()
for binary in "${binaries[@]}"; do
    shlib_sources+=("$artifact_dir/$binary")
done
if [[ "$profile" != headless ]]; then
    shlib_sources+=("$shell_dir/openstream-desktop")
fi

# It insists on a debian/control in the working directory even with -O, and
# fails with "cannot read debian/control" otherwise -- which is how this
# silently produced nothing on the first attempt. A two-stanza skeleton is
# enough, and it is removed again before the package is built so it cannot end
# up inside it. The binaries are analysed where they were built: they are not
# in the stage directory yet, which is how it silently produced nothing on the
# second attempt.
mkdir -p "$stage/debian"
cat >"$stage/debian/control" <<EOF
Source: $package_name

Package: $package_name
Architecture: $arch
EOF
shlib_stderr="$stage/debian/shlibdeps.err"
if ! shlib_output="$(
    cd "$stage" && dpkg-shlibdeps -O "${shlib_sources[@]}" 2>"$shlib_stderr"
)"; then
    echo "dpkg-shlibdeps failed:" >&2
    sed 's/^/  /' "$shlib_stderr" >&2
    rm -rf -- "$stage/debian"
    exit 1
fi

# Exiting zero is not the same as having resolved everything.
#
# `--ignore-missing-info` used to be passed here, and dropping it is not enough
# on its own: a library that cannot be located at all -- an unresolvable RPATH,
# say -- is reported as a *warning*, and dpkg-shlibdeps still exits zero having
# emitted dependencies for everything it could map. The non-empty check then
# passes and the package ships claiming generated metadata while silently
# missing a library it needs.
#
# So the warnings are read. Two are routine on a merged-/usr Debian and mean
# nothing about resolution; anything else is treated as unresolved.
if [[ -s "$shlib_stderr" ]]; then
    unexpected="$(
        grep -E '^dpkg-shlibdeps: (warning|error):' "$shlib_stderr" |
            grep -v "binaries to analyze should already be installed in their package's directory" |
            grep -v 'diversions involved - output may be incorrect' ||
            true
    )"
    if [[ -n "$unexpected" ]]; then
        echo "dpkg-shlibdeps could not resolve every library:" >&2
        printf '%s\n' "$unexpected" | sed 's/^/  /' >&2
        echo "the package would declare only the libraries it managed to map," >&2
        echo "which is metadata that looks generated and is incomplete" >&2
        rm -rf -- "$stage/debian"
        exit 1
    fi
fi

shlib_depends="$(printf '%s\n' "$shlib_output" | sed -n 's/^shlibs:Depends=//p')"
rm -rf -- "$stage/debian"

if [[ -z "$shlib_depends" ]]; then
    # Legitimate for a fully static build and for nothing else, so it has to be
    # said out loud rather than assumed.
    if [[ "${OPENSTREAM_ALLOW_NO_SHLIB_DEPS:-}" == 1 ]]; then
        printf 'note: no library dependencies; OPENSTREAM_ALLOW_NO_SHLIB_DEPS=1 was set\n' >&2
    else
        echo "dpkg-shlibdeps found no library dependencies for:" >&2
        printf '  %s\n' "${shlib_sources[@]}" >&2
        echo "that is correct only for a fully static build; set" >&2
        echo "OPENSTREAM_ALLOW_NO_SHLIB_DEPS=1 if that is genuinely the case" >&2
        exit 1
    fi
else
    package_depends="$package_depends, $shlib_depends"
fi

cat >"$stage/DEBIAN/control" <<EOF
Package: $package_name
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: OpenStream contributors
Depends: $package_depends
Conflicts: $package_breaks
Replaces: $package_breaks
Description: Self-hosted low-latency desktop streaming ($profile)
EOF

# The machine service runs as its own unprivileged user so the broker's
# SO_PEERCRED check has something specific to admit, and so the network-facing
# half owns nothing.
#
# Neither unit is enabled here. Machine-level hosting needs the machine enrolled
# first -- without a grant key the broker refuses every session by design, and
# enabling the pair on install would leave a privileged service running and a
# network-facing one restart-looping, for a feature the operator never asked
# for. `openstream-enrol` prints what to do next.
cat >"$stage/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    if ! getent group openstream >/dev/null; then
        addgroup --system openstream
    fi
    if ! getent passwd openstream >/dev/null; then
        adduser --system --ingroup openstream --no-create-home \
            --home /nonexistent --shell /usr/sbin/nologin openstream
    fi
    chmod 0700 /etc/openstream 2>/dev/null || true

    # The two numbers only the install knows.
    #
    # The broker admits exactly one peer uid over SO_PEERCRED and hands the
    # socket to exactly one gid. Those are the `openstream` account just
    # created, and its ids are assigned here, now -- they cannot be written into
    # a unit file that ships in a package. Left unset, the broker falls back to
    # admitting uid 0, and the unprivileged service it is packaged with is
    # refused on every connection.
    service_uid="$(getent passwd openstream | cut -d: -f3)"
    service_gid="$(getent group openstream | cut -d: -f3)"

    # Written once. An upgrade must not overwrite what an operator configured --
    # losing OPENSTREAM_BROKER_CEILING on a package update would silently take
    # away every capability the machine was granting.
    if [ ! -e /etc/openstream/broker.env ]; then
        cat >/etc/openstream/broker.env <<BROKER_ENV
# Configuration for openstream-host-broker. Written by the package on first
# install and never overwritten; edit it freely.
#
# Do not assign an empty value to any of these. The broker reads an empty
# string as a value, not as "unset": an empty uid or gid fails to parse and it
# exits, and an empty grant-key path is a file it cannot open. Comment a line
# out instead.

# The account openstream-machine-service runs as. The broker serves this peer
# and no other.
OPENSTREAM_BROKER_SERVICE_UID=$service_uid

# The group the socket is handed to, so that account can open it without being
# root. SO_PEERCRED still decides who is actually served; this only makes the
# socket reachable.
OPENSTREAM_BROKER_SOCKET_GID=$service_gid

# What this machine's operator permits, as a comma-separated list of
# capture, keyboard, mouse, gamepad, clipboard. Commented out means nothing is
# granted: a broker that has not been told what is allowed has not been told it
# may hand out the keyboard.
#OPENSTREAM_BROKER_CEILING=capture,keyboard,mouse

# Written by \`openstream-enrol\`. Until both are set the broker starts and
# refuses every session, which is the intended posture for an unenrolled
# machine. The device id must match the one enrolment printed -- a grant
# addressed to another device is refused, so an approval for one host in a
# fleet is not an approval for all of them.
#OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key
#OPENSTREAM_BROKER_DEVICE_ID=
BROKER_ENV
        chmod 0600 /etc/openstream/broker.env
    fi

    if [ ! -e /etc/openstream/machine-service.env ]; then
        cat >/etc/openstream/machine-service.env <<'SERVICE_ENV'
# Configuration for openstream-machine-service. Written by the package on first
# install and never overwritten; edit it freely.
#
# As with broker.env, an empty value is not "unset". An empty origin replaces
# the program's own default with an unusable one, and an empty pairing path
# turns "no pairing configured" into "pairing configured, at a path that cannot
# be opened". Comment a line out instead.

# The control plane this machine talks to. Must be https:// unless it is a
# loopback address: this connection carries credentials.
#OPENSTREAM_SIGNAL_ORIGIN=https://your-control-plane

# The pairing this service relays to the broker. It cannot produce one or
# verify one, which is what makes the broker's check worth anything.
#OPENSTREAM_PAIRING_FILE=/run/openstream/pairing.json
SERVICE_ENV
        chmod 0600 /etc/openstream/machine-service.env
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    cat <<NOTICE
OpenStream: machine-level hosting is installed but not enabled.

The account it runs as has been created and the broker has been told its ids:
  uid $service_uid, gid $service_gid, in /etc/openstream/broker.env

To turn it on, enrol this machine -- which writes the grant key and records the
device id for the broker:

  OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key \\
  OPENSTREAM_BROKER_ENV_FILE=/etc/openstream/broker.env \\
    openstream-enrol --origin https://your-control-plane \\
                     --device-id "\$(cat /etc/machine-id)" \\
                     --public-key "\$YOUR_KEY_HEX" < access-token.txt

Then set, in /etc/openstream/broker.env:
  OPENSTREAM_BROKER_CEILING   what this machine may ever grant
and in /etc/openstream/machine-service.env:
  OPENSTREAM_SIGNAL_ORIGIN    the control plane
  OPENSTREAM_PAIRING_FILE     where the session pairing is written

Edit those files, not the unit files: a package upgrade replaces the units.

  systemctl enable --now openstream-machine-service

Until a grant key is configured the broker refuses every session, which is the
intended posture.
NOTICE
fi

exit 0
POSTINST
chmod 0755 "$stage/DEBIAN/postinst"

cat >"$stage/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop openstream-machine-service >/dev/null 2>&1 || true
    systemctl stop openstream-host-broker >/dev/null 2>&1 || true
    systemctl disable openstream-machine-service >/dev/null 2>&1 || true
    systemctl disable openstream-host-broker >/dev/null 2>&1 || true
fi

exit 0
PRERM
chmod 0755 "$stage/DEBIAN/prerm"

# Purge means purge. `remove` deliberately keeps the operator's configuration
# and the machine's identity, so that reinstalling does not force a
# re-enrolment; `purge` is the explicit request to leave nothing behind, and
# what it leaves behind matters here because /var/lib/openstream holds the
# device's private identity key. A purge that left a key on disk would be a
# key nobody is managing any more.
#
# The system account is kept. Removing it could orphan files elsewhere on the
# machine that this package cannot see, and an unused account with nologin and
# no home is not a hazard.
cat >"$stage/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
    rm -f /etc/openstream/broker.env /etc/openstream/machine-service.env
    rm -f /etc/openstream/grant.key
    rm -rf /var/lib/openstream
    # Only if this package was the only thing in it.
    rmdir /etc/openstream 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi

exit 0
POSTRM
chmod 0755 "$stage/DEBIAN/postrm"

for binary in "${binaries[@]}"; do
    install -m 0755 "$artifact_dir/$binary" "$stage/usr/bin/$binary"
done
if [[ "$profile" != headless ]]; then
    install -m 0755 "$shell_dir/openstream-desktop" "$stage/usr/bin/openstream-desktop"
    install -m 0644 "$repo_dir/packaging/linux/openstream-host-agent.service" \
        "$stage/usr/lib/systemd/user/openstream-host-agent.service"
    install -m 0644 "$repo_dir/packaging/linux/openstream.desktop" \
        "$stage/usr/share/applications/openstream.desktop"
fi

# System units for the pre-login subsystem. Shipped but NOT enabled: see
# DEBIAN/postinst for why.
for unit in openstream-host-broker openstream-machine-service; do
    install -m 0644 "$repo_dir/packaging/linux/$unit.service" \
        "$stage/usr/lib/systemd/system/$unit.service"
done

# Where openstream-enrol writes the grant key. 0700 because the broker refuses a
# key under a directory anyone else can write, and a package that created this
# world-readable would make every install fail that check.
chmod 0700 "$stage/etc/openstream"
mkdir -p "$(dirname -- "$output")"
dpkg-deb --build --root-owner-group "$stage" "$output" >/dev/null
printf 'built unsigned Debian package: %s\n' "$output"
