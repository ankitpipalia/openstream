#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned local Debian package from an already-built release tree.
# Signing and repository publication remain protected release-environment work.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0}"
output="${1:-$repo_dir/dist/OpenStream-${version}-amd64.deb}"
artifact_dir="${OPENSTREAM_ARTIFACT_DIR:-$repo_dir/engine/lowlat/target/release}"
# openstream.desktop launches the Tauri product shell, which is built from
# desktop/src-tauri and so lands in its own target directory. Packaging the
# desktop entry without this binary produced a menu item that did nothing.
shell_dir="${OPENSTREAM_SHELL_DIR:-$repo_dir/desktop/src-tauri/target/release}"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the Linux package" >&2
    exit 2
}

# The per-user host agent and the machine-level pre-login subsystem. The three
# pre-login binaries were built and tested for months without ever being in a
# package, which is what kept machine-level hosting an experiment rather than
# something an installer could turn on.
binaries=(
    openstream-host-agent
    openstream-ffmpeg-host
    openstream-linux-host
    openstream-signal-server
    openstream-host-broker
    openstream-machine-service
    openstream-enrol
)
for binary in "${binaries[@]}"; do
    [[ -x "$artifact_dir/$binary" ]] || {
        echo "missing release binary: $artifact_dir/$binary" >&2
        exit 1
    }
done
[[ -x "$shell_dir/openstream-desktop" ]] || {
    echo "missing product shell binary: $shell_dir/openstream-desktop" >&2
    echo "build it with: cd desktop && npm run tauri build" >&2
    echo "or set OPENSTREAM_SHELL_DIR to the directory that holds it" >&2
    exit 1
}

stage="$(mktemp -d "${TMPDIR:-/tmp}/openstream-deb.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/systemd/user" \
    "$stage/usr/lib/systemd/system" "$stage/usr/share/applications" \
    "$stage/etc/openstream"

cat >"$stage/DEBIAN/control" <<EOF
Package: openstream
Version: $version
Section: net
Priority: optional
Architecture: amd64
Maintainer: OpenStream contributors
Depends: ffmpeg
Description: Self-hosted low-latency desktop streaming
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

for binary in "${binaries[@]}"; do
    install -m 0755 "$artifact_dir/$binary" "$stage/usr/bin/$binary"
done
install -m 0755 "$shell_dir/openstream-desktop" "$stage/usr/bin/openstream-desktop"
install -m 0644 "$repo_dir/packaging/linux/openstream-host-agent.service" \
    "$stage/usr/lib/systemd/user/openstream-host-agent.service"
install -m 0644 "$repo_dir/packaging/linux/openstream.desktop" \
    "$stage/usr/share/applications/openstream.desktop"

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
