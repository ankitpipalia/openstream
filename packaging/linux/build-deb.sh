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
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    cat <<'NOTICE'
OpenStream: machine-level hosting is installed but not enabled.

To turn it on, enrol this machine and then start the pair:

  OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key \
    openstream-enrol --origin https://your-control-plane \
                     --device-id "$(cat /etc/machine-id)" \
                     --public-key "$YOUR_KEY_HEX" < access-token.txt

Then set OPENSTREAM_BROKER_DEVICE_ID, OPENSTREAM_BROKER_CEILING and
OPENSTREAM_BROKER_SOCKET_GID in openstream-host-broker.service, and
OPENSTREAM_SIGNAL_ORIGIN in openstream-machine-service.service, before:

  systemctl enable --now openstream-machine-service

Until then the broker refuses every session, which is the intended posture.
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
