#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned local Debian package from an already-built release tree.
# Signing and repository publication remain protected release-environment work.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0}"
output="${1:-$repo_dir/dist/OpenStream-${version}-amd64.deb}"
artifact_dir="${OPENSTREAM_ARTIFACT_DIR:-$repo_dir/engine/lowlat/target/release}"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the Linux package" >&2
    exit 2
}

for binary in openstream-host-agent openstream-linux-host openstream-signal-server; do
    [[ -x "$artifact_dir/$binary" ]] || {
        echo "missing release binary: $artifact_dir/$binary" >&2
        exit 1
    }
done

stage="$(mktemp -d "${TMPDIR:-/tmp}/openstream-deb.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/systemd/user" \
    "$stage/usr/share/applications"

cat >"$stage/DEBIAN/control" <<EOF
Package: openstream
Version: $version
Section: net
Priority: optional
Architecture: amd64
Maintainer: OpenStream contributors
Description: Self-hosted low-latency desktop streaming
EOF

for binary in openstream-host-agent openstream-linux-host openstream-signal-server; do
    install -m 0755 "$artifact_dir/$binary" "$stage/usr/bin/$binary"
done
install -m 0644 "$repo_dir/packaging/linux/openstream-host-agent.service" \
    "$stage/usr/lib/systemd/user/openstream-host-agent.service"
install -m 0644 "$repo_dir/packaging/linux/openstream.desktop" \
    "$stage/usr/share/applications/openstream.desktop"
mkdir -p "$(dirname -- "$output")"
dpkg-deb --build --root-owner-group "$stage" "$output" >/dev/null
printf 'built unsigned Debian package: %s\n' "$output"
