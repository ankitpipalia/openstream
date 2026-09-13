#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned Apple-Silicon disk image for the headless session client
# (openstream-desktop-client), NOT the Tauri product shell. The product shell
# is bundled by `npm run tauri build` in desktop/, which produces its own
# OpenStream.app under com.openstream.desktop. This bundle therefore carries
# its own name and identifier so the two can never be confused on disk or in
# Launch Services.
# codesign/notarization are deliberately separate protected release steps;
# see packaging/macos/notarize.sh, which signs with entitlements.plist.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0-dev}"
output="${1:-$repo_dir/dist/OpenStream-SessionClient-${version}-macOS-arm64.dmg}"
artifact_dir="${OPENSTREAM_ARTIFACT_DIR:-$repo_dir/engine/lowlat/target/aarch64-apple-darwin/release}"

[[ "$(uname -s)" == Darwin ]] || {
    echo "Apple-Silicon packaging must run on macOS" >&2
    exit 2
}
[[ "$(uname -m)" == arm64 ]] || {
    echo "Apple-Silicon packaging must run on an arm64 runner" >&2
    exit 2
}
command -v hdiutil >/dev/null 2>&1 || {
    echo "hdiutil is required to build the macOS disk image" >&2
    exit 2
}

binary="$artifact_dir/openstream-desktop-client"
[[ -x "$binary" ]] || {
    echo "missing release binary: $binary" >&2
    exit 1
}

stage="$(mktemp -d "${TMPDIR:-/tmp}/openstream-dmg.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
app="$stage/OpenStream Session Client.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 "$binary" "$app/Contents/MacOS/OpenStreamSessionClient"
cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>OpenStream Session Client</string>
<key>CFBundleExecutable</key><string>OpenStreamSessionClient</string>
<key>CFBundleIdentifier</key><string>com.openstream.session-client</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
</dict></plist>
EOF
mkdir -p "$(dirname -- "$output")"
hdiutil create -quiet -volname "OpenStream Session Client $version" -srcfolder "$stage" -format UDZO "$output"
printf 'built unsigned macOS session-client disk image: %s\n' "$output"
printf 'this is NOT the product shell; build that with: cd desktop && npm run tauri build\n'
