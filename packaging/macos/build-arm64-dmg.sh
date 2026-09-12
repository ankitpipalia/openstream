#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned Apple-Silicon disk image from an existing desktop binary.
# codesign/notarization are deliberately separate protected release steps.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0}"
output="${1:-$repo_dir/dist/OpenStream-${version}-macOS-arm64.dmg}"
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
app="$stage/OpenStream.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 "$binary" "$app/Contents/MacOS/OpenStream"
cp "$repo_dir/packaging/macos/entitlements.plist" "$app/Contents/Resources/entitlements.plist"
cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>OpenStream</string>
<key>CFBundleExecutable</key><string>OpenStream</string>
<key>CFBundleIdentifier</key><string>com.openstream.desktop</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
</dict></plist>
EOF
mkdir -p "$(dirname -- "$output")"
hdiutil create -quiet -volname "OpenStream $version" -srcfolder "$stage" -format UDZO "$output"
printf 'built unsigned macOS disk image: %s\n' "$output"
