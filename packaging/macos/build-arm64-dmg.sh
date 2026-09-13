#!/usr/bin/env bash
set -euo pipefail

# Build an Apple-Silicon disk image for the headless session client
# (openstream-desktop-client), NOT the Tauri product shell. The product shell
# is bundled by `npm run tauri build` in desktop/, which produces its own
# OpenStream.app under com.openstream.desktop. This bundle therefore carries
# its own name and identifier so the two can never be confused on disk or in
# Launch Services.
#
# When OPENSTREAM_SIGNING_IDENTITY names a Developer ID Application identity,
# the .app inside the image is signed here, with the hardened runtime and
# entitlements.plist, before the image is built. That ordering is required:
# notarization checks the executables being distributed, and entitlements
# only take effect when passed to codesign for the code they apply to.
# Signing the finished disk image instead -- which is what this used to leave
# to notarize.sh -- leaves the app inside it unsigned and un-hardened.
# packaging/macos/notarize.sh signs the image itself and submits it.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0-dev}"
output="${1:-$repo_dir/dist/OpenStream-SessionClient-${version}-macOS-arm64.dmg}"
artifact_dir="${OPENSTREAM_ARTIFACT_DIR:-$repo_dir/engine/lowlat/target/aarch64-apple-darwin/release}"

# CFBundleShortVersionString must be three period-separated integers and
# CFBundleVersion must be period-separated integers, so a marketing version
# such as "1.0.0-dev" or "1.1.0+build7" cannot go into either verbatim:
# Apple rejects the bundle. Strip any pre-release or build metadata and pad
# to three components, keeping the full string for human-facing text only.
normalize_version() {
    local raw="${1%%[-+]*}"
    local major minor patch
    IFS='.' read -r major minor patch <<<"$raw"
    major="${major:-1}"
    minor="${minor:-0}"
    patch="${patch:-0}"
    for component in "$major" "$minor" "$patch"; do
        [[ "$component" =~ ^[0-9]+$ ]] || {
            echo "OPENSTREAM_VERSION '$1' has no numeric major.minor.patch prefix" >&2
            exit 2
        }
    done
    printf '%s.%s.%s' "$major" "$minor" "$patch"
}

bundle_version="$(normalize_version "$version")"
# A monotonically increasing build number may be supplied separately; Apple
# requires it to be numeric and period-separated too.
build_version="${OPENSTREAM_BUILD_VERSION:-$bundle_version}"
[[ "$build_version" =~ ^[0-9]+(\.[0-9]+)*$ ]] || {
    echo "OPENSTREAM_BUILD_VERSION must be period-separated integers" >&2
    exit 2
}

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
<key>CFBundleName</key><string>OpenStream Session Client</string>
<key>CFBundleExecutable</key><string>OpenStreamSessionClient</string>
<key>CFBundleIdentifier</key><string>com.openstream.session-client</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$bundle_version</string>
<key>CFBundleVersion</key><string>$build_version</string>
<key>CFBundleGetInfoString</key><string>OpenStream Session Client $version</string>
<key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
EOF

if [[ -n "${OPENSTREAM_SIGNING_IDENTITY:-}" ]]; then
    command -v codesign >/dev/null 2>&1 || { echo "codesign is required to sign" >&2; exit 2; }
    entitlements="$repo_dir/packaging/macos/entitlements.plist"
    [[ -f "$entitlements" ]] || { echo "missing $entitlements" >&2; exit 2; }
    # Sign nested code before the bundle that contains it, innermost first.
    # `--deep` is explicitly not used: Apple documents it as unsuitable for
    # signing a product for distribution, and it cannot apply the right
    # entitlements to nested code anyway.
    while IFS= read -r -d '' nested; do
        codesign --force --options runtime --timestamp \
            --sign "$OPENSTREAM_SIGNING_IDENTITY" "$nested"
    done < <(find "$app/Contents" \
        \( -name '*.dylib' -o -name '*.framework' -o -path '*/Frameworks/*' \) -print0)
    codesign --force --options runtime --timestamp \
        --entitlements "$entitlements" \
        --sign "$OPENSTREAM_SIGNING_IDENTITY" "$app"
    codesign --verify --strict --verbose=2 "$app"
    printf 'signed %s with hardened runtime and entitlements\n' "$app"
else
    echo "OPENSTREAM_SIGNING_IDENTITY is unset; building an UNSIGNED image" >&2
    echo "an unsigned app cannot be notarized -- see packaging/macos/notarize.sh" >&2
fi

mkdir -p "$(dirname -- "$output")"
rm -f -- "$output"
hdiutil create -quiet -volname "OpenStream Session Client $version" -srcfolder "$stage" -format UDZO "$output"
printf 'built macOS session-client disk image: %s\n' "$output"
printf 'this is NOT the product shell; build that with: cd desktop && npm run tauri build\n'
