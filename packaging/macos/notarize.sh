#!/usr/bin/env bash
set -euo pipefail

# Sign, notarize, and staple a disk image whose app bundle is ALREADY signed.
#
# This script previously required OPENSTREAM_MACOS_SIGNING_IDENTITY but read
# OPENSTREAM_SIGNING_IDENTITY, so the identity it demanded was never the one
# it used; and it ran `codesign --entitlements` against the disk image, which
# does not give the executable inside the .app either the hardened runtime or
# those entitlements. Apple checks the code being distributed, so the .app has
# to be signed first -- packaging/macos/build-arm64-dmg.sh does that when
# OPENSTREAM_SIGNING_IDENTITY is set. This script verifies that happened,
# refuses to submit if it did not, and then signs the container.

artifact="${1:-}"
[[ -n "$artifact" && -f "$artifact" ]] || {
    echo "usage: $0 PATH_TO_DMG" >&2
    echo "the .dmg must contain an app already signed by build-arm64-dmg.sh" >&2
    exit 2
}
for variable in OPENSTREAM_SIGNING_IDENTITY APPLE_ID APPLE_TEAM_ID APPLE_APP_PASSWORD; do
    [[ -n "${!variable:-}" ]] || {
        echo "$variable must be provided by the protected signing environment" >&2
        exit 2
    }
done
command -v codesign >/dev/null 2>&1 || { echo "codesign is required" >&2; exit 2; }
command -v hdiutil >/dev/null 2>&1 || { echo "hdiutil is required" >&2; exit 2; }
command -v xcrun >/dev/null 2>&1 || { echo "xcrun is required" >&2; exit 2; }

# Refuse to submit an image whose payload is unsigned or un-hardened. Apple
# would reject it, but only after a round trip -- and a rejection that arrives
# minutes later is easy to misread as a transient notary problem.
mount_point="$(mktemp -d "${TMPDIR:-/tmp}/openstream-notarize.XXXXXX")"
cleanup() {
    hdiutil detach "$mount_point" -quiet >/dev/null 2>&1 || true
    rm -rf -- "$mount_point"
}
trap cleanup EXIT
hdiutil attach "$artifact" -nobrowse -readonly -mountpoint "$mount_point" -quiet

shopt -s nullglob
apps=("$mount_point"/*.app)
shopt -u nullglob
[[ ${#apps[@]} -gt 0 ]] || {
    echo "no .app bundle found inside $artifact" >&2
    exit 2
}
for app in "${apps[@]}"; do
    codesign --verify --strict --verbose=2 "$app" || {
        echo "the app inside $artifact is not validly signed: $app" >&2
        echo "run build-arm64-dmg.sh with OPENSTREAM_SIGNING_IDENTITY set" >&2
        exit 2
    }
    # Notarization requires the hardened runtime on every executable that is
    # distributed; codesign reports it in the CodeDirectory flags.
    codesign --display --verbose=2 "$app" 2>&1 | grep -q 'flags=.*runtime' || {
        echo "the app inside $artifact is signed without the hardened runtime: $app" >&2
        exit 2
    }
    printf 'verified signed, hardened app: %s\n' "$app"
done
cleanup
trap - EXIT

# Sign the container itself. A disk image is not code and takes no
# entitlements; those belong to the executables already signed inside it.
codesign --force --timestamp --sign "$OPENSTREAM_SIGNING_IDENTITY" "$artifact"
codesign --verify --strict --verbose=2 "$artifact"

xcrun notarytool submit "$artifact" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
xcrun stapler staple "$artifact"
xcrun stapler validate "$artifact"
# Gatekeeper's own verdict is the one that matters to a user opening the
# image; codesign only proves the signature is well formed.
if command -v spctl >/dev/null 2>&1; then
    spctl --assess --type open --context context:primary-signature --verbose=2 "$artifact"
fi
printf 'notarized and stapled: %s\n' "$artifact"
