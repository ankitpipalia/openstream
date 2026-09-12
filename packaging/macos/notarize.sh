#!/usr/bin/env bash
set -euo pipefail

artifact="${1:-}"
[[ -n "$artifact" && -f "$artifact" ]] || {
    echo "usage: $0 PATH_TO_SIGNED_DMG" >&2
    exit 2
}
for variable in OPENSTREAM_MACOS_SIGNING_IDENTITY APPLE_ID APPLE_TEAM_ID APPLE_APP_PASSWORD; do
    [[ -n "${!variable:-}" ]] || {
        echo "$variable must be provided by the protected signing environment" >&2
        exit 2
    }
done
command -v codesign >/dev/null 2>&1 || { echo "codesign is required" >&2; exit 2; }
command -v xcrun >/dev/null 2>&1 || { echo "xcrun is required" >&2; exit 2; }

echo "Signing and notarizing $artifact"
echo "The caller must sign the app bundle before invoking this script."
codesign --verify --deep --strict --verbose=2 "$artifact"
xcrun notarytool submit "$artifact" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
xcrun stapler staple "$artifact"
codesign --verify --deep --strict --verbose=2 "$artifact"
