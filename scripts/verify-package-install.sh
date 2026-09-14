#!/usr/bin/env bash
set -euo pipefail

# Verify package structure and executable metadata without mutating the host.
# A successful run is package-integrity evidence only; it is not install,
# launch, upgrade, rollback, signing, or notarization evidence.

package="${1:-}"
[[ -n "$package" && -f "$package" ]] || {
    echo "usage: $0 PATH_TO_PACKAGE" >&2
    exit 2
}

case "$package" in
    *.deb)
        command -v dpkg-deb >/dev/null 2>&1 || {
            echo "dpkg-deb is required to inspect Debian packages" >&2
            exit 2
        }
        package_info="$(dpkg-deb --info "$package")"
        grep -Eq '^ Package: openstream$' <<<"$package_info" || {
            echo "Debian package name is not openstream" >&2
            exit 1
        }
        grep -Eq '^ Architecture: (amd64|arm64)$' <<<"$package_info" || {
            echo "Debian package architecture is outside the supported release set" >&2
            exit 1
        }
        dpkg-deb --contents "$package" | grep -q '/usr/bin/openstream-desktop$' || {
            echo "Debian package is missing the product shell" >&2
            exit 1
        }
        dpkg-deb --contents "$package" | grep -q '/usr/bin/openstream-host-agent$' || {
            echo "Debian package is missing the host agent" >&2
            exit 1
        }
        printf 'package structure verified: Debian package %s\n' "$package"
        ;;
    *.dmg)
        [[ "$(uname -s)" == Darwin ]] || {
            echo "DMG inspection requires macOS" >&2
            exit 2
        }
        command -v hdiutil >/dev/null 2>&1 || {
            echo "hdiutil is required to inspect DMG packages" >&2
            exit 2
        }
        mount_point="$(mktemp -d "${TMPDIR:-/tmp}/openstream-package.XXXXXX")"
        cleanup() {
            hdiutil detach "$mount_point" -quiet >/dev/null 2>&1 || true
            rmdir "$mount_point" 2>/dev/null || true
        }
        trap cleanup EXIT
        hdiutil attach "$package" -readonly -nobrowse -mountpoint "$mount_point" -quiet
        app="$(find "$mount_point" -maxdepth 1 -name '*.app' -print -quit)"
        [[ -n "$app" ]] || {
            echo "DMG does not contain an application bundle" >&2
            exit 1
        }
        [[ -x "$app/Contents/MacOS/OpenStreamSessionClient" || -x "$app/Contents/MacOS/openstream-desktop" ]] || {
            echo "DMG application bundle has no supported OpenStream executable" >&2
            exit 1
        }
        printf 'package structure verified: macOS disk image %s\n' "$package"
        ;;
    *.tar.gz|*.tgz)
        command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }
        listing="$(tar -tzf "$package")"
        grep -q 'usr/bin/openstream-host-agent$' <<<"$listing" || {
            echo "archive is missing openstream-host-agent" >&2
            exit 1
        }
        grep -q 'usr/bin/openstream-desktop$' <<<"$listing" || {
            echo "archive is missing the product shell" >&2
            exit 1
        }
        printf 'package structure verified: tar archive %s\n' "$package"
        ;;
    *.zip)
        command -v unzip >/dev/null 2>&1 || { echo "unzip is required" >&2; exit 2; }
        unzip -tq "$package" >/dev/null
        unzip -Z1 "$package" | grep -Eq '(^|/)Info\.plist$' || {
            echo "application archive has no Info.plist" >&2
            exit 1
        }
        printf 'package structure verified: application archive %s\n' "$package"
        ;;
    *)
        echo "unsupported package suffix: $package" >&2
        exit 2
        ;;
esac

printf '%s\n' \
    'This command did not install or launch the package.' \
    'Record install/launch/upgrade/rollback and signing evidence separately.'
