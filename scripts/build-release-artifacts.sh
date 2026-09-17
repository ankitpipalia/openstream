#!/usr/bin/env bash
set -euo pipefail

# Stage release artifacts from already-built, operator-selected inputs. This
# script never invents a package, signature, hardware result, or WAN result.
# Missing platform inputs are errors, not placeholders. Signing and physical
# acceptance remain separate gates consumed by check-openstream-1-0-release.sh.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="${OPENSTREAM_VERSION:-1.0.0}"
artifact_root="${OPENSTREAM_ARTIFACT_ROOT:-$repo_dir/dist/openstream-1.0.0}"
engine_dir="$repo_dir/engine/lowlat"
shell_dir="${OPENSTREAM_SHELL_DIR:-$repo_dir/desktop/src-tauri/target/release}"
linux_target="${OPENSTREAM_LINUX_TARGET:-x86_64-unknown-linux-gnu}"
force=0

usage() {
    cat <<'EOF'
Usage: scripts/build-release-artifacts.sh [--force]

Environment:
  OPENSTREAM_VERSION           marketing version (default: 1.0.0)
  OPENSTREAM_ARTIFACT_ROOT     empty staging directory to create
  OPENSTREAM_LINUX_TARGET      Rust target (default: x86_64-unknown-linux-gnu)
  OPENSTREAM_SHELL_DIR         Tauri release binary directory
  OPENSTREAM_LINUX_PACKAGE      prebuilt Linux package to stage instead of
                               building the tarball here
  OPENSTREAM_MACOS_PACKAGE     prebuilt macOS package/disk image
  OPENSTREAM_MACOS_APP_ARCHIVE prebuilt macOS app archive

The command stages only real files. It does not sign, notarize, install, or
write PASS rows to the release gate report.
EOF
}

while (($# > 0)); do
    case "$1" in
        --force)
            force=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ "$version" == 1.0.0 ]] || {
    echo "this manifest stages only release version 1.0.0; set OPENSTREAM_VERSION=1.0.0" >&2
    exit 2
}

if [[ -e "$artifact_root" ]]; then
    if ((force == 0)); then
        echo "artifact root already exists: $artifact_root" >&2
        echo "remove it deliberately or pass --force after checking its contents" >&2
        exit 2
    fi
    # `--force` is deliberately constrained to the exact release staging
    # directory, never a repository root or a user data directory.
    [[ "$artifact_root" == "$repo_dir/dist/openstream-1.0.0" ]] || {
        echo "--force is allowed only for the canonical release staging root" >&2
        exit 2
    }
    rm -rf -- "$artifact_root"
fi
mkdir -p "$artifact_root/linux-x86_64" "$artifact_root/macos-aarch64" \
    "$artifact_root/checksums" "$artifact_root/sbom"

copy_required() {
    local source=$1
    local destination=$2
    [[ -f "$source" ]] || {
        echo "missing required release input: $source" >&2
        exit 1
    }
    install -m 0644 "$source" "$destination"
}

linux_package="${OPENSTREAM_LINUX_PACKAGE:-}"
if [[ -n "$linux_package" ]]; then
    copy_required "$linux_package" "$artifact_root/linux-x86_64/OpenStream-Linux-x86_64.tar.gz"
else
    # The per-user agent and the machine-level pre-login subsystem. The tarball
    # and the Debian package must ship the same set, or an operator who
    # installed from one finds a feature the other one has.
    linux_binaries=(
        openstream-host-agent
        openstream-ffmpeg-host
        openstream-linux-host
        openstream-signal-server
        openstream-host-broker
        openstream-machine-service
        openstream-enrol
    )
    for binary in "${linux_binaries[@]}"; do
        [[ -x "$engine_dir/target/$linux_target/release/$binary" ]] || {
            echo "missing Linux release binary: $engine_dir/target/$linux_target/release/$binary" >&2
            echo "build the pinned Linux target or set OPENSTREAM_LINUX_PACKAGE" >&2
            exit 1
        }
    done
    [[ -x "$shell_dir/openstream-desktop" ]] || {
        echo "missing Tauri product shell: $shell_dir/openstream-desktop" >&2
        echo "build it with: cd desktop && npm run tauri build" >&2
        exit 1
    }
    linux_stage="$(mktemp -d "${TMPDIR:-/tmp}/openstream-linux-stage.XXXXXX")"
    trap 'rm -rf -- "$linux_stage"' EXIT
    mkdir -p "$linux_stage/usr/bin" "$linux_stage/usr/lib/systemd/user" \
        "$linux_stage/usr/lib/systemd/system" "$linux_stage/usr/share/applications"
    for binary in "${linux_binaries[@]}"; do
        install -m 0755 "$engine_dir/target/$linux_target/release/$binary" \
            "$linux_stage/usr/bin/$binary"
    done
    install -m 0755 "$shell_dir/openstream-desktop" "$linux_stage/usr/bin/openstream-desktop"
    install -m 0644 "$repo_dir/packaging/linux/openstream-host-agent.service" \
        "$linux_stage/usr/lib/systemd/user/openstream-host-agent.service"
    install -m 0644 "$repo_dir/packaging/linux/openstream.desktop" \
        "$linux_stage/usr/share/applications/openstream.desktop"
    for unit in openstream-host-broker openstream-machine-service; do
        install -m 0644 "$repo_dir/packaging/linux/$unit.service" \
            "$linux_stage/usr/lib/systemd/system/$unit.service"
    done
    tar -czf "$artifact_root/linux-x86_64/OpenStream-Linux-x86_64.tar.gz" \
        -C "$linux_stage" usr
    rm -rf -- "$linux_stage"
    trap - EXIT
fi

macos_package="${OPENSTREAM_MACOS_PACKAGE:-}"
macos_archive="${OPENSTREAM_MACOS_APP_ARCHIVE:-}"
if [[ -n "$macos_package" ]]; then
    copy_required "$macos_package" "$artifact_root/macos-aarch64/OpenStream-macOS-arm64.dmg"
else
    echo "set OPENSTREAM_MACOS_PACKAGE to a real signed arm64 package before staging" >&2
    exit 1
fi
if [[ -n "$macos_archive" ]]; then
    copy_required "$macos_archive" "$artifact_root/macos-aarch64/OpenStream-macOS-arm64.zip"
else
    echo "set OPENSTREAM_MACOS_APP_ARCHIVE to a real signed app archive before staging" >&2
    exit 1
fi

"$repo_dir/scripts/generate-sbom.sh" \
    "$artifact_root/sbom/openstream-1.0.0.spdx.json"

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required" >&2
        exit 2
    fi
}

{
    for relative in \
        linux-x86_64/OpenStream-Linux-x86_64.tar.gz \
        macos-aarch64/OpenStream-macOS-arm64.dmg \
        macos-aarch64/OpenStream-macOS-arm64.zip; do
        printf '%s  %s\n' "$(hash_file "$artifact_root/$relative")" "$relative"
    done
} >"$artifact_root/checksums/SHA256SUMS"

printf 'staged real artifacts under: %s\n' "$artifact_root"
printf 'checksums and source SBOM generated; signing and acceptance evidence remain required\n'
