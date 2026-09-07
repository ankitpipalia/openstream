#!/usr/bin/env bash
set -euo pipefail

# Build project-owned OpenStream host/client artifacts for one native or cross
# target. The target compiler, SDK, and hardware runtime remain the caller's
# responsibility; this keeps package selection and locked dependency handling
# identical across supported platforms.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
engine_dir="$repo_dir/engine/lowlat"
target="${OPENSTREAM_TARGET:-}"
profile="${OPENSTREAM_PROFILE:-release}"

case "$profile" in
    release) release_flag=--release ;;
    debug) release_flag= ;;
    *) echo "OPENSTREAM_PROFILE must be release or debug" >&2; exit 2 ;;
esac

packages=(
    -p openstream-signal-server
    -p openstream-ffmpeg-host
    -p openstream-client
    -p openstream-desktop-client
)
case "$target" in
    *android*|*apple-ios*)
        packages=(-p openstream-mobile-ffi)
        ;;
    *linux|*linux-*)
        packages+=( -p openstream-linux-host )
        ;;
esac

cd "$engine_dir"
if [[ -n "$target" ]]; then
    cargo build --locked ${release_flag:+"$release_flag"} --target "$target" "${packages[@]}"
    output_dir="$engine_dir/target/$target"
else
    cargo build --locked ${release_flag:+"$release_flag"} "${packages[@]}"
    output_dir="$engine_dir/target"
fi
printf '%s\n' "OpenStream build passed; artifacts are under $output_dir"
