#!/usr/bin/env bash
set -euo pipefail

# Verify the operator-facing binaries produced by the locked release build.
# This checks artifact presence only; it does not claim that a local GPU,
# display server, audio server, or mobile device is available.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
engine_dir="$repo_dir/engine/lowlat"
target="${OPENSTREAM_TARGET:-}"
profile="${OPENSTREAM_PROFILE:-release}"

case "$profile" in
    release|debug) ;;
    *)
        echo "OPENSTREAM_PROFILE must be release or debug" >&2
        exit 2
        ;;
esac

if [[ -n "$target" ]]; then
    artifact_dir="$engine_dir/target/$target/$profile"
else
    artifact_dir="$engine_dir/target/$profile"
fi

required=()
if [[ "$target" == *android* || "$target" == *apple-ios* ]]; then
    case "$target" in
        *apple-ios*)
            required=("libopenstream_mobile_ffi.a")
            ;;
        *)
            required=("libopenstream_mobile_ffi.so" "libopenstream_mobile_ffi.a")
            ;;
    esac
else
    required=(
        "openstream-signal-server"
        "openstream-ffmpeg-host"
        "openstream-client"
        "openstream-desktop-client"
        "openstream-host-agent"
    )
    if [[ -z "$target" || "$target" == *linux* ]]; then
        required+=("openstream-linux-host")
    fi
fi

missing=0
for artifact in "${required[@]}"; do
    if [[ ! -x "$artifact_dir/$artifact" && ! -f "$artifact_dir/$artifact" ]]; then
        echo "missing release artifact: $artifact_dir/$artifact" >&2
        missing=1
    else
        printf 'ok   %s\n' "$artifact"
    fi
done

if (( missing != 0 )); then
    echo "release artifact check failed" >&2
    exit 1
fi
printf 'release artifact check passed (%d artifacts)\n' "${#required[@]}"
