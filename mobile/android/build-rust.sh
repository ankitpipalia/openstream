#!/bin/sh
# Build the client-only Rust bridge for every Android ABI used by OpenStream.
# Requires the cargo-ndk tool and an installed Android NDK.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
jni_dir="$script_dir/app/src/main/jniLibs"

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "cargo-ndk is required; install it with: cargo install cargo-ndk --locked" >&2
    exit 1
fi

mkdir -p "$jni_dir"
cargo ndk -t arm64-v8a -t x86_64 -o "$jni_dir" \
    build --manifest-path "$repo_dir/engine/lowlat/Cargo.toml" \
    --release -p openstream-mobile-ffi
