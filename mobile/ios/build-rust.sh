#!/bin/sh
# Build the client-only Rust bridge for an iPhoneOS Xcode target.
# Requires Xcode's iPhoneOS SDK and the aarch64-apple-ios Rust target.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)

cargo build --manifest-path "$repo_dir/engine/lowlat/Cargo.toml" \
    --target aarch64-apple-ios --release -p openstream-mobile-ffi
