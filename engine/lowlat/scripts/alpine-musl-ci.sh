#!/bin/sh
set -eu

apk add --no-cache build-base

# The repository's developer toolchain file intentionally follows stable for
# normal work. The CI image, however, is an immutable Rust 1.85.0 input, so
# override that channel explicitly instead of letting rustup download today's
# stable toolchain after it discovers rust-toolchain.toml.
export PATH="/usr/local/cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.85.0

rustc_version=$(rustc -V)
case "$rustc_version" in
  "rustc 1.85.0 "*) ;;
  *)
    echo "unexpected rustc version: $rustc_version" >&2
    exit 1
    ;;
esac

export CARGO_TARGET_DIR=/tmp/openstream-musl-target

cargo test --locked -p lowlat-common -p lowlat-core -p lowlat-net -- --test-threads=1

cc -std=c11 -Wall -Wextra -Werror -I include \
  -c crates/host/tests/c/alone.c -o /tmp/openstream-lowlat-abi-c.o
c++ -std=c++17 -Wall -Wextra -Werror -x c++ -I include \
  -c crates/host/tests/c/alone.c -o /tmp/openstream-lowlat-abi-cpp.o

echo "Alpine/musl validation passed"
