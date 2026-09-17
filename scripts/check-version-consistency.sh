#!/usr/bin/env bash
set -euo pipefail

# One product, one version number.
#
# The product version is written in nine places: a Tauri manifest, an npm
# manifest and its lock file, a Cargo manifest, two TypeScript constants, and
# the default in each packaging script. Nothing made them agree, and they did
# not: the release pipeline built and named artifacts `1.0.0` while every
# binary inside them reported `1.0.0-dev`, which is the kind of mismatch that
# is only ever found by reading all nine by hand.
#
# `desktop/src-tauri/tauri.conf.json` is the source of truth -- it is the one
# the packaged application actually reports to the operating system. Everything
# else must match it.
#
# Run: scripts/check-version-consistency.sh

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

fail=0
note() { printf '  ok   %-44s %s\n' "$1" "$2"; }
bad() {
    printf '  BAD  %-44s %s (expected %s)\n' "$1" "$2" "$3" >&2
    fail=1
}

# The first "version" key in a JSON file, without needing a JSON parser: these
# manifests all put it at the top level in the first few lines.
json_version() {
    sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -1
}

expected="$(json_version desktop/src-tauri/tauri.conf.json)"
if [[ -z "$expected" ]]; then
    echo "could not read the version from desktop/src-tauri/tauri.conf.json" >&2
    exit 1
fi
echo "product version (from desktop/src-tauri/tauri.conf.json): $expected"

check() {
    local label=$1 found=$2
    if [[ "$found" == "$expected" ]]; then
        note "$label" "$found"
    else
        bad "$label" "${found:-<not found>}" "$expected"
    fi
}

check "desktop/package.json" "$(json_version desktop/package.json)"
check "desktop/package-lock.json" "$(json_version desktop/package-lock.json)"
check "desktop/src-tauri/Cargo.toml" \
    "$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' desktop/src-tauri/Cargo.toml | head -1)"

# The Cargo lock file names the package too, and cargo builds with --locked:
# a manifest bumped without the lock fails resolution before it compiles a
# single crate, which presents as every desktop job failing at once for no
# visible reason.
check "desktop/src-tauri/Cargo.lock" \
    "$(awk '/^name = "openstream-desktop"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' \
        desktop/src-tauri/Cargo.lock)"

# The lock file names the workspace package a second time, in its packages map.
# A bump that edits only the top of the file leaves this one stale.
check "desktop/package-lock.json (packages[\"\"])" \
    "$(sed -n '/^  "packages": {/,/^  }/p' desktop/package-lock.json \
        | sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"

ts_version() {
    sed -n "s/.*version:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
}
check "desktop/src/adapters/productAdapter.ts" "$(ts_version desktop/src/adapters/productAdapter.ts)"
check "desktop/src/adapters/tauriAdapter.ts" \
    "$(sed -n 's/^const PRODUCT_VERSION[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' desktop/src/adapters/tauriAdapter.ts | head -1)"

# The packaging scripts fall back to a literal when OPENSTREAM_VERSION is unset.
# A stale fallback is how an artifact ends up named for a version its contents
# do not claim.
packaging_default() {
    sed -n 's/^version=\"\${OPENSTREAM_VERSION:-\([^}]*\)}\".*/\1/p' "$1" | head -1
}
check "packaging/macos/build-arm64-dmg.sh" "$(packaging_default packaging/macos/build-arm64-dmg.sh)"
check "packaging/linux/build-deb.sh" "$(packaging_default packaging/linux/build-deb.sh)"
check "scripts/build-release-artifacts.sh" "$(packaging_default scripts/build-release-artifacts.sh)"

if ((fail != 0)); then
    echo >&2
    echo "the product version disagrees between files; update them together" >&2
    exit 1
fi
echo "all version strings agree"
