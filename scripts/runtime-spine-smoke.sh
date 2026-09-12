#!/usr/bin/env bash
set -euo pipefail

# Assert that the desktop runtime spine is wired in the source tree: the Tauri
# runtime command boundary, the host-agent bridge, and the frontend adapter
# that consumes them. This is a source-shape check. It does not start a
# session, does not touch the network, and is not hardware, WAN, VideoToolbox,
# zero-copy, or release evidence.
#
# The script prints paths and status only. It never reads a pairing file, a
# settings file, or any credential material.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_dir="$(cd "$script_dir/.." && pwd -P)"
cd "$repo_dir"

failures=0

fail() {
    printf 'FAIL  %s\n' "$1"
    failures=$((failures + 1))
}

pass() {
    printf 'ok    %s\n' "$1"
}

note() {
    printf 'note  %s\n' "$1"
}

require_file() {
    if [ -f "$1" ]; then
        pass "$1 is present"
    else
        fail "$1 is missing"
    fi
}

require_match() {
    local pattern="$1"
    local path="$2"
    if [ ! -f "$path" ]; then
        fail "$path is missing, cannot check for $pattern"
        return
    fi
    if grep -q -- "$pattern" "$path"; then
        pass "$path declares $pattern"
    else
        fail "$path does not declare $pattern"
    fi
}

printf '== Tauri runtime command boundary ==\n'
require_file desktop/src-tauri/src/runtime.rs
for command in runtime_snapshot runtime_settings runtime_update_settings runtime_dispatch; do
    require_match "$command" desktop/src-tauri/src/lib.rs
done
require_match 'generate_handler!' desktop/src-tauri/src/lib.rs

printf '\n== Host-agent bridge ==\n'
require_file desktop/src-tauri/src/host_agent.rs
for command in host_agent_health host_agent_start host_agent_stop; do
    require_match "$command" desktop/src-tauri/src/lib.rs
done

printf '\n== Frontend runtime adapter ==\n'
require_file desktop/src/adapters/tauriAdapter.ts
require_file desktop/src/adapters/tauriAdapter.test.ts
require_match 'createDefaultAdapter' desktop/src/App.tsx
require_match 'createTauriAdapter' desktop/src/adapters/tauriAdapter.ts

printf '\n== Frontend lockfile ==\n'
if [ ! -f desktop/package-lock.json ]; then
    fail "desktop/package-lock.json is missing"
elif command -v node >/dev/null 2>&1; then
    if node -e 'JSON.parse(require("fs").readFileSync("desktop/package-lock.json","utf8"))' 2>/dev/null; then
        pass "desktop/package-lock.json parses as JSON"
    else
        fail "desktop/package-lock.json is not valid JSON"
    fi
elif command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import json,sys; json.load(open("desktop/package-lock.json"))' 2>/dev/null; then
        pass "desktop/package-lock.json parses as JSON"
    else
        fail "desktop/package-lock.json is not valid JSON"
    fi
else
    note "no node or python3 available to parse desktop/package-lock.json"
fi

printf '\n== Session runtime crates ==\n'
for crate in ffmpeg-host desktop-client signal-server client; do
    require_file "engine/lowlat/crates/$crate/Cargo.toml"
done

printf '\n== Built fallback binaries (informational) ==\n'
release_dir="engine/lowlat/target/release"
for binary in openstream-ffmpeg-host openstream-desktop-client openstream-signal-server openstream-client; do
    if [ -x "$release_dir/$binary" ]; then
        note "$release_dir/$binary is built"
    else
        note "$release_dir/$binary is not built in this checkout"
    fi
done

printf '\n== Credential boundary ==\n'
if [ -n "${OPENSTREAM_PAIRING_FILE:-}" ]; then
    note "OPENSTREAM_PAIRING_FILE is set; this script does not read it"
else
    note "OPENSTREAM_PAIRING_FILE is not set"
fi
if [ -n "${OPENSTREAM_PAIRING_JSON:-}" ]; then
    fail "OPENSTREAM_PAIRING_JSON is set in this environment; use the pairing-file boundary"
else
    pass "OPENSTREAM_PAIRING_JSON is not set"
fi

printf '\n'
if [ "$failures" -ne 0 ]; then
    printf 'runtime spine smoke: %d check(s) failed\n' "$failures"
    exit 1
fi
printf 'runtime spine smoke: source-shape checks passed\n'
printf 'This is not hardware, WAN, VideoToolbox, zero-copy, or release evidence.\n'
