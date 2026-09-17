#!/usr/bin/env bash
set -euo pipefail

unset OPENSTREAM_PAIRING_JSON OPENSTREAM_DEVELOPER_OVERRIDE

# A real OpenStream session between a native macOS host and the windowed
# desktop client on this machine, run to prove the zero-copy present path on a
# live window surface.
#
# Nothing here is a fixture: the host captures the display in-process and
# encodes with VideoToolbox, the client decodes with VideoToolbox into
# IOSurface-backed CVPixelBuffers, and the window imports each one into a Metal
# texture and draws it. No ffmpeg process is involved on either side, and no
# decoded pixel is ever read back to the CPU on the client.
#
# The host half is not zero-copy: it polls CGDisplayCreateImage and copies the
# framebuffer several times per frame, which is why the host stage lines in its
# log show far more time than anything on the client. That is a known finding,
# not something this rig is asserting away.
#
# What the offscreen tests cannot show, and this can:
#   * the presenter that draws the imported texture is the live window's
#     presenter, on the live swapchain, not an offscreen render target;
#   * frames survive the whole real path -- capture, encode, transport,
#     reassembly, decode, both mailboxes, import, present.
#
# Requires: macOS, Screen Recording permission for the terminal running this,
# and a GUI login session (the client opens a window).

umask 077
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
engine_dir="$repo_dir/engine/lowlat"
port="${OPENSTREAM_ZC_PORT:-18087}"
seconds="${OPENSTREAM_ZC_SECONDS:-15}"
# zero-copy (the default) or cpu, which runs the identical rig through the
# readback-and-upload path so the two can be compared on the same machine,
# the same capture and the same encoder. Without that A/B the zero-copy
# numbers have nothing to be better than.
mode="${OPENSTREAM_ZC_MODE:-zero-copy}"
server_log="$(mktemp -t openstream-zc-signal.XXXXXX)"
host_log="$(mktemp -t openstream-zc-host.XXXXXX)"
client_log="$(mktemp -t openstream-zc-client.XXXXXX)"
pairing_file="$(mktemp -t openstream-zc-pairing.XXXXXX)"
server_pid=""
host_pid=""

cleanup() {
    for pid in "$host_pid" "$server_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -f "$pairing_file"
}

on_exit() {
    status=$?
    if [[ "$status" != 0 ]]; then
        echo "zero-copy session failed; logs kept at:" >&2
        echo "  signal: $server_log" >&2
        echo "  host:   $host_log" >&2
        echo "  client: $client_log" >&2
    fi
    cleanup
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "this rig is macOS-only: the zero-copy path is VideoToolbox -> Metal" >&2
    exit 2
fi
case "$mode" in
    zero-copy) zero_copy=1 ;;
    cpu) zero_copy=0 ;;
    *) echo "OPENSTREAM_ZC_MODE must be zero-copy or cpu" >&2; exit 2 ;;
esac

cd "$engine_dir"
# Release, not debug. The pixel loops on both sides -- the host's stride pack
# and rescale, the client's readback -- are exactly what a debug build makes
# unrepresentative, and a latency measurement taken against them describes the
# compiler rather than the product.
cargo build -q --locked --release \
    -p openstream-signal-server \
    -p openstream-ffmpeg-host \
    -p openstream-desktop-client

OPENSTREAM_ALLOW_NO_AUTH=1 \
OPENSTREAM_SIGNAL_BIND="127.0.0.1:$port" target/release/openstream-signal-server \
    >"$server_log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "signal server did not become ready" >&2
    exit 1
fi

curl -fsS -X POST "http://127.0.0.1:$port/v1/session" \
    -H 'content-type: application/json' \
    -d '{"ttl_seconds":300}' >"$pairing_file"

common_env=(
    OPENSTREAM_SIGNAL_ORIGIN="http://127.0.0.1:$port"
    OPENSTREAM_PAIRING_FILE="$pairing_file"
    OPENSTREAM_UDP_BIND="127.0.0.1:0"
)

# OPENSTREAM_FFMPEG_ARGS is deliberately left unset: setting it would send the
# host back to the ffmpeg pipeline and this run would prove nothing.
env "${common_env[@]}" \
    OPENSTREAM_CAPTURE_BACKEND=native \
    OPENSTREAM_HOST_SECONDS="$seconds" \
    target/release/openstream-ffmpeg-host >"$host_log" 2>&1 &
host_pid=$!

# The client exits when the host stops and no reconnect is left, and prints its
# frame report on the way out -- which is where the presented-frame count that
# this rig asserts on comes from.
env "${common_env[@]}" \
    OPENSTREAM_RENDERER=metal \
    OPENSTREAM_DECODER=native \
    OPENSTREAM_ZERO_COPY="$zero_copy" \
    OPENSTREAM_RECONNECT_ATTEMPTS=0 \
    target/release/openstream-desktop-client >"$client_log" 2>&1 || true
wait "$host_pid" 2>/dev/null || true

fail=0
require() {
    if grep -Fq "$2" "$1"; then
        printf '  ok   %s\n' "$3"
    else
        printf '  MISS %s\n' "$3" >&2
        fail=1
    fi
}
refuse() {
    if grep -Fq "$2" "$1"; then
        printf '  BAD  %s\n' "$3" >&2
        fail=1
    else
        printf '  ok   %s\n' "$3"
    fi
}

echo "host:"
require "$host_log" "OpenStream native encoder: videotoolbox-h264" \
    "host encoded with VideoToolbox in-process"
# The host binary is still called openstream-ffmpeg-host and says so in its own
# banner, so the absence of the word proves nothing. What does is the selected
# source: the ffmpeg path reports the capture backend it was given
# (avfoundation on macOS) and an ffmpeg encoder profile, and neither can be
# printed by a run that went in-process.
require "$host_log" "OpenStream run capture=native" \
    "host captured in-process, not through an ffmpeg backend"
require "$host_log" "OpenStream run encoder=videotoolbox-h264" \
    "host reported the in-process encoder for the session"

echo "client ($mode):"
if ((zero_copy == 1)); then
    require "$client_log" "OpenStream zero-copy present enabled" \
        "client latched the zero-copy present path"
    require "$client_log" "GPU surfaces, no CPU readback" \
        "decode worker ran in GPU-surface mode"
    refuse "$client_log" "reverting to CPU frames" \
        "no import or present failure forced a fallback"
else
    # The comparison arm has to be the real CPU path, not a zero-copy run
    # with a different label, or the A/B measures nothing.
    require "$client_log" "CPU pixel buffers" \
        "decode worker ran in CPU-readback mode"
    refuse "$client_log" "OpenStream zero-copy present enabled" \
        "the comparison arm did not take the zero-copy path"
fi
refuse "$client_log" "using software present" \
    "the native Metal presenter stayed up"

# The counters are the only proof frames reached the live presenter: the log
# lines above would all appear even if every frame had been dropped.
presented="$(grep -o 'new_frames_present_submitted=[0-9]*' "$client_log" | tail -1 | cut -d= -f2)"
presented="${presented:-0}"
if ((presented > 0)); then
    printf '  ok   client presented %s frames (%s)\n' "$presented" "$mode"
else
    printf '  MISS client presented no frames\n' >&2
    fail=1
fi

if ((fail != 0)); then
    echo "zero-copy session did not meet its assertions" >&2
    exit 1
fi
printf '\nlive-window session passed: mode=%s frames=%s\n' "$mode" "$presented"
# The spans that differ between the two arms, printed so an A/B run can be
# compared without opening the logs.
grep -E 'telemetry (pixel_unpack|decoded_to_present_submit|present_call) ' "$client_log" || true
echo "logs: $server_log $host_log $client_log"
