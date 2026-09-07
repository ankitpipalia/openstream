#!/bin/sh
# Start a headless Xvfb virtual display for OpenStream hosting without a
# physical monitor. Prints the DISPLAY value to put in the host environment.
# Virtual-display capture then works through the normal x11grab path:
#
#   ./scripts/virtual-display.sh        # prints e.g. :99
#   DISPLAY=:99 OPENSTREAM_FFMPEG_INPUT=:99.0 \
#     OPENSTREAM_PAIRING_JSON="$(./scripts/create-session.sh)" \
#     ./target/release/openstream-ffmpeg-host
set -eu

display=":${OPENSTREAM_VIRTUAL_DISPLAY:-99}"
width="${OPENSTREAM_VIRTUAL_WIDTH:-1920}"
height="${OPENSTREAM_VIRTUAL_HEIGHT:-1080}"
depth="${OPENSTREAM_VIRTUAL_DEPTH:-24}"
pid_file="${OPENSTREAM_VIRTUAL_DISPLAY_PIDFILE:-/tmp/openstream-xvfb${display#:}.pid}"

if ! command -v Xvfb >/dev/null 2>&1; then
    echo "Xvfb is not installed (apt install xvfb)" >&2
    exit 1
fi

# shellcheck disable=SC2086
Xvfb "$display" -screen 0 "${width}x${height}x${depth}" >/tmp/openstream-xvfb"${display#:}".log 2>&1 &
echo "$!" > "$pid_file"
echo "started Xvfb pid $! (stop with: kill $!; remove $pid_file)" >&2
echo "$display"
