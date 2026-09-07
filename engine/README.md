# OpenStream engine workspace

This directory contains the Rust implementation workspace. The `lowlat`
subdirectory is an isolated import of the independent MIT-licensed
[`nomi-san/lowlat`](https://github.com/nomi-san/lowlat) project, retained as an
optional Parsec-family compatibility/research backend. OpenStream-owned
crates are named `openstream-*` and use their own service and wire format.

## What is runnable today

- `openstream-signal-server`: self-hosted HTTP pairing plus role-scoped
  WebSocket signaling. Pairings expire and pre-connect signaling is bounded.
- `openstream-client-core`: shared Rust signaling client for desktop and future
  Android/iOS bridges, including the encrypted versioned capability handshake.
- `openstream-protocol`: project-owned AES-256-GCM packet envelope with
  authenticated headers, MTU bounds, and counter replay checks.
- `openstream-transport`: connected UDP wrapper that seals and opens those
  packets, plus a bounded RFC 5389 STUN Binding client for the same socket.
- `openstream-media`: bounded encoded-video fragmentation and out-of-order
  reassembly with duplicate/eviction tests, plus bounded audio framing and a
  sequence-aware jitter queue.
- `openstream-linux-host`: Linux-only headless adapter that consumes the
  imported display/encoder and optional Opus desktop-audio pipeline and sends
  its encoded access units over the OpenStream data plane.
- `openstream-ffmpeg-host`: cross-platform external-FFmpeg host adapter for
  Linux (`x11grab`), Windows (`gdigrab`), and macOS (`avfoundation`). It keeps
  codec libraries out of the Rust process and sends real H.264 access data.
- `openstream-client`: cross-platform headless receiver that reassembles
  access units into an H.264 file, with an optional `OPENSTREAM_PLAYER=ffplay`
  live renderer for desktop smoke tests.
- `openstream-mobile-ffi`: client-only `cdylib`/`staticlib` bridge for Android
  and iOS native video decoder/UI layers, with decoded Opus PCM callbacks.
- `openstream-reference-peer`: synthetic host/client smoke test proving the
  HTTP → WebSocket → candidate exchange → encrypted UDP → acknowledgement path.
  `PeerSession::establish_configured` selects the direct STUN profile by
  default and the optional full-ICE/TURN profile when `OPENSTREAM_ICE=1` or
  `OPENSTREAM_ICE_URLS` is supplied.

The reference peer is not a desktop streamer: its “video” payload is a small
synthetic message. Capture, encode, decode, render, input, audio, relay, and
mobile UI are still tracked as implementation phases in
[`docs/IMPLEMENTATION_PLAN.md`](../docs/IMPLEMENTATION_PLAN.md).

## Local validation

```sh
cd engine/lowlat
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
```

For the end-to-end smoke test:

```sh
OPENSTREAM_SIGNAL_BIND=127.0.0.1:8080 cargo run -p openstream-signal-server
curl -X POST http://127.0.0.1:8080/v1/session \
  -H 'content-type: application/json' -d '{"ttl_seconds":120}'
```

Save the JSON response as `OPENSTREAM_PAIRING_JSON` and run one `host` and one
`client` reference peer with the same value. The complete pairing document is
only a development bootstrap; production key agreement must be replaced by an
authenticated per-role exchange.

To advertise server-reflexive candidates, set
`OPENSTREAM_STUN_SERVERS` to comma-separated numeric `ip:port` endpoints on
both roles, for example `203.0.113.7:3478,[2001:db8::7]:3478`. The current
implementation performs a Binding transaction and exchanges those results,
then runs an authenticated direct-path probe. For hostile NATs, set
`OPENSTREAM_ICE=1` and configure `OPENSTREAM_ICE_URLS` to select the separate
`webrtc-ice` path, which includes peer-reflexive candidates, nomination,
consent, and optional TURN allocation. External coturn interoperability is
still an acceptance gate.

For a real desktop smoke run, install `ffmpeg` and set
`OPENSTREAM_PLAYER=ffplay` on the client. The FFmpeg host chooses `x11grab`,
`gdigrab`, or `avfoundation` from the target OS; override the executable with
`OPENSTREAM_FFMPEG` or provide a complete argument fragment with
`OPENSTREAM_FFMPEG_ARGS`.

The optional audio smoke path uses `OPENSTREAM_AUDIO=1` plus either
`OPENSTREAM_AUDIO_FFMPEG_ARGS` or `OPENSTREAM_AUDIO_TEST=1`; the client writes
decoded stereo PCM when `OPENSTREAM_AUDIO_OUTPUT` is set.

## Portability rule

Linux-specific capture, host, uinput, and namespace fixtures stay behind
target gates. The project-owned protocol, signaling, and transport crates must
compile on the desktop targets and remain free of display-server or host
privileges so they can be reused by mobile clients.
