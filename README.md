# OpenStream

OpenStream is an independent, self-hosted low-latency desktop and game
streaming stack focused on Linux hosting. It includes a Rust signaling service,
encrypted UDP transport, bounded video/audio framing, a Linux host adapter,
cross-platform FFmpeg host/client adapters, desktop input, and client-only
Android/iOS integration seams.

This project is experimental. It is not a drop-in replacement for Parsec and
does not claim compatibility with Parsec's proprietary BUD/Kessel protocols or
services. The OpenStream runtime uses its own versioned protocol and can be
deployed with infrastructure that you control.

## What is included

- Self-hosted REST pairing and role-scoped WebSocket signaling.
- Authenticated X25519/AES-256-GCM UDP sessions with replay and size limits.
- Direct UDP nomination, optional STUN and UPnP, an application-owned relay,
  and an optional standards-based ICE/TURN path.
- Bounded H.264/H.265 fragmentation, reassembly, frame acknowledgements,
  audio framing, jitter buffering, packet-loss concealment, and clipboard/input
  envelopes.
- Linux X11/DRM/PipeWire capture and uinput integration through the imported
  lowlat engine, plus an external FFmpeg host path for Linux, Windows, and
  macOS.
- Software-rendered desktop client with an optional native `wgpu` presentation
  path (Metal, Vulkan/OpenGL, and Direct3D12), desktop gamepad/input support,
  mobile FFI, Android MediaCodec/AudioTrack sources, and iOS
  VideoToolbox/AudioEngine integration sources.
- Bounded queues, fuzz targets, CI checks, deployment templates, and detailed
  architecture/protocol documentation.
- Generation-scoped transport telemetry, a shared frame-feedback adapter, and
  host-authoritative direct ↔ opaque-relay ↔ direct migration over one
  encrypted session. ICE migration reports the typed unsupported result on the
  current `webrtc-ice` boundary.

## Repository layout

| Path | Purpose |
| --- | --- |
| `engine/lowlat` | Rust workspace containing OpenStream crates and the isolated MIT-licensed lowlat engine |
| `mobile/android` | Android client shell and JNI bridge |
| `mobile/ios` | iOS client integration sources |
| `include` | Public C header for the client-only mobile bridge |
| `deploy` | systemd and coturn deployment templates |
| `scripts` | Build, pairing, smoke-test, and mobile acceptance helpers |
| `docs` | Architecture, protocol, deployment, testing, compatibility, and research notes |

Vendor installers, extracted Parsec payloads, credentials, local packet/video
captures, build directories, and reverse-engineering work files are deliberately
excluded from this repository. The research documents describe how to perform
authorized local analysis without redistributing vendor artifacts.

## Quick start: local end-to-end demo

### Requirements

- Rust 1.85 or newer
- `ffmpeg` on `PATH`
- `curl`
- macOS, Linux, or a compatible Unix shell for the default launcher

Run the complete local signal-server, FFmpeg host, and headless-client demo:

```sh
./scripts/run-local-demo.sh
```

The demo uses loopback-only development authentication, creates temporary
pairing data, and writes an H.264 access-unit file. Override the duration,
ports, output path, or FFmpeg input with `OPENSTREAM_DEMO_SECONDS`,
`OPENSTREAM_DEMO_PORT`, `OPENSTREAM_DEMO_OUTPUT`, and
`OPENSTREAM_FFMPEG_ARGS`.

For a normal local-first role launch, keep the pairing response in a private
file and pass only its path to the launcher. Start the signal server
separately, then run the helper on one or both roles:

```sh
umask 077
pairing_file="$(mktemp "${TMPDIR:-/tmp}/openstream-pairing.XXXXXX")"
trap 'rm -f "$pairing_file"' EXIT
OPENSTREAM_FETCH_TURN=0 ./scripts/create-session.sh >"$pairing_file"
chmod 600 "$pairing_file"
OPENSTREAM_SIGNAL_ORIGIN=http://127.0.0.1:8080 \
  ./scripts/openstream-local-session.sh \
  --role both --pairing-file "$pairing_file" --duration 60
```

For two machines, copy the private pairing file through a secure channel and
run the helper separately with --role host and --role client. The helper
captures child output, enforces a finite duration, and never prints pairing
contents. The raw OPENSTREAM_PAIRING_JSON environment is reserved for an
explicit developer override using OPENSTREAM_DEVELOPER_OVERRIDE=1.

Run the authenticated full-ICE loopback smoke separately:

```sh
./scripts/full-ice-smoke.sh
```

Verify startup-order-independent direct establishment with the synthetic
reference peer:

```sh
./scripts/startup-order-smoke.sh
```

This starts the host first, waits 16 seconds (past the historical 15-second
candidate deadline), then starts the client and checks direct-v2 encrypted
media/control traffic. The smoke is loopback-only and does not claim WAN,
coturn, hardware, or native zero-copy media support.

On a Linux host, inspect native capture and device readiness before pairing:

```sh
./scripts/linux-host-preflight.sh
```

The report distinguishes DRM/KMS framebuffer reachability, X11/PipeWire
availability, FFmpeg and hardware candidates, and `/dev/uinput` presence. It
is diagnostic output, not proof of a live encoder/driver stream.

The physical Linux-NVIDIA → Apple-Silicon macOS MVP acceptance is recorded in
[`docs/BUILD.md`](docs/BUILD.md#physical-linux-nvidia--macos-apple-silicon-mvp-acceptance).
It validates the X11/FFmpeg `h264_nvenc` fallback, direct authenticated UDP,
the existing FFmpeg decoder, and software/wgpu Metal presentation. This is
the X11/FFmpeg/NVENC fallback path only. Native
DRM/KMS capture, VideoToolbox decode/encode, decoded-frame zero-copy, and
WAN/TURN acceptance remain separate gates.

To exercise the built-in opaque relay, configure a reachable relay endpoint
and set `OPENSTREAM_FORCE_RELAY=1`. For local testing:

```sh
OPENSTREAM_FORCE_RELAY=1 \
OPENSTREAM_RELAY_BIND=127.0.0.1:18100 \
OPENSTREAM_RELAY_ENDPOINT=127.0.0.1:18100 \
OPENSTREAM_DEMO_PORT=18101 \
./scripts/run-local-demo.sh
```

Run the one-session, three-generation migration acceptance:

```sh
./scripts/path-migration-smoke.sh
./scripts/ice-migration-capability.sh
```

The first command proves direct → application-owned opaque relay → direct;
the second reports `UnsupportedIceRestart` for the current
`webrtc-ice 0.17.2` boundary. Neither command claims external coturn,
public-NAT, native zero-copy media, or stock Parsec compatibility.

## Build and test

```sh
cd engine/lowlat
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo deny check
cargo build --workspace --release --locked

cd ..
scripts/check-release-artifacts.sh
scripts/secret-scan.sh
```

The fuzz package is intentionally outside the normal Cargo workspace. With
`cargo-fuzz` installed, run bounded campaigns before release, for example:

```sh
cargo fuzz run openstream-protocol -- -runs=10000
cargo fuzz run openstream-media -- -runs=10000
```

Hardware-dependent capture, GPU encoder, sound-server, uinput, Android, and
iOS tests require their native operating system, SDK, device, or driver and
are explicitly marked in the test and feature matrix.

The release artifact check verifies the host/client/server binaries produced
by the locked build. The secret scan uses gitleaks on the committed source
tree only; it does not scan build output or print matched material.

## Self-hosting

Build the release binaries from `engine/lowlat` and use the templates in
[`deploy/`](deploy/). Put the signaling service behind HTTPS/WSS for any
non-loopback deployment. Set a strong `OPENSTREAM_ADMIN_TOKEN`; without it,
session-management endpoints refuse requests unless the server is explicitly
run in loopback-only development mode with `OPENSTREAM_ALLOW_NO_AUTH=1`.

For the local-first MVP, an explicit trusted-LAN mode is available with
`OPENSTREAM_LOCAL_NO_AUTH=1` plus a numeric RFC1918/ULA/link-local
`OPENSTREAM_SIGNAL_BIND` (for example `192.168.1.69:8080`). It rejects
wildcard/public binds and requires no admin token. This removes only the
account/admin flow; role-scoped capabilities and encrypted peer sessions stay
enabled. Clients using a private-LAN `http://` origin must opt in with the
same variable. Treat the LAN as trusted and switch to admin-token HTTPS/WSS
before exposing the service beyond it.

For the application relay, configure:

```text
OPENSTREAM_RELAY_BIND=0.0.0.0:40000
OPENSTREAM_RELAY_ENDPOINT=203.0.113.10:40000
OPENSTREAM_RELAY_SECRET=REPLACE_WITH_A_LONG_RANDOM_SECRET
```

The relay secret must contain at least 16 bytes. Persist it securely if relay
tickets should survive service restarts. TURN credentials are configured
separately and are never placed in pairing JSON or URLs.

Pairing JSON contains role bearer capabilities. Treat it as a secret and never
commit it, put it in a public issue, or include it in logs.

## Current status

The local development path is functional and validated through direct UDP,
forced relay, authenticated loopback ICE, startup-order-independent direct-v2
establishment, and a real SteamOS/NVIDIA Linux-host → Apple-Silicon macOS-client
fallback stream. The GitHub workflow also runs the full-ICE loopback, a short
encrypted FFmpeg media loopback, and the host-checkable mobile acceptance
harness on Ubuntu. The implementation is not yet a finished product:
public-NAT/coturn interoperability, native DRM/KMS capture, long-run hardware
quality, exact Direct3D11/native GPU-driver acceptance, native macOS/Windows
capture and encode, VideoToolbox/zero-copy decode, durable signaling/account
state, native desktop audio, OS virtual microphone routing, virtual displays,
Windows/macOS virtual gamepads, Android/iOS device builds, USB passthrough,
and multi-guest media fan-out remain tracked work.

The legacy `lowlat-tray` binary is intentionally not load-bearing and remains
an open compatibility-engine phase. It is separate from the OpenStream
signal/host/client path.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [OpenStream protocol](docs/OPENSTREAM_PROTOCOL.md)
- [Build and validation matrix](docs/BUILD.md)
- [Deployment templates](deploy/README.md)
- [Feature matrix](docs/FEATURE_MATRIX.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Open-source stack decision](docs/OPEN_SOURCE_STACK.md)
- [Authorized reverse-engineering notes](docs/REVERSE_ENGINEERING.md)
- [Analysis toolkit](docs/RE_TOOLKIT.md)
- [Third-party inventory](THIRD_PARTY.md)
- [License](LICENSE)

## License

OpenStream-owned code is released under the MIT License. The isolated lowlat
engine and vendored third-party headers retain their own license and
provenance notices. See [THIRD_PARTY.md](THIRD_PARTY.md) before distributing
builds that include FFmpeg, PipeWire, libva, NVENC, coturn, or other external
components.
