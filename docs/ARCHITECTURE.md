# OpenStream architecture

OpenStream is the working name for an independent, open-source low-latency
remote desktop and game-streaming system. It is not a Parsec binary fork and
does not require the Parsec service. The architecture is intentionally split
so a private deployment can use its own identity, signaling, relay, and
clients.

## Product targets

| Platform | Host | Client | Initial backend |
|---|---:|---:|---|
| Linux x86-64 | yes | yes | Native lowlat path plus FFmpeg X11/PipeWire profiles; uinput |
| Linux arm64 | yes | yes | Native lowlat path plus FFmpeg X11/PipeWire profiles; uinput |
| Windows x86-64 | yes | yes | FFmpeg GDI profile now; Desktop Duplication/encoders next |
| Windows arm64 | yes | yes | FFmpeg GDI profile now; Windows capture APIs next |
| macOS x86-64 | yes | yes | FFmpeg AVFoundation profile now; ScreenCaptureKit/VideoToolbox next |
| macOS arm64 | yes | yes | FFmpeg AVFoundation profile now; ScreenCaptureKit/VideoToolbox/Metal next |
| Android arm64 | no | yes | MediaCodec, native transport |
| Android x86-64 | no | yes | MediaCodec, native transport; emulator/desktop ABI |
| iOS arm64 | no | yes | VideoToolbox, native transport |

“Host” and “client” are separate capabilities. A mobile build never exposes
host capture or input-injection privileges.

## Control plane

```text
HTTPS REST       account, devices, sessions, policy, health
WebSocket JSON   presence, offers, answers, candidates, disconnects
STUN             public endpoint discovery
UPnP IGD         opt-in same-socket UDP port mapping (direct profile)
UDP relay        self-hosted opaque fallback (implemented)
ICE/TURN         optional standards-based candidate checks and relay (implemented)
```

The OpenStream service will use its own domain and credentials. It must not
send bearer tokens to Parsec endpoints or depend on undocumented Parsec API
authorization.

The current development service is `openstream-signal-server` in
`engine/lowlat/crates/signal-server`. It provides health, pairing, and
role-scoped WebSocket forwarding. The current development client is
`openstream-client-core` in `engine/lowlat/crates/client-core`; it is shared by
desktop and mobile front ends.

Its `PeerSession` owns candidate exchange, role-scoped key exchange, and the
encrypted UDP socket. After transport setup it runs the versioned capability
handshake and returns the negotiated codec, audio, dimensions, FPS, input,
video-depth/chroma, clipboard, microphone, multi-monitor, pen, and rumble
policy. `PeerSession::connection_path()` exposes redacted local diagnostics
for whether direct UDP, a project relay, or full ICE was selected. The Linux
host and FFmpeg host log that value without logging addresses or credentials.
The Linux host adapter and headless client consume that same session object,
so native UI work does not fork the connection protocol.

The ephemeral X25519 exchange is bound to a persistent Ed25519 identity
signature. Native clients may load the identity from a secret file or
environment variable and pin the peer fingerprint; non-loopback sessions
fail closed without a pin unless the operator explicitly enables the unsafe
lab override.

## Data plane

The first implementation uses a versioned encrypted datagram protocol owned by
this project:

```text
UDP or QUIC datagram
  -> authenticated session envelope
  -> media/control channel
  -> frame or input message
```

QUIC remains the production transport candidate because it supplies modern key
agreement, replay protection, congestion control, streams, and datagrams. The
current MVP uses a small project-owned UDP wrapper while those policies are
implemented explicitly. A separate experimental compatibility backend may
implement the independently documented Parsec-family wire format, but it will
not be mixed into the default protocol or marketed as official compatibility
until a real peer test proves it.

The current prototype is `openstream-protocol` in
`engine/lowlat/crates/protocol`. It uses AES-256-GCM with authenticated headers,
monotonic counters, a 1200-byte initial UDP payload limit, and replay checks.
`openstream-media` adds bounded encoded-video fragmentation/reassembly. The
Linux host and headless client exercise fragmented access units and frame
ACKs. The native Linux path also has a bounded ACK-age/gap bitrate controller;
the external FFmpeg process path remains fixed-rate because it has no portable
live encoder-control ABI. The prototype is not a claim of BUD compatibility.
Direct authenticated nomination remains the default. When `OPENSTREAM_UPNP=1`
is set, the direct path also advertises the mapped address from the same UDP
socket after a bounded SSDP/SOAP IGD mapping attempt. When `OPENSTREAM_ICE=1` or `OPENSTREAM_ICE_URLS` is configured,
`openstream-client-core` uses `webrtc-ice` for host/server-reflexive/
peer-reflexive/relay candidates, nomination, consent freshness, and optional
TURN allocation. The signaling service also forwards opaque encrypted
datagrams through its role-token-validated application relay.

`openstream-ffmpeg-host` is the first real cross-platform source adapter. It
invokes FFmpeg as an external process, using the explicit `x11grab` or
`pipewire` profile on Linux, `gdigrab` on Windows, and `avfoundation` on
macOS, then feeds bounded H.264 chunks into the same encrypted packetizer.
The headless client can optionally pipe those chunks to `ffplay`.
`openstream-desktop-client` adds a desktop window: FFmpeg decodes negotiated
access units to BGRA while the default software presenter or optional wgpu
Metal/Vulkan/OpenGL/Direct3D12 presenter displays them. The window forwards
keyboard, pointer, wheel, and gamepad events through the shared `OI` envelope.
`openstream-ffmpeg-host` consumes those authenticated `OI` events through the
reliable control channel and translates basic keyboard, pointer, and wheel
input using Linux `uinput`, Windows `SendInput`, or macOS CoreGraphics HID
events when `OPENSTREAM_ENABLE_INPUT=1`. Native capture, hardware encoding,
exact Direct3D11 semantics, and platform audio sinks remain separate open
adapters; an optional `OPENSTREAM_AUDIO_PLAYER` process provides a portable
desktop PCM sink during development.

## Optional mature backend

The fact-check also records a separate Sunshine/Moonlight route for reaching a
feature-complete functional clone sooner. It is not part of the OpenStream
protocol or its default runtime. If adopted, it is an explicitly isolated
GPL-3.0 build/profile with its own corresponding-source obligations; Parsec
credentials and Parsec service endpoints remain out of scope.

## Media pipeline

```text
capture -> color conversion -> hardware/software encode -> packetize
       -> encrypted transport -> depacketize -> decode -> present
```

Video begins with H.264 8-bit 4:2:0; the external FFmpeg adapter also
supports H.265. Native HEVC, 10-bit, 4:4:4, multi-display, and zero-copy paths
are feature-gated. Audio uses Opus at 48 kHz using 10/20 ms
frames; the native Linux host and external FFmpeg host both feed that common
audio packetizer.

The latency policy is explicit: a late dependent video frame is discarded and
the receiver requests/reaches the next decodable keyframe. The system must not
grow an unbounded queue to preserve stale frames.

The host records each emitted frame in a bounded feedback window. A client
ACKs only a fully assembled/accepted frame, so pending-frame count, ACK age,
and explicit client-reported gaps are useful congestion signals without
trusting a peer clock.
The native Linux host uses those signals to lower or slowly raise the lowlat
encoder ceiling; a portable external FFmpeg host reports the limitation and
does not pretend that a bitrate change was applied.

## OS boundaries

The hot path is a small Rust core with no UI or platform policy. Platform
adapters are selected at compile time and reported at runtime:

- Linux capture: the current external backend supports X11 `x11grab` and an
  explicit PipeWire profile; PipeWire portal, XCB/XComposite, and
  DRM/KMS/DMA-BUF native adapters remain the production path.
- Windows capture: the current external backend supports `gdigrab`; Desktop
  Duplication first and Windows Graphics Capture later are the native path.
- macOS capture: the current external backend supports AVFoundation;
  ScreenCaptureKit, VideoToolbox encode, and Metal render are the native path.
- Linux input: `/dev/uinput` and libevdev; XTest is only an X11 fallback.
- Windows input: SendInput first; virtual gamepads are isolated behind an
  optional driver adapter.
- macOS input: CGEvent with explicit Accessibility permission.
- Android/iOS: native decoder and input clients only.

## Security boundaries

- Short-lived pairing codes and session credentials.
- Per-session authenticated encryption.
- Session revocation is implemented; a user-facing host approval policy/UI is
  still required for production.
- TURN credentials are session-scoped and short-lived. Provisioning helpers
  may embed them in the protected pairing response, while explicit
  environment/secure-storage credentials remain supported; they must never be
  logged or placed in a URL query.
- Native signaling authentication uses an `Authorization: Bearer` WebSocket
  handshake header. Query-string bearer tokens are rejected.
- The relay accepts only HMAC-authenticated, role-scoped relay tickets and
  enforces packet/byte budgets; it forwards opaque encrypted datagrams and
  never receives the session key.
- No arbitrary shell execution from a client.
- Host daemon separated from the UI process.
- `/dev/uinput` and display/GPU access granted only to the host service.
- Structured logs redact tokens, keys, candidate credentials, and user data.
