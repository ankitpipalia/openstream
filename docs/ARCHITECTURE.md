# OpenStream architecture

OpenStream is the working name for an independent, open-source low-latency
remote desktop and game-streaming system. It is not a Parsec binary fork and
does not require the Parsec service. The architecture is intentionally split
so a private deployment can use its own identity, signaling, relay, and
clients.

## Product targets

| Platform | Host | Client | Initial backend |
|---|---:|---:|---|
| Linux x86-64 | yes | yes | Native lowlat path plus FFmpeg X11/PipeWire profiles; uinput with explicit policy and runtime probe |
| Linux arm64 | yes | yes | Native lowlat path plus FFmpeg X11/PipeWire profiles; uinput with explicit policy and runtime probe |
| Windows x86-64 | yes | yes | FFmpeg GDI profile now; Desktop Duplication/encoders next |
| Windows arm64 | yes | yes | FFmpeg GDI profile now; Windows capture APIs next |
| macOS x86-64 | yes | yes | FFmpeg AVFoundation profile now; ScreenCaptureKit/VideoToolbox next |
| macOS arm64 | yes | yes | FFmpeg AVFoundation profile now; ScreenCaptureKit/VideoToolbox/Metal next |
| Android arm64 | no | yes | MediaCodec, native transport |
| Android x86-64 | no | yes | MediaCodec, native transport; emulator/desktop ABI |
| iOS arm64 | no | yes | VideoToolbox, native transport |

"Host" and "client" are separate capabilities. A mobile build never exposes
host capture or input-injection privileges.

Device capability truth is tracked locally in a separate catalog from the
coarse wire capability booleans. Each entry records protocol support,
implementation status, runtime availability, and hardware validation. A host
advertises a device feature only when protocol support, a real adapter, and a
successful bounded runtime probe are all present. Hardware-tested is reported
separately and is never inferred from a unit test, compile check, or API link.

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
handshake and returns the negotiated codec, audio, dimensions, FPS, basic
input, video-depth/chroma, clipboard, guest microphone, multi-monitor, pen,
and rumble policy. The `input` bit means only the basic keyboard, pointer, and
wheel path; it is not a promise that gamepad or tablet events are supported.
`PeerSession::connection_path()` exposes redacted local diagnostics
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
ACKs. Both host paths use the shared ACK-age/gap bitrate policy. That
end-to-end frame-feedback policy is separate from packet pacing and packet
congestion policy. Native Linux applies decisions through its live encoder
control, while the external FFmpeg path can opt into a hysteresis- and
cooldown-gated rolling encoder restart with
`OPENSTREAM_FFMPEG_RECONFIGURE=restart`. Fixed-rate remains the explicit
portable default because an external FFmpeg process has no live encoder-control
ABI. The prototype is not a claim of BUD compatibility.
Direct authenticated nomination remains the default. When `OPENSTREAM_UPNP=1`
is set, the direct path also advertises the mapped address from the same UDP
socket after a bounded SSDP/SOAP IGD mapping attempt. When `OPENSTREAM_ICE=1` or `OPENSTREAM_ICE_URLS` is configured,
`openstream-client-core` uses `webrtc-ice` for host/server-reflexive/
peer-reflexive/relay candidates, nomination, consent freshness, and optional
TURN allocation. The signaling service also forwards opaque encrypted
datagrams through its role-token-validated application relay.

Direct establishment is now startup-order independent. The signaling service
allocates a monotonic `establishment_generation` only for a complete current
host/client WebSocket pair and sends a server-generated `peer_ready(N)` to
those exact sockets. The direct client waits in a readiness state outside the
15-second candidate/key phase timers, then exchanges only the generation-tagged
`direct_candidate`, `direct_candidate_done`, and `direct_key` envelopes. A
socket replacement invalidates the old epoch and publishes a new one after
reset ordering succeeds. Socket generations remain separate from establishment
generations, and the existing `ice_candidate`, `ice_candidate_done`, and
legacy `key` vocabulary remains scoped to the independent ICE path.

### Shared transport policy boundary

Pure transport policy now lives in `openstream-transport-policy`, a
dependency-free `#![no_std]` crate. It contains the bounded `Pacer` state
machine and `PacerConfig`, plus the packet-congestion `Controller` state
machine and its `CongestionObservation` observation input type. It owns
deterministic policy only; it does not own sockets, wire-format encoding, or
session I/O.

`lowlat-core` re-exports those policy types for compatibility. It still owns
lowlat packet encoding, retransmission rings, PMTU probes, and session
orchestration, and supplies packet evidence to the policy. The portable
`PeerSession` now uses the same policy boundary without depending on lowlat
I/O or `webrtc-ice` details.

Portable `PeerSession` owns the common bounded class-aware outbound scheduler
and a channel-254 transport-meta ACK path. A fixed delivery-history ring
records authenticated sent-packet evidence and exposes aggregate plus
video/audio/critical snapshots with generation-scoped SRTT, delivery rate,
in-flight, stale, and retry observations. ACKs are coalesced and
non-ack-eliciting; application `send()` routes established media/control
traffic through the scheduler, while only typed setup/path-control operations
use immediate I/O. All four portable consumers (FFmpeg host, reference peer,
client, and desktop client) use the queue/flush/wake API, so the portable path
is scheduled and paced rather than an unpaced fixed-rate socket path.

These packet observations are local diagnostics and path-pressure evidence,
not fabricated peer delivery claims. The portable encoder remains driven by
end-to-end `FrameAck`/gap/age evidence; packet delivery statistics cannot by
themselves change its bitrate. Portable transport starts at the 1200-byte
sealed-datagram ceiling and does not yet implement portable DPLPMTUD. The
lowlat and portable backends therefore share policy semantics and scheduling
contracts, while their path I/O and remaining PMTU/media capabilities stay
separate. The portable FFmpeg encoder has no live-rate ABI; its bounded
rolling restart remains opt-in through
`OPENSTREAM_FFMPEG_RECONFIGURE=restart` and starts with a fresh IDR.

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
events. Basic input is negotiated only after `OPENSTREAM_ENABLE_INPUT=1` and
the host adapter's runtime probe succeed. Linux gamepad injection additionally
requires `OPENSTREAM_GAMEPAD=1`; the Linux injector permissions are set from
both grants, while unsupported gamepad and tablet events are rejected before
they reach an OS API. Windows and macOS have no virtual gamepad or full tablet
adapter in this build, so those features are not advertised. The
`microphone` capability is guest microphone transport and contained decode,
not an OS virtual microphone endpoint. Existing-monitor selection is not
virtual-display creation. Virtual microphones, virtual displays, USB
passthrough, and other privileged device adapters remain unimplemented and
are not advertised. Native capture, hardware encoding, exact Direct3D11
semantics, and platform audio sinks remain separate open adapters; an
optional `OPENSTREAM_AUDIO_PLAYER` process provides a portable desktop PCM
sink during development.

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
encoder ceiling. The portable external FFmpeg host routes the same frame
feedback through `PeerTelemetryAdapter`; when explicitly configured for
rolling reconfiguration, it applies a bounded restart with a fresh IDR.
The portable packet scheduler remains bounded and paced in either mode. The
encoder itself remains fixed-rate unless
`OPENSTREAM_FFMPEG_RECONFIGURE=restart` is enabled, because an external FFmpeg
process has no portable live-rate ABI; the implementation reports that
limitation rather than pretending a bitrate change was applied.

The imported sans-IO lowlat session also records packet-level local telemetry:
cumulative payload sent and cumulatively acknowledged, bounded-sample send and
delivery rates, SRTT, in-flight/stale pressure, and retransmission count. Rates
are decimal megabits per second, and the snapshot is available both in aggregate and
per send channel so video capacity is not inflated by control or audio traffic. The native
lowlat host applies the stream target to a bounded, per-guest video pacer; acknowledgements
are unpaced, while control/input and audio get bounded priority quanta ahead of bulk video.
The video burst is capped both by packet count and by approximately five milliseconds of
wire time at the current target; a path-MTU update can change the packet-count conversion.
The lowlat session now has a path-aware DPLPMTUD controller with exact authenticated padding
probes, three-attempt loss tolerance, IPv4/IPv6/relay-derived ceilings, maintenance reprobes,
and black-hole fallback. A confirmed size is applied atomically to ceiling-sized send-ring
storage, active packetization, and pacing; lowering is refused while an attached ring still
contains larger fragments. The portable `PeerSession` exposes generation-scoped
packet snapshots and `PeerTelemetryAdapter` consumes those snapshots alongside
end-to-end frame feedback. Path-local packet counters, pacer state, and
delivery samples reset on a path-generation change; the cipher/replay domain,
reliable-control ordering, frame IDs, and `FrameAck` history remain
session-wide.
The rate controller consumes measured delivery rate during clean-path ramp-up;
these counters are local diagnostics and do not add a congestion-feedback wire
message. The portable FFmpeg path uses the common frame-feedback adapter; its
encoder decisions remain grounded in `FrameAck` evidence, while local packet
rates remain diagnostic only.

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
- Linux input: `/dev/uinput` is opened only after the explicit input policy is
  enabled and the runtime probe succeeds; gamepads also require the explicit
  gamepad policy. A failed probe withholds the basic input and gamepad
  capability from negotiation.
- Windows input: SendInput provides basic keyboard and pointer events. There
  is no virtual gamepad, tablet, virtual microphone, virtual display, or USB
  adapter to advertise in this build.
- macOS input: CGEvent provides basic keyboard and pointer events after the
  host OS permits them. There is no virtual gamepad, tablet, virtual
  microphone, virtual display, or USB adapter to advertise in this build.
- Multi-monitor: the capability covers discovery and selection of existing
  outputs only. OS-level virtual monitor creation is a separate, unsupported
  adapter.
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
