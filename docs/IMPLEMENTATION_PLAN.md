# OpenStream implementation plan

This is the execution plan, not a claim that every phase is complete. Each
phase has a concrete gate and must remain honest about what it verifies.

## Engineering hardening P0 — correctness, security, and liveness

- [x] Replace guest bearer-token management URLs with stable non-secret guest
  identifiers; retain the bearer only in the create response and WebSocket
  `Authorization` header.
- [x] Prevent session-scoped TURN credentials from surviving the session's
  remaining lifetime; reject issuance when the remaining lifetime is below the
  configured minimum.
- [x] Validate the current signaling message vocabulary and bounded fields
  before forwarding messages between roles.
- [x] Make capability negotiation use the bounded reliable-control channel with
  retransmission and an acknowledgement barrier on both sides.
- [x] Add authenticated direct-UDP keepalives and a finite direct-path idle
  timeout; wire liveness maintenance into every OpenStream host/client loop.
- [x] Bound desktop UI and input queues so a stalled renderer or network worker
  cannot grow memory without limit.

Gate: focused service/client/desktop tests, the complete locked workspace test
suite, clippy with warnings denied, and both local FFmpeg and full-ICE smoke
paths pass. External coturn, physical NAT, hardware, and stock Parsec
interoperability remain separate acceptance gates.

## Phase 0 — workspace and evidence

- [x] Preserve the supplied Parsec artifacts as analysis inputs.
- [x] Record a fact-check separating local evidence, official claims, and
  independent reverse-engineering material.
- [x] Import the independent MIT-licensed lowlat compatibility engine into an
  isolated subtree and fix its Apple-target test portability.
- [x] Add the first self-hosted signaling service and shared client pairing
  library.
- [x] Add the first project-owned authenticated datagram format with replay and
  size-limit tests.
- [x] Make the imported Rust workspace reproducible with a committed
  `Cargo.lock` and locked local checks.
- [x] Add a license inventory and binary-artifact handling rules.
- [x] Compare the clean-room OpenStream route with the verified
  Sunshine/Moonlight feature-acceleration route.
- [x] Add a read-only, repeatable artifact inventory script and analysis index;
  vendor binaries remain evidence inputs and are not runtime dependencies.

Gate: a clean build of the project’s protocol and signaling tests on macOS,
Linux, and Windows CI targets. The project-owned portable crates have a
three-OS CI matrix; the full lowlat engine remains Linux/macOS-runner work.

## Phase 1 — protocol core

- [x] Versioned capability message types and codec/input-limit negotiation.
- [x] Explicit capability gates for 10-bit, 4:4:4, clipboard, microphone,
  multi-monitor, pen, and rumble; omitted fields decode as disabled for
  backwards-compatible but safe negotiation.
- [x] Bounded chunked UTF-8 clipboard transfer and clear-operation framing;
  platform clipboard adapters, a 64-message bounded control window, and user
  policy remain separate.
- [x] Authenticated envelope, tamper, size-limit, and duplicate-counter tests.
- [x] Bounded video fragmentation/reassembly with out-of-order and duplicate
  tests.
- [x] Shared peer-session choreography for candidate and X25519 exchange.
- [x] Signed Ed25519 identity binding for ephemeral key exchange, with
  persistent-key loading, peer fingerprint pinning, and fail-closed remote
  defaults.
- [x] Bounded ordered reliable-control channel integrated into desktop/mobile
  event loops for lifecycle, keyframe requests, and frame acknowledgements;
  mobile input payloads and Linux uinput delivery use the same bounded ordered
  channel; the versioned keyboard/pointer/gamepad envelope is implemented.
- [x] Loss-tolerant video reassembly and bounded keyframe recovery request.
- [x] Bounded audio framing/jitter queue with missing-packet events.
- [x] External-FFmpeg audio pacing, Opus encode/decode, bounded jitter, and
  packet-loss concealment path.
- [x] Bounded `FA` assembled-frame acknowledgements and reusable adaptive
  bitrate controller; native Linux applies its decisions through lowlat's
  live encoder reconfigure path, while the external FFmpeg limitation is
  explicit.
- [x] Add `cargo-fuzz` targets for the imported lowlat parsers and the
  OpenStream datagram, control, media, input, and reassembly boundaries;
  compile the complete fuzz package as a locked standalone workspace.

Gate: deterministic loopback with loss, reordering, duplication, MTU limits,
and no unbounded memory growth.

## Phase 2 — service and connectivity

- [x] REST session/pairing service.
- [x] WebSocket signaling server with bounded pre-connect and post-connect
  role queues.
- [x] Direct encrypted UDP loopback reference peer.
- [x] RFC 5389 STUN Binding client and server-reflexive candidate exchange.
- [x] Opt-in UPnP IGD discovery and same-socket UDP port mapping with bounded
  SSDP/SOAP parsing; the mapped candidate is integrated into direct nomination.
- [x] Bounded authenticated direct candidate probe and UDP nomination.
- [x] Application-owned UDP relay fallback with role-token validation and a
  forced-relay integration test.
- [x] Optional full ICE candidate priorities, peer-reflexive candidates,
  nomination, consent freshness, and keepalives through `webrtc-ice`; a local
  authenticated full-ICE loopback passed.
- [x] Standards-based TURN URL/configuration support through `webrtc-ice`.
- [x] Session-scoped TURN credential issuance (`GET /v1/session/{id}/turn`,
  TURN REST HMAC-SHA1, `OPENSTREAM_TURN_*` env, pairing-embedded credentials,
  provisioning-script fetch, `turnserver.conf.example` secret mode).
- [ ] External coturn live interoperability run and public NAT matrix
  (`docs/NAT_MATRIX.md` records expectations and steps; namespace/simulator
  and forced-relay coverage exists).
- [x] Admin-gated session creation and explicit session revocation endpoint;
  a bounded global creation limiter (60/minute) is now enforced; per-user
  account policy and user-facing approval UI remain planned.
- [x] Cross-platform shell/PowerShell pairing-provisioning helpers with
  protected admin-token support.
- [x] Independent expired-session reaper, WebSocket close notification, and
  graceful HTTP/relay shutdown on SIGTERM or Ctrl-C.

Gate: two local processes connect through loopback, LAN, the application relay,
and configured full ICE; tokens are never accepted after expiry or revocation.
The remaining connectivity gate is an external coturn deployment plus a
public-NAT interoperability matrix.

The performance acceptance target follows Parsec's documented policy: keep
video queues bounded, prefer the newest decodable frame, and couple measured
loss/RTT/queue pressure to encoder bitrate before latency grows. The initial
network profile should be evaluated at approximately 30 Mbps host upload,
30 Mbps client download, and 2 Mbps client upload for 1080p60, while treating
those figures as acceptance guidance rather than a protocol requirement.

## Phase 3 — Linux host

- [x] Native Linux DRM/KMS scanout capture: output/framebuffer discovery,
  device-buffer export, pointer-plane support, device-side conversion, and
  bounded encoder integration through the lowlat display pipeline.
- [x] X11 setup/screens enumeration for diagnostics; actual X11 frame capture
  is the external FFmpeg `x11grab` profile, not a hidden raw-ZPixmap fallback.
- [x] Native PipeWire source discovery (`pw-dump` node list, shell-free) plus
  the external FFmpeg `pipewire` capture profile and node selection.
- [x] Native H.264/HEVC encoder profiles through FFmpeg/libavcodec
  (`libx264`/`libx265` defaults, `h264_nvenc`/`hevc_nvenc`,
  `h264_vaapi`/`hevc_vaapi`, `auto` NVENC-first detection with software
  fallback); in-process dlopen encoding remains future work.
- [x] External FFmpeg H.264 host adapter for Linux/Windows/macOS and desktop
  `ffplay` presentation smoke path.
- [x] Optional external FFmpeg PCM audio source, Opus packetization, and
  headless PCM output smoke path.
- [x] VAAPI and NVENC adapters: bounded filesystem/driver detection, common
  distribution library paths, explicit render-node override, low-latency
  profile flags, and negotiated 10-bit/4:4:4 pixel-format gating
  (`OPENSTREAM_VIDEO_ENCODER`, `OPENSTREAM_PIX_FMT`,
  `OPENSTREAM_ALLOW_10BIT/444`).
- [x] Linux lowlat Opus system-audio capture with configurable device,
  bitrate, and local-mute policy; external FFmpeg remains the portable fallback.
- [x] Encrypted OpenStream input payloads can feed the imported lowlat control
  expander and Linux `/dev/uinput` devices when explicitly enabled.
- [x] Cross-platform basic host input for the external-FFmpeg adapter: Linux
  `uinput`, Windows `SendInput`, and macOS CoreGraphics HID events, with
  focus-loss release and opt-in permission boundaries.
- [x] Explicit external-FFmpeg capture profiles: Linux X11/PipeWire,
  Windows GDI Desktop Capture, macOS AVFoundation, and shell-free custom
  argument parsing with invalid-profile rejection.
- [x] Linux uinput force-feedback events now use a bounded project-owned
  host-to-client rumble envelope; desktop Gilrs, Android vibration, and iOS
  haptics consume it.
- [x] Native Linux ACK-age/gap feedback is connected to the live lowlat video
  ceiling with floor, ceiling, queue, and reconfigure-rate bounds.
- [x] Portable external-FFmpeg live bitrate response: ACK-driven adaptive
  controller plus a hysteresis/cooldown-gated rolling restart
  (`OPENSTREAM_FFMPEG_RECONFIGURE=restart`); the replacement encoder starts
  with an IDR frame. Fixed-rate remains the default.
- [x] Explicit host permission policy shared by adapters (`HostPolicy`:
  input/clipboard/gamepad/microphone opt-ins plus approval mode, logged once
  redacted); Windows/macOS virtual gamepad hosts and UI permission prompts
  remain open.
- [x] Native Linux host systemd user-service template with explicit device
  group boundary (`deploy/openstream-linux-host.service`).
- [x] systemd user/system service split
  (`deploy/openstream-linux-host-system.service` runs unattended as a
  dedicated system user; compositor-mediated capture stays session-bound).

The Linux-only headless adapter now wires the imported DRM/KMS display/encoder
path to the OpenStream packetizer. `openstream-linux-host --preflight` reports
the native capture gate, outputs, X11/PipeWire availability, input device, and
hardware candidates without exposing credentials. The cross-platform external-FFmpeg adapter provides
an initial real H.264 source and basic host keyboard/pointer/wheel injection,
and the client can hand the stream to `ffplay`; native host GPU capture/encode,
live OS-level virtual-microphone routing, and decoder-level keyframe acceptance
remain open.

Gate: Ubuntu 22.04+ host streams a real desktop at 1080p60 for ten minutes
with bounded latency, audio, pointer, and keyboard input.

## Phase 4 — desktop client

- [x] Shared client core and reusable peer-session establishment.
- [x] Cross-platform desktop window using FFmpeg decode and shared
  keyboard/pointer input (`openstream-desktop-client`), with validated
  software BGRA presents, paced re-presents, and an optional native `wgpu`
  texture-present path for Metal, Vulkan/OpenGL, and Direct3D12.
- [x] Optional external `ffplay` PCM sink for the desktop Opus path.
- [ ] Exact Direct3D11 backend (the `d3d11` selector currently uses wgpu's
  Direct3D12 backend) and native driver/device acceptance.
- [ ] Long-run native renderer acceptance across supported Windows, macOS, and
  Linux GPU/driver combinations.
- [x] Full-screen/windowed/scale modes (`OPENSTREAM_DISPLAY_MODE`:
  windowed/borderless/fullscreen via borderless + FitScreen; exclusive-mode
  switching stays with the future native renderers).
- [x] Clipboard with explicit direction, approval, privacy, and conflict
  policy (`OPENSTREAM_CLIPBOARD_MODE`, `OPENSTREAM_CLIPBOARD_APPROVAL`,
  deterministic conflict resolution, redacted diagnostics); legacy
  `OPENSTREAM_CLIPBOARD=1` maps to bidirectional.
- [x] Desktop gamepad button/axis/unplug events through `gilrs` and `OI`.
- [x] Host rumble handling through the bounded project-owned `OR` envelope;
  desktop clients consume it through Gilrs.
- [x] Hotkey policy (`OPENSTREAM_HOTKEYS`, default Ctrl+Alt+End disconnect,
  Ctrl+Alt+Home release, and Ctrl+Alt+PageUp/PageDown monitor selection;
  fullscreen stays startup-only).

Gate: Windows, macOS, and Linux clients connect to the Linux host and to their
own desktop hosts using the same test service.

## Phase 5 — mobile clients

- [x] Client-only Rust C ABI bridge with bounded video callback and input queue.
- [x] Android Gradle client shell with H.264 `MediaCodec`, PCM `AudioTrack`,
  lifecycle teardown, and touch-to-`OI` input.
- [x] Android callback backpressure: bounded latest-frame and PCM queues with
  dedicated decoder/audio handler threads; stale media is dropped rather than
  accumulated.
- [x] Android decoder input-size guard before copying an access unit into a
  `MediaCodec` buffer.
- [x] Reproducible Android `cargo-ndk` bridge build helper and ABI library
  layout for `arm64-v8a` and `x86_64`.
- [x] Host-checkable mobile acceptance harness (`scripts/mobile-acceptance.sh`:
  bridge unit tests, C-ABI symbol exports, Kotlin/Swift hook presence,
  signing-template hygiene).
- [ ] Android arm64/x86_64 MediaCodec decoder/input on-device runs and
  signed store-ready APK (release signing template added; debug key and
  device validation open).
- [x] iOS source client layer with H.264 sample-buffer presentation, PCM
  `AVAudioEngine` output, lifecycle-owned session, and touch-to-`OI` input.
- [x] iOS Rust bridge build helper and C module-map integration seam.
- [ ] iOS arm64 VideoToolbox decoder on-device run (source layer, C ABI
  seam, and lifecycle/thermal hooks exist; Xcode signing/device validation
  open).
- [x] Touch-to-pointer and minimal virtual A/B/X/Y gamepad controls.
- [x] Background/foreground session handling: bridge pause keeps ACKs flowing
  while dropping media callbacks and input; Android `onPause`/`onResume` and
  iOS view appear/disappear plus thermal-state notifications are wired.
- [x] Mobile bitrate/thermal policy: normalized 0-3 levels drive deterministic
  frame-shedding (predicted halves, then keyframes-only + PCM mute);
  Android `PowerManager` listener and iOS `thermalState` reporting included.

Gate: signed development builds on Android and iOS render a live H.264 stream
and send pointer/gamepad input without host capability exposure.

## Phase 6 — feature parity

- [x] H.265 capability negotiation and external-FFmpeg host path; hardware
  decoder acceptance rides the FFmpeg BGRA path on desktop clients.
- [x] Multi-monitor topology wire format (`MD` list / `MS` select, bounded),
  RandR enumeration, fail-closed `OPENSTREAM_DISPLAY` startup selection with
  x11grab offsets, selected-output metadata, client PageUp/PageDown selection,
  and bounded runtime capture switching for the Linux X11/FFmpeg and native
  DRM/KMS hosts; an Xvfb virtual-display helper remains available
  (`scripts/virtual-display.sh`). Live virtual-display drivers and OS-level
  monitor creation remain open.
- [x] 10-bit and 4:4:4 end-to-end through the FFmpeg host/decoder path behind
  `OPENSTREAM_ALLOW_10BIT/444` on both ends with negotiation gating; native
  renderer acceptance remains open for the platform/driver matrix.
- [x] Bounded host rumble envelope and desktop/mobile client haptic callbacks.
- [x] Pen semantics: versioned `PenMotion`/`PenButton`/`PenProximity` OI
  events with pressure clamping, pointer-path host translation on Linux
  (uinput), Windows (SendInput), and macOS (CoreGraphics); pressure/tilt
  past absolute position and native tablet devices remain open.
- [x] Microphone passthrough: desktop FFmpeg mono capture with Opus voice
  framing as native virtual-device mic controls, host capability/policy
  gating, native-seat enablement on Linux, and a contained
  decode-and-verify sink on the FFmpeg host (`OPENSTREAM_MIC_SINK`); live
  OS virtual-microphone routing remains open.
- [x] Multi-guest admission and permissions on the service: host-minted guest
  tokens with input tiers, redacted listing, kick with prompt close, parked
  queue with promotion, and active-guest relay; simultaneous media fan-out
  to N guests remains open.
- [x] Redacted selected-path and local packet counters for diagnostics.
- [x] Remote RTT/loss metrics from the `FA` stream with a desktop overlay
  line plus a deterministic reconnect backoff; crash-safe recovery drills
  remain manual.

Gate: feature matrix tests plus platform-specific manual acceptance runs.

## Performance phase — transport/media hot path

The architecture and feature work above are now ahead of the latency-critical
implementation. This phase targets the remaining Parsec-class performance gap
without changing the default OpenStream wire format.

- [x] Low-level `lowlat-core` transport telemetry: cumulative sent and
  cumulatively acknowledged payload bytes, delivered/send rate over a bounded
  sampling interval, in-flight and stale pressure, SRTT, and retransmission
  count; the local congestion controller consumes measured delivery rate
  instead of a constant zero. Rates are decimal megabits per second and snapshots are
  available per send channel as well as in aggregate.
- [x] Propagate video-channel telemetry into the native Linux host's exported
  diagnostics and rate loop, keeping each guest's delivery measurement separate
  when guests share one encoder. Existing ABI consumers retain
  `bitrate_mbps` as a delivery-rate alias; the new counters are appended.
- [x] Add a per-guest paced sender with a bounded byte budget for bulk video;
  acknowledgements, control/input, and audio are scheduled ahead of it, and a
  target can be applied independently to every network path.
- [ ] Add path-aware MTU probing; preserve the 1200-byte safe floor and never
  raise the protocol ceiling.
- [ ] Add a common packet-telemetry adapter for the portable `PeerSession` /
  FFmpeg path so it uses the same delivery estimator as the native lowlat host.
- [ ] Add native macOS ScreenCaptureKit → IOSurface/CVPixelBuffer →
  VideoToolbox capture/encode, with live VideoToolbox bitrate updates.
- [ ] Add native Windows capture/encode and decoder-surface presentation;
  prioritize zero-copy surfaces over API-name parity with D3D11.
- [ ] Add capability-detected Android HEVC decode and benchmark NDK
  MediaCodec/AAudio against the current Kotlin MediaCodec/AudioTrack path.

Gate: packet-level telemetry is visible in a bounded diagnostic snapshot;
synthetic loss, delay, reordering, and rate changes remain deterministic; and
each native media backend has a measured capture-to-present latency report
before it is enabled by default.

## Compatibility backend

The Parsec-family compatibility backend is an optional track. It can use the
independent lowlat implementation and the supplied artifacts as research
inputs, but it must be isolated from the default OpenStream protocol. The
following are not considered verified merely because a document lists them:

- exact BUD bytes and nonce rules;
- service-side authorization behavior;
- relay service details;
- protocol generation compatibility across current clients;
- behavior outside a controlled peer session.

Gate: a stock client test is run only with owned accounts/endpoints, captures
are redacted, and compatibility claims identify the exact client build tested.

## Feature-complete acceleration backend

This is deliberately isolated from the compatibility backend and from the
OpenStream wire format.

- [x] Host/client backend traits shared by native OpenStream and the
  Sunshine/Moonlight profiles (`openstream-bridge`: validated stream
  profiles, Sunshine conf/apps generation, Moonlight argv builder).
- [x] Separate-process bridge boundary documented (no linking; GPL
  components stay out of the MIT link graph; see `THIRD_PARTY.md` and the
  `openstream-bridge` crate docs).
- [ ] Decide whether distributed bridge builds are GPL-3.0 combined works or
  separate processes, and publish complete corresponding-source notices.
- [ ] Run the same Windows x86-64/arm64, Linux x86-64/arm64, macOS
  x86-64/arm64, Android arm64/x86-64, and iOS arm64 acceptance matrix for the chosen
  product profile.
