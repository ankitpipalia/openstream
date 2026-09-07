# Parsec-to-OpenStream feature matrix

Updated 2026-09-07 after rereading the supplied fact-check texts, inspecting
the current workspace, and revalidating Parsec's public documentation. This
matrix is intentionally evidence-based: a checked OpenStream item means code
exists and has a relevant local test or source check; it does not mean every
target device has passed acceptance.

| Capability | Supplied/local Parsec evidence | OpenStream state | Evidence/status |
|---|---|---|---|
| HTTPS/API control plane | Kessel/API strings and official connectivity page | Implemented with self-hosted REST service | `openstream-signal-server`; live health/session/revoke check passed |
| WebSocket signaling | Role URL/action strings and official connection sequence | Implemented with role-scoped bearer tokens, typed bounded envelopes, bounded queues, and reliable capability establishment | `openstream-client-core`, signal-server tests |
| STUN, UPnP, and simultaneous UDP | STUN/UPnP/hole-punch strings and official port requirements | Implemented for direct nomination, opt-in SSDP/SOAP IGD mapping, optional standards-based ICE, authenticated direct keepalive, and finite direct-path liveness | UPnP parser/escaping tests, transport/client-core tests, local full-ICE loopback passed; physical-router/public-network matrix remains open |
| Relay fallback | Official docs describe a Parsec Relay that forwards UDP; its TURN semantics are not established | Application-owned opaque relay plus optional standards-based TURN via `webrtc-ice`, now with session-scoped service credentials | forced-relay and local full-ICE tests passed; `/turn` issuance tests passed; external coturn live run open |
| Native media transport | Parsec documents proprietary BUD over UDP, DTLS 1.2/OpenSSL | OpenStream uses a separate versioned `OS` UDP format with X25519/AES-256-GCM | protocol tamper/replay/size tests; intentionally not stock-compatible |
| Video | H.264/H.265, hardware encode/decode, low-buffer behavior observed | H.264/H.265 negotiation, bounded fragmentation, FFmpeg host/decode path, NVENC/VAAPI/libx264-5 profiles with detection, negotiated 10-bit/4:4:4 pix-fmt gating, ACK-driven rolling-restart rate control | H.264/H.265 loopbacks passed; in-process native encoders open |
| Adaptive bitrate | BUD public description says it adapts before queues grow; exact controller is proprietary | Bounded `FA` assembled-frame ACKs; native Linux reduces/ramps the lowlat encoder ceiling from ACK age and explicit client-reported gaps; FFmpeg startup rate remains fixed | media controller tests and native hook compile; long-run network/encoder acceptance open |
| Audio | Opus, 48 kHz stereo, approximately 20 ms browser samples | Opus packetization, jitter buffer, PLC, FFmpeg and Linux audio host paths | audio loopback passed; native mobile/device acceptance open |
| Keyboard/pointer/wheel/pen | HID/input strings and browser input channel | Fixed 32-byte `OI` envelope incl. pen motion/button/proximity, full desktop HID map, Linux uinput, Windows SendInput, macOS CoreGraphics translations, shared host permission policy | protocol/host tests pass; OS permission acceptance open |
| Gamepad | Gamepad API, XInput/ViGEm/uinput evidence | Desktop `gilrs` buttons/axes/unplug; Linux host uinput gamepad and force feedback; desktop rumble delivery; mobile virtual A/B/X/Y plus haptic callback | Linux hardware/gamepad acceptance open; Windows/macOS virtual gamepad host adapters remain open |
| Linux hosting | Linux artifact sets `hosting_supported=false` and lacks host capture/encoder evidence; Parsec's public host requirements call for hardware encoding | Native lowlat Linux adapter plus external FFmpeg host adapter; X11 setup/enumeration plus raw capture, PipeWire node discovery, HW detection, user+system systemd units, guest-mic seat enablement | code exists; Ubuntu 22.04+ 1080p60 hardware gate remains open |
| Windows hosting | Windows artifact has DXGI/NVENC/AMF/MFX indicators | External FFmpeg host adapter with explicit `gdigrab` profile, SendInput plus pen pointer-path events, NVENC profile support | native Desktop Duplication/encoder adapters open |
| macOS hosting | macOS artifact has ScreenCaptureKit/VideoToolbox/Metal indicators | External FFmpeg host adapter with explicit `avfoundation` profile, CoreGraphics pointer/pen events | native capture/encode/render adapters open |
| Desktop clients | Native platform render/input paths observed | Software window client (validated BGRA presents, paced re-presents, windowed/borderless/fullscreen, hotkeys, metrics overlay line, mic capture, 10-bit/4:4:4 opt-ins) | CI target matrix (incl. Linux x86-64/arm64 release jobs); device acceptance open |
| Android client | Supplied XAPK is client-only; MediaCodec is the intended boundary | Kotlin/JNI shell plus pause/resume lifecycle, thermal listener, release signing template, host-checkable acceptance harness | on-device MediaCodec runs and signed store APK open |
| iOS client | Supplied/current Parsec support does not include iOS | Swift client-only layer plus foreground/background pause, thermal reporting, acceptance harness | Xcode signing/device validation open |
| Multi-monitor/virtual displays | Parsec strings expose virtual monitor/VDD/VUSB features | `MD`/`MS` wire messages, RandR enumeration, `OPENSTREAM_DISPLAY` selection with x11grab offsets, Xvfb helper | live virtual-display drivers and runtime switching open |
| Clipboard/pen/microphone | Feature strings and package dependencies observed | Chunked clipboard with direction/approval/conflict/privacy policy on all front ends; pen OI events with host pointer-path translation; mic capture on desktop with host-side contained decode and verification sink | OS virtual-device routing (tablet/mic) remains open |
| USB passthrough | Parsec strings expose LibUSB/YubiKey passthrough | Deliberately not exposed in the OpenStream capability set yet; no safe cross-platform policy/backend | Requires isolated privileged-device design |
| Auth, permissions, metrics, recovery | Teams/ownership/whitelist/elevation and metrics strings observed | Admin token, TTL/revocation, 60/min creation limit, guest admission with parking/kick by non-secret guest id, signed/pinnable peer identity, host permission policy, RTT/loss overlay metrics, reconnect backoff | per-user account policy/UI and simultaneous media fan-out open |

## Interpretation

The matrix confirms that the current implementation is a functional,
self-hosted OpenStream development stack with Linux hosting, not a finished
all-feature Parsec replacement. It also confirms why stock Parsec clients are
not a supported target: OpenStream deliberately does not claim the unverified
BUD/Kessel byte-level and authorization behavior. The remaining unchecked
items are tracked in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
