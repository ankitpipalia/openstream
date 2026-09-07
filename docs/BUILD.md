# Build matrix

## Host machine checks

```sh
cd engine/lowlat
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
```

The parser fuzz package is intentionally excluded from the normal workspace
because `cargo-fuzz` uses its own build flags. Compile every fuzz target with:

```sh
cargo check --manifest-path fuzz/Cargo.toml --locked
```

With `cargo-fuzz` installed, run bounded smoke campaigns before a release,
for example `cargo fuzz run openstream-protocol -- -runs=10000` and
`cargo fuzz run openstream-media -- -runs=10000`. The fuzz targets are
adversarial parser checks; they do not claim that FFmpeg, Opus, or a platform
GPU driver is memory-safe.

These checks cover the protocol, signaling, simulator, codec framing, and
platform-independent client logic. Hardware-dependent capture, encoder, audio,
and `/dev/uinput` tests are ignored or skipped when the device is unavailable.

The 2026-09-07 verification run passed all four commands above. The C ABI
header also passes `clang -fsyntax-only -x c`.

The latest local application smoke also completed over the current encrypted
path: a 5-second FFmpeg test source delivered 164 H.264 access units, the
client reassembled all 164, and the optional audio path produced a valid
48 kHz stereo `s16le` output file of 1,044,480 bytes. This is a loopback
acceptance test, not the Linux 1080p60 hardware gate.

The same host/client demo was rerun with `OPENSTREAM_UPNP=1`; it completed and
produced valid 1920×1080 H.264 while treating the router mapping as
best-effort. This verifies the application fallback path on a machine without
a controlled test IGD; it is not evidence of successful physical-router
mapping.

Use [`scripts/build-openstream.sh`](../scripts/build-openstream.sh), or
[`scripts/build-openstream.ps1`](../scripts/build-openstream.ps1) on native
Windows, to build the project-owned artifacts for one target.
`OPENSTREAM_TARGET` selects the Rust target triple; desktop targets build the
signal server, FFmpeg host, headless client, and desktop client, Linux targets
also build the native Linux host, and Android/iOS targets build only the
client-only mobile bridge. The script uses `--locked` and never includes the
supplied Parsec artifacts.

A separate H.265 loopback selection also passed: the host negotiated H.265,
sent 112 access units, and `ffprobe` identified the output as 320×240 HEVC at
25 fps. Native hardware decode/render acceptance remains platform-specific.

The release signaling binary's admin mode was also checked over HTTP: session
creation returned `401` without the configured token, returned `200` with the
bearer token, and revocation returned `204`.

To provision a pairing without hand-writing the REST request, run
[`scripts/create-session.sh`](../scripts/create-session.sh) or
[`scripts/create-session.ps1`](../scripts/create-session.ps1). Set
`OPENSTREAM_SIGNAL_ORIGIN`, `OPENSTREAM_SESSION_TTL`, and, for a protected
deployment, `OPENSTREAM_ADMIN_TOKEN`. Treat the printed JSON as a secret: it
contains independent host and client bearer capabilities.

For production peer authentication, persist an Ed25519 identity and provide
it through `OPENSTREAM_IDENTITY_KEY` (hex PKCS#8) or
`OPENSTREAM_IDENTITY_KEY_FILE` (raw PKCS#8 or hex text). Pin the other role's
logged SHA-256 identity fingerprint in `OPENSTREAM_EXPECT_PEER_IDENTITY`.
Non-loopback sessions reject an unpinned identity by default;
`OPENSTREAM_ALLOW_UNAUTHENTICATED_PEER=1` is a deliberate lab-only override.
Native WebSocket role tokens are sent in the `Authorization: Bearer` header;
query-string token authentication is not supported.

The repeatable local full-ICE smoke is
[`scripts/full-ice-smoke.sh`](../scripts/full-ice-smoke.sh). It starts a
loopback signal service, creates an ephemeral pairing, runs both reference
roles with `OPENSTREAM_ICE=1`, verifies the authenticated fragmented frame and
ACK, and removes only its own temporary files.

The same harness can exercise an external ICE/TURN service. Set
`OPENSTREAM_ICE_URLS` to comma-separated `stun:`/`turn:`/`turns:` URLs and set
`OPENSTREAM_TURN_USERNAME`/`OPENSTREAM_TURN_PASSWORD` separately. In that mode
the harness does not advertise loopback candidates, so a local direct path
cannot hide a TURN configuration error; credentials are passed only to the
child processes and are never printed.

The direct nomination profile can request router-assisted NAT traversal with
`OPENSTREAM_UPNP=1`. OpenStream performs bounded SSDP/SOAP IGD discovery and
maps the already-bound UDP port; `OPENSTREAM_UPNP_LEASE_SECONDS` controls the
short lease. This is intentionally opt-in and has not been claimed as a
physical-router acceptance test on this machine.

Desktop/Linux-host clipboard sync is opt-in with `OPENSTREAM_CLIPBOARD=1`
(legacy) or the explicit `OPENSTREAM_CLIPBOARD_MODE`
(`disabled`/`send`/`receive`/`bidirectional`) plus
`OPENSTREAM_CLIPBOARD_APPROVAL` (`auto`/`prompt`/`deny`). The
desktop client, native Linux host, and external FFmpeg host advertise the capability only when a local
clipboard adapter is available, exchange bounded `CB` chunks over the
authenticated reliable-control channel, and cap text at 64 KiB. The adapter
uses `pbcopy`/`pbpaste` on macOS, `clip.exe`/PowerShell on Windows, and
`wl-copy`/`wl-paste` with `xclip`/`xsel` fallbacks on Linux. Conflicting
concurrent edits resolve deterministically by transfer id, and diagnostics
carry lengths rather than contents.

After moving native WebSocket credentials from the URL query into the
`Authorization: Bearer` handshake header, the release reference host/client
session was rerun successfully; it completed encrypted UDP nomination,
capability exchange, fragmented video delivery, and the frame acknowledgement.

After the client-side signaling queues were bounded, a fresh local pairing
smoke again completed successfully: the host sent an authenticated fragmented
video frame and received its acknowledgement, while the client reassembled
the 2,319-byte payload. This confirms the backpressure change did not break
the live role handshake.

The optional full-ICE path was then exercised with `OPENSTREAM_ICE=1` and
loopback candidates enabled. Two role-authenticated peers exchanged ICE
credentials and marshalled candidate strings through the WebSocket, completed
ICE negotiation, and carried the same X25519/AES-GCM fragmented-video exchange;
the client reassembled the 2,319-byte payload and the host received its ACK.
This proves the local agent path, not an external coturn allocation.

The application-owned relay was then exercised with
`OPENSTREAM_FORCE_RELAY=1`. The pairing response advertised the relay,
invalid role tokens returned `401`, and the reference host/client completed
the same encrypted fragmented-video exchange through the relay. The relay
forwards opaque datagrams and does not possess the peer encryption key.

The high-rate release FFmpeg smoke also exercised the bounded-control
backpressure path: 17,530 encoded H.264 access units were sent and
reassembled, and `ffprobe` confirmed 320×240 at 25 fps. Capability negotiation
also reported the actual configured 320×240 stream dimensions to the client.
Redundant per-frame ACKs now yield to the bounded window instead of turning a
fast producer into a fatal control error; strict input, keyframe, and session
controls remain reliable/error-reporting.

After adding the negotiated-size FFmpeg filter, a fresh four-second real-time
`lavfi` loopback sent 112 H.264 access units from the host and reassembled 111
on the client; `ffprobe` confirmed the output dimensions remained 320×240.
The raw Annex-B output has no presentation timestamps, so its guessed frame
rate is not used as a timing assertion.

`openstream-desktop-client` is the first windowed desktop adapter. It accepts
the same pairing variables as `openstream-client`, starts an external FFmpeg
decoder for the negotiated codec, presents BGRA frames in a native window, and
forwards HID keyboard, three-button pointer, wheel, and gamepad events. The
default `OPENSTREAM_RENDERER=software` path is portable; `metal`, `vulkan`,
`opengl`/`gles`, and `d3d12` select the optional wgpu native texture-present
path. The legacy `d3d11` spelling is accepted for compatibility but maps to
wgpu's Direct3D12 backend because wgpu does not expose a D3D11 backend. If
native initialization or a later surface operation fails, the client logs the
reason and keeps the session alive with the software presenter. Set
`OPENSTREAM_AUDIO_PLAYER=ffplay` for the optional external PCM audio sink;
native audio sinks remain platform work.

For a credential-free native presentation smoke, build the desktop client and
run `OPENSTREAM_RENDERER=metal OPENSTREAM_RENDERER_SMOKE=1
./target/debug/openstream-desktop-client` on macOS, or select `vulkan`,
`opengl`, or `d3d12` on a host with that backend. The smoke creates a bounded
test frame, uploads it, presents once, pumps the window, and exits; unsupported
backends must report a software fallback rather than failing the process.

Clients acknowledge only fully assembled video frames with the versioned `FA`
control envelope. The native Linux host uses those ACKs for bounded bitrate
feedback (`OPENSTREAM_VIDEO_MBPS`, `OPENSTREAM_VIDEO_MIN_MBPS`, and
`OPENSTREAM_ADAPTIVE_BITRATE`); the external FFmpeg host validates and ignores
the feedback because its child process has no portable live-rate API.

The current optimized workspace release build was reproduced for the installed
`aarch64-apple-darwin` target, including signal-server, FFmpeg-host,
headless-client, desktop-client, reference-peer, and mobile-FFI artifacts. The
x86_64 macOS portable client/core/FFI/desktop check also passes, but its
release artifact and all Windows/Linux release artifacts must be rebuilt on
their native CI runners before distribution.

## Intended targets

| Target | Initial build | Required native SDKs |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Linux host/client | PipeWire, X11, FFmpeg, VAAPI/NVENC, uinput |
| `aarch64-unknown-linux-gnu` | Linux host/client | PipeWire, FFmpeg, VAAPI where available, uinput |
| `x86_64-pc-windows-msvc` | Windows host/client | Windows SDK, D3D11/DXGI, encoder runtime |
| `aarch64-pc-windows-msvc` | Windows on ARM host/client | Windows SDK and available encoder runtime |
| `x86_64-apple-darwin` | macOS host/client | ScreenCaptureKit, VideoToolbox, Metal |
| `aarch64-apple-darwin` | macOS host/client | ScreenCaptureKit, VideoToolbox, Metal |
| Android arm64/x86-64 | client only | Android NDK, MediaCodec |
| iOS arm64 | client only | Xcode SDK, VideoToolbox, Metal |

The current development machine has the Rust target libraries for macOS
arm64/x86-64, Windows x86-64/ARM64, Linux x86-64, Android arm64/x86-64, and iOS
arm64. The project-owned client/core/FFI subset checks pass for macOS x86-64;
the native workspace passes for macOS arm64. The other target rows below are
CI or SDK-dependent checks, not evidence of local cross-compilation: the
iPhoneOS SDK, Android NDK compiler, Windows MSVC sysroot, and Linux cross
GCC/sysroots are not present here. No mobile binary or store-readiness claim
is made.

The portable OpenStream target matrix is therefore authoritative in CI for
Windows x86_64/ARM64, Linux x86_64/ARM64, macOS x86_64, Android arm64/x86_64, and iOS
arm64. Native capture, display, encoder, and mobile SDK validation still needs
those runner toolchains and hardware.

CI now has an explicit target matrix for Linux x86_64 and ARM64, Windows
x86_64 and ARM64, macOS x86_64 and ARM64, Android ARM64 and x86_64, and iOS ARM64. It
checks the portable protocol/transport/media/platform subset for every target,
the cross-platform FFmpeg host adapter on all six desktop targets, and the
native Linux host adapter on both Linux targets. It also builds release
artifacts for the desktop host/client packages, native Linux host, desktop
client, and client-only mobile bridge; SDK- and NDK-dependent linking remains
runner-specific.

The target-specific result is deliberately split from the workspace result:

| Check | Result on this machine |
|---|---|
| `x86_64-apple-darwin` client/core/FFI crates | passed locally |
| `aarch64-apple-darwin` core crates | passed locally |
| `x86_64-apple-darwin` desktop client | passed locally |
| `aarch64-apple-darwin` desktop client | passed locally |
| `x86_64-pc-windows-msvc` core crates | CI target; no Windows C sysroot locally |
| `aarch64-pc-windows-msvc` core crates | CI target; no Windows C sysroot locally |
| `x86_64-unknown-linux-gnu` core crates | native Linux CI is authoritative; local cross-check blocked by missing `x86_64-linux-gnu-gcc`/Linux headers |
| `aarch64-unknown-linux-gnu` core crates | Linux CI target check; local cross-check unavailable without an ARM64 Linux sysroot |
| `aarch64-apple-ios` core crates | CI target; iOS standard library/SDK unavailable locally |
| `aarch64-linux-android` core crates | CI target; Android standard library/NDK unavailable locally |
| `x86_64-linux-android` core crates | CI target; Android standard library/NDK unavailable locally |
| `openstream-mobile-ffi` iOS binary | not linked: no `iphoneos` SDK |
| `openstream-mobile-ffi` Android binaries | not linked: no Android NDK clang toolchains |

The external FFmpeg adapter is a development/runtime backend for all three
desktop operating systems. It requires an `ffmpeg` executable on the host and
optionally `ffplay` on the client; capture-device names and permissions remain
OS-specific. It is not a substitute for the native low-latency capture and
hardware-encoder acceptance gates.

The default capture profiles are explicit and validated by the host adapter:

| OS | `OPENSTREAM_CAPTURE_BACKEND` | `OPENSTREAM_FFMPEG_INPUT` default |
|---|---|---|
| Linux/X11 | `x11grab` | `:0.0` |
| Linux/Wayland development path | `pipewire` | required PipeWire node name |
| macOS | `avfoundation` | `1:none` |
| Windows | `gdigrab` | `desktop` |

Set `OPENSTREAM_FFMPEG_ARGS` to provide a complete custom input. Its quoting
is parsed by OpenStream without a shell, so device names containing spaces
remain one argument and malformed quoting fails before process creation.

H.264 is the default. Set `OPENSTREAM_VIDEO_CODEC=h265` on the client to
negotiate H.265; the host then selects `libx265` unless
`OPENSTREAM_VIDEO_ENCODER` overrides it. Both encoders emit Annex-B access
units with codec-specific access-unit boundaries.

To exercise its audio path, set `OPENSTREAM_AUDIO=1` and either provide
`OPENSTREAM_AUDIO_FFMPEG_ARGS` for an OS audio device or set
`OPENSTREAM_AUDIO_TEST=1` for a generated 48 kHz sine source. Set
`OPENSTREAM_AUDIO_OUTPUT` on the client to write decoded interleaved stereo
16-bit PCM. The adapter inserts `-re` on the audio process so test/file input
cannot outrun the video wall clock.

The native Linux adapter uses the lowlat sound-server capture path when
`OPENSTREAM_AUDIO=1`; configure `OPENSTREAM_AUDIO_DEVICE`,
`OPENSTREAM_AUDIO_SERVER`, `OPENSTREAM_AUDIO_KBPS`, and
`OPENSTREAM_AUDIO_MUTE_LOCAL` as needed. The same client audio framing and
Opus decoder consume either host implementation.

Before starting a native Linux host, run
[`scripts/linux-host-preflight.sh`](../scripts/linux-host-preflight.sh), or
invoke `openstream-linux-host --preflight` directly.
It emits bounded JSON describing DRM/KMS outputs and framebuffer reachability,
X11 setup availability, PipeWire source discovery, FFmpeg presence, VAAPI/
NVENC candidates, `/dev/uinput` presence, and audio configuration. It never
prints pairing JSON, bearer tokens, addresses, or clipboard contents. A
successful preflight is necessary but not sufficient: the native encoder and
conversion driver still require a live paired stream. Set
`OPENSTREAM_VAAPI_RENDER_NODE=/dev/dri/renderDNNN` when the automatically
selected VAAPI node is not the device associated with the intended deployment.

`openstream-mobile-ffi` builds the SDK-independent native bridge as a
`cdylib`/`staticlib`; link it from the Android/iOS application and implement
the decoder/presentation callbacks in the platform layer. Cross-compilation
to the Apple mobile and Android targets requires the corresponding SDK/NDK,
target linker, and platform application project.

Source integrations are provided in [`mobile/android/`](../mobile/android/)
and [`mobile/ios/`](../mobile/). Android now has a Gradle project with a
`MediaCodec`/`AudioTrack`/touch client activity; it is deliberately not
described as an APK because this machine lacks the Android SDK/NDK and Gradle.
`mobile/android/build-rust.sh` now produces the imported JNI static libraries
through `cargo-ndk` when those tools are installed. The iOS bridge has the
corresponding `mobile/ios/build-rust.sh` helper and module-map seam.
The iOS integration provides the Swift session/view/audio/input source layer;
it still requires an Xcode project, SDK, signing, device acceptance, and
VideoToolbox/Metal integration testing.

For the optional mature backend, use the official Sunshine/Moonlight build
systems and licenses rather than copying binaries into the OpenStream runtime:
[Sunshine build/install documentation](https://github.com/LizardByte/Sunshine/blob/master/docs/getting_started.md),
[Moonlight Qt](https://github.com/moonlight-stream/moonlight-qt),
[Moonlight Android](https://github.com/moonlight-stream/moonlight-android), and
[Moonlight iOS](https://github.com/moonlight-stream/moonlight-ios).

Systemd deployment templates for the self-hosted signaling service, user-mode
FFmpeg host adapter, native Linux host adapter (user and system units), and coturn are in
[`deploy/`](../deploy). The client-core full-ICE path is enabled with
`OPENSTREAM_ICE=1` and `OPENSTREAM_ICE_URLS`; TURN credentials come from the
session-scoped `GET /v1/session/{id}/turn` endpoint (embedded in pairing JSON
by the provisioning scripts) or, as an override, through
`OPENSTREAM_TURN_USERNAME` and `OPENSTREAM_TURN_PASSWORD`. A local
full-ICE authenticated loopback passed. The external coturn live run and
public-NAT matrix remain release gates.
The FFmpeg host's basic keyboard/pointer/wheel injection is opt-in with
`OPENSTREAM_ENABLE_INPUT=1`; Linux requires access to `/dev/uinput`, Windows
requires the account's `SendInput` policy, and macOS requires Accessibility
permission for CoreGraphics HID events. Pen motion/buttons ride the absolute
pointer path on all three; gamepad and microphone need `OPENSTREAM_GAMEPAD=1`
and `OPENSTREAM_MIC=1` respectively, and the desktop microphone additionally
needs `OPENSTREAM_MIC_INPUT` naming the FFmpeg device. Hardware encoding is
selected with `OPENSTREAM_VIDEO_ENCODER` (`auto` detects NVENC then VAAPI
with a software fallback), and 10-bit/4:4:4 need `OPENSTREAM_ALLOW_10BIT` /
`OPENSTREAM_ALLOW_444` on both ends. Multi-monitor selection uses
`OPENSTREAM_DISPLAY` with topology advertised on negotiation; while connected,
the desktop client uses Ctrl+Alt+PageUp/PageDown to request the previous/next
announced output. The Linux X11/FFmpeg and native DRM/KMS hosts apply that
request live; custom FFmpeg inputs do not advertise switching. Headless
machines can add an Xvfb virtual display via
[`scripts/virtual-display.sh`](../scripts/virtual-display.sh).

For a one-command local host/client exercise, run
[`scripts/run-local-demo.sh`](../scripts/run-local-demo.sh) from the repository
root. It uses an FFmpeg `testsrc2` source by default, keeps pairing material in
temporary files, and writes the resulting H.264 stream to
`openstream-demo.h264`; set `OPENSTREAM_FFMPEG_ARGS` for a real display/device
source.
Native Windows users can run the equivalent PowerShell launcher at
[`scripts/run-local-demo.ps1`](../scripts/run-local-demo.ps1).

## Release rules

- Do not package the supplied Parsec artifacts.
- Do not package private session captures or credentials.
- Keep FFmpeg licensing/build flags explicit.
- Generate SBOM and third-party notices for every release.
- Produce separate host and client artifacts so mobile packages cannot acquire
  host privileges by configuration.
