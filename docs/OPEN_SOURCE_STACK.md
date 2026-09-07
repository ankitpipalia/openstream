# Open-source stack decision

This document reconciles the supplied fact-check with current upstream
projects. It prevents the project from treating “Parsec-like” and “stock
Parsec compatible” as the same engineering target.

## Three viable tracks

### A. Stock Parsec compatibility

Reimplementing BUD, Kessel authorization, relay behavior, and every media and
input quirk would be a clean-room interoperability project. The supplied
artifacts and `nomi-san/lowlat` are useful evidence, but they do not establish
an official wire specification. The OpenStream runtime must not ship Parsec
payloads, credentials, private keys, or copied implementation code.

### B. OpenStream native protocol

This is the default code path in `engine/lowlat`: a self-hosted service,
role-scoped WebSocket signaling, X25519/AES-GCM session transport, bounded
video/audio framing, opt-in UPnP IGD mapping, optional standards-based ICE/TURN
through `webrtc-ice`, and platform adapters. It gives us ownership of the server and protocol, but
it still needs production capture, codecs, desktop renderers, mobile device
validation, external coturn/public-NAT acceptance, and feature-parity work.
Android and iOS source-level client UI layers are present in `mobile/`.

### C. Feature-complete open-source acceleration

[Sunshine](https://github.com/LizardByte/Sunshine) is a self-hosted host for
Moonlight. Its current project matrix covers Linux, macOS, and Windows host
capture/encoding paths, including KMS/DRM, X11, Wayland/portal, DXGI,
ScreenCaptureKit, VAAPI, NVENC, VideoToolbox, and software encoding. The
project is GPL-3.0. Its current caveats matter: macOS is experimental,
gamepads are unavailable there, and Windows ARM64 is experimental.

[Moonlight Qt](https://github.com/moonlight-stream/moonlight-qt) supplies a
GPL-3.0 desktop client for Windows, macOS, and Linux. The official
[Moonlight Android](https://github.com/moonlight-stream/moonlight-android) and
[Moonlight iOS](https://github.com/moonlight-stream/moonlight-ios) projects
provide GPL-3.0 mobile clients. This is the shortest route to a working
cross-platform host/client product, but it speaks the GameStream/Sunshine
protocol, not OpenStream or Parsec BUD.

## Decision

OpenStream keeps its own service and protocol as the long-term product and
adds a separately isolated Sunshine/Moonlight acceleration track. A release
may choose one of these deployment modes:

| Mode | Host/client implementation | Compatibility | License consequence |
|---|---|---|---|
| Native OpenStream | OpenStream crates and native adapters | OpenStream peers | Project-owned code plus listed dependencies |
| Sunshine bridge | Sunshine host + an adapted Moonlight client | GameStream/Sunshine peers | GPL-3.0 obligations for distributed combined work |
| Parsec research | Isolated lowlat experiments only | Unverified stock compatibility | Do not ship Parsec artifacts or claim compatibility |

The bridge is not a silent dependency: it must be an explicit build/profile,
must preserve GPL source and notices, and must never send Parsec credentials to
third-party services. The native path remains necessary for a genuinely
self-hosted protocol and for future browser/mobile UI choices.

The safety/tooling baseline includes the imported lowlat fuzz corpus plus
OpenStream fuzz targets for the authenticated datagram, control, media, input,
and bounded reassembly parsers. These targets run before FFmpeg, Opus, and
platform GPU APIs, so they verify framing and allocation limits without
pretending to certify external codecs or drivers.

## Verified product implications

Parsec’s current Linux documentation still says Linux is client-only, which is
the gap this project addresses. Sunshine’s current host matrix demonstrates
that Linux hosting is practical, but it does not prove that every requested
architecture/GPU combination works. Each target still needs CI and hardware
acceptance tests.

The immediate implementation order is therefore:

1. Keep the tested OpenStream service, transport, media bounds, and Linux host
   adapter advancing.
2. Define a host/client backend interface so a Sunshine/Moonlight profile can
   supply mature capture, codec, input, and mobile behavior without entering
   the OpenStream wire path.
3. Complete native Windows/macOS host adapters and desktop renderers.
4. Finish native Android/iOS device acceptance and external coturn/public-NAT
   acceptance before declaring the requested matrix complete.
