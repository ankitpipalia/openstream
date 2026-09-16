# Workstream 2 — Platform implementation matrix

## Host implementations

- Linux: native DRM/KMS/encode foundation plus production fallback profiles
  for X11 and PipeWire through FFmpeg. Only the fallback NVIDIA H.264 path has
  two-machine evidence, and the current release report does not accept that as
  the shipped capture-path gate.
- Windows: FFmpeg `gdigrab`, software/hardware encoder selection, and basic
  `SendInput` adapter compile. No physical host run, service packaging, native
  Desktop Duplication, or GPU-surface pipeline.
- macOS: FFmpeg `avfoundation` and basic CoreGraphics input compile. No
  ScreenCaptureKit/VideoToolbox host path, host service package, or physical
  host run.

## Client implementations

- macOS desktop: physically exercised using FFmpeg H.264 decode and minifb or
  wgpu/Metal upload. No desktop VideoToolbox zero-copy implementation.
- Windows/Linux desktop: same engineering desktop client compiles; no physical
  acceptance.
- Android: Rust transport/media bridge, JNI, `MediaCodec` AVC surface,
  `AudioTrack`, touch and basic gamepad UI. No signed APK/device acceptance;
  UI still accepts raw pairing JSON.
- iOS: Swift/C ABI source seam, H.264 `AVSampleBufferDisplayLayer`,
  `AVAudioEngine`, touch/lifecycle code. No complete Xcode project, signed
  device build, Metal view, HEVC, or physical acceptance.

## Combination classification

| Host → client | Overall status | Best evidence |
|---|---|---|
| Windows → Windows | Partially implemented / Build-only | CI cross-build |
| Windows → Linux | Partially implemented / Build-only | CI cross-build |
| Windows → macOS | Partially implemented / Build-only | CI cross-build |
| Windows → Android | Partially implemented / Build-only | separate components compile |
| Windows → iOS | Partially implemented / Build-only | separate components compile |
| Linux → Windows | Partially implemented / Build-only | CI cross-build |
| Linux → Linux | Partially implemented / Integration tested | loopback/smoke, no physical pair |
| Linux → macOS | Implemented but insufficiently tested | physical LAN fallback H.264 video |
| Linux → Android | Partially implemented / Build-only | bridge cross-build; no device |
| Linux → iOS | Partially implemented / Build-only | bridge cross-build; no device |
| macOS → Windows | Partially implemented / Build-only | CI cross-build |
| macOS → Linux | Partially implemented / Build-only | CI cross-build |
| macOS → macOS | Partially implemented / Build-only | CI cross-build |
| macOS → Android | Partially implemented / Build-only | separate components compile |
| macOS → iOS | Partially implemented / Build-only | separate components compile |

No combination is production-ready. Linux→macOS is the only physically tested
combination, and that test did not cover the release capture backend,
VideoToolbox, input, audio, WAN, TURN, packaging, or long soak.
