# Mobile client bridge

`openstream-mobile-ffi` is the client-only Rust bridge for Android arm64,
x86_64, and iOS arm64 front ends. It owns the same signaling, direct or optional full
ICE/TURN candidate negotiation, X25519/AES-GCM transport, bounded video
reassembly, and bounded reliable input queue as the desktop client. It exports
a stable C ABI in
[`include/openstream_client.h`](../include/openstream_client.h).

The platform layer remains responsible for:

- Android `MediaCodec` surface/input integration; the provided Android
  application now includes the H.264 surface path and touch-to-`OI` bridge;
- Android callback backpressure is bounded: two video access units and eight
  48 kHz PCM fragments are drained on dedicated handler threads, so a slow
  decoder or audio/UI path drops stale media instead of accumulating latency;
- The Android decoder checks each access unit against the current
  `MediaCodec` input-buffer capacity before copying it, preventing a malformed
  or unusually large frame from throwing on the decoder thread.
- iOS `VideoToolbox`/Metal integration; the provided Swift layer presents
  H.264 through `AVSampleBufferDisplayLayer` and owns the audio engine;
- Android and iOS touch-to-pointer plus minimal virtual A/B/X/Y gamepad
  controls using the shared versioned `OI` envelope;
- host-to-client rumble is carried through a bounded `OR` envelope and exposed
  as `on_rumble`; Android maps it to `VibrationEffect` and iOS maps it to a
  haptic feedback generator;
- touch-to-pointer, virtual gamepad, orientation, lifecycle, and PCM audio
  sink;
- secure storage of pairing data and user-facing permission prompts.

The bridge calls `PeerSession::establish_configured` for the normal start API.
Mobile deployments use the direct profile by default. For production NAT
traversal, the C ABI also exposes `openstream_client_start_with_ice`: pass a
comma-separated `stun:`/`turn:`/`turns:` URL list and separate username/password
byte strings loaded from platform secure storage. That explicit API selects
full ICE without mutating process environment variables. Desktop tools can
still use `OPENSTREAM_ICE=1`, `OPENSTREAM_ICE_URLS`, and separate TURN
environment variables. Credentials must never be serialized into pairing JSON
or logs.

The callbacks receive H.264 access-unit bytes and interleaved signed-16-bit
48 kHz stereo PCM only for the duration of the callback; the platform must
copy them before returning. Missing Opus packets are decoded through the
codec's packet-loss-concealment path. `openstream_client_send_input` accepts
bounded `openstream-media` `OI` input events and sends them through the
ordered, bounded control channel; the host still decides whether input is
permitted. No mobile API exposes capture or `/dev/uinput`.

The minimal platform callback setup is:

```c
OpenStreamCallbacks callbacks = {
    .context = app,
    .on_ready = on_ready,
    .on_video = on_h264_access_unit,
    .on_audio = on_pcm_stereo_48khz,
    .on_rumble = on_rumble,
    .on_error = on_stream_error,
};
```

`on_video` and `on_audio` run on the Rust worker thread. A UI must copy or
enqueue both buffers before returning and marshal presentation/audio work to
its platform thread as required by MediaCodec, VideoToolbox, or the native
audio API.

The bridge is intentionally independent of Android/iOS SDK headers, which lets
the Rust portion be cross-checked on macOS now and linked by Gradle/Xcode
toolchains in the mobile build jobs. Source-level application integrations are
provided in [`mobile/android/`](../mobile/android/) and
[`mobile/ios/`](../mobile/). The Android project is not device-verified here
because the local machine has no Android SDK/NDK or Gradle installation; the
iOS integration is a Swift/Xcode source layer pending the iPhoneOS SDK,
project signing, and device acceptance.
