# OpenStream Android client application

This directory is the Android-facing shell for the client-only Rust bridge.
It does not contain host capture or input-injection code. The Rust library
produced by `openstream-mobile-ffi` owns signaling, encrypted UDP, video
reassembly, Opus decode, ordered input, and the bounded host-to-client rumble
callback; Kotlin owns lifecycle, permissions, MediaCodec presentation,
AudioTrack output, haptic vibration, and touch policy. The minimal
application is in `app/src/main/java/app/openstream/MainActivity.kt`.

## Link the bridge

1. Install Android Studio with SDK 35, NDK, CMake 3.22.1, and Gradle support.
2. Install `cargo-ndk` with `cargo install cargo-ndk --locked` and ensure the
   Android NDK is discoverable through `ANDROID_NDK_HOME` or the usual SDK
   layout.
3. Run [`build-rust.sh`](build-rust.sh). It builds
   `openstream-mobile-ffi` and places `libopenstream_mobile_ffi.a` under
   `app/src/main/jniLibs/arm64-v8a/` and `app/src/main/jniLibs/x86_64/`.
4. Open this directory as a Gradle project and run `:app:assembleDebug`.
   The CMake build links the JNI shim in
   [`app/src/main/cpp/openstream_jni.cpp`](app/src/main/cpp/openstream_jni.cpp).
5. Enter the self-hosted signal origin and pairing JSON. The activity feeds
   H.264 access units to a `MediaCodec` surface, writes PCM to `AudioTrack`,
   and sends touch events through `OpenStreamNative.sendInput`.

For production NAT traversal, load the ICE URL list and TURN credentials from
Android Keystore-backed storage and call
`OpenStreamNative.nativeStartWithIce`. The URL list is separate from the
credentials and pairing JSON; use `nativeStart` for the direct development
profile.

The Rust bridge, ABI build helper, and Android project are source-complete,
but this machine has neither an Android SDK/NDK nor a Gradle installation, so
an APK, device run, signing result, and hardware decoder acceptance claim are
still outstanding.

The activity keeps callback pressure bounded: its video path retains at most
two access units and its audio path at most eight PCM fragments (about 160 ms
at 48 kHz), each drained on a dedicated handler thread. This is a latency
policy, not a substitute for device-level decoder and audio acceptance. Each
access unit is checked against the current `MediaCodec` input-buffer capacity
before it is copied.
