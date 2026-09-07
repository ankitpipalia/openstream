# OpenStream iOS client integration

`OpenStreamSession.swift` is a Swift wrapper around the client-only C ABI. The
provided programmatic client layer adds `OpenStreamVideoView.swift` for H.264
Annex-B presentation through `AVSampleBufferDisplayLayer`,
`OpenStreamAudioSink.swift` for 48 kHz stereo PCM through `AVAudioEngine`, and
`OpenStreamViewController.swift` for touch-to-`OI` input and host rumble
haptics. It retains the callback context for the entire Rust worker lifetime
and copies every callback buffer before dispatching to the application.

## Link the bridge

1. Run [`build-rust.sh`](build-rust.sh) from this directory after installing
   Xcode's `iphoneos` SDK; it builds `openstream-mobile-ffi` for
   `aarch64-apple-ios`.
2. Add the resulting static library and
   [`include/openstream_client.h`](../../include/openstream_client.h) to an
   Xcode target. The checked-in
   [`OpenStreamFFI/module.modulemap`](OpenStreamFFI/module.modulemap) is the
   module-map seam for importing the C ABI.
3. Add the Swift files in this directory, request network access, and keep the
   session object alive until the view/controller stops it.

For production NAT traversal, initialize `OpenStreamSession` with its
`iceURLs`, `turnUsername`, and `turnPassword` arguments after loading those
values from Keychain. The credentials are passed separately from pairing JSON;
the original initializer remains the direct-path development API.

The Rust bridge has no host capture, host input injection, UIKit, or
VideoToolbox dependency. This separation keeps iOS client-only by construction
and lets the application own AVAudioSession, Metal/VideoToolbox surfaces,
background policy, and user permissions. A real Xcode project and signed
device build remain outstanding because the local machine only has the Command
Line Tools, not the iPhoneOS SDK.
