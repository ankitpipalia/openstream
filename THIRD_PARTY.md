# Third-party components

This project will keep third-party code and licenses separate from the core
implementation.

| Component | Intended use | License/notes |
|---|---|---|
| libmatoya | Optional reference for cross-platform UI/networking helpers | MIT upstream; not vendored or required by the OpenStream build |
| lowlat | Optional Parsec-family compatibility research/backend | MIT; independent project, not Parsec source |
| Sunshine | Optional feature-complete host bridge | GPL-3.0; keep isolated and ship corresponding source/notices |
| Moonlight Qt/Android/iOS | Optional feature-complete client bridge | GPL-3.0; keep isolated and ship corresponding source/notices |
| FFmpeg | Codec/capture integration | LGPL/GPL depends on build configuration; publish build flags |
| ffmpeg/ffplay executable backend | Initial cross-platform capture/encode/live-render smoke path | External process only; no FFmpeg code is linked into OpenStream; follow the selected FFmpeg build license |
| libopus | Audio codec | BSD-style upstream license |
| PipeWire | Linux capture/audio | MIT/LGPL components; follow upstream notices |
| libva | Linux hardware encode/decode | MIT |
| libevdev | Linux input support | MIT |
| OpenSSL or rustls | TLS/HTTPS | Follow selected upstream license and platform policy |
| Tokio, axum, tokio-tungstenite | Async service, HTTP, and WebSocket plumbing | MIT/Apache-2.0 ecosystem crates; exact versions are locked in `engine/lowlat/Cargo.lock` |
| if-addrs | Enumerate concrete interface addresses for wildcard UDP binds | MIT/Apache-2.0 ecosystem crate; exact version is locked in `engine/lowlat/Cargo.lock` |
| aes-gcm, x25519-dalek, sha2 | OpenStream-owned session cryptography | MIT/Apache-2.0 ecosystem crates; review transitive notices from the lockfile |
| serde, serde_json, hex | Control-plane and key-message serialization | MIT/Apache-2.0 ecosystem crates |
| minifb | Initial software-rendered desktop client window | MIT; native GPU renderers may replace it per platform |
| wgpu | Optional native desktop texture presentation through Metal, Vulkan/OpenGL, and Direct3D12 backends | MIT/Apache-2.0 ecosystem crate; exact version is locked in `engine/lowlat/Cargo.lock` |
| hexf-parse | Transitive `wgpu`/`naga` parser for hexadecimal shader literals | CC0-1.0; allowed only as a crate-scoped `cargo-deny` exception |
| bytemuck, pollster | Pixel-slice casting and synchronous native-GPU initialization bridge | MIT/Apache-2.0 ecosystem crates; exact versions are locked in `engine/lowlat/Cargo.lock` |
| gilrs | Cross-platform desktop gamepad event collection | Apache-2.0/MIT; exact version is locked in `engine/lowlat/Cargo.lock` |
| webrtc-ice | Optional standards-based ICE/TURN agent in `openstream-client-core` | MIT/Apache-2.0; exact version is locked in `engine/lowlat/Cargo.lock` |
| url | URL parsing for the bounded UPnP device-description/SOAP client | MIT/Apache-2.0; exact version is locked in `engine/lowlat/Cargo.lock` |
| coturn | External standards-based TURN server for deployment/interoperability tests | Upstream license; separately deployed, with credentials supplied out of band |
| cargo-fuzz / libfuzzer-sys | Parser and allocation-boundary fuzzing | Development-only tooling; fuzz targets are in `engine/lowlat/fuzz/` |

No Parsec proprietary executable, service credential, private session key,
certificate, or installer payload is part of the OpenStream runtime.

The Rust dependency graph is the source of truth for generated notices. The
imported lowlat repository retains its own license and CI policy; OpenStream
does not silently relicense or merge it into the project-owned protocol.
