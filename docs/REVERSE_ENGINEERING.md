# Parsec artifact and stack notes

This is a clean-room engineering record for the supplied installers and
payloads. It is not Parsec source code, and it does not grant permission to
interoperate with private accounts or endpoints. The OpenStream runtime must
not ship these artifacts.

## Evidence set

The supplied installers and extracted payloads are private analysis inputs and
are intentionally excluded from the public repository. When authorized to
inspect a copy, keep the working files in a locally ignored `analysis/`
directory or outside the checkout. The public engineering record retains only
the following high-level observations:

| Artifact | Local observation |
|---|---|
| Linux `.deb` | `parsecd-150-104a.so`, x86-64 ELF; package dependencies include libc6, libgcc/libstdc++, libudev, OpenSSL, X11/Xcursor/Xi/SM, OpenGL, ALSA, JPEG/PNG, curl, and FFmpeg |
| Windows payload | x86-64 PE; `parsecd.exe`, `pservice.exe`, `teams.exe`, and the service configuration were extracted |
| macOS package | version `150.101.1`; universal x86-64/arm64 payload; host capability is present |
| Android XAPK | XAPK v2; package `tv.parsec.client`, version `3.150.097.05`, min SDK 28, target SDK 34, arm64 split only; native file is `lib/arm64-v8a/libmain.so` |
| `libmatoya` | separate MIT-licensed cross-platform C source; useful as a reference dependency, not evidence that every Parsec path uses it |

Recorded hashes include:

- Linux payload: `708bc4e7194333dd16da64ae1c822dd973d0f647b39588351ea2b226bac09a07`
- Windows DLL: `8c8c4299ddf503b2c25c0905b0a0820f3e8238c252e9ace37bf25964ef4a8f6f`
- macOS x86 payload: `04d7a5e797b9fdd24c737b82fd3185a2b2c16b8505cf487d3f2b14b4ba83b49d`
- macOS arm64 payload: `2ff41665ab1ca6ad2c6159646b9c1143f2f932ce08c348342b71feadc5fbb9a9`

The supplied Linux and Windows `appdata.json` files name the versioned payload
and carry the matching SHA-256 hash. The Linux payload's dynamic symbol table
exposes only `wx_main` and `console_main` as defined exports. Its ELF
`DT_NEEDED` entries are limited to libc, libm, libstdc++, libgcc, and the
loader; strings and launcher behavior indicate that optional curl/OpenSSL,
FFmpeg, X11, OpenGL/Vulkan, audio, and device libraries are resolved with
`dlopen`/`dlsym`. This is consistent with a thin launcher plus a mostly
self-contained versioned payload. The file utility reports the Linux object as
“not stripped”, so “only two exported symbols” should not be confused with
“fully stripped”.

## Connection architecture

The official connection sequence describes four logical pieces: the client,
host, a signaling WebSocket, and STUN. In normal operation:

```text
client/host -> HTTPS API and WebSocket signaling
client/host -> STUN: learn public address and source UDP port
client <---- signaling ----> host: exchange candidates and session material
client <======== UDP =======> host: simultaneous-open/direct media path
                         \-> Parsec Relay/relay when direct UDP fails
```

The native media path is Parsec's BUD protocol over UDP. Publicly documented
properties are:

- BUD is a proprietary UDP protocol for low-latency interactive streaming.
- It uses DTLS 1.2 and AES-GCM for the protected record path.
- It has reliability semantics for selected traffic and custom congestion
  control coupled to the encoder/stream rate.
- The native client path uses BUD; the browser path is different: WebRTC
  DataChannels over SCTP over DTLS over UDP.
- The host-side BUD implementation is made ICE-compatible for browser
  sessions; browser and native interoperability is therefore not implied by
  the fact that both use UDP.
- UPnP and aggressive UDP hole punching are connectivity mechanisms (the public
  connection-sequence page calls them the default path); they are not the
  media protocol itself. OpenStream mirrors the behavior with opt-in IGD
  mapping and direct nomination.
- Public Parsec documentation calls the fallback a relay, including an
  enterprise on-premises Parsec Relay. It does not by itself establish that
  the fallback is a standards-compliant TURN allocation, so this report does
  not label it TURN without packet-level proof.

These high-level claims are supported by Parsec's [BUD networking
article](https://parsec.app/blog/a-networking-protocol-built-for-the-lowest-latency-interactive-game-streaming-1fd5a03a6007),
[browser networking article](https://parsec.app/blog/game-streaming-tech-in-the-browser-with-parsec-5b70d0f359bc),
and [connection sequence](https://support.parsec.app/hc/en-us/articles/32361410290324-Components-and-Connection-Sequence).

## Native stack indicators

The Linux payload's strings and symbols include the following strong
indicators:

| Layer | Evidence | Engineering interpretation |
|---|---|---|
| Control plane | HTTP/TLS URL and API strings; WebSocket/client-service strings | HTTPS API plus a persistent signaling WebSocket |
| NAT traversal | STUN, ICE candidate/action names, `libminiupnpc` source paths | STUN discovery, candidate exchange, optional UPnP mapping |
| Media transport | `bud_*`, `nat_*`, UDP, DTLS strings | Native BUD/UDP transport with NAT traversal support |
| Cryptography | `DTLS_method`, `EVP_aes_128_gcm`, `EVP_aes_256_gcm` | OpenSSL-backed DTLS/AES-GCM symbols are present in this build |
| Browser/network support | userspace SCTP source paths and `usrsctp` indicators | WebRTC/SCTP support is present in the native payload, although it does not mean native sessions use DataChannels |
| Video decode | FFmpeg decoder entry points and codec/source strings | FFmpeg is used at least for decoder paths in the inspected Linux object |
| Audio | Opus 1.1.3 indicators and ALSA dependency | Opus audio plus Linux sound integration is present |
| Device/control | X11/OpenGL/ALSA/libudev dependencies | Linux desktop, GPU, sound, and device integration |

The absence of visible `pipewire`, `wayland`, `vaapi`, `v4l2`, or `nvenc`
strings in this payload is only negative static evidence. It cannot prove
that those implementations are absent from a separately loaded library or a
runtime-generated path.

## Linux capability finding

The inspected Linux object contains host-related scaffolding but reports host
capability as false. The relevant path was re-disassembled:

```text
0x0002b6fe  xor edi, edi
0x0002b703  call 0x90070
0x0002b708  lea rsi, str.hosting_supported
0x0002b70f  mov rdi, r12
0x0002b712  mov rdx, rax
0x0002b715  call 0x90580
```

The helper at `0x90070` serializes the Boolean argument, so the Linux build
serializes `hosting_supported=false`. That explains the product behavior more
reliably than the presence of `host_*` strings: code can contain shared
protocol or configuration scaffolding while the shipped capability gate
still disables hosting.

The exact contiguous byte sequence `17 FE FD` was not found in the supplied
Linux shared object, Windows DLL, or macOS dylib. A missing static sequence is
not proof that a runtime record is absent; it can be constructed, encrypted,
relocated, or belong to another build. It is therefore not an OpenStream
implementation requirement.

## Android and iOS boundary

The supplied Android package is arm64 and client-only. Current Parsec
compatibility documentation also lists Android as experimental client-only and
does not support iOS/iPad. OpenStream's iOS client is consequently a new
implementation target, not an extracted feature. The planned native stacks
are Android MediaCodec/Surface input and iOS VideoToolbox/Metal rendering,
with no host capture or input-injection capability in either mobile package.

### Android split details

The XAPK manifest declares only `INTERNET`, `VIBRATE`, and `BLUETOOTH`; it does
not declare a host/display-capture or privileged input permission. The base APK
contains `tv.parsec.client.MainActivity` and Android input/surface classes. The
arm64 configuration split contains a stripped AArch64
`lib/arm64-v8a/libmain.so` with BuildID
`5c7a6dee00d757b271abbdb409ca361ac078dce3` and SHA-256
`ee3faf07cd7151e53a227cfc42ef591490d2241e2f88a6540941486ab7def4c0`.
Its native imports include `AMediaCodec`/`AMediaFormat`, `ANativeWindow`, and
AAudio stream APIs. Exported JNI symbols include Matoya app start/stop,
keyboard, pointer, scroll, gamepad, surface, and resize entry points; native
strings also expose Opus encode/decode, MiniUPnP, STUN, WebSocket, and the
same host-setting labels used by the shared UI. The host-setting strings are
shared product/UI vocabulary and are not evidence that this Android split can
capture or host a desktop session. The ABI and permission boundary support the
client-only conclusion.

## Independent lowlat material

The imported `engine/lowlat` checkout is the MIT-licensed independent
[`nomi-san/lowlat`](https://github.com/nomi-san/lowlat) project. Its documents
and tests provide valuable hypotheses about BUD framing, signaling fields,
candidate quirks, channels, ACKs, and packet limits. They are not Parsec source
and not an official specification. OpenStream therefore keeps that checkout
isolated and labels its exact BUD constants as provisional compatibility data.

The OpenStream-owned crates use a separate service and a separate `OS`-magic
AES-256-GCM datagram envelope. This avoids silently presenting an unverified
wire description as a supported Parsec implementation.

## Reproducible local analysis commands

Run these against copies of artifacts you are authorized to inspect:

```sh
file analysis/deb/usr/share/parsec/skel/parsecd-150-104a.so
shasum -a 256 analysis/deb/usr/share/parsec/skel/parsecd-150-104a.so
readelf -d analysis/deb/usr/share/parsec/skel/parsecd-150-104a.so
nm -D analysis/deb/usr/share/parsec/skel/parsecd-150-104a.so
rg -a -i 'bud|dtls|stun|candidate|opus|ffmpeg|hosting_supported' analysis/strings_linux.txt
```

For a second opinion, use `radare2` to locate the serialized capability field,
then verify the helper's calling convention and argument value before writing
the result into the fact-check. Do not patch, bypass, or redistribute the
vendor binary.
