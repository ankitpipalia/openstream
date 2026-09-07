# Reverse-engineering and build toolkit

This is the reproducible toolkit for studying the supplied installers and
building the independent OpenStream implementation. Run it only against
software and accounts you are authorized to inspect. The commands below are
for extraction, observation, and compatibility testing; they do not require
patching a vendor binary or defeating service authentication.

## 1. Identify and preserve evidence

Keep the original installer immutable. Work on copies, record the exact build,
architecture, and hash, and save tool output beside the artifact:

```sh
file artifact
shasum -a 256 artifact
```

Useful metadata tools by package type:

| Artifact | Tools | What they establish |
|---|---|---|
| Linux `.deb` | `dpkg-deb -I`, `dpkg-deb -x`, `ar`, `tar`, `readelf` | package metadata, dependencies, files, ELF ABI and dynamic dependencies |
| macOS `.pkg` | `pkgutil --expand-full`, `xar`, `plutil`, `codesign`, `otool` | component payloads, property lists, signature/provision metadata, Mach-O slices and load commands |
| Windows `.exe`/NSIS | `7z`, `7zz l/x`, `sigcheck`, `llvm-readobj`, `llvm-objdump` | embedded files, PE headers/imports/exports, version and signature metadata |
| Android `.xapk`/APK | `7z`, `unzip`, `aapt2 dump badging`, `apkanalyzer`, `jadx`, `apktool` | split ABI layout, SDK levels, manifest permissions, Java/Kotlin resources and native libraries |

Example non-destructive extraction commands:

```sh
mkdir -p work/deb work/pkg work/xapk
dpkg-deb -x parsec-linux.deb work/deb
pkgutil --expand-full parsec-macos.pkg work/pkg
7z x Parsec_3.150.097.05.xapk -owork/xapk
```

Do not include extracted vendor binaries, credentials, private captures, or
license files in an OpenStream release. The public repository intentionally
does not contain the local `analysis/` evidence area; keep authorized inputs
outside the checkout or in a locally ignored `analysis/` directory.

The repeatable local inventory is
[`scripts/audit-parsec-artifacts.sh`](../scripts/audit-parsec-artifacts.sh); it
prints hashes, file types, filtered strings, and optional ELF/Mach-O metadata
without executing or modifying the supplied files. It reports missing inputs
when the private evidence set is not present, which is the expected result in
a clean public checkout. The evidence-backed conclusions are summarized in
[`docs/FACT_CHECK.md`](FACT_CHECK.md).

The OpenStream connectivity smoke is
[`scripts/full-ice-smoke.sh`](../scripts/full-ice-smoke.sh). It validates the
local full-ICE signaling/agent/data path without printing the temporary bearer
pairing.

## 2. Static native inspection

Start with cheap, repeatable scans before disassembly:

```sh
strings -a -n 5 payload > strings.txt
nm -D payload                       # ELF defined/imported dynamic symbols
readelf -dW payload                 # DT_NEEDED and loader behavior
readelf -Ws payload | less
otool -L payload                    # Mach-O linked libraries
otool -l payload                    # load commands and code signatures
llvm-readobj --file-headers --sections --coff-imports payload.exe
llvm-nm -m payload.dylib
```

Search strings by subsystem rather than by one guessed protocol name:

```sh
rg -a -i 'bud|dtls|stun|turn|ice|candidate|relay|upnp|opus|ffmpeg|x264|x265' strings.txt
rg -a -i 'pipewire|wayland|vaapi|nvenc|vulkan|x11|alsa|uinput|hid|xinput|vigem' strings.txt
rg -a -i 'hosting_supported|hosting|host_|server|session|offer|answer|close|candex' strings.txt
```

For control-flow confirmation use `radare2`/Cutter, Ghidra, Binary Ninja,
Hopper, or LLVM disassembly. A useful sequence is:

1. Find the capability field or UI label in `.rodata`.
2. Find cross-references to that string.
3. Inspect the helper that serializes the value and its calling convention.
4. Record the architecture-specific argument value and the exact build hash.
5. Confirm the result in a second tool before treating it as a fact.

For the supplied Linux payload this process establishes that the
`hosting_supported` serializer receives zero. It does not establish that all
host code is absent, nor does a missing byte sequence prove that a runtime
record cannot be constructed.

## 3. Runtime observation

Only observe a controlled, authorized session. Capture enough context to
separate the control plane from the media plane:

| Goal | Tools | Expected result |
|---|---|---|
| DNS, TCP, TLS, WebSocket, UDP endpoints | Wireshark, `tshark`, `tcpdump` | API/WebSocket and STUN/UDP/relay address inventory |
| Timing and packet sizes | Wireshark I/O graphs, `tshark -T fields` | candidate exchange, keepalives, media cadence, retransmission hints |
| Process/library loading | `strace -f -e trace=network,openat`, `lsof -p`, LLDB | `dlopen`/device/runtime dependencies and socket lifecycle |
| macOS process observation | `fs_usage`, `opensnoop`, `dtruss` where permitted, Activity Monitor | file, library, device and network events; respect platform security controls |
| Windows process observation | Process Monitor, TCPView, ETW/WPR | DLL loading, sockets, device/encoder access |
| User-space call tracing | Frida, LLDB, platform debuggers | function arguments and state transitions in a lab build/session |
| HTTP metadata | browser developer tools, a controlled reverse proxy | URL/method/header/body shapes when TLS is under your control |

Do not infer plaintext from an encrypted packet capture. If TLS or DTLS is
being investigated, use keys or logging from a session you own and control;
do not defeat certificate pinning, intercept another user's traffic, or send
captured bearer tokens to a third-party endpoint.

## 4. Network and media test tools

The OpenStream acceptance loop uses the following tools:

```sh
# Inspect codec availability and generated streams
ffmpeg -hide_banner -hwaccels
ffmpeg -hide_banner -encoders
ffprobe -hide_banner -show_streams output.h264

# Impair a Linux test namespace without changing the host network
sudo ip netns add openstream-test
sudo tc qdisc add dev veth-test root netem loss 2% delay 30ms 5ms reorder 1%

# Inspect a reproducible packet trace
tshark -r capture.pcapng -T fields -e frame.time_epoch -e ip.src \
  -e ip.dst -e udp.length
```

The repository's `lowlat` tests model loss, duplication, reordering, NAT
mapping, PMTU, liveness, and recovery without requiring root. The new
`cargo-fuzz` targets add parser-level checks. Use `cargo-deny` for dependency
licenses/advisories and `cargo-audit` as an additional advisory scan when
available.

## 5. Package map from the supplied artifacts

The observed stack separates into these layers:

| Layer | Observed/probable components | OpenStream decision |
|---|---|---|
| Launcher/update | versioned payload, hash/lock metadata, `dlopen`/`dlsym`, `wx_main`/`console_main` | do not copy; use normal signed release artifacts and explicit host/client binaries |
| API/signaling | libcurl/OpenSSL, HTTP, WebSocket, Kessel-style action/candidate names | self-hosted axum REST plus bounded WebSocket signaling |
| NAT traversal | STUN, UPnP/MiniUPnPc, ICE-like candidate exchange, relay fallback | RFC5389 discovery, opt-in SSDP/SOAP IGD mapping, and authenticated direct nomination by default; optional `webrtc-ice` full ICE/TURN path; coturn/public-NAT acceptance remains open |
| Native media | proprietary BUD over UDP, DTLS 1.2/OpenSSL, reliability/congestion control | separate versioned `OS` AES-GCM datagrams; never claim BUD compatibility |
| Browser media | WebRTC DataChannel/SCTP/DTLS/UDP | future browser client; not assumed for native peers |
| Video | FFmpeg decoder indicators, H.264/H.265, platform encode paths on some builds | FFmpeg development backend now with Linux X11/PipeWire, Windows GDI, and macOS AVFoundation profiles; PipeWire/DRM/DXGI/ScreenCaptureKit native zero-copy and hardware encode next |
| Audio | Opus, ALSA and optional platform audio | Opus 48 kHz framing/jitter/PLC now; native per-OS sinks next |
| Input | HID, X11, uinput, XInput/ViGEm, gamepad APIs | stable 32-byte `OI` envelope; desktop `gilrs`; Linux uinput rumble returns through bounded `OR`; native host policy/gamepad adapters remain |
| UI/GPU | X11/OpenGL/Vulkan, Metal/D3D indicators, libmatoya | minifb/FFmpeg software desktop path now; native renderers next |
| Mobile | Android arm64 split, MediaCodec-style client boundary | Android arm64/x86_64 and iOS client-only Rust ABI/source shells; SDK/device acceptance next |

The complete dependency and license inventory is in
[`THIRD_PARTY.md`](../THIRD_PARTY.md). The evidence-backed Parsec conclusions
are in [`FACT_CHECK.md`](FACT_CHECK.md); the implementation status is in
[`FEATURE_MATRIX.md`](FEATURE_MATRIX.md).

## 6. Recommended open-source build profiles

For a practical Linux-host product, keep two explicit profiles:

- Native OpenStream: self-hosted signaling, project-owned encrypted transport,
  PipeWire/portal or X11 capture, VAAPI/NVENC/FFmpeg encode, Opus, and uinput.
- Sunshine/Moonlight acceleration: mature host/client media and capture stack,
  isolated as a GameStream-compatible GPL-3.0 profile with corresponding
  source and notices.

Sunshine/Moonlight is not a drop-in BUD implementation. A stock Parsec client
is not a supported OpenStream client unless a separately verified compatibility
backend is completed for a specific build and authorized test account.
