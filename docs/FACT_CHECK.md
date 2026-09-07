# Parsec analysis fact check

Updated 2026-09-07. This document separates observations from the supplied
artifacts, statements made by Parsec, and hypotheses from independent projects.

## Verdict summary

| Claim | Verdict | Evidence |
|---|---|---|
| API uses TCP/HTTPS and signaling uses WebSocket | Confirmed | Native strings, libmatoya sources, and Parsec connectivity documentation |
| STUN is used for public address discovery | Confirmed | Native strings and Parsec connection-sequence documentation |
| Native media transport is BUD over UDP | Confirmed at the architectural level | Parsec's BUD blog and native `bud_*`/UDP symbols |
| BUD has reliability and custom congestion control | Confirmed at a high level | Parsec's BUD blog |
| BUD uses DTLS 1.2 and AES-GCM | Confirmed at a high level | Parsec technology and BUD documentation |
| Native clients use WebRTC DataChannels | Not supported | Parsec says native clients use BUD; WebRTC DataChannels describe the browser path |
| Exact 29-byte BUD envelope, magic, nonce, ACK layout, opcodes, and constants | Provisional | Specified by the independent `nomi-san/lowlat` project; not published by Parsec and not fully proven by static inspection of this payload |
| Linux payload advertises hosting capability | False | Disassembly at Linux payload offset `0x2b6fe` passes `false` into the `hosting_supported` serializer |
| Linux payload contains shared hosting scaffolding | Confirmed | `hosting_*`, `host_*`, session, and server configuration strings plus host startup code |
| Launcher verifies/loads a versioned payload | Confirmed | Supplied `appdata.json` contains `so_name`, `entry_symbol`, and matching hash; launcher strings contain `dlopen`, `dlsym`, and hash/lock handling; Linux dynamic exports are `wx_main` and `console_main` |
| Linux payload is fully stripped | False/overstated | `file` reports the inspected ELF as “not stripped”; its dynamic ABI still exposes only the two defined entry symbols |
| Linux payload contains a production Linux capture/encoder backend | Not shown | No PipeWire, Wayland, VAAPI-encode, NVENC, V4L2, or capture-backend evidence was found; this is negative evidence, not a proof of absence |
| Android package is client-only | Confirmed | Official Android documentation and the supplied XAPK manifest |
| Parsec supports iOS clients | False for the inspected/current product | Current Parsec compatibility documentation says iOS/iPad are unsupported |
| `nomi-san/lowlat` is already a finished cross-platform product | False | Its current repository contains substantial implementation, but still has unchecked phases and is Linux-primary; this workspace's imported copy now passes its macOS tests after portability patches |
| Sunshine/Moonlight is a practical open-source functional-clone route | Confirmed with caveats | Current Sunshine and Moonlight repositories document the host/client split and GPL-3.0 licensing; macOS/Windows-ARM feature support remains platform-specific/experimental |

## Web revalidation

The official pages were rechecked on 2026-09-07 against the supplied texts and
the local artifacts. The current compatibility page says that joining is
supported from Windows, Linux, macOS, and Android, while hosting is only
available on Windows and macOS and Ubuntu hosting is unsupported. The current
connectivity page specifies TCP/443 for backend/WebSocket/API traffic, UDP/3478
for STUN, and encrypted peer-to-peer UDP, with relay fallback. The BUD article
still describes BUD as proprietary UDP protected by DTLS 1.2 via OpenSSL with
reliability semantics and custom congestion control. The browser article still
separates browser RTCDataChannels/SCTP/DTLS/UDP from native BUD. These public
claims corroborate the high-level architecture; they do not prove the
provisional byte-level BUD reconstruction.

The same recheck makes the relay wording more precise. Parsec's connection
sequence describes UPnP plus simultaneous UDP hole punching using STUN as the
default path, while the connectivity requirements describe an enterprise
Parsec Relay that accepts client UDP and forwards it to the host. The public
pages do not identify that relay as a standards-compliant TURN allocation, so
the report uses "relay" unless a separate authorized capture proves TURN
semantics. The compatibility page also says a host must have a hardware video
encoder and a display connected to the appropriate GPU; a software-only
fallback is therefore not equivalent to Parsec's supported host path.

OpenStream now has an intentionally explicit equivalent: `OPENSTREAM_UPNP=1`
performs bounded SSDP/SOAP IGD discovery and maps the already-bound UDP port.
It is opt-in because enabling UPnP changes router state; physical-router and
public-NAT acceptance remain a separate test gate.

The BUD article also gives the performance policy that the implementation must
match behaviorally: latency is prioritized before frame rate, and frame rate
before video quality; video is intentionally not buffered, and congestion is
handled by observing network metrics and changing encoder bitrate before a
queue turns into latency. The connectivity requirements say that direct P2P
operation does not support double NAT or CGNAT, while relay operation bypasses
that restriction, and their 1080p60 guidance is roughly 30 Mbps host upload,
30 Mbps client download, and 2 Mbps client upload. These are public product
targets, not measurements of the supplied binary and not a promise that every
network or GPU meets them.

## Local artifact facts

The inspected native artifacts are:

- Linux: `150-104a`, ELF x86-64 shared object, SHA-256
  `708bc4e7194333dd16da64ae1c822dd973d0f647b39588351ea2b226bac09a07`.
- Windows: `150-104a`, PE x86-64 DLL, SHA-256
  `8c8c4299ddf503b2c25c0905b0a0820f3e8238c252e9ace37bf25964ef4a8f6f`.
- macOS: `150.101.1`, x86-64 and arm64 payloads.
- Android: XAPK `3.150.097.05`, `min_sdk_version=28`, `target_sdk_version=34`,
  only the `config.arm64_v8a` split is supplied.

The Linux `hosting_supported` code path was re-disassembled with radare2:

```text
0x0002b6fe  xor edi, edi
0x0002b703  call 0x90070
0x0002b708  lea rsi, str.hosting_supported
0x0002b70f  mov rdi, r12
0x0002b712  mov rdx, rax
0x0002b715  call 0x90580
```

The helper at `0x90070` serializes its Boolean argument. The zeroing of `edi`
therefore makes the Linux capability explicitly false.

The native Linux object includes `EVP_aes_128_gcm`, `EVP_aes_256_gcm`,
`DTLS_method`, userspace SCTP sources, MiniUPnPc sources, Opus 1.1.3, and
`bud_*`/`nat_*` symbols. It also has FFmpeg decoder entry points. The supplied
payload did not contain a contiguous `17 FE FD` byte run, so the exact record
magic from the lowlat document is not marked as locally confirmed here; it may
be constructed at runtime or belong to a different generation.

## How to use the lowlat material

`nomi-san/lowlat` is independent MIT-licensed clean-room work. Its current
repository contains Rust implementation crates and protocol tests, and its
README describes stock-client interoperability as the target. Its protocol
documents are useful engineering evidence, but they are not Parsec source or
an official Parsec specification. We must preserve that distinction in code,
documentation, and release notes.

Before the portability patches, `cargo test --workspace` against the lowlat
checkout failed on this Apple target because `lowlat-common` used Unix
`clock_nanosleep` and `TIMER_ABSTIME`, which are not exposed by the current
Apple `libc` target. The imported copy now gates that implementation and the
Linux-only host/fixture modules correctly: its full workspace test suite
passes locally on macOS. This does not prove Windows, Linux hardware, or
mobile builds; those still require target-specific CI and devices.

## Sources

- [Parsec connectivity requirements](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements)
- [Parsec connection sequence](https://support.parsec.app/hc/en-us/articles/32361410290324-Components-and-Connection-Sequence)
- [Parsec BUD protocol article](https://parsec.app/blog/a-networking-protocol-built-for-the-lowest-latency-interactive-game-streaming-1fd5a03a6007)
- [Parsec browser networking article](https://parsec.app/blog/game-streaming-tech-in-the-browser-with-parsec-5b70d0f359bc)
- [Parsec technology overview](https://parsec.app/technology)
- [Parsec hardware/software compatibility](https://support.parsec.app/hc/en-us/articles/32381568346644-Hardware-and-Software-Compatibility)
- [Parsec Linux installation](https://support.parsec.app/hc/en-us/articles/32381552552340-Install-Parsec-App-on-Linux)
- [Parsec Android documentation](https://support.parsec.app/hc/en-us/articles/32381582866452-Install-Parsec-App-on-Android)
- [Independent lowlat repository](https://github.com/nomi-san/lowlat)
- [Independent lowlat protocol specification](https://github.com/nomi-san/lowlat/blob/main/docs/01-protocol.md)
- [Sunshine](https://github.com/LizardByte/Sunshine)
- [Moonlight Qt](https://github.com/moonlight-stream/moonlight-qt)
- [Moonlight Android](https://github.com/moonlight-stream/moonlight-android)
- [Moonlight iOS](https://github.com/moonlight-stream/moonlight-ios)
