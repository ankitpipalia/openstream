# OpenStream Windows client test plan

## Scope (what is and is not testable on Windows today)

**Testable now: a Windows *client* against a Linux host.** The desktop streaming
client compiles and runs on Windows, presents through wgpu (Direct3D 12, with a
software fallback), and takes keyboard/mouse input.

**Not testable: Windows *hosting*.** The host agent is Unix-only — its
`main` is `#[cfg(not(unix))]` and exits with "OpenStream host agent requires a
Unix local IPC platform". Windows hosting needs a named-pipe IPC supervisor,
Windows Graphics Capture / DXGI, `SendInput`, and a service; that is post-1.0
work. Do not expect to host from Windows.

So the interoperability matrix for this round is:

| Client | Host | Status |
| --- | --- | --- |
| Windows x86_64 | Linux/NVIDIA (the rig) | the target of this plan |
| Windows | Windows | not supported (host agent exits) |

## Prerequisites on the Windows machine

1. **ffmpeg on PATH.** The client shells out to `ffmpeg` for H.264 decode. Install
   a static Windows ffmpeg build and put `ffmpeg.exe` on `PATH`, or set
   `OPENSTREAM_FFMPEG=C:\path\to\ffmpeg.exe`. Without it the client connects but
   presents nothing.
2. **A GPU with Direct3D 12**, or force the software presenter with
   `OPENSTREAM_RENDERER=software` (higher CPU, still correct).
3. Outbound network to `signal.ankitpipalia.site` (443) and UDP to the host /
   TURN server.

## Getting the client binary

`openstream-desktop-client.exe` is built by the `release-artifacts` workflow's
**Windows x86_64 client (test build)** job and uploaded as the
`windows-x86_64-client` artifact. Download it from the workflow run and place it
in a working folder. (This is the CLI streaming client — the same binary used for
the LAN/WAN/relay tests, not the Tauri product shell, which is a separate build.)

## Pairing

A session mints one host pairing and one client pairing. The host side runs on
the rig; the client side runs on Windows. Write the client pairing JSON to a
file, e.g. `client.json`, readable only by you.

## Running the client (PowerShell)

```powershell
$env:OPENSTREAM_SIGNAL_ORIGIN   = "https://signal.ankitpipalia.site"
$env:OPENSTREAM_PAIRING_FILE    = "C:\openstream\client.json"
$env:OPENSTREAM_EXPECT_PEER_IDENTITY = "<host device identity, 64 hex>"
$env:OPENSTREAM_VIDEO_CODEC     = "h264"
# Full ICE + TURN (relay fallback) — omit for the direct/STUN path:
$env:OPENSTREAM_ICE             = "1"
$env:OPENSTREAM_ICE_URLS        = "turn:<turn-host>:3478?transport=udp"
$env:OPENSTREAM_TURN_USERNAME   = "<user>"
$env:OPENSTREAM_TURN_PASSWORD   = "<pass>"
# Optional: force the software presenter if the GPU path misbehaves
# $env:OPENSTREAM_RENDERER      = "software"
.\openstream-desktop-client.exe
```

Mutual peer-identity pinning is mandatory off-loopback, so
`OPENSTREAM_EXPECT_PEER_IDENTITY` must be the host's identity and the host must
pin the client's.

## What to verify

- **Establish:** the client logs `run path=Ice` (or `DirectUdp`) and the peer
  identity fingerprint matches the host.
- **Video:** the host desktop renders; colours correct; no persistent stalls.
- **Freshness/latency:** motion tracks with acceptable latency for the link.
- **Input:** keyboard and mouse reach the Linux host (if the host granted input).
- **Sustained:** runs for minutes without a control-window teardown (the fix in
  this candidate); the client should not die shortly after connecting.
- **Disconnect:** closing the client releases input and ends cleanly.

## Known limitations to expect (not bugs for this round)

- No Windows hosting (above).
- **TURN over TCP/TLS (443) is not available** — `webrtc-ice 0.17.2` implements
  only TURN over UDP. A network that blocks all UDP cannot fall back to a relay.
  TURN over UDP does work for symmetric NATs that allow UDP to the relay.
- Decode is ffmpeg software decode; there is no hardware decode straight into a
  Direct3D texture yet, so CPU use is higher than a native path would be.
