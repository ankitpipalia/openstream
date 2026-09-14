# OpenStream 1.0 hardware and WAN acceptance matrix

This is an evidence ledger, not a claim that the gates have passed. Each
`PASS` row must link to an operator-owned log, capture hash, or CI artifact
that can be reviewed independently. Do not put pairing JSON, TURN passwords,
relay tickets, private keys, or input values in the linked evidence.

The release checker is:

```sh
scripts/wan-acceptance.sh --check
scripts/network-fault-matrix.sh --check-report docs/acceptance/OPENSTREAM_1_0_HARDWARE_WAN_MATRIX.md
```

`UNVERIFIED` is intentionally the initial state. A release cannot be called
production-ready 1.0 while any required row remains unverified.

## Physical hardware gate

| case | status | evidence | notes |
| --- | --- | --- | --- |
| linux-nvidia-to-apple-silicon | PARTIAL | 2026-09-15, see "Run of 2026-09-15" below | Video, keyboard, absolute pointer, audio, and clean disconnect all confirmed. Raw pointer capture has since been implemented for macOS and verified: a 1750 px sweep across a 1280 px window is delivered, where the clamped path stopped at the edge. One case still blocks the row: the macOS window cannot go borderless, because minifb 0.27 implements that option for Wayland, X11 and Windows but not for macOS, where it is silently dropped. Note the capture path was the xdg-desktop-portal PipeWire node, not X11: Xwayland is rootless, so x11grab on this host captures nothing |
| apple-silicon-videotoolbox-metal | PARTIAL | 2026-09-15, see "Run of 2026-09-15" below | Metal presentation confirmed, and the FFmpeg decode fallback with it. VideoToolbox decode is still not wired up, so the decoder half of this row is unproven |
| input-release-watchdog | UNVERIFIED |  | focus loss, close, network loss, and permission revocation release every held key/button |
| background-host-restart | UNVERIFIED |  | host agent survives UI exit and restarts without two children |

## Network gate

| case | status | evidence | notes |
| --- | --- | --- | --- |
| direct-udp | PASS | 2026-09-15, see "Run of 2026-09-15" below | Authenticated role-scoped pairing over DirectUdp { candidate: Host }; media and control both flowed, 0.0% loss reported by the client |
| turn-relay | UNVERIFIED |  | coturn path with credentials redacted from evidence |
| application-relay | UNVERIFIED |  | OpenStream relay path and generation-scoped migration |
| ipv4-double-nat | UNVERIFIED |  | discovery and selected path recorded |
| ipv6 | UNVERIFIED |  | direct or relay selection recorded |
| symmetric-nat | UNVERIFIED |  | TURN or application relay selected |
| loss-jitter | UNVERIFIED |  | 5% loss and 30 ms jitter do not create unbounded queues |
| bandwidth-limit | UNVERIFIED |  | constrained egress remains bounded and recovers |
| wifi-ethernet-roam | UNVERIFIED |  | path migration preserves the authenticated session |
| router-restart | UNVERIFIED |  | reconnect is explicit and input state is released |

## Run of 2026-09-15

One session between a SteamOS/NVIDIA host at 192.168.1.69 and an
Apple-Silicon macOS client on the same LAN, signalling over an SSH-forwarded
loopback port. Every claim below was read off pixels or a captured sample,
not off a counter: the client's own telemetry reported frames decoded and
presented during an earlier run whose screen was blank, so counters are not
accepted here as evidence of a picture.

Method. The host desktop was given a recognisable moving picture (SMPTE bars
with a running elapsed counter and a wall clock) so that a correct frame and
a stale frame could be told apart. Frames were then sampled at three points:
the PipeWire node, the client's presenter (`OPENSTREAM_DUMP_FRAMES`), and the
macOS screen itself (`screencapture`).

| observation | result |
| --- | --- |
| host capture | Real desktop pixels from the portal ScreenCast node, 2560x1440 scaled to 1920x1080 at 30 fps |
| encode | h264_nvenc, 8 Mbps, 60 fps steady, 0 stalls over 17,992 frames |
| client decode | Pixel-accurate copy of the host desktop, colours correct |
| freshness | Wall clock inside a decoded frame matched the macOS menu bar clock to the second |
| keyboard | 13 synthesised key codes produced exactly "openstream ok" in a remote editor, confirmed by reading the text out of the decoded frame and by the editor's own column counter reaching 1:14 |
| pointer | Absolute motion moved the remote cursor into the editor; a click took focus there |
| audio | Host test tone recovered from the client's decoded PCM at 440 Hz, matching the source |
| presentation | Metal presented 45.6 fps with a 2.2 ms mean present call, against 32.1 fps and 9.3 ms for the software path |
| disconnect | Both ends ran their shutdown reporting to completion; no error path, no orphaned child |

Not established by this run: VideoToolbox decode, borderless or exclusive
fullscreen on macOS, and every WAN row other than `direct-udp`. Raw pointer
capture was not part of this run but has since been implemented and verified
separately, as noted in the physical row above.

## Release policy

The current repository has loopback and application-owned relay smoke tests,
but those are not substitutes for the rows above. If hardware, WAN, signing,
or notarization evidence is unavailable, publish a development build or a
release candidate with the exact missing gates listed; do not label it
OpenStream 1.0 production-ready.
