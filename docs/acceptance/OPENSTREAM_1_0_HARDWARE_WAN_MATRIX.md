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
| linux-nvidia-to-apple-silicon | UNVERIFIED |  | Linux x86-64 NVIDIA X11 → FFmpeg → NVENC to Apple-Silicon macOS client; keyboard, raw mouse, audio, fullscreen, and clean disconnect required |
| apple-silicon-videotoolbox-metal | UNVERIFIED |  | VideoToolbox decode and Metal presentation, with FFmpeg fallback evidence |
| input-release-watchdog | UNVERIFIED |  | focus loss, close, network loss, and permission revocation release every held key/button |
| background-host-restart | UNVERIFIED |  | host agent survives UI exit and restarts without two children |

## Network gate

| case | status | evidence | notes |
| --- | --- | --- | --- |
| direct-udp | UNVERIFIED |  | authenticated direct path and media/control traffic |
| turn-relay | UNVERIFIED |  | coturn path with credentials redacted from evidence |
| application-relay | UNVERIFIED |  | OpenStream relay path and generation-scoped migration |
| ipv4-double-nat | UNVERIFIED |  | discovery and selected path recorded |
| ipv6 | UNVERIFIED |  | direct or relay selection recorded |
| symmetric-nat | UNVERIFIED |  | TURN or application relay selected |
| loss-jitter | UNVERIFIED |  | 5% loss and 30 ms jitter do not create unbounded queues |
| bandwidth-limit | UNVERIFIED |  | constrained egress remains bounded and recovers |
| wifi-ethernet-roam | UNVERIFIED |  | path migration preserves the authenticated session |
| router-restart | UNVERIFIED |  | reconnect is explicit and input state is released |

## Release policy

The current repository has loopback and application-owned relay smoke tests,
but those are not substitutes for the rows above. If hardware, WAN, signing,
or notarization evidence is unavailable, publish a development build or a
release candidate with the exact missing gates listed; do not label it
OpenStream 1.0 production-ready.
