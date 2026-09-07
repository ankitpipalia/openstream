# OpenStream protocol v1 draft

This is the project-owned protocol currently exercised by the reference peer.
It is intentionally separate from Parsec BUD and is not advertised as a
stock-client compatibility format.

## Session establishment

1. An operator/controller calls `POST /v1/session` on the self-hosted
   service. Production deployments set `OPENSTREAM_ADMIN_TOKEN`; the request
   then carries an admin bearer token. Management requests are refused when
   the token is unset unless a loopback-only development server explicitly
   sets `OPENSTREAM_ALLOW_NO_AUTH=1`.
2. The service returns a random session ID, an expiring host capability, and
   an expiring client capability.
3. Each role opens its own WebSocket:
   `/v1/signal/{session_id}/host` or `/client`, sending its role token as an
   `Authorization: Bearer ...` handshake header. Query-string tokens are not
   accepted: putting bearer credentials in a URL exposes them to proxy,
   browser, and access logs.
4. Roles exchange candidate objects through the service. The default direct
   profile uses project-owned candidate objects:

   ```json
   {"type":"candidate","kind":"host","ip":"192.0.2.10","port":45678}
   {"type":"candidate_done","count":2}
   ```

   `kind` can be `host`, `mapped`, `server_reflexive`, or `relay`. With
   `OPENSTREAM_UPNP=1`, `mapped` is obtained by an opt-in SSDP/SOAP
   Internet-Gateway-Device mapping of the same bound UDP port. With a
   configured STUN server, `server_reflexive` is obtained from that same
   bound UDP socket using an RFC 5389 Binding transaction. With
   `OPENSTREAM_RELAY_ENDPOINT` configured, the fourth kind names the
   application-owned UDP relay. The `candidate_done` marker lets each side
   send more than one address without guessing when the list is complete. When
   `OPENSTREAM_ICE=1` or `OPENSTREAM_ICE_URLS` is set, the same role WebSocket
   carries `ice_credentials`, marshalled RFC 8445 candidate strings, and an
   `ice_candidate_done` marker. Candidate priorities, peer-reflexive
   candidates, consent, and TURN allocation are then owned by the ICE agent.

5. Each role generates a fresh X25519 key pair and sends its public key as
   hex in the authenticated signaling channel. The message also carries the
   role's long-lived Ed25519 identity public key and a signature over the
   session ID, role, and ephemeral X25519 public key:

   ```json
   {"type":"key","public_key":"...64 hex characters...","identity_public_key":"...64 hex characters...","signature":"...128 hex characters..."}
   ```

   The identity private key is loaded from `OPENSTREAM_IDENTITY_KEY` (hex) or
   `OPENSTREAM_IDENTITY_KEY_FILE` (raw Ed25519 PKCS#8 or hex text); when
   neither is configured, a process-local identity is generated. Production
   deployments should persist identities in a secret store and pin the
   peer's SHA-256 identity fingerprint with `OPENSTREAM_EXPECT_PEER_IDENTITY`.
   A non-loopback connection fails closed without that pin unless the operator
   explicitly sets `OPENSTREAM_ALLOW_UNAUTHENTICATED_PEER=1` for a lab.

6. Both sides derive the same AES-256-GCM key from the X25519 shared secret
   and a domain-separated, lexicographically ordered public-key transcript.
7. In the default profile, the roles connect UDP sockets to candidate pairs in
   deterministic priority order. Each attempt sends an encrypted path probe
   and requires an encrypted acknowledgement before it is nominated. Host,
   mapped, and server-reflexive candidates are preferred; a configured relay
   is tried last,
   or exclusively when `OPENSTREAM_FORCE_RELAY=1`. The relay validates the role
   token during registration and forwards only opaque encrypted datagrams. In
   the optional full-ICE profile, `webrtc-ice` performs RFC 8445 checks,
   nomination, peer-reflexive discovery, consent freshness, and RFC 5766 TURN
   allocation; the OpenStream AES-GCM envelope remains end-to-end above that
   selected connection.

   UPnP mapping is never implicit because it changes router state. The direct
   client/host path can enable it with `OPENSTREAM_UPNP=1`; the mapping uses
   the session socket's selected UDP port, a bounded lease from
   `OPENSTREAM_UPNP_LEASE_SECONDS` (default 3600), and the description
   `OpenStream`. Callers that own an orderly shutdown can invoke the transport
   `PeerSession::release_upnp` method; routers also expire the lease if the
   process dies.
8. The host sends a versioned capability hello over encrypted control data and
   the client answers with its capabilities. The first intersection selects
   H.264, optional Opus, the smaller width/height/FPS limits, and whether input
   is enabled. A peer with an unsupported capability version or no common
   video codec is rejected before media starts.

The capability payload is JSON inside the authenticated `Kind::Control`
packet, for example:

```json
{"type":"hello","role":"host","capabilities":{"version":1,"video_codecs":["h264","h265"],"audio_codecs":["opus"],"max_width":7680,"max_height":4320,"max_fps":240,"input":true,"video_10_bit":false,"video_444":false,"clipboard":false,"microphone":false,"multi_monitor":false,"pen":false,"rumble":false}}
```

This is only the media contract; it does not grant host privileges. The host
binary decides whether it will create capture/input devices, and the mobile
builds expose client capability only.

The optional boolean capability fields are deliberately explicit and default
to `false` when decoding an older hello. They are intersected between host and
client before use: `video_10_bit` and `video_444` require an end-to-end codec
and renderer path; `clipboard`, `microphone`, `multi_monitor`, and `pen`
require both an implementation and an enabled policy; `rumble` requires a
host feedback source and a client haptic/gamepad sink. A feature is never
enabled merely because a platform could theoretically provide it. This gives
the protocol a safe extension point for the Parsec features identified in the
artifact review without advertising unfinished adapters.

Clipboard text uses `openstream-media::clipboard` chunks inside the reliable
`Kind::Control` channel. The `CB` v1 envelope carries a transfer ID, operation
kind (`text` or `clear`), chunk index/count, and total byte count. Text is
UTF-8 and capped at 64 KiB; each chunk is bounded below the encrypted control
datagram limit; the assembler allows only four in-flight transfers and drops
no platform data by itself. The host/client UI must still gate clipboard
direction, origin, and OS access before applying a completed operation.
The reliable-control window is capped at 64 messages per direction, which is
enough for the largest permitted clipboard transfer while remaining a fixed
memory bound.

### Input and force feedback

Client input uses the fixed 32-byte `OI` envelope described below and is sent
through the bounded reliable control channel. Linux hosts translate gamepad
events into uinput devices. When those devices receive a force-feedback
request, the host sends a fixed 12-byte `OR` rumble envelope back through the
same authenticated control path:

```text
0..1    ASCII OR magic
2       envelope version (1)
3       reserved (zero)
4..7    client device identifier, big-endian u32
8       strong/large motor, u8
9       weak/small motor, u8
10..11  reserved (zero)
```

Desktop clients map the device identifier back to the local gamepad and use
the platform's force-feedback API when available. Android and iOS expose the
same event to their native haptic layer. A zero-strength update stops both
motors. Windows/macOS virtual gamepad host backends are still separate
platform work; unsupported host paths do not silently claim to provide them.

The shared `PeerSession` implementation performs steps 3–7 for both the
headless client and the Linux host adapter and provides the capability
exchange as `negotiate_host`/`negotiate_client`; platform UIs should call it
rather than reimplementing the handshake.

### Pen input

Pen/stylus uses three `OI` kinds on the same reliable control channel:
`PenMotion` (9: absolute output coordinates plus pressure 0–8191 and an
eraser-end flag), `PenButton` (10: tip/barrel index plus press state), and
`PenProximity` (11: hover-range presence). Hosts translate motion/buttons
through their absolute pointer path; pressure and tilt beyond position are
not carried in v1, and proximity is inert by design (it never releases
unrelated held input).

### Microphone passthrough

Guest microphone audio rides the control channel as the native
virtual-device microphone message (opcode 32 with the microphone selector),
not the media audio channel: a 13-byte control header plus a fixed
1932-byte body carrying mono Opus voice (or raw `s16le` verification
frames). Hosts accept it only when the `microphone` capability negotiated
and host policy allows it. The desktop client captures via an external
FFmpeg mono source (`OPENSTREAM_MIC_INPUT`); the native Linux seat takes it
directly, while the FFmpeg host decodes into a verification sink
(`OPENSTREAM_MIC_SINK`). Live OS virtual-microphone routing remains open.

### Multi-monitor topology

Topology rides the reliable control channel as `MD` list messages (up to 16
displays: id, x/y offsets, dimensions, primary flag) with `MS` 8-byte
selection messages back. Hosts enumerate via RandR on Linux (single-display
fallback elsewhere) and advertise when `multi_monitor` negotiated; clients
select at startup with `OPENSTREAM_DISPLAY`. Runtime switching needs a host
restart and is acknowledged as such.

### Guest sessions and TURN credentials

The signaling service admits guests beyond the legacy client token:
host-minted guest bearer tokens with input tiers
(`POST /v1/session/{id}/guests`), redacted listing, and kick by the returned
non-secret `guest_id` (`DELETE /v1/session/{id}/guests/{guest_id}`) with prompt
close. The guest bearer token is returned only in the create response and is
sent in the WebSocket `Authorization` header, never in a management URL. Media stays 1:1 — the first connected guest with no legacy client
attached goes active while the rest park with promotion on disconnect; the
active guest may use the relay under the client role. Session-scoped TURN
credentials come from `GET /v1/session/{id}/turn` (TURN REST HMAC-SHA1 over
`expiry:session:role`) and are embedded in pairing JSON by the provisioning
scripts; explicit `OPENSTREAM_TURN_*` variables still win when set.

### Diagnostics

After establishment, `PeerSession::connection_path()` exposes only the
selected path family for UI/telemetry: direct UDP with a host,
server-reflexive, or opaque-relay candidate, or the full ICE path.
`PeerSession::stats()` also exposes bounded local sent/received packet and
byte counters. Host and FFmpeg adapters log these values alongside the
negotiated codec, dimensions, FPS, audio choice, and input policy. The
diagnostic values deliberately omit peer addresses, pairing tokens, TURN
credentials, and session keys.

## Encrypted datagram layout

Every datagram is at most 1200 bytes in the initial profile. The 16-byte
header is authenticated as AES-GCM associated data and is followed by the
ciphertext and a 16-byte tag.

| Bytes | Field | Encoding |
|---:|---|---|
| 0..2 | magic | ASCII `OS` |
| 2 | version | `1` |
| 3 | kind | `1` control, `2` video, `3` audio, `4` input |
| 4 | channel | application-defined stream ID |
| 5 | flags | application-defined flags |
| 6..14 | counter | unsigned 64-bit big-endian |
| 14..16 | plaintext length | unsigned 16-bit big-endian |
| 16.. | ciphertext | AES-GCM in-place encryption |
| final 16 | tag | AES-GCM detached tag |

The nonce is twelve bytes: four zero bytes followed by the eight-byte packet
counter. A sender counter is never reused for a session. A receiver keeps a
64-packet sliding replay window, accepts bounded reordering, rejects duplicate
counters, and rejects packets older than the window. Length checks happen
before allocating plaintext storage.

The code is in
[`engine/lowlat/crates/protocol`](../engine/lowlat/crates/protocol), with the
socket wrapper in
[`engine/lowlat/crates/transport`](../engine/lowlat/crates/transport).

The client-only native mobile bridge is in
[`engine/lowlat/crates/mobile-ffi`](../engine/lowlat/crates/mobile-ffi), with
the public ABI at
[`include/openstream_client.h`](../include/openstream_client.h). It carries
the same video access units, decoded Opus audio, and input messages as the
desktop client without exposing host capture or injection capabilities.

Encoded video is packetized by
[`engine/lowlat/crates/media`](../engine/lowlat/crates/media). It uses a
20-byte inner fragment header with frame ID, fragment index/count, presentation
timestamp, and keyframe bit. The reassembler has explicit frame-size and
in-flight-frame bounds and evicts the oldest incomplete frame when full.
The same crate now defines a bounded Opus-oriented audio access-unit header
and sequence-aware jitter queue; missing sequences are surfaced for decoder
packet-loss concealment rather than filled with unbounded buffering.

The protocol crate contains an ordered control envelope and bounded
cumulative-acknowledgement state in
[`engine/lowlat/crates/protocol/src/lib.rs`](../engine/lowlat/crates/protocol/src/lib.rs).
It supports out-of-order buffering, duplicate suppression, retransmission of
the oldest outstanding message, and a bounded send window. The reusable
`ReliableControl` helper in `openstream-client-core` now drives it from the
desktop and mobile event loops for keyframe requests, frame acknowledgements,
session end, and mobile input state. The Linux host accepts those ordered
input payloads when input is explicitly enabled. The headless client's
`OPENSTREAM_TEST_INPUT` switch remains a raw compatibility/test path. New
front ends should use the fixed 32-byte versioned `OI` input envelope from
`openstream-media`; it covers keyboard usages, relative/absolute pointer
motion, mouse buttons, wheel, gamepad buttons/axes, gamepad unplug, and
focus-loss release.
The native Linux host translates it into the imported lowlat control
representation only at the `/dev/uinput` boundary. The portable FFmpeg host
uses the same authenticated envelope with native Windows `SendInput` and
macOS CoreGraphics translations. Absolute-input extent is taken from the
negotiated stream dimensions, so a client requesting a scaled mode does not
map pointer coordinates against the host's 1920×1080 default.

The `OI` envelope is deliberately fixed-width:

| Bytes | Field |
|---:|---|
| 0..2 | ASCII `OI` magic |
| 2 | version `1` |
| 3 | event kind |
| 4..6 | flags; bit 0 means relative pointer motion |
| 6..10 | device/pad identifier |
| 10..14 | HID usage, mouse button, or gamepad axis/button code |
| 14..18 | signed value |
| 18..22 | signed second value |
| 22..30 | client timestamp in microseconds |
| 30..32 | reserved zero bytes |

Event kind `8` is gamepad unplug; its `device/pad identifier` selects the
previously announced pad and all other payload fields are zero. This keeps
device removal explicit without making a disconnected pad look like a held
state.

Keyboard `code` is a HID usage and `flags` carries lock/modifier state;
pointer values are pixels or deltas; gamepad axes use signed 16-bit units.
Unknown kinds, versions, lengths, or non-zero reserved bytes are rejected.

The control window is intentionally bounded. Strict controls such as input,
keyframe requests, and session end return an error when the peer is not
draining acknowledgements. A video frame acknowledgement is redundant and is
sent through the non-blocking capacity-aware helper; when the window is full,
that individual ACK may be skipped because a later ACK supersedes it.

### Video acknowledgement and adaptive bitrate

After a client has assembled a complete frame and accepted it for decoding,
it sends an `FA` frame acknowledgement through the same authenticated,
ordered control channel. The twelve-byte payload is:

| Bytes | Field |
|---:|---|
| 0..2 | ASCII `FA` magic |
| 2 | envelope version `1` |
| 3 | reserved zero byte |
| 4..8 | assembled frame ID, big-endian `u32` |
| 8..10 | client-observed missing frame count, big-endian `u16` |
| 10..12 | reserved zero bytes |

The ACK contains no client clock, address, token, or media bytes. The native
Linux host records its own send time for each frame in a 64-entry bounded
window. `openstream-media::AdaptiveBitrate` lowers the live bitrate ceiling
when that window backs up, an ACK becomes too old, or the client reports
missing frame IDs. It ramps up only after a quiet period and cannot move outside the
configured floor/ceiling or reconfigure more often than the bounded interval.
The Linux adapter applies decisions through lowlat's live-video reconfigure
path. The external FFmpeg adapter applies significant decisions as bounded
rolling restarts behind `OPENSTREAM_FFMPEG_RECONFIGURE=restart`
(the replacement encoder starts with an IDR frame); the default stays
fixed-rate because an arbitrary FFmpeg process has no portable in-place
rate-control ABI.

This is OpenStream feedback, not a claim that the proprietary Parsec BUD
controller has been reproduced. The controller is a queue/loss policy above
the encrypted transport; it does not expose peer addresses or credentials.

## Current limitations

This is a working development streaming stack, not yet a finished product:

- native GPU capture/encode/render adapters remain open on all three desktop
  OSes; the FFmpeg external path (x11grab/PipeWire/GDI/AVFoundation,
  libx264/x265 plus NVENC/VAAPI profiles, 8-bit 4:2:0 with opt-in 10-bit and
  4:4:4) is implemented and tested, with native X11/PipeWire discovery wired
  into the Linux host;
- desktop presentation is software (validated BGRA, paced re-presents,
  windowed/borderless/fullscreen modes, hotkeys); D3D11/Metal/Vulkan upload
  paths remain open;
- mobile shells need on-device acceptance and signed packaging; lifecycle,
  thermal shedding, and the host-checkable harness are implemented;
- multi-guest media fan-out to N simultaneous guests remains open; admission,
  parking, permissions record, kick, and guest listing are implemented;
- STUN/direct/relay/coturn paths are implemented with session-scoped TURN
  credentials; the external coturn live run and public-NAT matrix remain open;
- key exchange is authenticated by both the role-scoped service channel and a
  signed Ed25519 identity binding; a user-facing host approval UI beyond the
  `owner` approval mode flag is still open.

Those are explicit implementation items, not hidden assumptions. The target
media profile is H.264/H.265 8-bit 4:2:0 plus Opus 48 kHz; platform capture,
hardware encode/decode, presentation, and input adapters remain outside this
crate.
