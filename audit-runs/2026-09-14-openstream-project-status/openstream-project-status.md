# OpenStream — Complete Project Status and 1.0 Readiness Audit

Audit date: 2026-09-14  
Audited source: `cac3b2fd363da00417a79da682bcc1f0299cdb87`  
Repository: `ankitpipalia/openstream`

## 1. Executive summary

OpenStream is a credible low-latency remote-streaming engineering foundation,
not yet an installable or supportable 1.0 product.

What is real today:

- authenticated, encrypted direct UDP with bounded replay protection;
- a project-owned candidate path plus standards-based ICE/STUN/TURN support;
- an authenticated application relay fallback;
- portable packet scheduling, ACK-based delivery estimation, congestion policy,
  bounded media/control queues, frame ACKs, liveness, and reconnect logic;
- Linux native-host foundations and cross-platform FFmpeg host adapters;
- desktop and mobile client implementations at different maturity levels;
- a persistent Linux host supervisor, settings v2, product domain model,
  Tauri/React shell, diagnostics, and unusually broad CI;
- one physically exercised path: Linux/NVIDIA to Apple-Silicon macOS over LAN,
  using the fallback capture/encode and FFmpeg/BGRA client path.

What is not real yet as a complete product:

- clicking Connect in the product shell does not create a network session or
  launch a native session window;
- there is no durable account/device directory, enrollment, presence, trusted
  device policy, refresh credential, or secure OS key store;
- the full ICE/TURN handshake does not have direct-v2's startup-order epochs;
- the tested Linux Wayland/NVIDIA machine does not have a release-accepted
  desktop capture path;
- desktop macOS has no VideoToolbox-to-IOSurface/Metal zero-copy decoder;
- raw/immersive mouse input, physical input safety acceptance, and audio
  acceptance are missing;
- all public-WAN, NAT, external TURN, roaming, and router-restart cases remain
  unverified;
- no production release artifacts, SBOM, signing/notarization evidence,
  signed updater, or package upgrade/rollback evidence exist.

The current defensible latency result is approximately 220–240 ms P50 on one
LAN rig, not Parsec-class latency. The newly corrected stage instrumentation has
not yet been rerun on that rig.

**Readiness: NO-GO.** Passing CI demonstrates source quality and portability;
it does not bridge the product, hardware, WAN, or release-evidence gaps.

## 2. Exact repository and GitHub state

The audit began from a clean checkout. The only later working-tree additions
are this audit's `audit-runs/` artifacts.

| Item | Exact state |
|---|---|
| Current branch | `main` |
| `HEAD` | `cac3b2fd363da00417a79da682bcc1f0299cdb87` |
| `origin/main` | same |
| Merge base | same |
| Initial working tree | clean, `## main...origin/main` |
| Latest commit | `perf: stage-level latency instrumentation, frame-age counters, and an interaction probe (#18)` |
| Open PRs | 0 |
| Latest PR | #18, merged |
| Post-merge CI | run `34816872196`, success, 27/27 jobs |
| Branch protection | strict, required check `CI gate` |
| Tags/releases | none |
| Product version | `1.0.0-dev`; Rust crates mostly `0.1.0`/`0.0.0` |

One stale local and remote branch remains:
`perf/latency-instrumentation` at `f81e19d`. It has squash-merge ancestry, but
its tree is exactly equal to `cac3b2f`; it contains no unlanded file change and
can be deleted after this audit. See `evidence/repository-state.md`.

The workspace contains 685 tracked files, 216 Rust files, roughly 158,020 Rust
lines under the crate tree, and 33 Cargo packages.

## 3. Product scope and assumptions

The eventual three-host/five-client platform goal is architecturally valid,
but it is not the current release scope. The smallest defensible first release
remains:

- Linux x86-64/NVIDIA host;
- a reliable X11 or Wayland/PipeWire capture path and NVENC H.264, with H.265
  only where runtime probing succeeds;
- Apple-Silicon macOS client with native VideoToolbox/Metal and FFmpeg fallback;
- keyboard, mouse, wheel, Opus audio, one selected display;
- direct UDP first, full ICE/TURN and application-relay fallback;
- background host agent and self-hostable control plane;
- signed/notarized packages and an evidence-backed release process.

Windows/macOS hosting and polished mobile clients should remain post-1.0 unless
the project deliberately expands the release contract. Compilation alone must
not change this scope.

## 4. Current architecture overview

```text
Tauri/React product shell
        │ settings + AppModel + host lifecycle
        ▼
desktop Rust runtime ── Unix IPC ── host agent ── FFmpeg/native host
        │                                      capture/encode/input/audio
        │ (session launch missing)
        ▼
engineering desktop/mobile client
        │
        ▼
PeerSession
├── WebSocket signaling
├── direct candidate path or ICE/STUN/TURN
├── X25519 + Ed25519-authenticated key exchange
├── AES-256-GCM datagrams + replay window
├── packet scheduler/delivery ACK/pacer
├── reliable logical control + frame ACK
├── path generations/migration/liveness
└── UDP / application relay / ICE Conn
```

The crate boundaries are coherent. `lowlat-core` is sans-I/O; the common
`openstream-transport-policy` crate owns deterministic policy; portable
`PeerSession` owns async transport; platform crates own OS APIs. Unsafe code is
concentrated in VAAPI/NVENC/CUDA/Vulkan and OS FFI, which is a reasonable
boundary but requires physical validation.

The major break is above the engine. Tauri can read/update settings and start
or stop the host agent, but a Connect command currently updates only
`AppModel`. `desktop/src-tauri/src/runtime.rs:273-278` says the session runner
does not exist; `desktop-client/src/session.rs:1-6` says it is only a lifecycle
seam. React must remain a control UI; media must go directly through a native
session process/window.

## 5. Middle-server versus peer-to-peer data flow

### Direct path

1. `POST /v1/session` creates an in-memory session and random host/client role
   capabilities (`signal-server/src/main.rs:1126-1171`).
2. Each role opens an Authorization-header-authenticated WebSocket.
3. The server publishes `peer_ready(N)` only to the current host/client socket
   pair. Direct candidates and signed ephemeral keys carry N.
4. The peers probe candidates with authenticated OpenStream datagrams.
5. Media, audio, input, ACKs, and logical control travel directly over the
   selected UDP socket.

The WebSocket remains alive for control, migration signaling, ping/idle
detection, and revocation. It is not carrying steady-state media.

### Full ICE/TURN path

`PeerSession::establish_with_ice` exchanges ICE credentials/candidates over the
WebSocket, then `webrtc-ice` performs checks, nomination, keepalives, consent
freshness, and TURN allocation (`client-core/src/lib.rs:2306-2315`). OpenStream
AES-GCM packets pass over the selected ICE `Conn`; ICE does not replace
OpenStream's end-to-end encryption.

If ICE selects a host/server-reflexive/peer-reflexive pair, steady-state media
is P2P. If it selects TURN, TURN remains in the media path and adds relay cost
and latency, as TURN inherently does.[^rfc8656]

### Application relay

The signaling process also owns an opaque UDP relay
(`signal-server/src/main.rs:2841-2850`). Relay registration uses a scoped HMAC
ticket, not the WebSocket bearer. The relay forwards encrypted datagrams and
cannot read media, but it remains in the media path while selected. Per-slot
limits are 8 MiB/s and 10,000 packets/s.

### Verdict

The implementation does **not** assume direct P2P always works: TURN and an
application relay exist. It also does **not** make the middle server disappear
universally. Successful direct media bypasses it; control remains connected;
relayed media necessarily traverses helper infrastructure.

## 6. Authentication and trust status

### Implemented

- X25519 ephemeral agreement and direction-separated AES-256-GCM keys;
- Ed25519 signatures over key-exchange transcripts;
- session and sender-role transcript binding; direct-v2 additionally binds the
  establishment generation;
- expected-peer identity pinning for remote origins unless an explicit unsafe
  override is used;
- 64-counter anti-replay window and authenticated outer counters;
- expiring role capabilities, TURN credentials, and relay tickets;
- role credentials in headers, not WebSocket URLs;
- secure pairing-file loader with size, symlink, ownership, and permission
  checks (`client-core/src/lib.rs:632-703`).

### Missing or incomplete

- The server authenticates an administrator capability and ephemeral session
  roles; it does not authenticate users or enrolled devices.
- `AppModel` has device/trust concepts, but no persistent service drives them.
- `SecretRef` exists, but Keychain, DPAPI/Credential Manager, and Secret Service
  implementations do not.
- `local_identity()` reads an environment value or plain file and generates a
  fresh identity if neither exists (`client-core/src/lib.rs:4078-4101`). The
  identity-file path does not use the hardened pairing-file loader.
- No MFA/passkey/recovery, device revocation propagation, durable audit log, or
  server-backed trusted-device policy exists.

The cryptographic session is strong. The product trust system is missing.
Parsec's publicly documented account/MFA and backend-validated peer flow is a
useful product reference, not evidence about proprietary internals.[^parsec-security]

## 7. Full host/client platform matrix

Abbreviations: BO = build-only; IT = integration tested; PT = physically
tested. “Transport implemented” means common source exists, not that the
combination has been exercised.

| Host → Client | Capture | Encode | Transport | Decode/render | Input | Audio | Permissions | Packaging | Test evidence |
|---|---|---|---|---|---|---|---|---|---|
| Windows → Windows | gdigrab partial | FFmpeg profiles | Implemented | FFmpeg/BGRA + wgpu | basic SendInput | Opus source | partial | missing | BO |
| Windows → Linux | gdigrab partial | FFmpeg profiles | Implemented | FFmpeg/BGRA + wgpu | basic SendInput | Opus source | partial | missing | BO |
| Windows → macOS | gdigrab partial | FFmpeg profiles | Implemented | FFmpeg/BGRA + Metal upload | basic SendInput | Opus source | partial | missing | BO |
| Windows → Android | gdigrab partial | FFmpeg profiles | Implemented | MediaCodec AVC source | basic SendInput | AudioTrack source | partial | missing | BO components |
| Windows → iOS | gdigrab partial | FFmpeg profiles | Implemented | AVSampleBufferDisplayLayer H.264 | basic SendInput | AVAudioEngine source | partial | missing | BO components |
| Linux → Windows | X11/PipeWire/DRM partial | NVENC/VAAPI/FFmpeg | Implemented | FFmpeg/BGRA + wgpu | uinput host | Opus source | partial | Linux host scripts only | BO |
| Linux → Linux | X11/PipeWire/DRM partial | NVENC/VAAPI/FFmpeg | Implemented | FFmpeg/BGRA + wgpu | uinput | Opus source | partial | Linux scripts | IT loopback only |
| Linux → macOS | fallback exercised | H.264 NVENC exercised | direct UDP exercised | FFmpeg/BGRA + Metal upload | source only in rig | source only in rig | partial | unverified | PT/LAN video fallback |
| Linux → Android | X11/PipeWire/DRM partial | NVENC/VAAPI/FFmpeg | Implemented | MediaCodec AVC source | touch/JNI source | AudioTrack source | partial | missing | BO bridge |
| Linux → iOS | X11/PipeWire/DRM partial | NVENC/VAAPI/FFmpeg | Implemented | H.264 display-layer source | touch/FFI source | AVAudioEngine source | partial | missing | BO bridge |
| macOS → Windows | avfoundation fallback | FFmpeg profiles | Implemented | FFmpeg/BGRA + wgpu | CoreGraphics host | Opus source | partial | missing | BO |
| macOS → Linux | avfoundation fallback | FFmpeg profiles | Implemented | FFmpeg/BGRA + wgpu | CoreGraphics host | Opus source | partial | missing | BO |
| macOS → macOS | avfoundation fallback | FFmpeg profiles | Implemented | FFmpeg/BGRA + Metal upload | CoreGraphics host | Opus source | partial | missing | BO |
| macOS → Android | avfoundation fallback | FFmpeg profiles | Implemented | MediaCodec AVC source | CoreGraphics host | AudioTrack source | partial | missing | BO components |
| macOS → iOS | avfoundation fallback | FFmpeg profiles | Implemented | H.264 display-layer source | CoreGraphics host | AVAudioEngine source | partial | missing | BO components |

No row is production-ready. Official Parsec documentation currently supports
hosting on Windows/macOS, with clients on Windows/Linux/macOS/Android; Linux
hosting is therefore a genuine OpenStream differentiator if it is made robust.[^parsec-platforms]

## 8. Implemented versus tested versus production-verified

| Capability | Final status | Highest evidence |
|---|---|---|
| Direct authenticated UDP | Implemented and verified | unit/integration + one LAN rig |
| AES-GCM/replay/key signatures | Implemented and verified | vectors/unit/integration |
| Packet scheduler/delivery ACK/pacer | Implemented and verified | deterministic + encrypted loopback + rig |
| Direct-v2 startup order | Implemented and verified | deterministic/integration |
| Full ICE | Implemented but insufficiently tested | authenticated loopback |
| TURN | Implemented but insufficiently tested | library/loopback/config tests; no external coturn WAN |
| Application relay | Implemented but insufficiently tested | loopback/fault tests; no public deployment |
| Direct↔relay migration | Implemented but insufficiently tested | local acceptance only |
| ICE restart migration | Partially implemented | typed `UnsupportedIceRestart` |
| Linux X11/NVENC fallback | Implemented but insufficiently tested | one physical rig, environment-sensitive |
| Linux native DRM | Experimental | failed on tested NVIDIA path |
| Wayland/PipeWire production capture | Partially implemented | portal/bridge experiments, release gate open |
| macOS desktop FFmpeg/Metal upload | Implemented but insufficiently tested | one physical rig |
| macOS VideoToolbox zero copy | Missing | no desktop implementation |
| Windows host/client | Partially implemented | build-only |
| Android client | Partially implemented | source/bridge build-only |
| iOS client | Partially implemented | source/bridge build-only |
| Keyboard/mouse | Partially implemented | unit/source; no production raw-input rig |
| Opus audio | Implemented but insufficiently tested | loopback/unit, no physical release run |
| Product shell settings/host lifecycle | Partially implemented | unit/frontend/CI |
| Product Connect/session launch | Missing | no side-effect runtime |
| Account/device trust service | Missing | domain model only |
| Release packages/signatures/SBOM | Missing | scripts/templates only |

## 9. Networking and relay status

OpenStream has more than a LAN-only transport, but production behavior remains
unproven.

- Direct mode is the default and uses host, optional STUN server-reflexive,
  optional UPnP mapping, and application-relay candidates
  (`client-core/src/lib.rs:2265-2285`, `2570-2603`).
- Full ICE must be explicitly enabled and supports UDP4/UDP6 host,
  server-reflexive, peer-reflexive, and relay candidates
  (`client-core/src/lib.rs:2331-2347`).
- RFC 8445 is the correct basis for heterogeneous NAT traversal and defines ICE
  restart for a changed data destination.[^rfc8445]
- Current `webrtc-ice` integration cannot perform a safe ICE restart, so network
  interface/NAT changes may require whole-session reconnect.
- Signal WebSockets ping every 15 seconds and time out after 45 seconds; direct
  data paths have authenticated keepalive; ICE owns consent freshness.
- The server is in-memory and single-process. Restart terminates active
  signaling state and invalidates relay state; no HA/persistent session broker
  exists.

The architecture chooses a sensible custom-UDP path for latency and control.
Alternative assessment:

| Option | Latency/HOL | NAT/relay | Complexity | Recommendation |
|---|---|---|---|---|
| Current UDP + ICE/TURN | no transport HOL; app chooses reliability | strong if ICE/TURN proven | high, already invested | Keep and finish |
| QUIC streams only | stream HOL within each stream | still needs traversal/relay | medium | Reject for bulk real-time media |
| QUIC DATAGRAM | unreliable encrypted datagrams, congestion controlled[^rfc9221] | still needs traversal/relay | medium/high migration | Needs evidence; no urgent rewrite |
| WebRTC media/data | mature ICE/TURN/interoperability | strong | large external policy/codec stack | Consider adapter, not forced rewrite |
| Relay-only | predictable reachability | always incurs relay latency/cost | operationally simple | Reject as default; retain fallback |

## 10. Media pipeline status

The production-intended Linux→macOS path is incomplete at both ends.

```text
Current physical fallback:
Wayland portal/PipeWire or X11 bridge
→ external FFmpeg
→ h264_nvenc
→ whole access unit
→ OpenStream encrypted UDP
→ external FFmpeg decode
→ CPU BGRA
→ per-pixel Vec<u32>
→ minifb or wgpu texture upload
```

The host profiles correctly distinguish generated sources from live capture,
probe each codec/backend rather than trusting library/node presence, and use
low-delay encoder flags. H.264 and H.265 are protocol/FFmpeg-capable, but the
tested GTX 970 only proved H.264 NVENC. H.265 must remain capability-gated.

The desktop client has no in-process VideoToolbox decoder. Apple provides the
native primitives needed to decode to `CVImageBuffer` and map a Core Video
image to a Metal texture; callback ordering and GPU lifetime must be handled
explicitly.[^apple-vt][^apple-metal]

NVIDIA's own low-latency guidance supports low/ultra-low-latency tuning, small
VBV, and no B-frame reordering for cloud gaming.[^nvenc] The current tuning is
a useful improvement, not a substitute for direct capture surfaces, live
encoder control, sub-frame output, and stage instrumentation.

## 11. Latency risks and measurement gaps

The repository carefully retracts unsupported claims. The current defensible
physical result is 220–240 ms P50 with roughly ±30 ms screenshot/clock-offset
uncertainty (`parsec-display-input-latency-gap.md:77-118`). It is substantially
better than the original ~1 second, but not close to the 15–30 ms target class.

PR #18 added frame-age and stage instrumentation. No physical run uses all
corrected stamps (`latency-rig-runs.md:217-233`), so current capture→encode,
encode→packet, network, decode, and true present attribution is unknown.

Priority risks:

1. host capture bridge/process boundary and missing frame-liveness proof;
2. whole-frame access-unit packetization rather than slices/sub-frame output;
3. FFmpeg subprocess decode and CPU BGRA copies;
4. fixed queues whose drop direction can retain older frames;
5. minifb/window-loop presentation rather than native display-linked present;
6. pointer movement sharing reliable ordered control with key transitions;
7. unmeasured 60/120 Hz behavior and no long soak.

Parsec static evidence shows relevant native facilities, but exact queue depths,
algorithms, and latency are unknown and must not be inferred from symbols.

## 12. Security and privacy findings

Good controls include strict bounds, constant-time bearer comparisons,
credential-redacting Debug output, field-aware diagnostic redaction, secure
pairing files, header-based WebSocket credentials, explicit insecure modes,
relay HMAC tickets, ASan/fuzz/secret scanning, and input release-on-drop.

The main security risk is the missing product identity plane, not broken packet
encryption. An admin token plus ephemeral role tokens is suitable for an
engineering/self-hosted session broker; it is not a user/device authentication
system. The private-LAN no-auth mode is correctly restricted to explicit local
addresses, but an RFC1918 LAN is not a user-authentication boundary.

The local IPC is strong on Unix (64 KiB framing, typed secret-free messages,
private parent/socket modes, symlink refusal), but returns
`UnsupportedPlatform` outside Unix (`local-ipc/src/lib.rs:412-520`).

## 13. Parsec comparison

Local artifact paths requested under `/workspace/scratch/...` were unavailable.
Equivalent authorized, gitignored local artifacts were identified by SHA-256
against the committed manifest. Analysis was static only; binaries were not
executed, modified, authenticated, or contacted.

| Area | Parsec evidence/confidence | OpenStream | Decision |
|---|---|---|---|
| Linux hosting | Publicly documented absent[^parsec-platforms] | core differentiator, not robust yet | Improve |
| Direct P2P/relay | Publicly documented encrypted UDP + relay[^parsec-connectivity] | direct UDP + ICE/TURN + app relay | Adopt concept; finish WAN proof |
| User/device auth | Publicly documented account/MFA[^parsec-security] | ephemeral admin/session capabilities | Adopt product model independently |
| macOS decode/present | Observed directly: VT/CoreVideo/IOSurface/Metal imports; architecture is strong inference | FFmpeg CPU BGRA upload | Adopt native zero-copy architecture |
| Raw input | Observed directly: IOHID and Windows Raw Input imports | sampled window pointer, reliable control | Adopt event-driven/raw input |
| Cursor side channel | Observed key `client_png_cursor`; behavior weak/strong inference only | no cursor-shape path | Needs more evidence; likely improve |
| Encoder slices/VBV | Observed configuration keys; exact behavior unknown | whole AUs; basic VBV/latency flags | Improve after measurement |
| Hardware platform breadth | Public docs and artifact presence | mostly build-only outside Linux→Mac | Defer breadth until primary path works |
| Proprietary protocol compatibility | Unknown/private | independent protocol | Reject as 1.0 requirement |
| Linux limitation | Publicly documented | OpenStream can surpass it | Keep differentiation |

“Observed directly” means only that a symbol/key exists in a hashed artifact.
The pipeline assembled from multiple symbols is a strong inference. Proprietary
wire format, congestion algorithm, exact queue policy, and credentials remain
unknown.

## 14. Confirmed bugs and issue register

### OS-001

ID: OS-001  
Title: Product Connect flow has no session side effect  
Severity: Critical  
Confidence: High  
Affected platform: Desktop product shell  
Affected component: `desktop/src-tauri`, session ownership  
Evidence: `runtime.rs:273-278`; `RuntimeCommand::Connect` only maps to
`AppCommand::Connect` at `runtime.rs:493-502`; only host enable/disable have
external side effects in `src-tauri/src/lib.rs:82-94`.  
Current behavior: UI/model can enter connection states without creating a
control-plane request, `PeerSession`, decoder, or session window.  
Expected behavior: One supervised operation obtains ephemeral credentials,
establishes transport, launches/owns a native session, and reports actual state.  
Impact: The product application cannot perform its primary user journey.  
Recommended fix: Implement a session supervisor and control-plane adapter;
pass credentials over protected IPC/inherited handles, never argv/React.  
Required test: Install two apps, click Connect, stream, disconnect, reconnect,
and prove process/resource cleanup.  
Release blocker: Yes

### AUTH-001

ID: AUTH-001  
Title: Durable user/device authentication and trust are absent  
Severity: Critical  
Confidence: High  
Affected platform: All  
Affected component: Signal/control server and product runtime  
Evidence: Signal routes are session/guest/turn/relay only
(`signal-server/src/main.rs:982-999`); creation accepts one admin capability and
issues UUID role tokens (`1126-1169`).  
Current behavior: No users, enrolled devices, presence, trusted-device policy,
refresh credentials, recovery, or durable revocation/audit store.  
Expected behavior: Device enrollment and identity-backed authorization issue
short-lived session capabilities and persist trust/audit state.  
Impact: Pairing JSON/admin-token workflows cannot support a consumer product.  
Recommended fix: Add a separate self-hostable control service and repository
layer; keep signaling ephemeral.  
Required test: enroll, authenticate, approve, reconnect, revoke, token expiry,
server restart, and compromised-device recovery.  
Release blocker: Yes

### NET-001

ID: NET-001  
Title: Full ICE startup and reconnect lack establishment epochs  
Severity: High  
Confidence: High  
Affected platform: All full-ICE/TURN sessions  
Affected component: `PeerSession::establish_with_ice`, signaling pending queues  
Evidence: ICE credentials are sent before peer readiness and an absolute
15-second deadline starts at `client-core/src/lib.rs:2382-2401`; generic pending
messages are queued at `signal-server/src/main.rs:1914-1979`, while only direct
messages are generation-scoped. Tests explicitly preserve ICE messages while
dropping stale direct messages.  
Current behavior: A peer started more than 15 seconds earlier can time out; old
queued ICE credentials/candidates/`key` records have no authoritative attempt
generation on reconnect.  
Expected behavior: Wait for a server-authoritative ICE establishment epoch,
then start bounded candidate/key deadlines; invalidate it on role replacement.  
Impact: Production TURN/ICE startup order and reconnect can fail or consume
stale handshake records.  
Recommended fix: Create direct-v2-equivalent ICE readiness/epoch envelopes or
use a backend with a rigorously scoped restart generation.  
Required test: host/client separated by minutes; replacements before candidate
done and key; late old-epoch records; external TURN.  
Release blocker: Yes

### HOST-001

ID: HOST-001  
Title: Host Ready means process survival, not frame liveness  
Severity: High  
Confidence: High  
Affected platform: Linux host now; future hosts  
Affected component: `openstream-host-agent` health  
Evidence: A child becomes `Ready` after startup grace if `try_wait` says it is
alive (`host-agent/src/lib.rs:1015-1023`); health has no frame/capture counter.
Repository hardware notes show a running portal/node/session can emit no pixels.  
Current behavior: UI can advertise Ready while capture is black or emits zero
frames.  
Expected behavior: readiness requires backend preflight plus fresh frame/
encoder-output heartbeat, with typed degraded/failure state.  
Impact: Users connect to a nominally healthy but dead host.  
Recommended fix: Add child→agent health IPC containing capture, encode, and
frame-age counters; watchdog and fallback on no-frame timeout.  
Required test: stale portal token, black Xwayland root, wedged encoder, frozen
capture, normal damage-idle desktop, and recovery.  
Release blocker: Yes

### CFG-001

ID: CFG-001  
Title: Host settings cannot be proved applied to the supervised child  
Severity: High  
Confidence: High  
Affected platform: Product host  
Affected component: Tauri runtime ↔ host-agent IPC  
Evidence: `desktop/src-tauri/src/runtime.rs:418-440` states the agent never reads
the shell settings and Start carries no settings/revision.  
Current behavior: stop/start can rerun the daemon's old environment while UI
correctly leaves settings pending.  
Expected behavior: validated effective config and revision cross IPC and are
echoed by health.  
Impact: Product settings do not control hosting reliably.  
Recommended fix: Add secret-free config revision and protected session/config
descriptor to Start; report consumed revision.  
Required test: edit capture/encoder/port, restart, prove exact child config;
revert and concurrent start/stop.  
Release blocker: Yes

### MEDIA-001

ID: MEDIA-001  
Title: Primary Linux capture path is not release-verified on the target rig  
Severity: High  
Confidence: High  
Affected platform: Linux NVIDIA host  
Affected component: X11/PipeWire/DRM capture  
Evidence: `docs/BUILD.md:260-292` records black Xwayland capture, missing FFmpeg
PipeWire demuxer, and kmsgrab rejection of `ABGR2101010`; release report lines
29-36 keeps the physical gate open.  
Current behavior: The fallback transport/encode path works, but real Wayland
desktop pixels are environment-dependent and the shipped native path failed.  
Expected behavior: Auto selection proves actual frames and falls back to a
working portal/PipeWire or X11 capture.  
Impact: Linux hosting—the core differentiator—can produce black video.  
Recommended fix: Productionize the PipeWire portal FD path, preserve DMA-BUF
where possible, and make frame-producing probes authoritative.  
Required test: KDE Wayland, X11, Steam Game Mode/gamescope, monitor hotplug,
10-bit framebuffer, sleep/resume, 30-minute and 8-hour runs.  
Release blocker: Yes

### MEDIA-002

ID: MEDIA-002  
Title: macOS desktop has no native hardware decode/zero-copy presentation  
Severity: High  
Confidence: High  
Affected platform: Apple-Silicon macOS client  
Affected component: Desktop decoder/renderer  
Evidence: `desktop-client` decodes through FFmpeg to BGRA and
`render.rs` uploads it; no desktop `VTDecompressionSession` implementation.
The iOS display-layer source is separate and untested.  
Current behavior: Multiple CPU copies/conversion and process boundaries remain.  
Expected behavior: H.264/H.265 VideoToolbox decode to CVPixelBuffer/IOSurface,
CVMetalTexture mapping, Metal present, explicit FFmpeg fallback.  
Impact: Large latency/power gap and unmet stated 1.0 target.  
Recommended fix: Implement in-process native backend with timestamp ordering,
format changes, hardware-status verification, and GPU lifetime discipline.  
Required test: H.264/H.265, resize, IDR recovery, decoder failure/fallback,
60/120 Hz, 4K, sleep/wake, and long soak.  
Release blocker: Yes

### INPUT-001

ID: INPUT-001  
Title: Desktop pointer path is not production low-latency raw input  
Severity: High  
Confidence: High  
Affected platform: Desktop clients  
Affected component: `desktop-client`, media input queue/control  
Evidence: pointer positions are sampled in `desktop-client/src/main.rs:679-711`;
all input is sent via `ReliableControl` at `1428-1460`. The input queue can
coalesce motion, but transport remains ordered/retransmitted.  
Current behavior: no raw relative mouse, cursor lock/immersive mode, or
latest-wins non-retransmitted motion; physical Mac→Linux safety test absent.  
Expected behavior: reliable keys/buttons/release; sequenced coalesced
non-retransmitted motion; focus/disconnect/watchdog ReleaseAll.  
Impact: sticky/high-latency mouse under loss and unusable edge-bound FPS input.  
Recommended fix: native window/raw-device runner and split input transport
semantics while retaining host-side authorization.  
Required test: full keyboard/mouse matrix, loss, focus loss, held key/button,
disconnect, permission revoke, detach hotkey, watchdog.  
Release blocker: Yes

### SEC-001

ID: SEC-001  
Title: Device identity has no secure persistent custody  
Severity: High  
Confidence: High  
Affected platform: All  
Affected component: identity loading/settings secrets  
Evidence: `client-core/src/lib.rs:4078-4101`; searches find `SecretRef` but no
Keychain, DPAPI, Credential Manager, or Secret Service implementation.  
Current behavior: key can live in environment/plain file or be regenerated.  
Expected behavior: non-exportable or access-controlled OS secret storage with
stable device identity, migration, and revocation.  
Impact: weak device continuity and avoidable private-key exposure.  
Recommended fix: platform secret-provider trait; harden file fallback like the
pairing loader and prohibit environment keys in production mode.  
Required test: permissions/symlinks, OS-store round trip, reinstall/upgrade,
locked store, key rotation, revocation.  
Release blocker: Yes

### WAN-001

ID: WAN-001  
Title: Public WAN, NAT, TURN, and roaming behavior is unverified  
Severity: High  
Confidence: High  
Affected platform: All remote sessions  
Affected component: connectivity and relay operations  
Evidence: `scripts/wan-acceptance.sh` reports all ten cases unverified; the
release report marks external TURN/WAN and relay migration unverified.  
Current behavior: loopback/local tests pass; no public-network evidence exists.  
Expected behavior: direct-first connection with bounded automatic relay
fallback and clear path status across common NATs and network changes.  
Impact: The product may fail outside one LAN, defeating remote access.  
Recommended fix: external coturn and application-relay lab on independent
networks; automate fault injection and collect credential-safe evidence.  
Required test: the exact ten-case WAN matrix plus server outage/restart and
credential expiry.  
Release blocker: Yes

### LAT-001

ID: LAT-001  
Title: Current corrected instrumentation has no physical baseline  
Severity: High  
Confidence: High  
Affected platform: Linux→macOS primary rig  
Affected component: performance evidence  
Evidence: `latency-rig-runs.md:217-233` says all runs predate three corrected
stamps and Run F is outstanding.  
Current behavior: 220–240 ms is an external screenshot estimate; stage loss and
present attribution are not current.  
Expected behavior: monotonic same-clock stage metrics and end-to-end optical/
high-speed or equivalent repeatable measurement.  
Impact: Optimization priority and release performance cannot be defended.  
Recommended fix: Run corrected instrumentation before architecture changes,
then preserve a benchmark baseline.  
Required test: P50/P90/P99 across 30/60 fps, profiles, direct/relay, loss, and
soak, with queue/drop counters.  
Release blocker: Yes

### REL-001

ID: REL-001  
Title: Release artifacts, signing, SBOM, updater, and rollback evidence are absent  
Severity: Critical  
Confidence: High  
Affected platform: Linux x86-64 and macOS arm64 release targets  
Affected component: packaging/release engineering  
Evidence: `check-openstream-1-0-release.sh` fails with 11 missing items;
`release/openstream-1.0-gates.tsv:8-23`; no tags/releases exist.  
Current behavior: scripts/templates exist, but no staged candidate or evidence.  
Expected behavior: reproducible artifacts, hashes, SPDX/CycloneDX, verified
signatures/notarization/stapling, install/launch/upgrade/rollback, signed update.  
Impact: Users cannot safely install or recover a supported release.  
Recommended fix: Stage a pinned RC only after runtime/hardware/WAN blockers;
complete fail-closed gate evidence and independent review.  
Required test: clean install, launch, service persistence, upgrade, rollback,
tamper rejection, revoked/expired signature, update health-check rollback.  
Release blocker: Yes

### PORT-001

ID: PORT-001  
Title: Non-Linux hosts and mobile clients are source/build surfaces, not products  
Severity: Medium  
Confidence: High  
Affected platform: Windows/macOS host; Android/iOS client  
Affected component: platform adapters, IPC, packaging, UX  
Evidence: local IPC is Unix-only; Android README requires origin/pairing JSON;
iOS README says Xcode project/signed device build remain outstanding; CI only
cross-builds the bridge.  
Current behavior: components compile but lack physical integration, installers,
permissions/onboarding, lifecycle qualification, and support evidence.  
Expected behavior: per-platform native lifecycle, media/input, secure storage,
packaging, and device acceptance.  
Impact: The advertised eventual matrix is not current support.  
Recommended fix: keep capability-gated and develop after the narrow primary
1.0 path, unless release scope is expanded.  
Required test: physical combination matrix and platform-specific install/
permissions/background tests.  
Release blocker: No for a narrowly declared Linux-host/macOS-client 1.0; Yes if
the product claims the full platform matrix.

### AUDIO-001

ID: AUDIO-001  
Title: Audio transport exists without physical endpoint acceptance  
Severity: Medium  
Confidence: High  
Affected platform: Primary Linux→macOS path and mobile  
Affected component: Opus capture/playback/jitter  
Evidence: codec/jitter/PLC tests pass; release report and hardware record
explicitly exclude audio.  
Current behavior: functional source and loopback coverage, no measured A/V sync,
latency, device switching, underrun, or sleep/reconnect proof.  
Expected behavior: stable low-latency audio with bounded jitter, device
recovery, and A/V sync.  
Impact: Incomplete remote-desktop experience and unknown latency.  
Recommended fix: platform endpoint acceptance, then replace helper processes
where measurements justify it.  
Required test: Opus under loss/jitter, mute, device change, suspend/resume,
30-minute and 8-hour sync/underrun.  
Release blocker: Yes for stated audio-inclusive 1.0.

## 15. Partially implemented features

- Tauri product shell and settings-to-UI adapter;
- host-agent service and host settings application;
- trusted-device/approval domain types without durable backend;
- Windows/macOS FFmpeg hosting and basic input injection;
- Android/iOS client source layers;
- Linux PipeWire and native DRM capture;
- hardware decoder capability model without macOS desktop backend;
- one-active-display multi-monitor selection;
- guest admission/parking/kick without complete media fan-out;
- microphone transport without a virtual microphone product backend;
- reconnect state/model without full product-controlled credential/session
  recreation;
- direct↔relay migration without ICE restart.

## 16. Missing features

- real shell-to-session connection runtime and native session window;
- durable account/device/presence/trust/control service;
- OS secure key/credential stores;
- production Wayland/PipeWire capture on the target host;
- macOS desktop VideoToolbox/IOSurface/Metal zero-copy path;
- raw relative/immersive input and cursor-shape side channel;
- signed updater and rollback coordinator;
- Windows host service/IPC/package and macOS host service/package;
- Android/iOS signed applications and product onboarding;
- production database/HA/audit/multi-tenant relay operations;
- simultaneous multi-display streams and real multi-guest fan-out.

## 17. Untested features

- all Windows-host and macOS-host combinations;
- physical Windows/Linux desktop clients;
- Android/iOS device decode, input, audio, lifecycle, radio, thermal, and stores;
- external coturn, public WAN, CGNAT, symmetric NAT, IPv6, double NAT;
- application relay over WAN and migration under real failure;
- ICE startup ordering, reconnect, and stale records across delayed peers;
- native DRM on supported NVIDIA formats and production PipeWire portal capture;
- H.265 hardware path on the primary rig;
- VideoToolbox desktop decode, because it is missing;
- physical keyboard/raw mouse/watchdog safety;
- physical audio/A-V sync;
- service/server restart, update, install, upgrade, rollback, signing;
- 30-minute and 8-hour release-candidate soaks.

## 18. Known production blockers

The minimum Linux-host/macOS-client 1.0 is blocked by:

1. OS-001 product session integration;
2. AUTH-001 and SEC-001 durable identity/trust and secure key custody;
3. NET-001 full-ICE epoch correctness;
4. MEDIA-001 frame-producing Linux capture plus HOST-001 truthful liveness;
5. MEDIA-002 native macOS decode/presentation, or an explicit decision to ship
   the slower fallback with revised scope and measured acceptance;
6. INPUT-001 production input and AUDIO-001 physical audio;
7. WAN-001 public connectivity/relay evidence;
8. LAT-001 corrected performance baseline;
9. CFG-001 settings actually controlling the host child;
10. REL-001 packages, signing, SBOM, updater/rollback and release evidence.

## 19. CI and release evidence

GitHub run `34816872196` ran directly on the audited merge SHA and passed all 27
jobs. Coverage includes formatting, Clippy `-D warnings`, workspace tests,
release build, C/C++ ABI checks, fuzz-harness compilation, ASan, Loom,
cargo-deny, gitleaks, protocol/media loopbacks, Alpine/musl, frontend tests and
bundle, Tauri tests, desktop builds, and Android/iOS bridge cross-builds.

Local re-verification also passed the workspace, Tauri, and frontend suites.
A warning remains that dependency `block 0.1.6` contains future-incompatible
code; it is maintenance debt, not evidence of a current failure.

Important limits:

- hardware-required tests are ignored on ordinary runners;
- target checks prove compilation, not launch or platform behavior;
- mobile acceptance explicitly excludes real devices;
- `wan-acceptance.sh` checks operator evidence and does not create traffic;
- release scripts/templates do not prove a signed package exists;
- gitleaks currently depends on an external Docker image tag, a CI availability
  risk even though the scan itself passed.

The fail-closed release checker is excellent. Its current failure is the
correct result, not a defect.

## 20. Recommended next work ordered by priority

This is the smallest sequence to reach a trustworthy narrow 1.0, not a generic
feature roadmap:

1. **Close runtime ownership:** product Connect/Disconnect must supervise a real
   session process/window; host Start must carry and prove a config revision.
2. **Add durable identity/control:** enroll devices, persist presence/trust,
   issue ephemeral session credentials, implement revocation/audit, and use OS
   secure stores.
3. **Fix full ICE epochs:** make delayed startup/reconnect as safe as direct-v2,
   then prove it against external coturn.
4. **Make Linux hosting truthful:** production PipeWire/portal or working X11
   capture, frame-output heartbeat, automatic fallback, and target-rig tests.
5. **Complete native session/input:** winit/native lifecycle, raw relative
   mouse, reliable transitions, latest-wins motion, ReleaseAll watchdog.
6. **Complete macOS media:** VideoToolbox H.264 first, IOSurface/CVMetalTexture,
   Metal present, then H.265; retain explicit FFmpeg fallback.
7. **Run corrected latency instrumentation:** establish P50/P90/P99 and stage
   bottlenecks before slice/sub-frame or further tuning.
8. **Qualify audio and displays** on the physical rig, including failures,
   reconnect, suspend, and long soak.
9. **Run the ten-case WAN matrix** on separate networks with direct, external
   TURN, and application relay forced independently.
10. **Freeze an RC and finish release engineering:** reproducible packages,
    SBOM, checksums, signing/notarization, clean install, upgrade, rollback,
    signed updater, and independent evidence review.

Do not expand to Windows hosting, macOS hosting, or polished mobile clients
until step 7 establishes a stable primary path, unless those platforms become
explicit release blockers by scope decision.

## 21. OpenStream 1.0 readiness decision

OpenStream has enough source architecture to continue toward 1.0 without a
protocol rewrite. It does not have sufficient evidence—or a complete product
runtime—to release today. The blockers are concrete and concentrated: runtime
integration, identity/trust, full-ICE lifecycle, Linux capture/liveness, native
macOS media, production input/audio, WAN/TURN, and signed release artifacts.

## 22. Evidence appendix

Audit artifacts:

- `evidence/repository-state.md`
- `evidence/verification.md`
- `evidence/internet-sources.md`
- `evidence/parsec-static-verification.md`
- `worker-reports/01-codebase-architecture.md`
- `worker-reports/02-platform-matrix.md`
- `worker-reports/03-network-auth-control.md`
- `worker-reports/04-media-latency.md`
- `worker-reports/05-security-test-release.md`
- `summary.json`

Primary repository evidence:

- `.github/workflows/ci.yml:21-471`
- `engine/lowlat/crates/client-core/src/lib.rs:2255-2520,2570-2758,4078-4175`
- `engine/lowlat/crates/client-core/src/path.rs:88-272`
- `engine/lowlat/crates/signal-server/src/main.rs:206-345,982-999,1126-1180,1889-2025,2841-3050`
- `engine/lowlat/crates/signal-server/src/turn.rs:23-187`
- `engine/lowlat/crates/protocol/src/lib.rs:600-790`
- `engine/lowlat/crates/host-agent/src/lib.rs:990-1040,1198-1232`
- `desktop/src-tauri/src/lib.rs:42-235`
- `desktop/src-tauri/src/runtime.rs:253-306,418-440,493-585`
- `engine/lowlat/crates/desktop-client/src/main.rs:640-735,1043-1188,1400-1480`
- `engine/lowlat/crates/desktop-client/src/render.rs`
- `engine/lowlat/crates/media/src/input.rs:380-510`
- `engine/lowlat/crates/settings/src/lib.rs:753-838`
- `engine/lowlat/crates/local-ipc/src/lib.rs:1-260,412-520`
- `mobile/android/app/src/main/java/app/openstream/MainActivity.kt:97-344`
- `mobile/ios/OpenStreamVideoView.swift:1-227`
- `mobile/ios/README.md:1-34`
- `docs/BUILD.md:170-305`
- `docs/research/evidence/latency-rig-runs.md:1-75,195-233`
- `docs/research/parsec-display-input-latency-gap.md:77-125,392-540`
- `docs/research/evidence/parsec-artifact-manifest.md:1-125`
- `release/openstream-1.0-gates.tsv:1-23`
- `docs/acceptance/OPENSTREAM_1_0_RELEASE_REPORT.md:1-43`
- `scripts/check-openstream-1-0-release.sh`
- `scripts/wan-acceptance.sh:1-80`
- `scripts/mobile-acceptance.sh:1-78`

Sources accessed 2026-09-14:

[^rfc8445]: [RFC 8445 — Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445.html).
[^rfc8656]: [RFC 8656 — TURN](https://www.rfc-editor.org/rfc/rfc8656.html).
[^rfc9221]: [RFC 9221 — QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html).
[^apple-vt]: [Apple — VTDecompressionSession](https://developer.apple.com/documentation/videotoolbox/vtdecompressionsession).
[^apple-metal]: [Apple — CVMetalTextureCacheCreateTextureFromImage](https://developer.apple.com/documentation/corevideo/cvmetaltexturecachecreatetexturefromimage(_:_:_:_:_:_:_:_:_:)).
[^nvenc]: [NVIDIA — NVENC Video Encoder API Programming Guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-video-encoder-api-prog-guide/).
[^parsec-platforms]: [Parsec — Hardware and Software Compatibility](https://support.parsec.app/hc/en-us/articles/32381568346644-Hardware-and-Software-Compatibility).
[^parsec-security]: [Parsec — Security at Parsec](https://support.parsec.app/hc/en-us/articles/32361366289940-Security-At-Parsec).
[^parsec-connectivity]: [Parsec — Connectivity Requirements](https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements).

NO-GO — specific release blockers remain.
