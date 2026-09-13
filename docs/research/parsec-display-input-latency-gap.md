# Parsec Display and Input Latency Gap Analysis

## Executive finding

**The remaining display latency is not yet decomposed.** OpenStream's fall
from roughly 1,000 ms to **220-240 ms P50** is supported by the measured
decoder and NVENC changes in #15, and each of those two steps was measured
separately. Nothing has yet measured where the remaining time goes. See
[Post-merge validation](#post-merge-validation-on-f6896c4) for the figures
and for why this measurement technique cannot attribute it.

Source inspection identifies four concrete candidates, in no proven order:

1. stale-frame retention -- both decoded-frame handoffs drop the *newest*
   frame when full and keep older ones;
2. the `AccessUnitizer` boundary, which cannot emit frame N until the
   encoder begins frame N+1: about 33 ms at 30 fps, and the one stage
   presently known from source rather than suspected;
3. subprocess and CPU frame movement -- an FFmpeg child, a raw BGRA pipe, an
   8.3 MB allocation and a per-pixel conversion for every 1080p frame;
4. presentation scheduling, which is not tied to the display's refresh.

**Two budgets, and only one of them has been measured.**

```text
DISPLAY LATENCY          host pixel -> capture -> encode -> network
                         -> decode -> present -> client pixel
                         measured: 217-254 ms

INTERACTION LATENCY      physical input -> client capture -> network
                         -> host injection -> application redraw
                         -> the whole display path above
                         never measured
```

The clock experiment reads a host-generated pixel off the client's window. No
part of the input path appears in it. Input work will change how the session
*feels* and cannot change that ~230 ms figure; conversely the display fixes
below do not address the input path's own latency, which source inspection
suggests is substantial and is described separately.

Parsec's inspected macOS payload contains a cohesive native display pipeline
and a separate event-driven input pipeline. OpenStream passes decoded pixels
and input through several queues whose semantics favour boundedness and
reliability over freshness. The highest-value next step is not another fix:
it is stage-level instrumentation, so the step after it can be attributed.
## Post-merge validation on f6896c4

Measured after #13-#15 landed, with both host and client built from `main`,
against a live KDE Wayland desktop over the portal, NVENC, direct UDP, at
1920x1080 / 30 fps.

```text
Run A -- integration tree
  P50 165 ms, range 153-222 ms
  estimated host/client offset +137 ms

Run B -- merged main
  P50 221 ms, range 203-275 ms
  offset +98 ms

Run C -- merged main
  P50 237 ms, range 222-240 ms
  offset +103/+104 ms, measured before and after the sample set
```

Interpretation:

- B and C reproduce one another.
- A does not.
- **The discrepancy has not been explained.** The estimated clock offset
  differed by about 35 ms between A and B/C, which is enough to account for
  it arithmetically, but nothing here establishes that as the cause.
- Cross-host clock-offset estimation and screenshot timing make this
  technique unsuitable for precise stage attribution. Three samples in one
  set captured the wrong window entirely, which is a further reason it does
  not scale to a P50/P90/P99 campaign.
- The current defensible display-latency result is approximately
  **220-240 ms P50** on this hardware and configuration, with roughly
  +/-30 ms screenshot measurement uncertainty. The earlier single-sample
  figure of 217-254 ms, and run A's 165 ms, should not be quoted as
  results.

Against the ~1,000 ms baseline this is around a quarter of the original
latency, with no catastrophic regression from integrating the three
changes. That is what the experiment establishes; it does not establish
where the remaining time goes, and it is not precise enough to attribute a
future change of tens of milliseconds.

### Why the next measurement must not work this way

Two endpoints on two machines cannot be compared to better than the
synchronisation between them. The replacement is to keep every measurement
inside one clock domain:

- **Host-local** spans (`capture -> encode`, `encode -> access unit`,
  `access unit -> socket`) and **client-local** spans (`receive ->
  reassemble`, `reassemble -> decode`, `decode -> UI`, `UI -> present`)
  need no synchronisation at all, and already separate a capture/encode
  problem from a decode/present one.
- **Interaction latency** is measurable end to end on the client's clock
  alone: send a probe, have the host render a deterministic marker for it,
  stop the timer when that marker is presented. No NTP, no SSH offset, no
  cross-run discrepancy.

Never subtract a host `Instant` from a client `Instant`. If a one-way
network figure is genuinely needed, use a four-timestamp exchange and
report the synchronisation uncertainty alongside it.

## Evidence

The artifacts are not in this repository: `analysis/` is gitignored because it
holds vendor binaries and multi-megabyte string tables, and they are never
executed, published, or shipped. Every citation below therefore points at
[`evidence/parsec-artifact-manifest.md`](evidence/parsec-artifact-manifest.md),
which records each artifact's SHA-256 and the specific symbols and
configuration keys the conclusions rest on — so the reasoning stays checkable
from a clean clone without redistributing anything.

## Evidence confidence

| Confidence | Meaning |
|---|---|
| High | Direct import, linked framework, configuration key, UI string, or OpenStream source behavior |
| Medium | Architecture strongly implied by multiple independent high-confidence indicators |
| Unknown | Exact runtime policy, numeric queue depth, packet format, or scheduler behavior not recoverable from the evidence |

## Display pipeline

### What the Parsec macOS payload proves

The arm64 payload directly links or imports:

- VideoToolbox decompression (`VTDecompressionSessionCreate` and
  `VTDecompressionSessionDecodeFrame`);
- Core Video pixel-buffer and IOSurface access;
- `CVMetalTextureCacheCreateTextureFromImage` and
  `CVMetalTextureGetTexture`;
- Metal drawable acquisition and presentation;
- `CVDisplayLink` callbacks;
- hardware-decoder status through
  `kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder`.

The same payload carries `client_zero_copy`, `client_decoder_index`,
`client_vsync`, `encodeLatency`, `decodeLatency`, and `networkLatency`. This is
high-confidence evidence that decoder selection, zero-copy behavior,
presentation synchronization, and stage metrics are explicit product/runtime
concepts rather than accidental platform defaults.[^parsec-arm64]

Taken together, those imports support this medium-confidence architecture:

```text
compressed H.264/H.265
        ↓
VTDecompressionSession
        ↓
CVPixelBuffer backed by IOSurface
        ↓
CVMetalTextureCache
        ↓
Metal drawable, refresh-aware present
```

Static inspection cannot prove that every Parsec codec/pixel-format path is
zero-copy or that `client_zero_copy` is enabled on every device. It does prove
that the native path exists in the inspected payload.

### What OpenStream does today

OpenStream's current macOS client path is:

```text
complete encoded access unit
        ↓ pipe to FFmpeg child
FFmpeg decode and scale to BGRA
        ↓ stdout pipe
allocate an 8.3 MB 1080p byte buffer
        ↓ per-pixel conversion
allocate/populate Vec<u32>
        ↓ bounded async queue (capacity 2)
bounded UI queue (capacity 8)
        ↓
minifb software present
or wgpu write_texture → Metal present
```

The optional Metal path is GPU presentation, but it still uploads a
CPU-visible BGRA frame for every picture. It is not a native decoder-surface
path.[^openstream-client][^openstream-render]

At 1920×1080, one BGRA frame is 8,294,400 bytes. At 60 fps, one full-frame
copy stage moves about 498 MB/s before counting FFmpeg output, per-pixel
conversion, queue transfers, wgpu staging, or display composition.

### The freshness bug hidden inside bounded queues

PR #12 fixed a deadlock by making the decoder-to-network handoff non-blocking.
That was necessary, but both current frame handoffs discard the arriving frame
when full. They retain the older frames already queued:

```text
decoder queue full → drop newest decoded frame
UI queue full      → drop newest UI frame
```

For interactive streaming, the preferred policy is usually the opposite:

```text
one frame currently being presented
+ one atomic/latest pending frame
newer frame replaces older pending frame
```

The current capacity-two decoder queue plus capacity-eight UI queue can retain
up to ten frames across those two explicit handoffs. That is not a claim that
OpenStream always adds ten frame intervals—the consumers often drain quickly—
but it allows stale work to survive exactly when the renderer is behind. At
30 fps, ten frame intervals are 333 ms. A latest-frame mailbox should be built
before interpreting the remaining measured 230 ms as exclusively decoder or
capture cost.

### Other display-side capabilities present in Parsec

The inspected payload also exposes:

- `encoder_slices`, indicating sub-frame encoder slicing is a supported
  tuning surface;
- separate `encoder_vbv_max`, `encoder_vbv_initial`, and `encoder_vbv_multi`;
- `encoder_idr_interval`;
- `host_capture_timeout`;
- ScreenCaptureKit and CGDisplayStream capture APIs, including queue-depth
  configuration;
- `client_png_cursor` and internal cursor-cache indicators.

The cursor evidence supports a medium-confidence conclusion that Parsec has a
dedicated cursor representation/path in at least some configurations. It does
not prove local cursor prediction or the exact network format. OpenStream has
no equivalent cursor-shape/position side channel in the desktop client; its
visible remote cursor generally depends on the next captured, encoded,
transported, decoded, and presented video frame.[^parsec-cursor]

### Display gaps

| Capability | Parsec evidence | OpenStream status | Priority |
|---|---|---|---|
| In-process hardware decode | VideoToolbox imports and hardware-decoder property | FFmpeg subprocess | P0 |
| GPU-resident decoded surface | CVPixelBuffer/IOSurface/CVMetalTexture imports and `client_zero_copy` | CPU BGRA and texture upload | P0 |
| Latest-frame semantics | Exact policy not statically proven, but native queue controls exist | Older queued frames survive; newest is dropped | P0 |
| Refresh-aware presentation | CVDisplayLink, VSync setting, Metal drawable calls | minifb loop/wgpu present; no native display-link contract | P0 |
| Queue-depth control | Capture queue-depth API and decoder configuration surface | Fixed queues across subprocess/UI boundaries | P0 |
| Sub-frame video | `encoder_slices` | Whole access unit is assembled before fragmentation/transmit | P1 |
| Native host capture | ScreenCaptureKit/IOSurface on macOS; native platform stack | Linux production fallback is external X11/FFmpeg; Wayland bridge crosses a pipe | P1 |
| Cursor side channel | `client_png_cursor` and cursor cache indicators | No cursor metadata/shape stream | P1 |
| Stage timing | encode/decode/network latency fields | Partial transport/frame metrics, no capture-to-present trace | P0 |
| 60/120 fps production path | Configurable encoder FPS | Tested path currently 30 fps | P1 |

## Keyboard and mouse pipeline

### What the Parsec artifacts prove

On Windows, the payload imports `RegisterRawInputDevices`, `GetRawInputData`,
and `GetRawInputDeviceInfoW`. That is direct evidence of a Windows Raw Input
path rather than cursor-position polling.[^parsec-windows]

On macOS, the payload imports IOHID manager/device callbacks, CoreGraphics
event taps, and native AppKit mouse callbacks. Product strings describe:

- relative mouse mode;
- locking the cursor to the client window;
- a detach-mouse hotkey and click-to-reattach behavior;
- keyboard, mouse, or combined immersive modes;
- forwarding system shortcuts such as Command-Tab when Input Monitoring is
  granted;
- configurable macOS Command/Control mapping.

The payload also serializes distinct `keyboardTime`, `mouseTime`,
`gamepadTime`, and `penTime` floating-point fields alongside connection
telemetry. This is high-confidence evidence that Parsec measures or reports
input-class timing separately, although static analysis alone does not prove
the exact start/end timestamps represented by those values.[^parsec-input]

These findings align with Parsec's documented immersive and detach-input
behavior.[^parsec-immersive]

### What OpenStream does today

The current desktop input path is:

```text
minifb window loop, capped at 120 updates/s
        ↓
poll key state, cursor position, buttons, wheel
        ↓
1,024-entry normal FIFO
        ↓
ReliableControl on ordered control channel 0
        ↓
portable scheduler critical class
        ↓
host decodes control stream among FrameAck, clipboard,
microphone, display-selection and other control messages
        ↓
Linux uinput injection
```

PR #14 correctly changes desktop pointer reporting from accumulated relative
deltas to absolute stream-image coordinates. That fixes cursor alignment for
desktop use. It does not implement raw relative input for games.

OpenStream already contains a better `InputQueue`: consecutive relative
motion is coalesced, relative motion is the only lossy class, and key/button/
release transitions remain ordered. The desktop client never instantiates
that queue. Instead, every event enters the generic FIFO and every event is
sent through `ReliableControl`.[^openstream-input]

### The reliable control channel is stop-and-wait, not a pipelined stream

This is the most serious input finding, and it is not a loss-recovery
problem: it costs latency on a perfect link.

`ReliableControl::send` queues a message and then flushes, and the flush
sends exactly one frame -- `next_frame()`, documented as *"the oldest
outstanding frame for initial send or retry"*, selected by
`max_by_key(next_sequence.wrapping_sub(sequence))`.

So a newer message cannot reach the wire until every older one has been
acknowledged:

```text
queue key-down  seq=10   -> send seq=10
queue motion    seq=11   -> flush sends seq=10 again
queue key-up    seq=12   -> flush sends seq=10 again
ACK 10 arrives
                         -> only now can seq=11 be sent
```

The 64-message window is therefore a **storage** bound, not 64 packets of
in-flight concurrency. Every event generated inside one RTT queues behind
the first unacknowledged one, and because all of this shares
`Kind::Control` channel 0, unrelated clipboard, display-selection and frame
acknowledgement traffic sits in the same ordered domain and can stall input
the same way.

On a LAN the RTT is small enough that this hides. Off-LAN it does not.

The fix is not to tune the retry timer. Motion belongs on a lane where the
newest sample supersedes the last and nothing is retransmitted; key, button
and release edges belong on a reliable lane with a genuine sliding window or
selective acknowledgement, independent of clipboard and display traffic.
Reusing today's `ReliableControl` unchanged for the edge lane would carry the
same stop-and-wait behaviour into it.

### Why this adds latency

1. **Polling granularity.** A 120 Hz UI loop adds up to about 8.3 ms before an
   event is observed and cannot preserve a 500–1,000 Hz mouse's event cadence.
   Native event callbacks/raw HID avoid tying input collection to rendering.

2. **Ordered motion.** Mouse motion has a short useful lifetime. Sending every
   motion record through an ordered reliable stream lets one lost record hold
   newer motion behind it.

3. **100 ms loss recovery.** The desktop client drives
   `ReliableControl::retry()` from a 100 ms control tick. A lost key/button
   transition may therefore wait roughly that cadence before retransmission.
   The exact delay depends on send/ACK timing, but the timer is too coarse for
   a latency-first input lane.

4. **Shared head-of-line domain.** Input shares reliable control channel 0
   with frame acknowledgements, keyframe requests, clipboard, microphone
   envelopes, display selection, and teardown. The transport scheduler gives
   the resulting packet critical priority, but it cannot undo ordering inside
   `ReliableControl`.

5. **Unsafe overflow behavior.** Call sites ignore `try_send` failure for
   ordinary input. If the 1,024-entry FIFO fills, a key-up or button-up can be
   silently lost. A priority release lane exists, but `InputReceiver` drains
   the normal FIFO before the critical lane, so `ReleaseAll` can sit behind a
   large input backlog.

6. **No active focus-loss integration.** The repository has a tested
   `SessionRunner` model that reserves a release slot on focus loss, but the
   current minifb runtime labels it as a future seam and does not drive it from
   native focus events.

7. **No end-to-end input timing.** `InputEvent.timestamp_us` is process-local
   and documented as diagnostic only. The host applies events immediately but
   does not return an authenticated applied-input timestamp suitable for
   input-to-host or input-to-photon measurement.

8. **Limited mouse surface.** The desktop client currently polls left,
   middle, and right buttons. Back/forward buttons, high-resolution wheel
   deltas, cursor capture, raw relative mode, and host/client cursor-state
   synchronization are incomplete.

### Input gaps

| Capability | Parsec evidence | OpenStream status | Priority |
|---|---|---|---|
| Event-driven raw mouse | Windows Raw Input; macOS IOHID/native callbacks | minifb position polling at 120 Hz | P0 |
| Relative locked mode | Explicit runtime strings and detach behavior | Absolute desktop pointer only after PR #14 | P0 |
| Motion freshness policy | Exact Parsec transport policy unknown | Correct coalescing queue exists but is unused | P0 |
| Dedicated input lane | Separate input entry points/timing; exact wire lane unknown | Shared reliable control channel 0 | P0 |
| Fast edge recovery | Exact Parsec timer unknown | 100 ms reliable-control retry tick | P0 |
| Immediate release safety | Detach/immersive lifecycle | Reserved model exists; runtime drains normal backlog first | P0 |
| Special-key capture | CGEventTap/Input Monitoring and immersive setting | No production immersive macOS path | P1 |
| Keyboard mapping policy | HID keyboard and macOS key-swap settings | HID mapping exists; no user/platform mapping policy | P1 |
| Additional mouse buttons | Native raw input path | Three buttons polled | P1 |
| Input timing telemetry | Per-class time fields | No applied-input or input-to-photon measurement | P0 |
| Cursor response decoupled from video | Cursor configuration/cache evidence | Cursor generally arrives through video | P1 |

## Recommended independent implementation

### P0: remove latency-retaining queues

Introduce a generation-tagged one-slot frame mailbox:

```text
decoder callback publishes(frame, pts)
    atomically replaces pending older frame
render callback consumes newest eligible frame
```

Only a drawable in flight and one latest pending surface should exist in the
steady state. Record every replacement/drop. Do this even before VideoToolbox;
it will reveal how much of the remaining latency is queue age.

### P0: implement native macOS decode/present

Build an in-process backend with:

```text
Annex-B parser
→ SPS/PPS/VPS format-description lifecycle
→ VTDecompressionSession (real-time, hardware required/preferred)
→ PTS-aware output reorder handling
→ CVPixelBuffer/IOSurface
→ CVMetalTextureCache
→ Metal render pass
→ drawable presentation
```

Keep FFmpeg/BGRA as an explicit fallback. Never pass frame bytes through
Tauri/React IPC.

### P0: split input semantics

Use native window/HID events and map them into two wire policies:

```text
Reliable edge lane
  key down/up
  mouse button down/up
  ReleaseAll
  permission/lifecycle transitions

Fresh-state lane
  relative mouse motion
  absolute desktop pointer
  accumulated wheel deltas
```

The fresh-state lane should be sequenced, non-retransmitted, coalesced before
packetization, and processed latest-first. It should use `Kind::Input`, not
`ReliableControl` channel 0. The reliable edge lane needs RTT-aware or short
bounded retransmission rather than a fixed 100 ms poll.

`ReleaseAll` must bypass ordinary backlog while preserving safety: the host
should treat it as an epoch barrier and discard older input from that epoch,
which removes the need to drain 1,024 older events before releasing state.

### P0: instrument before the next optimization claim

Attach monotonic IDs/timestamps to:

```text
input captured
input packet emitted
input authenticated at host
input injected

capture requested
capture complete
encode submitted
first encoded slice available
first/last network fragment
frame assembled
decode submitted
decode callback
drawable submitted
drawable presented
```

Report queue age, not only queue length. The next hardware test should produce
p50/p95/p99 for input-to-injection and capture-to-present.

### P1: sub-frame and cursor work

After the native client path is stable:

- enable multiple low-latency H.264/HEVC slices where the encoder supports it;
- packetize and transmit slices/NAL groups as they become available rather
  than waiting for a complete frame;
- replace the external Linux capture bridge with a native PipeWire DMA-BUF
  consumer and direct encoder-surface import;
- design a cursor metadata/shape channel so ordinary desktop cursor feedback
  does not require a new video frame;
- qualify 60 fps, then 120 fps, without allowing capture/encode/decode queues
  to deepen.

## Suggested implementation order

**Instrumentation first.** Every item below this line is a hypothesis about
where ~230 ms lives. Ordering the work by architectural conviction is how a
project arrives at 20-30 ms without knowing which change bought it, and
without being able to tell a regression from a plateau.

1. **Stage timestamps and frame/input identifiers.** Capture acquired,
   encoder input, first encoder byte, complete access unit, first and last
   UDP fragment sent, first fragment received, access unit assembled,
   decoder write, decoded frame read, frame offered to the UI, frame
   consumed, present submitted. Report P50/P95/P99, not one screenshot.
2. **Latest-frame mailbox**, carrying `frame_id` and `decoded_at` so every
   replacement yields `frames_replaced`, `pending_frame_age_us` and
   `presented_frame_age_us`. This quantifies whether freshness is worth
   10 ms or 150 ms.
3. **Repeat the clock experiment** and attribute the change.
4. Native event-driven input with a real session window and focus
   semantics.
5. Fresh motion lane plus a genuinely pipelined reliable edge lane.
6. **Measure input to injection separately** -- it is not in the display
   budget and never was.
7. VideoToolbox decode into `CVPixelBuffer`/IOSurface, Metal presentation.
8. **Measure again.**
9. Native PipeWire DMA-BUF capture, replacing the raw-frame bridge.
10. Slice-based encode and incremental packetization; qualify 60 and
    120 fps.
11. Cursor metadata/shape path.

## What the evidence does not justify

The current artifacts do not justify copying or claiming knowledge of:

- Parsec's proprietary BUD packet formats for input or video slices;
- its precise reliability policy for each input event;
- exact capture, decoder, or render queue depths;
- whether local cursor prediction is used;
- exact thread priorities or realtime scheduling classes;
- a precise decomposition of OpenStream's remaining ~230 ms.

OpenStream does not need those proprietary details. The public platform APIs
and the independently derived freshness/reliability requirements are enough to
build the missing behavior cleanly.

## Sources

[^parsec-arm64]: Supplied Parsec macOS arm64 artifact and retained filtered evidence: [`analysis/strings_arm64.txt`](evidence/parsec-artifact-manifest.md), especially the VideoToolbox/CoreVideo/Metal imports and configuration/latency fields. Access: authorized local artifact, static inspection only.
[^parsec-cursor]: Retained Parsec macOS/Windows strings: [`analysis/strings_arm64.txt`](evidence/parsec-artifact-manifest.md) and [`analysis/strings_win_dll.txt`](evidence/parsec-artifact-manifest.md), including `client_png_cursor`, `_cache_cursor`, relative-mode and detach-mouse indicators. Access: authorized local artifacts, static inspection only.
[^parsec-windows]: Supplied Windows payload and retained imports in [`analysis/strings_win_dll.txt`](evidence/parsec-artifact-manifest.md), including Windows Raw Input APIs. Access: authorized local artifact, static inspection only.
[^parsec-input]: Disassembly of the supplied arm64 payload around the serializer referencing `keyboardTime`, `mouseTime`, `gamepadTime`, and `penTime`; retained strings in [`analysis/strings_arm64.txt`](evidence/parsec-artifact-manifest.md). Access: authorized local artifact, static inspection only.
[^openstream-client]: OpenStream desktop runtime: [`engine/lowlat/crates/desktop-client/src/main.rs`](../../engine/lowlat/crates/desktop-client/src/main.rs).
[^openstream-render]: OpenStream BGRA texture-upload presenter: [`engine/lowlat/crates/desktop-client/src/render.rs`](../../engine/lowlat/crates/desktop-client/src/render.rs).
[^openstream-input]: OpenStream input protocol and currently unused freshness-aware queue: [`engine/lowlat/crates/media/src/input.rs`](../../engine/lowlat/crates/media/src/input.rs); reliable control and scheduler: [`engine/lowlat/crates/client-core/src/lib.rs`](../../engine/lowlat/crates/client-core/src/lib.rs).
[^parsec-immersive]: Parsec, [Immersive Mode Setting](https://support.parsec.app/hc/en-us/articles/32361385571860-Immersive-Mode-Setting).

Additional public context:

- Parsec, [A Networking Protocol Built for Low-Latency Interactive Game Streaming](https://parsec.app/blog/a-networking-protocol-built-for-the-lowest-latency-interactive-game-streaming-1fd5a03a6007).
- Apple, [VTDecompressionOutputCallback](https://developer.apple.com/documentation/videotoolbox/vtdecompressionoutputcallback).
- Apple, [CVMetalTextureCache](https://developer.apple.com/documentation/corevideo/cvmetaltexturecache-q3j).

