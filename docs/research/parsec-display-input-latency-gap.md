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
                         measured: see First instrumented measurement
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

**That instrumentation now exists and has been run.** See
[First instrumented measurement](#first-instrumented-measurement-on-442dd2b)
for the first attempt and
[the corrected rerun](#corrected-rerun-on-d6218dc) for what it says after
review. One candidate is ruled out: nothing was dropped by either
decoded-frame handoff, in either run.

The corrected rerun contradicts the fourth candidate in the other
direction. Presentation scheduling is not merely untied to refresh -- **the
presenter call itself costs 9.3 ms per frame** at 2560x1440, which nothing
had measured, and the raw-to-BGRA conversion costs another 1.8 ms. Both sat
outside the first run's clock.

**The rest of that first run's conclusions have been retracted.** Review found
three measurement holes that made the numbers describe less than they
appeared to, all since fixed and none yet re-measured:

- the reassembly span was computed only for frames the assembler could
  release immediately, so frames held in the reorder buffer -- the population
  the span exists to expose -- were absent from it;
- the client's raw-to-BGRA pixel conversion happened before the frame clock
  started, so several megabytes of per-frame CPU work sat outside every span;
- `present_submit` was stamped before the presenter was called, so texture
  upload, surface acquisition and the blit were all excluded, and a frame
  whose presenter call then failed had already been counted as presented.

So "client frame movement is ruled out" was not supported by that run. It may
still be true; it has not been measured.

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

## First instrumented measurement on 442dd2b

The single-clock replacement described above now exists and has been run on
the rig. Same hardware, KDE Wayland over the portal, NVENC, direct UDP, but
at **2560x1440 / 60 fps** rather than 1920x1080 / 30 -- native resolution, so
the probe marker reaches the client unscaled.

No screenshots, no OCR, no cross-host clock offset. Every number below is a
difference between two readings of one clock.

### Client stage spans, keyed by host frame id

```text
FirstFragmentReceived -> LastFragmentReceived  n=5376 p50<=500us  p95<=8000us mean=2277us max=102536us
LastFragmentReceived  -> Reassembled           n=5376 p50<=100us  p95<=100us  mean=3us    max=181us
Reassembled           -> DecoderSubmitted      n=5374 p50<=100us  p95<=100us  mean=6us    max=127us
DecoderSubmitted      -> DecodedReady          not-observable
DecodedReady          -> HandedToWindow        not-observable
HandedToWindow        -> TakenByWindow         not-observable
TakenByWindow         -> PresentSubmitted      not-observable
frames=5384 stalls=0 in_flight_at_end=0
```

Percentiles are bucket upper bounds; `mean` and `max` are exact.

The four `not-observable` rows are not a gap in the instrumentation. FFmpeg
does not return the frame id it was given, so nothing the client stamps after
submission can be attributed to a host frame without inventing the
correspondence. Those stages are measured instead by decoded sequence number,
below.

### Client frame age, keyed by decoded sequence number

```text
decoded_frames=5251 never_presented=0
decoder_queue enqueued=5251 dropped_newest=0 closed=0
ui_queue      enqueued=5251 dropped_newest=0 closed=0
ui_frames_consumed=5251 new_frames_present_submitted=5251 pending_frames_replaced=0

decoder_queue_wait         n=5251 p50<=250us   p95<=500us   mean=185us  max=4344us
ui_queue_wait              n=5251 p50<=16000us p95<=33000us mean=9629us max=26485us
decoded_to_ui_consume      n=5251 p50<=16000us p95<=33000us mean=9815us max=26698us
decoded_to_present_submit  n=5251 p50<=16000us p95<=33000us mean=9816us max=26699us
```

`present_submit` is the moment the window hands a buffer to the presenter. It
is not photon time; the compositor's queueing, the swap and the panel are
outside the process and unmeasured.

### Interaction latency, on the client's clock alone

```text
interaction_to_decoded         n=478 p50<=500000us mean=285121us max=1229794us overflow=1
interaction_to_present_submit  n=478 p50<=500000us mean=295399us max=1242699us overflow=1
probes sent=479 decoded=478 present_submitted=478 abandoned=0 repeat_sightings=43
```

The probe id travels on an ordinary injected keystroke, so this span includes
the client's input path, the network, host uinput injection, the helper's own
response to the event, compositor redraw, portal capture, encode, network and
decode.

### What the table establishes, after review

Review of the instrumentation found that three of these spans measured less
than they appeared to. What survives, and what does not:

**Stands.** Nothing was dropped: zero drops in either bounded queue, zero
frames consumed and replaced, across 5,251 decoded pictures. That matters
because a dropped frame leaves no span sample at all -- before these counters
a client discarding half its output would have shown the same healthy
distribution as one dropping none. Stale-frame dropping and backpressure were
not responsible for this run's latency.

**Retracted -- the reassembly figure.** `Assembler::push` returns the frame
that became *releasable*, which is frequently an older frame than the one the
arriving fragment just completed, and it returns nothing at all when a frame
completes while an older one is missing. Completion was stamped only on the
returning branch, so every frame held in the reorder buffer was missing from
both adjacent spans. The 3us mean describes a population selected to contain
no reorder waiting, measured by the span whose purpose is to expose reorder
waiting.

**Retracted -- "client frame handling is ruled out".** The raw-to-BGRA
conversion ran before `decoded_at` was stamped, so roughly 3.7 million pixels
and a 15 MB allocation per picture sat outside every span. It may be cheap.
Nothing here measured it.

**Retracted -- the 10 ms decode-to-present figure as a bound on client
presentation cost.** `present_submit` was stamped before the presenter was
called, so GPU texture upload, surface acquisition and the software blit are
all outside that 10 ms, and a frame whose presenter call subsequently failed
had already been counted as submitted.

**Stands, weakly.** Most of the interaction span is still somewhere this
branch could not see. That remains the shape of the problem; the proportion
should not be quoted until the reruns land.

**`stalls=0` was not an observation.** Nothing in that run classified a frame
as stalled, because nothing was watching -- the liveness machinery existed
and was not wired. It is now.

### What it does not establish, and the run-to-run spread

Two consecutive runs of the same build differed materially:

```text
Run C  interaction_to_decoded  n=444 p50<=250000us max=265773us   ~44 fps decoded
Run D  interaction_to_decoded  n=478 mean=285121us max=1229794us  ~21 fps decoded
```

Run D decoded at roughly half run C's frame rate and carried a single
outlier past 1.2 s. **Neither difference has been explained.** They are
recorded here rather than averaged away, and no figure from either run should
be quoted as OpenStream's interaction latency until the spread is understood.

What was missing was a rate at each boundary. The helper's 16 ms heartbeat is
a *requested* upload interval and was never evidence it achieved sixty
uploads per second. The helper now publishes uploads per second and their
duration, the stage report carries frames per second on both sides, and the
client's liveness watch reports per-milestone rates. Whichever boundary first
drops from ~44/s to ~21/s is where to look; until a run produces those
numbers, attributing the spread to the portal, NVENC, the network, the
decoder or the helper would be guessing.

The bucket edges are also too coarse at this range: 150 ms and 250 ms are
adjacent edges, so a median anywhere between them renders identically. That
is why the exact mean is now carried beside the percentiles.

Raw telemetry for every run, including the two superseded ones, is in
[latency-rig-runs.md](evidence/latency-rig-runs.md), along with how to
reproduce them.

## Corrected rerun on d6218dc

Same rig and configuration, after the six defects below were fixed. Three
spans exist here that did not exist in the first run, and every boundary now
publishes a rate. Full telemetry:
[latency-rig-runs.md](evidence/latency-rig-runs.md).

```text
pixel_unpack               n=8720 mean=1778us  max=3781us
decoder_queue_wait         n=8720 mean=196us   max=572us
ui_queue_wait              n=8720 mean=11210us max=36295us
decoded_to_present_submit  n=8720 mean=20684us max=45654us
present_call               n=8720 mean=9267us  max=10371us

LastFragmentReceived -> Reassembled  n=8865 mean=282us max=289725us

interaction_to_decoded  n=591 mean=297596us max=1297537us overflow=1
probes sent=603 decoded=591 present_submitted=591 abandoned=12 timeouts=11
```

Three measurements that did not exist before:

- **The presenter call costs 9.3 ms**, p95 under 16 ms. `present_submit` used
  to be stamped before the call, so texture upload, surface acquisition and
  the software blit were all outside it. The same fix moved
  `decoded_to_present_submit` from 9.8 ms to 20.7 ms -- roughly half of
  decode-to-present is the presenter call.
- **The pixel conversion costs 1.8 ms**, which the first run's clock started
  after.
- **Reorder waiting has a 290 ms tail.** The reassembly span went from a 3 us
  mean over immediately-releasable frames to a 282 us mean once held frames
  were included in it.

And the rates, which is what the C/D spread needed:

```text
helper surface uploads   43.6/s   (requested 62.5; each upload costs 4.5 ms)
client fragments         499.2/s
client frames decoded     25.8/s
client frames presented   25.8/s
```

The helper does not achieve its requested heartbeat, and the client decodes
26/s against the helper's 44/s. Client CPU is a candidate but not a
sufficient one -- 1.8 ms of unpack plus 9.3 ms of present is 11 ms per frame,
which would allow about 90/s. **Where the rate is lost between the helper and
the decoder is not established**, and the host side is still
`not-observable`, so the next instrumentation belongs there.

Zero drops again, in both bounded queues, across 8,720 decoded pictures.

### Six defects found in the instrumentation itself

Three surfaced on the rig and three in review. Every one of them reported a
number instead of failing, which is the failure mode this instrumentation
exists to prevent -- and the fact that half were invisible from the rig is
the argument for reading the instrumentation as carefully as the results.

Recorded because each was a measurement reporting a number rather than
failing, which is the failure mode this instrumentation exists to prevent.

1. **The probe report rendered an empty histogram as `n=0 p50<=-us ...
   max=0us`.** A dash where there was no measurement, and beside it a zero
   claiming the slowest interaction took no time. It now renders
   `no-samples`, like every other unmeasured span.
2. **A 10 Hz helper heartbeat produced an 8.6 fps stream.** A portal
   screencast is damage driven; a helper that only redraws on input leaves
   the desktop static and the capture idle. The reported interaction latency
   was drawn from a stream nobody would run. The heartbeat now defaults to
   16 ms and is documented as deciding what the probe measures.
3. **Press and release sent back to back lost three keystrokes in four.** The
   helper sees a keypress as a down transition between two polls; a pair
   delivered inside one poll interval collapses into nothing. Each lost
   keystroke then made the client re-send an id already outstanding, and when
   the helper finally advanced, the match landed on the oldest stamp carrying
   that id -- reporting a **10.18 second** interaction latency that was
   really a lost keystroke. Press and release now go out on separate ticks,
   and an id is sent once.

Found in review of the instrumentation, not from the rig:

4. **Frames held in the reorder buffer never received their completion
   stamp**, because completion was keyed on `Assembler::push` returning a
   frame -- and the frame it returns is the one that became *releasable*,
   often an older one. The reassembly span was therefore measured on the
   population that had no reorder waiting in it.
5. **A retransmission of an already-assembled frame opened a stage timeline
   that could never finish.** `push` returned the same `Ok(None)` for
   "ignored duplicate" and "accepted, still incomplete", so the client could
   not tell them apart; the ghost timelines then displaced real ones from the
   recorder's bounded window. `PushOutcome` now states the lifecycle.
6. **An out-of-order pair of timestamps became a zero-microsecond sample.**
   `Stamp::since` saturated, so a bug in the caller's ordering was
   indistinguishable from a genuinely fast frame and dragged every statistic
   it entered towards zero. It now returns `None`, and the count of rejected
   attempts is published beside each span.

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

