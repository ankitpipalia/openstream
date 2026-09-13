# Latency rig runs

Raw telemetry from the physical rig, kept so the figures quoted in
[the gap analysis](../parsec-display-input-latency-gap.md) can be checked
against what the client actually printed.

Rig: macOS arm64 client on the LAN, Linux/NVIDIA host, KDE Wayland captured
through xdg-desktop-portal and PipeWire, h264_nvenc, direct UDP, 2560x1440 at
up to 60 fps. The interaction probe drives `openstream-probe-helper` on the
host desktop.

Every span below is a difference between two readings of one clock.
Percentiles are bucket upper bounds; `mean` and `max` are exact.

## Run A -- 10 Hz helper heartbeat (superseded)

Kept because it is the run that showed a slow heartbeat does not fail
loudly. Decoded 1,119 frames in about 130 s -- roughly 8.6 fps -- because a
portal screencast is damage driven and nothing else on the desktop moved.

```text
stage client FirstFragmentReceived -> LastFragmentReceived  n=1241 p50<=8000us p95<=8000us p99<=16000us max=20891us
stage client LastFragmentReceived -> Reassembled  n=1241 p50<=100us max=45us
stage client Reassembled -> DecoderSubmitted  n=1241 p50<=100us max=77us
stage client frames=1241 stalls=0 in_flight_at_end=0
decoded_frames=1119 never_presented=0
decoder_queue enqueued=1119 dropped_newest=0 closed=0
ui_queue       enqueued=1119 dropped_newest=0 closed=0
decoder_queue_wait         n=1119 p50<=250us  p95<=500us   max=519us
ui_queue_wait              n=1119 p50<=16000us p95<=33000us max=20204us
decoded_to_present_submit  n=1119 p50<=16000us p95<=33000us max=20403us
interaction_to_decoded     n=222 p50<=500000us max=1400456us
probes sent=224 decoded=222 present_submitted=222 abandoned=0 repeat_sightings=0
```

## Run B -- 16 ms heartbeat, probe still sending press and release together

Frame rate recovered to about 43 fps. The interaction figure is meaningless:
the helper recorded 96 keystrokes against 396 probes sent, so nearly every
span is a stale stamp matched to a much later marker. All 391 samples
overflowed the last bucket, which is why every percentile equals the maximum.

```text
stage client FirstFragmentReceived -> LastFragmentReceived  n=8240 p50<=8000us p99<=16000us max=55509us
stage client frames=8240 stalls=0 in_flight_at_end=0
decoded_frames=8117 never_presented=0   (all queues: zero drops)
decoder_queue_wait         n=8117 p50<=250us   p95<=250us   max=1457us
ui_queue_wait              n=8117 p50<=16000us p95<=33000us max=33343us
decoded_to_present_submit  n=8117 p50<=16000us p95<=33000us max=33500us
interaction_to_decoded     n=391 p50<=10182190us p95<=10182190us p99<=10182190us max=10182190us
probes sent=396 decoded=391 present_submitted=391 abandoned=0 repeat_sightings=28
```

## Run C -- press and release on separate ticks

436 helper keystrokes against 445 probes: essentially every probe landed.

```text
stage client FirstFragmentReceived -> LastFragmentReceived  n=9617 p50<=4000us p95<=50000us p99<=75000us max=114616us
stage client frames=9618 stalls=0 in_flight_at_end=0
decoded_frames=9494 never_presented=0   (all queues: zero drops)
decoder_queue_wait         n=9494 p50<=250us   p95<=500us   max=601us
ui_queue_wait              n=9494 p50<=16000us p95<=33000us max=37009us
decoded_to_present_submit  n=9494 p50<=16000us p95<=33000us max=37172us
interaction_to_decoded         n=444 p50<=250000us p95<=250000us p99<=500000us max=265773us
interaction_to_present_submit  n=444 p50<=250000us p95<=250000us p99<=500000us max=272355us
probes sent=445 decoded=444 present_submitted=444 abandoned=0 repeat_sightings=183
```

## Run D -- same build, with the exact mean rendered

The run quoted in the gap analysis. Decoded about 21 fps, roughly half run
C's rate, and carried one outlier past 1.2 s. Neither difference from run C
has been explained.

```text
stage client FirstFragmentReceived -> LastFragmentReceived  n=5376 p50<=500us p95<=8000us p99<=16000us mean=2277us max=102536us
stage client LastFragmentReceived -> Reassembled            n=5376 p50<=100us p95<=100us p99<=100us mean=3us max=181us
stage client Reassembled -> DecoderSubmitted                n=5374 p50<=100us p95<=100us p99<=100us mean=6us max=127us
stage client DecoderSubmitted -> DecodedReady               not-observable
stage client DecodedReady -> HandedToWindow                 not-observable
stage client HandedToWindow -> TakenByWindow                not-observable
stage client TakenByWindow -> PresentSubmitted              not-observable
stage client frames=5384 stalls=0 in_flight_at_end=0

decoded_frames=5251 never_presented=0
decoder_queue enqueued=5251 dropped_newest=0 closed=0
ui_queue      enqueued=5251 dropped_newest=0 closed=0
ui_frames_consumed=5251 new_frames_present_submitted=5251 repeat_present_submissions=0 pending_frames_replaced=0
decoder_queue_wait         n=5251 p50<=250us   p95<=500us   p99<=500us   mean=185us  max=4344us
ui_queue_wait              n=5251 p50<=16000us p95<=33000us p99<=33000us mean=9629us max=26485us
decoded_to_ui_consume      n=5251 p50<=16000us p95<=33000us p99<=33000us mean=9815us max=26698us
decoded_to_present_submit  n=5251 p50<=16000us p95<=33000us p99<=33000us mean=9816us max=26699us

interaction_to_decoded         n=478 p50<=500000us p95<=500000us p99<=500000us mean=285121us max=1229794us overflow=1
interaction_to_present_submit  n=478 p50<=500000us p95<=500000us p99<=500000us mean=295399us max=1242699us overflow=1
probes sent=479 decoded=478 present_submitted=478 abandoned=0 repeat_sightings=43
```

## Reproducing

On the host desktop, with the portal grant held and the capture pipeline
running:

```sh
OPENSTREAM_PROBE_SIZE=2560x1440 openstream-probe-helper
```

On the client:

```sh
OPENSTREAM_PROBE_ORIGIN=0,0 openstream-desktop-client
```

The helper prints the marker origin it is using; the client must be given the
same one. Both reports are written to stderr when the session ends. The probe
is off unless `OPENSTREAM_PROBE_ORIGIN` is set -- it presses a key on the
host -- and the frame-age counters are always on.

## Run E -- corrected instrumentation, commit d6218dc

The rerun after review. Three spans that did not exist before, and the
first rates published at each boundary. Same rig and configuration.

```text
run commit=d6218dc codec=H264 size=2560x1440 fps=60 path=DirectUdp{Host}
run bitrate_mbps=not-visible-from-here  capture=not-visible-from-here
run encoder=not-visible-from-here       decoder=ffmpeg h264
run presenter=Software                  vsync=not-reported-by-presenter
run client_observability=ExternalDecoder

stage client FirstFragmentReceived -> LastFragmentReceived  n=8865 p50<=500us p95<=33000us p99<=100000us mean=5026us max=192140us
stage client LastFragmentReceived  -> Reassembled           n=8865 p50<=100us p95<=100us  p99<=100us    mean=282us  max=289725us
stage client Reassembled           -> DecoderSubmitted      n=8843 p50<=100us p95<=100us  p99<=100us    mean=6us    max=38us
stage client DecoderSubmitted -> ... -> PresentSubmitted    not-observable
stage client frames=8868 rate=26.3/s stalls_observed=0 in_flight_at_end=3

liveness client PacketReceived   n=168475 499.2/s last=2409ms ago
liveness client FrameDecoded     n=8720    25.8/s last=2503ms ago
liveness client FramePresented   n=8720    25.8/s last=2479ms ago

decoded_frames=8720 never_presented=0
decoder_queue enqueued=8720 dropped_newest=0 closed=0
ui_queue      enqueued=8720 dropped_newest=0 closed=0
ui_frames_consumed=8720 new_frames_present_submitted=8720 pending_frames_replaced=0

pixel_unpack               n=8720 p50<=2000us  p95<=4000us  mean=1778us  max=3781us
decoder_queue_wait         n=8720 p50<=250us   p95<=500us   mean=196us   max=572us
ui_queue_wait              n=8720 p50<=16000us p95<=33000us mean=11210us max=36295us
decoded_to_ui_consume      n=8720 p50<=16000us p95<=33000us mean=11406us max=36461us
decoded_to_present_submit  n=8720 p50<=33000us p95<=33000us mean=20684us max=45654us
present_call               n=8720 p50<=16000us p95<=16000us mean=9267us  max=10371us

interaction_to_decoded         n=591 mean=297596us max=1297537us overflow=1
interaction_to_present_submit  n=591 mean=317184us max=1323212us overflow=1
probes sent=603 decoded=591 present_submitted=591 abandoned=12 repeat_sightings=322
probe timeouts=11 outstanding_at_end=0
```

Helper, same run:

```text
601 events, marker now 601, uploads=14609 43.6/s mean=4535us max=13301us
```

### What changed, and why each change mattered

**`present_call mean=9267us`.** Entirely invisible before, because the
submit stamp was taken before the presenter was called. The software
presenter costs 9.3 ms per frame at this resolution, p95 under 16 ms. The
same fix moved `decoded_to_present_submit` from 9.8 ms to 20.7 ms: roughly
half of decode-to-present is the presenter call itself.

**`pixel_unpack mean=1778us`.** Also invisible before, sitting in front of
the clock. The raw-to-BGRA conversion costs 1.8 ms per frame.

**Reorder waiting is finally in the reassembly span.** `LastFragmentReceived
-> Reassembled` went from a 3 us mean over immediately-releasable frames to a
282 us mean with a **290 ms** tail once held frames were included. The old
figure was a selected population, exactly as review predicted.

**`in_flight_at_end=3`**, which could only ever print zero before.

**The probe timeout fired 11 times** at the end of the run, when the host was
stopped and the marker stopped advancing. Previously that state was silent.

### What the rates say about the C/D spread

```text
helper surface uploads   43.6/s   (requested 62.5; each upload costs 4.5 ms)
client fragments         499.2/s
client frames decoded    25.8/s
client frames presented  25.8/s
```

Two things are now visible that were not. The helper does not achieve its
requested heartbeat -- 43.6/s against 62.5 -- because each full-surface
upload takes 4.5 ms. And the client decodes 25.8/s against the helper's
43.6/s, so frames are being lost to rate somewhere between the helper's
upload and the client's decoder.

Client CPU is a candidate: 1.8 ms of pixel unpack plus 9.3 ms of presenter
call is 11 ms per frame, and 1/0.011 is about 90/s, so it does not explain
26/s on its own. **Where the rate is actually lost is not established.** The
host side is still `not-observable`, and no host-side rate was published in
this run.
