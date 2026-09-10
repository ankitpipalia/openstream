# Portable Packet Scheduling and Delivery Telemetry

**Status:** approved for implementation planning
**Date:** 2026-09-10
**Scope:** portable `PeerSession` transport only

## Goal

Give the portable OpenStream session a bounded outbound scheduler and
authenticated packet-delivery telemetry without coupling it to the Linux
lowlat I/O shell, changing the cryptographic session, or treating local socket
write rate as network capacity.

The result is an independent OpenStream transport feature. It does not claim
compatibility with Parsec's proprietary BUD protocol.

## Current boundary

`PeerSession::send()` currently seals a packet and writes it immediately to the
selected `UdpTransport` or ICE connection. `PeerTransportSnapshot` reports
local socket counters, but the portable path has no acknowledgement of the
authenticated outer counters and therefore cannot measure acknowledged
delivery rate, packet in-flight pressure, or packet-level RTT.

The existing `openstream-transport-policy` crate owns deterministic pacing and
congestion policy. The portable session owns Tokio I/O, encryption, path
migration, and media/control semantics. This change adds a fixed-size delivery
estimator to the policy crate, a protocol-owned transport-meta acknowledgement,
and a session-owned queue/scheduler around those policy primitives.

## Scope and non-goals

In scope:

- A bounded four-class outbound scheduler for portable `PeerSession`.
- A reserved authenticated transport-meta ACK record using the existing
  encrypted `Kind::Control` packet.
- A fixed-size packet delivery estimator with path-generation isolation.
- A conservative portable pacing configuration based on the actual current
  OpenStream sealed datagram ceiling.
- Compatibility and non-blocking APIs that prevent normal media call sites
  from bypassing the scheduler.
- Diagnostics that expose aggregate and video-specific packet-delivery data.
- Deterministic unit, integration, and stress tests for the specified edge
  cases.

Out of scope:

- Replacing `FrameAck` or changing its encoder-facing semantics.
- Packet retransmission of media. `ReliableControl` logical retries remain
  separate from retransmission of one encrypted outer packet.
- DPLPMTUD implementation for the portable path. The scheduler must accept a
  future path datagram-size update, but this phase starts and remains at the
  current portable wire ceiling.
- A `webrtc-ice` upgrade or manual ICE candidate nomination.
- Native macOS/Windows capture, encode, decode, or presentation.
- Stock Parsec/BUD interoperability.

## Normative invariants

1. Transport ACKs are transport-meta records, never `ReliableControl` frames.
   They are intercepted before ordered-control decoding, are non-ack-eliciting,
   are excluded from delivery accounting, are never retransmitted by
   `ReliableControl`, and are coalesced rather than queued.
2. Every transport ACK carries a bounded `ack_delay_us` for the largest
   acknowledged packet. RTT sampling subtracts only that receiver-controlled
   delay and uses the largest newly acknowledged ack-eliciting packet.
3. The ACK bitmap has an exact mathematical meaning: bit 0 acknowledges
   `largest_counter`; bit `n` acknowledges `largest_counter - n` for
   `1 <= n < 64`. A set bit that would underflow the counter is invalid.
4. ACKs are irrevocable. Once an outer counter is acknowledged, a later ACK
   with a smaller bitmap cannot make it outstanding again.
5. An ACK with `largest_counter` above the highest outer counter sent for its
   generation is rejected without mutating estimator state. An ACK for an old
   generation is ignored without mutating the current generation.
6. Every delivery-history slot retains the complete identity
   `{generation, outer_counter, bytes, sent_at_ms, traffic_class,
   ack_eliciting, logical_retransmission}`. A modulo-ring collision may never
   acknowledge a newer entry using an old counter. An unresolved entry that
   ages out is explicitly classified as stale/lost before replacement; it is
   never silently forgotten.
7. `ReliableControl::retry()` creates a newly sealed outer packet with a new
   cipher counter. It is recorded as a logical reliable-control retry, not as a
   retransmission of the original outer packet. Only a future scheduler-level
   resend of the same sealed bytes may be counted as an outer retransmission.
8. The public compatibility `PeerSession::send()` path routes application
   video, audio, input, and ordinary control through the scheduler once the
   session is established. Immediate sending is private and is used only for
   setup/path-control and coalesced transport-meta ACK records.
9. Queue saturation is class-specific: critical control/input returns bounded
   backpressure, audio drops the oldest queued audio packet to preserve a
   recent bounded queue, video drops the oldest queued video packet and reports
   the drop, and transport ACKs replace one coalesced pending record.
10. Priority service is bounded. ACK/meta traffic is immediate; critical
    control/input and audio receive finite service quanta; video consumes the
    remaining paced budget. Continuous priority traffic cannot starve video
    forever.
11. The pacer consumes encrypted wire bytes, not encoder payload bitrate. The
    portable scheduler has a named wire-rate configuration. No API silently
    equates an encoder bitrate with a wire pacing rate or uses local send rate
    as encoder capacity.
12. A path-generation change atomically resets the delivery estimator,
    path-local RTT/rate state, ACK receive window, and pacer credit while
    preserving the one global `CipherSession`, its outer counter/replay domain,
    reliable-control logical sequence space, frame IDs, and `FrameAck` history.
13. Packets and ACKs from generation N cannot mutate generation N+1 delivery
    state. Late best-effort media may be discarded by the existing replay and
    migration rules.

## Transport-meta ACK wire record

The record is carried as an authenticated `Kind::Control` packet on reserved
channel `254`. Path-control remains on channel `255`; ordered application
control remains on its existing channels. A transport-meta ACK is not an
ordered-control frame and must be recognized by channel before attempting
`ControlFrame::decode`.

The v1 record is exactly 32 bytes:

```text
offset  size  field
0       1     version = 1
1       1     record_type = ACK (1)
2       2     reserved = 0
4       8     path_generation, big-endian u64
12      8     largest_counter, big-endian u64
20      8     received_mask, big-endian u64
28      4     ack_delay_us, big-endian u32
```

`MAX_ACK_DELAY_US` is `25_000`. Encoders must reject a larger delay rather
than wrap it; decoders must reject non-zero reserved bytes, an unsupported
version/type, counter-underflow bits, or a delay above that bound.

The receiver's receive window is the same 64-counter recent window used by
the record. The receiver tracks only authenticated, active-generation,
ack-eliciting application packets. It does not track transport-meta ACKs,
path-control records, path probes, or keepalive records.

The receiver emits an ACK when any of these conditions is true:

- `packet_threshold` ack-eliciting packets are pending;
- `max_delay` has elapsed since the packet that made an ACK pending;
- an out-of-order or gap-filling packet arrives.

The default configuration is `packet_threshold = 2` and `max_delay = 2 ms`.
Both values are session policy configuration, not wire-format fields. The
threshold must be at least one and the delay must be positive and no larger
than `MAX_ACK_DELAY_US`. The ACK for the largest counter reports the elapsed
time since that largest counter arrived, capped by the validated maximum.

The ACK is sent on the current active path through the private immediate
meta-send function. It is never added to the application scheduler and never
causes the receiver to schedule another ACK.

## Delivery estimator

`openstream-transport-policy::DeliveryEstimator` is dependency-free and
`#![no_std]`, like the existing pacer. It has
`DELIVERY_HISTORY_CAPACITY = 256`, `STALE_AFTER_MS = 250.0`, and a minimum
delivery-rate sample interval of `10.0 ms`.

The estimator accepts these exact operations:

```rust
pub fn new(generation: u64) -> Self;
pub fn can_record(&self, generation: u64, outer_counter: u64, now_ms: f64) -> bool;
pub fn record_sent(&mut self, packet: SentPacket) -> Result<SendOutcome, DeliveryError>;
pub fn acknowledge(
    &mut self,
    generation: u64,
    largest_counter: u64,
    received_mask: u64,
    ack_delay_us: u32,
    now_ms: f64,
) -> Result<AckOutcome, DeliveryError>;
pub fn snapshot(&mut self, now_ms: f64) -> DeliverySnapshot;
pub fn reset_generation(&mut self, generation: u64);
```

`SentPacket` contains:

```rust
pub struct SentPacket {
    pub generation: u64,
    pub outer_counter: u64,
    pub bytes: u32,
    pub sent_at_ms: f64,
    pub traffic_class: TrafficClass,
    pub ack_eliciting: bool,
    pub logical_retransmission: bool,
}
```

Only `ack_eliciting` entries occupy delivery-history slots. The full identity
is still retained in every occupied slot. `can_record` is checked before
sealing the next packet; if the matching slot is unresolved and younger than
`STALE_AFTER_MS`, the scheduler applies bounded backpressure. If it is older,
`record_sent` returns an explicit stale eviction and records it in the
snapshot.

`acknowledge` first validates the generation and future-counter rule. It then
walks set bitmap bits, matches the complete generation/counter identity in the
corresponding slot, and retires each match at most once. Missing or already
retired entries are harmless; they cannot acknowledge a different entry that
later occupies the same modulo slot. A successful ACK reports newly
acknowledged counts/bytes and an optional RTT sample. A duplicate ACK reports
zero newly acknowledged bytes and cannot change SRTT or delivery totals.

RTT is measured from the largest newly acknowledged entry that is present in
the history:

```text
sample_ms = max(0, now_ms - sent_at_ms - ack_delay_us / 1000.0)
```

The first sample seeds SRTT. Later samples use the fixed EWMA
`srtt = 7/8 * srtt + 1/8 * sample`. Delivery rate is acknowledged unique wire
bytes divided by the elapsed delivery sample interval and is expressed in
decimal Mbps. The estimator reports aggregate and per-class counters for
`Critical`, `Audio`, and `Video`; input is classified as `Critical`.

The estimator's packet retransmission count includes only an identical outer
counter recorded again by an explicitly supported future resend path. A
`logical_retransmission` flag on a newly sealed packet is reported separately
and never changes the outer packet retransmission count.

## Portable outbound scheduler

`client-core/src/scheduler.rs` owns the Tokio-independent queue policy around
the shared pacer. It stores clear packet fields until emission so queued
packets do not consume cipher counters. Each emission seals exactly once and
records the resulting outer counter and full encrypted wire length in the
delivery estimator after a successful socket write.

The classes and default capacities are:

```text
Critical control/input    256 packets; reject new packets when full
Audio                      32 packets; drop oldest on saturation
Video                     256 packets; drop oldest on saturation
Transport ACK               0 packets; one coalesced meta record outside queues
```

The current portable protocol's `openstream_protocol::MAX_DATAGRAM` is `1200`
bytes including its 16-byte header and 16-byte GCM tag. Until portable PMTU
discovery exists, the scheduler constructs a validated pacer configuration
with minimum and maximum datagram size both equal to that actual `1200`-byte
sealed wire ceiling. The lowlat policy crate's `1229`-byte compatibility
default remains unchanged because it belongs to the separate lowlat protocol
path. This explicit configuration prevents the portable path from assuming a
larger packet than its wire decoder accepts.

The default portable `wire_rate_mbps` is `30.0`. It is a wire-rate ceiling and
is independently configurable through `PeerSession::set_wire_pacing_rate`.
The scheduler never reads an encoder bitrate to set it. A disabled rate is not
the default; setting zero explicitly disables pacing for a controlled test.

Priority service uses a persistent per-class quantum. The quantum is the
larger of one current wire datagram and the smaller of four current datagrams
or `2 ms` of the configured wire rate. A priority class yields once its
quantum is spent while a lower class has due work. A class with no lower due
work can drain its bounded queue. After a lower class is serviced, the
priority debt resets. Video is emitted only when the pacer can consume its
full sealed wire length. `next_wake_ms` returns the pacer's exact refill wait
when video is the next serviceable work.

The session APIs are:

```rust
pub fn queue(
    &mut self,
    kind: Kind,
    channel: u8,
    flags: u8,
    payload: &[u8],
) -> Result<QueueOutcome, Error>;

pub async fn flush_outbound(&mut self) -> Result<FlushReport, Error>;
pub fn next_outbound_wake(&self) -> Option<Duration>;
pub fn outbound_pending(&self) -> usize;
pub fn set_wire_pacing_rate(&mut self, rate_mbps: f64) -> Result<(), Error>;
```

`send()` remains for setup-sized and compatibility callers, but it queues the
application packet and drives `flush_outbound` until that packet is emitted.
It is not a direct-write escape hatch. New streaming loops use `queue` plus
`flush_outbound` and the scheduler timer so a video wait does not block
receiving ACKs or control. Only private typed methods may use the immediate
path: `send_path_control` and `send_transport_ack`.

## Session receive and generation behavior

`PeerSession::recv_step` opens one encrypted packet, then applies this order:

1. Discard invalid/authentication failures according to the existing
   migration behavior.
2. Intercept channel `254`; decode `TransportAck`, validate it against the
   current generation estimator, and return no application packet.
3. Intercept path-control channel `255` and retain existing migration behavior.
4. Classify internal keepalives and path probes without delivery accounting.
5. For an active-generation application packet, update the ACK receive window
   and send an immediate coalesced ACK when its policy says due.
6. Record the existing local counters and return the application packet.

An ACK arriving through a draining ingress is not allowed to mutate the active
generation estimator. Application packets from a draining path retain the
existing bounded receive-only behavior; they do not create ACK state for the
new generation.

When migration activates generation N+1, the session performs one synchronous
reset boundary: it resets scheduler pacing credit, delivery estimator,
transport ACK window, path sample baseline, and ICE/direct path counters
before the next application emission. The cipher object and all application
logical sequence/frame feedback objects remain untouched.

## Telemetry contract

`PeerTransportSnapshot` remains the local path observation and keeps its
existing meaning. A separate `PeerDeliverySnapshot` exposes:

```text
path_generation
sample_interval_ms
srtt_ms
aggregate delivery class snapshot
video delivery class snapshot
audio delivery class snapshot
critical delivery class snapshot
```

Each class snapshot includes sent/acknowledged packet and wire-byte totals,
delivery rate, in-flight count, stale count, logical reliable retries, and
outer retransmissions. Missing packet evidence is represented as `None` and
is never fabricated from local socket writes.

`PeerTelemetryAdapter` may observe and publish this snapshot for diagnostics,
but `AdaptiveBitrate` continues to change encoder decisions only from
`FrameAck`, frame gaps, and acknowledgement age. Packet delivery is a second
signal, not a replacement. Local send rate remains diagnostic/path pressure,
not encoder capacity.

## Error handling and resource bounds

- Invalid transport-meta records produce a bounded `InvalidMessage` error and
  never allocate based on a peer-provided length.
- Future-counter ACKs are rejected without estimator mutation.
- Stale-generation ACKs are ignored and counted only in diagnostics.
- Invalid timestamps, counter overflow, and non-finite pacing rates fail
  closed without moving monotonic clocks backward.
- A full critical queue returns a typed `OutboundBackpressure` error.
- Audio/video drops are bounded and reported; they never grow memory or block
  the receive loop indefinitely.
- An estimator history full condition prevents sealing another tracked packet
  until an ACK or explicit stale classification frees a slot.
- Path migration and `close()` clear queue ownership and ACK state without
  creating a background task that can retain credentials indefinitely.

## Required verification

The implementation is not complete until the following deterministic cases are
covered:

- transport-meta encode/decode, reserved fields, version/type, delay bound;
- ACK bitmap math, counter underflow, ACK loss, duplicate ACKs, irrevocability;
- impossible future counters and stale-generation ACK isolation;
- ACK-of-ACK suppression and coalescing threshold/timer/out-of-order behavior;
- estimator RTT with ACK-delay subtraction and delivery-rate units;
- estimator ring wrap/aliasing, unresolved-history backpressure, explicit stale
  eviction, and logical-control retry distinction;
- scheduler queue saturation for all classes;
- persistent priority quanta with continuous control traffic and video service;
- video pacer refusal/refill and exact next-wake timing;
- portable pacer starts at 1200 actual sealed bytes, not 2000 or encoder rate;
- no normal media call site invokes an immediate send path;
- two-session authenticated packet ACK delivery over loopback;
- ACK loss, >64-counter reordering, duplicate packets, constrained ACK
  bandwidth behavior, and late old-generation ACKs during migration;
- atomic path-generation reset preserving cipher counter and `FrameAck` history;
- full locked workspace tests, Clippy with warnings denied, fuzz harness
  compilation, release build, cargo-deny, and the existing smoke checks.

The synthetic network acceptance harness must report that packet telemetry and
`FrameAck` remain separate, and it must not claim external coturn, public NAT,
hardware capture, or native zero-copy media acceptance.
