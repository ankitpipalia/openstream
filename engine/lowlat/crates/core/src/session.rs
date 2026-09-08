//! The sans-IO session: bytes in, bytes out, time as a parameter.
//!
//! This is the whole protocol core behind one object. It reads no clock, owns
//! no socket, spawns no thread, and allocates nothing. The shell drives it:
//!
//! ```text
//! loop:
//!     timeout = session.next_timer_ms(now)
//!     wait for a packet, an application send, or that timeout
//!     for each datagram:  session.process_input(bytes, now)
//!     drain:              while let Some(n) = session.get_output(now, buf) { send(buf[..n]) }
//! ```
//!
//! Storage for the per-channel rings is lent by the caller, so a session that
//! carries only control and video costs two rings rather than nineteen.

use crate::channel::RecvRing;
use crate::congestion::Controller;
use crate::envelope::{Direction, ENVELOPE_LEN, Envelope};
use crate::error::{Error, Result};
use crate::message::Message;
use crate::pacer::Pacer;
use crate::packet::{self, Ack, AckKind, CHANNEL_COUNT, Packet};
use crate::send::SendRing;

/// Longest gap between group acknowledgements while a session is alive.
pub const ACK_CADENCE_MS: f64 = 30.0;
/// No progress for this long is a soft failure.
pub const LIVENESS_SOFT_MS: f64 = 60_000.0;
/// No progress for this long is a hard failure.
pub const LIVENESS_HARD_MS: f64 = 120_000.0;
/// Data outstanding with none of it acknowledged for this long is a hard
/// failure of its own.
///
/// **A different question from the two deadlines above, and a much shorter
/// one.** Those ask whether anything arrives, which a peer that keeps
/// acknowledging on the cadence while receiving nothing satisfies for ever;
/// everything queued for it is retransmitted for exactly as long. A congested
/// path recovers inside a few seconds and acknowledges throughout, so a window
/// that has moved by nothing in fifteen is not congestion.
pub const DELIVERY_DEADLINE_MS: f64 = 15_000.0;

/// Weight given to a new round-trip sample.
const SRTT_ALPHA: f64 = 0.1;
/// Avoid turning a fast event-loop tick into a bursty one-millisecond rate
/// sample. The controller retains the last sample until this interval elapses.
const TRANSPORT_SAMPLE_MIN_MS: f64 = 100.0;

/// The host-to-guest video channel. The session owns the transport mechanics,
/// so keeping this semantic channel here lets its controller and pacer make
/// the same choice without treating control/audio traffic as video capacity.
pub const VIDEO_CHANNEL: u8 = 1;
/// The host-to-guest audio channel, which is scheduled ahead of bulk video.
pub const AUDIO_CHANNEL: u8 = 2;

const CONTROL_CHANNEL_INDEX: usize = crate::control::CONTROL_CHANNEL as usize;
const AUDIO_CHANNEL_INDEX: usize = AUDIO_CHANNEL as usize;

/// Maximum unpaced control bytes released before a lower-priority channel gets
/// a turn, when channel 0 has a backlog. Channel 0 is one ordered stream that
/// combines input and control, so the scheduler cannot safely move a later
/// input message ahead of an earlier control fragment without changing the
/// wire protocol. A bounded quantum is the safe protection against a bulk
/// control transfer becoming an unbounded pre-video burst.
pub const CONTROL_PRIORITY_QUANTUM_BYTES: usize =
    crate::DEFAULT_DATAGRAM * crate::pacer::MAX_BURST_DATAGRAMS;

/// Maximum unpaced audio bytes released before bulk video gets a turn.
pub const AUDIO_PRIORITY_QUANTUM_BYTES: usize =
    crate::DEFAULT_DATAGRAM * crate::pacer::MAX_BURST_DATAGRAMS;

/// Output order after an acknowledgement has been emitted. Channel 0 carries
/// control and input, so it is latency-sensitive; audio is small and should
/// stay ahead of bulk video. The remaining channels retain their numeric
/// order for forward compatibility.
const DRAIN_ORDER: [usize; CHANNEL_COUNT] = [
    0, 2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
];

/// What a datagram turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// A fragment was stored on this channel.
    Data { channel: u8 },
    /// An acknowledgement, which may have advanced windows.
    Ack,
    /// A keepalive.
    Keepalive,
    /// Well formed but not for a channel we hold a ring for.
    Unhandled { channel: u8 },
}

/// How the session is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Alive,
    /// No progress for [`LIVENESS_SOFT_MS`].
    Stalled,
    /// No progress for [`LIVENESS_HARD_MS`]. Tear down.
    Dead,
    /// Data has been outstanding and unacknowledged for
    /// [`DELIVERY_DEADLINE_MS`]. Tear down.
    ///
    /// **Distinct from [`Health::Dead`] because the cause is.** Dead is a peer
    /// that says nothing; this is a peer that still speaks and has stopped
    /// receiving, and the two are told apart only by whether a window moves.
    Undeliverable,
}

/// A bounded snapshot of the packet-level transport signals available to the
/// sans-IO session.
///
/// The byte counters are cumulative and the rates are calculated over a
/// minimum-sized sampling interval. `bytes_acked` is payload covered by the
/// peer's cumulative acknowledgements, so `delivery_rate_mbps` describes what
/// the path delivered rather than what the sender attempted to put on the
/// socket. Rates use decimal megabits per second, matching
/// [`crate::congestion::Controller`]. No peer clock or address is included.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TransportStats {
    /// Duration of the last rate sample. Zero until the first sample exists.
    pub interval_ms: f64,
    /// Fragments currently in the send windows.
    pub in_flight: u32,
    /// Fragments classified as stale during the last send scan.
    pub stale: u32,
    /// Payload bytes handed to the wire, including retransmissions.
    pub bytes_sent: u64,
    /// Payload bytes covered by cumulative acknowledgements.
    pub bytes_acked: u64,
    /// Retransmission transmissions since the session began.
    pub retransmitted_fragments: u64,
    /// Attempted payload rate over the last sample interval, in decimal
    /// megabits/s.
    pub send_rate_mbps: f64,
    /// Delivered payload rate over the last sample interval, in decimal
    /// megabits/s.
    pub delivery_rate_mbps: f64,
    /// Smoothed fragment round trip in fractional milliseconds.
    pub srtt_ms: f64,
}

/// One channel's delivery progress.
#[derive(Debug, Clone, Copy)]
struct Delivery {
    /// The channel's acknowledged count when it last moved.
    acked_seen: u64,
    /// When that was. **Seeded at construction and refreshed by every poll
    /// that finds the channel empty**, which is what a ring attached after
    /// construction relies on: nothing can be outstanding on it before it has
    /// been given something to send.
    since_ms: f64,
}

/// One peer-to-peer session.
#[derive(Debug)]
pub struct Session<'a> {
    envelope: Envelope,
    /// Which direction this side seals. The peer is expected to seal the
    /// opposite bit; [`Session::process_input`] rejects anything else before
    /// decryption so a (key, nonce) pair is never reused across directions.
    direction: Direction,
    recv: [Option<RecvRing<'a>>; CHANNEL_COUNT],
    send: [Option<SendRing<'a>>; CHANNEL_COUNT],
    controller: Controller,
    level: usize,

    /// Monotonic per sender, bit 63 reserved for [`Direction`]. Never reused:
    /// a wrap would repeat a nonce.
    tx_counter: u64,
    srtt_ms: f64,
    srtt_seeded: bool,

    last_ack_sent_ms: f64,
    last_progress_ms: f64,
    /// Per channel, when delivery on it last made progress.
    ///
    /// **Per channel and not per session.** A peer that has stopped draining
    /// one ring keeps acknowledging the others, and it is the busy channel
    /// that backs up: a figure summed across all of them is refreshed by the
    /// cheap traffic and never reports the expensive traffic going nowhere.
    delivery: [Delivery; CHANNEL_COUNT],
    /// Latest packet-level telemetry snapshot.
    transport_stats: TransportStats,
    /// Latest packet-level snapshot for each attached send channel. The
    /// aggregate above is kept for diagnostics; the session controller and
    /// media callers use the video entry so control and audio traffic cannot
    /// inflate video delivery.
    channel_stats: [TransportStats; CHANNEL_COUNT],
    /// Cumulative counters at the start of the current rate sample.
    last_sample_ms: f64,
    last_sample_bytes_sent: [u64; CHANNEL_COUNT],
    last_sample_bytes_acked: [u64; CHANNEL_COUNT],
    ack_due: bool,
    /// Why the pending acknowledgement is owed. Data arrival makes it an
    /// acknowledgement; the cadence alone makes it a keepalive.
    ack_kind: AckKind,
    trigger: (u8, u32),

    /// Which channel the output drain is working through.
    drain_channel: usize,
    drain_started: bool,
    /// Optional bulk-video pacing. It is disabled until the owning host gives
    /// this session a path-specific target, preserving the old sans-IO API for
    /// callers that have no congestion-control target yet.
    pacer: Pacer,
    /// Wire bytes emitted from each bounded priority class in the current
    /// drain pass. ACKs are not data and are intentionally not counted here.
    drain_bytes: [usize; CHANNEL_COUNT],
}

impl<'a> Session<'a> {
    /// Build a host-side session. Rings are attached separately, per channel.
    pub fn new(envelope: Envelope, level: usize, now_ms: f64) -> Self {
        Self::with_direction(envelope, Direction::Host, level, now_ms)
    }

    /// Build a guest-side session (seals with the guest direction bit).
    pub fn new_guest(envelope: Envelope, level: usize, now_ms: f64) -> Self {
        Self::with_direction(envelope, Direction::Guest, level, now_ms)
    }

    /// Build a session with an explicit seal direction.
    pub fn with_direction(
        envelope: Envelope,
        direction: Direction,
        level: usize,
        now_ms: f64,
    ) -> Self {
        Self {
            envelope,
            direction,
            recv: core::array::from_fn(|_| None),
            send: core::array::from_fn(|_| None),
            controller: Controller::new(level, 1.0, 500.0),
            level,
            tx_counter: 0,
            srtt_ms: 0.0,
            srtt_seeded: false,
            last_ack_sent_ms: now_ms,
            last_progress_ms: now_ms,
            delivery: [Delivery {
                acked_seen: 0,
                since_ms: now_ms,
            }; CHANNEL_COUNT],
            transport_stats: TransportStats::default(),
            channel_stats: [TransportStats::default(); CHANNEL_COUNT],
            last_sample_ms: now_ms,
            last_sample_bytes_sent: [0; CHANNEL_COUNT],
            last_sample_bytes_acked: [0; CHANNEL_COUNT],
            ack_due: false,
            ack_kind: AckKind::Ack,
            trigger: (0, 0),
            drain_channel: 0,
            drain_started: false,
            pacer: Pacer::new(now_ms),
            drain_bytes: [0; CHANNEL_COUNT],
        }
    }

    /// Give the session a receive ring for `channel`.
    pub fn attach_recv(&mut self, channel: u8, ring: RecvRing<'a>) -> Result<()> {
        *self
            .recv
            .get_mut(channel as usize)
            .ok_or(Error::Malformed)? = Some(ring);
        Ok(())
    }

    /// Give the session a send ring for `channel`.
    pub fn attach_send(&mut self, channel: u8, ring: SendRing<'a>) -> Result<()> {
        *self
            .send
            .get_mut(channel as usize)
            .ok_or(Error::Malformed)? = Some(ring);
        Ok(())
    }

    /// Smoothed round trip, in fractional milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt_ms
    }

    /// Encoder rate the controller currently wants.
    pub fn rate_mbps(&self) -> f64 {
        self.controller.rate_mbps()
    }

    /// Set the target rate for bulk video pacing on this peer's path.
    ///
    /// The target is deliberately supplied by the owner of the session: one
    /// host may have several guests with different paths, and a single global
    /// pacer would let a fast LAN guest spend a relay guest's budget. A zero,
    /// negative, or non-finite rate disables pacing. Rates are decimal Mbps.
    pub fn set_pacing_rate_mbps(&mut self, now_ms: f64, rate_mbps: f64) {
        self.pacer.set_rate(now_ms, rate_mbps);
    }

    /// Set the path datagram size used by the pacer's burst calculation.
    ///
    /// This changes pacing only. A DPLPMTUD owner must update packetization and
    /// this value as one path transition, and should call it only after the
    /// send rings have been resized to emit the same packet size.
    pub fn set_pacing_datagram_size(&mut self, datagram_bytes: usize) -> bool {
        self.pacer.set_datagram_size(datagram_bytes)
    }

    /// The path-specific pacing target, or zero while pacing is disabled.
    pub fn pacing_rate_mbps(&self) -> f64 {
        self.pacer.rate_mbps()
    }

    /// Effective pacing burst ceiling for the current target and path size.
    pub fn pacing_burst_capacity_bytes(&self) -> usize {
        self.pacer.burst_capacity_bytes()
    }

    /// Return the latest bounded packet-level transport snapshot.
    pub fn transport_stats(&self) -> TransportStats {
        self.transport_stats
    }

    /// Return the latest bounded packet-level snapshot for one send channel.
    ///
    /// The snapshot is deliberately channel-local: a high-rate video stream
    /// must not mistake control or audio traffic for delivered video capacity.
    pub fn channel_transport_stats(&self, channel: u8) -> Option<TransportStats> {
        let ring = self.send.get(channel as usize)?.as_ref()?;
        let mut stats = self.channel_stats.get(channel as usize).copied()?;
        // A send happens after `Session::poll()` in the normal shell order.
        // Refresh the cumulative/window fields here so a diagnostic reader
        // never reports the previous turn's queue state or byte totals; the
        // bounded rate sample itself remains owned by `poll()`.
        stats.in_flight = ring.in_flight();
        stats.stale = ring.stale();
        stats.bytes_sent = ring.bytes_sent();
        stats.bytes_acked = ring.bytes_acked();
        stats.retransmitted_fragments = ring.retransmitted();
        stats.srtt_ms = self.srtt_ms;
        Some(stats)
    }

    /// Liveness, judged against the last forward progress in each direction.
    ///
    /// **Both directions, because a session can fail in either.** Nothing
    /// arriving is one failure; everything queued sitting unacknowledged is
    /// another, and it is invisible to a deadline that only watches what comes
    /// in.
    pub fn health(&self, now_ms: f64) -> Health {
        let idle = now_ms - self.last_progress_ms;
        if idle >= LIVENESS_HARD_MS {
            return Health::Dead;
        }
        if self.undeliverable(now_ms) {
            return Health::Undeliverable;
        }
        if idle >= LIVENESS_SOFT_MS {
            Health::Stalled
        } else {
            Health::Alive
        }
    }

    /// True when a channel has held data the peer has not acknowledged for the
    /// whole of [`DELIVERY_DEADLINE_MS`].
    ///
    /// The window is read now rather than remembered, so a channel that
    /// drained a moment ago is not judged on what it used to hold.
    fn undeliverable(&self, now_ms: f64) -> bool {
        self.send.iter().enumerate().any(|(channel, ring)| {
            ring.as_ref().is_some_and(|ring| {
                ring.in_flight() > 0
                    && self
                        .delivery
                        .get(channel)
                        .is_some_and(|entry| now_ms - entry.since_ms >= DELIVERY_DEADLINE_MS)
            })
        })
    }

    /// One channel's send pressure: the outstanding window, the stale count
    /// from the last scan, and the payload bytes sent so far.
    ///
    /// **The window is `send_next - send_base`**, which is what both the
    /// congestion controller and the delivery gate's room test are defined
    /// against. It is not [`crate::send::SendRing::outstanding`], which counts
    /// what a single scan released and is bounded by the per-channel cap.
    pub fn send_pressure(&self, channel: u8) -> Option<(u32, u32, u64)> {
        let ring = self.send.get(channel as usize)?.as_ref()?;
        Some((ring.in_flight(), ring.stale(), ring.bytes_sent()))
    }

    /// Contiguous frontier on `channel`: what we would acknowledge.
    pub fn recv_cumulative(&self, channel: u8) -> Option<u32> {
        Some(self.recv.get(channel as usize)?.as_ref()?.cumulative_ack())
    }

    /// Anchor a receive channel at `sequence`.
    ///
    /// For a session joined mid-stream, or a replay that does not begin at
    /// zero. Discards anything already buffered on that channel.
    pub fn reset_recv(&mut self, channel: u8, sequence: u32) -> Result<()> {
        self.recv
            .get_mut(channel as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Malformed)?
            .reset_to(sequence);
        Ok(())
    }

    /// Queue a message for sending on `channel`.
    ///
    /// Nothing goes on the wire here. The fragments become pending and
    /// [`Session::get_output`] releases them, so backpressure is visible as a
    /// refusal rather than as unbounded buffering.
    pub fn send_message(&mut self, channel: u8, header: &[u8], payload: &[u8]) -> Result<u32> {
        let ring = self
            .send
            .get_mut(channel as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Malformed)?;
        let message = Message::new(header, payload)?;
        ring.enqueue(&message)
    }

    /// Take the next complete message from `channel`, if one has arrived.
    pub fn take_message(&mut self, channel: u8, out: &mut [u8]) -> Option<Result<usize>> {
        self.recv
            .get_mut(channel as usize)
            .and_then(Option::as_mut)?
            .take_message(out)
    }

    /// True if `channel` is missing a fragment below what has arrived.
    pub fn has_gap(&self, channel: u8) -> bool {
        self.recv
            .get(channel as usize)
            .and_then(Option::as_ref)
            .is_some_and(RecvRing::has_gap)
    }

    /// Abandon an unfillable gap on `channel` and resume further along.
    ///
    /// Policy lives with the caller, deliberately. Only the layer that
    /// understands the payload can say which slots are resumable, and only the
    /// shell knows how long a stall has lasted. The core supplies the
    /// mechanism and the guarantee that the jump goes to the furthest usable
    /// slot rather than the nearest.
    pub fn escape_stall(&mut self, channel: u8, resumable: impl Fn(&[u8]) -> bool) -> Option<u32> {
        self.recv
            .get_mut(channel as usize)
            .and_then(Option::as_mut)?
            .escape_stall(resumable)
    }

    /// Feed one received datagram.
    pub fn process_input(
        &mut self,
        datagram: &[u8],
        now_ms: f64,
        scratch: &mut [u8],
    ) -> Result<Inbound> {
        // Fail closed on a wrong-direction record before decryption: without
        // this, a peer reflecting our own packets back would present valid
        // tags under reused (key, nonce) pairs.
        if Direction::from_datagram(datagram) != Some(self.direction.opposite()) {
            return Err(Error::Decrypt);
        }
        let opened = self.envelope.open(datagram, scratch)?;
        let packet = packet::parse(opened.cleartext)?;
        self.last_progress_ms = now_ms;

        match packet {
            Packet::Data(data) => {
                self.trigger = (data.channel, data.seq);
                // Any data arrival makes an acknowledgement due; the cadence
                // check in get_output decides when it actually leaves.
                self.ack_due = true;
                self.ack_kind = AckKind::Ack;
                let Some(ring) = self
                    .recv
                    .get_mut(data.channel as usize)
                    .and_then(Option::as_mut)
                else {
                    return Ok(Inbound::Unhandled {
                        channel: data.channel,
                    });
                };
                ring.store(data.seq, data.body);
                Ok(Inbound::Data {
                    channel: data.channel,
                })
            }
            Packet::Ack(ack) => {
                let mut sample = None;
                for ring in self.send.iter_mut().flatten() {
                    if let Some(taken) = ring.on_ack(&ack, now_ms) {
                        sample = Some(taken);
                    }
                }
                if let Some(sample) = sample {
                    self.observe_rtt(sample);
                }
                Ok(match ack.kind {
                    AckKind::Ack => Inbound::Ack,
                    AckKind::Keepalive => Inbound::Keepalive,
                })
            }
        }
    }

    /// Fold a round-trip sample into the smoothed estimate.
    ///
    /// The first sample seeds it outright; averaging against a zero start would
    /// leave the estimate an order of magnitude low for the first dozen
    /// samples, and the retransmission timeout is built on it.
    fn observe_rtt(&mut self, sample_ms: f64) {
        if !sample_ms.is_finite() || sample_ms < 0.0 {
            return;
        }
        if self.srtt_seeded {
            self.srtt_ms = self.srtt_ms * (1.0 - SRTT_ALPHA) + sample_ms * SRTT_ALPHA;
        } else {
            self.srtt_ms = sample_ms;
            self.srtt_seeded = true;
        }
    }

    /// Housekeeping. Safe to call whenever the loop wakes.
    pub fn poll(&mut self, now_ms: f64) {
        // A poll begins a fresh output pass. This also releases a pass that
        // stopped at the pacer because the bucket was empty; the next drain
        // must recalculate the send window rather than inherit the old cap.
        self.drain_started = false;
        // Every acknowledgement resets the cadence, whatever prompted it, so
        // this fires only when nothing else has sent one. That is what makes it
        // a keepalive: the session is never silent for longer than the cadence,
        // and an idle one stays alive without a separate schedule.
        if !self.ack_due && now_ms - self.last_ack_sent_ms >= ACK_CADENCE_MS {
            self.ack_due = true;
            self.ack_kind = AckKind::Keepalive;
        }
        // **An empty channel is progress, not a stall.** A channel with
        // nothing outstanding can produce no acknowledgement, and a deadline
        // that did not say so would end every session that stopped sending.
        for (channel, ring) in self.send.iter().enumerate() {
            let (Some(ring), Some(entry)) = (ring.as_ref(), self.delivery.get_mut(channel)) else {
                continue;
            };
            let acked = ring.acked();
            if ring.in_flight() == 0 || acked != entry.acked_seen {
                entry.acked_seen = acked;
                entry.since_ms = now_ms;
            }
        }
        let elapsed = now_ms - self.last_sample_ms;
        let sampled = elapsed.is_finite()
            && elapsed >= TRANSPORT_SAMPLE_MIN_MS
            && now_ms >= self.last_sample_ms;
        for (ring, stats) in self.send.iter().zip(self.channel_stats.iter_mut()) {
            if let Some(ring) = ring.as_ref() {
                stats.in_flight = ring.in_flight();
                stats.stale = ring.stale();
                stats.bytes_sent = ring.bytes_sent();
                stats.bytes_acked = ring.bytes_acked();
                stats.retransmitted_fragments = ring.retransmitted();
                stats.srtt_ms = self.srtt_ms;
            } else {
                *stats = TransportStats::default();
            }
        }
        if sampled {
            for ((stats, last_sent), last_acked) in self
                .channel_stats
                .iter_mut()
                .zip(self.last_sample_bytes_sent.iter_mut())
                .zip(self.last_sample_bytes_acked.iter_mut())
            {
                let sent_delta = stats.bytes_sent.saturating_sub(*last_sent);
                let acked_delta = stats.bytes_acked.saturating_sub(*last_acked);
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "the counter is a byte total; f64 is sufficient for a rate sample"
                )]
                let send_bits = sent_delta as f64 * 8.0;
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "the counter is a byte total; f64 is sufficient for a rate sample"
                )]
                let acked_bits = acked_delta as f64 * 8.0;
                let seconds = elapsed / 1000.0;
                let send_rate_mbps = send_bits / seconds / 1_000_000.0;
                let delivery_rate_mbps = acked_bits / seconds / 1_000_000.0;
                stats.interval_ms = elapsed;
                stats.send_rate_mbps = if send_rate_mbps.is_finite() {
                    send_rate_mbps.max(0.0)
                } else {
                    0.0
                };
                stats.delivery_rate_mbps = if delivery_rate_mbps.is_finite() {
                    delivery_rate_mbps.max(0.0)
                } else {
                    0.0
                };
                *last_sent = stats.bytes_sent;
                *last_acked = stats.bytes_acked;
            }
            self.last_sample_ms = now_ms;
        }
        let mut aggregate = TransportStats {
            interval_ms: self.transport_stats.interval_ms,
            ..TransportStats::default()
        };
        for stats in &self.channel_stats {
            aggregate.in_flight = aggregate.in_flight.saturating_add(stats.in_flight);
            aggregate.stale = aggregate.stale.saturating_add(stats.stale);
            aggregate.bytes_sent = aggregate.bytes_sent.saturating_add(stats.bytes_sent);
            aggregate.bytes_acked = aggregate.bytes_acked.saturating_add(stats.bytes_acked);
            aggregate.retransmitted_fragments = aggregate
                .retransmitted_fragments
                .saturating_add(stats.retransmitted_fragments);
            aggregate.send_rate_mbps += stats.send_rate_mbps;
            aggregate.delivery_rate_mbps += stats.delivery_rate_mbps;
        }
        if sampled {
            aggregate.interval_ms = elapsed;
        }
        aggregate.srtt_ms = self.srtt_ms;
        self.transport_stats = aggregate;
        // This controller's public rate is a video rate. The aggregate
        // snapshot remains useful for diagnostics, but feeding control or
        // audio pressure into it makes a busy side channel look like video
        // congestion and was the ambiguity the per-channel telemetry fixed.
        if let Some(video) = self.channel_stats.get(VIDEO_CHANNEL as usize)
            && self
                .send
                .get(VIDEO_CHANNEL as usize)
                .and_then(Option::as_ref)
                .is_some()
        {
            self.controller
                .tick(video.in_flight, video.stale, video.delivery_rate_mbps);
        }
    }

    /// Return the bytes allowed in one pass for a potentially bulky priority
    /// channel. A value is enforced only when a lower-priority channel has a
    /// due fragment; otherwise a control-only or audio-only session drains
    /// normally instead of being throttled by a fairness mechanism it does not
    /// need.
    const fn priority_quantum(channel: usize) -> Option<usize> {
        match channel {
            CONTROL_CHANNEL_INDEX => Some(CONTROL_PRIORITY_QUANTUM_BYTES),
            AUDIO_CHANNEL_INDEX => Some(AUDIO_PRIORITY_QUANTUM_BYTES),
            _ => None,
        }
    }

    /// Whether a channel later in the current scheduler order has a fragment
    /// ready to release. This is deliberately a read-only query: the decision
    /// to yield a priority channel must not advance any send cursor.
    fn has_due_after(&self, position: usize, now_ms: f64) -> bool {
        let srtt = self.srtt_ms;
        for order_position in position.saturating_add(1)..CHANNEL_COUNT {
            let Some(&channel) = DRAIN_ORDER.get(order_position) else {
                continue;
            };
            if self
                .send
                .get(channel)
                .and_then(Option::as_ref)
                .is_some_and(|ring| ring.next_due_len(now_ms, srtt, self.level).is_some())
            {
                return true;
            }
        }
        false
    }

    /// Whether a bounded priority ring has work that should wake the shell.
    ///
    /// This matters after a priority quantum yields to media: once the media
    /// has drained, the remaining control/audio backlog must be scheduled
    /// promptly rather than waiting for the thirty-millisecond ACK cadence.
    fn has_due_priority(&self, now_ms: f64) -> bool {
        [CONTROL_CHANNEL_INDEX, AUDIO_CHANNEL_INDEX]
            .into_iter()
            .any(|channel| {
                self.send
                    .get(channel)
                    .and_then(Option::as_ref)
                    .is_some_and(|ring| {
                        ring.next_due_len(now_ms, self.srtt_ms, self.level)
                            .is_some()
                    })
            })
    }

    /// Milliseconds until the session next needs attention.
    ///
    /// The shell arms its wait from this. There is no fixed tick: a loop that
    /// polls on a timer instead of on this will either burn cycles or miss
    /// deadlines, and both have shipped before.
    pub fn next_timer_ms(&self, now_ms: f64) -> f64 {
        let since_ack = now_ms - self.last_ack_sent_ms;
        let mut next = (ACK_CADENCE_MS - since_ack).max(0.0);
        if let Some(video) = self
            .send
            .get(VIDEO_CHANNEL as usize)
            .and_then(Option::as_ref)
            && let Some(cleartext_len) = video.next_due_len(now_ms, self.srtt_ms, self.level)
        {
            let wire_len = ENVELOPE_LEN.saturating_add(cleartext_len);
            let wait = if self.pacer.enabled() {
                self.pacer.wait_ms(now_ms, wire_len)
            } else {
                0.0
            };
            next = next.min(wait);
            // When video is waiting for credit, do not turn a control backlog
            // into a one-millisecond busy loop. The next wake is the precise
            // refill event, where the bounded priority quantum is followed by
            // the video packet.
            if self.pacer.enabled() && wait.is_finite() && wait > 0.0 {
                return next;
            }
        }
        if self.has_due_priority(now_ms) {
            next = 0.0;
        }
        next
    }

    /// Emit the next datagram, sealed and ready for the socket.
    ///
    /// Drive until `None`. Acknowledgements are emitted first, then control and
    /// audio are given bounded priority quanta before bulk video, so a keyframe
    /// burst cannot delay feedback or turn a large control transfer into an
    /// unbounded pre-video burst.
    pub fn get_output(&mut self, now_ms: f64, out: &mut [u8]) -> Option<Result<usize>> {
        if !self.drain_started {
            for ring in self.send.iter_mut().flatten() {
                ring.begin_pass();
            }
            self.drain_channel = 0;
            self.drain_bytes = [0; CHANNEL_COUNT];
            self.drain_started = true;
        }

        // Acknowledgements are independent of the bulk send budget. Emit one
        // first so a peer can release its window and so control feedback is
        // never queued behind a keyframe burst.
        if self.ack_due {
            let result = self.emit_ack(out);
            if result.is_ok() {
                self.ack_due = false;
                self.last_ack_sent_ms = now_ms;
            }
            return Some(result);
        }

        // Cleartext is built directly at the ciphertext offset so sealing is a
        // header-and-tag write rather than a second pass over the payload.
        while self.drain_channel < CHANNEL_COUNT {
            let Some(&index) = DRAIN_ORDER.get(self.drain_channel) else {
                self.drain_channel = CHANNEL_COUNT;
                continue;
            };
            let srtt = self.srtt_ms;
            let level = self.level;
            let Some(cleartext_len) = self
                .send
                .get(index)
                .and_then(Option::as_ref)
                .and_then(|ring| ring.next_due_len(now_ms, srtt, level))
            else {
                self.drain_channel += 1;
                continue;
            };
            let wire_len = ENVELOPE_LEN.saturating_add(cleartext_len);
            let priority_bytes = self.drain_bytes.get(index).copied().unwrap_or_default();
            if let Some(quantum) = Self::priority_quantum(index)
                && priority_bytes > 0
                && priority_bytes.saturating_add(wire_len) > quantum
                && self.has_due_after(self.drain_channel, now_ms)
            {
                // Channel 0 combines input and bulk control in one ordered
                // sequence space, so this yields at a fragment boundary. It
                // prevents a large control transfer from monopolising the
                // socket while retaining the ordering the peer relies on.
                self.drain_channel += 1;
                continue;
            }
            let Some(ring) = self.send.get_mut(index).and_then(Option::as_mut) else {
                self.drain_channel += 1;
                continue;
            };
            // Channel 0 carries input/control and channel 2 carries audio;
            // both are small, latency-sensitive streams. Bulk video alone is
            // paced against the target for this path, and the token check is
            // performed before poll_send commits the slot as transmitted.
            let paced = index == VIDEO_CHANNEL as usize && self.pacer.enabled();
            if paced && !self.pacer.can_consume(now_ms, wire_len) {
                // Keep the pass open. The next timer includes exactly the
                // refill delay, and no ring cursor or send counter has
                // moved yet.
                return None;
            }
            let Some(body) = out.get_mut(ENVELOPE_LEN..) else {
                return Some(Err(Error::BufferTooSmall));
            };
            match ring.poll_send(now_ms, srtt, level, body) {
                Some(Ok(written)) => {
                    let result = self.seal(written, out);
                    if let Ok(len) = result {
                        if paced {
                            // The read-only preflight above used the same
                            // candidate and length. A failed consume here
                            // would indicate arithmetic or state corruption;
                            // retain the packet because the ring is already
                            // committed and make the invariant visible in
                            // debug builds.
                            // Keep the call outside `debug_assert!`: the
                            // token subtraction is the pacing side effect and
                            // must also happen in release builds.
                            let _consumed = self.pacer.try_consume(now_ms, len);
                            debug_assert!(_consumed);
                        }
                        if Self::priority_quantum(index).is_some() {
                            if let Some(bytes) = self.drain_bytes.get_mut(index) {
                                *bytes = bytes.saturating_add(len);
                            }
                        }
                    }
                    return Some(result);
                }
                Some(Err(error)) => return Some(Err(error)),
                None => self.drain_channel += 1,
            }
        }

        self.drain_started = false;
        None
    }

    /// Build and seal a group acknowledgement covering every channel.
    ///
    /// A keepalive carries the same nineteen cumulative counts but no trigger
    /// and no negative acknowledgement: nothing prompted it, so there is
    /// nothing to point at, and the flag combination with a trigger is not one
    /// a peer accepts.
    fn emit_ack(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut cumulative = [0u32; CHANNEL_COUNT];
        let mut gap = false;
        for (index, slot) in self.recv.iter().enumerate() {
            let Some(ring) = slot.as_ref() else { continue };
            if let Some(entry) = cumulative.get_mut(index) {
                *entry = ring.cumulative_ack();
            }
            if ring.has_gap() {
                gap = true;
            }
        }
        let keepalive = self.ack_kind == AckKind::Keepalive;
        let ack = Ack {
            kind: self.ack_kind,
            nack: gap && !keepalive,
            trigger_channel: if keepalive { 0 } else { self.trigger.0 },
            trigger_seq: if keepalive { 0 } else { self.trigger.1 },
            cumulative,
            // We carry every channel, and [`packet::encode_ack`] writes them
            // all. A peer with fewer reads the prefix it understands.
            reported: CHANNEL_COUNT,
        };
        let body = out.get_mut(ENVELOPE_LEN..).ok_or(Error::BufferTooSmall)?;
        let written = packet::encode_ack(body, &ack)?;
        self.seal(written, out)
    }

    /// Wrap cleartext already sitting at the ciphertext offset.
    fn seal(&mut self, cleartext_len: usize, out: &mut [u8]) -> Result<usize> {
        // Bit 63 carries the seal direction; counters beyond it are rejected
        // rather than allowed to alias the other direction's nonces.
        if self.tx_counter >= (1_u64 << 63) {
            return Err(Error::Oversized);
        }
        let counter = self.tx_counter | self.direction.seal_bit();
        self.tx_counter = self.tx_counter.checked_add(1).ok_or(Error::Oversized)?;
        self.envelope.seal_in_place(counter, cleartext_len, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::SlotMeta;
    use crate::send::SendSlot;
    use std::vec::Vec;

    const SLOT: usize = 64;
    const SLOTS: usize = 32;
    const KEY: [u8; 32] = [3u8; 32];
    const VIDEO: u8 = 1;
    const CONTROL: u8 = 0;

    /// Storage for one endpoint: a receive and a send ring per channel.
    struct Arena {
        recv_bodies: Vec<u8>,
        recv_meta: Vec<SlotMeta>,
        send_bodies: Vec<u8>,
        send_meta: Vec<SendSlot>,
        control_recv_bodies: Vec<u8>,
        control_recv_meta: Vec<SlotMeta>,
        control_send_bodies: Vec<u8>,
        control_send_meta: Vec<SendSlot>,
    }

    impl Arena {
        fn new() -> Self {
            Self {
                recv_bodies: std::vec![0u8; SLOT * SLOTS],
                recv_meta: std::vec![SlotMeta::default(); SLOTS],
                send_bodies: std::vec![0u8; SLOT * SLOTS],
                send_meta: std::vec![SendSlot::default(); SLOTS],
                control_recv_bodies: std::vec![0u8; SLOT * SLOTS],
                control_recv_meta: std::vec![SlotMeta::default(); SLOTS],
                control_send_bodies: std::vec![0u8; SLOT * SLOTS],
                control_send_meta: std::vec![SendSlot::default(); SLOTS],
            }
        }
    }

    fn endpoint(arena: &mut Arena, now: f64) -> Session<'_> {
        endpoint_directed(arena, now, Direction::Host)
    }

    /// The guest side of a loopback pair: seals with the guest bit.
    fn endpoint_guest(arena: &mut Arena, now: f64) -> Session<'_> {
        endpoint_directed(arena, now, Direction::Guest)
    }

    fn endpoint_directed(arena: &mut Arena, now: f64, direction: Direction) -> Session<'_> {
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), direction, 1, now);
        session
            .attach_recv(
                VIDEO,
                RecvRing::new(&mut arena.recv_bodies, &mut arena.recv_meta, SLOT).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                VIDEO,
                SendRing::new(&mut arena.send_bodies, &mut arena.send_meta, SLOT, VIDEO).unwrap(),
            )
            .unwrap();
        session
    }

    /// An endpoint carrying both channels, with the video receive ring
    /// optionally missing.
    ///
    /// **A peer that is not draining what it is sent** looks exactly like
    /// this from the far side: its transport still acknowledges the channel it
    /// is keeping up with, and the one it is not never advances.
    fn endpoint_pair(arena: &mut Arena, now: f64, video_recv: bool) -> Session<'_> {
        endpoint_pair_directed(arena, now, video_recv, Direction::Host)
    }

    /// The guest side of a loopback pair.
    fn endpoint_pair_guest(arena: &mut Arena, now: f64, video_recv: bool) -> Session<'_> {
        endpoint_pair_directed(arena, now, video_recv, Direction::Guest)
    }

    fn endpoint_pair_directed(
        arena: &mut Arena,
        now: f64,
        video_recv: bool,
        direction: Direction,
    ) -> Session<'_> {
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), direction, 1, now);
        if video_recv {
            session
                .attach_recv(
                    VIDEO,
                    RecvRing::new(&mut arena.recv_bodies, &mut arena.recv_meta, SLOT).unwrap(),
                )
                .unwrap();
        }
        session
            .attach_recv(
                CONTROL,
                RecvRing::new(
                    &mut arena.control_recv_bodies,
                    &mut arena.control_recv_meta,
                    SLOT,
                )
                .unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                VIDEO,
                SendRing::new(&mut arena.send_bodies, &mut arena.send_meta, SLOT, VIDEO).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                CONTROL,
                SendRing::new(
                    &mut arena.control_send_bodies,
                    &mut arena.control_send_meta,
                    SLOT,
                    CONTROL,
                )
                .unwrap(),
            )
            .unwrap();
        session
    }

    /// Drain one endpoint into nothing, which is a path that is not carrying.
    fn discard(from: &mut Session<'_>, now: f64) {
        let mut wire = [0u8; 512];
        while let Some(result) = from.get_output(now, &mut wire) {
            result.unwrap();
        }
    }

    /// Drain one endpoint into the other, returning how many datagrams moved.
    fn pump(from: &mut Session<'_>, to: &mut Session<'_>, now: f64) -> usize {
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let mut moved = 0;
        while let Some(result) = from.get_output(now, &mut wire) {
            let written = result.unwrap();
            to.process_input(&wire[..written], now, &mut scratch)
                .unwrap();
            moved += 1;
        }
        moved
    }

    #[test]
    fn a_message_crosses_a_loopback_pair() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, b"hdr", b"payload").unwrap();
        assert!(pump(&mut left, &mut right, 1.0) >= 1);

        let mut out = [0u8; 256];
        let len = right.take_message(VIDEO, &mut out).unwrap().unwrap();
        assert_eq!(&out[..len], b"hdrpayload");
    }

    #[test]
    fn a_multi_fragment_message_crosses_intact() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        left.send_message(VIDEO, &[], &payload).unwrap();
        pump(&mut left, &mut right, 1.0);

        let mut out = [0u8; 1024];
        let len = right.take_message(VIDEO, &mut out).unwrap().unwrap();
        assert_eq!(&out[..len], &payload[..]);
    }

    /// The acknowledgement path closes the loop: the sender's window must free
    /// once the receiver's acknowledgement comes back.
    #[test]
    fn acknowledgements_free_the_senders_window() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"x").unwrap();
        pump(&mut left, &mut right, 1.0);
        let mut out = [0u8; 64];
        right.take_message(VIDEO, &mut out);

        // The receiver acknowledges on its next drain.
        right.poll(40.0);
        assert!(pump(&mut right, &mut left, 40.0) >= 1);

        // Nothing is outstanding now, so a second pass sends nothing.
        assert_eq!(
            pump(&mut left, &mut right, 41.0),
            0,
            "retransmitted an acknowledged fragment"
        );
    }

    #[test]
    fn a_round_trip_seeds_the_smoothed_estimate() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"x").unwrap();
        pump(&mut left, &mut right, 10.0);
        right.poll(50.0);
        pump(&mut right, &mut left, 50.0);

        assert!(left.srtt_ms() > 0.0, "no sample was taken");
        assert!((left.srtt_ms() - 40.0).abs() < 1.0, "{}", left.srtt_ms());
    }

    #[test]
    fn transport_stats_report_delivery_rate_after_a_bounded_sample() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"payload").unwrap();
        assert_eq!(pump(&mut left, &mut right, 1.0), 1);
        let mut out = [0u8; 64];
        assert!(right.take_message(VIDEO, &mut out).is_some());

        // The receiver's data acknowledgement returns at t=50. The sender
        // samples at t=100, after the 100 ms minimum interval, so its
        // controller sees delivered bytes rather than a zero placeholder.
        right.poll(50.0);
        assert!(pump(&mut right, &mut left, 50.0) >= 1);
        left.poll(100.0);

        let stats = left.transport_stats();
        // The transport counts the message framing prefix as sent payload;
        // the outer encrypted envelope is intentionally not part of these
        // low-level delivery counters.
        assert_eq!(stats.bytes_sent, 11);
        assert_eq!(stats.bytes_acked, 11);
        assert_eq!(stats.retransmitted_fragments, 0);
        assert_eq!(stats.in_flight, 0);
        assert!((stats.interval_ms - 100.0).abs() < f64::EPSILON);
        let expected_rate = 11.0 * 8.0 / 0.1 / 1_000_000.0;
        assert!((stats.send_rate_mbps - expected_rate).abs() < 1e-12);
        assert!((stats.delivery_rate_mbps - expected_rate).abs() < 1e-12);
        assert!(stats.srtt_ms > 0.0);
        let video = left
            .channel_transport_stats(VIDEO)
            .expect("the video send ring is attached");
        assert_eq!(video.bytes_sent, stats.bytes_sent);
        assert_eq!(video.bytes_acked, stats.bytes_acked);
        assert!((video.delivery_rate_mbps - stats.delivery_rate_mbps).abs() < f64::EPSILON);
        assert!(left.channel_transport_stats(2).is_none());
    }

    #[test]
    fn transport_rate_sample_is_stable_across_fast_polls() {
        let mut arena = Arena::new();
        let mut session = endpoint(&mut arena, 0.0);
        session.poll(50.0);
        assert!(session.transport_stats().interval_ms.abs() < f64::EPSILON);
        session.poll(99.0);
        assert!(session.transport_stats().interval_ms.abs() < f64::EPSILON);
        session.poll(100.0);
        assert!((session.transport_stats().interval_ms - 100.0).abs() < f64::EPSILON);
        assert!(session.transport_stats().send_rate_mbps.abs() < f64::EPSILON);
    }

    #[test]
    fn acknowledgements_precede_queued_video() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint_pair(&mut left_arena, 0.0, true);
        let mut right = endpoint_pair_guest(&mut right_arena, 0.0, true);
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];

        left.send_message(VIDEO, &[], b"video").unwrap();
        let left_written = left.get_output(0.0, &mut wire).unwrap().unwrap();
        right
            .process_input(&wire[..left_written], 0.0, &mut scratch)
            .expect("the queued video reaches the peer");
        right.send_message(VIDEO, &[], b"reply-video").unwrap();

        // The reply has both an acknowledgement owed to the received frame
        // and its own video waiting. The acknowledgement must be first.
        let written = right.get_output(1.0, &mut wire).unwrap().unwrap();
        let opened = right.envelope.open(&wire[..written], &mut scratch).unwrap();
        let Packet::Ack(_) = packet::parse(opened.cleartext).unwrap() else {
            panic!("video was allowed to delay an acknowledgement");
        };
    }

    #[test]
    fn control_is_scheduled_before_paced_video() {
        let mut arena = Arena::new();
        let mut session = endpoint_pair(&mut arena, 0.0, true);
        session.set_pacing_rate_mbps(0.0, 0.001);
        session.send_message(VIDEO, &[], b"video").unwrap();
        session.send_message(CONTROL, &[], b"input").unwrap();

        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let written = session.get_output(0.0, &mut wire).unwrap().unwrap();
        let opened = session
            .envelope
            .open(&wire[..written], &mut scratch)
            .unwrap();
        let Packet::Data(data) = packet::parse(opened.cleartext).unwrap() else {
            panic!("expected the control data packet");
        };
        assert_eq!(data.channel, CONTROL);
    }

    #[test]
    fn bulk_control_yields_to_video_at_the_priority_quantum() {
        const CONTROL_SLOTS: usize = 128;
        let mut video_bodies = std::vec![0u8; SLOT * SLOTS];
        let mut video_meta = std::vec![SendSlot::default(); SLOTS];
        let mut control_bodies = std::vec![0u8; SLOT * CONTROL_SLOTS];
        let mut control_meta = std::vec![SendSlot::default(); CONTROL_SLOTS];
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), Direction::Host, 1, 0.0);
        session
            .attach_send(
                VIDEO,
                SendRing::new(&mut video_bodies, &mut video_meta, SLOT, VIDEO).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                CONTROL,
                SendRing::new(&mut control_bodies, &mut control_meta, SLOT, CONTROL).unwrap(),
            )
            .unwrap();

        // Fill channel 0 with full-size control fragments, then put one video
        // fragment behind them. A scheduler that treats every control byte as
        // unconditionally priority would emit all 128 before reaching video.
        let control_payload = [0xCCu8; SLOT - crate::message::LENGTH_PREFIX_LEN];
        for _ in 0..CONTROL_SLOTS {
            session
                .send_message(CONTROL, &[], &control_payload)
                .unwrap();
        }
        session.send_message(VIDEO, &[], b"video").unwrap();

        let mut wire = [0u8; 256];
        let mut scratch = [0u8; 256];
        let mut control_bytes = 0usize;
        let mut control_packets = 0usize;
        let mut saw_video = false;
        while let Some(result) = session.get_output(0.0, &mut wire) {
            let written = result.unwrap();
            let opened = session
                .envelope
                .open(&wire[..written], &mut scratch)
                .unwrap();
            let Packet::Data(data) = packet::parse(opened.cleartext).unwrap() else {
                continue;
            };
            if data.channel == VIDEO {
                saw_video = true;
                break;
            }
            assert_eq!(data.channel, CONTROL);
            control_packets += 1;
            control_bytes += written;
        }

        assert!(saw_video, "control backlog starved the video channel");
        assert!(control_packets < CONTROL_SLOTS);
        assert!(
            control_bytes <= CONTROL_PRIORITY_QUANTUM_BYTES,
            "priority control emitted {control_bytes} bytes before video"
        );

        // The yielded control backlog must wake promptly once video has been
        // served; waiting for the ACK cadence would add an avoidable 30 ms.
        session.poll(0.0);
        assert!(session.next_timer_ms(0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn side_channel_pressure_does_not_drive_the_video_controller() {
        const CONTROL_SLOTS: usize = 128;
        let mut video_bodies = std::vec![0u8; SLOT * SLOTS];
        let mut video_meta = std::vec![SendSlot::default(); SLOTS];
        let mut control_bodies = std::vec![0u8; SLOT * CONTROL_SLOTS];
        let mut control_meta = std::vec![SendSlot::default(); CONTROL_SLOTS];
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), Direction::Host, 1, 0.0);
        session
            .attach_send(
                VIDEO,
                SendRing::new(&mut video_bodies, &mut video_meta, SLOT, VIDEO).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                CONTROL,
                SendRing::new(&mut control_bodies, &mut control_meta, SLOT, CONTROL).unwrap(),
            )
            .unwrap();

        // Move the controller above its floor so an accidental
        // aggregate-congestion tick is observable as a rate cut.
        for _ in 0..60 {
            session.controller.tick(0, 0, 10.0);
        }
        let before = session.rate_mbps();
        for _ in 0..CONTROL_SLOTS {
            session.send_message(CONTROL, &[], b"control").unwrap();
        }

        let mut wire = [0u8; 256];
        while let Some(result) = session.get_output(0.0, &mut wire) {
            result.unwrap();
        }
        session.poll(100.0);

        assert_eq!(session.controller.total_decreases(), 0);
        assert!((session.rate_mbps() - before).abs() < f64::EPSILON);
    }

    #[test]
    fn video_pacing_has_a_bounded_burst_and_refill_timer() {
        const PACER_SLOT: usize = 128;
        const PACER_SLOTS: usize = 64;
        let mut bodies = std::vec![0u8; PACER_SLOT * PACER_SLOTS];
        let mut meta = std::vec![SendSlot::default(); PACER_SLOTS];
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), Direction::Host, 1, 0.0);
        session
            .attach_send(
                VIDEO,
                SendRing::new(&mut bodies, &mut meta, PACER_SLOT, VIDEO).unwrap(),
            )
            .unwrap();
        session.set_pacing_rate_mbps(0.0, 1.0);

        // Seven messages produce more than one bucketful while keeping every
        // message within the ring's bounded capacity.
        let payload = [0xA5u8; 900];
        for _ in 0..7 {
            session.send_message(VIDEO, &[], &payload).unwrap();
        }

        let mut wire = [0u8; 256];
        let mut sent = 0usize;
        while let Some(result) = session.get_output(0.0, &mut wire) {
            let written = result.unwrap();
            sent = sent.saturating_add(written);
        }
        assert!(sent > 0);
        let burst_capacity = session.pacing_burst_capacity_bytes();
        assert!(
            sent <= burst_capacity,
            "the pacer emitted {sent} bytes in one burst (capacity={burst_capacity})"
        );
        let wait = session.next_timer_ms(0.0);
        assert!(wait > 0.0 && wait < ACK_CADENCE_MS, "wait={wait}");

        // A fresh poll starts another output pass after the bucket refills.
        session.poll(wait + 0.1);
        assert!(
            session
                .get_output(wait + 0.1, &mut wire)
                .is_some_and(|result| result.is_ok())
        );
    }

    #[test]
    fn the_nonce_counter_never_repeats() {
        let mut arena = Arena::new();
        let mut session = endpoint(&mut arena, 0.0);
        let mut wire = [0u8; 512];
        let mut seen = Vec::new();
        for round in 0..8 {
            session.send_message(VIDEO, &[], b"x").unwrap();
            while let Some(result) = session.get_output(f64::from(round), &mut wire) {
                let written = result.unwrap();
                seen.push(wire[3..11].to_vec());
                assert!(written > ENVELOPE_LEN);
            }
        }
        let unique: std::collections::BTreeSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "a nonce counter repeated");
    }

    #[test]
    fn directions_seal_different_nonces_and_reject_reflection() {
        let mut host_arena = Arena::new();
        let mut guest_arena = Arena::new();
        let mut host = endpoint(&mut host_arena, 0.0);
        let mut guest = endpoint_guest(&mut guest_arena, 0.0);

        host.send_message(VIDEO, &[], b"host-bytes").unwrap();
        guest.send_message(VIDEO, &[], b"host-bytes").unwrap();
        let mut host_wire = [0u8; 512];
        let mut guest_wire = [0u8; 512];
        let host_len = host.get_output(0.0, &mut host_wire).unwrap().unwrap();
        let guest_len = guest.get_output(0.0, &mut guest_wire).unwrap().unwrap();
        // Same key, same counter, same plaintext: wire must still differ.
        assert_ne!(&host_wire[..host_len], &guest_wire[..guest_len]);
        // Direction bits are opposite on the wire.
        assert_eq!(
            Direction::from_datagram(&host_wire[..host_len]),
            Some(Direction::Host)
        );
        assert_eq!(
            Direction::from_datagram(&guest_wire[..guest_len]),
            Some(Direction::Guest)
        );
        // Reflection is rejected before decryption: feeding the host its own
        // packet fails even though the tag is valid.
        let mut scratch = [0u8; 512];
        assert!(
            host.process_input(&host_wire[..host_len], 1.0, &mut scratch)
                .is_err()
        );
        assert!(
            guest
                .process_input(&guest_wire[..guest_len], 1.0, &mut scratch)
                .is_err()
        );
        // Cross-direction delivery still works.
        assert!(
            guest
                .process_input(&host_wire[..host_len], 1.0, &mut scratch)
                .is_ok()
        );
        assert!(
            host.process_input(&guest_wire[..guest_len], 1.0, &mut scratch)
                .is_ok()
        );
    }

    /// An acknowledgement the cadence produced carries the keepalive flag and
    /// points at nothing, because nothing prompted it.
    #[test]
    fn a_cadence_acknowledgement_is_flagged_keepalive() {
        let mut arena = Arena::new();
        let mut session = endpoint(&mut arena, 0.0);
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];

        session.poll(ACK_CADENCE_MS);
        let written = session
            .get_output(ACK_CADENCE_MS, &mut wire)
            .unwrap()
            .unwrap();

        let opened = session
            .envelope
            .open(&wire[..written], &mut scratch)
            .unwrap();
        let Packet::Ack(ack) = packet::parse(opened.cleartext).unwrap() else {
            panic!("expected an acknowledgement");
        };
        assert_eq!(ack.kind, AckKind::Keepalive);
        assert!(!ack.nack);
        assert_eq!((ack.trigger_channel, ack.trigger_seq), (0, 0));
    }

    /// One that data prompted is an ordinary acknowledgement and does point at
    /// what prompted it, which is what drives the peer's fast retransmission.
    #[test]
    fn a_data_acknowledgement_keeps_its_trigger() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"x").unwrap();
        pump(&mut left, &mut right, 1.0);

        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let written = right.get_output(2.0, &mut wire).unwrap().unwrap();
        let opened = right.envelope.open(&wire[..written], &mut scratch).unwrap();
        let Packet::Ack(ack) = packet::parse(opened.cleartext).unwrap() else {
            panic!("expected an acknowledgement");
        };
        assert_eq!(ack.kind, AckKind::Ack);
        assert_eq!(ack.trigger_channel, VIDEO);
    }

    /// The regression for an idle session dying. Nothing is sent by the
    /// application for well past the hard liveness deadline, and both ends stay
    /// alive on the cadence alone.
    #[test]
    fn an_idle_pair_survives_past_the_hard_liveness_deadline() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        let mut now = 0.0;
        while now < LIVENESS_HARD_MS + 10_000.0 {
            now += ACK_CADENCE_MS;
            left.poll(now);
            right.poll(now);
            pump(&mut left, &mut right, now);
            pump(&mut right, &mut left, now);
        }

        assert_eq!(left.health(now), Health::Alive, "the idle sender died");
        assert_eq!(right.health(now), Health::Alive, "the idle receiver died");
    }

    /// **The regression for a peer that stopped receiving and never stopped
    /// talking.** Its acknowledgements keep arriving on the cadence, so every
    /// deadline that watches the inbound direction is satisfied for ever,
    /// while nothing queued for it is ever delivered and all of it is
    /// retransmitted for as long as the session lasts.
    #[test]
    fn a_peer_that_acknowledges_nothing_is_undeliverable() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"x").unwrap();

        let mut now = 0.0;
        while now < DELIVERY_DEADLINE_MS {
            now += ACK_CADENCE_MS;
            left.poll(now);
            right.poll(now);
            // Only one direction. The peer is heard from throughout and
            // receives nothing, which is the shape of a broken return path and
            // of a peer that has stopped reading.
            discard(&mut left, now);
            pump(&mut right, &mut left, now);
        }

        assert_eq!(
            left.health(now),
            Health::Undeliverable,
            "a window that has moved by nothing for the whole deadline"
        );
        assert_eq!(
            right.health(now),
            Health::Alive,
            "the end with nothing outstanding is not the one at fault"
        );
    }

    /// **The peer is reachable, is acknowledging, and is still not receiving
    /// the stream.** Its control channel keeps up while its video ring takes
    /// nothing, which is what a peer that has stopped draining looks like from
    /// here. A deadline summed across channels never fires, because the cheap
    /// channel refreshes it for the expensive one.
    #[test]
    fn a_channel_that_is_not_draining_is_undeliverable_while_another_keeps_up() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint_pair(&mut left_arena, 0.0, true);
        // No video receive ring: everything sent on it is unhandled and never
        // acknowledged, while control is taken normally.
        let mut right = endpoint_pair_guest(&mut right_arena, 0.0, false);

        left.send_message(VIDEO, &[], b"x").unwrap();

        let mut now = 0.0;
        while now < DELIVERY_DEADLINE_MS {
            now += ACK_CADENCE_MS;
            left.send_message(CONTROL, &[], b"c").unwrap();
            left.poll(now);
            right.poll(now);
            pump(&mut left, &mut right, now);
            pump(&mut right, &mut left, now);
            let mut body = [0u8; SLOT];
            while right.take_message(CONTROL, &mut body).is_some() {}
        }

        assert_eq!(
            left.health(now),
            Health::Undeliverable,
            "the channel that is not moving decides this, not the one that is"
        );
    }

    /// The control for the test above: the same duration, the same traffic,
    /// and the acknowledgements getting through. **A congested path fills a
    /// window and looks identical from the send side**, so the deadline has to
    /// be judged on the acknowledgements and not on the window.
    #[test]
    fn a_peer_that_keeps_acknowledging_survives_the_delivery_deadline() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        // **Something is outstanding the whole way through**, enqueued at the
        // end of each pass and acknowledged at the start of the next, so the
        // window is never empty when health is judged. A deadline that read
        // the window rather than the acknowledgements would end this session,
        // and this is the traffic it would end.
        let mut now = 0.0;
        left.send_message(VIDEO, &[], b"x").unwrap();
        while now < DELIVERY_DEADLINE_MS + 5_000.0 {
            now += ACK_CADENCE_MS;
            left.poll(now);
            right.poll(now);
            pump(&mut left, &mut right, now);
            pump(&mut right, &mut left, now);
            // Read, so the receive ring keeps taking new fragments.
            let mut body = [0u8; SLOT];
            while right.take_message(VIDEO, &mut body).is_some() {}
            left.send_message(VIDEO, &[], b"x").unwrap();
        }

        assert!(
            left.transport_stats().in_flight > 0,
            "the check is only worth anything with a window to misread"
        );
        assert_eq!(left.health(now), Health::Alive, "a delivering peer died");
    }

    #[test]
    fn liveness_degrades_then_dies() {
        let mut arena = Arena::new();
        let session = endpoint(&mut arena, 0.0);
        assert_eq!(session.health(0.0), Health::Alive);
        assert_eq!(session.health(LIVENESS_SOFT_MS), Health::Stalled);
        assert_eq!(session.health(LIVENESS_HARD_MS), Health::Dead);
    }

    #[test]
    fn the_timer_tracks_the_acknowledgement_cadence() {
        let mut arena = Arena::new();
        let session = endpoint(&mut arena, 0.0);
        assert!((session.next_timer_ms(0.0) - ACK_CADENCE_MS).abs() < 1e-9);
        assert!((session.next_timer_ms(10.0) - 20.0).abs() < 1e-9);
        assert!(
            (session.next_timer_ms(1000.0)).abs() < 1e-9,
            "must not go negative"
        );
    }

    #[test]
    fn a_channel_without_a_ring_is_reported_not_fatal() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        // Left sends on the video channel; right detaches its ring first.
        right.recv[VIDEO as usize] = None;
        left.send_message(VIDEO, &[], b"x").unwrap();

        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let result = left.get_output(1.0, &mut wire).unwrap().unwrap();
        assert_eq!(
            right
                .process_input(&wire[..result], 1.0, &mut scratch)
                .unwrap(),
            Inbound::Unhandled { channel: VIDEO }
        );
    }

    #[test]
    fn a_forged_datagram_is_refused() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(&mut left_arena, 0.0);
        let mut right = endpoint_guest(&mut right_arena, 0.0);

        left.send_message(VIDEO, &[], b"x").unwrap();
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let written = left.get_output(1.0, &mut wire).unwrap().unwrap();
        wire[ENVELOPE_LEN] ^= 0xFF;
        assert_eq!(
            right.process_input(&wire[..written], 1.0, &mut scratch),
            Err(Error::Decrypt)
        );
    }
}
