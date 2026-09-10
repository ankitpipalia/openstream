use std::collections::VecDeque;
use std::fmt;

use openstream_protocol::Kind;
use openstream_protocol::transport_meta::TRANSPORT_META_CHANNEL;
use openstream_transport_policy::{MAX_BURST_DATAGRAMS, MAX_BURST_TIME_MS, Pacer, PacerConfig};

/// The largest sealed datagram accepted by the portable protocol.
pub const PORTABLE_WIRE_DATAGRAM_BYTES: usize = openstream_protocol::MAX_DATAGRAM;
/// The default portable wire pacing ceiling, in decimal megabits per second.
pub const DEFAULT_WIRE_RATE_MBPS: f64 = 30.0;

/// Maximum number of queued packets for each application class.
pub const CRITICAL_QUEUE_CAPACITY: usize = 256;
pub const AUDIO_QUEUE_CAPACITY: usize = 32;
pub const VIDEO_QUEUE_CAPACITY: usize = 256;

const WIRE_OVERHEAD_BYTES: usize = openstream_protocol::HEADER_LEN + openstream_protocol::TAG_LEN;
const DEFAULT_GENERATION: u64 = 1;

/// Application output class selected by the bounded scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundClass {
    /// Ordered control and input packets.
    Critical,
    /// Interactive audio packets.
    Audio,
    /// Bulk video packets.
    Video,
}

impl OutboundClass {
    fn from_kind(kind: Kind) -> Self {
        match kind {
            Kind::Control | Kind::Input => Self::Critical,
            Kind::Audio => Self::Audio,
            Kind::Video => Self::Video,
        }
    }
}

/// A clear packet retained until the scheduler admits it for emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPacket {
    pub class: OutboundClass,
    pub kind: Kind,
    pub channel: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub logical_retransmission: bool,
}

impl PendingPacket {
    fn wire_len(&self) -> usize {
        WIRE_OVERHEAD_BYTES + self.payload.len()
    }
}

/// Result of placing one packet into a bounded class queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOutcome {
    Queued,
    DroppedOldest,
}

/// Failures that prevent a packet from being queued or admitted for emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    QueueFull,
    InvalidPacket,
    HistoryFull,
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::QueueFull => "critical outbound queue is full",
            Self::InvalidPacket => "outbound packet is invalid or exceeds the portable wire limit",
            Self::HistoryFull => "delivery history is full",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SchedulerError {}

/// Bounded, Tokio-independent portable output scheduler.
#[derive(Debug, Clone)]
pub struct OutboundScheduler {
    critical: VecDeque<PendingPacket>,
    audio: VecDeque<PendingPacket>,
    video: VecDeque<PendingPacket>,
    pacer: Pacer,
    wire_rate_mbps: f64,
    generation: u64,
    critical_debt_bytes: usize,
    audio_debt_bytes: usize,
}

impl OutboundScheduler {
    /// Create a scheduler with the portable wire ceiling and default rate.
    pub fn new(now_ms: f64) -> Self {
        let mut scheduler = Self {
            critical: VecDeque::with_capacity(CRITICAL_QUEUE_CAPACITY),
            audio: VecDeque::with_capacity(AUDIO_QUEUE_CAPACITY),
            video: VecDeque::with_capacity(VIDEO_QUEUE_CAPACITY),
            pacer: Self::new_pacer(now_ms),
            wire_rate_mbps: 0.0,
            generation: DEFAULT_GENERATION,
            critical_debt_bytes: 0,
            audio_debt_bytes: 0,
        };
        scheduler.set_wire_rate_mbps(now_ms, DEFAULT_WIRE_RATE_MBPS);
        scheduler
    }

    /// Queue one clear packet without reserving or consuming a cipher counter.
    pub fn queue(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
        logical_retransmission: bool,
    ) -> Result<QueueOutcome, SchedulerError> {
        if kind == Kind::Control && channel == TRANSPORT_META_CHANNEL {
            return Err(SchedulerError::InvalidPacket);
        }
        if payload
            .len()
            .checked_add(WIRE_OVERHEAD_BYTES)
            .is_none_or(|wire_len| wire_len > PORTABLE_WIRE_DATAGRAM_BYTES)
        {
            return Err(SchedulerError::InvalidPacket);
        }

        let class = OutboundClass::from_kind(kind);
        let packet = PendingPacket {
            class,
            kind,
            channel,
            flags,
            payload: payload.to_vec(),
            logical_retransmission,
        };

        let (queue, capacity) = match class {
            OutboundClass::Critical => (&mut self.critical, CRITICAL_QUEUE_CAPACITY),
            OutboundClass::Audio => (&mut self.audio, AUDIO_QUEUE_CAPACITY),
            OutboundClass::Video => (&mut self.video, VIDEO_QUEUE_CAPACITY),
        };
        if queue.len() == capacity {
            if class == OutboundClass::Critical {
                return Err(SchedulerError::QueueFull);
            }
            let _ = queue.pop_front();
            queue.push_back(packet);
            return Ok(QueueOutcome::DroppedOldest);
        }
        queue.push_back(packet);
        Ok(QueueOutcome::Queued)
    }

    /// Admit and remove the next packet, without sealing it.
    ///
    /// The callback is checked before the packet leaves its queue. Its
    /// argument is the next cipher outer counter that the caller intends to
    /// use for the eventual sealed packet.
    pub fn pop_due<F>(
        &mut self,
        now_ms: f64,
        next_outer_counter: u64,
        mut can_record: F,
    ) -> Result<Option<PendingPacket>, SchedulerError>
    where
        F: FnMut(u64) -> bool,
    {
        let Some(class) = self.select_class(now_ms) else {
            return Ok(None);
        };

        let queue = match class {
            OutboundClass::Critical => &mut self.critical,
            OutboundClass::Audio => &mut self.audio,
            OutboundClass::Video => &mut self.video,
        };
        let Some(packet) = queue.front() else {
            return Ok(None);
        };
        let wire_len = packet.wire_len();

        if !can_record(next_outer_counter) {
            return Err(SchedulerError::HistoryFull);
        }

        if class == OutboundClass::Video && !self.pacer.try_consume(now_ms, wire_len) {
            return Ok(None);
        }

        let packet = queue.pop_front().expect("front packet was checked");
        self.record_service(class, wire_len);
        Ok(Some(packet))
    }

    /// Return the exact absolute timestamp at which queued work next becomes
    /// serviceable, or `None` when no work is queued.
    pub fn next_wake_ms(&self, now_ms: f64) -> Option<f64> {
        if self.select_class(now_ms).is_some() {
            return Some(now_ms);
        }

        let packet = self.video.front()?;
        let wait_ms = self.pacer.wait_ms(now_ms, packet.wire_len());
        if wait_ms.is_finite() {
            Some(now_ms + wait_ms)
        } else {
            None
        }
    }

    /// Number of packets retained across all application queues.
    pub fn pending(&self) -> usize {
        self.critical
            .len()
            .saturating_add(self.audio.len())
            .saturating_add(self.video.len())
    }

    /// Change the independent portable wire pacing rate.
    ///
    /// Zero, non-finite, and negative values disable pacing through the shared
    /// policy's fail-closed rate handling.
    pub fn set_wire_rate_mbps(&mut self, now_ms: f64, rate_mbps: f64) {
        self.pacer.set_rate(now_ms, rate_mbps);
        self.wire_rate_mbps = self.pacer.rate_mbps();
        self.clamp_debt();
    }

    /// Reset path-local pacing and fairness state for a new generation.
    /// Queued clear packets remain owned by their class queues.
    pub fn reset_generation(&mut self, now_ms: f64, generation: u64) {
        if generation == 0 {
            return;
        }
        self.generation = generation;
        self.pacer = Self::new_pacer(now_ms);
        self.pacer.set_rate(now_ms, self.wire_rate_mbps);
        self.critical_debt_bytes = 0;
        self.audio_debt_bytes = 0;
    }

    /// Current portable sealed datagram ceiling used by the pacer.
    pub fn wire_datagram_bytes(&self) -> usize {
        self.pacer.datagram_size()
    }

    /// Current independent wire pacing rate.
    pub fn wire_rate_mbps(&self) -> f64 {
        self.wire_rate_mbps
    }

    /// Current path generation associated with this scheduler.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn new_pacer(now_ms: f64) -> Pacer {
        let config = PacerConfig {
            min_datagram_bytes: PORTABLE_WIRE_DATAGRAM_BYTES,
            max_datagram_bytes: PORTABLE_WIRE_DATAGRAM_BYTES,
            max_burst_datagrams: MAX_BURST_DATAGRAMS,
            max_burst_time_ms: MAX_BURST_TIME_MS,
        };
        Pacer::with_config(now_ms, config).expect("portable pacer configuration is valid")
    }

    fn select_class(&self, now_ms: f64) -> Option<OutboundClass> {
        if !self.critical.is_empty() && !self.priority_must_yield(OutboundClass::Critical, now_ms) {
            return Some(OutboundClass::Critical);
        }
        if !self.audio.is_empty() && !self.priority_must_yield(OutboundClass::Audio, now_ms) {
            return Some(OutboundClass::Audio);
        }
        self.video_due(now_ms).then_some(OutboundClass::Video)
    }

    fn priority_must_yield(&self, class: OutboundClass, now_ms: f64) -> bool {
        let lower_due = match class {
            OutboundClass::Critical => !self.audio.is_empty() || self.video_due(now_ms),
            OutboundClass::Audio => self.video_due(now_ms),
            OutboundClass::Video => false,
        };
        if !lower_due {
            return false;
        }
        let debt = match class {
            OutboundClass::Critical => self.critical_debt_bytes,
            OutboundClass::Audio => self.audio_debt_bytes,
            OutboundClass::Video => 0,
        };
        debt >= self.priority_quantum_bytes()
    }

    fn video_due(&self, now_ms: f64) -> bool {
        self.video
            .front()
            .is_some_and(|packet| self.pacer.can_consume(now_ms, packet.wire_len()))
    }

    fn priority_quantum_bytes(&self) -> usize {
        let datagram = self.pacer.datagram_size();
        let packet_cap = datagram.saturating_mul(MAX_BURST_DATAGRAMS);
        let rate_bytes_per_ms = self.wire_rate_mbps * 1_000_000.0 / 8.0 / 1_000.0;
        let time_cap = rate_bytes_per_ms * 2.0;
        let quantum = time_cap.max(datagram as f64).min(packet_cap as f64);
        if !quantum.is_finite() || quantum <= 0.0 {
            return datagram;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "quantum is bounded by the fixed four-datagram portable burst"
        )]
        {
            quantum.ceil() as usize
        }
    }

    fn record_service(&mut self, class: OutboundClass, wire_len: usize) {
        let quantum = self.priority_quantum_bytes();
        match class {
            OutboundClass::Critical => {
                self.critical_debt_bytes = self
                    .critical_debt_bytes
                    .saturating_add(wire_len)
                    .min(quantum);
            }
            OutboundClass::Audio => {
                self.critical_debt_bytes = 0;
                self.audio_debt_bytes = self.audio_debt_bytes.saturating_add(wire_len).min(quantum);
            }
            OutboundClass::Video => {
                self.critical_debt_bytes = 0;
                self.audio_debt_bytes = 0;
            }
        }
    }

    fn clamp_debt(&mut self) {
        let quantum = self.priority_quantum_bytes();
        self.critical_debt_bytes = self.critical_debt_bytes.min(quantum);
        self.audio_debt_bytes = self.audio_debt_bytes.min(quantum);
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;
    use std::cell::Cell;

    const MAX_PAYLOAD: usize = openstream_protocol::MAX_PLAINTEXT;

    fn scheduler() -> OutboundScheduler {
        OutboundScheduler::new(0.0)
    }

    fn queue_packet(
        scheduler: &mut OutboundScheduler,
        kind: Kind,
        payload: &[u8],
    ) -> Result<QueueOutcome, SchedulerError> {
        scheduler.queue(kind, 7, 3, payload, false)
    }

    fn pop(scheduler: &mut OutboundScheduler, now_ms: f64) -> PendingPacket {
        scheduler
            .pop_due(now_ms, 0, |_| true)
            .expect("scheduler admission succeeds")
            .expect("packet is queued")
    }

    #[test]
    fn queue_classifies_control_and_input_as_critical() {
        let mut scheduler = scheduler();
        queue_packet(&mut scheduler, Kind::Control, b"control").unwrap();
        assert_eq!(pop(&mut scheduler, 0.0).class, OutboundClass::Critical);

        queue_packet(&mut scheduler, Kind::Input, b"input").unwrap();
        assert_eq!(pop(&mut scheduler, 0.0).class, OutboundClass::Critical);
    }

    #[test]
    fn queue_classifies_audio_and_video_separately() {
        let mut scheduler = scheduler();
        queue_packet(&mut scheduler, Kind::Audio, b"audio").unwrap();
        assert_eq!(pop(&mut scheduler, 0.0).class, OutboundClass::Audio);

        scheduler.set_wire_rate_mbps(0.0, 0.0);
        queue_packet(&mut scheduler, Kind::Video, b"video").unwrap();
        assert_eq!(pop(&mut scheduler, 0.0).class, OutboundClass::Video);
    }

    #[test]
    fn class_capacities_are_exact_and_critical_backpressures() {
        let mut critical = scheduler();
        for _ in 0..256 {
            assert_eq!(
                queue_packet(&mut critical, Kind::Control, b"c"),
                Ok(QueueOutcome::Queued)
            );
        }
        assert_eq!(critical.pending(), 256);
        assert_eq!(
            queue_packet(&mut critical, Kind::Input, b"c"),
            Err(SchedulerError::QueueFull)
        );

        let mut audio = scheduler();
        for _ in 0..32 {
            assert_eq!(
                queue_packet(&mut audio, Kind::Audio, b"a"),
                Ok(QueueOutcome::Queued)
            );
        }
        assert_eq!(audio.pending(), 32);
        assert_eq!(
            queue_packet(&mut audio, Kind::Audio, b"a"),
            Ok(QueueOutcome::DroppedOldest)
        );
        assert_eq!(audio.pending(), 32);

        let mut video = scheduler();
        for _ in 0..256 {
            assert_eq!(
                queue_packet(&mut video, Kind::Video, b"v"),
                Ok(QueueOutcome::Queued)
            );
        }
        assert_eq!(video.pending(), 256);
        assert_eq!(
            queue_packet(&mut video, Kind::Video, b"v"),
            Ok(QueueOutcome::DroppedOldest)
        );
        assert_eq!(video.pending(), 256);
    }

    #[test]
    fn audio_and_video_saturation_drop_the_oldest_packet() {
        let mut audio = scheduler();
        queue_packet(&mut audio, Kind::Audio, &[0]).unwrap();
        for _ in 1..32 {
            queue_packet(&mut audio, Kind::Audio, &[1]).unwrap();
        }
        assert_eq!(
            queue_packet(&mut audio, Kind::Audio, &[2]),
            Ok(QueueOutcome::DroppedOldest)
        );
        assert_eq!(pop(&mut audio, 0.0).payload, vec![1]);

        let mut video = scheduler();
        video.set_wire_rate_mbps(0.0, 0.0);
        queue_packet(&mut video, Kind::Video, &[0]).unwrap();
        for _ in 1..256 {
            queue_packet(&mut video, Kind::Video, &[1]).unwrap();
        }
        assert_eq!(
            queue_packet(&mut video, Kind::Video, &[2]),
            Ok(QueueOutcome::DroppedOldest)
        );
        assert_eq!(pop(&mut video, 0.0).payload, vec![1]);
    }

    #[test]
    fn oversized_payload_is_rejected_before_queueing() {
        let mut scheduler = scheduler();
        assert_eq!(
            queue_packet(&mut scheduler, Kind::Video, &vec![0; MAX_PAYLOAD + 1]),
            Err(SchedulerError::InvalidPacket)
        );
        assert_eq!(scheduler.pending(), 0);
    }

    #[test]
    fn transport_ack_is_not_an_application_queue_entry() {
        let mut scheduler = scheduler();
        assert_eq!(
            scheduler.queue(Kind::Control, TRANSPORT_META_CHANNEL, 0, &[0; 32], false,),
            Err(SchedulerError::InvalidPacket)
        );
        assert_eq!(scheduler.pending(), 0);
    }

    #[test]
    fn queued_packets_do_not_attempt_history_admission_until_pop() {
        let mut scheduler = scheduler();
        queue_packet(&mut scheduler, Kind::Control, b"control").unwrap();
        let calls = Cell::new(0);
        assert_eq!(scheduler.pending(), 1);
        let packet = scheduler
            .pop_due(0.0, 41, |counter| {
                assert_eq!(counter, 41);
                calls.set(calls.get() + 1);
                true
            })
            .unwrap()
            .unwrap();
        assert_eq!(packet.payload, b"control");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn can_record_backpressure_preserves_the_pending_packet() {
        let mut scheduler = scheduler();
        queue_packet(&mut scheduler, Kind::Control, b"control").unwrap();
        assert_eq!(
            scheduler.pop_due(0.0, 41, |_| false),
            Err(SchedulerError::HistoryFull)
        );
        assert_eq!(scheduler.pending(), 1);
    }

    #[test]
    fn video_pacer_uses_full_wire_length_and_exact_refill_wake() {
        let mut scheduler = scheduler();
        assert_eq!(scheduler.wire_datagram_bytes(), 1200);
        assert!((scheduler.wire_rate_mbps() - 30.0).abs() < f64::EPSILON);
        scheduler.set_wire_rate_mbps(0.0, 1.0);
        let payload = vec![0; MAX_PAYLOAD];
        queue_packet(&mut scheduler, Kind::Video, &payload).unwrap();
        queue_packet(&mut scheduler, Kind::Video, &payload).unwrap();

        assert_eq!(pop(&mut scheduler, 0.0).payload.len(), MAX_PAYLOAD);
        assert_eq!(scheduler.pop_due(0.0, 1, |_| true), Ok(None));
        assert_eq!(scheduler.pending(), 1);
        let wake = scheduler.next_wake_ms(0.0).unwrap();
        assert!((wake - 9.6).abs() < 1e-12, "wake={wake}");
        assert_eq!(pop(&mut scheduler, wake).payload.len(), MAX_PAYLOAD);
    }

    #[test]
    fn continuous_critical_traffic_cannot_starve_video() {
        let mut scheduler = scheduler();
        queue_packet(&mut scheduler, Kind::Control, &vec![0; 1000]).unwrap();
        queue_packet(&mut scheduler, Kind::Video, b"video").unwrap();
        let mut video_seen = false;
        for now_ms in (0..100).map(f64::from) {
            queue_packet(&mut scheduler, Kind::Control, &vec![0; 1000]).ok();
            if scheduler
                .pop_due(now_ms, 0, |_| true)
                .unwrap()
                .is_some_and(|packet| packet.class == OutboundClass::Video)
            {
                video_seen = true;
                break;
            }
        }
        assert!(video_seen);
    }

    #[test]
    fn reset_generation_restores_pacer_credit_and_clears_priority_debt() {
        let mut scheduler = scheduler();
        scheduler.set_wire_rate_mbps(0.0, 1.0);
        let payload = vec![0; MAX_PAYLOAD];
        queue_packet(&mut scheduler, Kind::Video, &payload).unwrap();
        queue_packet(&mut scheduler, Kind::Video, &payload).unwrap();
        pop(&mut scheduler, 0.0);
        assert_eq!(scheduler.pop_due(0.0, 1, |_| true), Ok(None));

        scheduler.reset_generation(0.0, 2);
        assert_eq!(pop(&mut scheduler, 0.0).payload.len(), MAX_PAYLOAD);
    }
}
