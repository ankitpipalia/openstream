use core::fmt;

/// Number of fixed delivery-history slots.
///
/// At the portable default wire size (1,200 bytes), this supports the
/// documented 100 Mbps / 100 ms bandwidth-delay envelope with headroom while
/// keeping the estimator allocation-free and bounded.
pub const DELIVERY_HISTORY_CAPACITY: usize = 2_048;
/// Age at which an unresolved history entry may be explicitly evicted.
pub const STALE_AFTER_MS: f64 = 250.0;
/// Minimum interval used when producing a delivery-rate sample.
pub const MIN_DELIVERY_SAMPLE_INTERVAL_MS: f64 = 10.0;
/// Maximum receiver-controlled ACK delay accepted by the estimator.
pub const MAX_ACK_DELAY_US: u32 = 25_000;

const DELIVERY_CLASS_COUNT: usize = 3;

/// Application traffic classes understood by the shared transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// Ordered control and input traffic share the critical class.
    Critical,
    /// Interactive audio traffic.
    Audio,
    /// Bulk video traffic.
    Video,
}

impl TrafficClass {
    const fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::Audio => 1,
            Self::Video => 2,
        }
    }
}

/// Complete identity and send metadata for one encrypted outer packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SentPacket {
    pub generation: u64,
    pub outer_counter: u64,
    pub bytes: u32,
    pub sent_at_ms: f64,
    pub traffic_class: TrafficClass,
    pub ack_eliciting: bool,
    pub logical_retransmission: bool,
}

/// Result of recording one sent packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOutcome {
    /// Whether an aged unresolved entry was classified stale and replaced.
    pub stale_evicted: bool,
    /// Whether this was a newly sealed logical reliable-control retry.
    pub logical_retransmission: bool,
    /// Whether this was an explicitly supported resend of the same outer
    /// counter while its original history entry was still unresolved.
    pub outer_retransmission: bool,
}

impl SendOutcome {
    const fn new(
        stale_evicted: bool,
        logical_retransmission: bool,
        outer_retransmission: bool,
    ) -> Self {
        Self {
            stale_evicted,
            logical_retransmission,
            outer_retransmission,
        }
    }
}

/// Result of applying one authenticated transport ACK.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AckOutcome {
    /// Number of history entries retired by this ACK.
    pub newly_acknowledged_packets: u32,
    /// Unique wire bytes retired by this ACK.
    pub newly_acknowledged_bytes: u64,
    /// RTT sample from `largest_counter` when that packet is newly
    /// acknowledged by this ACK, when present.
    pub rtt_sample_ms: Option<f64>,
    /// True only for the stale-generation compatibility outcome.
    pub ignored_stale_generation: bool,
}

impl AckOutcome {
    /// Compatibility value returned for an ACK from an older path generation.
    #[allow(non_upper_case_globals)]
    pub const IgnoredStaleGeneration: Self = Self {
        newly_acknowledged_packets: 0,
        newly_acknowledged_bytes: 0,
        rtt_sample_ms: None,
        ignored_stale_generation: true,
    };

    const fn acknowledged(
        newly_acknowledged_packets: u32,
        newly_acknowledged_bytes: u64,
        rtt_sample_ms: Option<f64>,
    ) -> Self {
        Self {
            newly_acknowledged_packets,
            newly_acknowledged_bytes,
            rtt_sample_ms,
            ignored_stale_generation: false,
        }
    }
}

/// Errors produced while validating or updating delivery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    /// A generation value of zero is not a usable path generation.
    InvalidGeneration,
    /// A packet or ACK belongs to a later generation than the estimator.
    FutureGeneration,
    /// A sent packet belongs to an earlier generation than the estimator.
    StaleGeneration,
    /// A caller supplied a NaN, infinity, negative, or backward timestamp.
    InvalidTimestamp,
    /// A bitmap bit refers to a counter below zero.
    CounterUnderflow,
    /// The ACK largest counter is above the highest counter sent here.
    FutureCounter,
    /// The receiver-controlled ACK delay exceeds the bounded wire value.
    AckDelayTooLarge,
    /// The target fixed-ring slot still contains a young unresolved entry.
    HistoryFull,
    /// A counter was reused after its history entry was retired or with a
    /// different packet identity.
    CounterReuse,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidGeneration => "delivery generation must be non-zero",
            Self::FutureGeneration => "delivery generation is from the future",
            Self::StaleGeneration => "delivery generation is stale",
            Self::InvalidTimestamp => "delivery timestamp is invalid or moved backward",
            Self::CounterUnderflow => "delivery acknowledgement counter underflows",
            Self::FutureCounter => "delivery acknowledgement counter is from the future",
            Self::AckDelayTooLarge => "delivery acknowledgement delay is too large",
            Self::HistoryFull => "delivery history slot is still unresolved",
            Self::CounterReuse => "delivery outer counter was reused",
        };
        formatter.write_str(message)
    }
}

/// Counters for one traffic class or the aggregate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeliveryClassSnapshot {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub acknowledged_packets: u64,
    pub acknowledged_bytes: u64,
    pub delivery_rate_mbps: Option<f64>,
    pub in_flight: u32,
    pub stale: u64,
    pub logical_reliable_retries: u64,
    pub outer_retransmissions: u64,
}

/// Aggregate and per-class packet delivery telemetry for one path generation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeliverySnapshot {
    pub path_generation: u64,
    pub sample_interval_ms: f64,
    pub srtt_ms: Option<f64>,
    pub aggregate: DeliveryClassSnapshot,
    pub video: DeliveryClassSnapshot,
    pub audio: DeliveryClassSnapshot,
    pub critical: DeliveryClassSnapshot,
}

/// A small conversion boundary for client-facing diagnostics.
///
/// The policy crate owns the dependency-free snapshot shape. Higher-level
/// clients can expose an address-free representation without making the
/// media crate depend on a concrete session implementation.
pub trait DeliverySnapshotView {
    fn delivery_snapshot(&self) -> DeliverySnapshot;
}

impl DeliverySnapshotView for DeliverySnapshot {
    fn delivery_snapshot(&self) -> DeliverySnapshot {
        *self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ClassState {
    sent_packets: u64,
    sent_bytes: u64,
    acknowledged_packets: u64,
    acknowledged_bytes: u64,
    delivery_rate_mbps: Option<f64>,
    in_flight: u32,
    stale: u64,
    logical_reliable_retries: u64,
    outer_retransmissions: u64,
    rate_bytes: u64,
}

impl ClassState {
    const fn empty() -> Self {
        Self {
            sent_packets: 0,
            sent_bytes: 0,
            acknowledged_packets: 0,
            acknowledged_bytes: 0,
            delivery_rate_mbps: None,
            in_flight: 0,
            stale: 0,
            logical_reliable_retries: 0,
            outer_retransmissions: 0,
            rate_bytes: 0,
        }
    }

    const fn snapshot(self) -> DeliveryClassSnapshot {
        DeliveryClassSnapshot {
            sent_packets: self.sent_packets,
            sent_bytes: self.sent_bytes,
            acknowledged_packets: self.acknowledged_packets,
            acknowledged_bytes: self.acknowledged_bytes,
            delivery_rate_mbps: self.delivery_rate_mbps,
            in_flight: self.in_flight,
            stale: self.stale,
            logical_reliable_retries: self.logical_reliable_retries,
            outer_retransmissions: self.outer_retransmissions,
        }
    }
}

/// Dependency-free fixed-size packet-delivery estimator.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryEstimator {
    generation: u64,
    /// The only delivery-history storage. ACK matching must verify the full
    /// generation/counter identity after selecting this modulo slot.
    history: [Option<SentPacket>; DELIVERY_HISTORY_CAPACITY],
    highest_sent: Option<u64>,
    aggregate: ClassState,
    classes: [ClassState; DELIVERY_CLASS_COUNT],
    srtt_ms: Option<f64>,
    last_timestamp_ms: Option<f64>,
    rate_sample_start_ms: Option<f64>,
    sample_interval_ms: f64,
}

impl DeliveryEstimator {
    /// Create an empty estimator for one non-zero path generation.
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            history: [None; DELIVERY_HISTORY_CAPACITY],
            highest_sent: None,
            aggregate: ClassState::empty(),
            classes: [ClassState::empty(); DELIVERY_CLASS_COUNT],
            srtt_ms: None,
            last_timestamp_ms: None,
            rate_sample_start_ms: None,
            sample_interval_ms: 0.0,
        }
    }

    /// Whether the next ack-eliciting packet can reserve its ring slot.
    pub fn can_record(&self, generation: u64, outer_counter: u64, now_ms: f64) -> bool {
        if generation == 0 || generation != self.generation || !self.acceptable_timestamp(now_ms) {
            return false;
        }
        if let Some(highest_sent) = self.highest_sent {
            if outer_counter <= highest_sent {
                let index = slot_index(outer_counter);
                return self.history[index].is_some_and(|entry| {
                    entry.generation == generation && entry.outer_counter == outer_counter
                });
            }
        }

        let index = slot_index(outer_counter);
        match self.history[index] {
            None => true,
            Some(entry) => elapsed_ms(now_ms, entry.sent_at_ms) >= STALE_AFTER_MS,
        }
    }

    /// Record one successfully emitted packet and its complete identity.
    pub fn record_sent(&mut self, packet: SentPacket) -> Result<SendOutcome, DeliveryError> {
        self.validate_packet(&packet)?;

        if let Some(highest_sent) = self.highest_sent {
            if packet.outer_counter <= highest_sent {
                let index = slot_index(packet.outer_counter);
                if packet.ack_eliciting
                    && self.history[index].is_some_and(|entry| {
                        entry.generation == packet.generation
                            && entry.outer_counter == packet.outer_counter
                    })
                {
                    let existing =
                        self.history[index].expect("the matching history entry was checked above");
                    if existing.bytes != packet.bytes
                        || existing.traffic_class != packet.traffic_class
                        || !existing.ack_eliciting
                    {
                        return Err(DeliveryError::CounterReuse);
                    }
                    self.history[index] = Some(packet);
                    self.record_sent_stats(packet, true);
                    self.last_timestamp_ms = Some(packet.sent_at_ms);
                    return Ok(SendOutcome::new(false, false, true));
                }
                return Err(DeliveryError::CounterReuse);
            }
        }

        let mut stale_evicted = false;
        if packet.ack_eliciting {
            let index = slot_index(packet.outer_counter);
            if let Some(existing) = self.history[index] {
                let age_ms = elapsed_ms(packet.sent_at_ms, existing.sent_at_ms);
                if age_ms < STALE_AFTER_MS {
                    return Err(DeliveryError::HistoryFull);
                }
                self.mark_stale(existing);
                self.history[index] = None;
                stale_evicted = true;
            }
            self.history[index] = Some(packet);
            self.add_in_flight(packet.traffic_class);
            if self.rate_sample_start_ms.is_none() {
                self.rate_sample_start_ms = Some(packet.sent_at_ms);
            }
        }

        self.record_sent_stats(packet, false);
        self.highest_sent = Some(self.highest_sent.map_or(packet.outer_counter, |highest| {
            highest.max(packet.outer_counter)
        }));
        self.last_timestamp_ms = Some(packet.sent_at_ms);

        Ok(SendOutcome::new(
            stale_evicted,
            packet.logical_retransmission,
            false,
        ))
    }

    /// Apply an authenticated ACK bitmap to the current path generation.
    pub fn acknowledge(
        &mut self,
        generation: u64,
        largest_counter: u64,
        received_mask: u64,
        ack_delay_us: u32,
        now_ms: f64,
    ) -> Result<AckOutcome, DeliveryError> {
        if generation == 0 {
            return Err(DeliveryError::InvalidGeneration);
        }
        if generation < self.generation {
            return Ok(AckOutcome::IgnoredStaleGeneration);
        }
        if generation > self.generation {
            return Err(DeliveryError::FutureGeneration);
        }
        if !self.acceptable_timestamp(now_ms) {
            return Err(DeliveryError::InvalidTimestamp);
        }
        if ack_delay_us > MAX_ACK_DELAY_US {
            return Err(DeliveryError::AckDelayTooLarge);
        }
        if self.highest_sent != Some(largest_counter)
            && self
                .highest_sent
                .is_none_or(|highest| largest_counter > highest)
        {
            return Err(DeliveryError::FutureCounter);
        }
        for bit in 1_u32..64 {
            if received_mask & (1_u64 << bit) != 0 && u64::from(bit) > largest_counter {
                return Err(DeliveryError::CounterUnderflow);
            }
        }

        let mut newly_acknowledged_packets = 0_u32;
        let mut newly_acknowledged_bytes = 0_u64;
        let mut largest_acknowledged: Option<SentPacket> = None;

        for bit in 0_u32..64 {
            if received_mask & (1_u64 << bit) == 0 {
                continue;
            }
            let offset = u64::from(bit);
            let counter = largest_counter - offset;
            let index = slot_index(counter);
            let Some(entry) = self.history[index] else {
                continue;
            };
            if entry.generation != generation || entry.outer_counter != counter {
                continue;
            }

            self.history[index] = None;
            self.mark_acknowledged(entry);
            newly_acknowledged_packets = newly_acknowledged_packets.saturating_add(1);
            newly_acknowledged_bytes =
                newly_acknowledged_bytes.saturating_add(u64::from(entry.bytes));
            // ACK delay is defined relative to largest_counter. Do not use
            // the delay for that packet when a later bitmap merely retires an
            // older packet.
            if bit == 0 {
                largest_acknowledged = Some(entry);
            }
        }

        let rtt_sample_ms = largest_acknowledged.map(|entry| {
            let delay_ms = f64::from(ack_delay_us) / 1_000.0;
            let elapsed = elapsed_ms(now_ms, entry.sent_at_ms);
            (elapsed - delay_ms).max(0.0)
        });
        if let Some(sample_ms) = rtt_sample_ms {
            self.srtt_ms = Some(match self.srtt_ms {
                None => sample_ms,
                Some(previous) => 7.0 / 8.0 * previous + 1.0 / 8.0 * sample_ms,
            });
        }
        self.last_timestamp_ms = Some(now_ms);

        Ok(AckOutcome::acknowledged(
            newly_acknowledged_packets,
            newly_acknowledged_bytes,
            rtt_sample_ms,
        ))
    }

    /// Take an aggregate and per-class snapshot at a monotonic timestamp.
    pub fn snapshot(&mut self, now_ms: f64) -> DeliverySnapshot {
        if self.acceptable_timestamp(now_ms) {
            self.last_timestamp_ms = Some(now_ms);
            self.maybe_sample_rate(now_ms);
        }

        DeliverySnapshot {
            path_generation: self.generation,
            sample_interval_ms: self.sample_interval_ms,
            srtt_ms: self.srtt_ms,
            aggregate: self.aggregate.snapshot(),
            video: self.classes[TrafficClass::Video.index()].snapshot(),
            audio: self.classes[TrafficClass::Audio.index()].snapshot(),
            critical: self.classes[TrafficClass::Critical.index()].snapshot(),
        }
    }

    /// Clear all path-local state for a new non-zero generation.
    ///
    /// A zero generation is invalid and therefore leaves the estimator
    /// untouched.
    pub fn reset_generation(&mut self, generation: u64) {
        if generation == 0 {
            return;
        }
        *self = Self::new(generation);
    }

    fn validate_packet(&self, packet: &SentPacket) -> Result<(), DeliveryError> {
        if packet.generation == 0 {
            return Err(DeliveryError::InvalidGeneration);
        }
        if packet.generation < self.generation {
            return Err(DeliveryError::StaleGeneration);
        }
        if packet.generation > self.generation {
            return Err(DeliveryError::FutureGeneration);
        }
        if !self.acceptable_timestamp(packet.sent_at_ms) {
            return Err(DeliveryError::InvalidTimestamp);
        }
        Ok(())
    }

    fn acceptable_timestamp(&self, timestamp_ms: f64) -> bool {
        timestamp_ms.is_finite()
            && timestamp_ms >= 0.0
            && self
                .last_timestamp_ms
                .is_none_or(|last| timestamp_ms >= last)
    }

    fn record_sent_stats(&mut self, packet: SentPacket, outer_retransmission: bool) {
        let bytes = u64::from(packet.bytes);
        add_sent_stats(&mut self.aggregate, bytes, packet, outer_retransmission);
        add_sent_stats(
            &mut self.classes[packet.traffic_class.index()],
            bytes,
            packet,
            outer_retransmission,
        );
    }

    fn add_in_flight(&mut self, traffic_class: TrafficClass) {
        self.aggregate.in_flight = self.aggregate.in_flight.saturating_add(1);
        let class = &mut self.classes[traffic_class.index()];
        class.in_flight = class.in_flight.saturating_add(1);
    }

    fn mark_stale(&mut self, entry: SentPacket) {
        self.aggregate.in_flight = self.aggregate.in_flight.saturating_sub(1);
        self.aggregate.stale = self.aggregate.stale.saturating_add(1);
        let class = &mut self.classes[entry.traffic_class.index()];
        class.in_flight = class.in_flight.saturating_sub(1);
        class.stale = class.stale.saturating_add(1);
    }

    fn mark_acknowledged(&mut self, entry: SentPacket) {
        let bytes = u64::from(entry.bytes);
        self.aggregate.in_flight = self.aggregate.in_flight.saturating_sub(1);
        self.aggregate.acknowledged_packets = self.aggregate.acknowledged_packets.saturating_add(1);
        self.aggregate.acknowledged_bytes = self.aggregate.acknowledged_bytes.saturating_add(bytes);
        self.aggregate.rate_bytes = self.aggregate.rate_bytes.saturating_add(bytes);

        let class = &mut self.classes[entry.traffic_class.index()];
        class.in_flight = class.in_flight.saturating_sub(1);
        class.acknowledged_packets = class.acknowledged_packets.saturating_add(1);
        class.acknowledged_bytes = class.acknowledged_bytes.saturating_add(bytes);
        class.rate_bytes = class.rate_bytes.saturating_add(bytes);
    }

    fn maybe_sample_rate(&mut self, now_ms: f64) {
        let Some(start_ms) = self.rate_sample_start_ms else {
            return;
        };
        let elapsed = elapsed_ms(now_ms, start_ms);
        if elapsed < MIN_DELIVERY_SAMPLE_INTERVAL_MS || self.aggregate.rate_bytes == 0 {
            return;
        }

        self.sample_interval_ms = elapsed;
        self.aggregate.delivery_rate_mbps = Some(decimal_mbps(self.aggregate.rate_bytes, elapsed));
        for class in &mut self.classes {
            if class.rate_bytes > 0 {
                class.delivery_rate_mbps = Some(decimal_mbps(class.rate_bytes, elapsed));
            }
            class.rate_bytes = 0;
        }
        self.aggregate.rate_bytes = 0;
        self.rate_sample_start_ms = Some(now_ms);
    }
}

fn add_sent_stats(
    state: &mut ClassState,
    bytes: u64,
    packet: SentPacket,
    outer_retransmission: bool,
) {
    state.sent_packets = state.sent_packets.saturating_add(1);
    state.sent_bytes = state.sent_bytes.saturating_add(bytes);
    if packet.logical_retransmission && !outer_retransmission {
        state.logical_reliable_retries = state.logical_reliable_retries.saturating_add(1);
    }
    if outer_retransmission {
        state.outer_retransmissions = state.outer_retransmissions.saturating_add(1);
    }
}

fn decimal_mbps(bytes: u64, elapsed_ms: f64) -> f64 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "delivery byte totals are converted to decimal Mbps after bounded sampling"
    )]
    let bits = bytes as f64 * 8.0;
    let rate = bits / (elapsed_ms * 1_000.0);
    if rate.is_finite() { rate } else { 0.0 }
}

fn elapsed_ms(now_ms: f64, earlier_ms: f64) -> f64 {
    let elapsed = now_ms - earlier_ms;
    if elapsed.is_finite() {
        elapsed.max(0.0)
    } else {
        f64::MAX
    }
}

fn slot_index(counter: u64) -> usize {
    let capacity = u64::try_from(DELIVERY_HISTORY_CAPACITY).expect("history capacity fits u64");
    usize::try_from(counter % capacity).expect("history index fits usize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(generation: u64, outer_counter: u64, sent_at_ms: f64) -> SentPacket {
        SentPacket {
            generation,
            outer_counter,
            bytes: 1_250,
            sent_at_ms,
            traffic_class: TrafficClass::Video,
            ack_eliciting: true,
            logical_retransmission: false,
        }
    }

    fn sent_class(
        generation: u64,
        outer_counter: u64,
        sent_at_ms: f64,
        bytes: u32,
        traffic_class: TrafficClass,
        logical_retransmission: bool,
    ) -> SentPacket {
        SentPacket {
            generation,
            outer_counter,
            bytes,
            sent_at_ms,
            traffic_class,
            ack_eliciting: true,
            logical_retransmission,
        }
    }

    #[test]
    fn sent_packet_becomes_in_flight_and_an_exact_ack_retires_it() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 41, 1_000.0)).unwrap();

        let before_ack = estimator.snapshot(1_010.0);
        assert_eq!(before_ack.aggregate.in_flight, 1);
        assert_eq!(before_ack.aggregate.sent_packets, 1);
        assert_eq!(before_ack.aggregate.acknowledged_packets, 0);

        let outcome = estimator.acknowledge(1, 41, 1, 0, 1_020.0).unwrap();
        assert_eq!(outcome.newly_acknowledged_packets, 1);
        assert_eq!(outcome.newly_acknowledged_bytes, 1_250);

        let after_ack = estimator.snapshot(1_020.0);
        assert_eq!(after_ack.aggregate.in_flight, 0);
        assert_eq!(after_ack.aggregate.acknowledged_packets, 1);
        assert_eq!(after_ack.aggregate.acknowledged_bytes, 1_250);
    }

    #[test]
    fn ack_delay_is_removed_from_the_largest_new_rtt_sample() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 41, 1_000.0)).unwrap();
        let outcome = estimator.acknowledge(1, 41, 1, 2_000, 1_022.0).unwrap();
        assert!((outcome.rtt_sample_ms.unwrap() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ack_delay_is_not_applied_when_only_an_older_packet_is_newly_acknowledged() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 100, 0.0)).unwrap();
        estimator.record_sent(sent(1, 101, 1.0)).unwrap();

        let first = estimator.acknowledge(1, 101, 1, 0, 11.0).unwrap();
        assert!((first.rtt_sample_ms.unwrap() - 10.0).abs() < f64::EPSILON);

        // The largest counter was already acknowledged. The second ACK only
        // retires counter 100, so the delay carried for counter 101 cannot be
        // subtracted from counter 100's RTT.
        let second = estimator.acknowledge(1, 101, 0b11, 9_000, 20.0).unwrap();
        assert_eq!(second.newly_acknowledged_packets, 1);
        assert_eq!(second.rtt_sample_ms, None);
        assert!((estimator.snapshot(20.0).srtt_ms.unwrap() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn first_and_second_rtt_samples_follow_the_fixed_ewma() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 1, 0.0)).unwrap();
        estimator.acknowledge(1, 1, 1, 0, 20.0).unwrap();
        assert!((estimator.snapshot(20.0).srtt_ms.unwrap() - 20.0).abs() < f64::EPSILON);

        estimator.record_sent(sent(1, 2, 20.0)).unwrap();
        estimator.acknowledge(1, 2, 1, 0, 50.0).unwrap();
        assert!((estimator.snapshot(50.0).srtt_ms.unwrap() - 21.25).abs() < f64::EPSILON);
    }

    #[test]
    fn unique_acknowledged_bytes_produce_decimal_mbps_after_a_ten_ms_interval() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 1, 0.0, 12_500, TrafficClass::Video, false))
            .unwrap();
        estimator.acknowledge(1, 1, 1, 0, 10.0).unwrap();

        let snapshot = estimator.snapshot(10.0);
        assert!((snapshot.aggregate.delivery_rate_mbps.unwrap() - 10.0).abs() < f64::EPSILON);
        assert!((snapshot.video.delivery_rate_mbps.unwrap() - 10.0).abs() < f64::EPSILON);
        assert!((snapshot.sample_interval_ms - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn duplicate_acks_are_irrevocable_and_report_zero_new_bytes() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 7, 0.0)).unwrap();
        estimator.acknowledge(1, 7, 1, 0, 20.0).unwrap();
        let after_first_ack = estimator.clone();
        let first_srtt = estimator.snapshot(20.0).srtt_ms.unwrap();

        let duplicate = estimator.acknowledge(1, 7, 1, 25_000, 40.0).unwrap();
        assert_eq!(duplicate.newly_acknowledged_packets, 0);
        assert_eq!(duplicate.newly_acknowledged_bytes, 0);
        assert!(duplicate.rtt_sample_ms.is_none());
        assert!((estimator.snapshot(40.0).srtt_ms.unwrap() - first_srtt).abs() < f64::EPSILON);
        assert_eq!(estimator.snapshot(40.0).aggregate.acknowledged_bytes, 1_250);
        assert_eq!(estimator.snapshot(40.0).aggregate.in_flight, 0);
        assert_ne!(estimator, after_first_ack);
    }

    #[test]
    fn a_future_largest_counter_is_rejected_without_mutating_state() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 9, 0.0)).unwrap();
        let before = estimator.clone();

        assert_eq!(
            estimator.acknowledge(1, 10, 1, 0, 10.0),
            Err(DeliveryError::FutureCounter)
        );
        assert_eq!(estimator, before);
    }

    #[test]
    fn an_old_generation_ack_is_ignored_without_mutating_current_state() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 1, 0.0)).unwrap();
        estimator.reset_generation(2);
        estimator.record_sent(sent(2, 2, 10.0)).unwrap();
        let before = estimator.clone();

        let outcome = estimator.acknowledge(1, 1, 1, 0, 20.0).unwrap();
        assert_eq!(outcome, AckOutcome::IgnoredStaleGeneration);
        assert_eq!(estimator, before);
    }

    #[test]
    fn bitmap_bits_acknowledge_mathematical_counter_positions() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 10, 0.0, 100, TrafficClass::Critical, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 11, 0.0, 200, TrafficClass::Audio, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 12, 0.0, 300, TrafficClass::Video, false))
            .unwrap();

        let outcome = estimator.acknowledge(1, 12, 0b101, 0, 20.0).unwrap();
        assert_eq!(outcome.newly_acknowledged_packets, 2);
        assert_eq!(outcome.newly_acknowledged_bytes, 400);
        assert_eq!(estimator.snapshot(20.0).aggregate.in_flight, 1);

        let outcome = estimator.acknowledge(1, 11, 1, 0, 25.0).unwrap();
        assert_eq!(outcome.newly_acknowledged_packets, 1);
        assert_eq!(outcome.newly_acknowledged_bytes, 200);
        assert_eq!(estimator.snapshot(25.0).aggregate.in_flight, 0);
    }

    #[test]
    fn reordering_more_than_sixty_four_counters_does_not_ack_older_history() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 1, 0.0, 100, TrafficClass::Audio, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 65, 0.0, 200, TrafficClass::Video, false))
            .unwrap();

        let outcome = estimator.acknowledge(1, 65, 1, 0, 20.0).unwrap();
        assert_eq!(outcome.newly_acknowledged_packets, 1);
        assert_eq!(outcome.newly_acknowledged_bytes, 200);
        assert_eq!(estimator.snapshot(20.0).aggregate.in_flight, 1);
        assert_eq!(estimator.snapshot(20.0).audio.in_flight, 1);
    }

    #[test]
    fn ring_aliasing_rejects_a_young_collision_and_explicitly_evicts_stale_entry() {
        let alias_counter = DELIVERY_HISTORY_CAPACITY as u64 + 1;
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 1, 0.0, 100, TrafficClass::Audio, false))
            .unwrap();

        assert!(!estimator.can_record(1, alias_counter, 100.0));
        assert_eq!(
            estimator.record_sent(sent_class(
                1,
                alias_counter,
                100.0,
                200,
                TrafficClass::Video,
                false
            )),
            Err(DeliveryError::HistoryFull)
        );

        let eviction = estimator
            .record_sent(sent_class(
                1,
                alias_counter,
                250.0,
                200,
                TrafficClass::Video,
                false,
            ))
            .unwrap();
        assert!(eviction.stale_evicted);
        assert_eq!(estimator.snapshot(250.0).aggregate.stale, 1);
        assert_eq!(estimator.snapshot(250.0).aggregate.in_flight, 1);

        let old_ack = estimator.acknowledge(1, 1, 1, 0, 260.0).unwrap();
        assert_eq!(old_ack.newly_acknowledged_packets, 0);
        assert_eq!(old_ack.newly_acknowledged_bytes, 0);
        assert_eq!(estimator.snapshot(260.0).aggregate.in_flight, 1);

        estimator
            .acknowledge(1, alias_counter, 1, 0, 270.0)
            .unwrap();
        assert_eq!(estimator.snapshot(270.0).aggregate.in_flight, 0);
    }

    #[test]
    fn history_covers_the_documented_hundred_mbps_hundred_ms_bdp() {
        const PACKET_BYTES: u32 = 1_200;
        const PACKETS_IN_FLIGHT: u64 = 1_050;
        const RATE_MBPS: f64 = 100.0;
        let packet_interval_ms =
            f64::from(PACKET_BYTES) * 8.0 / (RATE_MBPS * 1_000_000.0) * 1_000.0;
        let mut estimator = DeliveryEstimator::new(1);

        for counter in 0..PACKETS_IN_FLIGHT {
            let sent_at_ms = counter as f64 * packet_interval_ms;
            estimator
                .record_sent(sent_class(
                    1,
                    counter,
                    sent_at_ms,
                    PACKET_BYTES,
                    TrafficClass::Video,
                    false,
                ))
                .expect("documented BDP must not exhaust delivery history");
        }

        assert_eq!(
            estimator
                .snapshot((PACKETS_IN_FLIGHT - 1) as f64 * packet_interval_ms)
                .aggregate
                .in_flight,
            u32::try_from(PACKETS_IN_FLIGHT).expect("test packet count fits in in-flight counter")
        );
    }

    #[test]
    fn logical_reliable_control_retry_is_separate_from_outer_retransmission() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 1, 0.0, 100, TrafficClass::Critical, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 2, 10.0, 120, TrafficClass::Critical, true))
            .unwrap();

        let before_outer_resend = estimator.snapshot(10.0);
        assert_eq!(before_outer_resend.critical.logical_reliable_retries, 1);
        assert_eq!(before_outer_resend.critical.outer_retransmissions, 0);

        let resend = estimator
            .record_sent(sent_class(1, 2, 20.0, 120, TrafficClass::Critical, false))
            .unwrap();
        assert!(resend.outer_retransmission);
        let after_outer_resend = estimator.snapshot(20.0);
        assert_eq!(after_outer_resend.critical.logical_reliable_retries, 1);
        assert_eq!(after_outer_resend.critical.outer_retransmissions, 1);
    }

    #[test]
    fn aggregate_and_video_snapshots_differ_when_only_audio_and_control_are_acked() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator
            .record_sent(sent_class(1, 1, 0.0, 100, TrafficClass::Critical, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 2, 0.0, 200, TrafficClass::Audio, false))
            .unwrap();
        estimator
            .record_sent(sent_class(1, 3, 0.0, 300, TrafficClass::Video, false))
            .unwrap();
        estimator.acknowledge(1, 2, 0b11, 0, 20.0).unwrap();

        let snapshot = estimator.snapshot(20.0);
        assert_eq!(snapshot.aggregate.acknowledged_packets, 2);
        assert_eq!(snapshot.aggregate.acknowledged_bytes, 300);
        assert_eq!(snapshot.video.acknowledged_packets, 0);
        assert_eq!(snapshot.video.acknowledged_bytes, 0);
        assert_eq!(snapshot.audio.acknowledged_packets, 1);
        assert_eq!(snapshot.critical.acknowledged_packets, 1);
        assert_ne!(snapshot.aggregate, snapshot.video);
    }

    #[test]
    fn invalid_timestamps_and_zero_generation_reset_fail_closed() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 1, 0.0)).unwrap();
        let before = estimator.clone();

        assert_eq!(
            estimator.record_sent(sent(1, 2, f64::NAN)),
            Err(DeliveryError::InvalidTimestamp)
        );
        assert_eq!(estimator, before);

        assert_eq!(
            estimator.acknowledge(1, 1, 1, 0, f64::INFINITY),
            Err(DeliveryError::InvalidTimestamp)
        );
        assert_eq!(estimator, before);

        estimator.reset_generation(0);
        assert_eq!(estimator, before);
    }

    #[test]
    fn invalid_ack_bitmap_and_delay_fail_without_mutation() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 0, 0.0)).unwrap();
        let before = estimator.clone();

        assert_eq!(
            estimator.acknowledge(1, 0, 1 << 1, 0, 10.0),
            Err(DeliveryError::CounterUnderflow)
        );
        assert_eq!(estimator, before);

        assert_eq!(
            estimator.acknowledge(1, 0, 1, 25_001, 10.0),
            Err(DeliveryError::AckDelayTooLarge)
        );
        assert_eq!(estimator, before);
    }

    #[test]
    fn future_counter_validation_precedes_bitmap_underflow() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 9, 0.0)).unwrap();
        let before = estimator.clone();

        assert_eq!(
            estimator.acknowledge(1, 10, 1 << 11, 0, 10.0),
            Err(DeliveryError::FutureCounter)
        );
        assert_eq!(estimator, before);
    }

    #[test]
    fn backward_timestamps_are_rejected_without_moving_the_clock() {
        let mut estimator = DeliveryEstimator::new(1);
        estimator.record_sent(sent(1, 1, 10.0)).unwrap();
        let before = estimator.clone();

        assert_eq!(
            estimator.record_sent(sent(1, 2, 9.0)),
            Err(DeliveryError::InvalidTimestamp)
        );
        assert_eq!(estimator, before);
        assert!(!estimator.can_record(1, 2, 9.0));
    }

    #[test]
    fn non_ack_eliciting_packets_do_not_consume_delivery_history() {
        let mut estimator = DeliveryEstimator::new(1);
        let mut packet = sent(1, 1, 0.0);
        packet.ack_eliciting = false;
        estimator.record_sent(packet).unwrap();

        assert!(estimator.can_record(1, 257, 0.0));
        assert_eq!(estimator.snapshot(0.0).aggregate.in_flight, 0);
    }
}
