use std::fmt;
use std::time::Duration;

use openstream_protocol::transport_meta::{MAX_ACK_DELAY_US, TransportAck, TransportMetaError};

/// Local policy for coalescing authenticated transport acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportAckConfig {
    pub packet_threshold: u8,
    pub max_delay: Duration,
    pub immediate_on_gap: bool,
}

impl Default for TransportAckConfig {
    fn default() -> Self {
        Self {
            packet_threshold: 2,
            max_delay: Duration::from_millis(2),
            immediate_on_gap: true,
        }
    }
}

/// Validation failures for a local transport-ACK policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportAckConfigError {
    ZeroPacketThreshold,
    ZeroMaxDelay,
    MaxDelayTooLarge,
}

impl fmt::Display for TransportAckConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroPacketThreshold => "transport ACK packet threshold must be non-zero",
            Self::ZeroMaxDelay => "transport ACK maximum delay must be positive",
            Self::MaxDelayTooLarge => "transport ACK maximum delay exceeds 25 milliseconds",
        })
    }
}

impl std::error::Error for TransportAckConfigError {}

impl TransportAckConfig {
    /// Construct and validate one ACK policy.
    pub fn new(
        packet_threshold: u8,
        max_delay: Duration,
        immediate_on_gap: bool,
    ) -> Result<Self, TransportAckConfigError> {
        Self {
            packet_threshold,
            max_delay,
            immediate_on_gap,
        }
        .validate()
    }

    /// Validate the local policy against the fixed wire delay bound.
    pub fn validate(self) -> Result<Self, TransportAckConfigError> {
        if self.packet_threshold == 0 {
            return Err(TransportAckConfigError::ZeroPacketThreshold);
        }
        if self.max_delay.is_zero() {
            return Err(TransportAckConfigError::ZeroMaxDelay);
        }
        if self.max_delay > Duration::from_micros(u64::from(MAX_ACK_DELAY_US)) {
            return Err(TransportAckConfigError::MaxDelayTooLarge);
        }
        Ok(self)
    }
}

/// Failures that can make an ACK receive window unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportAckWindowError {
    InvalidGeneration,
    InvalidTimestamp,
    InvalidPolicy(TransportAckConfigError),
    InvalidRecord(TransportMetaError),
}

impl fmt::Display for TransportAckWindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeneration => formatter.write_str("transport ACK generation is invalid"),
            Self::InvalidTimestamp => formatter.write_str("transport ACK timestamp is invalid"),
            Self::InvalidPolicy(error) => {
                write!(formatter, "transport ACK policy is invalid: {error}")
            }
            Self::InvalidRecord(error) => {
                write!(formatter, "transport ACK record is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for TransportAckWindowError {}

/// A fixed 64-counter receive window used to coalesce transport ACKs.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportAckWindow {
    config: TransportAckConfig,
    generation: u64,
    largest_counter: Option<u64>,
    received_mask: u64,
    pending_mask: u64,
    largest_received_at_ms: f64,
    pending_since_ms: Option<f64>,
    force_ack: bool,
}

impl TransportAckWindow {
    /// Create a receive window for a non-zero path generation.
    pub fn new(generation: u64, config: TransportAckConfig) -> Self {
        Self::try_new(generation, config).expect("transport ACK window configuration is valid")
    }

    /// Fallible constructor useful to callers loading policy from config.
    pub fn try_new(
        generation: u64,
        config: TransportAckConfig,
    ) -> Result<Self, TransportAckWindowError> {
        if generation == 0 {
            return Err(TransportAckWindowError::InvalidGeneration);
        }
        let config = config
            .validate()
            .map_err(TransportAckWindowError::InvalidPolicy)?;
        Ok(Self {
            config,
            generation,
            largest_counter: None,
            received_mask: 0,
            pending_mask: 0,
            largest_received_at_ms: 0.0,
            pending_since_ms: None,
            force_ack: false,
        })
    }

    /// Observe one newly authenticated, ACK-eliciting application counter.
    ///
    /// Invalid or backward policy timestamps are ignored. The session owns
    /// the authenticated/generation filtering before calling this method.
    pub fn observe(&mut self, counter: u64, received_at_ms: f64) {
        if !received_at_ms.is_finite() || received_at_ms < 0.0 {
            return;
        }
        let Some(last_received_at_ms) = self.pending_since_ms else {
            // No pending timer exists, so an older packet is still valid if
            // it is the first packet of a newly constructed window.
            if self
                .largest_counter
                .is_some_and(|_| received_at_ms < self.largest_received_at_ms)
            {
                return;
            }
            self.observe_valid(counter, received_at_ms);
            return;
        };
        if received_at_ms < last_received_at_ms {
            return;
        }
        self.observe_valid(counter, received_at_ms);
    }

    /// Whether a coalesced ACK should be emitted at this policy timestamp.
    pub fn due(&self, now_ms: f64) -> bool {
        let Some(pending_since_ms) = self.pending_since_ms else {
            return false;
        };
        if !now_ms.is_finite() || now_ms < pending_since_ms {
            return false;
        }
        self.force_ack
            || self.pending_count() >= u32::from(self.config.packet_threshold)
            || now_ms - pending_since_ms >= self.config.max_delay.as_secs_f64() * 1_000.0
    }

    /// Take one due ACK and clear only its pending-send state.
    pub fn take(&mut self, now_ms: f64, generation: u64) -> Option<TransportAck> {
        if generation != self.generation || !self.due(now_ms) {
            return None;
        }
        let largest_counter = self.largest_counter?;
        let delay_ms = (now_ms - self.largest_received_at_ms)
            .max(0.0)
            .min(f64::from(MAX_ACK_DELAY_US) / 1_000.0);
        let delay_us = {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "delay is validated and clamped to the u32 wire bound"
            )]
            {
                (delay_ms * 1_000.0).round() as u32
            }
        };
        let ack = TransportAck {
            generation: self.generation,
            largest_counter,
            received_mask: self.received_mask,
            ack_delay_us: delay_us.min(MAX_ACK_DELAY_US),
        };
        self.pending_mask = 0;
        self.pending_since_ms = None;
        self.force_ack = false;
        Some(ack)
    }

    /// Reset all receive-window state for a new path generation.
    ///
    /// A zero generation is invalid and leaves the window untouched.
    pub fn reset(&mut self, generation: u64) {
        if generation == 0 {
            return;
        }
        self.generation = generation;
        self.largest_counter = None;
        self.received_mask = 0;
        self.pending_mask = 0;
        self.largest_received_at_ms = 0.0;
        self.pending_since_ms = None;
        self.force_ack = false;
    }

    /// Number of newly observed counters not yet represented by an ACK.
    pub fn pending(&self) -> usize {
        usize::try_from(self.pending_mask.count_ones()).expect("u32 fits usize")
    }

    /// Return the bounded wait until this window next becomes due.
    pub(crate) fn next_wake(&self, now_ms: f64) -> Option<Duration> {
        let pending_since_ms = self.pending_since_ms?;
        if self.due(now_ms) {
            return Some(Duration::ZERO);
        }
        let due_ms = pending_since_ms + self.config.max_delay.as_secs_f64() * 1_000.0;
        let wait_ms = (due_ms - now_ms).max(0.0);
        wait_ms
            .is_finite()
            .then(|| Duration::from_secs_f64(wait_ms / 1_000.0))
    }

    /// Current path generation represented by this receive window.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn pending_count(&self) -> u32 {
        self.pending_mask.count_ones()
    }

    fn observe_valid(&mut self, counter: u64, received_at_ms: f64) {
        let Some(largest_counter) = self.largest_counter else {
            self.largest_counter = Some(counter);
            self.received_mask = 1;
            self.pending_mask = 1;
            self.largest_received_at_ms = received_at_ms;
            self.pending_since_ms = Some(received_at_ms);
            return;
        };

        if counter > largest_counter {
            let delta = counter - largest_counter;
            if delta >= 64 {
                self.received_mask = 1;
                self.pending_mask = 1;
            } else {
                let shift = u32::try_from(delta).expect("counter delta is below 64");
                self.received_mask = (self.received_mask << shift) | 1;
                self.pending_mask = (self.pending_mask << shift) | 1;
            }
            self.largest_counter = Some(counter);
            self.largest_received_at_ms = received_at_ms;
            self.mark_pending(received_at_ms, delta > 1);
            return;
        }

        let offset = largest_counter - counter;
        if offset >= 64 {
            return;
        }
        let bit = 1_u64 << u32::try_from(offset).expect("offset is below 64");
        if self.received_mask & bit != 0 {
            return;
        }
        self.received_mask |= bit;
        self.pending_mask |= bit;
        self.mark_pending(received_at_ms, true);
    }

    fn mark_pending(&mut self, received_at_ms: f64, gap: bool) {
        if self.pending_since_ms.is_none() {
            self.pending_since_ms = Some(received_at_ms);
        }
        self.force_ack |= gap && self.config.immediate_on_gap;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openstream_protocol::transport_meta::{MAX_ACK_DELAY_US, TransportAck};

    use super::{TransportAckConfig, TransportAckWindow};

    fn window() -> TransportAckWindow {
        TransportAckWindow::new(7, TransportAckConfig::default())
    }

    fn config(packet_threshold: u8) -> TransportAckConfig {
        TransportAckConfig {
            packet_threshold,
            max_delay: Duration::from_millis(2),
            immediate_on_gap: true,
        }
    }

    #[test]
    fn first_packet_starts_the_ack_timer() {
        let mut window = window();

        window.observe(41, 10.0);

        assert_eq!(window.pending(), 1);
        assert!(!window.due(11.999));
        assert!(window.due(12.0));
    }

    #[test]
    fn threshold_sends_one_coalesced_ack() {
        let mut window = window();

        window.observe(41, 10.0);
        window.observe(42, 10.1);

        assert!(window.due(10.1));
        assert_eq!(
            window.take(10.1, 7),
            Some(TransportAck {
                generation: 7,
                largest_counter: 42,
                received_mask: 0b11,
                ack_delay_us: 0,
            })
        );
        assert_eq!(window.pending(), 0);
        assert_eq!(window.take(10.1, 7), None);
    }

    #[test]
    fn timer_sends_one_ack_after_the_delay() {
        let mut window = TransportAckWindow::new(7, config(8));

        window.observe(9, 5.0);

        assert!(!window.due(6.999));
        assert!(window.due(7.0));
        assert_eq!(
            window.take(7.0, 7),
            Some(TransportAck {
                generation: 7,
                largest_counter: 9,
                received_mask: 1,
                ack_delay_us: 2_000,
            })
        );
    }

    #[test]
    fn out_of_order_gap_is_immediate_even_below_the_threshold() {
        let mut window = TransportAckWindow::new(7, config(8));

        window.observe(10, 1.0);
        window.observe(12, 1.1);

        assert!(window.due(1.1));
        assert_eq!(
            window.take(1.1, 7).expect("gap ACK"),
            TransportAck {
                generation: 7,
                largest_counter: 12,
                received_mask: 0b101,
                ack_delay_us: 0,
            }
        );
    }

    #[test]
    fn duplicate_receive_does_not_inflate_pending_count() {
        let mut window = window();

        window.observe(10, 1.0);
        window.observe(10, 1.1);

        assert_eq!(window.pending(), 1);
    }

    #[test]
    fn ack_delay_is_measured_from_the_largest_counter_arrival() {
        let mut window = TransportAckWindow::new(7, config(8));

        window.observe(10, 1.0);
        window.observe(11, 4.0);

        assert_eq!(window.take(6.0, 7).unwrap().ack_delay_us, 2_000);
    }

    #[test]
    fn bitmap_math_reaches_the_sixty_fourth_counter_without_underflow() {
        let mut window = TransportAckWindow::new(7, config(8));

        window.observe(1, 1.0);
        window.observe(64, 2.0);

        assert_eq!(
            window.take(2.0, 7),
            Some(TransportAck {
                generation: 7,
                largest_counter: 64,
                received_mask: (1_u64 << 63) | 1,
                ack_delay_us: 0,
            })
        );
    }

    #[test]
    fn reset_clears_pending_state_and_changes_the_ack_generation() {
        let mut window = window();
        window.observe(41, 1.0);

        window.reset(8);

        assert_eq!(window.pending(), 0);
        assert!(!window.due(100.0));
        window.observe(2, 100.0);
        assert_eq!(window.take(102.0, 8).unwrap().generation, 8);
    }

    #[test]
    fn policy_rejects_even_sub_microsecond_delay_above_the_wire_bound() {
        let too_large = Duration::from_micros(u64::from(MAX_ACK_DELAY_US))
            .saturating_add(Duration::from_nanos(1));

        assert_eq!(
            TransportAckConfig::new(2, too_large, true),
            Err(super::TransportAckConfigError::MaxDelayTooLarge)
        );
    }
}
