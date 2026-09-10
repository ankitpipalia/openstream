#![no_std]

use core::fmt;

/// Packet-count ceiling for a pacer's stored burst credit.
pub const MAX_BURST_DATAGRAMS: usize = 4;

/// Time-based ceiling for a pacer's stored burst credit, in milliseconds.
pub const MAX_BURST_TIME_MS: f64 = 5.0;

/// Errors returned when a pacer configuration would be unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// A datagram bound is zero.
    ZeroDatagramSize,
    /// The minimum datagram size is greater than the maximum.
    MinimumExceedsMaximum,
    /// The configured packet-count burst ceiling is zero.
    ZeroBurstDatagrams,
    /// The configured time-based burst ceiling is not finite and positive.
    InvalidBurstTime,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroDatagramSize => "datagram sizes must be non-zero",
            Self::MinimumExceedsMaximum => "minimum datagram size exceeds maximum",
            Self::ZeroBurstDatagrams => "burst datagram count must be non-zero",
            Self::InvalidBurstTime => "burst time must be finite and positive",
        };
        formatter.write_str(message)
    }
}

/// Protocol-independent bounds for a bounded token-bucket pacer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacerConfig {
    /// Smallest datagram size accepted by [`Pacer::set_datagram_size`].
    pub min_datagram_bytes: usize,
    /// Largest datagram size accepted by [`Pacer::set_datagram_size`].
    pub max_datagram_bytes: usize,
    /// Maximum number of datagrams represented by stored burst credit.
    pub max_burst_datagrams: usize,
    /// Maximum wire time represented by stored burst credit, in milliseconds.
    pub max_burst_time_ms: f64,
}

impl PacerConfig {
    /// The configuration used by the existing lowlat transport.
    pub const fn compatibility_default() -> Self {
        Self {
            min_datagram_bytes: 1229,
            max_datagram_bytes: 2000,
            max_burst_datagrams: MAX_BURST_DATAGRAMS,
            max_burst_time_ms: MAX_BURST_TIME_MS,
        }
    }

    /// Validate and return this configuration for use by a [`Pacer`].
    pub fn validate(self) -> Result<Self, ConfigError> {
        if self.min_datagram_bytes == 0 || self.max_datagram_bytes == 0 {
            return Err(ConfigError::ZeroDatagramSize);
        }
        if self.min_datagram_bytes > self.max_datagram_bytes {
            return Err(ConfigError::MinimumExceedsMaximum);
        }
        if self.max_burst_datagrams == 0 {
            return Err(ConfigError::ZeroBurstDatagrams);
        }
        if !self.max_burst_time_ms.is_finite() || self.max_burst_time_ms <= 0.0 {
            return Err(ConfigError::InvalidBurstTime);
        }
        Ok(self)
    }
}

/// A monotonic, bounded token bucket for bulk traffic.
///
/// Rates are decimal megabits per second (`1 Mbps = 1_000_000 bits/s`), and
/// timestamps are caller-supplied fractional milliseconds. Invalid or
/// backward timestamps never create credit.
#[derive(Debug, Clone, Copy)]
pub struct Pacer {
    config: PacerConfig,
    rate_mbps: f64,
    tokens_bytes: f64,
    last_ms: f64,
    datagram_bytes: usize,
}

impl Pacer {
    /// Create a disabled pacer using the lowlat-compatible configuration.
    pub const fn new(now_ms: f64) -> Self {
        let config = PacerConfig::compatibility_default();
        Self {
            config,
            rate_mbps: 0.0,
            tokens_bytes: 0.0,
            last_ms: now_ms,
            datagram_bytes: config.min_datagram_bytes,
        }
    }

    /// Create a disabled pacer with a validated custom configuration.
    ///
    /// A custom pacer starts at the configuration's maximum datagram size;
    /// callers can lower it to a path-safe value before enabling output.
    pub fn with_config(now_ms: f64, config: PacerConfig) -> Result<Self, ConfigError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            rate_mbps: 0.0,
            tokens_bytes: 0.0,
            last_ms: now_ms,
            datagram_bytes: config.max_datagram_bytes,
        })
    }

    /// The configured rate. Zero means disabled.
    pub fn rate_mbps(&self) -> f64 {
        self.rate_mbps
    }

    /// Whether this pacer currently limits output.
    pub fn enabled(&self) -> bool {
        self.rate_mbps > 0.0
    }

    /// The datagram size used to translate the packet-count burst ceiling into
    /// bytes.
    pub fn datagram_size(&self) -> usize {
        self.datagram_bytes
    }

    /// Change the currently usable datagram size.
    ///
    /// Increasing the size never manufactures credit. Decreasing it clips
    /// existing credit to the new bounded capacity.
    pub fn set_datagram_size(&mut self, datagram_bytes: usize) -> bool {
        if !(self.config.min_datagram_bytes..=self.config.max_datagram_bytes)
            .contains(&datagram_bytes)
        {
            return false;
        }
        self.datagram_bytes = datagram_bytes;
        if self.enabled() {
            self.tokens_bytes = self.tokens_bytes.min(self.capacity());
        }
        true
    }

    /// Effective stored-credit ceiling in whole wire bytes.
    pub fn burst_capacity_bytes(&self) -> usize {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "capacity is bounded by the configured packet count and datagram size"
        )]
        {
            self.capacity() as usize
        }
    }

    /// Change the target rate without throwing away accumulated credit.
    ///
    /// Enabling a previously disabled pacer starts with one bounded burst.
    /// Disabling it discards credit so an old target cannot resurface later.
    pub fn set_rate(&mut self, now_ms: f64, rate_mbps: f64) {
        self.refill(now_ms);
        if Self::bytes_per_ms(rate_mbps).is_none() {
            self.rate_mbps = 0.0;
            self.tokens_bytes = 0.0;
            return;
        }

        let was_enabled = self.enabled();
        self.rate_mbps = rate_mbps;
        if !was_enabled {
            self.tokens_bytes = self.capacity();
        } else {
            self.tokens_bytes = self.tokens_bytes.min(self.capacity());
        }
    }

    /// Whether `bytes` can be sent immediately.
    pub fn can_consume(&self, now_ms: f64, bytes: usize) -> bool {
        if !self.enabled() || bytes == 0 {
            return true;
        }
        self.available(now_ms) >= bytes as f64
    }

    /// Consume `bytes` if the bucket has enough credit.
    pub fn try_consume(&mut self, now_ms: f64, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        if !self.enabled() {
            return true;
        }
        self.refill(now_ms);
        let bytes = bytes as f64;
        if self.tokens_bytes < bytes {
            return false;
        }
        self.tokens_bytes -= bytes;
        true
    }

    /// Milliseconds until `bytes` can be consumed.
    ///
    /// Zero means immediately. Disabled pacers and zero-length requests are
    /// immediately serviceable. A request larger than the bounded bucket is
    /// unserviceable and returns infinity.
    pub fn wait_ms(&self, now_ms: f64, bytes: usize) -> f64 {
        if bytes == 0 || !self.enabled() {
            return 0.0;
        }
        let bytes = bytes as f64;
        let capacity = self.capacity();
        if bytes > capacity {
            return f64::INFINITY;
        }
        let available = self.available(now_ms);
        if available >= bytes {
            return 0.0;
        }
        let Some(bytes_per_ms) = Self::bytes_per_ms(self.rate_mbps) else {
            return f64::INFINITY;
        };
        (bytes - available) / bytes_per_ms
    }

    fn capacity(&self) -> f64 {
        let Some(bytes_per_ms) = Self::bytes_per_ms(self.rate_mbps) else {
            return 0.0;
        };
        let datagram_bytes = self.datagram_bytes as f64;
        let packet_cap = datagram_bytes * self.config.max_burst_datagrams as f64;
        let time_cap = bytes_per_ms * self.config.max_burst_time_ms;
        time_cap.max(datagram_bytes).min(packet_cap)
    }

    /// Refill from a forward, finite timestamp. A clock reset is ignored
    /// until a timestamp at or beyond the stored one arrives.
    fn refill(&mut self, now_ms: f64) {
        if !now_ms.is_finite() {
            return;
        }
        if !self.last_ms.is_finite() {
            self.last_ms = now_ms;
            return;
        }
        if now_ms <= self.last_ms {
            return;
        }
        if self.enabled() {
            let elapsed_ms = now_ms - self.last_ms;
            if let Some(bytes_per_ms) = Self::bytes_per_ms(self.rate_mbps) {
                self.tokens_bytes =
                    (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(self.capacity());
            }
        }
        self.last_ms = now_ms;
    }

    /// Refill calculation without mutating the bucket, for timer queries.
    fn available(&self, now_ms: f64) -> f64 {
        if !self.enabled() || !now_ms.is_finite() || !self.last_ms.is_finite() {
            return self.tokens_bytes;
        }
        if now_ms <= self.last_ms {
            return self.tokens_bytes;
        }
        let elapsed_ms = now_ms - self.last_ms;
        let Some(bytes_per_ms) = Self::bytes_per_ms(self.rate_mbps) else {
            return self.tokens_bytes;
        };
        (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(self.capacity())
    }

    fn bytes_per_ms(rate_mbps: f64) -> Option<f64> {
        let bytes_per_ms = rate_mbps * 1_000_000.0 / 8.0 / 1000.0;
        (bytes_per_ms.is_finite() && bytes_per_ms > 0.0).then_some(bytes_per_ms)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: f64 = 1.0;
    const FAST_RATE: f64 = 100.0;
    const DEFAULT_DATAGRAM: usize = 1229;
    const MAX_DATAGRAM: usize = 2000;
    const MAX_BURST_DATAGRAMS: usize = 4;
    const MAX_BURST_BYTES: usize = DEFAULT_DATAGRAM * MAX_BURST_DATAGRAMS;

    #[test]
    fn compatibility_config_is_the_lowlat_default() {
        let config = PacerConfig::compatibility_default();
        assert_eq!(config.min_datagram_bytes, 1229);
        assert_eq!(config.max_datagram_bytes, 2000);
        assert_eq!(config.max_burst_datagrams, 4);
        assert_eq!(config.max_burst_time_ms.to_bits(), 5.0f64.to_bits());
        assert_eq!(config.validate(), Ok(config));
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        let base = PacerConfig::compatibility_default();
        for config in [
            PacerConfig {
                min_datagram_bytes: 0,
                ..base
            },
            PacerConfig {
                min_datagram_bytes: 2001,
                ..base
            },
            PacerConfig {
                max_datagram_bytes: 1228,
                ..base
            },
            PacerConfig {
                max_datagram_bytes: 0,
                ..base
            },
            PacerConfig {
                max_burst_datagrams: 0,
                ..base
            },
            PacerConfig {
                max_burst_time_ms: 0.0,
                ..base
            },
            PacerConfig {
                max_burst_time_ms: -1.0,
                ..base
            },
            PacerConfig {
                max_burst_time_ms: f64::NAN,
                ..base
            },
            PacerConfig {
                max_burst_time_ms: f64::INFINITY,
                ..base
            },
        ] {
            assert!(config.validate().is_err(), "invalid config was accepted");
        }
    }

    #[test]
    fn custom_config_controls_size_validation_and_burst_capacity() {
        let config = PacerConfig {
            min_datagram_bytes: 100,
            max_datagram_bytes: 1600,
            max_burst_datagrams: 2,
            max_burst_time_ms: 2.0,
        };
        let mut pacer = Pacer::with_config(0.0, config).unwrap();
        pacer.set_rate(0.0, 100.0);
        assert_eq!(pacer.burst_capacity_bytes(), 3200);
        assert!(!pacer.set_datagram_size(99));
        assert!(pacer.set_datagram_size(1600));
        assert!(!pacer.set_datagram_size(1601));
    }

    #[test]
    fn starts_disabled_and_invalid_rates_stay_disabled() {
        let mut pacer = Pacer::new(0.0);
        assert!(!pacer.enabled());
        pacer.set_rate(0.0, 0.0);
        assert!(!pacer.enabled());
        pacer.set_rate(0.0, f64::NAN);
        assert!(!pacer.enabled());
        pacer.set_rate(0.0, f64::INFINITY);
        assert!(!pacer.enabled());
        pacer.set_rate(0.0, f64::MAX);
        assert!(!pacer.enabled());
    }

    #[test]
    fn initial_credit_is_bounded() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        for _ in 0..MAX_BURST_DATAGRAMS {
            assert!(pacer.try_consume(0.0, DEFAULT_DATAGRAM));
        }
        assert!(!pacer.try_consume(0.0, DEFAULT_DATAGRAM));
        assert!(pacer.wait_ms(0.0, DEFAULT_DATAGRAM).is_finite());
    }

    #[test]
    fn credit_refills_at_the_configured_rate() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.try_consume(0.0, DEFAULT_DATAGRAM));
        // 1 Mbps is 125 bytes per millisecond.
        assert!((pacer.wait_ms(0.0, 125) - 1.0).abs() < 1e-9);
        assert!(pacer.try_consume(1.0, 125));
    }

    #[test]
    fn low_rates_are_time_bounded_but_can_send_one_whole_datagram() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        // Five milliseconds at 1 Mbps is 625 bytes, so packet atomicity lifts
        // the bucket to one default datagram, not four.
        assert_eq!(pacer.burst_capacity_bytes(), DEFAULT_DATAGRAM);
        assert!(pacer.burst_capacity_bytes() < MAX_BURST_BYTES);

        let mut medium = Pacer::new(0.0);
        medium.set_rate(0.0, 5.0);
        assert_eq!(medium.burst_capacity_bytes(), 3125);
    }

    #[test]
    fn a_path_datagram_size_changes_the_packet_bounded_cap() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        assert_eq!(pacer.datagram_size(), DEFAULT_DATAGRAM);
        assert_eq!(pacer.burst_capacity_bytes(), MAX_BURST_BYTES);
        assert!(pacer.set_datagram_size(1400));
        assert_eq!(pacer.datagram_size(), 1400);
        assert_eq!(pacer.burst_capacity_bytes(), 1400 * MAX_BURST_DATAGRAMS);
        assert!(!pacer.set_datagram_size(0));
        assert!(!pacer.set_datagram_size(MAX_DATAGRAM + 1));
        assert_eq!(pacer.datagram_size(), 1400);
    }

    #[test]
    fn shrinking_datagram_size_clips_existing_credit() {
        let config = PacerConfig {
            min_datagram_bytes: 100,
            max_datagram_bytes: 1600,
            max_burst_datagrams: 4,
            max_burst_time_ms: 2.0,
        };
        let mut pacer = Pacer::with_config(0.0, config).unwrap();
        pacer.set_rate(0.0, FAST_RATE);
        assert!(pacer.try_consume(0.0, 1000));
        assert!(pacer.set_datagram_size(100));
        assert_eq!(pacer.burst_capacity_bytes(), 400);
        assert!(pacer.try_consume(0.0, 400));
        assert!(!pacer.try_consume(0.0, 1));
    }

    #[test]
    fn idle_time_never_grows_the_bucket_past_the_burst() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        assert!(pacer.try_consume(0.0, MAX_BURST_BYTES));
        assert!(pacer.try_consume(10_000.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(10_000.0, 1));
    }

    #[test]
    fn backward_and_invalid_time_do_not_create_credit_or_move_the_clock() {
        let mut pacer = Pacer::new(100.0);
        pacer.set_rate(100.0, RATE);
        assert!(pacer.try_consume(100.0, DEFAULT_DATAGRAM));
        assert!(!pacer.try_consume(99.0, 1));
        assert!(!pacer.try_consume(f64::NAN, 1));
        assert!(pacer.try_consume(101.0, 125));
        assert!(!pacer.try_consume(101.0, 125));
    }

    #[test]
    fn can_consume_does_not_consume_credit() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.can_consume(0.0, DEFAULT_DATAGRAM));
        assert!(pacer.can_consume(0.0, DEFAULT_DATAGRAM));
        assert!(pacer.try_consume(0.0, DEFAULT_DATAGRAM));
    }

    #[test]
    fn zero_length_requests_are_always_immediate() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.can_consume(0.0, 0));
        assert!(pacer.try_consume(0.0, 0));
        assert!(pacer.wait_ms(0.0, 0).abs() < f64::EPSILON);
    }

    #[test]
    fn oversized_wait_requests_are_unserviceable() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        assert!(!pacer.can_consume(0.0, MAX_BURST_BYTES + 1));
        assert!(!pacer.try_consume(0.0, MAX_BURST_BYTES + 1));
        assert!(pacer.wait_ms(0.0, MAX_BURST_BYTES + 1).is_infinite());
    }

    #[test]
    fn disabling_discards_old_credit() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        assert!(pacer.try_consume(0.0, MAX_BURST_BYTES));
        pacer.set_rate(1.0, 0.0);
        pacer.set_rate(1.0, FAST_RATE);
        assert!(pacer.try_consume(1.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(1.0, 1));
    }
}
