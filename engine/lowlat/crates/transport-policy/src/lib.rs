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

/// Packet-level observations supplied by a transport implementation.
///
/// Optional fields are deliberately not synthesized by this policy crate. A
/// caller that cannot observe packet-window state must leave `in_flight` or
/// `stale` absent rather than substituting a local send-rate estimate.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CongestionObservation {
    /// Number of fragments currently in the transport's outstanding window.
    pub in_flight: Option<u32>,
    /// Number of fragments past their retransmission deadline.
    pub stale: Option<u32>,
    /// A delivery-rate sample in decimal Mbps, when the transport can measure
    /// acknowledged unique payload bytes.
    pub delivery_rate_mbps: Option<f64>,
    /// Smoothed round-trip time in milliseconds, when available to the caller.
    /// The compatibility controller does not currently use this field.
    pub srtt_ms: Option<f64>,
}

/// Window below which congestion is never declared.
pub const WINDOW_FLOOR: u32 = 100;

/// Consecutive clean ticks between rate increases.
const INCREASE_PERIOD: u32 = 30;
/// Consecutive congested ticks between rate decreases.
const DECREASE_PERIOD: u32 = 60;
/// Multiplicative decrease.
const DECREASE_FACTOR: f64 = 0.7;
/// Additive increase per step unit.
const INCREASE_STEP_MBPS: f64 = 0.15;
/// Step growth per increase, and the value it is capped at when applied.
const STEP_GROWTH: u32 = 2;
const STEP_CAP: u32 = 5;

/// Per-level congestion tuning.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Level {
    /// Multiplier on the smoothed round trip when classifying staleness.
    pub rtt_mult: f64,
    /// Constant added to the staleness threshold, in milliseconds.
    pub base_ms: f64,
    /// Stale-to-window ratio above which the channel is congested.
    pub stale_ratio: f64,
}

/// Available congestion tuning levels.
///
/// Level 0 is **not** "disabled". Its threshold of zero means any stale
/// fragment declares congestion once the window exceeds the floor, which
/// makes it the most aggressive setting rather than the least. It exists for
/// compatibility with an older scheme and must never be used as a fallback
/// for an out-of-range value.
pub const LEVELS: [Level; 3] = [
    Level {
        rtt_mult: 0.0,
        base_ms: 0.0,
        stale_ratio: 0.0,
    },
    Level {
        rtt_mult: 1.1,
        base_ms: 20.0,
        stale_ratio: 0.15,
    },
    Level {
        rtt_mult: 1.5,
        base_ms: 50.0,
        stale_ratio: 0.35,
    },
];

/// The default congestion tuning level.
pub const DEFAULT_LEVEL: usize = 1;

/// Resolve a level index, clamping to the default rather than to zero.
pub fn level(index: usize) -> Level {
    *LEVELS.get(index).unwrap_or(&LEVELS[DEFAULT_LEVEL])
}

/// Rate controller for one channel.
#[derive(Debug, Clone)]
pub struct Controller {
    level: usize,
    min_mbps: f64,
    max_mbps: f64,
    current_mbps: f64,
    peak_mbps: f64,
    increase_ticks: u32,
    decrease_ticks: u32,
    step: u32,
    /// Set until the first increase, which snaps the rate to the floor rather
    /// than creeping up from wherever it started.
    reset_pending: bool,
    total_decreases: u32,
}

impl Controller {
    pub fn new(level: usize, min_mbps: f64, max_mbps: f64) -> Self {
        Self {
            level,
            min_mbps,
            max_mbps,
            current_mbps: min_mbps,
            peak_mbps: min_mbps,
            increase_ticks: 0,
            decrease_ticks: 0,
            step: 1,
            reset_pending: true,
            total_decreases: 0,
        }
    }

    /// Move the bounds because the budget they came from changed.
    ///
    /// The current rate is pulled down to the new ceiling rather than left
    /// above it, and the reset is armed so the next increase snaps to the
    /// floor and climbs from there.
    pub fn set_bounds(&mut self, min_mbps: f64, max_mbps: f64) {
        self.min_mbps = min_mbps;
        self.max_mbps = max_mbps;
        if self.current_mbps > max_mbps {
            self.current_mbps = max_mbps;
        }
        if self.peak_mbps > max_mbps {
            self.peak_mbps = max_mbps;
        }
        self.reset_pending = true;
    }

    /// The ceiling currently in force.
    pub fn max_mbps(&self) -> f64 {
        self.max_mbps
    }

    /// How many times the rate has been cut. Surfaced for diagnostics.
    pub fn total_decreases(&self) -> u32 {
        self.total_decreases
    }

    /// Current rate, already clamped.
    pub fn rate_mbps(&self) -> f64 {
        self.current_mbps.clamp(self.min_mbps, self.max_mbps)
    }

    /// True if this window and stale count constitute congestion.
    pub fn is_congested(&self, window: u32, stale: u32) -> bool {
        if window <= WINDOW_FLOOR {
            return false;
        }
        let ratio = f64::from(stale) / f64::from(window);
        ratio > level(self.level).stale_ratio
    }

    /// Apply one lowlat-compatible packet observation.
    ///
    /// Packet-window evidence is required. The optional delivery rate is used
    /// only when present; it is not inferred from local send-rate telemetry.
    pub fn tick_observation(&mut self, observation: CongestionObservation) -> Option<f64> {
        let (Some(window), Some(stale)) = (observation.in_flight, observation.stale) else {
            return None;
        };
        Some(self.tick(window, stale, observation.delivery_rate_mbps.unwrap_or(0.0)))
    }

    /// One compatibility tick.
    ///
    /// `measured_mbps` is the throughput observed since the last increase,
    /// used to track the peak. Rates are decimal Mbps.
    pub fn tick(&mut self, window: u32, stale: u32, measured_mbps: f64) -> f64 {
        if self.is_congested(window, stale) {
            // The pre-increment value is tested, so the first congested tick
            // acts and then every sixtieth after it.
            let observed = self.decrease_ticks;
            self.decrease_ticks = self.decrease_ticks.wrapping_add(1);
            if observed % DECREASE_PERIOD == 0 {
                self.total_decreases = self.total_decreases.saturating_add(1);
                self.increase_ticks = 0;
                self.peak_mbps *= DECREASE_FACTOR;
                self.current_mbps = self.peak_mbps;
            }
        } else {
            // Here the post-increment value is tested, so the first action
            // lands on the thirtieth clean tick rather than the first.
            self.increase_ticks = self.increase_ticks.wrapping_add(1);
            if self.increase_ticks % INCREASE_PERIOD == 0 {
                self.decrease_ticks = 0;
                if self.reset_pending {
                    self.current_mbps = self.min_mbps;
                    self.peak_mbps = self.min_mbps;
                    self.reset_pending = false;
                } else {
                    if measured_mbps > self.peak_mbps {
                        self.peak_mbps = measured_mbps;
                    }
                    let step = self.step.min(STEP_CAP);
                    self.current_mbps += f64::from(step) * INCREASE_STEP_MBPS;
                    self.step = self.step.saturating_add(STEP_GROWTH);
                }
            }
        }
        self.rate_mbps()
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
    fn invalid_configurations_report_exact_errors() {
        let base = PacerConfig::compatibility_default();
        let cases = [
            (
                PacerConfig {
                    min_datagram_bytes: 0,
                    ..base
                },
                ConfigError::ZeroDatagramSize,
            ),
            (
                PacerConfig {
                    min_datagram_bytes: 2001,
                    ..base
                },
                ConfigError::MinimumExceedsMaximum,
            ),
            (
                PacerConfig {
                    max_datagram_bytes: 1228,
                    ..base
                },
                ConfigError::MinimumExceedsMaximum,
            ),
            (
                PacerConfig {
                    max_datagram_bytes: 0,
                    ..base
                },
                ConfigError::ZeroDatagramSize,
            ),
            (
                PacerConfig {
                    max_burst_datagrams: 0,
                    ..base
                },
                ConfigError::ZeroBurstDatagrams,
            ),
            (
                PacerConfig {
                    max_burst_time_ms: 0.0,
                    ..base
                },
                ConfigError::InvalidBurstTime,
            ),
            (
                PacerConfig {
                    max_burst_time_ms: -1.0,
                    ..base
                },
                ConfigError::InvalidBurstTime,
            ),
            (
                PacerConfig {
                    max_burst_time_ms: f64::NAN,
                    ..base
                },
                ConfigError::InvalidBurstTime,
            ),
            (
                PacerConfig {
                    max_burst_time_ms: f64::INFINITY,
                    ..base
                },
                ConfigError::InvalidBurstTime,
            ),
        ];
        for (config, expected) in cases {
            assert_eq!(config.validate(), Err(expected));
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
    fn fractional_millisecond_refill_uses_decimal_rate() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.try_consume(0.0, DEFAULT_DATAGRAM));

        // At 1 Mbps the pacer refills 125 bytes per millisecond, so these
        // fractional timestamps expose the fractional-byte boundaries rather
        // than rounding elapsed time to whole milliseconds.
        assert!(pacer.can_consume(0.5, 62));
        assert!(!pacer.can_consume(0.5, 63));
        assert!((pacer.wait_ms(0.5, 63) - 0.004).abs() < 1e-12);

        assert!(pacer.can_consume(1.25, 156));
        assert!(!pacer.can_consume(1.25, 157));
        assert!((pacer.wait_ms(1.25, 157) - 0.006).abs() < 1e-12);
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

    fn controller() -> Controller {
        Controller::new(DEFAULT_LEVEL, 1.0, 100.0)
    }

    fn assert_controller_state_eq(actual: &Controller, expected: &Controller) {
        assert_eq!(actual.level, expected.level);
        assert_eq!(actual.min_mbps.to_bits(), expected.min_mbps.to_bits());
        assert_eq!(actual.max_mbps.to_bits(), expected.max_mbps.to_bits());
        assert_eq!(
            actual.current_mbps.to_bits(),
            expected.current_mbps.to_bits()
        );
        assert_eq!(actual.peak_mbps.to_bits(), expected.peak_mbps.to_bits());
        assert_eq!(actual.increase_ticks, expected.increase_ticks);
        assert_eq!(actual.decrease_ticks, expected.decrease_ticks);
        assert_eq!(actual.step, expected.step);
        assert_eq!(actual.reset_pending, expected.reset_pending);
        assert_eq!(actual.total_decreases, expected.total_decreases);
    }

    #[test]
    fn level_zero_is_the_most_aggressive_not_disabled() {
        let zero = level(0);
        assert!(zero.stale_ratio <= 0.0);
        let aggressive = Controller::new(0, 1.0, 100.0);
        // A single stale fragment past the floor is congestion at level 0.
        assert!(aggressive.is_congested(WINDOW_FLOOR + 1, 1));
        // Whereas the default tolerates it.
        assert!(!controller().is_congested(WINDOW_FLOOR + 1, 1));
    }

    #[test]
    fn an_out_of_range_level_falls_back_to_the_default_not_to_zero() {
        assert_eq!(level(99), LEVELS[DEFAULT_LEVEL]);
        assert_ne!(level(99), LEVELS[0]);
    }

    #[test]
    fn a_small_window_is_never_congested() {
        let controller = controller();
        assert!(!controller.is_congested(WINDOW_FLOOR, u32::from(u16::MAX)));
        assert!(!controller.is_congested(10, 10));
    }

    #[test]
    fn the_ratio_decides_above_the_floor() {
        let controller = controller();
        // 0.15 threshold: 15 of 200 is not above it, 31 is.
        assert!(!controller.is_congested(200, 30));
        assert!(controller.is_congested(200, 31));
    }

    /// The pre-increment test means the very first congested tick acts.
    #[test]
    fn the_first_congested_tick_cuts_the_rate() {
        let mut controller = controller();
        controller.peak_mbps = 10.0;
        controller.current_mbps = 10.0;
        controller.tick(200, 100, 0.0);
        assert_eq!(controller.total_decreases(), 1);
        assert!((controller.rate_mbps() - 7.0).abs() < 1e-9);
    }

    #[test]
    fn further_cuts_wait_for_the_period() {
        let mut controller = controller();
        for _ in 0..DECREASE_PERIOD {
            controller.tick(200, 100, 0.0);
        }
        assert_eq!(
            controller.total_decreases(),
            1,
            "cut more than once too soon"
        );
        controller.tick(200, 100, 0.0);
        assert_eq!(controller.total_decreases(), 2);
    }

    /// The post-increment test means nothing happens until the period elapses.
    #[test]
    fn increases_wait_a_full_period() {
        let mut controller = controller();
        for _ in 0..INCREASE_PERIOD - 1 {
            controller.tick(10, 0, 5.0);
        }
        assert!(controller.reset_pending, "acted before the period elapsed");
        controller.tick(10, 0, 5.0);
        assert!(!controller.reset_pending);
    }

    #[test]
    fn the_first_increase_snaps_to_the_floor_then_creeps() {
        let mut controller = Controller::new(DEFAULT_LEVEL, 2.0, 100.0);
        controller.current_mbps = 50.0;
        for _ in 0..INCREASE_PERIOD {
            controller.tick(10, 0, 0.0);
        }
        assert!((controller.rate_mbps() - 2.0).abs() < 1e-9, "did not snap");
        for _ in 0..INCREASE_PERIOD {
            controller.tick(10, 0, 0.0);
        }
        assert!(controller.rate_mbps() > 2.0, "did not creep back up");
    }

    #[test]
    fn the_rate_stays_inside_its_bounds() {
        let mut controller = Controller::new(DEFAULT_LEVEL, 5.0, 6.0);
        for _ in 0..10_000 {
            controller.tick(10, 0, 1000.0);
        }
        assert!(controller.rate_mbps() <= 6.0);
        for _ in 0..10_000 {
            controller.tick(200, 200, 0.0);
        }
        assert!(controller.rate_mbps() >= 5.0);
    }

    #[test]
    fn congestion_resets_the_increase_counter() {
        let mut controller = controller();
        for _ in 0..INCREASE_PERIOD - 1 {
            controller.tick(10, 0, 1.0);
        }
        controller.tick(200, 100, 0.0);
        // The increase counter was cleared, so one more clean tick must not
        // trigger an increase.
        controller.tick(10, 0, 1.0);
        assert!(controller.reset_pending);
    }

    #[test]
    fn missing_packet_evidence_does_not_change_controller() {
        let mut controller = Controller::new(DEFAULT_LEVEL, 1.0, 100.0);
        let before = controller.clone();
        assert_eq!(
            controller.tick_observation(CongestionObservation::default()),
            None
        );
        assert_controller_state_eq(&controller, &before);
    }

    #[test]
    fn either_missing_packet_field_keeps_observation_inert() {
        let observations = [
            CongestionObservation {
                in_flight: None,
                stale: Some(1),
                delivery_rate_mbps: Some(5.0),
                srtt_ms: Some(20.0),
            },
            CongestionObservation {
                in_flight: Some(WINDOW_FLOOR + 1),
                stale: None,
                delivery_rate_mbps: Some(5.0),
                srtt_ms: Some(20.0),
            },
        ];

        for observation in observations {
            let mut controller = Controller::new(DEFAULT_LEVEL, 1.0, 100.0);
            let before = controller.clone();
            assert_eq!(controller.tick_observation(observation), None);
            assert_controller_state_eq(&controller, &before);
        }
    }

    #[test]
    fn complete_observation_matches_direct_ticks_with_and_without_rate() {
        let mut observation_with_rate = controller();
        let mut direct_with_rate = controller();
        let mut observation_without_rate = controller();
        let mut direct_without_rate = controller();

        for _ in 0..INCREASE_PERIOD * 2 {
            let observation = CongestionObservation {
                in_flight: Some(10),
                stale: Some(0),
                delivery_rate_mbps: Some(5.0),
                srtt_ms: Some(20.0),
            };
            let expected = direct_with_rate.tick(10, 0, 5.0);
            assert_eq!(
                observation_with_rate.tick_observation(observation),
                Some(expected)
            );

            let observation = CongestionObservation {
                in_flight: Some(10),
                stale: Some(0),
                delivery_rate_mbps: None,
                srtt_ms: Some(20.0),
            };
            let expected = direct_without_rate.tick(10, 0, 0.0);
            assert_eq!(
                observation_without_rate.tick_observation(observation),
                Some(expected)
            );
        }

        assert_controller_state_eq(&observation_with_rate, &direct_with_rate);
        assert_controller_state_eq(&observation_without_rate, &direct_without_rate);
        assert_eq!(observation_with_rate.peak_mbps.to_bits(), 5.0f64.to_bits());
        assert_eq!(
            observation_without_rate.peak_mbps.to_bits(),
            1.0f64.to_bits()
        );
    }
}
