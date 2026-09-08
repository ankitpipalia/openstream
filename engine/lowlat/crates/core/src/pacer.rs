//! A bounded token-bucket pacer for bulk media.
//!
//! The congestion controller decides how much a path can carry; this module
//! decides when the next datagram may leave. Keeping the two separate is
//! deliberate: a controller can change its target without giving a sender an
//! unbounded burst of credit, and the pacer remains usable by a shell that
//! does not own a socket.
//!
//! The bucket is deliberately small. A quiet desktop must not accumulate
//! hundreds of milliseconds of credit and then put a keyframe-sized burst on
//! the wire when the first pixel changes. The session uses this for video
//! traffic; acknowledgement, control, and audio traffic have their own
//! latency policy.

/// The maximum burst, measured in datagrams at the protocol's default size.
///
/// Four datagrams is enough to amortise a wakeup without allowing a static
/// stream to save a meaningful amount of latency debt.
pub const MAX_BURST_DATAGRAMS: usize = 4;

/// Maximum number of wire bytes that can be emitted from one bucketful.
pub const MAX_BURST_BYTES: usize = crate::DEFAULT_DATAGRAM * MAX_BURST_DATAGRAMS;

/// A monotonic, bounded token bucket.
///
/// Rates are decimal megabits per second (`1 Mbps = 1_000_000 bits/s`), the
/// same unit used by the encoder configuration and transport telemetry. Time
/// is supplied by the caller as fractional milliseconds. Invalid or backward
/// timestamps never create credit.
#[derive(Debug, Clone, Copy)]
pub struct Pacer {
    rate_mbps: f64,
    tokens_bytes: f64,
    last_ms: f64,
}

impl Pacer {
    /// Create a disabled pacer at `now_ms`.
    pub const fn new(now_ms: f64) -> Self {
        Self {
            rate_mbps: 0.0,
            tokens_bytes: 0.0,
            last_ms: now_ms,
        }
    }

    /// The configured rate. Zero means disabled.
    pub fn rate_mbps(&self) -> f64 {
        self.rate_mbps
    }

    /// Whether this pacer currently limits output.
    pub fn enabled(&self) -> bool {
        self.rate_mbps > 0.0
    }

    /// Change the target rate without throwing away accumulated credit.
    ///
    /// Enabling a previously disabled pacer starts with one bounded burst so
    /// the first frame is not delayed by an artificial warm-up. Disabling it
    /// discards the credit, preventing an old target from resurfacing as a
    /// burst if pacing is enabled again later.
    pub fn set_rate(&mut self, now_ms: f64, rate_mbps: f64) {
        self.refill(now_ms);
        let valid = Self::bytes_per_ms(rate_mbps).is_some();
        if !valid {
            self.rate_mbps = 0.0;
            self.tokens_bytes = 0.0;
            return;
        }

        if !self.enabled() {
            self.tokens_bytes = Self::capacity();
        } else {
            self.tokens_bytes = self.tokens_bytes.min(Self::capacity());
        }
        self.rate_mbps = rate_mbps;
    }

    /// True when `bytes` can be sent immediately.
    pub fn can_consume(&self, now_ms: f64, bytes: usize) -> bool {
        if !self.enabled() || bytes == 0 {
            return true;
        }
        self.available(now_ms) >= bytes as f64
    }

    /// Consume a datagram's wire bytes, if the bucket has room.
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
    /// Zero means immediately. An invalid request or a disabled pacer returns
    /// zero because the caller is not supposed to wait on this policy. A
    /// datagram larger than the bounded bucket is rejected by returning
    /// infinity; the protocol's absolute datagram ceiling is below the
    /// bucket, so this is a defensive result for future callers.
    pub fn wait_ms(&self, now_ms: f64, bytes: usize) -> f64 {
        if bytes == 0 || !self.enabled() {
            return 0.0;
        }
        let bytes = bytes as f64;
        let capacity = Self::capacity();
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

    fn capacity() -> f64 {
        MAX_BURST_BYTES as f64
    }

    /// Refill from a forward, finite timestamp. A clock reset is ignored until
    /// the caller presents a timestamp at or beyond the stored one; it cannot
    /// manufacture tokens by moving time backwards.
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
                    (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(Self::capacity());
            }
        }
        self.last_ms = now_ms;
    }

    /// The same refill calculation as [`Self::refill`], without mutating the
    /// bucket. This is what a timer query needs between output calls.
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
        (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(Self::capacity())
    }

    /// Convert a target to bytes per millisecond without allowing a finite
    /// but unrepresentable target to silently create a permanently stalled
    /// bucket. Host callers already clamp to a practical range; this keeps the
    /// core API well-defined for other callers too.
    fn bytes_per_ms(rate_mbps: f64) -> Option<f64> {
        let bytes_per_ms = rate_mbps * 1_000_000.0 / 8.0 / 1000.0;
        (bytes_per_ms.is_finite() && bytes_per_ms > 0.0).then_some(bytes_per_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: f64 = 1.0;
    const DATAGRAM: usize = crate::DEFAULT_DATAGRAM;

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
        pacer.set_rate(0.0, RATE);
        for _ in 0..MAX_BURST_DATAGRAMS {
            assert!(pacer.try_consume(0.0, DATAGRAM));
        }
        assert!(!pacer.try_consume(0.0, DATAGRAM));
        assert!(pacer.wait_ms(0.0, DATAGRAM).is_finite());
    }

    #[test]
    fn credit_refills_at_the_configured_rate() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.try_consume(0.0, MAX_BURST_BYTES));
        // 1 Mbps is 125 bytes per millisecond.
        assert!((pacer.wait_ms(0.0, 125) - 1.0).abs() < 1e-9);
        assert!(pacer.try_consume(1.0, 125));
    }

    #[test]
    fn idle_time_never_grows_the_bucket_past_the_burst() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.try_consume(0.0, MAX_BURST_BYTES));
        assert!(pacer.try_consume(10_000.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(10_000.0, 1));
    }

    #[test]
    fn backwards_time_does_not_create_credit() {
        let mut pacer = Pacer::new(100.0);
        pacer.set_rate(100.0, RATE);
        assert!(pacer.try_consume(100.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(99.0, 1));
        assert!(pacer.try_consume(101.0, 125));
    }

    #[test]
    fn disabling_discards_old_credit() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, RATE);
        assert!(pacer.try_consume(0.0, MAX_BURST_BYTES));
        pacer.set_rate(1.0, 0.0);
        pacer.set_rate(1.0, RATE);
        assert!(pacer.try_consume(1.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(1.0, 1));
    }
}
