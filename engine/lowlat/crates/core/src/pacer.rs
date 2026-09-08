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

/// The packet-count ceiling used by the burst limit.
///
/// The effective bucket is also bounded by [`MAX_BURST_TIME_MS`]. Keeping both
/// limits matters: four packets is a harmless burst on a fast path, but it can
/// represent tens of milliseconds of serialization on a constrained path.
pub const MAX_BURST_DATAGRAMS: usize = 4;

/// Maximum burst period in milliseconds, before the one-datagram floor applies.
///
/// A token bucket cannot split one datagram, so very low rates still receive
/// enough credit for one packet. Above that floor, stored credit represents no
/// more than this much wire time and never more than
/// [`MAX_BURST_DATAGRAMS`] packets.
pub const MAX_BURST_TIME_MS: f64 = 5.0;

/// Maximum number of wire bytes on the default path's packet-count ceiling.
///
/// This is retained as a named compatibility constant for callers that used
/// the original fixed-burst bound. The effective limit is rate- and
/// path-datagram-size dependent; use [`Pacer::burst_capacity_bytes`] when the
/// current target is known.
pub const MAX_BURST_BYTES: usize = crate::DEFAULT_DATAGRAM * MAX_BURST_DATAGRAMS;

const MIN_DATAGRAM_BYTES: usize = crate::DEFAULT_DATAGRAM;

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
    /// Current path datagram size. DPLPMTUD can update this without changing
    /// the pacing target, so burst credit remains measured in the same units
    /// as the packet actually sent.
    datagram_bytes: usize,
}

impl Pacer {
    /// Create a disabled pacer at `now_ms`.
    pub const fn new(now_ms: f64) -> Self {
        Self {
            rate_mbps: 0.0,
            tokens_bytes: 0.0,
            last_ms: now_ms,
            datagram_bytes: MIN_DATAGRAM_BYTES,
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

    /// The datagram size used to translate the packet-count burst ceiling into
    /// bytes.
    pub fn datagram_size(&self) -> usize {
        self.datagram_bytes
    }

    /// Change the path's currently usable datagram size.
    ///
    /// The protocol starts at [`crate::DEFAULT_DATAGRAM`] and never emits a
    /// packet above [`crate::MAX_DATAGRAM`]. Returning `false` for an invalid
    /// value keeps a path probe from silently making the sender permanently
    /// unserviceable. Increasing the size never manufactures additional
    /// credit; decreasing it clips credit that no longer fits the new bucket.
    pub fn set_datagram_size(&mut self, datagram_bytes: usize) -> bool {
        if !(MIN_DATAGRAM_BYTES..=crate::MAX_DATAGRAM).contains(&datagram_bytes) {
            return false;
        }
        self.datagram_bytes = datagram_bytes;
        if self.enabled() {
            self.tokens_bytes = self.tokens_bytes.min(self.capacity());
        }
        true
    }

    /// Effective stored-credit ceiling in whole wire bytes for the current
    /// rate and path datagram size.
    pub fn burst_capacity_bytes(&self) -> usize {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the computed capacity is bounded by four MAX_DATAGRAM packets"
        )]
        {
            self.capacity() as usize
        }
    }

    /// Change the target rate without throwing away accumulated credit.
    ///
    /// Enabling a previously disabled pacer starts with one bounded burst so
    /// the first frame is not delayed by an artificial warm-up. Disabling it
    /// discards the credit, preventing an old target from resurfacing as a
    /// burst if pacing is enabled again later.
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
    /// datagram larger than the current bounded bucket is rejected by
    /// returning infinity. The one-datagram floor makes normal packets
    /// serviceable at the lowest targets; this is defensive for a caller that
    /// changes packetization without updating the path size.
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
        let one_datagram = self.datagram_bytes as f64;
        let packet_cap = one_datagram * MAX_BURST_DATAGRAMS as f64;
        let time_cap = bytes_per_ms * MAX_BURST_TIME_MS;
        time_cap.max(one_datagram).min(packet_cap)
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
                    (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(self.capacity());
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
        (self.tokens_bytes + elapsed_ms * bytes_per_ms).min(self.capacity())
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
    const FAST_RATE: f64 = 100.0;
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
        pacer.set_rate(0.0, FAST_RATE);
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
        assert!(pacer.try_consume(0.0, DATAGRAM));
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
        assert_eq!(pacer.burst_capacity_bytes(), DATAGRAM);
        assert!(pacer.burst_capacity_bytes() < MAX_BURST_BYTES);

        let mut medium = Pacer::new(0.0);
        medium.set_rate(0.0, 5.0);
        assert_eq!(medium.burst_capacity_bytes(), 3125);
    }

    #[test]
    fn a_path_datagram_size_changes_the_packet_bounded_cap() {
        let mut pacer = Pacer::new(0.0);
        pacer.set_rate(0.0, FAST_RATE);
        assert_eq!(pacer.datagram_size(), DATAGRAM);
        assert_eq!(pacer.burst_capacity_bytes(), MAX_BURST_BYTES);
        assert!(pacer.set_datagram_size(1400));
        assert_eq!(pacer.datagram_size(), 1400);
        assert_eq!(pacer.burst_capacity_bytes(), 1400 * MAX_BURST_DATAGRAMS);
        assert!(!pacer.set_datagram_size(0));
        assert!(!pacer.set_datagram_size(crate::MAX_DATAGRAM + 1));
        assert_eq!(pacer.datagram_size(), 1400);
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
    fn backwards_time_does_not_create_credit() {
        let mut pacer = Pacer::new(100.0);
        pacer.set_rate(100.0, FAST_RATE);
        assert!(pacer.try_consume(100.0, MAX_BURST_BYTES));
        assert!(!pacer.try_consume(99.0, 1));
        assert!(pacer.try_consume(101.0, 125));
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
