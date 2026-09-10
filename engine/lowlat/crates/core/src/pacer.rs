//! Lowlat compatibility exports for the shared bounded transport pacer.
//!
//! The policy implementation is protocol-neutral and lives in
//! `openstream-transport-policy`. This module retains the lowlat names and
//! fixed compatibility constant used by existing session code.

pub use openstream_transport_policy::{
    ConfigError, MAX_BURST_DATAGRAMS, MAX_BURST_TIME_MS, Pacer, PacerConfig,
};

/// Lowlat's original fixed packet-count burst bound at the default datagram
/// size. The effective pacer capacity remains rate- and path-size-dependent.
pub const MAX_BURST_BYTES: usize = crate::DEFAULT_DATAGRAM * MAX_BURST_DATAGRAMS;

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
