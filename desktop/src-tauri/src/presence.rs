//! When a hosting desktop should re-announce itself to the control plane.
//!
//! `POST /v1/presence` is a heartbeat. The service drops an entry that has not
//! been refreshed within its presence TTL -- 90 seconds, in
//! `signal-server`'s `connect.rs` -- so a host that announces once and stops
//! vanishes from its owner's device list while it is still hosting, and every
//! later request to it is refused as offline.
//!
//! The decision lives here, apart from the task that performs the IO, because
//! the interesting part is *when* and that is what wants testing. Everything
//! takes `now` as an argument: a test advances a fake clock instead of
//! sleeping, which keeps the assertions about this schedule rather than about
//! the operating system's scheduler.

use std::time::{Duration, Instant};

/// The service's own presence lifetime. Not ours to choose; it is
/// `PRESENCE_TTL` in `engine/lowlat/crates/signal-server/src/connect.rs`, and
/// the only reason this constant exists here is so the tests can state the
/// property that matters: a beat always lands inside it.
pub const SERVER_PRESENCE_TTL: Duration = Duration::from_secs(90);

/// How long after a successful beat the next one is due.
///
/// A third of the server's lifetime. Two consecutive failures still leave a
/// further attempt before the entry lapses, which is the point of renewing
/// well before expiry rather than just before it.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(30);

/// Added to `RENEW_INTERVAL`, never subtracted, so jitter can never shorten
/// the margin against the TTL.
pub const RENEW_JITTER: Duration = Duration::from_secs(5);

/// First retry delay after a failed beat, doubling up to [`RETRY_MAX`].
pub const RETRY_MIN: Duration = Duration::from_secs(2);

/// The retry ceiling. Deliberately far below the TTL: a host whose beats are
/// failing should keep trying often enough that one success rescues it.
pub const RETRY_MAX: Duration = Duration::from_secs(15);

/// What the presence task should do on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceAction {
    /// Nothing is due.
    Wait,
    /// Announce now, then report the outcome through
    /// [`PresenceSchedule::record_success`] or
    /// [`PresenceSchedule::record_failure`].
    Announce,
}

/// When the next presence beat is due.
///
/// The caller must report the outcome of every [`PresenceAction::Announce`]
/// it is given. Nothing else moves the schedule forward, so a caller that
/// announces and stays silent will be told to announce again on its next
/// tick.
#[derive(Debug)]
pub struct PresenceSchedule {
    /// `None` means "beat at the next opportunity": either nothing has been
    /// sent yet, or hosting has just been switched back on.
    next_due: Option<Instant>,
    consecutive_failures: u32,
    seed: u64,
}

impl PresenceSchedule {
    /// `seed` picks this process's jitter sequence. Production seeds it from
    /// the clock so that two machines started by the same script do not beat
    /// in lockstep; a test passes a constant and gets a fixed sequence.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            next_due: None,
            consecutive_failures: 0,
            seed,
        }
    }

    /// Seeded from the wall clock, for the running application.
    #[must_use]
    pub fn from_clock() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos() as u64 ^ since.as_secs());
        Self::new(seed)
    }

    /// What to do now.
    ///
    /// `hosting` and `authenticated` are read fresh on every tick rather than
    /// tracked here: hosting can stop because the agent died, not only
    /// because someone pressed a button, and a schedule that believed its own
    /// last answer would keep announcing a host that is gone.
    pub fn poll(&mut self, now: Instant, hosting: bool, authenticated: bool) -> PresenceAction {
        if !hosting || !authenticated {
            // Not an error, and not something to back off from. Forget the
            // schedule so that enabling hosting again beats at once instead
            // of leaving the device invisible for most of a renewal interval.
            self.reset();
            return PresenceAction::Wait;
        }
        if self.is_due(now) {
            PresenceAction::Announce
        } else {
            PresenceAction::Wait
        }
    }

    /// Whether a beat is due, ignoring hosting and sign-in state.
    ///
    /// The task uses this as a cheap pre-check so that an ordinary tick with
    /// nothing to do does not take the control-plane lock at all.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        match self.next_due {
            None => true,
            Some(due) => now >= due,
        }
    }

    /// Hosting stopped, or nobody is signed in.
    pub fn reset(&mut self) {
        self.next_due = None;
        self.consecutive_failures = 0;
    }

    pub fn record_success(&mut self, now: Instant) {
        self.consecutive_failures = 0;
        self.next_due = Some(now + RENEW_INTERVAL + self.next_jitter());
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_due = Some(now + retry_delay(self.consecutive_failures));
    }

    /// When the next beat is due, for tests and diagnostics. `None` means
    /// "as soon as hosting allows".
    #[must_use]
    pub fn next_due(&self) -> Option<Instant> {
        self.next_due
    }

    /// A value in `[0, RENEW_JITTER]`, from a plain linear congruential
    /// sequence. This spreads a fleet; it is not security material and is not
    /// used for anything that needs unpredictability.
    fn next_jitter(&mut self) -> Duration {
        self.seed = self
            .seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let span = RENEW_JITTER.as_millis() as u64;
        if span == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis((self.seed >> 33) % (span + 1))
    }
}

/// `RETRY_MIN` doubled per consecutive failure, capped at `RETRY_MAX`.
#[must_use]
pub fn retry_delay(consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return RETRY_MIN;
    }
    let shift = consecutive_failures.saturating_sub(1).min(16);
    RETRY_MIN.saturating_mul(1u32 << shift).min(RETRY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Step a fake clock through `span`, beating whenever the schedule says
    /// to, and return the instant of every beat. `outcome` decides whether
    /// each beat is reported as delivered.
    fn beats_over(
        schedule: &mut PresenceSchedule,
        start: Instant,
        span: Duration,
        hosting: impl Fn(u64) -> bool,
        outcome: impl Fn(usize) -> bool,
    ) -> Vec<Instant> {
        let mut beats = Vec::new();
        for second in 0..=span.as_secs() {
            let now = start + Duration::from_secs(second);
            if schedule.poll(now, hosting(second), true) == PresenceAction::Announce {
                beats.push(now);
                if outcome(beats.len() - 1) {
                    schedule.record_success(now);
                } else {
                    schedule.record_failure(now);
                }
            }
        }
        beats
    }

    /// The property the server actually enforces: a hosting device is only
    /// listed while its last beat is inside the presence TTL. Three full TTL
    /// intervals, because one is not enough to catch a schedule that renews
    /// once and then stops -- which is exactly what the desktop did before
    /// this module existed.
    #[test]
    fn presence_is_renewed_before_the_server_ttl_expires() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(0x5eed_1234);
        let beats = beats_over(
            &mut schedule,
            start,
            SERVER_PRESENCE_TTL * 3,
            |_| true,
            |_| true,
        );

        assert!(
            beats.len() >= 7,
            "three TTL intervals should hold at least seven beats, got {}",
            beats.len()
        );
        assert_eq!(beats[0], start, "hosting should announce immediately");
        for pair in beats.windows(2) {
            let gap = pair[1].duration_since(pair[0]);
            assert!(
                gap < SERVER_PRESENCE_TTL,
                "a {gap:?} gap lets the service forget this device"
            );
        }
        let last = beats.last().copied().expect("at least one beat");
        let remaining = (start + SERVER_PRESENCE_TTL * 3).duration_since(last);
        assert!(
            remaining < SERVER_PRESENCE_TTL,
            "the device goes stale {remaining:?} after the last beat"
        );
    }

    /// A control plane that is refusing every beat must still be retried
    /// often enough that one success rescues the entry, and must never be
    /// backed off past the TTL itself.
    #[test]
    fn a_run_of_failures_still_beats_inside_the_server_ttl() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(7);
        let beats = beats_over(
            &mut schedule,
            start,
            SERVER_PRESENCE_TTL * 2,
            |_| true,
            |_| false,
        );

        assert!(
            beats.len() > 10,
            "failures should be retried, not abandoned"
        );
        for pair in beats.windows(2) {
            let gap = pair[1].duration_since(pair[0]);
            assert!(
                gap <= RETRY_MAX + Duration::from_secs(1),
                "retry gap {gap:?} exceeds the ceiling"
            );
        }
    }

    #[test]
    fn the_retry_delay_doubles_and_is_capped() {
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(2), Duration::from_secs(4));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(4), RETRY_MAX);
        assert_eq!(retry_delay(40), RETRY_MAX);
    }

    /// Jitter spreads a fleet, so it has to vary; it is added and never
    /// subtracted, so it can only ever widen the gap, never shorten the
    /// margin against the TTL.
    #[test]
    fn renewal_is_spread_without_drifting_past_the_ttl() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(0xabcd_ef01);
        let mut gaps = Vec::new();
        let mut now = start;
        for _ in 0..64 {
            schedule.record_success(now);
            let due = schedule.next_due().expect("a beat is scheduled");
            gaps.push(due.duration_since(now));
            now = due;
        }

        for gap in &gaps {
            assert!(
                *gap >= RENEW_INTERVAL && *gap <= RENEW_INTERVAL + RENEW_JITTER,
                "gap {gap:?} is outside the renewal window"
            );
            assert!(*gap < SERVER_PRESENCE_TTL, "gap {gap:?} outlives the entry");
        }
        let first = gaps[0];
        assert!(
            gaps.iter().any(|gap| *gap != first),
            "every gap was identical, so nothing is being spread"
        );
    }

    /// Switching hosting off and on again must not leave the device
    /// invisible until some earlier schedule happens to come due.
    #[test]
    fn hosting_that_stops_and_restarts_beats_immediately() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(11);

        assert_eq!(
            schedule.poll(start, true, true),
            PresenceAction::Announce,
            "the first tick while hosting should announce"
        );
        schedule.record_success(start);

        let later = start + Duration::from_secs(5);
        assert_eq!(schedule.poll(later, true, true), PresenceAction::Wait);
        assert_eq!(
            schedule.poll(later, false, true),
            PresenceAction::Wait,
            "a device that is not hosting must not announce"
        );
        assert_eq!(
            schedule.poll(later + Duration::from_secs(1), true, true),
            PresenceAction::Announce,
            "hosting again should announce at once, not wait out the interval"
        );
    }

    /// Signing out is not a failure to retry; it is a reason to stop.
    #[test]
    fn a_signed_out_shell_does_not_announce() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(3);
        assert_eq!(schedule.poll(start, true, false), PresenceAction::Wait);
        assert!(schedule.next_due().is_none());
    }

    /// The schedule only moves when the caller reports what happened, so a
    /// beat that was never reported is offered again rather than silently
    /// dropped.
    #[test]
    fn an_unreported_beat_is_offered_again() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(5);
        assert_eq!(schedule.poll(start, true, true), PresenceAction::Announce);
        assert_eq!(schedule.poll(start, true, true), PresenceAction::Announce);
    }
}
