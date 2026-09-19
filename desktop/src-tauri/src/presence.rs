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

use openstream_app_core::HostStatus;
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

/// Spread, so a fleet restarted by one script does not beat in lockstep.
///
/// It is *added* to [`RENEW_INTERVAL`], so it lengthens the gap between beats
/// and therefore **narrows** the margin against the TTL rather than widening
/// it: the worst case is a 35-second gap against a 90-second lifetime, which
/// still leaves room for one missed beat and a retry. That is why it is a
/// small fixed bound and not a fraction of the interval.
pub const RENEW_JITTER: Duration = Duration::from_secs(5);

/// First retry delay after a failed beat, doubling up to [`RETRY_MAX`].
pub const RETRY_MIN: Duration = Duration::from_secs(2);

/// The retry ceiling. Deliberately far below the TTL: a host whose beats are
/// failing should keep trying often enough that one success rescues it.
pub const RETRY_MAX: Duration = Duration::from_secs(15);

/// Whether a host in this state should be advertised as connectable.
///
/// `Ready` and nothing else. The tempting version of this is "anything but
/// `Disabled`", which is what the hosting lifecycle elsewhere asks, and it is
/// wrong here: [`HostStatus`] also has `Failed`, so a host whose agent crashed
/// or exhausted its restart budget would go on announcing itself for as long
/// as the shell stayed open. The device would sit in its owner's list looking
/// connectable, and every request to it would time out with nothing to explain
/// why. `Starting` is excluded for the same reason -- there is nothing behind
/// it yet, and the wait is short enough that the first beat lands as soon as
/// it becomes `Ready`.
#[must_use]
pub fn advertises_presence(status: &HostStatus) -> bool {
    matches!(status, HostStatus::Ready)
}

/// What the presence task should do on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceAction {
    /// Nothing is due.
    Wait,
    /// Announce now, then report the outcome through
    /// [`PresenceSchedule::record_success`] or
    /// [`PresenceSchedule::record_failure`].
    Announce,
    /// This device was advertised and is no longer ready to host. Withdraw
    /// now, then report through [`PresenceSchedule::record_withdrawn`] or
    /// [`PresenceSchedule::record_failure`].
    ///
    /// Without this a host that crashed stayed listed as connectable until
    /// the service's own lifetime ran out, and every request to it in that
    /// window went to a host that was not there.
    Withdraw,
}

/// When the next presence beat is due.
///
/// The caller must report the outcome of every [`PresenceAction::Announce`]
/// it is given. Nothing else moves the schedule forward, so a caller that
/// announces and stays silent will be told to announce again on its next
/// tick.
#[derive(Debug)]
pub struct PresenceSchedule {
    /// `None` means "act at the next opportunity": either nothing has been
    /// sent yet, or readiness has just changed.
    next_due: Option<Instant>,
    consecutive_failures: u32,
    seed: u64,
    /// Whether the service has been told this device is online and has not
    /// been told otherwise. This is what makes withdrawal possible: a host
    /// that never announced has nothing to take back, and one that did must
    /// take it back rather than waiting out the lifetime.
    advertised: bool,
    /// Whether the current run of work is a withdrawal rather than a beat.
    withdrawing: bool,
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
            advertised: false,
            withdrawing: false,
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
    pub fn poll(&mut self, now: Instant, ready: bool, authenticated: bool) -> PresenceAction {
        if !authenticated {
            // Nothing can be withdrawn without a token, and there is no one
            // to withdraw on behalf of. Sign-out withdraws on its own path
            // while it still holds the token; anything else lapses on the
            // service's lifetime, which is what that lifetime is for.
            self.reset();
            return PresenceAction::Wait;
        }
        if ready {
            self.withdrawing = false;
            return if self.is_due(now) {
                PresenceAction::Announce
            } else {
                PresenceAction::Wait
            };
        }
        // Not ready. A device that was never advertised has nothing to take
        // back, so this is simply the idle state: forget the schedule, so
        // that becoming ready announces at once rather than waiting out an
        // interval that started earlier.
        if !self.advertised {
            self.reset();
            return PresenceAction::Wait;
        }
        // It was advertised and is not ready any more, which is the case that
        // used to leave a dead host listed. Withdraw on the first tick after
        // the transition rather than at the next renewal, and pace retries on
        // the same backoff as a failed beat.
        if !self.withdrawing {
            self.withdrawing = true;
            self.next_due = None;
            self.consecutive_failures = 0;
        }
        if self.is_due(now) {
            PresenceAction::Withdraw
        } else {
            PresenceAction::Wait
        }
    }

    /// Whether this tick has anything to do, without changing anything.
    ///
    /// The task's pre-check, so an ordinary tick with nothing owed does not
    /// take the control-plane lock. It has to distinguish "ready and not due"
    /// from "not ready with a withdrawal owed": asking only whether a beat is
    /// due took the lock every second for as long as a device stayed
    /// advertised, and asking only whether the device is advertised did the
    /// same.
    #[must_use]
    pub fn wants_attention(&self, now: Instant, ready: bool) -> bool {
        if ready {
            return self.is_due(now);
        }
        if !self.advertised {
            return false;
        }
        // A withdrawal is owed. Immediately on the transition, and afterwards
        // paced like any other retry.
        !self.withdrawing || self.is_due(now)
    }

    /// Whether a beat is due, ignoring hosting and sign-in state.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        match self.next_due {
            None => true,
            Some(due) => now >= due,
        }
    }

    /// Forget the schedule. Does not change whether the device is currently
    /// advertised, because forgetting when to act says nothing about what the
    /// service has been told.
    pub fn reset(&mut self) {
        self.next_due = None;
        self.consecutive_failures = 0;
        self.withdrawing = false;
    }

    /// A beat landed: the service now believes this device is online.
    pub fn record_success(&mut self, now: Instant) {
        self.consecutive_failures = 0;
        self.advertised = true;
        self.next_due = Some(now + RENEW_INTERVAL + self.next_jitter());
    }

    /// A withdrawal landed: the service no longer believes it.
    pub fn record_withdrawn(&mut self) {
        self.advertised = false;
        self.reset();
    }

    /// Whether the service has been told this device is online.
    #[must_use]
    pub fn is_advertised(&self) -> bool {
        self.advertised
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

    /// Jitter spreads a fleet, so it has to vary. Because it is added it
    /// narrows the margin against the TTL, so what matters is that the widened
    /// gap still lands well inside the service's lifetime.
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

    /// The transitions, in the order a host actually goes through them.
    ///
    /// Starting is the one that was wrong in two places at once: the command
    /// path announced as soon as it had asked the agent to start, and the
    /// loop had no way to take that back. A host that never became Ready was
    /// advertised as connectable, and a host that became Ready and then died
    /// stayed advertised until the service's lifetime ran out.
    #[test]
    fn presence_follows_readiness_in_both_directions() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(0x51a7);

        // Starting: nothing is claimed, so there is nothing to take back.
        assert_eq!(
            schedule.poll(start, false, true),
            PresenceAction::Wait,
            "a host that has not started must not be announced"
        );
        assert!(!schedule.is_advertised());

        // Ready: announce, and only now is the device claimed to be online.
        assert_eq!(schedule.poll(start, true, true), PresenceAction::Announce);
        assert!(
            !schedule.is_advertised(),
            "nothing is claimed until the announcement actually lands"
        );
        schedule.record_success(start);
        assert!(schedule.is_advertised());

        // Still ready, not yet due: quiet.
        let soon = start + Duration::from_secs(5);
        assert_eq!(schedule.poll(soon, true, true), PresenceAction::Wait);

        // The agent dies. The withdrawal is owed at once, not at the next
        // renewal, which would leave a dead host listed for most of a minute.
        assert_eq!(
            schedule.poll(soon, false, true),
            PresenceAction::Withdraw,
            "a host that stopped being ready must be taken back immediately"
        );
        schedule.record_withdrawn();
        assert!(!schedule.is_advertised());

        // And once withdrawn, it stays quiet rather than withdrawing forever.
        assert_eq!(
            schedule.poll(soon + Duration::from_secs(1), false, true),
            PresenceAction::Wait
        );
    }

    /// A withdrawal that does not land is owed until it does. Until then the
    /// service is still offering a host that is not there.
    #[test]
    fn a_failed_withdrawal_is_retried() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(9);
        assert_eq!(schedule.poll(start, true, true), PresenceAction::Announce);
        schedule.record_success(start);

        let mut now = start + Duration::from_secs(1);
        assert_eq!(schedule.poll(now, false, true), PresenceAction::Withdraw);
        schedule.record_failure(now);

        // Not immediately -- that would spin -- but on the same backoff a
        // failed beat uses, and still owed.
        assert_eq!(schedule.poll(now, false, true), PresenceAction::Wait);
        now += RETRY_MAX + Duration::from_secs(1);
        assert_eq!(
            schedule.poll(now, false, true),
            PresenceAction::Withdraw,
            "the device is still advertised, so the withdrawal is still owed"
        );
        assert!(schedule.is_advertised());
    }

    /// The pre-check has to agree with what `poll` would decide, or the loop
    /// either takes the control-plane lock every second for nothing or misses
    /// work it owes.
    #[test]
    fn the_pre_check_agrees_with_the_decision() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(0x7ea);

        // Ready and nothing sent yet: a beat is owed.
        assert!(schedule.wants_attention(start, true));
        schedule.record_success(start);

        // Ready and not due: nothing owed, and so no lock taken.
        let soon = start + Duration::from_secs(5);
        assert!(
            !schedule.wants_attention(soon, true),
            "an advertised device with no beat due must not wake the loop"
        );
        assert_eq!(schedule.poll(soon, true, true), PresenceAction::Wait);

        // Ready and due again.
        let due = start + RENEW_INTERVAL + RENEW_JITTER + Duration::from_secs(1);
        assert!(schedule.wants_attention(due, true));

        // Not ready, and advertised: owed at once, whatever the beat schedule
        // said.
        assert!(
            schedule.wants_attention(soon, false),
            "a withdrawal must not wait for the next renewal"
        );
        assert_eq!(schedule.poll(soon, false, true), PresenceAction::Withdraw);
        schedule.record_withdrawn();

        // Not ready and not advertised: nothing owed, ever.
        assert!(!schedule.wants_attention(soon, false));
        assert!(!schedule.wants_attention(due, false));
    }

    /// Signing out takes the token with it, so there is nothing to withdraw
    /// with. The sign-out path withdraws while it still holds one.
    #[test]
    fn losing_the_token_does_not_try_to_withdraw() {
        let start = Instant::now();
        let mut schedule = PresenceSchedule::new(13);
        assert_eq!(schedule.poll(start, true, true), PresenceAction::Announce);
        schedule.record_success(start);
        assert_eq!(
            schedule.poll(start + Duration::from_secs(1), false, false),
            PresenceAction::Wait
        );
    }

    /// The state that mattered and was wrong: a host that failed kept being
    /// advertised, because the check asked "not Disabled" rather than "Ready".
    #[test]
    fn only_a_ready_host_is_advertised() {
        assert!(advertises_presence(&HostStatus::Ready));
        assert!(!advertises_presence(&HostStatus::Disabled));
        assert!(
            !advertises_presence(&HostStatus::Starting),
            "a host that has not started yet cannot serve a session"
        );
        for retryable in [true, false] {
            assert!(
                !advertises_presence(&HostStatus::Failed {
                    message: "the agent exited".into(),
                    retryable,
                }),
                "a failed host must stop advertising, retryable={retryable}"
            );
        }
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

        // Stopping is not simply silence any more: the device was announced,
        // so it has to be taken back before it can be quiet.
        assert_eq!(
            schedule.poll(later, false, true),
            PresenceAction::Withdraw,
            "a device that was advertised and stopped hosting must be withdrawn"
        );
        schedule.record_withdrawn();
        assert_eq!(
            schedule.poll(later, false, true),
            PresenceAction::Wait,
            "once withdrawn it is quiet"
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
