//! Telling apart the frames a capture source delivered from the ones the host
//! re-sent by itself.
//!
//! ScreenCaptureKit delivers on change, not on a clock, so a desktop nobody is
//! touching stops producing surfaces entirely. The host answers that with a
//! keepalive: once a second it re-encodes the last surface, which compresses to
//! almost nothing and keeps the client's liveness watch satisfied.
//!
//! That keepalive is also what makes encoded output useless as a measure of
//! capture: the frame counter advances at a steady one a second whether the
//! source is healthy or wedged. So the two are counted separately here.
//!
//! **What this is not.** It is not stall detection. A still screen and a frozen
//! source produce the same thing -- no new surface -- and no amount of counting
//! on this side separates them. That needs the stream-level `SCStreamDelegate`
//! and its `stream:didStopWithError:`, which the capture wrapper does not
//! install. What this gives is a diagnostic: how the frames in a session were
//! produced, and a line while a run of keepalives is happening.
//!
//! Not platform-gated, deliberately. The logic is arithmetic, the bug it exists
//! to prevent was arithmetic, and a counter that only compiles on macOS is a
//! counter that is only tested where someone happens to be looking.

/// How one submission to the encoder was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Submission {
    /// From a surface the capture source had just delivered.
    Fresh,
    /// By re-encoding a surface already sent, because nothing new arrived.
    Repeated,
}

/// Something worth saying out loud about the run of submissions so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report {
    /// The current unbroken run of keepalives has reached another multiple of
    /// the reporting interval.
    StillRepeating { consecutive: u64 },
    /// New surfaces are arriving again, after a run long enough to have been
    /// reported. A shorter gap says nothing: those are ordinary.
    Resumed { after: u64 },
}

/// Counts of how the frames in a session were produced.
#[derive(Debug, Default)]
pub(crate) struct FreshnessLog {
    fresh: u64,
    repeated: u64,
    /// Repeats since the last fresh surface. **Reset when one arrives** -- the
    /// point of the whole type.
    consecutive_repeats: u64,
    interval: u64,
}

impl FreshnessLog {
    /// Report every `interval` consecutive repeats. Zero disables reporting.
    pub(crate) fn new(interval: u64) -> Self {
        Self {
            interval,
            ..Self::default()
        }
    }

    /// Record one submission, and say whether it is worth reporting.
    ///
    /// Reporting is driven by the *consecutive* count, so a line appears while
    /// the picture is actually still and stops once it moves. Driving it from a
    /// lifetime total instead -- which is the bug this replaced -- crosses each
    /// multiple at whatever moment a long session happens to reach it, which is
    /// unrelated to what the screen is doing and reads as a stall report when
    /// nothing is stalled.
    pub(crate) fn note(&mut self, submission: Submission) -> Option<Report> {
        match submission {
            Submission::Repeated => {
                self.repeated += 1;
                self.consecutive_repeats += 1;
                if self.interval > 0 && self.consecutive_repeats % self.interval == 0 {
                    Some(Report::StillRepeating {
                        consecutive: self.consecutive_repeats,
                    })
                } else {
                    None
                }
            }
            Submission::Fresh => {
                self.fresh += 1;
                let run = std::mem::take(&mut self.consecutive_repeats);
                // Only worth mentioning if the run was reported in the first
                // place; otherwise every gap between two keystrokes is news.
                if self.interval > 0 && run >= self.interval {
                    Some(Report::Resumed { after: run })
                } else {
                    None
                }
            }
        }
    }

    /// Submissions that came from a new capture.
    pub(crate) fn fresh(&self) -> u64 {
        self.fresh
    }

    /// Submissions that re-sent a surface already encoded.
    pub(crate) fn repeated(&self) -> u64 {
        self.repeated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a sequence, collecting what it reported.
    fn run(interval: u64, sequence: &[Submission]) -> (FreshnessLog, Vec<Report>) {
        let mut log = FreshnessLog::new(interval);
        let reports = sequence.iter().filter_map(|&s| log.note(s)).collect();
        (log, reports)
    }

    #[test]
    fn a_run_of_repeats_reports_at_each_interval() {
        let (log, reports) = run(3, &[Submission::Repeated; 7]);
        assert_eq!(
            reports,
            vec![
                Report::StillRepeating { consecutive: 3 },
                Report::StillRepeating { consecutive: 6 },
            ]
        );
        assert_eq!(log.repeated(), 7);
        assert_eq!(log.fresh(), 0);
    }

    #[test]
    fn a_fresh_surface_resets_the_run_so_reports_track_the_screen() {
        // The regression. With a cumulative counter, these two short runs add
        // up to the interval and report -- announcing a still picture at the
        // exact moment a new surface has just arrived.
        let (log, reports) = run(
            4,
            &[
                Submission::Repeated,
                Submission::Repeated,
                Submission::Fresh,
                Submission::Repeated,
                Submission::Repeated,
            ],
        );
        assert!(
            reports.is_empty(),
            "two runs of two must not add up to a run of four: {reports:?}"
        );
        assert_eq!(
            log.repeated(),
            4,
            "the lifetime total still counts them all"
        );
        assert_eq!(log.fresh(), 1);
    }

    #[test]
    fn coming_back_is_reported_only_after_a_run_that_was_reported() {
        let mut log = FreshnessLog::new(2);
        // A run shorter than the interval: silent, and its recovery is silent
        // too, or every pause between keystrokes becomes a line.
        assert_eq!(log.note(Submission::Repeated), None);
        assert_eq!(log.note(Submission::Fresh), None);
        // A run that reaches the interval: reported, and so is its recovery.
        assert_eq!(
            log.note(Submission::Repeated),
            None,
            "one repeat is not yet a run"
        );
        assert_eq!(
            log.note(Submission::Repeated),
            Some(Report::StillRepeating { consecutive: 2 })
        );
        assert_eq!(
            log.note(Submission::Fresh),
            Some(Report::Resumed { after: 2 })
        );
        // And the counter really did reset.
        assert_eq!(log.note(Submission::Repeated), None);
    }

    #[test]
    fn totals_separate_what_the_source_produced_from_what_the_host_repeated() {
        // The number that makes a session legible after the fact: a run that is
        // nearly all keepalive was showing a picture that barely changed.
        let (log, _) = run(
            0,
            &[
                Submission::Fresh,
                Submission::Repeated,
                Submission::Repeated,
                Submission::Fresh,
            ],
        );
        assert_eq!((log.fresh(), log.repeated()), (2, 2));
    }

    #[test]
    fn a_zero_interval_reports_nothing_but_still_counts() {
        let (log, reports) = run(0, &[Submission::Repeated; 100]);
        assert!(reports.is_empty());
        assert_eq!(log.repeated(), 100);
    }
}
