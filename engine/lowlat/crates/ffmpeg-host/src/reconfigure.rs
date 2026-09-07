//! Bounded rolling-restart bitrate control for the external FFmpeg host.
//!
//! Arbitrary FFmpeg processes expose no common in-place encoder-control
//! interface, so live bitrate changes are applied by respawning the encoder
//! at the new rate. Restarts are rate-limited (cooldown), hysteresis-gated
//! (no flapping on small changes), and disabled by default behind
//! `OPENSTREAM_FFMPEG_RECONFIGURE=restart`. The replacement encoder starts
//! with an IDR frame, which also serves the pending keyframe request.

use std::time::Duration;

/// Default minimum seconds between two encoder restarts.
pub(crate) const DEFAULT_MIN_INTERVAL_SECS: u64 = 10;
/// Relative bitrate change required to justify a restart (15%).
pub(crate) const DEFAULT_CHANGE_THRESHOLD: f64 = 0.15;

/// When and how aggressively the host may restart FFmpeg for a new rate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RestartPolicy {
    pub(crate) enabled: bool,
    pub(crate) min_interval: Duration,
    pub(crate) change_threshold: f64,
}

impl RestartPolicy {
    /// Read the policy from the process environment.
    pub(crate) fn from_env() -> Self {
        let enabled = std::env::var("OPENSTREAM_FFMPEG_RECONFIGURE").as_deref() == Ok("restart");
        let min_interval = std::env::var("OPENSTREAM_RECONFIGURE_MIN_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(DEFAULT_MIN_INTERVAL_SECS));
        Self {
            enabled,
            min_interval,
            change_threshold: DEFAULT_CHANGE_THRESHOLD,
        }
    }

    /// Decide whether to restart the encoder now.
    ///
    /// Returns the target rate when restarts are enabled, the relative
    /// change exceeds the threshold, and the cooldown since `last_restart`
    /// (`None` = never restarted) has elapsed.
    pub(crate) fn should_restart(
        &self,
        current_mbps: f64,
        target_mbps: f64,
        now: std::time::Instant,
        last_restart: Option<std::time::Instant>,
    ) -> Option<f64> {
        if !self.enabled {
            return None;
        }
        if !current_mbps.is_finite() || !target_mbps.is_finite() {
            return None;
        }
        if current_mbps <= 0.0 || target_mbps <= 0.0 {
            return None;
        }
        let change = (target_mbps - current_mbps).abs() / current_mbps;
        if change < self.change_threshold {
            return None;
        }
        if let Some(previous) = last_restart
            && now.duration_since(previous) < self.min_interval
        {
            return None;
        }
        Some(target_mbps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RestartPolicy {
        RestartPolicy {
            enabled: true,
            min_interval: Duration::from_secs(10),
            change_threshold: DEFAULT_CHANGE_THRESHOLD,
        }
    }

    #[test]
    fn disabled_policy_never_restarts() {
        let policy = RestartPolicy {
            enabled: false,
            ..policy()
        };
        let now = std::time::Instant::now();
        assert_eq!(policy.should_restart(10.0, 1.0, now, None), None);
    }

    #[test]
    fn small_changes_do_not_restart() {
        let policy = policy();
        let now = std::time::Instant::now();
        assert_eq!(policy.should_restart(10.0, 9.0, now, None), None);
        assert_eq!(policy.should_restart(10.0, 10.5, now, None), None);
    }

    #[test]
    fn large_changes_restart_once_per_cooldown() {
        let policy = policy();
        let start = std::time::Instant::now();
        assert_eq!(policy.should_restart(10.0, 5.0, start, None), Some(5.0));
        assert_eq!(
            policy.should_restart(10.0, 5.0, start + Duration::from_secs(5), Some(start)),
            None
        );
        assert_eq!(
            policy.should_restart(10.0, 5.0, start + Duration::from_secs(11), Some(start)),
            Some(5.0)
        );
    }

    #[test]
    fn nonfinite_and_nonpositive_rates_never_restart() {
        let policy = policy();
        let now = std::time::Instant::now();
        assert_eq!(policy.should_restart(f64::NAN, 5.0, now, None), None);
        assert_eq!(policy.should_restart(10.0, 0.0, now, None), None);
        assert_eq!(policy.should_restart(-1.0, 5.0, now, None), None);
    }
}
