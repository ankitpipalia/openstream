//! Bounded receive-feedback bitrate control.
//!
//! This controller is deliberately independent from any encoder API. A host
//! reports the frame identifiers it sent, a client acknowledges frames it
//! actually assembled, and the controller turns backlog, missing frames, and
//! measured acknowledgement age into a slowly changing bitrate ceiling.
//! Keeping the policy here makes it usable by the native Linux encoder and by
//! a future platform-native encoder without smuggling socket state into the
//! capture or codec layers.

use std::collections::BTreeMap;

/// Maximum number of sent-but-unacknowledged frames retained for feedback.
pub const MAX_PENDING_FRAMES: usize = 64;
/// A pending frame older than this indicates growing interactive latency.
pub const ACK_TIMEOUT_MS: u64 = 250;
/// A host must remain healthy for this long before the controller ramps up.
pub const RAMP_INTERVAL_MS: u64 = 2_000;
/// Do not reconfigure an encoder more often than this.
pub const MIN_CHANGE_INTERVAL_MS: u64 = 500;
/// Eight frames is already more than one short interactive queue.
pub const BACKLOG_LIMIT: usize = 8;

/// Why a bitrate decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitrateReason {
    /// The receiver is not acknowledging frames quickly enough.
    Backlog,
    /// The receiver acknowledged a later frame, implying one or more gaps.
    Loss,
    /// The path has been healthy long enough to cautiously use more capacity.
    RampUp,
}

/// A bounded bitrate change requested by the feedback controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BitrateDecision {
    pub bitrate_mbps: f64,
    pub reason: BitrateReason,
    pub pending_frames: usize,
    pub oldest_frame_age_ms: u64,
    pub smoothed_ack_ms: Option<f64>,
}

/// Feedback state for one host-to-client video stream.
#[derive(Debug)]
pub struct AdaptiveBitrate {
    min_mbps: f64,
    max_mbps: f64,
    current_mbps: f64,
    pending: BTreeMap<u32, u64>,
    smoothed_ack_ms: Option<f64>,
    loss_since_tick: u32,
    healthy_since_ms: Option<u64>,
    ramp_suppressed_until_ms: u64,
    last_change_ms: u64,
}

impl AdaptiveBitrate {
    /// Create a controller with a sanitized initial, floor, and ceiling.
    pub fn new(initial_mbps: f64, min_mbps: f64, max_mbps: f64) -> Self {
        let min_mbps = finite_or(min_mbps, 0.5).max(0.1);
        let max_mbps = finite_or(max_mbps, min_mbps).max(min_mbps);
        Self {
            min_mbps,
            max_mbps,
            current_mbps: finite_or(initial_mbps, max_mbps).clamp(min_mbps, max_mbps),
            pending: BTreeMap::new(),
            smoothed_ack_ms: None,
            loss_since_tick: 0,
            healthy_since_ms: None,
            ramp_suppressed_until_ms: 0,
            last_change_ms: 0,
        }
    }

    /// The bitrate ceiling currently requested from the encoder.
    pub fn bitrate_mbps(&self) -> f64 {
        self.current_mbps
    }

    /// Number of frames waiting for a client acknowledgement.
    pub fn pending_frames(&self) -> usize {
        self.pending.len()
    }

    /// Smoothed host-observed acknowledgement age.
    pub fn smoothed_ack_ms(&self) -> Option<f64> {
        self.smoothed_ack_ms
    }

    /// Prevent a path transition from immediately reusing an earlier healthy
    /// interval to raise the encoder target.
    pub(crate) fn suppress_ramp_until(&mut self, now_ms: u64) {
        self.healthy_since_ms = Some(now_ms);
        self.ramp_suppressed_until_ms = now_ms.saturating_add(RAMP_INTERVAL_MS);
    }

    /// Record a frame before its fragments are sent.
    pub fn frame_sent(&mut self, frame_id: u32, now_ms: u64) {
        if self.pending.len() >= MAX_PENDING_FRAMES {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, sent_at)| *sent_at)
                .map(|(id, _)| *id)
            {
                self.pending.remove(&oldest);
                self.loss_since_tick = self.loss_since_tick.saturating_add(1);
            }
        }
        self.pending.insert(frame_id, now_ms);
    }

    /// Record a client acknowledgement and return its measured age.
    pub fn frame_acknowledged(&mut self, frame_id: u32, now_ms: u64) -> Option<u64> {
        self.frame_acknowledged_with_loss(frame_id, now_ms, 0)
    }

    /// Record a client acknowledgement and an explicit client-observed gap.
    pub fn frame_acknowledged_with_loss(
        &mut self,
        frame_id: u32,
        now_ms: u64,
        lost_frames: u16,
    ) -> Option<u64> {
        let sent_at = self.pending.get(&frame_id).copied()?;
        // Frame ACKs are cumulative with respect to the host's bounded
        // feedback window. A redundant ACK for frame N supersedes older ACKs
        // that may have been dropped by the reliable-control capacity bound.
        self.pending
            .retain(|pending_id, _| !sequence_at_or_before(*pending_id, frame_id));
        let age_ms = now_ms.saturating_sub(sent_at);
        self.smoothed_ack_ms = Some(match self.smoothed_ack_ms {
            Some(previous) => previous * 0.8 + age_ms as f64 * 0.2,
            None => age_ms as f64,
        });

        self.loss_since_tick = self.loss_since_tick.saturating_add(u32::from(lost_frames));
        Some(age_ms)
    }

    /// Evaluate the queue once from the host event loop's monotonic clock.
    pub fn tick(&mut self, now_ms: u64) -> Option<BitrateDecision> {
        let oldest_frame_age_ms = self
            .pending
            .values()
            .min()
            .map_or(0, |sent_at| now_ms.saturating_sub(*sent_at));
        let backlog = self.pending.len() >= BACKLOG_LIMIT || oldest_frame_age_ms >= ACK_TIMEOUT_MS;
        let loss = self.loss_since_tick > 0;
        let healthy = !backlog
            && !loss
            && self.pending.len() <= 2
            && self.smoothed_ack_ms.is_some_and(|age| age <= 100.0);

        let (reason, next) = if loss {
            self.healthy_since_ms = None;
            (Some(BitrateReason::Loss), self.current_mbps * 0.70)
        } else if backlog {
            self.healthy_since_ms = None;
            (Some(BitrateReason::Backlog), self.current_mbps * 0.75)
        } else if healthy {
            let healthy_since = *self.healthy_since_ms.get_or_insert(now_ms);
            if now_ms >= self.ramp_suppressed_until_ms
                && now_ms.saturating_sub(healthy_since) >= RAMP_INTERVAL_MS
            {
                (Some(BitrateReason::RampUp), self.current_mbps * 1.10)
            } else {
                (None, self.current_mbps)
            }
        } else {
            self.healthy_since_ms = None;
            (None, self.current_mbps)
        };

        self.loss_since_tick = 0;
        let reason = reason?;
        if now_ms.saturating_sub(self.last_change_ms) < MIN_CHANGE_INTERVAL_MS {
            return None;
        }
        let next = next.clamp(self.min_mbps, self.max_mbps);
        if (next - self.current_mbps).abs() < 0.001 {
            return None;
        }
        self.current_mbps = next;
        self.last_change_ms = now_ms;
        Some(BitrateDecision {
            bitrate_mbps: next,
            reason,
            pending_frames: self.pending.len(),
            oldest_frame_age_ms,
            smoothed_ack_ms: self.smoothed_ack_ms,
        })
    }
}

fn finite_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() { value } else { fallback }
}

pub(crate) fn sequence_at_or_before(sequence: u32, reference: u32) -> bool {
    sequence == reference || reference.wrapping_sub(sequence) < 0x8000_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backlog_reduces_rate_and_respects_floor() {
        let mut controller = AdaptiveBitrate::new(10.0, 2.0, 20.0);
        let backlog_limit = u32::try_from(BACKLOG_LIMIT).expect("test bound fits");
        let max_pending = u32::try_from(MAX_PENDING_FRAMES).expect("test bound fits");
        for id in 0..backlog_limit {
            controller.frame_sent(id, 0);
        }
        let decision = controller
            .tick(MIN_CHANGE_INTERVAL_MS)
            .expect("backlog decision");
        assert_eq!(decision.reason, BitrateReason::Backlog);
        assert_eq!(decision.pending_frames, BACKLOG_LIMIT);
        assert!((decision.bitrate_mbps - 7.5).abs() < f64::EPSILON);

        for id in backlog_limit..max_pending + 4 {
            controller.frame_sent(id, 1_000 + u64::from(id));
            let _ = controller.tick(2_000 + u64::from(id));
        }
        assert!(controller.bitrate_mbps() >= 2.0);
    }

    #[test]
    fn explicit_client_gap_marks_loss() {
        let mut controller = AdaptiveBitrate::new(10.0, 1.0, 10.0);
        controller.frame_sent(10, 0);
        controller.frame_sent(11, 0);
        controller.frame_sent(12, 0);
        assert_eq!(controller.frame_acknowledged(10, 20), Some(20));
        assert_eq!(controller.frame_acknowledged_with_loss(12, 30, 1), Some(30));
        let decision = controller.tick(500).expect("loss decision");
        assert_eq!(decision.reason, BitrateReason::Loss);
        assert!((decision.bitrate_mbps - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn healthy_path_ramps_only_after_a_quiet_period() {
        let mut controller = AdaptiveBitrate::new(5.0, 1.0, 10.0);
        controller.frame_sent(1, 0);
        controller.frame_acknowledged(1, 10);
        assert!(controller.tick(10).is_none());
        assert!(controller.tick(RAMP_INTERVAL_MS + 9).is_none());
        let decision = controller
            .tick(RAMP_INTERVAL_MS + 10)
            .expect("ramp decision");
        assert_eq!(decision.reason, BitrateReason::RampUp);
        assert!((decision.bitrate_mbps - 5.5).abs() < f64::EPSILON);
    }

    #[test]
    fn pending_window_is_bounded() {
        let mut controller = AdaptiveBitrate::new(5.0, 1.0, 10.0);
        let max_pending = u32::try_from(MAX_PENDING_FRAMES).expect("test bound fits");
        for id in 0..(max_pending + 10) {
            controller.frame_sent(id, u64::from(id));
        }
        assert_eq!(controller.pending_frames(), MAX_PENDING_FRAMES);
    }

    #[test]
    fn a_later_redundant_ack_clears_older_pending_frames() {
        let mut controller = AdaptiveBitrate::new(5.0, 1.0, 10.0);
        controller.frame_sent(10, 0);
        controller.frame_sent(11, 1);
        assert_eq!(controller.frame_acknowledged(11, 20), Some(19));
        assert_eq!(controller.pending_frames(), 0);
    }
}
