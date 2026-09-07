//! Remote link metrics and reconnect policy from assembled-frame ACKs.
//!
//! Local transport counters (`SessionStats`) cannot see loss: only the
//! receiver's `FrameAck` stream reports gaps (`lost_frames`) and round trips
//! (send time vs ACK arrival). This module turns that stream into a bounded
//! snapshot for overlays plus a deterministic reconnect backoff. All state
//! is bounded and every computation is pure enough to unit-test without a
//! socket.

use std::collections::VecDeque;
use std::time::Duration;

/// Samples retained for RTT estimation (covers ~8s at 60 fps).
pub const RTT_WINDOW: usize = 512;
/// ACKs retained for the loss-ratio window.
pub const LOSS_WINDOW: usize = 600;

/// One-line remote link snapshot for overlays and logs. Never carries
/// addresses, tokens, or clipboard contents.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct MetricsSnapshot {
    pub rtt_ms: Option<f64>,
    pub loss_ratio: f64,
    pub frames_sent: u64,
    pub frames_acked: u64,
    pub frames_lost: u64,
    pub frames_received: u64,
}

impl MetricsSnapshot {
    /// Short overlay line, e.g. `rtt 12ms loss 0.0% frames 3600/3598`.
    pub fn overlay_line(self) -> String {
        let rtt = self
            .rtt_ms
            .map(|rtt| format!("{rtt:.0}ms"))
            .unwrap_or_else(|| "-".to_string());
        format!(
            "rtt {rtt} loss {:.1}% frames {}/{}",
            self.loss_ratio * 100.0,
            self.frames_acked,
            self.frames_sent,
        )
    }
}

/// Tracks one session's ACK stream. Send timestamps keyed by frame id give
/// RTT; the ACKs' own `lost_frames` fields give receiver-observed loss.
#[derive(Debug, Default)]
pub struct MetricsReporter {
    sent: VecDeque<(u32, std::time::Instant)>,
    rtts_ms: VecDeque<f64>,
    rtt_ewma: Option<f64>,
    frames_sent: u64,
    frames_acked: u64,
    frames_lost: u64,
    lost_window: VecDeque<u64>,
    acked_ids: VecDeque<u32>,
    frames_received: u64,
}

impl MetricsReporter {
    /// Record a transmitted frame id with its send time.
    pub fn frame_sent(&mut self, frame_id: u32) {
        self.frame_sent_at(frame_id, std::time::Instant::now());
    }

    /// Record a transmitted frame at the actual send boundary. Callers that
    /// can observe the network send should use this method; the convenience
    /// `frame_sent` method exists only for simple adapters.
    pub fn frame_sent_at(&mut self, frame_id: u32, sent_at: std::time::Instant) {
        self.frames_sent += 1;
        if self.sent.len() >= RTT_WINDOW {
            self.sent.pop_front();
        }
        self.sent.push_back((frame_id, sent_at));
    }

    /// Record a frame received by a client. This is intentionally separate
    /// from `frame_sent`: a client cannot infer the sender's transmit time
    /// from its own receive clock and must not manufacture a zero RTT sample.
    pub fn frame_received(&mut self, _frame_id: u32) {
        self.frames_received += 1;
    }

    /// Record one assembly ACK. `frame_id`/`lost_frames` come straight from
    /// the decoded `FrameAck`; `now` should be the arrival instant.
    pub fn frame_acked(&mut self, frame_id: u32, lost_frames: u16, now: std::time::Instant) {
        if self.acked_ids.iter().any(|id| *id == frame_id) {
            return;
        }
        if self.acked_ids.len() >= RTT_WINDOW {
            self.acked_ids.pop_front();
        }
        self.acked_ids.push_back(frame_id);
        self.frames_acked += 1;
        self.frames_lost += u64::from(lost_frames);
        if self.lost_window.len() >= LOSS_WINDOW {
            self.lost_window.pop_front();
        }
        self.lost_window.push_back(u64::from(lost_frames));
        if let Some((_, sent_at)) = self.sent.iter().rev().find(|(id, _)| *id == frame_id) {
            let sample = now.duration_since(*sent_at).as_secs_f64() * 1000.0;
            if sample.is_finite() && sample >= 0.0 {
                if self.rtts_ms.len() >= RTT_WINDOW {
                    self.rtts_ms.pop_front();
                }
                self.rtts_ms.push_back(sample);
                self.rtt_ewma = Some(match self.rtt_ewma {
                    Some(ewma) => ewma * 0.9 + sample * 0.1,
                    None => sample,
                });
            }
        }
        // Retire fully-acknowledged send records so a wrap in frame ids can
        // never alias a stale timestamp into a fresh RTT sample.
        while self
            .sent
            .front()
            .is_some_and(|(id, _)| frame_id_older_or_equal(*id, frame_id))
        {
            self.sent.pop_front();
        }
    }

    /// Current snapshot for overlays and logs.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let windowed: u64 = self.lost_window.iter().sum();
        let loss_ratio = if self.lost_window.is_empty() {
            0.0
        } else {
            // Receiver-observed gaps over the recent window, normalized by
            // the number of ACKs in that same window.
            (windowed as f64 / self.lost_window.len() as f64).min(1.0)
        };
        MetricsSnapshot {
            rtt_ms: self.rtt_ewma,
            loss_ratio,
            frames_sent: self.frames_sent,
            frames_acked: self.frames_acked,
            frames_lost: self.frames_lost,
            frames_received: self.frames_received,
        }
    }
}

/// Wrapping-aware "a was sent no later than b" for 32-bit frame ids.
fn frame_id_older_or_equal(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < u32::MAX / 2 || a == b
}

/// Reconnect backoff after `attempt` (0-based) consecutive failures:
/// 1s, 2s, 4s ... capped at 30s. Pure so tests pin the schedule; callers add
/// their own jitter if desired.
pub fn reconnect_backoff(attempt: u32) -> Duration {
    Duration::from_secs(1_u64.saturating_mul(1 << attempt.min(5)).min(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reporter_snapshots_zero() {
        let snapshot = MetricsReporter::default().snapshot();
        assert_eq!(snapshot.rtt_ms, None);
        assert!(snapshot.loss_ratio <= 0.0);
        assert!(snapshot.overlay_line().contains("frames 0/0"));
    }

    #[test]
    fn acked_frames_produce_rtt_and_loss() {
        let mut reporter = MetricsReporter::default();
        let start = std::time::Instant::now();
        reporter.frame_sent_at(1, start);
        reporter.frame_sent_at(2, start);
        reporter.frame_sent_at(3, start);
        reporter.frame_acked(3, 2, start + Duration::from_millis(20));
        let snapshot = reporter.snapshot();
        assert!(snapshot.rtt_ms.is_some());
        assert_eq!(snapshot.frames_sent, 3);
        assert_eq!(snapshot.frames_acked, 1);
        assert_eq!(snapshot.frames_lost, 2);
        assert!(snapshot.loss_ratio > 0.0);
        assert!(snapshot.overlay_line().contains("loss "));
    }

    #[test]
    fn recent_loss_ratio_uses_recent_ack_count() {
        let mut reporter = MetricsReporter::default();
        let now = std::time::Instant::now();
        let loss_window = u32::try_from(LOSS_WINDOW).unwrap_or(u32::MAX);
        for id in 0..(loss_window + 1) {
            reporter.frame_sent_at(id, now);
            reporter.frame_acked(id, if id == 0 { 10 } else { 0 }, now);
        }
        assert!(reporter.snapshot().loss_ratio < 0.1);
    }

    #[test]
    fn unknown_ack_ids_still_count_without_rtt() {
        let mut reporter = MetricsReporter::default();
        reporter.frame_acked(99, 0, std::time::Instant::now());
        let snapshot = reporter.snapshot();
        assert_eq!(snapshot.rtt_ms, None);
        assert_eq!(snapshot.frames_acked, 1);
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let secs: Vec<u64> = (0..8)
            .map(|attempt| reconnect_backoff(attempt).as_secs())
            .collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn frame_id_comparison_survives_wrapping() {
        assert!(frame_id_older_or_equal(10, 20));
        assert!(frame_id_older_or_equal(20, 20));
        assert!(!frame_id_older_or_equal(20, 10));
        assert!(frame_id_older_or_equal(u32::MAX - 1, 3));
    }
}
