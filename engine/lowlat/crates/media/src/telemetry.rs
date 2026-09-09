//! Peer-local coordination between portable path telemetry and frame feedback.
//!
//! Path samples remain observational: only authenticated [`FrameAck`] values
//! are passed to the adaptive encoder controller.

use std::collections::BTreeMap;

use openstream_transport::{PathGeneration, PeerTransportSnapshot, TransportSample};

use crate::adaptive::{MAX_PENDING_FRAMES, sequence_at_or_before};
use crate::{AdaptiveBitrate, BitrateDecision, FrameAck};

#[derive(Debug, Clone, Copy)]
struct PendingFrame {
    encoded_bytes: usize,
    sent_at_ms: u64,
}

/// Bounded peer-local telemetry suitable for host diagnostics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerTelemetrySnapshot {
    pub path_generation: PathGeneration,
    pub path: Option<PeerTransportSnapshot>,
    pub path_sample_baseline: Option<TransportSample>,
    pub bitrate_mbps: f64,
    pub pending_frames: usize,
    pub pending_encoded_bytes: usize,
    pub oldest_frame_age_ms: u64,
    pub smoothed_frame_ack_ms: Option<f64>,
    pub frame_loss_since_tick: u32,
}

/// Coordinates path observations with receiver-proven video feedback.
#[derive(Debug)]
pub struct PeerTelemetryAdapter {
    adaptive: AdaptiveBitrate,
    generation: PathGeneration,
    pending: BTreeMap<u32, PendingFrame>,
    path: Option<PeerTransportSnapshot>,
    path_sample_baseline: Option<TransportSample>,
    last_now_ms: u64,
}

impl PeerTelemetryAdapter {
    pub fn new(adaptive: AdaptiveBitrate, generation: PathGeneration, now_ms: u64) -> Self {
        Self {
            adaptive,
            generation,
            pending: BTreeMap::new(),
            path: None,
            path_sample_baseline: None,
            last_now_ms: now_ms,
        }
    }

    /// Record a local path snapshot without using its rates as encoder input.
    pub fn observe_path(&mut self, snapshot: &PeerTransportSnapshot, now_ms: u64) {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        if snapshot.path_generation < self.generation {
            return;
        }
        if snapshot.path_generation > self.generation {
            self.generation = snapshot.path_generation;
            self.path_sample_baseline = None;
            self.adaptive.suppress_ramp_until(now_ms);
        } else {
            self.path_sample_baseline = snapshot.sample;
        }
        self.path = Some(*snapshot);
    }

    /// Record one complete encoded frame after all of its fragments are sent.
    pub fn frame_sent(&mut self, frame_id: u32, encoded_bytes: usize, now_ms: u64) {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        if self.pending.len() >= MAX_PENDING_FRAMES {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, frame)| frame.sent_at_ms)
                .map(|(id, _)| *id)
            {
                self.pending.remove(&oldest);
            }
        }
        self.pending.insert(
            frame_id,
            PendingFrame {
                encoded_bytes,
                sent_at_ms: now_ms,
            },
        );
        self.adaptive.frame_sent(frame_id, now_ms);
    }

    /// Apply authenticated receiver evidence for a completed video frame.
    pub fn frame_ack(&mut self, ack: FrameAck, now_ms: u64) {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        if self
            .adaptive
            .frame_acknowledged_with_loss(ack.frame_id, now_ms, ack.lost_frames)
            .is_some()
        {
            self.pending
                .retain(|pending_id, _| !sequence_at_or_before(*pending_id, ack.frame_id));
        }
    }

    /// Decode and accept a portable frame acknowledgement payload.
    pub fn accept_frame_ack_payload(&mut self, payload: &[u8], now_ms: u64) -> bool {
        let Ok(ack) = FrameAck::decode(payload) else {
            return false;
        };
        self.frame_ack(ack, now_ms);
        true
    }

    /// Advance encoder policy from frame feedback only.
    pub fn tick(&mut self, now_ms: u64) -> Option<BitrateDecision> {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        self.adaptive.tick(now_ms)
    }

    pub fn bitrate_mbps(&self) -> f64 {
        self.adaptive.bitrate_mbps()
    }

    pub fn pending_frames(&self) -> usize {
        self.pending.len()
    }

    /// Return a snapshot using the latest timestamp observed by the adapter.
    pub fn snapshot(&self) -> PeerTelemetrySnapshot {
        self.snapshot_at(self.last_now_ms)
    }

    /// Return a snapshot with a fresh monotonic timestamp for pending-frame age.
    pub fn snapshot_at(&self, now_ms: u64) -> PeerTelemetrySnapshot {
        let oldest_frame_age_ms = self
            .pending
            .values()
            .map(|frame| frame.sent_at_ms)
            .min()
            .map_or(0, |sent_at_ms| now_ms.saturating_sub(sent_at_ms));
        PeerTelemetrySnapshot {
            path_generation: self.generation,
            path: self.path,
            path_sample_baseline: self.path_sample_baseline,
            bitrate_mbps: self.bitrate_mbps(),
            pending_frames: self.pending_frames(),
            pending_encoded_bytes: self.pending.values().fold(0_usize, |total, frame| {
                total.saturating_add(frame.encoded_bytes)
            }),
            oldest_frame_age_ms,
            smoothed_frame_ack_ms: self.adaptive.smoothed_ack_ms(),
            frame_loss_since_tick: self.adaptive.frame_loss_since_tick(),
        }
    }
}
