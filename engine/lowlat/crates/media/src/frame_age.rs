//! Where a decoded frame spends its time on the client, and what happens to
//! the ones that never arrive.
//!
//! [`crate::latency`] measures a frame that completes its journey. This
//! module measures the journey itself, including its failures: two bounded
//! queues sit between the decoder and the window, both drop frames when the
//! consumer falls behind, and until now both reported that as a `bool` or as
//! nothing at all. A dropped frame does not appear in any span histogram --
//! it has no end stamp -- so a client that is discarding half its output can
//! show a perfectly healthy decode-to-present distribution. This record is
//! the counter side of that: it counts what was produced, what was accepted,
//! what was dropped, and what reached the presenter, so the spans can be read
//! against the population they were drawn from.
//!
//! # This is a baseline, not a fix
//!
//! Nothing here changes the queues. The counters exist to establish what
//! today's client actually does before anything is redesigned, and the tests
//! deliberately pin the current drop-newest behaviour so that a later change
//! to drop-oldest (a latest-frame mailbox) shows up as a failing test rather
//! than as a silent difference in a benchmark.
//!
//! # `present_submit` is not photon time
//!
//! The last milestone this module records is the moment the window hands a
//! buffer to the presenter. Everything after that -- the compositor's own
//! queueing, the swap, the panel's response -- is outside the process and
//! unmeasured. `present_submit` is the boundary of what the client can
//! observe, and it is named for the act rather than for the outcome so no
//! reader mistakes it for the photon leaving the display.

use std::collections::VecDeque;
use std::fmt;

use crate::latency::{Client, Histogram, SpanValue, Stamp};

/// Identity the client assigns to each picture its decoder produces.
///
/// Deliberately *not* the host's frame id. The client receives access units,
/// not frames, and the decoder is free to emit a different number of pictures
/// than the host encoded -- it drops damaged ones, it may reorder, and after
/// a seek or a keyframe request the correspondence restarts. Carrying a host
/// frame id through the decoder would look like a correlation and would not
/// be one; any span computed from it would be a fabricated number wearing a
/// real one's units. A locally assigned sequence number claims only what is
/// true: this is the Nth picture this decoder produced.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DecodedFrameSeq(u64);

impl DecodedFrameSeq {
    /// The first picture of a session.
    pub const FIRST: Self = Self(0);

    /// The underlying counter, for rendering and for tests.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next sequence number.
    ///
    /// `u64` is not a wrap-around risk here: at one thousand pictures per
    /// second this counter needs about 5.8e8 years to overflow. It saturates
    /// rather than panicking because a debug-build panic in the decoder
    /// reader would take the session down for an arithmetic event that
    /// cannot occur.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for DecodedFrameSeq {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// A decoded picture, carrying the stamps it collects on the way to the
/// window.
///
/// The stamps travel with the frame because the queues between the decoder
/// and the window are ordinary channels: the consumer has no other way to
/// know when the producer let go of it. `ui_queued_at` is optional because a
/// frame can be measured before it is ever offered to the window, and an
/// absent stamp must stay absent rather than defaulting to "now" -- a
/// defaulted stamp would report a queue wait of zero for a frame that never
/// went through the queue.
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    seq: DecodedFrameSeq,
    decoded_at: Stamp<Client>,
    ui_queued_at: Option<Stamp<Client>>,
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

impl DecodedFrame {
    /// A picture fresh out of the decoder.
    #[must_use]
    pub const fn new(
        seq: DecodedFrameSeq,
        decoded_at: Stamp<Client>,
        width: usize,
        height: usize,
        pixels: Vec<u32>,
    ) -> Self {
        Self {
            seq,
            decoded_at,
            ui_queued_at: None,
            width,
            height,
            pixels,
        }
    }

    /// Stamp the moment this frame is handed to the window's queue.
    pub const fn entering_ui_queue(&mut self, at: Stamp<Client>) {
        self.ui_queued_at = Some(at);
    }

    #[must_use]
    pub const fn seq(&self) -> DecodedFrameSeq {
        self.seq
    }

    #[must_use]
    pub const fn decoded_at(&self) -> Stamp<Client> {
        self.decoded_at
    }

    #[must_use]
    pub const fn ui_queued_at(&self) -> Option<Stamp<Client>> {
        self.ui_queued_at
    }

    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    #[must_use]
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    /// Take the pixels, leaving the frame's stamps intact for accounting.
    #[must_use]
    pub fn into_pixels(self) -> Vec<u32> {
        self.pixels
    }
}

/// What a bounded queue did with a frame it was offered.
///
/// This replaces a `bool` that meant "keep going", under which a delivered
/// frame and a dropped frame were the same value and only a closed channel
/// was distinguishable. The caller needs all three: `Enqueued` is the normal
/// path, `DroppedNewest` is a frame the consumer will never see and must be
/// counted, and `Closed` is the only one that should stop the producer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameOffer {
    /// Accepted by the queue.
    Enqueued,
    /// The queue was full, so *this* frame -- the newest one -- was
    /// discarded. Note the direction: a full `try_send` drops the frame
    /// being offered, not the stale frame already queued, which is the
    /// opposite of a latest-frame mailbox. The name says which, because the
    /// two have opposite effects on latency and the code reads identically.
    DroppedNewest,
    /// The consumer is gone. The producer should stop.
    Closed,
}

impl FrameOffer {
    /// Whether the consumer will see this frame.
    #[must_use]
    pub const fn delivered(self) -> bool {
        matches!(self, Self::Enqueued)
    }

    /// Whether the producer should stop. A dropped frame is not a reason to
    /// stop; a closed channel is.
    #[must_use]
    pub const fn should_stop(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Counters for one bounded queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueCounters {
    /// Frames the queue accepted.
    pub enqueued: u64,
    /// Frames discarded because the queue was full.
    pub dropped_newest: u64,
    /// Frames discarded because the consumer was gone.
    pub closed: u64,
}

impl QueueCounters {
    fn record(&mut self, offer: FrameOffer) {
        let counter = match offer {
            FrameOffer::Enqueued => &mut self.enqueued,
            FrameOffer::DroppedNewest => &mut self.dropped_newest,
            FrameOffer::Closed => &mut self.closed,
        };
        *counter = counter.saturating_add(1);
    }

    /// Frames offered to this queue in total.
    #[must_use]
    pub const fn offered(&self) -> u64 {
        self.enqueued
            .saturating_add(self.dropped_newest)
            .saturating_add(self.closed)
    }

    fn render(&self, name: &str) -> String {
        format!(
            "{name} enqueued={} dropped_newest={} closed={}",
            self.enqueued, self.dropped_newest, self.closed
        )
    }
}

/// How many consumed-but-unpresented frames to remember.
///
/// Bounded for the same reason the trace ring is: the window consumes frames
/// in a batch and presents them one at a time, so a handful can be in flight,
/// but an unbounded list would grow without limit if presentation stopped.
const PENDING_CAPACITY: usize = 8;

/// The client's frame-age baseline.
///
/// Always on: the counters are integer increments on paths that already copy
/// a megabyte of pixels, and a drop that is only visible when telemetry is
/// switched on is a drop that will be missed.
#[derive(Debug)]
pub struct FrameAgeRecord {
    next_seq: DecodedFrameSeq,
    decoded_frames: u64,
    decoder_queue: QueueCounters,
    ui_queue: QueueCounters,
    ui_frames_consumed: u64,
    new_frames_present_submitted: u64,
    repeat_present_submissions: u64,
    pending_frames_replaced: u64,
    decoder_queue_wait: Histogram,
    ui_queue_wait: Histogram,
    decoded_to_ui_consume: Histogram,
    decoded_to_present_submit: Histogram,
    pending: VecDeque<DecodedFrameSeq>,
    last_present_submitted: Option<DecodedFrameSeq>,
}

impl Default for FrameAgeRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAgeRecord {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: DecodedFrameSeq::FIRST,
            decoded_frames: 0,
            decoder_queue: QueueCounters::default(),
            ui_queue: QueueCounters::default(),
            ui_frames_consumed: 0,
            new_frames_present_submitted: 0,
            repeat_present_submissions: 0,
            pending_frames_replaced: 0,
            decoder_queue_wait: Histogram::new(),
            ui_queue_wait: Histogram::new(),
            decoded_to_ui_consume: Histogram::new(),
            decoded_to_present_submit: Histogram::new(),
            pending: VecDeque::with_capacity(PENDING_CAPACITY),
            last_present_submitted: None,
        }
    }

    /// A picture came out of the decoder. Returns the sequence number to
    /// carry with it.
    pub fn frame_decoded(&mut self) -> DecodedFrameSeq {
        let seq = self.next_seq;
        self.next_seq = seq.next();
        self.decoded_frames = self.decoded_frames.saturating_add(1);
        seq
    }

    /// Outcome of offering a frame to the decoder-to-session queue.
    pub fn decoder_queue_offer(&mut self, offer: FrameOffer) {
        self.decoder_queue.record(offer);
    }

    /// The session loop took a frame off the decoder queue.
    pub fn decoder_queue_consumed(&mut self, frame: &DecodedFrame, at: Stamp<Client>) {
        self.decoder_queue_wait
            .record_span(at.since(frame.decoded_at()));
    }

    /// Outcome of offering a frame to the window's queue.
    pub fn ui_queue_offer(&mut self, offer: FrameOffer) {
        self.ui_queue.record(offer);
    }

    /// The window loop took a frame off its queue.
    ///
    /// A frame consumed while an earlier one is still waiting to be
    /// submitted means that earlier frame was replaced without ever being
    /// shown. That is counted here rather than inferred later, because once
    /// the pixels are overwritten there is nothing left to infer it from.
    pub fn ui_queue_consumed(&mut self, frame: &DecodedFrame, at: Stamp<Client>) {
        self.ui_frames_consumed = self.ui_frames_consumed.saturating_add(1);
        if let Some(queued_at) = frame.ui_queued_at() {
            self.ui_queue_wait.record_span(at.since(queued_at));
        }
        self.decoded_to_ui_consume
            .record_span(at.since(frame.decoded_at()));
        if self.pending.len() >= PENDING_CAPACITY {
            self.pending.pop_front();
            self.pending_frames_replaced = self.pending_frames_replaced.saturating_add(1);
        }
        self.pending.push_back(frame.seq());
    }

    /// The window handed a frame's pixels to the presenter.
    ///
    /// Only the first submission of a given sequence number is a new frame.
    /// The window re-presents its last buffer while the stream is idle, so
    /// counting every submission would report a frame rate the host never
    /// produced and would feed the same decode timestamp into the histogram
    /// repeatedly, dragging the tail of a span that never happened again.
    pub fn present_submitted(&mut self, frame: &DecodedFrame, at: Stamp<Client>) {
        self.present_submitted_seq(frame.seq(), frame.decoded_at(), at);
    }

    /// As [`Self::present_submitted`], for a caller that kept the identity
    /// after dropping the pixels.
    pub fn present_submitted_seq(
        &mut self,
        seq: DecodedFrameSeq,
        decoded_at: Stamp<Client>,
        at: Stamp<Client>,
    ) {
        if self.last_present_submitted == Some(seq) {
            self.repeat_present_submissions = self.repeat_present_submissions.saturating_add(1);
            return;
        }
        // Everything queued ahead of this frame was skipped: the window
        // moved on without submitting it.
        while let Some(front) = self.pending.front().copied() {
            self.pending.pop_front();
            if front == seq {
                break;
            }
            self.pending_frames_replaced = self.pending_frames_replaced.saturating_add(1);
        }
        self.last_present_submitted = Some(seq);
        self.new_frames_present_submitted = self.new_frames_present_submitted.saturating_add(1);
        self.decoded_to_present_submit
            .record_span(at.since(decoded_at));
    }

    /// The session ended. Frames still waiting to be submitted were never
    /// shown, and are counted as replaced rather than left in limbo.
    pub fn session_ended(&mut self) {
        let stranded = u64::try_from(self.pending.len()).unwrap_or(u64::MAX);
        self.pending.clear();
        self.pending_frames_replaced = self.pending_frames_replaced.saturating_add(stranded);
    }

    #[must_use]
    pub const fn decoded_frames(&self) -> u64 {
        self.decoded_frames
    }

    #[must_use]
    pub const fn decoder_queue(&self) -> QueueCounters {
        self.decoder_queue
    }

    #[must_use]
    pub const fn ui_queue(&self) -> QueueCounters {
        self.ui_queue
    }

    #[must_use]
    pub const fn ui_frames_consumed(&self) -> u64 {
        self.ui_frames_consumed
    }

    /// Distinct pictures submitted to the presenter. Idle re-presents of an
    /// already-submitted picture are not counted here.
    #[must_use]
    pub const fn new_frames_present_submitted(&self) -> u64 {
        self.new_frames_present_submitted
    }

    /// Re-submissions of the picture already on screen.
    #[must_use]
    pub const fn repeat_present_submissions(&self) -> u64 {
        self.repeat_present_submissions
    }

    /// Frames the window consumed and then discarded without submitting.
    #[must_use]
    pub const fn pending_frames_replaced(&self) -> u64 {
        self.pending_frames_replaced
    }

    /// Pictures decoded but never submitted to the presenter, by any route:
    /// dropped by either queue, or consumed and replaced.
    ///
    /// Derived rather than counted, so it can never disagree with the
    /// counters it is derived from.
    #[must_use]
    pub const fn frames_never_presented(&self) -> u64 {
        self.decoded_frames
            .saturating_sub(self.new_frames_present_submitted)
    }

    #[must_use]
    pub const fn decoder_queue_wait(&self) -> &Histogram {
        &self.decoder_queue_wait
    }

    #[must_use]
    pub const fn ui_queue_wait(&self) -> &Histogram {
        &self.ui_queue_wait
    }

    #[must_use]
    pub const fn decoded_to_ui_consume(&self) -> &Histogram {
        &self.decoded_to_ui_consume
    }

    #[must_use]
    pub const fn decoded_to_present_submit(&self) -> &Histogram {
        &self.decoded_to_present_submit
    }

    /// The four spans, each as a [`SpanValue`] so an unexercised one renders
    /// as `no-samples` rather than as a zero.
    #[must_use]
    pub fn spans(&self) -> [(&'static str, SpanValue); 4] {
        [
            (
                "decoder_queue_wait",
                SpanValue::from_histogram(&self.decoder_queue_wait),
            ),
            (
                "ui_queue_wait",
                SpanValue::from_histogram(&self.ui_queue_wait),
            ),
            (
                "decoded_to_ui_consume",
                SpanValue::from_histogram(&self.decoded_to_ui_consume),
            ),
            (
                "decoded_to_present_submit",
                SpanValue::from_histogram(&self.decoded_to_present_submit),
            ),
        ]
    }

    /// The one fact worth showing live: how many decoded pictures actually
    /// reached the presenter. A stream that looks smooth in the span
    /// histograms and shows `shown 300/900` here is dropping two frames in
    /// three, and the histograms would never say so.
    #[must_use]
    pub fn overlay_fragment(&self) -> String {
        format!(
            "shown {}/{}",
            self.new_frames_present_submitted, self.decoded_frames
        )
    }

    /// A report whose counter lines and span lines describe the same
    /// population, so a healthy-looking span cannot hide a discarded one.
    #[must_use]
    pub fn report(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(8);
        lines.push(format!(
            "decoded_frames={} never_presented={}",
            self.decoded_frames,
            self.frames_never_presented()
        ));
        lines.push(self.decoder_queue.render("decoder_queue"));
        lines.push(self.ui_queue.render("ui_queue      "));
        lines.push(format!(
            "ui_frames_consumed={} new_frames_present_submitted={} repeat_present_submissions={} pending_frames_replaced={}",
            self.ui_frames_consumed,
            self.new_frames_present_submitted,
            self.repeat_present_submissions,
            self.pending_frames_replaced
        ));
        for (name, value) in self.spans() {
            lines.push(format!("{name:<26} {}", value.render()));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodedFrame, DecodedFrameSeq, FrameAgeRecord, FrameOffer, PENDING_CAPACITY};
    use crate::latency::{Client, SpanValue, Stamp};
    use std::time::{Duration, Instant};

    fn at(base: Instant, millis: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(millis))
    }

    fn frame(seq: DecodedFrameSeq, base: Instant, decoded_ms: u64) -> DecodedFrame {
        DecodedFrame::new(seq, at(base, decoded_ms), 4, 2, vec![0; 8])
    }

    #[test]
    fn sequence_numbers_are_assigned_in_order_and_counted() {
        let mut record = FrameAgeRecord::new();
        assert_eq!(record.frame_decoded(), DecodedFrameSeq::FIRST);
        assert_eq!(record.frame_decoded().get(), 1);
        assert_eq!(record.frame_decoded().get(), 2);
        assert_eq!(record.decoded_frames(), 3);
    }

    /// A frame that never reaches the presenter leaves no span sample, so
    /// the counters are the only place its loss is visible.
    #[test]
    fn a_frame_dropped_by_the_decoder_queue_is_counted_and_never_presented() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();

        let kept = record.frame_decoded();
        let lost = record.frame_decoded();
        assert_ne!(kept, lost);

        record.decoder_queue_offer(FrameOffer::Enqueued);
        record.decoder_queue_offer(FrameOffer::DroppedNewest);

        let kept_frame = frame(kept, base, 0);
        record.decoder_queue_consumed(&kept_frame, at(base, 2));
        record.ui_queue_offer(FrameOffer::Enqueued);
        let mut kept_frame = kept_frame;
        kept_frame.entering_ui_queue(at(base, 2));
        record.ui_queue_consumed(&kept_frame, at(base, 5));
        record.present_submitted(&kept_frame, at(base, 6));

        assert_eq!(record.decoded_frames(), 2);
        assert_eq!(record.decoder_queue().enqueued, 1);
        assert_eq!(record.decoder_queue().dropped_newest, 1);
        assert_eq!(record.new_frames_present_submitted(), 1);
        assert_eq!(record.frames_never_presented(), 1);
        // The span histogram looks perfectly healthy for the frame that
        // survived. That is exactly why the counters have to be read with it.
        assert_eq!(record.decoded_to_present_submit().count(), 1);
    }

    #[test]
    fn an_unexercised_span_reads_as_no_samples_not_zero() {
        let record = FrameAgeRecord::new();
        for (name, value) in record.spans() {
            assert_eq!(value, SpanValue::NoSamples { invalid: 0 }, "{name}");
            assert_eq!(value.render(), "no-samples", "{name}");
        }
    }

    /// The window re-presents its last buffer while the stream is idle.
    /// Counting those would report frames the host never sent.
    #[test]
    fn re_presenting_the_same_picture_is_not_a_new_frame() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let seq = record.frame_decoded();
        let picture = frame(seq, base, 0);
        record.ui_queue_consumed(&picture, at(base, 4));

        record.present_submitted(&picture, at(base, 5));
        for repeat in 1..=10 {
            record.present_submitted(&picture, at(base, 5 + repeat * 16));
        }

        assert_eq!(record.new_frames_present_submitted(), 1);
        assert_eq!(record.repeat_present_submissions(), 10);
        // One sample, not eleven: the repeats would have dragged the tail of
        // a span that only happened once.
        assert_eq!(record.decoded_to_present_submit().count(), 1);
        assert_eq!(record.decoded_to_present_submit().max_us(), 5_000);
    }

    /// Consuming a frame and then consuming another before submitting the
    /// first means the first was never shown.
    #[test]
    fn a_consumed_frame_replaced_before_submission_is_counted_as_replaced() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let first = record.frame_decoded();
        let second = record.frame_decoded();

        let first_frame = frame(first, base, 0);
        let second_frame = frame(second, base, 16);
        record.ui_queue_consumed(&first_frame, at(base, 4));
        record.ui_queue_consumed(&second_frame, at(base, 20));
        record.present_submitted(&second_frame, at(base, 21));

        assert_eq!(record.ui_frames_consumed(), 2);
        assert_eq!(record.new_frames_present_submitted(), 1);
        assert_eq!(record.pending_frames_replaced(), 1);
        assert_eq!(record.frames_never_presented(), 1);
    }

    #[test]
    fn frames_still_waiting_when_the_session_ends_were_never_shown() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        for index in 0..3 {
            let seq = record.frame_decoded();
            record.ui_queue_consumed(&frame(seq, base, index * 16), at(base, index * 16 + 2));
        }
        record.session_ended();

        assert_eq!(record.pending_frames_replaced(), 3);
        assert_eq!(record.new_frames_present_submitted(), 0);
        assert_eq!(record.frames_never_presented(), 3);
    }

    /// The pending list is bounded, so a window that stops presenting
    /// entirely cannot grow it without limit.
    #[test]
    fn the_pending_list_is_bounded() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        for index in 0..(PENDING_CAPACITY as u64 * 4) {
            let seq = record.frame_decoded();
            record.ui_queue_consumed(&frame(seq, base, index), at(base, index));
        }
        assert_eq!(
            record.pending_frames_replaced(),
            PENDING_CAPACITY as u64 * 3
        );
    }

    /// A frame measured before it ever reached the window queue must not
    /// report a queue wait of zero.
    #[test]
    fn a_frame_with_no_ui_queue_stamp_records_no_ui_queue_wait() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let seq = record.frame_decoded();
        let picture = frame(seq, base, 0);
        assert!(picture.ui_queued_at().is_none());
        record.ui_queue_consumed(&picture, at(base, 9));

        assert_eq!(record.ui_queue_wait().count(), 0);
        assert_eq!(
            SpanValue::from_histogram(record.ui_queue_wait()),
            SpanValue::NoSamples { invalid: 0 }
        );
        // The decode-relative span is still measurable and is recorded.
        assert_eq!(record.decoded_to_ui_consume().count(), 1);
    }

    #[test]
    fn each_hop_is_measured_from_the_stamp_the_producer_left() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let seq = record.frame_decoded();
        let mut picture = frame(seq, base, 0);

        record.decoder_queue_consumed(&picture, at(base, 3));
        picture.entering_ui_queue(at(base, 4));
        record.ui_queue_consumed(&picture, at(base, 11));
        record.present_submitted(&picture, at(base, 13));

        assert_eq!(record.decoder_queue_wait().max_us(), 3_000);
        assert_eq!(record.ui_queue_wait().max_us(), 7_000);
        assert_eq!(record.decoded_to_ui_consume().max_us(), 11_000);
        assert_eq!(record.decoded_to_present_submit().max_us(), 13_000);
    }

    #[test]
    fn the_report_states_the_population_alongside_the_spans() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let seq = record.frame_decoded();
        record.frame_decoded();
        record.decoder_queue_offer(FrameOffer::Enqueued);
        record.decoder_queue_offer(FrameOffer::DroppedNewest);
        let picture = frame(seq, base, 0);
        record.ui_queue_offer(FrameOffer::Enqueued);
        record.ui_queue_consumed(&picture, at(base, 5));
        record.present_submitted(&picture, at(base, 6));

        let report = record.report().join("\n");
        assert!(report.contains("decoded_frames=2"), "{report}");
        assert!(report.contains("never_presented=1"), "{report}");
        assert!(report.contains("dropped_newest=1"), "{report}");
        assert!(
            report.contains("new_frames_present_submitted=1"),
            "{report}"
        );
        // Named for the act, not for the outcome: nothing here has seen a
        // photon and the report must not suggest otherwise.
        assert!(!report.contains("photon"), "{report}");
        assert!(report.contains("decoded_to_present_submit"), "{report}");
    }

    #[test]
    fn the_overlay_fragment_shows_presented_against_decoded() {
        let base = Instant::now();
        let mut record = FrameAgeRecord::new();
        let seq = record.frame_decoded();
        record.frame_decoded();
        record.frame_decoded();
        let picture = frame(seq, base, 0);
        record.ui_queue_consumed(&picture, at(base, 4));
        record.present_submitted(&picture, at(base, 5));
        assert_eq!(record.overlay_fragment(), "shown 1/3");
    }

    #[test]
    fn the_offer_outcome_says_which_frames_are_lost_and_when_to_stop() {
        assert!(FrameOffer::Enqueued.delivered());
        assert!(!FrameOffer::DroppedNewest.delivered());
        assert!(!FrameOffer::Closed.delivered());
        // A dropped frame is not a reason to tear down the session.
        assert!(!FrameOffer::DroppedNewest.should_stop());
        assert!(FrameOffer::Closed.should_stop());
    }

    #[test]
    fn queue_counters_total_what_was_offered() {
        let mut record = FrameAgeRecord::new();
        record.ui_queue_offer(FrameOffer::Enqueued);
        record.ui_queue_offer(FrameOffer::Enqueued);
        record.ui_queue_offer(FrameOffer::DroppedNewest);
        record.ui_queue_offer(FrameOffer::Closed);
        assert_eq!(record.ui_queue().offered(), 4);
        assert_eq!(record.ui_queue().enqueued, 2);
        assert_eq!(record.ui_queue().dropped_newest, 1);
        assert_eq!(record.ui_queue().closed, 1);
        assert_eq!(record.decoder_queue().offered(), 0);
    }
}
