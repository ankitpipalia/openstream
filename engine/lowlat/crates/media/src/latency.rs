//! Stage timing for one frame's journey, and the rules that keep it honest.
//!
//! # Why the types look like this
//!
//! The measurement this replaces compared a clock on the host with a clock on
//! the client, and could not be trusted to better than the synchronisation
//! between them -- which drifted by ~35 ms between two runs of identical
//! code and produced a 165 ms result that never reproduced. See
//! `docs/research/parsec-display-input-latency-gap.md`.
//!
//! So the rule is: **never subtract a host timestamp from a client one.**
//! Here that is not a convention to remember, it is a type error.
//! [`Stamp<Host>`] and [`Stamp<Client>`] are different types, and
//! [`Stamp::since`] only accepts its own domain. A cross-domain span cannot
//! be written by accident.
//!
//! Everything measured here is therefore *local*: host-local spans say
//! whether capture and encode are slow, client-local spans say whether
//! decode and presentation are, and neither needs a shared clock. One-way
//! network time is deliberately absent; the honest way to get an end-to-end
//! number is [`interaction`], which runs entirely on the client's clock.
//!
//! # Two stages that must not be named optimistically
//!
//! Two measurements cannot mean what their obvious name would suggest, and
//! the enum spells that out rather than letting a reader assume:
//!
//! - [`HostStage::FrameEnteredOpenStream`] is not "capture complete". On a
//!   Wayland host the frame has already crossed the portal, PipeWire, a
//!   GStreamer bridge and a pipe before OpenStream sees it. That span is
//!   outside this clock domain entirely and shows up nowhere in these
//!   numbers.
//! - [`HostStage::AccessUnitBoundaryKnown`] is not "encoder finished the
//!   frame". An Annex-B byte stream only reveals a frame's end when the next
//!   frame's delimiter arrives, so this is the moment the boundary became
//!   *knowable*, which trails encoder completion by up to a frame interval.

use std::fmt;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// A machine whose clock readings may be compared with one another.
pub trait ClockDomain: Copy + fmt::Debug {
    /// Name used in diagnostics.
    const NAME: &'static str;
}

/// The machine doing capture and encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host;
impl ClockDomain for Host {
    const NAME: &'static str = "host";
}

/// The machine doing decode and presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client;
impl ClockDomain for Client {
    const NAME: &'static str = "client";
}

/// A monotonic instant, tagged with the machine that read it.
///
/// The tag is the whole point: two stamps can only be subtracted when they
/// came from the same clock, so a host-to-client "span" does not compile.
#[derive(Debug, Clone, Copy)]
pub struct Stamp<D: ClockDomain> {
    at: Instant,
    domain: PhantomData<D>,
}

impl<D: ClockDomain> Stamp<D> {
    /// Read this machine's monotonic clock.
    #[must_use]
    pub fn now() -> Self {
        Self {
            at: Instant::now(),
            domain: PhantomData,
        }
    }

    /// Build a stamp from an `Instant` already taken on this machine.
    #[must_use]
    pub const fn from_instant(at: Instant) -> Self {
        Self {
            at,
            domain: PhantomData,
        }
    }

    /// Time from `earlier` to this stamp, saturating at zero.
    ///
    /// Only same-domain stamps can be passed, so the result is always a
    /// duration one clock actually measured:
    ///
    /// ```
    /// use openstream_media::latency::{Host, Stamp};
    /// let start: Stamp<Host> = Stamp::now();
    /// let end: Stamp<Host> = Stamp::now();
    /// let _elapsed = end.since(start);
    /// ```
    ///
    /// Mixing clocks does not compile. This is the mistake that produced a
    /// 165 ms result which never reproduced, so it is enforced by the type
    /// system rather than by remembering:
    ///
    /// ```compile_fail
    /// use openstream_media::latency::{Client, Host, Stamp};
    /// let host: Stamp<Host> = Stamp::now();
    /// let client: Stamp<Client> = Stamp::now();
    /// // error[E0308]: mismatched types -- two machines, two clocks.
    /// let _nonsense = client.since(host);
    /// ```
    #[must_use]
    pub fn since(self, earlier: Self) -> Duration {
        self.at.saturating_duration_since(earlier.at)
    }
}

/// Points in a frame's life that the host can time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostStage {
    /// The frame reached OpenStream.
    ///
    /// **Not "capture complete".** Whatever produced it -- a portal grant, a
    /// PipeWire node, a bridge, a pipe -- ran before this and is not in this
    /// clock domain. Time spent there is invisible to every span below.
    FrameEnteredOpenStream,
    /// Handed to the encoder.
    EncodeSubmitted,
    /// First encoded byte read back from the encoder.
    EncoderFirstByte,
    /// The frame's end became *knowable*.
    ///
    /// **Not "encoder finished".** An Annex-B stream marks a boundary only
    /// when the next delimiter arrives, so this trails completion by up to a
    /// frame interval. That delay is structural, not a measurement error,
    /// and it is inside the span rather than beside it.
    AccessUnitBoundaryKnown,
    /// First fragment handed to the transport.
    FirstFragmentSent,
    /// Last fragment handed to the transport.
    LastFragmentSent,
}

/// Points in a frame's life that the client can time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientStage {
    FirstFragmentReceived,
    LastFragmentReceived,
    Reassembled,
    DecoderSubmitted,
    DecodedReady,
    /// Written into the frame handoff toward the window.
    HandedToWindow,
    /// Taken by the window.
    TakenByWindow,
    PresentSubmitted,
}

impl HostStage {
    /// Every stage, in the order a frame passes through them.
    pub const ORDER: [Self; 6] = [
        Self::FrameEnteredOpenStream,
        Self::EncodeSubmitted,
        Self::EncoderFirstByte,
        Self::AccessUnitBoundaryKnown,
        Self::FirstFragmentSent,
        Self::LastFragmentSent,
    ];
}

impl ClientStage {
    /// Every stage, in the order a frame passes through them.
    pub const ORDER: [Self; 8] = [
        Self::FirstFragmentReceived,
        Self::LastFragmentReceived,
        Self::Reassembled,
        Self::DecoderSubmitted,
        Self::DecodedReady,
        Self::HandedToWindow,
        Self::TakenByWindow,
        Self::PresentSubmitted,
    ];
}

/// Upper edge of each histogram bucket, in microseconds.
///
/// Logarithmic-ish and hand-placed rather than uniform: the interesting
/// range for an interactive stream spans three orders of magnitude, and the
/// resolution that matters is fine near a frame interval and coarse out in
/// the tail where the only question is "how bad".
const BUCKET_EDGES_US: [u64; 16] = [
    100, 250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 33_000, 50_000, 75_000, 100_000, 150_000,
    250_000, 500_000, 1_000_000,
];

/// A fixed-bucket duration histogram.
///
/// Always on, so it allocates nothing and does no work per sample beyond a
/// comparison walk and an increment. Overflow past the last edge is counted
/// separately rather than clamped, so a pathological tail stays visible
/// instead of piling up in the top bucket as if it were merely slow.
#[derive(Debug, Clone, Copy)]
pub struct Histogram {
    buckets: [u64; BUCKET_EDGES_US.len()],
    overflow: u64,
    count: u64,
    total_us: u64,
    max_us: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: [0; BUCKET_EDGES_US.len()],
            overflow: 0,
            count: 0,
            total_us: 0,
            max_us: 0,
        }
    }

    /// Record one duration.
    pub fn record(&mut self, span: Duration) {
        let micros = u64::try_from(span.as_micros()).unwrap_or(u64::MAX);
        self.count = self.count.saturating_add(1);
        self.total_us = self.total_us.saturating_add(micros);
        self.max_us = self.max_us.max(micros);
        for (index, edge) in BUCKET_EDGES_US.iter().enumerate() {
            if micros <= *edge {
                self.buckets[index] = self.buckets[index].saturating_add(1);
                return;
            }
        }
        self.overflow = self.overflow.saturating_add(1);
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    #[must_use]
    pub const fn max_us(&self) -> u64 {
        self.max_us
    }

    #[must_use]
    pub fn mean_us(&self) -> Option<u64> {
        (self.count > 0).then(|| self.total_us / self.count)
    }

    /// Approximate percentile, in microseconds.
    ///
    /// The answer is a bucket's upper edge, so it is an upper bound rather
    /// than an interpolation: reporting "at most this" is honest about the
    /// resolution, where interpolating between edges would invent precision
    /// the buckets do not have. `None` when nothing has been recorded; the
    /// tail beyond the last edge reports [`Self::max_us`].
    #[must_use]
    pub fn percentile_us(&self, percentile: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let clamped = percentile.clamp(0.0, 100.0);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "count is bounded by observation and the fraction is clamped to [0,1]"
        )]
        let target = ((clamped / 100.0) * self.count as f64).ceil().max(1.0) as u64;
        let mut seen: u64 = 0;
        for (index, edge) in BUCKET_EDGES_US.iter().enumerate() {
            seen = seen.saturating_add(self.buckets[index]);
            if seen >= target {
                return Some(*edge);
            }
        }
        Some(self.max_us)
    }
}

/// How many frame timelines the opt-in trace ring retains.
///
/// Bounded because tracing must never become a memory leak on a session
/// left running for hours. At 30 fps this is about eight seconds of history,
/// which is enough to catch a stall after noticing one.
pub const TRACE_CAPACITY: usize = 256;

/// One frame's stage timings within a single clock domain.
#[derive(Debug, Clone, Copy)]
pub struct FrameTrace<S, D: ClockDomain> {
    pub frame_id: u32,
    stages: [Option<Stamp<D>>; 8],
    kinds: [Option<S>; 8],
    used: usize,
}

impl<S: Copy + PartialEq, D: ClockDomain> FrameTrace<S, D> {
    #[must_use]
    pub fn new(frame_id: u32) -> Self {
        Self {
            frame_id,
            stages: [None; 8],
            kinds: [None; 8],
            used: 0,
        }
    }

    /// Record one stage. A stage recorded twice keeps the first reading:
    /// the first time a frame reached a point is what a latency question is
    /// asking about, and a retry or a duplicate fragment should not make a
    /// frame look slower than it was.
    pub fn mark(&mut self, stage: S, at: Stamp<D>) {
        if self.stamp_of(stage).is_some() || self.used >= self.stages.len() {
            return;
        }
        self.kinds[self.used] = Some(stage);
        self.stages[self.used] = Some(at);
        self.used += 1;
    }

    #[must_use]
    pub fn stamp_of(&self, stage: S) -> Option<Stamp<D>> {
        self.kinds
            .iter()
            .position(|kind| *kind == Some(stage))
            .and_then(|index| self.stages[index])
    }

    /// Duration between two stages, when both were recorded.
    #[must_use]
    pub fn span(&self, from: S, to: S) -> Option<Duration> {
        let start = self.stamp_of(from)?;
        let end = self.stamp_of(to)?;
        Some(end.since(start))
    }
}

/// Stage timing for one clock domain: always-on aggregates, plus an
/// optional bounded ring of individual frame timelines.
///
/// The split is deliberate. Aggregates answer "is this stage slow" on every
/// session at negligible cost, and are what a health check or an overlay
/// should read. Per-frame traces answer "what happened to *that* frame",
/// which is what a stall investigation needs and what nobody should pay for
/// continuously -- so they are opt-in and bounded.
#[derive(Debug)]
pub struct StageRecorder<S: Copy + PartialEq + Ord + 'static, D: ClockDomain> {
    order: &'static [S],
    spans: Vec<Histogram>,
    frames: u64,
    tracing: bool,
    traces: std::collections::VecDeque<FrameTrace<S, D>>,
    in_flight: Option<FrameTrace<S, D>>,
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> StageRecorder<S, D> {
    /// Build a recorder over consecutive stages, aggregates only.
    #[must_use]
    pub fn new(order: &'static [S]) -> Self {
        Self {
            order,
            spans: vec![Histogram::new(); order.len().saturating_sub(1)],
            frames: 0,
            tracing: false,
            traces: std::collections::VecDeque::new(),
            in_flight: None,
        }
    }

    /// Turn the per-frame trace ring on or off. Off by default, and turning
    /// it off releases what it held.
    pub fn set_tracing(&mut self, enabled: bool) {
        self.tracing = enabled;
        if !enabled {
            self.traces.clear();
            self.traces.shrink_to_fit();
        }
    }

    #[must_use]
    pub const fn tracing(&self) -> bool {
        self.tracing
    }

    /// Begin timing a frame, retiring whichever was in flight.
    ///
    /// A frame that never finished is still worth keeping when tracing: an
    /// unfinished timeline is precisely the evidence of a stall, and
    /// discarding it would hide the case the ring exists for.
    pub fn begin(&mut self, frame_id: u32, at: Stamp<D>) {
        if let Some(previous) = self.in_flight.take() {
            self.retire(previous);
        }
        let mut trace = FrameTrace::new(frame_id);
        trace.mark(self.order[0], at);
        self.in_flight = Some(trace);
    }

    /// Record a stage for the frame in flight. Ignored when the frame id
    /// does not match, so a late fragment from an abandoned frame cannot
    /// contaminate the current one's timings.
    pub fn mark(&mut self, frame_id: u32, stage: S, at: Stamp<D>) {
        let Some(trace) = self.in_flight.as_mut() else {
            return;
        };
        if trace.frame_id != frame_id {
            return;
        }
        trace.mark(stage, at);
    }

    /// Finish the frame in flight and fold it into the aggregates.
    pub fn finish(&mut self, frame_id: u32) {
        let Some(trace) = self.in_flight.as_ref() else {
            return;
        };
        if trace.frame_id != frame_id {
            return;
        }
        let trace = self.in_flight.take().expect("checked above");
        self.retire(trace);
    }

    fn retire(&mut self, trace: FrameTrace<S, D>) {
        self.frames = self.frames.saturating_add(1);
        for (index, pair) in self.order.windows(2).enumerate() {
            if let Some(span) = trace.span(pair[0], pair[1])
                && let Some(histogram) = self.spans.get_mut(index)
            {
                histogram.record(span);
            }
        }
        if self.tracing {
            if self.traces.len() >= TRACE_CAPACITY {
                self.traces.pop_front();
            }
            self.traces.push_back(trace);
        }
    }

    /// Histogram for the span between two consecutive stages.
    #[must_use]
    pub fn span_histogram(&self, from: S, to: S) -> Option<&Histogram> {
        let index = self
            .order
            .windows(2)
            .position(|pair| pair[0] == from && pair[1] == to)?;
        self.spans.get(index)
    }

    /// Frames folded into the aggregates.
    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    /// Retained per-frame timelines, oldest first. Empty unless tracing.
    pub fn traces(&self) -> impl Iterator<Item = &FrameTrace<S, D>> {
        self.traces.iter()
    }

    /// One line per span: `stage -> stage  n=.. p50=..us p95=..us max=..us`.
    #[must_use]
    pub fn report(&self) -> Vec<String> {
        self.order
            .windows(2)
            .enumerate()
            .map(|(index, pair)| {
                let histogram = self.spans.get(index).copied().unwrap_or_default();
                let value =
                    |v: Option<u64>| v.map_or_else(|| "-".to_string(), |us| format!("{us}"));
                format!(
                    "{} {:?} -> {:?}  n={} p50={}us p95={}us p99={}us max={}us",
                    D::NAME,
                    pair[0],
                    pair[1],
                    histogram.count(),
                    value(histogram.percentile_us(50.0)),
                    value(histogram.percentile_us(95.0)),
                    value(histogram.percentile_us(99.0)),
                    histogram.max_us(),
                )
            })
            .collect()
    }
}

/// Host-side stage recorder.
pub type HostRecorder = StageRecorder<HostStage, Host>;
/// Client-side stage recorder.
pub type ClientRecorder = StageRecorder<ClientStage, Client>;

#[cfg(test)]
mod tests {
    use super::{
        Client, ClientRecorder, ClientStage, Histogram, Host, HostRecorder, HostStage, Stamp,
        TRACE_CAPACITY,
    };
    use std::time::{Duration, Instant};

    fn host_at(base: Instant, offset_ms: u64) -> Stamp<Host> {
        Stamp::from_instant(base + Duration::from_millis(offset_ms))
    }

    fn client_at(base: Instant, offset_ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(offset_ms))
    }

    /// A span is only ever a difference one clock actually measured.
    ///
    /// The cross-domain case is not tested here because it cannot be
    /// written: `Stamp<Client>::since` does not accept a `Stamp<Host>`, so
    /// the mistake that produced an unreproducible 165 ms result is a
    /// compile error rather than a review comment. The `compile_fail`
    /// doctest on `Stamp::since` pins that.
    #[test]
    fn a_span_measures_one_clock() {
        let base = Instant::now();
        assert_eq!(
            host_at(base, 40).since(host_at(base, 10)),
            Duration::from_millis(30)
        );
        // Out-of-order stamps saturate rather than wrapping into an
        // enormous duration.
        assert_eq!(host_at(base, 10).since(host_at(base, 40)), Duration::ZERO);
    }

    #[test]
    fn a_histogram_summarises_without_allocating_per_sample() {
        let mut histogram = Histogram::new();
        assert_eq!(histogram.percentile_us(50.0), None, "empty has no median");

        for _ in 0..90 {
            histogram.record(Duration::from_micros(900));
        }
        for _ in 0..10 {
            histogram.record(Duration::from_millis(120));
        }

        assert_eq!(histogram.count(), 100);
        // 90% sit in the <=1000us bucket, so the median is its upper edge.
        assert_eq!(histogram.percentile_us(50.0), Some(1_000));
        // The tail is reported at the bucket that contains it, not averaged
        // away by the bulk.
        assert_eq!(histogram.percentile_us(99.0), Some(150_000));
        assert_eq!(histogram.max_us(), 120_000);
    }

    /// A pathological sample must stay visible rather than being clamped
    /// into the top bucket as though it were merely slow.
    #[test]
    fn an_outlier_past_every_bucket_is_still_reported() {
        let mut histogram = Histogram::new();
        histogram.record(Duration::from_micros(500));
        histogram.record(Duration::from_secs(4));
        assert_eq!(histogram.max_us(), 4_000_000);
        assert_eq!(histogram.percentile_us(100.0), Some(4_000_000));
    }

    #[test]
    fn host_spans_are_aggregated_per_stage_pair() {
        let base = Instant::now();
        let mut recorder = HostRecorder::new(&HostStage::ORDER);

        for frame in 0..5_u32 {
            recorder.begin(frame, host_at(base, 0));
            recorder.mark(frame, HostStage::EncodeSubmitted, host_at(base, 2));
            recorder.mark(frame, HostStage::EncoderFirstByte, host_at(base, 6));
            recorder.mark(frame, HostStage::AccessUnitBoundaryKnown, host_at(base, 39));
            recorder.mark(frame, HostStage::FirstFragmentSent, host_at(base, 40));
            recorder.mark(frame, HostStage::LastFragmentSent, host_at(base, 43));
            recorder.finish(frame);
        }

        assert_eq!(recorder.frames(), 5);
        let encode = recorder
            .span_histogram(HostStage::EncodeSubmitted, HostStage::EncoderFirstByte)
            .expect("consecutive stages have a histogram");
        assert_eq!(encode.count(), 5);
        assert_eq!(encode.max_us(), 4_000);

        // The boundary-detection wait is its own span, so the frame interval
        // it costs is attributable instead of hidden inside "encode".
        let boundary = recorder
            .span_histogram(
                HostStage::EncoderFirstByte,
                HostStage::AccessUnitBoundaryKnown,
            )
            .expect("consecutive stages have a histogram");
        assert_eq!(boundary.max_us(), 33_000);

        // Non-consecutive pairs are not spans.
        assert!(
            recorder
                .span_histogram(
                    HostStage::FrameEnteredOpenStream,
                    HostStage::LastFragmentSent
                )
                .is_none()
        );
    }

    /// A late fragment belonging to an abandoned frame must not be folded
    /// into the current frame's timings.
    #[test]
    fn a_stale_frame_id_cannot_contaminate_the_frame_in_flight() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);

        recorder.begin(7, client_at(base, 0));
        recorder.mark(6, ClientStage::Reassembled, client_at(base, 900));
        recorder.mark(7, ClientStage::LastFragmentReceived, client_at(base, 3));
        recorder.mark(7, ClientStage::Reassembled, client_at(base, 5));
        recorder.finish(7);

        let span = recorder
            .span_histogram(ClientStage::LastFragmentReceived, ClientStage::Reassembled)
            .expect("histogram exists");
        assert_eq!(span.max_us(), 2_000, "the stale 900ms mark was ignored");
    }

    /// The first time a frame reached a stage is the answer; a repeat must
    /// not make it look slower.
    #[test]
    fn a_stage_recorded_twice_keeps_the_first_reading() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        recorder.begin(1, client_at(base, 0));
        recorder.mark(1, ClientStage::LastFragmentReceived, client_at(base, 4));
        recorder.mark(1, ClientStage::LastFragmentReceived, client_at(base, 400));
        recorder.mark(1, ClientStage::Reassembled, client_at(base, 5));
        recorder.finish(1);

        let span = recorder
            .span_histogram(ClientStage::LastFragmentReceived, ClientStage::Reassembled)
            .expect("histogram exists");
        assert_eq!(span.max_us(), 1_000);
    }

    #[test]
    fn tracing_is_off_by_default_and_bounded_when_on() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);

        recorder.begin(1, client_at(base, 0));
        recorder.finish(1);
        assert!(!recorder.tracing());
        assert_eq!(
            recorder.traces().count(),
            0,
            "tracing costs nothing when off"
        );

        recorder.set_tracing(true);
        let capacity = u32::try_from(TRACE_CAPACITY).expect("ring capacity fits a frame id");
        for frame in 0..(capacity + 50) {
            recorder.begin(frame, client_at(base, 0));
            recorder.mark(frame, ClientStage::DecodedReady, client_at(base, 3));
            recorder.finish(frame);
        }
        assert_eq!(
            recorder.traces().count(),
            TRACE_CAPACITY,
            "the ring is bounded so a long session cannot leak"
        );
        // It keeps the newest, which is what an investigation just after a
        // stall actually wants.
        let newest = recorder.traces().last().expect("ring is non-empty");
        assert_eq!(newest.frame_id, capacity + 49);

        recorder.set_tracing(false);
        assert_eq!(recorder.traces().count(), 0, "turning it off releases it");
    }

    /// A frame that never finished is evidence of a stall, so tracing keeps
    /// its partial timeline rather than discarding it.
    #[test]
    fn an_unfinished_frame_is_retired_when_the_next_one_starts() {
        let base = Instant::now();
        let mut recorder = HostRecorder::new(&HostStage::ORDER);
        recorder.set_tracing(true);

        recorder.begin(1, host_at(base, 0));
        recorder.mark(1, HostStage::EncodeSubmitted, host_at(base, 2));
        // Frame 1 never reaches the wire; frame 2 begins.
        recorder.begin(2, host_at(base, 100));
        recorder.finish(2);

        let ids: Vec<u32> = recorder.traces().map(|trace| trace.frame_id).collect();
        assert_eq!(ids, vec![1, 2], "the stalled frame is kept, not dropped");
        let stalled = recorder.traces().next().expect("frame 1 retained");
        assert!(stalled.stamp_of(HostStage::LastFragmentSent).is_none());
        assert!(stalled.stamp_of(HostStage::EncodeSubmitted).is_some());
    }

    #[test]
    fn the_report_names_its_clock_domain() {
        let base = Instant::now();
        let mut recorder = HostRecorder::new(&HostStage::ORDER);
        recorder.begin(1, host_at(base, 0));
        recorder.mark(1, HostStage::EncodeSubmitted, host_at(base, 3));
        recorder.finish(1);

        let lines = recorder.report();
        assert_eq!(lines.len(), HostStage::ORDER.len() - 1);
        assert!(lines[0].starts_with("host "), "{}", lines[0]);
        assert!(lines[0].contains("FrameEnteredOpenStream -> EncodeSubmitted"));

        let client = ClientRecorder::new(&ClientStage::ORDER);
        assert!(client.report()[0].starts_with("client "));
    }
}
