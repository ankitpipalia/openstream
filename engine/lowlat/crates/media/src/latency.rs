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

use std::collections::VecDeque;
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

    /// Upper bound on the median. See [`Self::percentile_upper_bound_us`].
    #[must_use]
    pub fn p50_upper_bound_us(&self) -> Option<u64> {
        self.percentile_upper_bound_us(50.0)
    }

    /// Upper bound on the 95th percentile.
    #[must_use]
    pub fn p95_upper_bound_us(&self) -> Option<u64> {
        self.percentile_upper_bound_us(95.0)
    }

    /// Upper bound on the 99th percentile.
    #[must_use]
    pub fn p99_upper_bound_us(&self) -> Option<u64> {
        self.percentile_upper_bound_us(99.0)
    }

    /// Upper bound on a percentile, in microseconds.
    ///
    /// The answer is a bucket's upper edge: the true value is at most this,
    /// and the name says so. Interpolating between edges would invent
    /// precision the buckets do not have, and a caller reading `p95()` would
    /// reasonably present it as an exact percentile. `None` when nothing has
    /// been recorded; the tail beyond the last edge reports
    /// [`Self::max_us`].
    #[must_use]
    pub fn percentile_upper_bound_us(&self, percentile: f64) -> Option<u64> {
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

/// How many frames may be timed at once.
///
/// A frame is several fragments, and both the link and the reassembler can
/// have two frames' worth in hand at the same time. Twice the client
/// assembler's default reorder window, so frames arriving now cannot push
/// out ones it is still holding back; bounded all the same, because a
/// timeline whose frame never completes must retire rather than accumulate,
/// and it does so as [`TraceEnd::Superseded`] once this many newer frames
/// have started.
pub const IN_FLIGHT_CAPACITY: usize = 16;

/// How many frame timelines the opt-in trace ring retains.
///
/// Bounded because tracing must never become a memory leak on a session
/// left running for hours. At 30 fps this is about eight seconds of history,
/// which is enough to catch a stall after noticing one.
pub const TRACE_CAPACITY: usize = 256;

/// Why a frame's timeline stopped.
///
/// An incomplete trace on its own says only "the frame stopped here", which
/// cannot distinguish a genuine stall from instrumentation housekeeping.
/// Recording the reason makes that difference legible without having to
/// reconstruct it from surrounding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEnd {
    /// Reached the last stage.
    Completed,
    /// A newer frame began while this one was still in flight. Common and
    /// benign at the head of a pipeline; repeated at the tail it is a stall.
    Superseded,
    /// Dropped to keep the ring bounded. Says nothing about the frame.
    TraceRingEvicted,
    /// The session ended before the frame did.
    SessionEnded,
    /// No further capture progress within the liveness deadline.
    CaptureStalled,
    /// The decoder accepted the frame and produced nothing.
    DecoderStalled,
    /// The frame was decoded and never presented.
    PresenterStalled,
}

impl TraceEnd {
    /// Whether this ending indicates the pipeline failed, as opposed to the
    /// instrumentation tidying up after itself.
    #[must_use]
    pub const fn is_stall(self) -> bool {
        matches!(
            self,
            Self::CaptureStalled | Self::DecoderStalled | Self::PresenterStalled
        )
    }
}

/// One frame's stage timings within a single clock domain.
#[derive(Debug, Clone, Copy)]
pub struct FrameTrace<S, D: ClockDomain> {
    pub frame_id: u32,
    /// Why the timeline stopped; `None` while the frame is still in flight.
    pub ended: Option<TraceEnd>,
    stages: [Option<Stamp<D>>; 8],
    kinds: [Option<S>; 8],
    used: usize,
}

impl<S: Copy + PartialEq, D: ClockDomain> FrameTrace<S, D> {
    #[must_use]
    pub fn new(frame_id: u32) -> Self {
        Self {
            frame_id,
            ended: None,
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
    observable: &'static [S],
    spans: Vec<Histogram>,
    frames: u64,
    tracing: bool,
    traces: std::collections::VecDeque<FrameTrace<S, D>>,
    in_flight: VecDeque<FrameTrace<S, D>>,
    evicted: u64,
    stalls: u64,
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> StageRecorder<S, D> {
    /// Build a recorder whose backend can observe every stage.
    #[must_use]
    pub fn new(order: &'static [S]) -> Self {
        Self::with_observable(order, order)
    }

    /// Build a recorder where the backend can observe only some stages.
    ///
    /// Spans touching an unobservable stage report
    /// [`SpanValue::NotObservable`] instead of being absent from the table,
    /// so the gap is stated rather than inferred from a missing row.
    #[must_use]
    pub fn with_observable(order: &'static [S], observable: &'static [S]) -> Self {
        Self {
            order,
            observable,
            spans: vec![Histogram::new(); order.len().saturating_sub(1)],
            frames: 0,
            tracing: false,
            traces: std::collections::VecDeque::new(),
            in_flight: VecDeque::new(),
            evicted: 0,
            stalls: 0,
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

    /// Begin timing a frame, stamping the first stage this backend can
    /// observe.
    ///
    /// Calling this again for a frame already being timed is a no-op: a
    /// frame arrives as several fragments, and restarting its timeline on
    /// each one would report only the span of its last fragment.
    ///
    /// Several frames are timed at once, up to [`IN_FLIGHT_CAPACITY`].
    /// Fragments of consecutive frames interleave on a lossy link, and the
    /// assembler holds a completed frame back while an earlier one is still
    /// missing, so a single timeline would be restarted by the next frame's
    /// first fragment and would lose every stage the held-back frame reached
    /// afterwards -- silently, as a shorter span rather than a missing one.
    ///
    /// When the window is full the oldest unfinished timeline retires as
    /// [`TraceEnd::Superseded`]. It is kept rather than dropped when
    /// tracing: an unfinished timeline is precisely the evidence of a stall.
    ///
    /// The stamp goes on the first *observable* stage, not the first stage
    /// in the order. On a backend that cannot see the earlier ones, writing
    /// `at` to the first of them would put a real timestamp on a stage that
    /// never happened at that moment -- invisible in a report, which gates
    /// on observability, and misleading in an exported trace, which does
    /// not.
    pub fn begin(&mut self, frame_id: u32, at: Stamp<D>) {
        if self
            .in_flight
            .iter()
            .any(|trace| trace.frame_id == frame_id)
        {
            return;
        }
        if self.in_flight.len() >= IN_FLIGHT_CAPACITY
            && let Some(oldest) = self.in_flight.pop_front()
        {
            self.retire(oldest, TraceEnd::Superseded);
        }
        let mut trace = FrameTrace::new(frame_id);
        trace.mark(*self.observable.first().unwrap_or(&self.order[0]), at);
        self.in_flight.push_back(trace);
    }

    /// Record a stage for a frame in flight. Ignored when no timeline is
    /// open for that frame id, so a late fragment from a frame that has
    /// already retired cannot contaminate another one's timings.
    pub fn mark(&mut self, frame_id: u32, stage: S, at: Stamp<D>) {
        if let Some(trace) = self
            .in_flight
            .iter_mut()
            .find(|trace| trace.frame_id == frame_id)
        {
            trace.mark(stage, at);
        }
    }

    /// Finish a frame in flight and fold it into the aggregates.
    pub fn finish(&mut self, frame_id: u32) {
        self.retire_frame(frame_id, TraceEnd::Completed);
    }

    /// End one frame for a reason other than completing -- a frame dropped
    /// before it ever reached the decoder, say.
    pub fn abandon_frame(&mut self, frame_id: u32, reason: TraceEnd) {
        self.retire_frame(frame_id, reason);
    }

    fn retire_frame(&mut self, frame_id: u32, reason: TraceEnd) {
        let Some(index) = self
            .in_flight
            .iter()
            .position(|trace| trace.frame_id == frame_id)
        else {
            return;
        };
        if let Some(trace) = self.in_flight.remove(index) {
            self.retire(trace, reason);
        }
    }

    /// End every frame still in flight, such as on a stall observed by a
    /// watchdog or at session shutdown. Oldest first, so retained traces
    /// stay in the order the frames arrived.
    pub fn abandon(&mut self, reason: TraceEnd) {
        while let Some(trace) = self.in_flight.pop_front() {
            self.retire(trace, reason);
        }
    }

    /// Frames currently being timed.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    fn retire(&mut self, mut trace: FrameTrace<S, D>, reason: TraceEnd) {
        trace.ended = Some(reason);
        self.frames = self.frames.saturating_add(1);
        if reason.is_stall() {
            self.stalls = self.stalls.saturating_add(1);
        }
        for (index, pair) in self.order.windows(2).enumerate() {
            if let Some(span) = trace.span(pair[0], pair[1])
                && let Some(histogram) = self.spans.get_mut(index)
            {
                histogram.record(span);
            }
        }
        if self.tracing {
            if self.traces.len() >= TRACE_CAPACITY && self.traces.pop_front().is_some() {
                // Only counted. Marking the evicted copy would be writing to
                // a value on its way out; what a reader needs is to know the
                // retained window is shorter than the session, which the
                // count says. `TraceEnd::TraceRingEvicted` exists for an
                // exporter that streams traces out rather than retaining
                // them.
                self.evicted = self.evicted.saturating_add(1);
            }
            self.traces.push_back(trace);
        }
    }

    /// What this report can say about the span between two consecutive
    /// stages: not observable here, observable but unexercised, or measured.
    #[must_use]
    pub fn span_value(&self, from: S, to: S) -> SpanValue {
        if !self.observable.contains(&from) || !self.observable.contains(&to) {
            return SpanValue::NotObservable;
        }
        let Some(histogram) = self.span_histogram(from, to) else {
            return SpanValue::NotObservable;
        };
        SpanValue::from_histogram(histogram)
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

    /// Frames whose timeline ended in a stall rather than completing.
    ///
    /// Always counted, including when tracing is off: the count is the cheap
    /// signal, the timeline is the expensive one.
    #[must_use]
    pub const fn stalls(&self) -> u64 {
        self.stalls
    }

    /// Traces dropped to keep the ring bounded. A non-zero value means the
    /// retained window is shorter than the session.
    #[must_use]
    pub const fn evicted_traces(&self) -> u64 {
        self.evicted
    }

    /// Retained per-frame timelines, oldest first. Empty unless tracing.
    pub fn traces(&self) -> impl Iterator<Item = &FrameTrace<S, D>> {
        self.traces.iter()
    }

    /// One line per span, covering every stage pair including the ones this
    /// backend cannot see.
    ///
    /// Rendering goes through [`SpanValue`], so an unobservable span reads
    /// `not-observable` and an unexercised one reads `no-samples`. Neither
    /// can be formatted as a duration by a later caller.
    #[must_use]
    pub fn report(&self) -> Vec<String> {
        self.order
            .windows(2)
            .map(|pair| {
                format!(
                    "{} {:?} -> {:?}  {}",
                    D::NAME,
                    pair[0],
                    pair[1],
                    self.span_value(pair[0], pair[1]).render()
                )
            })
            .collect()
    }
}

/// A stage recorder that prints its table however the session ends.
///
/// A session loop leaves by `?` from a dozen places -- a transport error, a
/// decoder that died, a terminal configuration fault. A report written after
/// the loop is printed only on the paths that return normally, which are the
/// least interesting ones; a run that ended badly is exactly the run whose
/// stage table someone wants. Frames still open when it ends retire as
/// [`TraceEnd::SessionEnded`] rather than staying in flight, so they are not
/// later mistaken for evidence of a stall.
///
/// Derefs to the recorder, so it is used exactly like one.
#[derive(Debug)]
pub struct ReportOnDrop<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> {
    recorder: StageRecorder<S, D>,
    note: Option<&'static str>,
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> ReportOnDrop<S, D> {
    /// Wrap a recorder, with the sentence naming what this backend cannot
    /// see -- from [`HostObservability::unobserved_note`] or
    /// [`ClientObservability::unobserved_note`].
    #[must_use]
    pub const fn new(recorder: StageRecorder<S, D>, note: Option<&'static str>) -> Self {
        Self { recorder, note }
    }

    /// The lines this would print, without printing them. Separated so the
    /// content can be tested without capturing stderr.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        if self.recorder.frames() == 0 {
            return Vec::new();
        }
        let mut lines = self.recorder.report();
        lines.push(format!(
            "{} frames={} stalls={} in_flight_at_end={}",
            D::NAME,
            self.recorder.frames(),
            self.recorder.stalls(),
            self.recorder.in_flight(),
        ));
        if let Some(note) = self.note {
            lines.push(format!("{} note: {note}", D::NAME));
        }
        lines
    }
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> std::ops::Deref
    for ReportOnDrop<S, D>
{
    type Target = StageRecorder<S, D>;

    fn deref(&self) -> &Self::Target {
        &self.recorder
    }
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> std::ops::DerefMut
    for ReportOnDrop<S, D>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.recorder
    }
}

impl<S: Copy + PartialEq + Ord + fmt::Debug + 'static, D: ClockDomain> Drop for ReportOnDrop<S, D> {
    fn drop(&mut self) {
        self.recorder.abandon(TraceEnd::SessionEnded);
        for line in self.lines() {
            eprintln!("OpenStream stage {line}");
        }
    }
}

/// Host-side stage recorder.
pub type HostRecorder = StageRecorder<HostStage, Host>;

impl HostRecorder {
    /// Build a host recorder that claims only what this backend can see.
    #[must_use]
    pub fn for_backend(observability: HostObservability) -> Self {
        Self::with_observable(&HostStage::ORDER, observability.observable_stages())
    }
}
/// Client-side stage recorder.
pub type ClientRecorder = StageRecorder<ClientStage, Client>;

impl ClientRecorder {
    /// Build a recorder that only times what this client can attribute to a
    /// host frame id.
    #[must_use]
    pub fn for_decoder(observability: ClientObservability) -> Self {
        Self::with_observable(&ClientStage::ORDER, observability.observable_stages())
    }
}

/// How far a host frame id survives on this client.
///
/// The client's stage recorder is keyed by the frame id in the fragment
/// header, and that identity does not come back out of an external decoder.
/// FFmpeg is handed access units and returns raw pictures; it may drop a
/// damaged one, reorder, or restart its output after a keyframe request, and
/// it reports none of that per picture. Anything the client stamps after the
/// decoder therefore belongs to a picture it cannot name, so attaching it to
/// the frame id that went in would invent a correspondence rather than
/// measure one.
///
/// The stages past that boundary are still enumerated in [`ClientStage`],
/// because the shape of the path is worth stating, and they report
/// `not-observable` rather than a number. What actually happens there is
/// measured by [`crate::frame_age`], which keys on a sequence number the
/// client assigns to the pictures it receives -- an identity it can prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientObservability {
    /// An external decoder process. Frame identity ends at submission.
    ExternalDecoder,
    /// An in-process decoder that returns the identity it was given, so
    /// every stage carries the same frame id.
    Full,
}

impl ClientObservability {
    /// The last stage this client can attribute to a host frame id.
    #[must_use]
    pub const fn last_observable_stage(self) -> ClientStage {
        match self {
            Self::ExternalDecoder => ClientStage::DecoderSubmitted,
            Self::Full => ClientStage::PresentSubmitted,
        }
    }

    /// Stages this client times, in order.
    #[must_use]
    pub fn observable_stages(self) -> &'static [ClientStage] {
        match self {
            Self::ExternalDecoder => &[
                ClientStage::FirstFragmentReceived,
                ClientStage::LastFragmentReceived,
                ClientStage::Reassembled,
                ClientStage::DecoderSubmitted,
            ],
            Self::Full => &ClientStage::ORDER,
        }
    }

    /// A sentence for a report, naming what is missing and where to look
    /// for it instead.
    #[must_use]
    pub const fn unobserved_note(self) -> Option<&'static str> {
        match self {
            Self::ExternalDecoder => Some(
                "an external decoder does not return the frame id it was given;                  everything after submission is measured by sequence number in                  the frame-age record, not reported as zero here",
            ),
            Self::Full => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Client, ClientRecorder, ClientStage, Histogram, Host, HostRecorder, HostStage,
        IN_FLIGHT_CAPACITY, Stamp, TRACE_CAPACITY, TraceEnd,
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
        assert_eq!(histogram.p50_upper_bound_us(), None, "empty has no median");

        for _ in 0..90 {
            histogram.record(Duration::from_micros(900));
        }
        for _ in 0..10 {
            histogram.record(Duration::from_millis(120));
        }

        assert_eq!(histogram.count(), 100);
        // 90% sit in the <=1000us bucket, so the median is its upper edge.
        assert_eq!(histogram.p50_upper_bound_us(), Some(1_000));
        // The tail is reported at the bucket that contains it, not averaged
        // away by the bulk.
        assert_eq!(histogram.p99_upper_bound_us(), Some(150_000));
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
        assert_eq!(histogram.percentile_upper_bound_us(100.0), Some(4_000_000));
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
    /// A frame that never finishes is retired once the in-flight window
    /// has moved past it, with its partial timeline intact.
    #[test]
    fn an_unfinished_frame_is_retired_when_the_window_moves_past_it() {
        let base = Instant::now();
        let mut recorder = HostRecorder::new(&HostStage::ORDER);
        recorder.set_tracing(true);

        recorder.begin(1, host_at(base, 0));
        recorder.mark(1, HostStage::EncodeSubmitted, host_at(base, 2));
        // Frame 1 never reaches the wire. It stays in flight while the
        // window has room, because a later fragment of it could still
        // arrive; it retires only once enough newer frames have started.
        let capacity = u32::try_from(IN_FLIGHT_CAPACITY).expect("capacity fits a frame id");
        for frame in 2..=capacity {
            recorder.begin(frame, host_at(base, u64::from(frame)));
        }
        assert_eq!(recorder.traces().count(), 0, "frame 1 is still open");

        recorder.begin(capacity + 1, host_at(base, 100));

        let ids: Vec<u32> = recorder.traces().map(|trace| trace.frame_id).collect();
        assert_eq!(ids, vec![1], "the stalled frame is kept, not dropped");
        let stalled = recorder.traces().next().expect("frame 1 retained");
        assert_eq!(stalled.ended, Some(TraceEnd::Superseded));
        assert!(stalled.stamp_of(HostStage::LastFragmentSent).is_none());
        assert!(stalled.stamp_of(HostStage::EncodeSubmitted).is_some());
    }

    /// The reason the recorder times more than one frame at a time.
    ///
    /// A frame is several fragments, and the fragments of two consecutive
    /// frames interleave. With a single timeline, frame 1's first fragment
    /// would be superseded by frame 2's, and frame 1's remaining stages
    /// would be silently discarded -- producing a *shorter* span for the
    /// frames that did complete rather than an obviously missing one.
    #[test]
    fn interleaved_fragments_do_not_destroy_each_other_s_timelines() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        recorder.set_tracing(true);

        recorder.begin(1, client_at(base, 0));
        recorder.begin(2, client_at(base, 1));
        // Frame 1's remaining fragments arrive after frame 2 has started.
        recorder.mark(1, ClientStage::LastFragmentReceived, client_at(base, 4));
        recorder.mark(2, ClientStage::LastFragmentReceived, client_at(base, 6));
        // ...and the assembler releases them in order.
        recorder.mark(1, ClientStage::Reassembled, client_at(base, 7));
        recorder.finish(1);
        recorder.mark(2, ClientStage::Reassembled, client_at(base, 8));
        recorder.finish(2);

        let ends: Vec<(u32, Option<TraceEnd>)> = recorder
            .traces()
            .map(|trace| (trace.frame_id, trace.ended))
            .collect();
        assert_eq!(
            ends,
            vec![
                (1, Some(TraceEnd::Completed)),
                (2, Some(TraceEnd::Completed))
            ]
        );
        let span = recorder
            .span_histogram(
                ClientStage::FirstFragmentReceived,
                ClientStage::LastFragmentReceived,
            )
            .expect("histogram exists");
        assert_eq!(span.count(), 2, "both frames measured, neither discarded");
        assert_eq!(span.max_us(), 5_000);
        assert_eq!(recorder.in_flight(), 0);
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

#[cfg(test)]
mod trace_end_tests {
    use super::{
        Client, ClientRecorder, ClientStage, IN_FLIGHT_CAPACITY, Stamp, TRACE_CAPACITY, TraceEnd,
    };
    use std::time::{Duration, Instant};

    fn at(base: Instant, ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    /// An incomplete timeline must say why it stopped. "The frame stopped
    /// here" cannot distinguish a pipeline stall from the instrumentation
    /// tidying up, and those call for opposite responses.
    #[test]
    fn a_timeline_records_why_it_ended() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        recorder.set_tracing(true);

        // Completed normally.
        recorder.begin(1, at(base, 0));
        recorder.finish(1);

        // Superseded: frame 2 never completes and the in-flight window
        // eventually moves past it.
        recorder.begin(2, at(base, 10));
        let capacity = u32::try_from(IN_FLIGHT_CAPACITY).expect("capacity fits a frame id");
        for frame in 3..=(capacity + 2) {
            recorder.begin(frame, at(base, 20));
        }
        recorder.finish(3);

        // Abandoned by a watchdog: every open timeline ends, oldest first.
        recorder.abandon(TraceEnd::DecoderStalled);

        let ends: Vec<(u32, Option<TraceEnd>)> = recorder
            .traces()
            .map(|trace| (trace.frame_id, trace.ended))
            .collect();
        let mut expected = vec![
            (1, Some(TraceEnd::Completed)),
            (2, Some(TraceEnd::Superseded)),
            (3, Some(TraceEnd::Completed)),
        ];
        expected.extend((4..=(capacity + 2)).map(|frame| (frame, Some(TraceEnd::DecoderStalled))));
        assert_eq!(ends, expected);
    }

    /// One frame can end early without disturbing the others in flight.
    #[test]
    fn abandoning_one_frame_leaves_the_rest_timing() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        recorder.set_tracing(true);

        recorder.begin(1, at(base, 0));
        recorder.begin(2, at(base, 1));
        recorder.begin(3, at(base, 2));
        // Frame 2 is discarded while the client waits for a keyframe.
        recorder.abandon_frame(2, TraceEnd::Superseded);
        assert_eq!(recorder.in_flight(), 2);

        recorder.mark(3, ClientStage::Reassembled, at(base, 5));
        recorder.finish(3);
        recorder.finish(1);

        let ends: Vec<(u32, Option<TraceEnd>)> = recorder
            .traces()
            .map(|trace| (trace.frame_id, trace.ended))
            .collect();
        assert_eq!(
            ends,
            vec![
                (2, Some(TraceEnd::Superseded)),
                (3, Some(TraceEnd::Completed)),
                (1, Some(TraceEnd::Completed)),
            ]
        );
    }

    /// Housekeeping is not a stall, and a stall is not housekeeping.
    #[test]
    fn only_real_stalls_count_as_stalls() {
        assert!(!TraceEnd::Completed.is_stall());
        assert!(!TraceEnd::Superseded.is_stall());
        assert!(!TraceEnd::TraceRingEvicted.is_stall());
        assert!(!TraceEnd::SessionEnded.is_stall());
        assert!(TraceEnd::CaptureStalled.is_stall());
        assert!(TraceEnd::DecoderStalled.is_stall());
        assert!(TraceEnd::PresenterStalled.is_stall());
    }

    /// The stall count is always on. Tracing is the expensive half; knowing
    /// that something stalled is the half every session should pay for.
    #[test]
    fn stalls_are_counted_even_with_tracing_off() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        assert!(!recorder.tracing());

        recorder.begin(1, at(base, 0));
        recorder.abandon(TraceEnd::PresenterStalled);
        recorder.begin(2, at(base, 5));
        recorder.finish(2);

        assert_eq!(recorder.stalls(), 1);
        assert_eq!(recorder.frames(), 2);
        assert_eq!(recorder.traces().count(), 0, "still no traces retained");
    }

    /// A non-zero eviction count is how a reader knows the retained window
    /// is shorter than the session, rather than silently seeing a partial
    /// history.
    #[test]
    fn evictions_are_counted_so_a_truncated_history_is_visible() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::new(&ClientStage::ORDER);
        recorder.set_tracing(true);
        let capacity = u32::try_from(TRACE_CAPACITY).expect("capacity fits a frame id");

        for frame in 0..capacity {
            recorder.begin(frame, at(base, 0));
            recorder.finish(frame);
        }
        assert_eq!(recorder.evicted_traces(), 0, "nothing dropped yet");

        for frame in capacity..(capacity + 10) {
            recorder.begin(frame, at(base, 0));
            recorder.finish(frame);
        }
        assert_eq!(recorder.evicted_traces(), 10);
        assert_eq!(recorder.traces().count(), TRACE_CAPACITY);
    }
}

/// What a report can say about one span.
///
/// Three outcomes, kept apart on purpose. A backend that cannot see a stage
/// has no number; a stage that has been seen but not yet exercised has no
/// samples; and a measured stage has bucket-edge bounds. Collapsing the
/// first two into "0" or "N/A" is how an unmeasured hole becomes a claim
/// that something was instant, which is the error this whole module exists
/// to prevent. A formatter has to handle all three by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanValue {
    /// This backend cannot observe one or both endpoints. The elapsed time
    /// is real and unknown; it is emphatically not zero.
    NotObservable,
    /// Observable, but no frame has crossed it yet.
    NoSamples,
    /// Measured. Percentiles are upper bounds; see [`Histogram`].
    Measured {
        count: u64,
        p50_upper_us: u64,
        p95_upper_us: u64,
        p99_upper_us: u64,
        max_us: u64,
        mean_us: u64,
    },
}

impl SpanValue {
    /// Read a histogram of an *observable* span.
    ///
    /// An empty histogram is [`Self::NoSamples`], never a zero. Callers that
    /// know the span is unobservable must return [`Self::NotObservable`]
    /// themselves: a histogram cannot tell "nothing has crossed this yet"
    /// apart from "this endpoint does not exist on this backend", and
    /// guessing would turn a structural hole into a transient one.
    #[must_use]
    pub fn from_histogram(histogram: &Histogram) -> Self {
        if histogram.count() == 0 {
            return Self::NoSamples;
        }
        Self::Measured {
            count: histogram.count(),
            p50_upper_us: histogram.p50_upper_bound_us().unwrap_or_default(),
            p95_upper_us: histogram.p95_upper_bound_us().unwrap_or_default(),
            p99_upper_us: histogram.p99_upper_bound_us().unwrap_or_default(),
            max_us: histogram.max_us(),
            mean_us: histogram.mean_us().unwrap_or_default(),
        }
    }

    /// Render for a table, never as a number that could be mistaken for a
    /// measurement.
    #[must_use]
    pub fn render(self) -> String {
        match self {
            Self::NotObservable => "not-observable".to_string(),
            Self::NoSamples => "no-samples".to_string(),
            Self::Measured {
                count,
                p50_upper_us,
                p95_upper_us,
                p99_upper_us,
                max_us,
                ..
            } => {
                let mut line = String::with_capacity(72);
                line.push_str(&format!("n={count}"));
                line.push_str(&format!(" p50<={p50_upper_us}us"));
                line.push_str(&format!(" p95<={p95_upper_us}us"));
                line.push_str(&format!(" p99<={p99_upper_us}us"));
                line.push_str(&format!(" max={max_us}us"));
                line
            }
        }
    }

    /// Whether a number is present at all.
    #[must_use]
    pub const fn is_measured(self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

/// A point in the pipeline whose forward progress is worth watching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Milestone {
    FrameEntered,
    AccessUnitBoundary,
    PacketSent,
    PacketReceived,
    FrameDecoded,
    FramePresented,
}

impl Milestone {
    pub const ORDER: [Self; 6] = [
        Self::FrameEntered,
        Self::AccessUnitBoundary,
        Self::PacketSent,
        Self::PacketReceived,
        Self::FrameDecoded,
        Self::FramePresented,
    ];
}

/// Always-on forward-progress counters, one per milestone.
///
/// This exists because the trace ring cannot help in the case that matters
/// most. The ring is indexed by frame, so a pipeline that has stopped
/// producing frames produces no further evidence -- the history freezes at
/// whatever was happening before the stall and then says nothing, for as
/// long as the stall lasts.
///
/// These counters answer the question the ring cannot: *is anything still
/// moving, and where did it stop moving?* They are also the concrete form of
/// the rule that a process being alive, a socket being open, a portal grant
/// being held and a PipeWire node reporting `running` are all consistent
/// with a completely dead capture:
///
/// > liveness is frame progress, not the health of the things that are
/// > supposed to produce frames.
///
/// Costs one counter increment and one clock read per event, so it stays on
/// in production.
#[derive(Debug, Clone)]
pub struct Liveness<D: ClockDomain> {
    counts: [u64; Milestone::ORDER.len()],
    last: [Option<Stamp<D>>; Milestone::ORDER.len()],
    last_id: [Option<u32>; Milestone::ORDER.len()],
    /// When this milestone last moved to a *different* frame.
    last_advance: [Option<Stamp<D>>; Milestone::ORDER.len()],
    started: Stamp<D>,
}

impl<D: ClockDomain> Liveness<D> {
    #[must_use]
    pub fn new(now: Stamp<D>) -> Self {
        Self {
            counts: [0; Milestone::ORDER.len()],
            last: [None; Milestone::ORDER.len()],
            last_id: [None; Milestone::ORDER.len()],
            last_advance: [None; Milestone::ORDER.len()],
            started: now,
        }
    }

    fn index(milestone: Milestone) -> usize {
        Milestone::ORDER
            .iter()
            .position(|candidate| *candidate == milestone)
            .expect("every milestone is in ORDER")
    }

    /// Record that `frame_id` passed this milestone.
    ///
    /// Health is measured against the frame *changing*, not against this
    /// being called. A layer that replays a stale frame keeps its timestamp
    /// fresh while the pipeline has stopped advancing, and a timestamp-only
    /// check would call that healthy -- which is the same family of mistake
    /// as trusting a live process or an open socket. So the same id arriving
    /// again is counted, and is not progress.
    pub fn advance(&mut self, milestone: Milestone, frame_id: u32, at: Stamp<D>) {
        let index = Self::index(milestone);
        self.counts[index] = self.counts[index].saturating_add(1);
        self.last[index] = Some(at);
        if self.last_id[index] != Some(frame_id) {
            self.last_id[index] = Some(frame_id);
            self.last_advance[index] = Some(at);
        }
    }

    /// The most recent frame id seen at this milestone.
    #[must_use]
    pub fn last_frame_id(&self, milestone: Milestone) -> Option<u32> {
        self.last_id[Self::index(milestone)]
    }

    /// How long since this milestone moved to a *different* frame.
    ///
    /// Distinct from [`Self::since_last`], which only says when it was last
    /// touched. The gap between the two is exactly a stage repeating itself.
    #[must_use]
    pub fn since_advance(&self, milestone: Milestone, now: Stamp<D>) -> Option<Duration> {
        self.last_advance[Self::index(milestone)].map(|last| now.since(last))
    }

    #[must_use]
    pub fn count(&self, milestone: Milestone) -> u64 {
        self.counts[Self::index(milestone)]
    }

    /// How long since this milestone last advanced. `None` if it never has.
    #[must_use]
    pub fn since_last(&self, milestone: Milestone, now: Stamp<D>) -> Option<Duration> {
        self.last[Self::index(milestone)].map(|last| now.since(last))
    }

    /// Rate in events per second over the whole session.
    ///
    /// A session average, not an instantaneous rate: it answers "has this
    /// been running at roughly the right speed", and deliberately does not
    /// pretend to detect a momentary dip. Use [`Self::since_last`] for that.
    #[must_use]
    pub fn rate_per_second(&self, milestone: Milestone, now: Stamp<D>) -> Option<f64> {
        let elapsed = now.since(self.started).as_secs_f64();
        (elapsed > 0.0).then(|| {
            #[allow(
                clippy::cast_precision_loss,
                reason = "a frame count large enough to lose precision is decades of streaming"
            )]
            let count = self.count(milestone) as f64;
            count / elapsed
        })
    }

    /// The first milestone that has fallen behind the one before it by more
    /// than `deadline`, which is where the pipeline stopped.
    ///
    /// "Behind" means it has not moved to a new frame, not that nothing has
    /// called it. A stage repeating one frame forever is stalled however
    /// busy it looks.
    ///
    /// A stage that has never advanced at all is reported only when the
    /// stage before it has, so a session that has not started yet is not
    /// mistaken for one that died at the first step.
    #[must_use]
    pub fn stalled_at(&self, deadline: Duration, now: Stamp<D>) -> Option<Milestone> {
        for pair in Milestone::ORDER.windows(2) {
            let (upstream, downstream) = (pair[0], pair[1]);
            if self.count(upstream) == 0 {
                continue;
            }
            let upstream_moved = self.since_advance(upstream, now)?;
            match self.since_advance(downstream, now) {
                // Downstream has never moved although upstream has, and
                // enough time has passed that it should have.
                None if upstream_moved >= deadline => return Some(downstream),
                None => {}
                Some(downstream_moved) if downstream_moved >= deadline => {
                    return Some(downstream);
                }
                Some(_) => {}
            }
        }
        None
    }

    /// One line per milestone: count, rate, and time since it last moved.
    #[must_use]
    pub fn report(&self, now: Stamp<D>) -> Vec<String> {
        Milestone::ORDER
            .iter()
            .map(|milestone| {
                let rate = self
                    .rate_per_second(*milestone, now)
                    .map_or_else(|| "-".to_string(), |value| format!("{value:.1}/s"));
                let idle = self.since_last(*milestone, now).map_or_else(
                    || "never".to_string(),
                    |since| format!("{}ms ago", since.as_millis()),
                );
                format!(
                    "{} {:?}  n={} {} last={}",
                    D::NAME,
                    milestone,
                    self.count(*milestone),
                    rate,
                    idle
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod liveness_tests {
    use super::{Client, Liveness, Milestone, Stamp};
    use std::time::{Duration, Instant};

    fn at(base: Instant, ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    /// The case the trace ring cannot cover: everything stops, so no new
    /// frame begins, so no new timeline is recorded, and the frame history
    /// simply freezes. These counters still show where it froze.
    #[test]
    fn a_total_stall_is_located_even_though_no_new_frames_arrive() {
        let base = Instant::now();
        let mut liveness = Liveness::<Client>::new(at(base, 0));

        // Packets keep arriving and being decoded; presentation stops.
        for tick in 0..30 {
            let now = at(base, tick * 33);
            let frame = u32::try_from(tick).expect("small");
            liveness.advance(Milestone::PacketReceived, frame, now);
            liveness.advance(Milestone::FrameDecoded, frame, now);
            if tick < 10 {
                liveness.advance(Milestone::FramePresented, frame, now);
            }
        }

        let now = at(base, 30 * 33);
        assert_eq!(
            liveness.stalled_at(Duration::from_millis(200), now),
            Some(Milestone::FramePresented),
            "the stage that stopped moving is named, not merely 'something is wrong'"
        );
        assert_eq!(liveness.count(Milestone::FrameDecoded), 30);
        assert_eq!(liveness.count(Milestone::FramePresented), 10);
    }

    /// A healthy pipeline reports no stall.
    #[test]
    fn a_pipeline_that_is_moving_is_not_a_stall() {
        let base = Instant::now();
        let mut liveness = Liveness::<Client>::new(at(base, 0));
        for tick in 0..20 {
            let now = at(base, tick * 33);
            let frame = u32::try_from(tick).expect("small");
            for milestone in Milestone::ORDER {
                liveness.advance(milestone, frame, now);
            }
        }
        let now = at(base, 20 * 33);
        assert_eq!(liveness.stalled_at(Duration::from_millis(200), now), None);
    }

    /// A session that has not started is not a session that died at the
    /// first step.
    #[test]
    fn a_pipeline_that_never_started_is_not_reported_as_stalled() {
        let base = Instant::now();
        let liveness = Liveness::<Client>::new(at(base, 0));
        let now = at(base, 10_000);
        assert_eq!(
            liveness.stalled_at(Duration::from_millis(200), now),
            None,
            "nothing upstream has moved, so nothing downstream is late"
        );
    }

    #[test]
    fn rates_and_idle_time_are_reported_per_milestone() {
        let base = Instant::now();
        let mut liveness = Liveness::<Client>::new(at(base, 0));
        for tick in 0..60 {
            liveness.advance(
                Milestone::FrameDecoded,
                u32::try_from(tick).expect("small"),
                at(base, tick * 16),
            );
        }
        let now = at(base, 1_000);

        let rate = liveness
            .rate_per_second(Milestone::FrameDecoded, now)
            .expect("elapsed time is non-zero");
        assert!((rate - 60.0).abs() < 1.0, "about 60/s, got {rate}");

        // The last decode was at 59*16 = 944ms, so ~56ms ago.
        let idle = liveness
            .since_last(Milestone::FrameDecoded, now)
            .expect("it has advanced");
        assert_eq!(idle, Duration::from_millis(56));

        assert!(
            liveness
                .since_last(Milestone::FramePresented, now)
                .is_none()
        );

        let lines = liveness.report(now);
        assert_eq!(lines.len(), Milestone::ORDER.len());
        assert!(lines[0].starts_with("client "), "{}", lines[0]);
        assert!(
            lines.iter().any(|line| line.contains("last=never")),
            "a milestone that never moved says so: {lines:?}"
        );
    }
}

/// What OpenStream can actually observe about a frame on this host.
///
/// The stages a backend can time are a property of the backend, not of the
/// telemetry, and the difference is not cosmetic. With an external encoder,
/// OpenStream hands a capture source to a child process and reads an encoded
/// byte stream back: it never sees an individual frame go in, so there is no
/// identity to correlate between "a frame arrived" and "an access unit came
/// out". Reporting those spans as zero, or inventing a correlation to fill
/// them, would both be worse than saying they are not observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostObservability {
    /// An external encoder process owns capture and encode. Only the
    /// encoded stream is visible, so timing begins at
    /// [`HostStage::EncoderFirstByte`].
    EncodedStreamOnly,
    /// Capture and encode happen in-process, so every stage is observable
    /// and carries the same frame identity.
    Full,
}

impl HostObservability {
    /// The first stage this backend can time. Stages before it are not
    /// measured and must not be reported as fast.
    #[must_use]
    pub const fn first_observable_stage(self) -> HostStage {
        match self {
            Self::EncodedStreamOnly => HostStage::EncoderFirstByte,
            Self::Full => HostStage::FrameEnteredOpenStream,
        }
    }

    /// Stages this backend times, in order.
    #[must_use]
    pub fn observable_stages(self) -> &'static [HostStage] {
        match self {
            Self::EncodedStreamOnly => &[
                HostStage::EncoderFirstByte,
                HostStage::AccessUnitBoundaryKnown,
                HostStage::FirstFragmentSent,
                HostStage::LastFragmentSent,
            ],
            Self::Full => &HostStage::ORDER,
        }
    }

    /// A sentence for a report, naming what is missing and why.
    #[must_use]
    pub const fn unobserved_note(self) -> Option<&'static str> {
        match self {
            Self::EncodedStreamOnly => Some(
                "capture and encode run in an external process; the time before \
                 the first encoded byte is not measured and is not zero",
            ),
            Self::Full => None,
        }
    }
}

/// Everything needed to compare one measurement run with another.
///
/// A stage table without this is close to unreadable after the fact: a
/// "decode P95 <= 4ms" line means nothing without knowing the resolution,
/// the codec, which decoder, and what the code was. Recorded alongside every
/// export so a number found in six months can still be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContext {
    pub commit: String,
    pub codec: String,
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub bitrate_mbps: String,
    pub capture_backend: String,
    pub encoder: String,
    pub decoder: String,
    pub presenter: String,
    /// `direct` or `relay`.
    pub path: String,
    pub vsync: String,
    pub profile: String,
    pub host_observability: HostObservability,
}

impl RunContext {
    /// One line per field, stable order, safe to log.
    ///
    /// Carries no addresses, tokens, or user content: every field is a
    /// configuration choice, not a session secret.
    #[must_use]
    pub fn report(&self) -> Vec<String> {
        let mut lines = vec![
            format!("commit={}", self.commit),
            format!("codec={}", self.codec),
            format!("size={}x{}", self.width, self.height),
            format!("fps={}", self.fps),
            format!("bitrate_mbps={}", self.bitrate_mbps),
            format!("capture={}", self.capture_backend),
            format!("encoder={}", self.encoder),
            format!("decoder={}", self.decoder),
            format!("presenter={}", self.presenter),
            format!("path={}", self.path),
            format!("vsync={}", self.vsync),
            format!("profile={}", self.profile),
            format!("host_observability={:?}", self.host_observability),
        ];
        if let Some(note) = self.host_observability.unobserved_note() {
            lines.push(format!("unobserved={note}"));
        }
        lines
    }
}

#[cfg(test)]
mod context_tests {
    use super::{HostObservability, HostStage, RunContext};

    /// The external-encoder path cannot time capture, and must say so
    /// rather than reporting those stages as instant.
    #[test]
    fn an_external_encoder_reports_what_it_cannot_see() {
        let external = HostObservability::EncodedStreamOnly;
        assert_eq!(
            external.first_observable_stage(),
            HostStage::EncoderFirstByte
        );
        assert!(
            !external
                .observable_stages()
                .contains(&HostStage::FrameEnteredOpenStream),
            "a stage that cannot be timed is not offered"
        );
        let note = external
            .unobserved_note()
            .expect("there is something missing");
        assert!(note.contains("is not zero"), "{note}");

        let native = HostObservability::Full;
        assert_eq!(
            native.first_observable_stage(),
            HostStage::FrameEnteredOpenStream
        );
        assert_eq!(native.observable_stages().len(), HostStage::ORDER.len());
        assert!(native.unobserved_note().is_none());
    }

    /// A stage table is uninterpretable later without the configuration it
    /// was taken under.
    #[test]
    fn a_run_records_enough_to_be_compared_with_another() {
        let context = RunContext {
            commit: "bd90b04".into(),
            codec: "H264".into(),
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_mbps: "10.00".into(),
            capture_backend: "portal-pipewire".into(),
            encoder: "h264_nvenc".into(),
            decoder: "ffmpeg".into(),
            presenter: "minifb-software".into(),
            path: "direct".into(),
            vsync: "off".into(),
            profile: "balanced".into(),
            host_observability: HostObservability::EncodedStreamOnly,
        };

        let report = context.report();
        for field in [
            "commit=",
            "codec=",
            "size=1920x1080",
            "fps=30",
            "encoder=",
            "decoder=",
            "presenter=",
            "path=",
            "vsync=",
            "profile=",
        ] {
            assert!(
                report.iter().any(|line| line.contains(field)),
                "missing {field} in {report:?}"
            );
        }
        assert!(
            report.iter().any(|line| line.starts_with("unobserved=")),
            "the gap is stated in the export, not left to be remembered"
        );

        // Nothing here is a secret: these are configuration choices.
        let joined = report.join(" ");
        for forbidden in ["token", "Bearer", "192.168", "pairing"] {
            assert!(!joined.contains(forbidden), "leaked {forbidden}");
        }
    }
}

#[cfg(test)]
mod progress_tests {
    use super::{Client, Liveness, Milestone, Stamp};
    use std::time::{Duration, Instant};

    fn at(base: Instant, ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    /// A stage replaying one frame forever is stalled, however busy it looks.
    ///
    /// This is the same family of mistake as trusting a live process or an
    /// open socket: something keeps being called, so a timestamp keeps being
    /// refreshed, and nothing is actually moving. Health has to be measured
    /// against the frame identity changing.
    #[test]
    fn a_stage_repeating_one_frame_is_not_progress() {
        let base = Instant::now();
        let mut liveness = Liveness::<Client>::new(at(base, 0));

        // Decode keeps advancing; the presenter re-presents frame 7 forever.
        for tick in 0..40_u32 {
            let now = at(base, u64::from(tick) * 16);
            liveness.advance(Milestone::FrameDecoded, tick, now);
            liveness.advance(Milestone::FramePresented, 7, now);
        }

        let now = at(base, 40 * 16);
        // Touched a moment ago...
        assert!(
            liveness
                .since_last(Milestone::FramePresented, now)
                .expect("touched")
                < Duration::from_millis(50)
        );
        // ...but has not moved to a new frame in the whole run.
        assert!(
            liveness
                .since_advance(Milestone::FramePresented, now)
                .expect("advanced once, at frame 7")
                >= Duration::from_millis(600)
        );
        assert_eq!(
            liveness.stalled_at(Duration::from_millis(200), now),
            Some(Milestone::FramePresented),
            "a timestamp-only check would have called this healthy"
        );
        assert_eq!(liveness.last_frame_id(Milestone::FramePresented), Some(7));
    }

    /// Genuine progress is not reported as a stall.
    #[test]
    fn advancing_frames_are_healthy() {
        let base = Instant::now();
        let mut liveness = Liveness::<Client>::new(at(base, 0));
        for tick in 0..40_u32 {
            let now = at(base, u64::from(tick) * 16);
            liveness.advance(Milestone::FrameDecoded, tick, now);
            liveness.advance(Milestone::FramePresented, tick, now);
        }
        let now = at(base, 40 * 16);
        assert_eq!(liveness.stalled_at(Duration::from_millis(200), now), None);
    }
}

#[cfg(test)]
mod observability_tests {
    use super::{
        Client, ClientObservability, ClientRecorder, ClientStage, Host, HostObservability,
        HostRecorder, HostStage, ReportOnDrop, SpanValue, Stamp,
    };
    use std::time::{Duration, Instant};

    fn at(base: Instant, ms: u64) -> Stamp<Host> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    fn client_at(base: Instant, ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    /// The capture hole must never be formatted as a duration.
    ///
    /// With an external encoder, OpenStream never sees a frame go in, so the
    /// time before the first encoded byte is real and unknown. A report that
    /// rendered it as `0us`, or dropped the row entirely, would turn an
    /// unmeasured gap into a claim that capture is instant -- which is the
    /// exact error this module exists to prevent.
    #[test]
    fn an_unobservable_span_reports_itself_rather_than_a_number() {
        let base = Instant::now();
        let mut recorder = HostRecorder::for_backend(HostObservability::EncodedStreamOnly);

        // Only the stages this backend can see are ever marked.
        recorder.begin(1, at(base, 0));
        recorder.mark(1, HostStage::EncoderFirstByte, at(base, 0));
        recorder.mark(1, HostStage::AccessUnitBoundaryKnown, at(base, 33));
        recorder.mark(1, HostStage::FirstFragmentSent, at(base, 34));
        recorder.mark(1, HostStage::LastFragmentSent, at(base, 37));
        recorder.finish(1);

        assert_eq!(
            recorder.span_value(
                HostStage::FrameEnteredOpenStream,
                HostStage::EncodeSubmitted
            ),
            SpanValue::NotObservable
        );
        assert_eq!(
            recorder.span_value(HostStage::EncodeSubmitted, HostStage::EncoderFirstByte),
            SpanValue::NotObservable,
            "a span is unobservable if either end is"
        );

        let measured = recorder.span_value(
            HostStage::EncoderFirstByte,
            HostStage::AccessUnitBoundaryKnown,
        );
        assert!(measured.is_measured());
        assert_eq!(
            measured.render(),
            "n=1 p50<=33000us p95<=33000us p99<=33000us max=33000us"
        );

        // Every stage pair appears, and the holes say what they are.
        let report = recorder.report();
        assert_eq!(report.len(), HostStage::ORDER.len() - 1);
        let holes = report
            .iter()
            .filter(|line| line.contains("not-observable"))
            .count();
        assert_eq!(holes, 2, "the two unmeasurable spans are named: {report:?}");
        for line in &report {
            if line.contains("not-observable") {
                assert!(
                    !line.contains("us"),
                    "a hole rendered as a duration: {line}"
                );
                assert!(
                    !line.contains("n="),
                    "a hole rendered a sample count: {line}"
                );
            }
        }
    }

    /// An observable span that nothing has crossed is distinct from one that
    /// cannot be seen at all.
    #[test]
    fn no_samples_is_not_the_same_as_not_observable() {
        let recorder = HostRecorder::for_backend(HostObservability::EncodedStreamOnly);
        assert_eq!(
            recorder.span_value(
                HostStage::EncoderFirstByte,
                HostStage::AccessUnitBoundaryKnown
            ),
            SpanValue::NoSamples,
            "observable, just not exercised yet"
        );
        assert_eq!(
            recorder.span_value(
                HostStage::FrameEnteredOpenStream,
                HostStage::EncodeSubmitted
            ),
            SpanValue::NotObservable
        );
    }

    /// A native backend measures everything, with no holes.
    #[test]
    fn a_native_backend_has_no_unobservable_spans() {
        let base = Instant::now();
        let mut recorder = HostRecorder::for_backend(HostObservability::Full);
        recorder.begin(1, at(base, 0));
        for (index, stage) in HostStage::ORDER.iter().enumerate().skip(1) {
            recorder.mark(1, *stage, at(base, index as u64 * 5));
        }
        recorder.finish(1);

        let report = recorder.report();
        assert!(
            !report.iter().any(|line| line.contains("not-observable")),
            "{report:?}"
        );
        assert!(report.iter().all(|line| line.contains("n=1")), "{report:?}");
    }

    /// On a backend that cannot see the earlier stages, `begin` must stamp
    /// the first stage it *can* see.
    ///
    /// Writing the stamp to `FrameEnteredOpenStream` instead would put a
    /// real timestamp on a moment that was never observed. A report would
    /// hide it, because it gates on observability -- but an exported trace
    /// would not, and it would read as a capture time the host never
    /// measured.
    #[test]
    fn timing_starts_at_the_first_stage_the_backend_can_see() {
        let base = Instant::now();
        let mut recorder = HostRecorder::for_backend(HostObservability::EncodedStreamOnly);
        recorder.set_tracing(true);
        recorder.begin(1, at(base, 0));
        recorder.mark(1, HostStage::AccessUnitBoundaryKnown, at(base, 8));
        recorder.mark(1, HostStage::FirstFragmentSent, at(base, 9));
        recorder.mark(1, HostStage::LastFragmentSent, at(base, 10));
        recorder.finish(1);

        let trace = recorder.traces().next().expect("one trace retained");
        assert!(
            trace.stamp_of(HostStage::FrameEnteredOpenStream).is_none(),
            "a stage this host never observed must carry no timestamp"
        );
        assert!(trace.stamp_of(HostStage::EncoderFirstByte).is_some());
        let span = recorder.span_value(
            HostStage::EncoderFirstByte,
            HostStage::AccessUnitBoundaryKnown,
        );
        assert!(span.is_measured(), "{span:?}");
        assert_eq!(
            recorder.span_value(
                HostStage::FrameEnteredOpenStream,
                HostStage::EncodeSubmitted
            ),
            SpanValue::NotObservable
        );
    }

    /// The report that gets printed when a session ends badly.
    #[test]
    fn the_drop_report_carries_the_counts_and_the_note() {
        let base = Instant::now();
        let mut guard = ReportOnDrop::new(
            HostRecorder::for_backend(HostObservability::EncodedStreamOnly),
            HostObservability::EncodedStreamOnly.unobserved_note(),
        );
        guard.begin(1, at(base, 0));
        guard.mark(1, HostStage::AccessUnitBoundaryKnown, at(base, 8));
        guard.finish(1);
        // Frame 2 is still open when the session ends.
        guard.begin(2, at(base, 20));

        let lines = guard.lines().join("\n");
        assert!(lines.contains("frames=1"), "{lines}");
        assert!(lines.contains("in_flight_at_end=1"), "{lines}");
        assert!(lines.contains("not-observable"), "{lines}");
        assert!(
            lines.contains("is not measured and is not zero"),
            "the note has to say why the hole is there: {lines}"
        );
    }

    /// A session that never carried a frame prints nothing rather than a
    /// table of empty rows.
    #[test]
    fn a_session_with_no_frames_has_nothing_to_report() {
        let guard = ReportOnDrop::new(
            HostRecorder::for_backend(HostObservability::EncodedStreamOnly),
            None,
        );
        assert!(guard.lines().is_empty());
    }

    /// The client's frame id does not survive an external decoder, and the
    /// stages past it must say so rather than report a number.
    ///
    /// This is the client-side twin of the host's encoded-stream-only case.
    /// Stamping `DecodedReady` against the frame id that was submitted would
    /// produce a plausible decode span for a picture nobody can prove is the
    /// same one -- the shape of the error that made an earlier end-to-end
    /// figure unreproducible.
    #[test]
    fn an_external_decoder_ends_the_frame_identity_at_submission() {
        let base = Instant::now();
        let mut recorder = ClientRecorder::for_decoder(ClientObservability::ExternalDecoder);
        recorder.begin(7, client_at(base, 0));
        recorder.mark(7, ClientStage::LastFragmentReceived, client_at(base, 1));
        recorder.mark(7, ClientStage::Reassembled, client_at(base, 2));
        recorder.mark(7, ClientStage::DecoderSubmitted, client_at(base, 3));
        recorder.finish(7);

        assert!(
            recorder
                .span_value(ClientStage::Reassembled, ClientStage::DecoderSubmitted)
                .is_measured()
        );
        assert_eq!(
            recorder.span_value(ClientStage::DecoderSubmitted, ClientStage::DecodedReady),
            SpanValue::NotObservable
        );
        assert_eq!(
            recorder.span_value(ClientStage::TakenByWindow, ClientStage::PresentSubmitted),
            SpanValue::NotObservable
        );
        assert_eq!(
            ClientObservability::ExternalDecoder.last_observable_stage(),
            ClientStage::DecoderSubmitted
        );
        // The note points at where the missing measurement actually lives.
        let note = ClientObservability::ExternalDecoder
            .unobserved_note()
            .expect("an external decoder has an unobserved tail");
        assert!(note.contains("frame-age"), "{note}");
        assert!(ClientObservability::Full.unobserved_note().is_none());
    }

    #[test]
    fn an_in_process_decoder_observes_every_client_stage() {
        let recorder = ClientRecorder::for_decoder(ClientObservability::Full);
        assert_eq!(
            recorder.span_value(ClientStage::DecodedReady, ClientStage::HandedToWindow),
            SpanValue::NoSamples,
            "observable but unexercised is not the same as unobservable"
        );
    }
}
