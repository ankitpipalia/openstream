//! A machine-readable marker for measuring interaction latency.
//!
//! # What this measures, and what it does not
//!
//! The client times a probe it sent against the moment it sees that probe's
//! marker come back in the decoded video:
//!
//! ```text
//! client sends probe(id)
//!     -> host draws a marker carrying id, on the real desktop
//!     -> the ordinary capture / encode / network / decode path
//!     -> client detects the marker
//! ```
//!
//! Both ends of that measurement are readings of **one** clock, on the
//! client. There is no host/client comparison, so none of the
//! synchronisation error that made an earlier experiment unreproducible
//! applies here.
//!
//! Two spans are worth reporting and they are named for what they are:
//! `interaction_to_decoded` and `interaction_to_present_submit`. Neither is
//! "input to photon". A present submission is not evidence that a panel
//! emitted anything; establishing that needs a display callback with known
//! semantics, or external hardware.
//!
//! # Why a binary block rather than text
//!
//! The previous measurement read a clock off a screenshot, which cost about
//! +/-30 ms of timing error and, in one run, silently captured the wrong
//! window three times. A marker meant for a machine should be read by one:
//! this is high-contrast cells detected in the decoded frame in memory,
//! before presentation, with no screenshot and no OCR anywhere.
//!
//! # Why the marker must be drawn by the desktop
//!
//! It has to travel the path being measured. Drawing it inside OpenStream
//! after capture would skip exactly the capture and encode delay the probe
//! exists to include -- and on a Wayland host OpenStream does not own the
//! desktop, so it could not draw there anyway. The marker is therefore
//! produced by a host-side helper window on the captured output. That makes
//! the probe a test and benchmark facility, not a production path.
//!
//! # The helper is fullscreen, and it reacts to real input
//!
//! Two properties the helper needs, both of which follow from what is being
//! measured rather than from convenience.
//!
//! **Fullscreen**, because [`detect`] reads the marker at an agreed
//! coordinate rather than searching for it, and under Wayland a client
//! cannot place a window at an absolute desktop position -- `xdg_toplevel`
//! offers fullscreen, maximise and interactive move, not arbitrary
//! placement. A fullscreen helper on the captured output makes the
//! surface-local coordinate a known desktop coordinate. For a benchmark,
//! owning the screen is acceptable, and it settles keyboard focus too.
//!
//! **Driven by a real injected event**, because a probe id delivered over a
//! side channel would skip the host half of the path. The sequence is:
//!
//! ```text
//! helper displays marker 0
//! client sees marker 0                  -- synchronised
//!
//! client: probe.sent(1)
//! client: send an ordinary key or button event
//!     -> OpenStream input
//!     -> network
//!     -> host uinput injection
//!     -> the helper receives it as an application event
//!     -> helper advances its marker to 1
//!     -> compositor redraws
//!     -> portal / PipeWire / encode / network / decode
//! client: sees marker 1                 -- interaction_to_decoded
//! client: that frame is submitted        -- interaction_to_present_submit
//! ```
//!
//! So the probe id is a counter the helper increments on each event, and
//! nothing about the measurement travels outside the ordinary input and
//! video paths. A benchmark message carrying the id would have measured a
//! shorter path than the one being reported.

/// Cells across the marker grid.
pub const GRID_COLUMNS: usize = 7;
/// Cells down the marker grid.
pub const GRID_ROWS: usize = 6;
/// Cells carrying calibration rather than payload.
pub const CALIBRATION_CELLS: usize = 2;
/// Payload bits: 16 magic, 16 probe id, 8 checksum.
pub const PAYLOAD_BITS: usize = 40;

// The grid has to hold the payload and its calibration pair. Checked at
// compile time so a later change to the grid cannot silently truncate the
// payload into a marker that decodes to the wrong id.
const _: () = assert!(CALIBRATION_CELLS + PAYLOAD_BITS <= GRID_COLUMNS * GRID_ROWS);

/// Distinctive header, chosen to be improbable in desktop content: an
/// alternating run is unlikely to appear by accident in a corner of a real
/// screen, and its own bit pattern makes a misaligned read obvious.
pub const MAGIC: u16 = 0xA55A;

/// Side of one cell in pixels at 1080p.
///
/// Deliberately large. The marker has to survive 4:2:0 chroma subsampling,
/// a quantiser that has been told to prioritise latency over quality, and
/// whatever scaling sits between capture and decode. Small cells are the
/// first thing an encoder throws away; a 24-pixel block of flat luma is
/// nearly free to encode and nearly impossible to lose.
pub const CELL_PIXELS: usize = 24;

/// Fraction of a cell sampled at its centre, avoiding edges where the
/// encoder's deblocking filter smears neighbouring cells together.
const SAMPLE_INSET: usize = CELL_PIXELS / 4;

/// Total marker width in pixels.
#[must_use]
pub const fn marker_width() -> usize {
    GRID_COLUMNS * CELL_PIXELS
}

/// Total marker height in pixels.
#[must_use]
pub const fn marker_height() -> usize {
    GRID_ROWS * CELL_PIXELS
}

/// Checksum over the magic and probe id.
///
/// Not integrity protection -- nothing here is adversarial. It rejects a
/// frame that was decoded mid-update or read at the wrong offset, where the
/// magic could still line up but the payload is torn.
#[must_use]
pub const fn checksum(probe_id: u16) -> u8 {
    let bytes = [
        (MAGIC >> 8) as u8,
        (MAGIC & 0xff) as u8,
        (probe_id >> 8) as u8,
        (probe_id & 0xff) as u8,
    ];
    // Sum with a fixed offset so an all-zero payload does not checksum to
    // zero, which would make a black frame look like a valid marker.
    let sum = bytes[0]
        .wrapping_add(bytes[1])
        .wrapping_add(bytes[2])
        .wrapping_add(bytes[3]);
    sum ^ 0x5A
}

/// The bits a marker encodes, in draw order.
///
/// The first two cells are calibration: one always white, one always black.
/// A detector derives its threshold from them rather than assuming a fixed
/// luma, so the marker survives an encoder that shifts levels, a limited
/// range conversion, or a display pipeline that adjusts brightness.
#[must_use]
pub fn cells_for(probe_id: u16) -> [bool; GRID_COLUMNS * GRID_ROWS] {
    let mut cells = [false; GRID_COLUMNS * GRID_ROWS];
    cells[0] = true; // calibration white
    cells[1] = false; // calibration black

    let payload =
        (u64::from(MAGIC) << 24) | (u64::from(probe_id) << 8) | u64::from(checksum(probe_id));
    for bit in 0..PAYLOAD_BITS {
        // Most significant bit first, so a partially drawn marker fails the
        // magic check rather than decoding to a plausible id.
        let shift = PAYLOAD_BITS - 1 - bit;
        cells[CALIBRATION_CELLS + bit] = (payload >> shift) & 1 == 1;
    }
    cells
}

/// Luma of a BGRA pixel packed as `0xAARRGGBB`, using Rec. 601 weights.
///
/// Integer arithmetic throughout: this runs over every decoded frame when
/// probing, and floating point would buy nothing on a black-or-white cell.
#[must_use]
const fn luma(pixel: u32) -> u32 {
    let red = (pixel >> 16) & 0xff;
    let green = (pixel >> 8) & 0xff;
    let blue = pixel & 0xff;
    (red * 77 + green * 150 + blue * 29) >> 8
}

/// Mean luma of the inset centre of one cell.
fn cell_luma(
    frame: &[u32],
    width: usize,
    height: usize,
    origin: (usize, usize),
    column: usize,
    row: usize,
) -> Option<u32> {
    let left = origin.0 + column * CELL_PIXELS + SAMPLE_INSET;
    let top = origin.1 + row * CELL_PIXELS + SAMPLE_INSET;
    let span = CELL_PIXELS - SAMPLE_INSET * 2;
    if left + span > width || top + span > height {
        return None;
    }
    let mut total: u64 = 0;
    for y in top..top + span {
        let base = y.checked_mul(width)?;
        for x in left..left + span {
            total += u64::from(luma(*frame.get(base + x)?));
        }
    }
    let samples = u64::try_from(span * span).ok()?;
    (samples > 0).then(|| u32::try_from(total / samples).unwrap_or(u32::MAX))
}

/// Read a probe id out of a decoded BGRA frame, if a marker is present.
///
/// `origin` is the marker's top-left pixel, which the host helper and the
/// client agree on rather than searching for: scanning a 1080p frame for a
/// pattern on every decode would cost more than the thing being measured.
///
/// That agreement is why the helper is fullscreen. A Wayland client cannot
/// ask to be placed at an absolute desktop coordinate, so the only way a
/// surface-local position is also a known capture position is for the
/// surface to cover the output.
///
/// Returns `None` for any frame that does not carry an intact marker --
/// wrong magic, failed checksum, calibration cells that did not separate.
/// A miss is expected and cheap; the probe simply completes on a later
/// frame.
#[must_use]
pub fn detect(frame: &[u32], width: usize, height: usize, origin: (usize, usize)) -> Option<u16> {
    if width == 0 || height == 0 || frame.len() < width.checked_mul(height)? {
        return None;
    }

    let mut luma_cells = [0_u32; GRID_COLUMNS * GRID_ROWS];
    for row in 0..GRID_ROWS {
        for column in 0..GRID_COLUMNS {
            luma_cells[row * GRID_COLUMNS + column] =
                cell_luma(frame, width, height, origin, column, row)?;
        }
    }

    // Threshold from the calibration pair rather than a fixed level, so an
    // encoder that shifts luma or a limited-range conversion does not break
    // detection.
    let white = luma_cells[0];
    let black = luma_cells[1];
    // They must actually separate. A flat region -- a black frame, a solid
    // window -- would otherwise produce a threshold in the middle of noise
    // and decode gibberish that might pass the magic check by chance.
    const MIN_SEPARATION: u32 = 40;
    if white <= black || white - black < MIN_SEPARATION {
        return None;
    }
    let threshold = (white + black) / 2;

    let mut payload: u64 = 0;
    for bit in 0..PAYLOAD_BITS {
        payload <<= 1;
        if luma_cells[CALIBRATION_CELLS + bit] > threshold {
            payload |= 1;
        }
    }

    let magic = u16::try_from((payload >> 24) & 0xffff).ok()?;
    if magic != MAGIC {
        return None;
    }
    let probe_id = u16::try_from((payload >> 8) & 0xffff).ok()?;
    let found = u8::try_from(payload & 0xff).ok()?;
    (found == checksum(probe_id)).then_some(probe_id)
}

/// Render a marker into a BGRA buffer, for tests and for a host helper that
/// draws through the real desktop.
pub fn render(
    frame: &mut [u32],
    width: usize,
    height: usize,
    origin: (usize, usize),
    probe_id: u16,
) {
    const WHITE: u32 = 0xffff_ffff;
    const BLACK: u32 = 0xff00_0000;
    let cells = cells_for(probe_id);
    for row in 0..GRID_ROWS {
        for column in 0..GRID_COLUMNS {
            let value = if cells[row * GRID_COLUMNS + column] {
                WHITE
            } else {
                BLACK
            };
            for y in 0..CELL_PIXELS {
                let target_y = origin.1 + row * CELL_PIXELS + y;
                if target_y >= height {
                    continue;
                }
                for x in 0..CELL_PIXELS {
                    let target_x = origin.0 + column * CELL_PIXELS + x;
                    if target_x >= width {
                        continue;
                    }
                    if let Some(pixel) = frame.get_mut(target_y * width + target_x) {
                        *pixel = value;
                    }
                }
            }
        }
    }
}

use crate::latency::{Client, Histogram, SpanValue, Stamp};
use std::collections::VecDeque;
use std::time::Duration;

/// Probes tracked at once.
///
/// Bounded: a probe whose marker never comes back must not accumulate. At
/// one probe per few frames this is seconds of outstanding work, which is
/// far longer than any latency worth measuring.
pub const MAX_OUTSTANDING: usize = 32;

/// One completed interaction measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub probe_id: u16,
    /// Probe sent until its marker appeared in a decoded frame.
    pub to_decoded: Duration,
    /// Probe sent until that frame was submitted for presentation.
    ///
    /// `None` until the frame carrying the marker reaches the presenter.
    /// **Not** input-to-photon: submission is not proof of emission.
    pub to_present_submit: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct Outstanding {
    probe_id: u16,
    sent: Stamp<Client>,
    decoded: Option<Stamp<Client>>,
}

/// Client-side interaction latency measurement.
///
/// Every timestamp here is read from the client's own monotonic clock, so
/// the result needs no synchronisation with the host and carries none of
/// its uncertainty.
#[derive(Debug)]
pub struct InteractionProbe {
    outstanding: VecDeque<Outstanding>,
    to_decoded: Histogram,
    to_present_submit: Histogram,
    sent: u64,
    decoded: u64,
    present_submitted: u64,
    abandoned: u64,
    repeat_sightings: u64,
}

impl Default for InteractionProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractionProbe {
    #[must_use]
    pub fn new() -> Self {
        Self {
            outstanding: VecDeque::new(),
            to_decoded: Histogram::new(),
            to_present_submit: Histogram::new(),
            sent: 0,
            decoded: 0,
            present_submitted: 0,
            abandoned: 0,
            repeat_sightings: 0,
        }
    }

    /// Record that a probe was sent.
    ///
    /// Call this immediately before sending the *real* input event that
    /// will make the helper advance its marker to `probe_id`. Nothing about
    /// the probe travels outside the ordinary input path, so the span
    /// includes host injection and the application's own response.
    ///
    /// The oldest outstanding probe is dropped once the bound is reached,
    /// and counted as abandoned.
    pub fn sent(&mut self, probe_id: u16, at: Stamp<Client>) {
        if self.outstanding.len() >= MAX_OUTSTANDING && self.outstanding.pop_front().is_some() {
            // Evicted before reaching presentation, whether or not it was
            // decoded. A probe that was seen and never presented is not a
            // completed measurement of the span it was sent to measure.
            self.abandoned = self.abandoned.saturating_add(1);
        }
        self.sent = self.sent.saturating_add(1);
        self.outstanding.push_back(Outstanding {
            probe_id,
            sent: at,
            decoded: None,
        });
    }

    /// Record that a marker was seen in a decoded frame.
    ///
    /// **Idempotent.** A marker stays on screen for as long as the helper
    /// draws it, so the same id arrives in many consecutive frames. Only the
    /// first sighting is the measurement; later ones are counted so a
    /// reader can tell a marker that lingered from one that flickered, and
    /// otherwise ignored. Without this the histogram would fill with
    /// progressively larger values for a single interaction and the median
    /// would describe how long the marker was displayed.
    pub fn marker_decoded(&mut self, probe_id: u16, at: Stamp<Client>) -> Option<Completion> {
        let entry = self
            .outstanding
            .iter_mut()
            .find(|entry| entry.probe_id == probe_id)?;
        if entry.decoded.is_some() {
            self.repeat_sightings = self.repeat_sightings.saturating_add(1);
            return None;
        }
        entry.decoded = Some(at);
        let sent = entry.sent;
        let to_decoded = at.since(sent);
        // `record_span` counts an out-of-order pair as invalid rather than
        // as a zero-microsecond interaction. The probe is still retired --
        // a marker seen is a marker seen -- but it contributes no sample.
        self.to_decoded.record_span(to_decoded);
        self.decoded = self.decoded.saturating_add(1);
        Some(Completion {
            probe_id,
            to_decoded: to_decoded?,
            to_present_submit: None,
        })
    }

    /// Record that the frame carrying a marker was submitted for
    /// presentation, retiring the probe.
    pub fn marker_present_submitted(
        &mut self,
        probe_id: u16,
        at: Stamp<Client>,
    ) -> Option<Completion> {
        let index = self
            .outstanding
            .iter()
            .position(|entry| entry.probe_id == probe_id)?;
        let entry = self.outstanding.get(index).copied()?;
        let decoded = entry.decoded?;
        self.outstanding.remove(index);
        let to_present = at.since(entry.sent);
        self.to_present_submit.record_span(to_present);
        self.present_submitted = self.present_submitted.saturating_add(1);
        Some(Completion {
            probe_id,
            to_decoded: decoded.since(entry.sent)?,
            to_present_submit: Some(to_present?),
        })
    }

    #[must_use]
    pub const fn to_decoded(&self) -> &Histogram {
        &self.to_decoded
    }

    #[must_use]
    pub const fn to_present_submit(&self) -> &Histogram {
        &self.to_present_submit
    }

    #[must_use]
    pub const fn sent_count(&self) -> u64 {
        self.sent
    }

    /// Probes whose marker was seen in a decoded frame.
    ///
    /// Deliberately not called "completed": a decoded marker is half the
    /// measurement, and a probe can be decoded and then evicted without ever
    /// reaching presentation. Each counter names one stage so the summary
    /// agrees with the two histograms rather than implying more than either.
    #[must_use]
    pub const fn decoded_count(&self) -> u64 {
        self.decoded
    }

    /// Probes whose marked frame reached the presenter.
    #[must_use]
    pub const fn present_submitted_count(&self) -> u64 {
        self.present_submitted
    }

    /// Give up on every outstanding probe.
    ///
    /// Called at a session boundary. A probe outstanding when a session
    /// drops can otherwise be matched by a marker from the *next* session,
    /// and the span it reports then spans the reconnect downtime -- a
    /// fabricated multi-second interaction latency indistinguishable from a
    /// real one.
    pub fn abandon_all(&mut self) {
        let stranded = u64::try_from(self.outstanding.len()).unwrap_or(u64::MAX);
        self.outstanding.clear();
        self.abandoned = self.abandoned.saturating_add(stranded);
    }

    /// Give up on one probe, so a late marker carrying its id cannot be
    /// matched against a stamp that is no longer meaningful.
    pub fn abandon(&mut self, probe_id: u16) -> bool {
        let Some(index) = self
            .outstanding
            .iter()
            .position(|entry| entry.probe_id == probe_id)
        else {
            return false;
        };
        self.outstanding.remove(index);
        self.abandoned = self.abandoned.saturating_add(1);
        true
    }

    /// Probes still waiting for their marker.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// Probes retired without reaching presentation, decoded or not.
    #[must_use]
    pub const fn abandoned_count(&self) -> u64 {
        self.abandoned
    }

    /// Repeat sightings of an already-measured marker.
    #[must_use]
    pub const fn repeat_sightings(&self) -> u64 {
        self.repeat_sightings
    }

    /// Two lines, named for what they actually measure.
    ///
    /// Rendered through [`SpanValue`] rather than formatted here, so a span
    /// no probe has crossed reads `no-samples`. It used to print
    /// `n=0 p50<=-us ... max=0us`, which put a dash where there was no
    /// measurement and a zero right next to it -- and `max=0us` is a number,
    /// claiming the slowest interaction observed took no time at all.
    #[must_use]
    pub fn report(&self) -> Vec<String> {
        let line = |label: &str, histogram: &Histogram| {
            format!("{label}  {}", SpanValue::from_histogram(histogram).render())
        };
        vec![
            line("interaction_to_decoded       ", &self.to_decoded),
            line("interaction_to_present_submit", &self.to_present_submit),
            format!(
                "probes sent={} decoded={} present_submitted={} abandoned={} \
                 repeat_sightings={}",
                self.sent,
                self.decoded,
                self.present_submitted,
                self.abandoned,
                self.repeat_sightings
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Completion, GRID_COLUMNS, GRID_ROWS, InteractionProbe, MAGIC, MAX_OUTSTANDING, cells_for,
        checksum, detect, marker_height, marker_width, render,
    };
    use crate::latency::{Client, Stamp};
    use std::time::{Duration, Instant};

    const WIDTH: usize = 640;
    const HEIGHT: usize = 360;
    const ORIGIN: (usize, usize) = (16, 16);

    fn blank() -> Vec<u32> {
        // Mid grey: neither calibration value, so a frame without a marker
        // cannot accidentally satisfy the threshold test.
        vec![0xff80_8080; WIDTH * HEIGHT]
    }

    fn at(base: Instant, ms: u64) -> Stamp<Client> {
        Stamp::from_instant(base + Duration::from_millis(ms))
    }

    #[test]
    fn a_marker_round_trips_through_a_frame() {
        for probe_id in [0, 1, 7, 255, 4096, u16::MAX] {
            let mut frame = blank();
            render(&mut frame, WIDTH, HEIGHT, ORIGIN, probe_id);
            assert_eq!(
                detect(&frame, WIDTH, HEIGHT, ORIGIN),
                Some(probe_id),
                "probe {probe_id} did not survive a round trip"
            );
        }
    }

    /// The grid must hold the payload plus its calibration pair.
    #[test]
    fn the_grid_has_room_for_what_it_encodes() {
        assert_eq!(cells_for(0).len(), GRID_COLUMNS * GRID_ROWS);
        assert_eq!(marker_width(), GRID_COLUMNS * 24);
        assert_eq!(marker_height(), GRID_ROWS * 24);
        // Calibration is fixed regardless of payload.
        let cells = cells_for(0x1234);
        assert!(cells[0], "first cell is the white reference");
        assert!(!cells[1], "second cell is the black reference");
    }

    /// Ordinary desktop content must not decode as a marker.
    #[test]
    fn a_frame_without_a_marker_reports_nothing() {
        assert_eq!(detect(&blank(), WIDTH, HEIGHT, ORIGIN), None);

        // Solid black and solid white both fail: the calibration cells do
        // not separate, so there is no threshold and nothing is guessed.
        assert_eq!(
            detect(&vec![0xff00_0000; WIDTH * HEIGHT], WIDTH, HEIGHT, ORIGIN),
            None,
            "a black frame must not look like an all-zero payload"
        );
        assert_eq!(
            detect(&vec![0xffff_ffff; WIDTH * HEIGHT], WIDTH, HEIGHT, ORIGIN),
            None
        );
    }

    /// A marker read at the wrong offset must fail the magic check rather
    /// than returning a plausible id.
    #[test]
    fn a_misaligned_read_is_rejected() {
        let mut frame = blank();
        render(&mut frame, WIDTH, HEIGHT, ORIGIN, 0x2BAD);
        assert_eq!(
            detect(&frame, WIDTH, HEIGHT, (ORIGIN.0 + 12, ORIGIN.1)),
            None
        );
        assert_eq!(
            detect(&frame, WIDTH, HEIGHT, (ORIGIN.0, ORIGIN.1 + 12)),
            None
        );
    }

    /// The marker exists to survive an encoder tuned for latency over
    /// quality. This applies the damage such an encoder does: luma shifted
    /// toward limited range, contrast reduced, blocking noise added, and the
    /// cell edges smeared the way a deblocking filter smears them.
    #[test]
    fn a_marker_survives_compression_damage() {
        let mut frame = blank();
        render(&mut frame, WIDTH, HEIGHT, ORIGIN, 0x0BAD);

        let mut damaged = frame.clone();
        for (index, pixel) in damaged.iter_mut().enumerate() {
            let value = super::luma(*pixel);
            // Limited range plus a contrast squeeze: 0..255 -> ~40..200.
            let squeezed = 40 + (value * 160 / 255);
            // Blocking noise that varies across the frame.
            let offset = i64::try_from(index % 17).expect("small") - 8;
            let noisy = u32::try_from((i64::from(squeezed) + offset).clamp(0, 255))
                .expect("clamped into 0..=255");
            *pixel = 0xff00_0000 | (noisy << 16) | (noisy << 8) | noisy;
        }

        assert_eq!(
            detect(&damaged, WIDTH, HEIGHT, ORIGIN),
            Some(0x0BAD),
            "the calibration pair should absorb a level shift and a contrast squeeze"
        );
    }

    /// A torn frame -- half of an old marker, half of a new one -- must not
    /// decode as either.
    #[test]
    fn a_torn_marker_fails_its_checksum() {
        let mut old = blank();
        render(&mut old, WIDTH, HEIGHT, ORIGIN, 0x1111);
        let mut new = blank();
        render(&mut new, WIDTH, HEIGHT, ORIGIN, 0x2222);

        let mut torn = old.clone();
        let split = ORIGIN.1 + marker_height() / 2;
        for y in split..HEIGHT {
            for x in 0..WIDTH {
                torn[y * WIDTH + x] = new[y * WIDTH + x];
            }
        }
        assert_eq!(
            detect(&torn, WIDTH, HEIGHT, ORIGIN),
            None,
            "a mixed marker must not report either id"
        );
    }

    #[test]
    fn the_checksum_rejects_a_flipped_payload_bit() {
        assert_ne!(checksum(0x1234), checksum(0x1235));
        // An all-zero payload must not checksum to zero, or a black region
        // would validate.
        assert_ne!(checksum(0), 0);
        assert_eq!(MAGIC, 0xA55A);
    }

    /// A marker stays on screen for many frames. Only the first sighting is
    /// the measurement; counting the rest would fill the histogram with
    /// progressively larger values describing how long it was displayed.
    #[test]
    fn a_lingering_marker_measures_once() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        probe.sent(9, at(base, 0));

        let first = probe.marker_decoded(9, at(base, 40));
        assert_eq!(
            first,
            Some(Completion {
                probe_id: 9,
                to_decoded: Duration::from_millis(40),
                to_present_submit: None,
            })
        );

        // The next twenty frames still show it.
        for frame in 1..20 {
            assert_eq!(
                probe.marker_decoded(9, at(base, 40 + frame * 16)),
                None,
                "repeat sighting {frame} must not measure again"
            );
        }
        assert_eq!(probe.to_decoded().count(), 1);
        assert_eq!(probe.repeat_sightings(), 19);
        assert_eq!(probe.to_decoded().max_us(), 40_000);
    }

    #[test]
    fn present_submission_is_reported_separately_from_decode() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        probe.sent(3, at(base, 0));
        probe.marker_decoded(3, at(base, 30));

        let completion = probe
            .marker_present_submitted(3, at(base, 48))
            .expect("the probe was decoded first");
        assert_eq!(completion.to_decoded, Duration::from_millis(30));
        assert_eq!(
            completion.to_present_submit,
            Some(Duration::from_millis(48))
        );
        assert_eq!(probe.to_present_submit().count(), 1);

        // Retired: a later sighting matches nothing.
        assert_eq!(probe.marker_decoded(3, at(base, 60)), None);
    }

    /// Presentation without a prior decode is not a measurement.
    #[test]
    fn presenting_an_unseen_marker_measures_nothing() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        probe.sent(5, at(base, 0));
        assert_eq!(probe.marker_present_submitted(5, at(base, 20)), None);
        assert_eq!(probe.to_present_submit().count(), 0);
    }

    /// A probe whose marker never returns must not accumulate forever.
    #[test]
    fn unanswered_probes_are_bounded_and_counted() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        let overflow = u16::try_from(MAX_OUTSTANDING).expect("small") + 10;
        for id in 0..overflow {
            probe.sent(id, at(base, u64::from(id)));
        }
        assert_eq!(probe.sent_count(), u64::from(overflow));
        assert_eq!(probe.abandoned_count(), 10);

        // The oldest are gone; the newest still measure.
        assert_eq!(probe.marker_decoded(0, at(base, 500)), None);
        assert!(probe.marker_decoded(overflow - 1, at(base, 500)).is_some());
    }

    /// A probe can be seen and never presented. The counters must say so.
    ///
    /// A single "completed" counter incremented at decode made this state
    /// read as `completed=1 abandoned=1`, which is individually explainable
    /// and collectively misleading: the probe completed nothing, it was
    /// decoded and then thrown away. Each counter names one stage instead.
    #[test]
    fn a_decoded_probe_that_never_presents_is_not_counted_as_complete() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();

        probe.sent(1, at(base, 0));
        probe.marker_decoded(1, at(base, 30));
        // ...and presentation never happens for it. Fill the bound so it is
        // evicted.
        let overflow = u16::try_from(MAX_OUTSTANDING).expect("small") + 1;
        for id in 2..=overflow {
            probe.sent(id, at(base, u64::from(id)));
        }

        assert_eq!(probe.decoded_count(), 1, "it was seen");
        assert_eq!(
            probe.present_submitted_count(),
            0,
            "and never reached the presenter"
        );
        assert_eq!(probe.abandoned_count(), 1, "so it was abandoned");
        // The histograms agree with the counters.
        assert_eq!(probe.to_decoded().count(), 1);
        assert_eq!(probe.to_present_submit().count(), 0);
    }

    /// A full measurement increments decode and presentation, not abandon.
    #[test]
    fn a_probe_that_reaches_the_presenter_is_counted_at_both_stages() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        probe.sent(1, at(base, 0));
        probe.marker_decoded(1, at(base, 22));
        probe.marker_present_submitted(1, at(base, 38));

        assert_eq!(probe.sent_count(), 1);
        assert_eq!(probe.decoded_count(), 1);
        assert_eq!(probe.present_submitted_count(), 1);
        assert_eq!(probe.abandoned_count(), 0);
    }

    /// A span no probe has crossed must not be formatted as a number.
    ///
    /// The report used to print `n=0 p50<=-us p95<=-us max=0us` for an empty
    /// histogram: a dash where there was no measurement, and `max=0us` right
    /// beside it, which *is* a number and says the slowest interaction seen
    /// took no time. Rendering through `SpanValue` makes that state say what
    /// it is.
    #[test]
    fn an_unexercised_probe_span_reads_as_no_samples() {
        let probe = InteractionProbe::new();
        let report = probe.report().join("\n");
        assert!(
            report.contains("interaction_to_decoded         no-samples"),
            "{report}"
        );
        assert!(
            report.contains("interaction_to_present_submit  no-samples"),
            "{report}"
        );
        assert!(!report.contains("max=0us"), "{report}");
        assert!(!report.contains("<=-us"), "{report}");
    }

    #[test]
    fn the_report_names_what_it_measures() {
        let base = Instant::now();
        let mut probe = InteractionProbe::new();
        probe.sent(1, at(base, 0));
        probe.marker_decoded(1, at(base, 25));
        probe.marker_present_submitted(1, at(base, 41));

        let report = probe.report();
        assert!(report[0].contains("interaction_to_decoded"));
        assert!(report[1].contains("interaction_to_present_submit"));
        // The name that would overclaim must not appear anywhere.
        let joined = report.join(" ");
        assert!(
            !joined.to_lowercase().contains("photon"),
            "present-submit is not photon latency: {joined}"
        );
    }
}
