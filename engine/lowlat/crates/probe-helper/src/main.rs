//! Fullscreen benchmark helper for the interaction probe.
//!
//! This runs on the **host desktop**, inside the output OpenStream is
//! capturing. It draws the machine-readable marker from
//! [`openstream_media::probe`] and advances it by one whenever it receives an
//! ordinary input event. The client stamps when it sent the input that caused
//! that event and stamps again when it sees the new marker, and the
//! difference is the whole interactive path: client input, network, host
//! injection, the application's own response, compositor redraw, portal
//! capture, encode, network, decode, present-submit.
//!
//! # Why fullscreen
//!
//! The client reads the marker at an agreed coordinate rather than searching
//! for it -- scanning a 1080p frame on every decoded picture would cost more
//! than the thing being measured. Under Wayland a client cannot ask to be
//! placed at an absolute desktop position: `xdg_toplevel` offers fullscreen,
//! maximise and interactive move, not arbitrary placement. Covering the
//! output is therefore the only way a surface-local coordinate is also a
//! known capture coordinate. It settles keyboard focus at the same time,
//! which this needs anyway.
//!
//! # Why a real input event, and not a benchmark message
//!
//! Handing the helper the next probe id over a side channel would be easier
//! and would measure a shorter path than the one being reported: everything
//! from the client's input queue through host injection to the application
//! receiving an event would be skipped, and the result would still be
//! labelled `interaction_to_decoded`. So the id is simply a counter the
//! helper increments on each event it receives. It cannot tell an injected
//! event from a local keypress -- which is the point, because neither can
//! the compositor.
//!
//! # Running it
//!
//! ```text
//! OPENSTREAM_PROBE_SIZE=2560x1440 openstream-probe-helper
//! ```
//!
//! It prints the marker origin and size; give the client the same origin.
//! Press Escape to quit. Nothing here is part of a session: it is a test and
//! benchmark facility and has no OpenStream connection of its own.

use std::env;
use std::time::{Duration, Instant};

use minifb::{Key, KeyRepeat, MouseButton, Window, WindowOptions};
use openstream_media::probe::{self, CELL_PIXELS, marker_height, marker_width};

/// Default surface size when `OPENSTREAM_PROBE_SIZE` is unset. Deliberately
/// a common capture size rather than something clever: the operator knows
/// what the host is streaming and the helper has no way to ask.
const DEFAULT_SIZE: (usize, usize) = (1920, 1080);

/// Largest surface this will allocate, so a mistyped environment variable
/// cannot ask for a multi-gigabyte buffer.
const MAX_DIMENSION: usize = 16_384;

/// Background, and the two shades of the human-visible pulse bar. Mid-grey
/// so neither shade can be mistaken for the marker's own black and white
/// calibration cells by someone reading the screen.
const BACKGROUND: u32 = 0x0020_2024;
const PULSE_ON: u32 = 0x0080_80A0;
const PULSE_OFF: u32 = 0x0030_3040;

/// How long to sleep between polls when nothing has happened.
///
/// Short, because this is the helper's own contribution to the measured
/// latency: an event arriving just after a poll waits this long before the
/// marker advances, and that wait lands inside `interaction_to_decoded`. Two
/// milliseconds is well under a frame interval at any rate worth measuring,
/// and the loop does no work in that time beyond pumping events.
const IDLE_FRAME: Duration = Duration::from_millis(2);

/// Default interval between re-uploads of an unchanged surface, in
/// milliseconds. Overridden by `OPENSTREAM_PROBE_HEARTBEAT_MS`.
///
/// This setting decides what the probe is measuring, so it is worth being
/// explicit about both directions.
///
/// A portal screencast is damage driven: it emits a buffer when something on
/// the screen changed. A helper that drew once and went still would stop the
/// capture entirely -- the client would decode nothing, never read the
/// marker, and never learn which id to send, so the probe would deadlock
/// before its first measurement. Worse, a heartbeat that is merely *slow*
/// does not deadlock, it quietly produces a slow stream: a first rig run at
/// ten hertz measured a session running at 8.6 fps, and an interaction
/// latency drawn from that says nothing about an interactive desktop.
///
/// So the default matches a typical stream rate, and the helper is the thing
/// keeping the capture busy, the way a desktop someone is using would be.
/// The cost is real -- each upload is the whole surface -- which is why it
/// is a knob: a slower heartbeat lowers the helper's own load at the price
/// of measuring a stream nobody would stream.
const DEFAULT_HEARTBEAT_MS: u64 = 16;

/// Largest accepted heartbeat. Beyond about a third of a second the capture
/// is no longer a video stream in any useful sense.
const MAX_HEARTBEAT_MS: u64 = 250;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (width, height) = surface_size()?;
    let origin = marker_origin()?;
    let heartbeat = heartbeat_interval()?;
    if origin.0 + marker_width() > width || origin.1 + marker_height() > height {
        return Err(format!(
            "marker at {origin:?} sized {}x{} does not fit in {width}x{height}",
            marker_width(),
            marker_height()
        )
        .into());
    }

    let mut window = Window::new(
        "OpenStream probe helper",
        width,
        height,
        WindowOptions {
            borderless: true,
            topmost: true,
            resize: false,
            ..WindowOptions::default()
        },
    )?;
    window.set_position(0, 0);
    // The event loop has to run for key events to arrive, but the surface is
    // only uploaded when the marker changes, so this is a poll rate rather
    // than a frame rate.
    window.set_target_fps(240);

    println!("OpenStream probe helper: surface {width}x{height}");
    println!(
        "OpenStream probe helper: marker origin {},{} size {}x{} cell {CELL_PIXELS}px",
        origin.0,
        origin.1,
        marker_width(),
        marker_height()
    );
    println!(
        "OpenStream probe helper: heartbeat {}ms -- the capture runs no faster than this",
        heartbeat.as_millis()
    );
    println!("OpenStream probe helper: give the client the same origin; Escape quits");

    let mut buffer = vec![BACKGROUND; width * height];
    // Starts at zero and is shown before any input arrives, so the client can
    // confirm it is reading the right place before it measures anything.
    let mut probe_id: u16 = 0;
    let mut events: u64 = 0;
    // The requested heartbeat is not proof of what the helper achieved.
    // When two runs of the same build differ two-to-one in frame rate, the
    // first question is which boundary slowed down, and the helper is the
    // first boundary: if it did not upload, nothing downstream could.
    let mut uploads: u64 = 0;
    let mut upload_total = Duration::ZERO;
    let mut upload_max = Duration::ZERO;
    let started = Instant::now();
    let mut buttons_down = [false; 3];
    let mut last_report = Instant::now();
    // Zero elapsed at the start would skip the first upload; force one.
    let mut last_upload = Instant::now() - heartbeat;
    draw(&mut buffer, width, height, origin, probe_id);

    while window.is_open() && !window.is_key_down(Key::Escape) {
        // One advance per event, whatever kind it was. `KeyRepeat::No` so a
        // held key does not advance the marker on every frame: the client
        // sends one press and expects exactly one new id.
        let mut advanced = false;
        for _ in window.get_keys_pressed(KeyRepeat::No) {
            advanced = true;
            events += 1;
        }
        for (index, button) in [MouseButton::Left, MouseButton::Middle, MouseButton::Right]
            .into_iter()
            .enumerate()
        {
            let down = window.get_mouse_down(button);
            if down && !buttons_down[index] {
                advanced = true;
                events += 1;
            }
            buttons_down[index] = down;
        }

        if advanced {
            // Wrapping is correct rather than merely convenient: the client
            // matches on the id it sent, and its outstanding set is far
            // smaller than the 16-bit space, so a wrap cannot make two
            // outstanding probes collide.
            probe_id = probe_id.wrapping_add(1);
            draw(&mut buffer, width, height, origin, probe_id);
        }

        // Upload on change, and otherwise at a slow heartbeat.
        //
        // Not on every iteration: re-uploading fourteen million pixels at
        // the poll rate cost more host CPU than the session being measured,
        // and a benchmark helper that loads the host is measuring itself.
        //
        // But not only on change either. A portal screencast is damage
        // driven: a desktop where nothing moves produces no buffers, so a
        // helper that went completely still would stop the capture, and the
        // client would never see the marker it needs in order to know which
        // id to send next -- a probe that deadlocks itself before the first
        // measurement. The heartbeat keeps the stream alive at a rate that
        // costs a few percent of one core.
        let heartbeat_due = last_upload.elapsed() >= heartbeat;
        if advanced || heartbeat_due {
            let began = Instant::now();
            window.update_with_buffer(&buffer, width, height)?;
            let took = began.elapsed();
            uploads += 1;
            upload_total += took;
            upload_max = upload_max.max(took);
            last_upload = Instant::now();
        } else {
            window.update();
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            println!(
                "OpenStream probe helper: {events} events, marker now {probe_id}, {}",
                upload_summary(started, uploads, upload_total, upload_max)
            );
            last_report = Instant::now();
        }
        if !advanced {
            std::thread::sleep(IDLE_FRAME);
        }
    }
    println!(
        "OpenStream probe helper: {events} events total, {}",
        upload_summary(started, uploads, upload_total, upload_max)
    );
    Ok(())
}

/// What the helper actually achieved, as opposed to what it asked for.
fn upload_summary(started: Instant, uploads: u64, total: Duration, max: Duration) -> String {
    let elapsed = started.elapsed().as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let count = uploads as f64;
    let rate = if elapsed > 0.0 { count / elapsed } else { 0.0 };
    let mean_us = if uploads > 0 {
        u64::try_from(total.as_micros() / u128::from(uploads)).unwrap_or(u64::MAX)
    } else {
        0
    };
    format!(
        "uploads={uploads} {rate:.1}/s mean={mean_us}us max={}us",
        max.as_micros()
    )
}

/// Paint the background, the marker, and a bar a human can watch.
///
/// The bar exists so an operator can see the helper responding without
/// decoding anything; it is deliberately small. A full-screen flash on every
/// event would give the encoder a whole-frame change to compress, which is
/// not what an interactive update looks like and would measure the wrong
/// thing.
fn draw(buffer: &mut [u32], width: usize, height: usize, origin: (usize, usize), probe_id: u16) {
    buffer.fill(BACKGROUND);

    let bar_top = origin.1 + marker_height() + CELL_PIXELS;
    let bar_height = CELL_PIXELS;
    let segments = 16_usize;
    let segment = marker_width() / segments;
    for index in 0..segments {
        let lit = u32::from(probe_id) & (1 << index) != 0;
        let colour = if lit { PULSE_ON } else { PULSE_OFF };
        for row in bar_top..(bar_top + bar_height).min(height) {
            let left = origin.0 + index * segment;
            for column in left..(left + segment).min(width) {
                if let Some(pixel) = buffer.get_mut(row * width + column) {
                    *pixel = colour;
                }
            }
        }
    }

    probe::render(buffer, width, height, origin, probe_id);
}

fn surface_size() -> Result<(usize, usize), Box<dyn std::error::Error>> {
    match env::var("OPENSTREAM_PROBE_SIZE") {
        Ok(spec) => parse_size(&spec),
        Err(_) => Ok(DEFAULT_SIZE),
    }
}

fn parse_size(spec: &str) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let (width, height) = spec
        .split_once(['x', 'X'])
        .ok_or("OPENSTREAM_PROBE_SIZE must look like 1920x1080")?;
    let width: usize = width.trim().parse()?;
    let height: usize = height.trim().parse()?;
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(format!("OPENSTREAM_PROBE_SIZE out of range: {spec}").into());
    }
    Ok((width, height))
}

fn heartbeat_interval() -> Result<Duration, Box<dyn std::error::Error>> {
    match env::var("OPENSTREAM_PROBE_HEARTBEAT_MS") {
        Ok(spec) => parse_heartbeat(&spec),
        Err(_) => Ok(Duration::from_millis(DEFAULT_HEARTBEAT_MS)),
    }
}

fn parse_heartbeat(spec: &str) -> Result<Duration, Box<dyn std::error::Error>> {
    let millis: u64 = spec.trim().parse()?;
    if millis == 0 || millis > MAX_HEARTBEAT_MS {
        return Err(format!(
            "OPENSTREAM_PROBE_HEARTBEAT_MS must be 1..={MAX_HEARTBEAT_MS}, got {spec}"
        )
        .into());
    }
    Ok(Duration::from_millis(millis))
}

fn marker_origin() -> Result<(usize, usize), Box<dyn std::error::Error>> {
    match env::var("OPENSTREAM_PROBE_ORIGIN") {
        Ok(spec) => parse_origin(&spec),
        Err(_) => Ok((0, 0)),
    }
}

fn parse_origin(spec: &str) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let (x, y) = spec
        .split_once(',')
        .ok_or("OPENSTREAM_PROBE_ORIGIN must look like 0,0")?;
    Ok((x.trim().parse()?, y.trim().parse()?))
}

#[cfg(test)]
mod tests {
    use super::{BACKGROUND, MAX_HEARTBEAT_MS, draw, parse_heartbeat, parse_origin, parse_size};
    use openstream_media::probe::{detect, marker_height, marker_width};

    /// What the helper draws is what the client reads. If this ever stops
    /// holding, every interaction measurement silently becomes a count of
    /// markers that were never recognised.
    #[test]
    fn what_the_helper_draws_is_what_the_client_reads() {
        let (width, height) = (640, 480);
        let mut buffer = vec![BACKGROUND; width * height];
        for probe_id in [0_u16, 1, 2, 255, 4_096, u16::MAX] {
            draw(&mut buffer, width, height, (0, 0), probe_id);
            assert_eq!(
                detect(&buffer, width, height, (0, 0)),
                Some(probe_id),
                "probe {probe_id} did not round-trip"
            );
        }
    }

    /// The marker does not have to be at the corner, as long as both sides
    /// agree on where it is.
    #[test]
    fn an_offset_marker_round_trips_at_its_own_origin() {
        let (width, height) = (640, 480);
        let origin = (96, 48);
        let mut buffer = vec![BACKGROUND; width * height];
        draw(&mut buffer, width, height, origin, 1_234);

        assert_eq!(detect(&buffer, width, height, origin), Some(1_234));
        // Read at the wrong place it finds nothing, rather than a wrong id.
        assert_eq!(detect(&buffer, width, height, (0, 0)), None);
    }

    /// The human-visible bar must not overlap the marker the client reads.
    #[test]
    fn the_operator_bar_does_not_overwrite_the_marker() {
        let (width, height) = (640, 480);
        let mut buffer = vec![BACKGROUND; width * height];
        draw(&mut buffer, width, height, (0, 0), 0xFFFF);
        // Every bit set means every bar segment is lit; the marker still
        // reads, so the bar is genuinely outside it.
        assert_eq!(detect(&buffer, width, height, (0, 0)), Some(0xFFFF));
        assert!(marker_width() > 0 && marker_height() > 0);
    }

    /// Redrawing clears the previous marker rather than leaving fragments of
    /// it behind, which would decode as a torn payload.
    #[test]
    fn a_redraw_replaces_the_previous_marker() {
        let (width, height) = (640, 480);
        let mut buffer = vec![BACKGROUND; width * height];
        draw(&mut buffer, width, height, (0, 0), 7);
        draw(&mut buffer, width, height, (0, 0), 8);
        assert_eq!(detect(&buffer, width, height, (0, 0)), Some(8));
    }

    #[test]
    fn a_surface_size_is_parsed_or_refused() {
        assert_eq!(parse_size("1920x1080").expect("valid"), (1920, 1080));
        assert_eq!(parse_size(" 2560 X 1440 ").expect("valid"), (2560, 1440));
        assert!(parse_size("1920").is_err());
        assert!(parse_size("0x1080").is_err(), "a zero surface is refused");
        assert!(
            parse_size("999999x1080").is_err(),
            "a mistyped size must not ask for a multi-gigabyte buffer"
        );
    }

    /// A heartbeat slower than the stream makes the probe measure a stream
    /// nobody would run, and a zero heartbeat stops the capture entirely.
    #[test]
    fn a_heartbeat_is_parsed_or_refused() {
        assert_eq!(
            parse_heartbeat("16").expect("valid").as_millis(),
            16,
            "a 60Hz heartbeat is the default shape"
        );
        assert!(
            parse_heartbeat("0").is_err(),
            "a still helper stops capture"
        );
        assert!(parse_heartbeat(&(MAX_HEARTBEAT_MS + 1).to_string()).is_err());
        assert!(parse_heartbeat("fast").is_err());
    }

    #[test]
    fn an_origin_is_parsed_or_refused() {
        assert_eq!(parse_origin("0,0").expect("valid"), (0, 0));
        assert_eq!(parse_origin(" 96 , 48 ").expect("valid"), (96, 48));
        assert!(parse_origin("96").is_err());
        assert!(parse_origin("-1,0").is_err());
    }
}
