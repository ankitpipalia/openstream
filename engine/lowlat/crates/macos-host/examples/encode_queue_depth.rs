//! Is VideoToolbox actually holding frames?
//!
//! Apple documents the compression session's default frame-delay window as
//! *unlimited*. That is a statement about what the encoder is permitted to do,
//! not about what it does: an encoder allowed to buffer thirty frames may still
//! emit each one as it arrives. Before constraining the window -- or reaching
//! for any of the other latency knobs -- it is worth knowing which of the two
//! this machine is doing, because only one of them has any latency to recover.
//!
//! So this measures, over a live ScreenCaptureKit session at the stream size
//! the product negotiates:
//!
//!   * `NumberOfPendingFrames` sampled straight after each submit -- how many
//!     frames the session is holding at that instant;
//!   * submit-to-access-unit latency, the encoder's own contribution;
//!   * capture-to-access-unit latency, which adds the time the frame spent
//!     waiting to be picked up;
//!   * access-unit size, since anything that trades quality for speed shows up
//!     here first;
//!   * submitted frames against emitted access units, so a frame the encoder
//!     dropped is visible rather than averaged away.
//!
//! It also prints which of the optional properties the session accepted, so a
//! number can be read against the settings that produced it rather than the
//! settings that were requested.
//!
//! **Pairing output with input.** An access unit carries no timestamp back, so
//! the nth emitted unit is charged to the nth submitted frame. That holds only
//! because the session runs with frame reordering off, which makes output order
//! equal input order. If that ever changes, this pairing goes with it.
//!
//! Run: `cargo run --release -p openstream-macos-host --example encode_queue_depth`
//! (release matters: a debug build would report the compiler's slowness rather
//! than the encoder's).

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use openstream_macos_host::sck::{SckCapture, SckConfig};
    use openstream_macos_media::VideoToolboxH264Encoder;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    const STREAM_WIDTH: u32 = 1920;
    const STREAM_HEIGHT: u32 = 1080;
    const FPS: u32 = 60;
    const BITRATE: u32 = 10_000_000;
    const RUN_SECONDS: u64 = 10;
    /// The same pair the host uses: how long to wait for a frame in total, and
    /// how long to block on the stream before looking at the encoder again.
    const FRAME_WAIT: Duration = Duration::from_millis(100);
    const DRAIN_SLICE: Duration = Duration::from_millis(2);

    fn mean(values: &[u128]) -> u128 {
        if values.is_empty() {
            0
        } else {
            values.iter().sum::<u128>() / values.len() as u128
        }
    }

    /// The value at `percent` of the way through a sorted copy of `values`.
    ///
    /// Integer arithmetic throughout: a float index needs a cast back to
    /// `usize` that is only ever correct by inspection.
    fn percentile(values: &[u128], percent: usize) -> u128 {
        if values.is_empty() {
            return 0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let index = (sorted.len() - 1) * percent / 100;
        sorted[index]
    }

    let mut encoder = match VideoToolboxH264Encoder::new(STREAM_WIDTH, STREAM_HEIGHT, FPS, BITRATE)
    {
        Ok(encoder) => encoder,
        Err(error) => {
            eprintln!("VideoToolbox encoder unavailable: {error}");
            return std::process::ExitCode::from(2);
        }
    };

    // Read the settings back before measuring anything, so the report says what
    // was actually in force. Every one of these is optional; a `no` here is a
    // fact about this machine, not a failure.
    let low_latency = encoder.low_latency_rate_control();
    let frame_delay = encoder.max_frame_delay();
    let speed_hint = encoder.prioritises_speed();
    let pending_at_rest = encoder.pending_frames();
    let rate_limit = encoder.data_rate_limit();

    let stream = match SckCapture::start(SckConfig {
        width: STREAM_WIDTH,
        height: STREAM_HEIGHT,
        fps: FPS,
        display_id: None,
        show_cursor: true,
    }) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("ScreenCaptureKit capture failed: {error}");
            eprintln!("grant Screen Recording to the terminal running this and retry");
            return std::process::ExitCode::from(2);
        }
    };

    let mut pending = Vec::new();
    // Queue depth sampled just before the next submit, after the wait. If the
    // encoder finishes a frame on its own thread, this is where it shows: the
    // depth falls and `take_ready` returns something. If it stays up and
    // returns nothing, the encoder really is holding the frame until the next
    // one arrives, and no amount of draining will help.
    let mut pending_before = Vec::new();
    let mut ready_without_submit = 0usize;
    let mut encode_us = Vec::new();
    let mut capture_us = Vec::new();
    let mut au_bytes = Vec::new();
    // Submit and capture instants for frames the encoder has not answered for
    // yet. Drained in order as access units come out.
    let mut in_flight: VecDeque<(Instant, Instant)> = VecDeque::new();
    let mut submitted = 0usize;
    let mut emitted = 0usize;
    let mut submit_failures = 0usize;

    let started_at = Instant::now();
    let deadline = started_at + Duration::from_secs(RUN_SECONDS);
    while Instant::now() < deadline {
        // Wait for the next frame the way the host now does: in short slices,
        // checking the encoder between them, so a finished access unit is
        // collected when it exists rather than when the next capture happens
        // to arrive. Measuring any other way would report the bug instead of
        // the behaviour.
        let mut frame = None;
        let wait_deadline = Instant::now() + FRAME_WAIT;
        loop {
            if let Some(depth) = encoder.pending_frames() {
                pending_before.push(depth);
            }
            let early = encoder.take_ready();
            if !early.is_empty() {
                ready_without_submit += early.len();
                let now = Instant::now();
                for unit in early {
                    if let Some((submit, capture)) = in_flight.pop_front() {
                        encode_us.push((now - submit).as_micros());
                        capture_us.push((now - capture).as_micros());
                    }
                    au_bytes.push(unit.data.len() as u128);
                    emitted += 1;
                }
            }
            if let Some(surface) = stream.wait_frame(DRAIN_SLICE) {
                frame = Some(surface);
                break;
            }
            if Instant::now() >= wait_deadline {
                break;
            }
        }
        let Some(frame) = frame else {
            // A still screen delivers nothing. Not an error, and not a stall.
            continue;
        };
        let captured_at = Instant::now();
        let pts = i64::try_from(started_at.elapsed().as_micros()).unwrap_or(i64::MAX);

        let submitted_at = Instant::now();
        // SAFETY: the frame holds a retain on its pixel buffer for as long as
        // it is alive, and it outlives this call.
        let units = unsafe { encoder.encode_surface(frame.as_ptr(), pts) };
        let units = match units {
            Ok(units) => {
                submitted += 1;
                in_flight.push_back((submitted_at, captured_at));
                units
            }
            Err(error) => {
                submit_failures += 1;
                eprintln!("encode failed: {error}");
                Vec::new()
            }
        };

        // Sample the queue depth right after the submit: this is the number the
        // whole exercise is about.
        if let Some(depth) = encoder.pending_frames() {
            pending.push(depth);
        }

        let now = Instant::now();
        for unit in units {
            if let Some((submit, capture)) = in_flight.pop_front() {
                encode_us.push((now - submit).as_micros());
                capture_us.push((now - capture).as_micros());
            }
            au_bytes.push(unit.data.len() as u128);
            emitted += 1;
        }
    }

    let delivered = stream.delivered();
    drop(stream);

    // Anything still held at the end comes out now; without this the last few
    // frames would read as dropped.
    let flushed = encoder.flush().unwrap_or_default();
    let flushed_count = flushed.len();
    for unit in flushed {
        au_bytes.push(unit.data.len() as u128);
        emitted += 1;
    }

    // ---- report ----
    println!("{STREAM_WIDTH}x{STREAM_HEIGHT} at {FPS} fps, {BITRATE} bps, {RUN_SECONDS}s");
    println!();
    println!("session properties actually in force:");
    println!(
        "  low-latency rate control         {}",
        if low_latency {
            "yes"
        } else {
            "no (encoder specification refused)"
        }
    );
    println!(
        "  MaxFrameDelayCount               {}",
        frame_delay.map_or_else(
            || "not set (every rung refused; default window)".to_owned(),
            |value| value.to_string()
        )
    );
    println!(
        "  speed over quality               {}",
        if speed_hint {
            "yes"
        } else {
            "no (property refused)"
        }
    );
    println!(
        "  DataRateLimits (bytes / second)  {}",
        rate_limit.map_or_else(
            || "not set (property refused)".to_owned(),
            |bytes| format!(
                "{bytes} ({:.2} Mbps ceiling)",
                bytes as f64 * 8.0 / 1_000_000.0
            )
        )
    );
    println!(
        "  NumberOfPendingFrames readable   {}",
        if pending_at_rest.is_some() {
            "yes"
        } else {
            "no"
        }
    );
    println!();

    if pending.is_empty() {
        println!("queue depth: the session did not report NumberOfPendingFrames.");
        println!("  nothing here says whether it buffers; the latency figures below still hold.");
    } else {
        let max = pending.iter().copied().max().unwrap_or(0);
        let sum: i64 = pending.iter().sum();
        let at_zero = pending.iter().filter(|value| **value == 0).count();
        println!("queue depth after submit ({} samples):", pending.len());
        println!("  max                              {max}");
        println!(
            "  mean                             {:.2}",
            sum as f64 / pending.len() as f64
        );
        println!(
            "  samples reading zero             {at_zero} of {} ({:.0}%)",
            pending.len(),
            100.0 * at_zero as f64 / pending.len() as f64
        );
        if max == 0 {
            println!("  -> the encoder never held a frame. Constraining the window would");
            println!("     remove latency that is not there; look elsewhere.");
        } else {
            println!("  -> the encoder does hold frames, so the window is worth constraining.");
        }
    }
    println!();

    if !pending_before.is_empty() {
        let max_before = pending_before.iter().copied().max().unwrap_or(0);
        let sum_before: i64 = pending_before.iter().sum();
        let zero_before = pending_before.iter().filter(|value| **value == 0).count();
        println!(
            "queue depth before the next submit ({} samples):",
            pending_before.len()
        );
        println!("  max                              {max_before}");
        println!(
            "  mean                             {:.2}",
            sum_before as f64 / pending_before.len() as f64
        );
        println!("  samples reading zero             {zero_before}");
        println!("  access units found without submitting  {ready_without_submit}");
        if ready_without_submit > 0 {
            println!("  -> the encoder finishes on its own thread. A caller that drains only");
            println!("     while submitting holds finished frames for a whole inter-frame gap.");
        } else {
            println!("  -> nothing was ever ready between submits: the encoder really does");
            println!("     hold each frame until the next arrives. Draining cannot help.");
        }
        println!();
    }

    println!("latency ({} paired frames):", encode_us.len());
    println!(
        "  submit -> access unit            mean {:>7} us   p95 {:>7} us   max {:>7} us",
        mean(&encode_us),
        percentile(&encode_us, 95),
        encode_us.iter().copied().max().unwrap_or(0)
    );
    println!(
        "  capture -> access unit           mean {:>7} us   p95 {:>7} us   max {:>7} us",
        mean(&capture_us),
        percentile(&capture_us, 95),
        capture_us.iter().copied().max().unwrap_or(0)
    );
    println!();

    println!("throughput:");
    println!(
        "  delivered by the compositor      {delivered} ({:.1}/s)",
        delivered as f64 / RUN_SECONDS as f64
    );
    println!("  submitted to the encoder         {submitted}");
    println!(
        "  access units out                 {emitted} ({flushed_count} of them from the flush)"
    );
    println!(
        "  never answered for               {}",
        submitted.saturating_sub(emitted)
    );
    println!("  submit failures                  {submit_failures}");
    println!(
        "  access-unit size                 mean {:>7} B   p95 {:>7} B",
        mean(&au_bytes),
        percentile(&au_bytes, 95)
    );
    println!();
    println!("  a {FPS} fps frame budget is {} us", 1_000_000 / FPS);

    if submitted == 0 {
        eprintln!("nothing was submitted; the screen was still for the whole run");
        return std::process::ExitCode::from(1);
    }
    if submit_failures > 0 {
        eprintln!("the encoder rejected {submit_failures} frames");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("encode_queue_depth measures a VideoToolbox session and only runs on macOS");
}
