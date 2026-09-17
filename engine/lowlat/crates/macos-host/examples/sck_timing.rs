//! The two macOS capture paths, measured side by side on this machine.
//!
//! The question this answers is not "is ScreenCaptureKit faster" in the
//! abstract; it is how much of a 60 fps frame budget each path spends before
//! the encoder has anything to work with, at the same output size.
//!
//! The two are not symmetrical, and the output says so:
//!
//!   * CoreGraphics is a *poll*. Each call snapshots the display, copies the
//!     framebuffer out, and copies it again to drop stride padding -- and it
//!     delivers the display's native resolution, so a 1920x1080 stream still
//!     owes a CPU rescale afterwards, which this also times.
//!   * ScreenCaptureKit is a *stream*. The compositor delivers frames when
//!     content changes, already scaled, as IOSurface-backed pixel buffers. The
//!     per-frame cost to the host is taking one out of a slot; there is no
//!     copy and no rescale to measure, so what is reported instead is the
//!     delivery rate and that every frame really was IOSurface-backed.
//!
//! Run: `cargo run --release -p openstream-macos-host --example sck_timing`
//! (release matters -- the copies are the thing being measured, and a debug
//! build would report the compiler's slowness rather than the API's).

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use openstream_macos_host::capture::{ScreenCapture, pack_bgra_rows};
    use openstream_macos_host::sck::{SckCapture, SckConfig, is_expected_format, surface_format};
    use std::time::{Duration, Instant};

    const FRAMES: usize = 30;
    const STREAM_WIDTH: u32 = 1920;
    const STREAM_HEIGHT: u32 = 1080;
    const STREAM_SECONDS: u64 = 3;

    fn mean(values: &[u128]) -> u128 {
        if values.is_empty() {
            0
        } else {
            values.iter().sum::<u128>() / values.len() as u128
        }
    }

    // ---- CoreGraphics ----
    let mut capture = ScreenCapture::main();
    // The first call pays the TCC check and framebuffer setup; charging the
    // steady state for one-off cost would flatter neither path honestly.
    let first = match capture.capture() {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("CoreGraphics capture failed: {error}");
            eprintln!("grant Screen Recording to the terminal running this and retry");
            return std::process::ExitCode::from(2);
        }
    };
    let (native_width, native_height) = (first.width, first.height);
    let stride = native_width * 4;
    let scratch = vec![0u8; stride * native_height];

    let mut cg_capture_us = Vec::with_capacity(FRAMES);
    let mut cg_pack_us = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        let started = Instant::now();
        if capture.capture().is_err() {
            eprintln!("CoreGraphics capture failed mid-run");
            return std::process::ExitCode::from(2);
        }
        cg_capture_us.push(started.elapsed().as_micros());

        let started = Instant::now();
        let packed = pack_bgra_rows(&scratch, native_width, native_height, stride);
        cg_pack_us.push(started.elapsed().as_micros());
        std::hint::black_box(packed.len());
    }

    // ---- ScreenCaptureKit ----
    let config = SckConfig {
        width: STREAM_WIDTH,
        height: STREAM_HEIGHT,
        fps: 60,
        display_id: None,
        show_cursor: true,
    };
    let stream = match SckCapture::start(config) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("ScreenCaptureKit capture failed: {error}");
            return std::process::ExitCode::from(2);
        }
    };

    let mut take_us = Vec::new();
    let mut taken = 0usize;
    let mut wrong_format = 0usize;
    let deadline = Instant::now() + Duration::from_secs(STREAM_SECONDS);
    while Instant::now() < deadline {
        let started = Instant::now();
        let frame = stream.take_frame();
        match frame {
            Some(frame) => {
                take_us.push(started.elapsed().as_micros());
                taken += 1;
                // SAFETY: the frame holds a retain on its pixel buffer.
                if !is_expected_format(unsafe { surface_format(&frame) }) {
                    wrong_format += 1;
                }
            }
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    let delivered = stream.delivered();
    drop(stream);

    // ---- report ----
    let cg_capture = mean(&cg_capture_us);
    let cg_pack = mean(&cg_pack_us);
    let cg_cg_only = cg_capture.saturating_sub(cg_pack);
    println!("display {native_width}x{native_height}, stream {STREAM_WIDTH}x{STREAM_HEIGHT}");
    println!();
    println!("CoreGraphics poll ({FRAMES} frames, native resolution):");
    println!("  CGDisplayCreateImage + CopyData  {cg_cg_only:>7} us   (capture minus pack)");
    println!("  pack_bgra_rows                   {cg_pack:>7} us");
    println!("  capture() total                  {cg_capture:>7} us");
    println!("  + a CPU rescale to the stream size, and the encoder's own copy");
    println!();
    println!("ScreenCaptureKit stream ({STREAM_SECONDS}s, already scaled):");
    println!(
        "  take_frame()                     {:>7} us",
        mean(&take_us)
    );
    println!(
        "  delivered {delivered} frames ({:.1}/s), {taken} taken",
        delivered as f64 / STREAM_SECONDS as f64
    );
    println!("  frames in an unexpected format: {wrong_format}");
    println!("  no copy and no rescale: the encoder takes the surface as it is");
    println!(
        "  the rate follows screen activity, not the clock: a still desktop\n\
         \x20 delivers a handful a second and a moving one approaches the cap,\n\
         \x20 so a low number here is not a slow path -- it is a quiet screen\n\
         \x20 (which is also why the host will still need a keepalive)"
    );
    println!();
    println!("  a 60 fps frame budget is 16667 us");

    if wrong_format > 0 {
        eprintln!("some frames were not BGRA; the encoder would misread them");
        return std::process::ExitCode::from(1);
    }
    if delivered == 0 {
        eprintln!("the stream delivered nothing; nothing was measured");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("sck_timing measures the macOS capture paths and only runs there");
}
