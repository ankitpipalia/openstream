//! Where the macOS host's per-frame time actually goes.
//!
//! The live session rig showed the host spending ~85 ms between the encoder's
//! first byte and a complete access unit, delivering about 11 fps against a
//! requested 60 -- an order of magnitude more than anything on the client. That
//! number says the host is slow; it does not say which part is. This splits it.
//!
//! The three stages, in the order a frame meets them:
//!
//!   1. `CGDisplayCreateImage` plus `CGDataProviderCopyData`, which snapshots
//!      the display and hands back a copy of the whole framebuffer;
//!   2. `pack_bgra_rows`, which copies it again to drop stride padding;
//!   3. the VideoToolbox encode itself, which copies the BGRA into a pixel
//!      buffer before the hardware sees it.
//!
//! Stage 1 is measured by subtraction: `capture()` is stages 1 and 2 together,
//! and stage 2 is timed directly on a buffer of the same shape. Subtraction is
//! honest here because the two are sequential inside one call with nothing else
//! between them.
//!
//! Run: `cargo run --release -p openstream-macos-host --example capture_timing`
//! (release matters -- the row copy is the thing being measured, and a debug
//! build would report the compiler's slowness rather than the API's).

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use openstream_macos_host::capture::{ScreenCapture, pack_bgra_rows};
    use openstream_macos_media::VideoToolboxH264Encoder;
    use std::time::Instant;

    const FRAMES: usize = 30;
    // What the live rig negotiated, so these numbers line up with its logs.
    const STREAM_WIDTH: u32 = 1920;
    const STREAM_HEIGHT: u32 = 1080;

    let mut capture = ScreenCapture::main();
    // The first capture pays for the TCC check and the framebuffer setup, and
    // including it would blame the steady state for one-off cost.
    let first = match capture.capture() {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("capture failed: {error}");
            eprintln!("grant Screen Recording to the terminal running this and retry");
            return std::process::ExitCode::from(2);
        }
    };
    let (width, height) = (first.width, first.height);
    let stride = width * 4;
    let source = vec![0u8; stride * height];

    let mut encoder =
        match VideoToolboxH264Encoder::new(STREAM_WIDTH, STREAM_HEIGHT, 60, 10_000_000) {
            Ok(encoder) => encoder,
            Err(error) => {
                eprintln!("videotoolbox encoder unavailable: {error}");
                return std::process::ExitCode::from(2);
            }
        };
    let stream_bytes = (STREAM_WIDTH as usize) * (STREAM_HEIGHT as usize) * 4;

    let mut capture_us = Vec::with_capacity(FRAMES);
    let mut pack_us = Vec::with_capacity(FRAMES);
    let mut encode_us = Vec::with_capacity(FRAMES);
    for index in 0..FRAMES {
        let started = Instant::now();
        let frame = match capture.capture() {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("capture failed mid-run: {error}");
                return std::process::ExitCode::from(2);
            }
        };
        capture_us.push(started.elapsed().as_micros());

        let started = Instant::now();
        let packed = pack_bgra_rows(&source, width, height, stride);
        pack_us.push(started.elapsed().as_micros());
        std::hint::black_box(packed.len());

        // Encode a buffer of the negotiated size. The content does not change
        // what the copy-and-submit costs, and using the captured frame would
        // add the scale step this stage does not own.
        let payload = &frame.bgra[..stream_bytes.min(frame.bgra.len())];
        if payload.len() == stream_bytes {
            let started = Instant::now();
            match encoder.encode(payload, index as i64 * 16_667) {
                Ok(units) => {
                    encode_us.push(started.elapsed().as_micros());
                    std::hint::black_box(units.len());
                }
                Err(error) => {
                    eprintln!("encode failed: {error}");
                    return std::process::ExitCode::from(2);
                }
            }
        }
    }

    let mean = |values: &[u128]| -> u128 {
        if values.is_empty() {
            0
        } else {
            values.iter().sum::<u128>() / values.len() as u128
        }
    };
    let capture_mean = mean(&capture_us);
    let pack_mean = mean(&pack_us);
    let encode_mean = mean(&encode_us);
    // `capture()` is the CoreGraphics call plus the pack, in that order.
    let cg_mean = capture_mean.saturating_sub(pack_mean);

    println!(
        "display {width}x{height} ({} MB per frame)",
        stride * height / (1024 * 1024)
    );
    println!("samples {FRAMES}");
    println!("  CGDisplayCreateImage + CopyData  {cg_mean:>7} us   (capture minus pack)");
    println!("  pack_bgra_rows                   {pack_mean:>7} us");
    println!("  capture() total                  {capture_mean:>7} us");
    println!("  VideoToolbox encode @ {STREAM_WIDTH}x{STREAM_HEIGHT}     {encode_mean:>7} us");
    println!(
        "  host frame budget at 60 fps       16667 us; this path needs {} us",
        capture_mean + encode_mean
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("capture_timing measures the macOS host path and only runs there");
}
