//! The native macOS host path end to end, with no ffmpeg: capture the screen
//! (CoreGraphics) and hardware-encode it (VideoToolbox), proving the two crates
//! work together and produce a real H.264 elementary stream.
//!
//! It captures the main display, builds a `VideoToolboxH264Encoder` at the
//! captured geometry, encodes a run of frames, and reports the access units,
//! bytes, and keyframes plus whether the sequence header (SPS/PPS) is present. A
//! denied Screen Recording permission surfaces as a capture error; a working
//! path reports a non-empty stream with at least one keyframe.
//!
//! Run: `cargo run -p openstream-macos-host --example capture_encode_loopback`

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use openstream_macos_host::capture::ScreenCapture;
    use openstream_macos_media::VideoToolboxH264Encoder;

    let mut capture = ScreenCapture::main();
    let first = match capture.capture() {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("capture_encode_loopback: capture failed: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let (Ok(width), Ok(height)) = (u32::try_from(first.width), u32::try_from(first.height)) else {
        eprintln!("capture_encode_loopback: implausible capture dimensions");
        return std::process::ExitCode::from(2);
    };
    eprintln!("capture_encode_loopback: capturing {width}x{height}");

    // 10 Mbps, 60 fps, at the captured geometry.
    let mut encoder = match VideoToolboxH264Encoder::new(width, height, 60, 10_000_000) {
        Ok(encoder) => encoder,
        Err(error) => {
            eprintln!("capture_encode_loopback: encoder init failed: {error}");
            return std::process::ExitCode::from(3);
        }
    };

    let mut access_units = 0_u64;
    let mut bytes = 0_u64;
    let mut keyframes = 0_u64;
    let mut pts_us = 0_i64;
    let frame_interval_us = 1_000_000 / 60;

    let mut record = |units: Vec<openstream_macos_media::EncodedAccessUnit>| {
        for unit in units {
            access_units += 1;
            bytes += u64::try_from(unit.data.len()).unwrap_or(u64::MAX);
            if unit.keyframe {
                keyframes += 1;
            }
        }
    };

    for index in 0..60 {
        let frame = if index == 0 {
            first.clone()
        } else {
            match capture.capture() {
                Ok(frame) => frame,
                Err(_) => continue,
            }
        };
        // The encoder is fixed to the first geometry; skip a frame if the display
        // changed size mid-run rather than feeding a mismatched buffer.
        if u32::try_from(frame.width) != Ok(width) || u32::try_from(frame.height) != Ok(height) {
            continue;
        }
        match encoder.encode(&frame.bgra, pts_us) {
            Ok(units) => record(units),
            Err(error) => {
                eprintln!("capture_encode_loopback: encode failed: {error}");
                return std::process::ExitCode::from(4);
            }
        }
        pts_us += frame_interval_us;
    }
    match encoder.flush() {
        Ok(units) => record(units),
        Err(error) => {
            eprintln!("capture_encode_loopback: flush failed: {error}");
            return std::process::ExitCode::from(4);
        }
    }

    let has_sequence_header = encoder
        .sequence_header()
        .is_some_and(|header| !header.is_empty());
    println!(
        "{{\"width\": {width}, \"height\": {height}, \"access_units\": {access_units}, \"bytes\": {bytes}, \"keyframes\": {keyframes}, \"sequence_header\": {has_sequence_header}}}"
    );

    if access_units > 0 && keyframes > 0 && has_sequence_header {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("capture_encode_loopback: incomplete stream (no keyframe or sequence header)");
        std::process::ExitCode::from(5)
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("capture_encode_loopback is macOS-only");
}
