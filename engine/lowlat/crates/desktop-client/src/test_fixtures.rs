//! Shared test fixtures: generate real H.264 with ffmpeg and split it into
//! access units. Used by the VideoToolbox decoder tests and the decode
//! loopback harness so both drive genuine bitstreams rather than hand-rolled
//! bytes.

use std::process::Command;

/// The ffmpeg binary to drive, honouring `OPENSTREAM_FFMPEG`.
pub(crate) fn ffmpeg() -> String {
    std::env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string())
}

/// When set, a missing/failed ffmpeg fixture is a hard failure rather than a
/// skip — so a hardware-acceptance run cannot pass by silently not running.
pub(crate) fn require_vt_test() -> bool {
    std::env::var_os("OPENSTREAM_REQUIRE_VT_TEST").is_some()
}

/// Generate an Annex-B H.264 clip: one keyframe every `gop` frames, no
/// B-frames (so decode order is display order), and AUDs so access units split
/// cleanly. Returns `None` to skip when ffmpeg is unavailable, unless
/// `OPENSTREAM_REQUIRE_VT_TEST` forces a failure.
pub(crate) fn generate_h264(source: &str, frames: u32, gop: u32) -> Option<Vec<u8>> {
    let frames_s = frames.to_string();
    let gop_s = gop.to_string();
    let result = Command::new(ffmpeg())
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            source,
            "-frames:v",
            &frames_s,
            "-c:v",
            "libx264",
            "-bf",
            "0",
            "-g",
            &gop_s,
            "-keyint_min",
            &gop_s,
            "-pix_fmt",
            "yuv420p",
            "-x264-params",
            "aud=1",
            "-f",
            "h264",
            "-",
        ])
        .output();
    match result {
        Ok(out) if out.status.success() && !out.stdout.is_empty() => Some(out.stdout),
        other => {
            let detail = match &other {
                Ok(out) => String::from_utf8_lossy(&out.stderr).into_owned(),
                Err(error) => error.to_string(),
            };
            assert!(
                !require_vt_test(),
                "OPENSTREAM_REQUIRE_VT_TEST is set but ffmpeg could not produce a fixture: {detail}"
            );
            eprintln!("ffmpeg unavailable ({detail}); skipping test");
            None
        }
    }
}

/// Split an Annex-B elementary stream into access units on AUD (type 9)
/// boundaries. Valid for streams generated with `aud=1`.
pub(crate) fn access_units_by_aud(stream: &[u8]) -> Vec<Vec<u8>> {
    let mut aud_offsets: Vec<usize> = Vec::new();
    let mut p = 0usize;
    while p + 4 <= stream.len() {
        if stream[p] == 0 && stream[p + 1] == 0 && stream[p + 2] == 1 {
            if stream[p + 3] & 0x1f == 9 {
                // Include a preceding zero (4-byte start code) if present.
                let start = if p > 0 && stream[p - 1] == 0 {
                    p - 1
                } else {
                    p
                };
                aud_offsets.push(start);
            }
            p += 3;
        } else {
            p += 1;
        }
    }
    let mut units = Vec::new();
    for (k, &start) in aud_offsets.iter().enumerate() {
        let end = aud_offsets.get(k + 1).copied().unwrap_or(stream.len());
        units.push(stream[start..end].to_vec());
    }
    units
}
