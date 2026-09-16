//! Native macOS host subsystems for OpenStream.
//!
//! Currently: screen capture via CoreGraphics `CGDisplayCreateImage`, the
//! lowest-dependency native path (no ScreenCaptureKit / Objective-C runtime).
//! It delivers tightly packed BGRA frames -- exactly what the VideoToolbox
//! encoder in `openstream-macos-media` takes -- so a macOS host is
//! capture -> `bgra_to_nv12`-free BGRA -> VideoToolbox H.264, with no ffmpeg.
//!
//! `CGDisplayCreateImage` is a polling API (and deprecated in favour of
//! ScreenCaptureKit), which is fine for a first native capture; the
//! low-latency follow-up is `CGDisplayStream` or ScreenCaptureKit. Capture
//! requires the Screen Recording permission (TCC): without it the OS returns no
//! image, surfaced here as [`capture::CaptureError::Unavailable`] rather than a
//! black frame.

#[cfg(target_os = "macos")]
pub mod capture;
