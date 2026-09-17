//! Native macOS host subsystems for OpenStream.
//!
//! Two screen-capture paths, both native and neither needing ffmpeg.
//!
//! [`sck`] is the fast one: ScreenCaptureKit delivers IOSurface-backed
//! `CVPixelBuffer`s, already scaled to the requested size by the compositor,
//! and `VTCompressionSessionEncodeFrame` takes such a buffer directly. Capture
//! reaches the hardware encoder with no CPU copy and no rescale. It needs the
//! Objective-C runtime, because ScreenCaptureKit has no C API.
//!
//! [`capture`] is the original: polling `CGDisplayCreateImage` for tightly
//! packed BGRA. It copies the framebuffer out of CoreGraphics, copies it again
//! to drop stride padding, and leaves the caller to rescale. Measured on an M1
//! Max at 3456x2234 the CoreGraphics call alone is 14.3 ms -- 86% of a 60 fps
//! frame budget, against 0.5 ms for the hardware encode it feeds -- and the API
//! is deprecated in favour of ScreenCaptureKit. It stays as the fallback for
//! systems where the stream cannot start.
//!
//! Both require the Screen Recording permission (TCC). Without it the OS
//! returns no image and no shareable content, surfaced as
//! [`capture::CaptureError::Unavailable`] and [`sck::SckError::NoShareableContent`]
//! rather than as a black frame.

#[cfg(target_os = "macos")]
pub mod capture;

#[cfg(target_os = "macos")]
mod objc_runtime;

#[cfg(target_os = "macos")]
pub mod sck;
