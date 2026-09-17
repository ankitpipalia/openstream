//! In-process H.264 encode on macOS via Apple VideoToolbox.
//!
//! The host counterpart to the client's VideoToolbox decoder: it turns captured
//! BGRA frames into an H.264 elementary stream in-process, with no external
//! ffmpeg subprocess, using a `VTCompressionSession` driven onto the hardware
//! encoder. It is the macOS equivalent of the Windows Media Foundation encoder
//! (`openstream-macos-media` mirrors `openstream-windows-media`).
//!
//! [`VideoToolboxH264Encoder`] takes BGRA frames (what macOS screen capture
//! delivers) and returns Annex-B H.264 access units, prepending the SPS/PPS to
//! each keyframe so a decoder can start from any of them.
//!
//! It accepts those frames two ways. `encode` takes packed BGRA bytes and
//! copies them into a pixel buffer for the hardware; `encode_surface` takes a
//! `CVPixelBuffer` the caller already holds and copies nothing, which is the
//! path for a capture source that hands back IOSurface-backed buffers.

#[cfg(target_os = "macos")]
mod vt_encoder;

#[cfg(target_os = "macos")]
pub use vt_encoder::{CvImageBufferRef, EncodedAccessUnit, VideoToolboxH264Encoder, VtEncError};
