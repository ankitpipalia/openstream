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

#[cfg(target_os = "macos")]
mod vt_encoder;

#[cfg(target_os = "macos")]
pub use vt_encoder::{EncodedAccessUnit, VideoToolboxH264Encoder, VtEncError};
