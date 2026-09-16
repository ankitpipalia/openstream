//! Vendor-neutral in-process H.264 codec on Windows via Media Foundation.
//!
//! This crate is the Windows counterpart to the macOS VideoToolbox path: it
//! decodes and encodes H.264 in-process, with no external ffmpeg subprocess,
//! using the OS Media Foundation transforms. Those MFTs drive the NVIDIA/AMD/
//! Intel hardware codecs through the OS and fall back to OS software codecs, so
//! this is preferred over any single vendor SDK.
//!
//! - [`MediaFoundationH264Decoder`] turns Annex-B H.264 access units into BGRA
//!   frames (the client decode path).
//! - [`MediaFoundationH264Encoder`] turns NV12 frames into H.264 access units
//!   (the host encode path).
//!
//! The pixel-format conversion the MFTs need is in the private, cross-platform
//! `nv12` module, unit-tested on every target; the Media Foundation FFI is
//! Windows-only and exercised against the real MFTs on the Windows CI job.

mod nv12;

#[cfg(target_os = "windows")]
mod mf_decoder;
#[cfg(target_os = "windows")]
mod mf_encoder;
#[cfg(target_os = "windows")]
mod mf_startup;

#[cfg(target_os = "windows")]
pub use mf_decoder::{MediaFoundationH264Decoder, MfError, MfFrame};
#[cfg(target_os = "windows")]
pub use mf_encoder::{EncodedAccessUnit, MediaFoundationH264Encoder, MfEncError};
