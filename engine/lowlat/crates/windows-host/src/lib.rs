//! Native Windows host subsystems for OpenStream.
//!
//! Each subsystem is an isolated, capability-gated vertical slice using native
//! OS APIs (no per-vendor SDKs): Desktop Duplication capture, and (to follow)
//! SendInput injection, WASAPI loopback audio, and the service/Job-Object
//! lifecycle. Pure logic in each is unit-tested on every target; the OS FFI is
//! compiled and checked for the Windows targets.
//!
//! Status: implemented and CI-validated (compiles for the Windows targets; pure
//! logic unit-tested). Physical Windows runtime verification is pending the
//! hardware, and none of these are production defaults until then.

pub mod audio;
pub mod capture;
pub mod input;
pub mod lifecycle;
