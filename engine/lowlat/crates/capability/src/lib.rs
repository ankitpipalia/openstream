//! Capability registry and pipeline planner for OpenStream 1.1.
//!
//! # Why this crate exists
//!
//! Through 1.0, what a host could capture and encode was answered by
//! *compile-time* facts: `cfg!(target_os = ...)` flags and flat booleans like a
//! single `nvenc_h264`. That produces two lies. First, a binary built for a
//! platform claims the platform's hardware whether or not the running machine
//! has it — a Windows build reports itself host-capable before a single capture
//! backend exists. Second, a flat boolean cannot describe a machine with more
//! than one GPU, or tell "this encoder exists in the abstract" from "this
//! encoder started successfully here five seconds ago".
//!
//! This crate replaces those flags with *runtime, per-device, probed* records.
//!
//! # The shape of it
//!
//! - A backend describes itself with a [`CaptureCapability`] or
//!   [`EncoderCapability`] [record]: which device it drives, which
//!   codecs and pixel formats it handles, which surface handles it hands off or
//!   ingests, which permissions it needs, whether it was actually
//!   [probed](record::ProbeStatus), and how much it is [trusted](record::StabilityTier).
//! - Those records go into a [`Registry`].
//! - The [`planner`] takes the registry and a [`StreamRequest`] and returns a
//!   [`Plan`]: every viable capture→encoder pipeline, each with its frame-handoff
//!   [`Conversion`] classified (zero-copy / on-device convert / host upload /
//!   cross-GPU copy) and costed, ranked best-first, with ordered fallbacks.
//!
//! The planner is a pure function of its inputs — no platform calls, no probing,
//! no globals — so the selection logic is testable on any host, which is exactly
//! how this crate is developed and exercised on macOS while the Linux/Windows
//! backends that feed it are built out.
//!
//! # Example
//!
//! ```
//! use openstream_capability::*;
//!
//! let mut registry = Registry::new();
//! registry.register_capture(CaptureCapability {
//!     backend_id: "pipewire-dmabuf".into(),
//!     os: Os::Linux,
//!     device: DeviceId::new(Vendor::Nvidia, "0000:01:00.0"),
//!     driver_version: Some("550.90".into()),
//!     limits: Limits::new(3840, 2160, 120),
//!     output_surfaces: vec![Surface::new(
//!         SurfaceKind::DmaBuf,
//!         PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
//!     )],
//!     required_permissions: vec![Permission::ScreenCapture],
//!     probe: ProbeStatus::Verified,
//!     stability: StabilityTier::Certified,
//! });
//! registry.register_encoder(EncoderCapability {
//!     backend_id: "nvenc".into(),
//!     os: Os::Linux,
//!     device: DeviceId::new(Vendor::Nvidia, "0000:01:00.0"),
//!     driver_version: Some("550.90".into()),
//!     codecs: vec![CodecSupport {
//!         codec: Codec::H264,
//!         bit_depths: vec![BitDepth::Eight],
//!         chroma: vec![Chroma::Yuv420],
//!         limits: Limits::new(3840, 2160, 120),
//!     }],
//!     input_surfaces: vec![Surface::new(
//!         SurfaceKind::DmaBuf,
//!         PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
//!     )],
//!     required_permissions: vec![],
//!     probe: ProbeStatus::Verified,
//!     stability: StabilityTier::Certified,
//! });
//!
//! let plan = registry.plan(&StreamRequest::h264_1080p60());
//! let primary = plan.primary().expect("a viable pipeline");
//! assert!(primary.is_zero_copy());
//! ```

pub mod planner;
pub mod record;

pub use planner::{Conversion, Cost, Pipeline, Plan, Registry, plan};
pub use record::{
    BitDepth, CaptureCapability, Chroma, Codec, CodecSupport, DeviceId, EncoderCapability, Limits,
    Os, Permission, PixelFormat, ProbeStatus, StabilityTier, StreamRequest, Surface, SurfaceKind,
    Vendor,
};

/// Whether a registry can actually host a session on this machine: it holds at
/// least one usable capture and one usable encoder that share an OS and can be
/// paired for some request. This is the runtime, evidence-based answer to
/// "is this a host?" — the truthful replacement for a compile-time `host_capable`
/// flag. A machine reports host-capable because it *demonstrated* the capability,
/// not because it was compiled for a platform that usually has it.
pub fn host_capable(registry: &Registry) -> bool {
    let has_capture = registry.captures().iter().any(CaptureCapability::is_usable);
    let has_encoder = registry.encoders().iter().any(EncoderCapability::is_usable);
    if !has_capture || !has_encoder {
        return false;
    }
    // Cheap, request-agnostic viability: some usable capture and usable encoder
    // share an OS. A concrete `plan()` still decides any specific request.
    registry.captures().iter().any(|c| {
        c.is_usable()
            && registry
                .encoders()
                .iter()
                .any(|e| e.is_usable() && e.os == c.os)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usable_capture(os: Os) -> CaptureCapability {
        CaptureCapability {
            backend_id: "cap".into(),
            os,
            device: DeviceId::new(Vendor::Nvidia, "gpu0"),
            driver_version: None,
            limits: Limits::new(3840, 2160, 60),
            output_surfaces: vec![Surface::new(
                SurfaceKind::DmaBuf,
                PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
            )],
            required_permissions: vec![],
            probe: ProbeStatus::Verified,
            stability: StabilityTier::Certified,
        }
    }

    fn usable_encoder(os: Os) -> EncoderCapability {
        EncoderCapability {
            backend_id: "enc".into(),
            os,
            device: DeviceId::new(Vendor::Nvidia, "gpu0"),
            driver_version: None,
            codecs: vec![CodecSupport {
                codec: Codec::H264,
                bit_depths: vec![BitDepth::Eight],
                chroma: vec![Chroma::Yuv420],
                limits: Limits::new(3840, 2160, 60),
            }],
            input_surfaces: vec![Surface::new(
                SurfaceKind::DmaBuf,
                PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
            )],
            required_permissions: vec![],
            probe: ProbeStatus::Verified,
            stability: StabilityTier::Certified,
        }
    }

    #[test]
    fn an_empty_registry_is_not_host_capable() {
        assert!(!host_capable(&Registry::new()));
    }

    #[test]
    fn a_client_only_machine_with_no_capture_is_not_host_capable() {
        // A Windows box that can decode/present but registered no capture or
        // encoder backend must not claim to be a host — the exact 1.0 lie.
        let mut reg = Registry::new();
        reg.register_encoder(usable_encoder(Os::Windows));
        assert!(!host_capable(&reg), "encoder alone is not a host");
        let mut reg2 = Registry::new();
        reg2.register_capture(usable_capture(Os::Windows));
        assert!(!host_capable(&reg2), "capture alone is not a host");
    }

    #[test]
    fn capture_and_encoder_on_the_same_os_is_host_capable() {
        let mut reg = Registry::new();
        reg.register_capture(usable_capture(Os::Linux));
        reg.register_encoder(usable_encoder(Os::Linux));
        assert!(host_capable(&reg));
    }

    #[test]
    fn a_failed_probe_does_not_count_toward_host_capability() {
        let mut reg = Registry::new();
        reg.register_capture(usable_capture(Os::Linux));
        let mut enc = usable_encoder(Os::Linux);
        enc.probe = ProbeStatus::Failed("no nvidia device".into());
        reg.register_encoder(enc);
        assert!(!host_capable(&reg));
    }
}
