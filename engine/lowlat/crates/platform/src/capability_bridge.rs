//! Bridge from the legacy flat hardware report into structured 1.1 capability
//! records.
//!
//! [`crate::hwaccel::HwReport`] is machine-global per-codec booleans plus one
//! render node. The 1.1 planner in `openstream-capability` wants per-device
//! records. This module adapts the former into the latter so today's discovery
//! can feed the new planner while the native per-backend discovery is built out.
//!
//! It is deliberately a *lossy* adaptor, and honest about the loss. The flat
//! report never carried a PCI id, a driver version, a bit-depth beyond 8, or a
//! real resolution ceiling, so those fields take documented defaults here rather
//! than invented values, and every record's [`ProbeStatus`] reflects what the
//! report *actually* established: the encoder probes that
//! [`HwReport::probe`](crate::hwaccel::HwReport::probe) ran are
//! [`Verified`](ProbeStatus::Verified); the screen-capture path it never probed
//! is [`Advertised`](ProbeStatus::Advertised). The goal is to wire the existing
//! host into the planner and then replace this backend-by-backend with native
//! discovery that fills the fields in for real -- not to pretend the flat report
//! had structure it did not.

use crate::hwaccel::{HwReport, vaapi_render_node};
use openstream_capability::{
    BitDepth, CaptureCapability, Chroma, Codec, CodecSupport, DeviceId, EncoderCapability, Limits,
    Os, Permission, PixelFormat, ProbeStatus, Registry, StabilityTier, Surface, SurfaceKind,
    Vendor,
};

/// A nominal resolution/frame-rate ceiling for a hardware encoder family.
///
/// The flat report did not probe a ceiling -- the encode probe ran at 64x64 -- so
/// this is the family's published capability, not a per-machine measurement. It
/// is only ever used as an upper-bound gate, and the pre-1.1 host applied these
/// encoders to any negotiated resolution with *no* ceiling check at all, so a
/// generous nominal bound is strictly more conservative than the status quo, not
/// a new claim. A native backend replaces it with the real device limit.
const NOMINAL_HW_LIMITS: Limits = Limits {
    max_width: 7680,
    max_height: 4320,
    max_fps: 120,
};

/// The current host OS as a capability [`Os`], or `None` when this platform has
/// no host path. Windows and mobile return `None`: there is no host agent there
/// (see `platform::host_capable`).
pub fn current_host_os() -> Option<Os> {
    if cfg!(target_os = "linux") {
        Some(Os::Linux)
    } else if cfg!(target_os = "macos") {
        Some(Os::MacOs)
    } else {
        None
    }
}

fn h264_and_or_h265(h264: bool, h265: bool) -> Vec<CodecSupport> {
    let mut codecs = Vec::new();
    // The flat report only ever probed 8-bit 4:2:0, so that is all these records
    // may claim; a native backend that probes 10-bit / 4:4:4 adds them.
    if h264 {
        codecs.push(CodecSupport {
            codec: Codec::H264,
            bit_depths: vec![BitDepth::Eight],
            chroma: vec![Chroma::Yuv420],
            limits: NOMINAL_HW_LIMITS,
        });
    }
    if h265 {
        codecs.push(CodecSupport {
            codec: Codec::H265,
            bit_depths: vec![BitDepth::Eight],
            chroma: vec![Chroma::Yuv420],
            limits: NOMINAL_HW_LIMITS,
        });
    }
    codecs
}

/// Encoder capability records adapted from a probed hardware report.
///
/// Emits at most one NVENC record and one VAAPI record -- whichever the report
/// proved can encode at least one codec -- plus a software libx264/libx265 record
/// as the always-present deterministic fallback. The hardware records are
/// [`Verified`](ProbeStatus::Verified) (the report opened those encoders) and
/// [`Certified`](StabilityTier::Certified) (they are the shipping ffmpeg paths);
/// the software record is [`Advertised`](ProbeStatus::Advertised) (ffmpeg
/// presence was not probed here) and [`Compatible`](StabilityTier::Compatible).
///
/// The NVENC input surface is [`SystemMemory`](SurfaceKind::SystemMemory)
/// because the ffmpeg host feeds NVENC software frames directly (no `hwupload`
/// filter), while VAAPI's input is a
/// [`VaapiSurface`](SurfaceKind::VaapiSurface) reached through the host's
/// `format=nv12,hwupload` filter -- so the planner correctly classifies the
/// screen-capture->NVENC handoff as a same-domain pass and the
/// screen-capture->VAAPI handoff as an upload, matching what ffmpeg actually does.
pub fn encoder_records(report: &HwReport, os: Os) -> Vec<EncoderCapability> {
    let mut records = Vec::new();

    if report.nvenc_h264 || report.nvenc_hevc {
        records.push(EncoderCapability {
            backend_id: "nvenc".to_string(),
            os,
            // The flat report cannot distinguish two NVIDIA GPUs, so all NVENC
            // collapses to one nominal device id. A native backend supplies the
            // per-GPU PCI id here.
            device: DeviceId::new(Vendor::Nvidia, "nvenc"),
            driver_version: None,
            codecs: h264_and_or_h265(report.nvenc_h264, report.nvenc_hevc),
            input_surfaces: vec![Surface::new(
                SurfaceKind::SystemMemory,
                PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
            )],
            required_permissions: vec![],
            probe: ProbeStatus::Verified,
            stability: StabilityTier::Certified,
        });
    }

    if report.vaapi_h264 || report.vaapi_hevc {
        // The render node is the only device identity the flat report has, and
        // it cannot tell Intel from AMD, so the vendor is Other and the node
        // path is the id. A native backend reads the vendor from sysfs.
        let node = vaapi_render_node().unwrap_or_else(|| "renderD128".to_string());
        records.push(EncoderCapability {
            backend_id: "vaapi".to_string(),
            os,
            device: DeviceId::new(Vendor::Other, node),
            driver_version: None,
            codecs: h264_and_or_h265(report.vaapi_h264, report.vaapi_hevc),
            input_surfaces: vec![Surface::new(
                SurfaceKind::VaapiSurface,
                PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
            )],
            required_permissions: vec![Permission::DeviceAccess],
            probe: ProbeStatus::Verified,
            stability: StabilityTier::Certified,
        });
    }

    // Software encoding through libx264/libx265 is the deterministic fallback:
    // it needs no accelerator, so a plan is available even when every hardware
    // probe failed. Advertised, not Verified -- HwReport does not probe it -- so
    // the planner keeps it below any verified hardware path.
    records.push(EncoderCapability {
        backend_id: "libx264".to_string(),
        os,
        device: DeviceId::cpu(),
        driver_version: None,
        codecs: vec![
            CodecSupport {
                codec: Codec::H264,
                bit_depths: vec![BitDepth::Eight],
                chroma: vec![Chroma::Yuv420, Chroma::Yuv444],
                limits: NOMINAL_HW_LIMITS,
            },
            CodecSupport {
                codec: Codec::H265,
                bit_depths: vec![BitDepth::Eight],
                chroma: vec![Chroma::Yuv420],
                limits: NOMINAL_HW_LIMITS,
            },
        ],
        input_surfaces: vec![Surface::new(
            SurfaceKind::SystemMemory,
            PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
        )],
        required_permissions: vec![],
        probe: ProbeStatus::Advertised,
        stability: StabilityTier::Compatible,
    });

    records
}

/// The screen-capture record for the host's ffmpeg capture path.
///
/// Today's host captures the screen with ffmpeg (x11grab/kmsgrab/PipeWire on
/// Linux, AVFoundation on macOS) into system-memory frames, so the record's
/// output is [`SystemMemory`](SurfaceKind::SystemMemory) with no GPU affinity --
/// which is why the planner pairs it with NVENC as a same-domain pass and with
/// VAAPI as an upload. It is [`Advertised`](ProbeStatus::Advertised): the report
/// never exercised capture, so this states the path exists without claiming it
/// was verified on this machine. A native capture backend that hands off a
/// DMA-BUF or IOSurface replaces this with a device-local, verified record.
pub fn capture_records(os: Os) -> Vec<CaptureCapability> {
    let backend_id = match os {
        Os::Linux => "ffmpeg-x11grab",
        Os::MacOs => "ffmpeg-avfoundation",
        Os::Windows => "ffmpeg-gdigrab",
    };
    vec![CaptureCapability {
        backend_id: backend_id.to_string(),
        os,
        device: DeviceId::cpu(),
        driver_version: None,
        limits: NOMINAL_HW_LIMITS,
        output_surfaces: vec![Surface::new(
            SurfaceKind::SystemMemory,
            PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
        )],
        required_permissions: vec![Permission::ScreenCapture],
        probe: ProbeStatus::Advertised,
        stability: StabilityTier::Certified,
    }]
}

/// Assemble a [`Registry`] from a probed report for a given host OS: the ffmpeg
/// capture path plus every usable encoder. The planner runs against this.
pub fn registry_from_report(report: &HwReport, os: Os) -> Registry {
    let mut registry = Registry::new();
    for capture in capture_records(os) {
        registry.register_capture(capture);
    }
    for encoder in encoder_records(report, os) {
        registry.register_encoder(encoder);
    }
    registry
}

/// Probe this host and build its capability registry, or `None` on a platform
/// with no host path (Windows, mobile). This is the one non-pure entry point --
/// [`HwReport::probe`](crate::hwaccel::HwReport::probe) spawns encoder probes;
/// the record-building above it is pure and unit-tested.
pub fn discover() -> Option<Registry> {
    let os = current_host_os()?;
    Some(registry_from_report(&HwReport::probe(), os))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstream_capability::{Conversion, StreamRequest};

    fn all_hardware() -> HwReport {
        HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            vaapi_hevc: true,
            nvenc_h264: true,
            nvenc_hevc: true,
            nvidia_smi: true,
        }
    }

    #[test]
    fn a_software_only_host_still_gets_a_deterministic_fallback() {
        let report = HwReport::default();
        let encoders = encoder_records(&report, Os::Linux);
        assert_eq!(encoders.len(), 1, "only the software fallback");
        assert_eq!(encoders[0].backend_id, "libx264");
        assert_eq!(encoders[0].device, DeviceId::cpu());
        assert!(matches!(encoders[0].probe, ProbeStatus::Advertised));
        // And a full plan still resolves to that fallback.
        let registry = registry_from_report(&report, Os::Linux);
        let plan = registry.plan(&StreamRequest::h264_1080p60());
        assert_eq!(plan.primary().unwrap().encoder_backend_id, "libx264");
    }

    #[test]
    fn nvenc_is_verified_and_preferred_over_the_software_fallback() {
        let report = HwReport {
            nvenc_h264: true,
            ..HwReport::default()
        };
        let registry = registry_from_report(&report, Os::Linux);
        let plan = registry.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        assert_eq!(primary.encoder_backend_id, "nvenc");
        // Screen-capture (system memory) into NVENC (system-memory input) is a
        // same-domain pass, not an upload -- ffmpeg feeds NVENC software frames.
        assert_eq!(primary.conversion, Conversion::ZeroCopy);
        // The software fallback is still offered below it.
        assert!(
            plan.fallbacks()
                .iter()
                .any(|p| p.encoder_backend_id == "libx264")
        );
    }

    #[test]
    fn vaapi_is_reached_through_an_upload_matching_the_hwupload_filter() {
        let report = HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            ..HwReport::default()
        };
        let registry = registry_from_report(&report, Os::Linux);
        let plan = registry.plan(&StreamRequest::h264_1080p60());
        let vaapi = plan
            .pipelines
            .iter()
            .find(|p| p.encoder_backend_id == "vaapi")
            .expect("a vaapi pipeline");
        // System-memory capture -> VAAPI surface encoder = host upload, which is
        // exactly the `format=nv12,hwupload` the ffmpeg profile appends.
        assert_eq!(vaapi.conversion, Conversion::Upload);
        assert!(vaapi.conversion.host_roundtrip());
    }

    #[test]
    fn the_flat_report_only_claims_what_it_probed() {
        // HEVC not probed => no HEVC record, even though H.264 is present.
        let report = HwReport {
            nvenc_h264: true,
            nvenc_hevc: false,
            ..HwReport::default()
        };
        let nvenc = encoder_records(&report, Os::Linux)
            .into_iter()
            .find(|e| e.backend_id == "nvenc")
            .expect("an nvenc record");
        assert_eq!(nvenc.codecs.len(), 1);
        assert_eq!(nvenc.codecs[0].codec, Codec::H264);
        // 10-bit was never probed, so it must not be advertised.
        assert_eq!(nvenc.codecs[0].bit_depths, vec![BitDepth::Eight]);
    }

    #[test]
    fn a_fully_loaded_host_prefers_nvenc_but_offers_vaapi_and_software() {
        let registry = registry_from_report(&all_hardware(), Os::Linux);
        let plan = registry.plan(&StreamRequest::h264_1080p60());
        assert_eq!(plan.primary().unwrap().encoder_backend_id, "nvenc");
        let backends: Vec<_> = plan
            .pipelines
            .iter()
            .map(|p| p.encoder_backend_id.as_str())
            .collect();
        assert!(backends.contains(&"nvenc"));
        assert!(backends.contains(&"vaapi"));
        assert!(backends.contains(&"libx264"));
    }

    #[test]
    fn windows_and_mobile_have_no_host_registry() {
        // current_host_os is compile-time; assert the mapping is right for the
        // build target and that discover() agrees with it.
        match current_host_os() {
            Some(_) => assert!(discover().is_some()),
            None => assert!(discover().is_none()),
        }
    }
}
