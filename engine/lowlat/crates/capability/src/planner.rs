//! The pipeline planner.
//!
//! Given a [`Registry`] of per-device capture and encoder records and a
//! [`StreamRequest`], the planner enumerates every capture->encoder pairing that
//! can actually service the request, classifies the frame handoff between them
//! ([`Conversion`]), assigns each a deterministic [`Cost`], and returns them
//! ranked best-first as a [`Plan`]. The first entry is the pipeline to run; the
//! rest are the ordered fallbacks to try if it fails to start.
//!
//! The ranking has two levers, in strict priority order:
//!
//! 1. **Reliability** -- stability tier (a pipeline is only as stable as its
//!    weaker half) plus a penalty for any half that is advertised-but-unproven.
//!    This dominates: a `Certified` upload path always beats an `Experimental`
//!    zero-copy path.
//! 2. **Latency** -- the copies and host<->device transfers the handoff costs.
//!    Among equally reliable pipelines, the one that moves the fewest bytes the
//!    fewest times wins, so a same-GPU zero-copy path beats an upload, which
//!    beats a cross-GPU copy.
//!
//! Ties beyond that are broken by backend and device id purely so the output is
//! stable regardless of registration order -- the planner is a pure function of
//! its inputs.

use crate::record::{
    CaptureCapability, DeviceId, EncoderCapability, ProbeStatus, StabilityTier, StreamRequest,
    Surface,
};

/// How a frame gets from the capture backend to the encoder backend. This is the
/// single most important thing the planner decides, because it dictates the
/// per-frame copy cost -- the difference between a same-GPU handoff and a
/// cross-GPU shuffle is the difference between a playable stream and a stuttering
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversion {
    /// The encoder ingests the capture's surface as-is: same device, same handle
    /// kind, same pixel format. No per-frame copy.
    ZeroCopy,
    /// Same memory domain (both on one GPU, or both in system memory) but the
    /// pixel layout must be converted. One copy, no host<->device transfer.
    Convert,
    /// The frame is in system memory and must cross the host<->device boundary
    /// (upload to a GPU encoder, or download to a software encoder).
    Upload,
    /// The frame lives on one GPU and the encoder is on another: it must be
    /// copied device->device (in practice via host or peer DMA). Two transfers.
    CrossGpuCopy,
}

impl Conversion {
    /// Number of per-frame pixel copies this handoff incurs.
    pub fn copies(self) -> u8 {
        match self {
            Conversion::ZeroCopy => 0,
            Conversion::Convert | Conversion::Upload => 1,
            Conversion::CrossGpuCopy => 2,
        }
    }

    /// Whether the handoff crosses the host<->device boundary at least once.
    pub fn host_roundtrip(self) -> bool {
        matches!(self, Conversion::Upload | Conversion::CrossGpuCopy)
    }

    /// A latency score; lower is better. A host<->device transfer dominates the
    /// per-copy cost because it pays PCIe/bandwidth latency on every frame.
    fn latency_score(self) -> u32 {
        let mut score = u32::from(self.copies()) * 10;
        if self.host_roundtrip() {
            score += 100;
        }
        score
    }
}

/// The cost the planner assigns to a candidate pipeline. Ordered lexicographically
/// by reliability first, then latency, so [`Cost`] is a total order the ranking
/// can sort on directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// Reliability penalty; lower is better. Dominated by stability tier, nudged
    /// by whether each half was actually probed.
    pub reliability_penalty: u32,
    /// Latency score from the [`Conversion`]; lower is better.
    pub latency_score: u32,
}

impl Cost {
    fn key(self) -> (u32, u32) {
        (self.reliability_penalty, self.latency_score)
    }
}

impl PartialOrd for Cost {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cost {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

fn stability_penalty(tier: StabilityTier) -> u32 {
    match tier {
        StabilityTier::Certified => 0,
        StabilityTier::Compatible => 100,
        StabilityTier::Experimental => 1_000,
        // Excluded before costing; kept total for safety.
        StabilityTier::Unavailable => 1_000_000,
    }
}

fn probe_penalty(probe: &ProbeStatus) -> u32 {
    match probe {
        ProbeStatus::Verified => 0,
        ProbeStatus::Advertised => 10,
        // Excluded before costing; kept total for safety.
        ProbeStatus::Failed(_) => 1_000_000,
    }
}

/// A resolved, runnable pipeline: which backends on which devices, how the frame
/// crosses between them, the negotiated encoder-input surface, its cost, and any
/// truthfulness warnings the caller should surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    /// Capture backend id.
    pub capture_backend_id: String,
    /// Device the capture runs on.
    pub capture_device: DeviceId,
    /// Encoder backend id.
    pub encoder_backend_id: String,
    /// Device the encoder runs on.
    pub encoder_device: DeviceId,
    /// How the frame is handed off.
    pub conversion: Conversion,
    /// The surface the encoder ingests after any conversion.
    pub encoder_input: Surface,
    /// The pipeline's stability -- the weaker of the two halves.
    pub stability: StabilityTier,
    /// The pipeline's cost, used for ranking.
    pub cost: Cost,
    /// Human-readable notes about anything that lowered confidence in this path
    /// (unproven probe, experimental tier, cross-GPU handoff).
    pub warnings: Vec<String>,
}

impl Pipeline {
    /// Whether this pipeline avoids a per-frame copy entirely.
    pub fn is_zero_copy(&self) -> bool {
        self.conversion == Conversion::ZeroCopy
    }

    /// A stable tiebreak key so equal-cost pipelines order deterministically
    /// regardless of registration order.
    fn tiebreak(&self) -> (&str, &str, &str, &str) {
        (
            &self.capture_backend_id,
            &self.encoder_backend_id,
            &self.capture_device.id,
            &self.encoder_device.id,
        )
    }
}

/// Resolve how a single capture surface can be delivered to a single encoder
/// surface, given which device each backend lives on. Returns `None` when no
/// known interop connects the two handle kinds.
fn resolve_pair(
    cap_surface: Surface,
    cap_device: &DeviceId,
    enc_surface: Surface,
    enc_device: &DeviceId,
) -> Option<Conversion> {
    let cap_host = !cap_surface.kind.is_device_local();
    let enc_host = !enc_surface.kind.is_device_local();
    let same_pixel = cap_surface.pixel == enc_surface.pixel;

    match (cap_host, enc_host) {
        // Both in system memory: a software handoff. Same layout is a pointer
        // pass; a different layout is a CPU colour convert.
        (true, true) => Some(if same_pixel {
            Conversion::ZeroCopy
        } else {
            Conversion::Convert
        }),
        // Capture in system memory, encoder wants a GPU surface: upload. (The
        // encoder's own colour convert folds into the same upload, so pixel
        // mismatch does not add a separate step here.)
        (true, false) => Some(Conversion::Upload),
        // Capture on a GPU, encoder wants system memory: a device->host download.
        // Same host boundary crossing as an upload, cost-wise.
        (false, true) => Some(Conversion::Upload),
        // Both device-local.
        (false, false) => {
            if cap_device == enc_device {
                // Same GPU: only interoperable when the handle kinds agree.
                // Distinct device-handle kinds on one GPU (e.g. VAAPI surface vs
                // CUDA pointer) have no assumed interop, so decline the pair.
                if cap_surface.kind == enc_surface.kind {
                    Some(if same_pixel {
                        Conversion::ZeroCopy
                    } else {
                        Conversion::Convert
                    })
                } else {
                    None
                }
            } else {
                // Different GPUs: a cross-device copy, whatever the handles.
                Some(Conversion::CrossGpuCopy)
            }
        }
    }
}

/// The cheapest handoff between a capture and an encoder, plus the encoder-input
/// surface that handoff lands in. `None` when no surface pair interoperates.
fn best_handoff(
    capture: &CaptureCapability,
    encoder: &EncoderCapability,
) -> Option<(Conversion, Surface)> {
    let mut best: Option<(Conversion, Surface)> = None;
    for &cap_surface in &capture.output_surfaces {
        for &enc_surface in &encoder.input_surfaces {
            let Some(conversion) =
                resolve_pair(cap_surface, &capture.device, enc_surface, &encoder.device)
            else {
                continue;
            };
            // For a system-memory->GPU upload the frame lands in the encoder's
            // surface; for a same-memory pass it lands in the capture's layout.
            // Either way the encoder-input surface is what the encoder ingests.
            let landing = enc_surface;
            let candidate = (conversion, landing);
            let replace = match &best {
                None => true,
                Some((current, _)) => conversion.latency_score() < current.latency_score(),
            };
            if replace {
                best = Some(candidate);
            }
        }
    }
    best
}

/// Evaluate one capturexencoder pairing against a request, producing a costed
/// [`Pipeline`] or `None` if the pair cannot service the request at all.
fn evaluate(
    capture: &CaptureCapability,
    encoder: &EncoderCapability,
    request: &StreamRequest,
) -> Option<Pipeline> {
    // A pipeline lives in one host process: both halves share an OS.
    if capture.os != encoder.os {
        return None;
    }
    // Failed probes and unavailable tiers are never planned.
    if !capture.is_usable() || !encoder.is_usable() {
        return None;
    }
    // The capture must be able to grab the requested geometry.
    if !capture
        .limits
        .admits(request.width, request.height, request.fps)
    {
        return None;
    }
    // The encoder must be able to emit the requested codec/format/geometry.
    encoder.codec_support(
        request.codec,
        request.bit_depth,
        request.chroma,
        request.width,
        request.height,
        request.fps,
    )?;
    // The frame has to physically get from one to the other.
    let (conversion, encoder_input) = best_handoff(capture, encoder)?;

    let stability = capture.stability.worst(encoder.stability);
    let reliability_penalty = stability_penalty(stability)
        .saturating_add(probe_penalty(&capture.probe))
        .saturating_add(probe_penalty(&encoder.probe));
    let cost = Cost {
        reliability_penalty,
        latency_score: conversion.latency_score(),
    };

    let mut warnings = Vec::new();
    if matches!(capture.probe, ProbeStatus::Advertised) {
        warnings.push(format!(
            "capture '{}' is advertised but not verified on this machine",
            capture.backend_id
        ));
    }
    if matches!(encoder.probe, ProbeStatus::Advertised) {
        warnings.push(format!(
            "encoder '{}' is advertised but not verified on this machine",
            encoder.backend_id
        ));
    }
    if stability == StabilityTier::Experimental {
        warnings.push("pipeline uses an experimental backend".to_string());
    }
    if conversion == Conversion::CrossGpuCopy {
        warnings.push(format!(
            "cross-GPU copy from {:?} device '{}' to {:?} device '{}'",
            capture.device.vendor, capture.device.id, encoder.device.vendor, encoder.device.id
        ));
    }

    Some(Pipeline {
        capture_backend_id: capture.backend_id.clone(),
        capture_device: capture.device.clone(),
        encoder_backend_id: encoder.backend_id.clone(),
        encoder_device: encoder.device.clone(),
        conversion,
        encoder_input,
        stability,
        cost,
        warnings,
    })
}

/// The registry of capability records discovered on this machine. Backends push
/// their records here at startup; the planner reads from it. It is a plain
/// container -- no platform code, no probing -- so it is trivially testable.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    captures: Vec<CaptureCapability>,
    encoders: Vec<EncoderCapability>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a capture backend's record.
    pub fn register_capture(&mut self, capture: CaptureCapability) {
        self.captures.push(capture);
    }

    /// Register an encoder backend's record.
    pub fn register_encoder(&mut self, encoder: EncoderCapability) {
        self.encoders.push(encoder);
    }

    /// All registered capture records.
    pub fn captures(&self) -> &[CaptureCapability] {
        &self.captures
    }

    /// All registered encoder records.
    pub fn encoders(&self) -> &[EncoderCapability] {
        &self.encoders
    }

    /// Every distinct device that appears in any record, in first-seen order.
    /// This is the multi-GPU enumeration the old first-render-node logic could
    /// not express: a two-GPU box yields two entries.
    pub fn devices(&self) -> Vec<DeviceId> {
        let mut seen: Vec<DeviceId> = Vec::new();
        let capture_devices = self.captures.iter().map(|c| &c.device);
        let encoder_devices = self.encoders.iter().map(|e| &e.device);
        for device in capture_devices.chain(encoder_devices) {
            if !seen.contains(device) {
                seen.push(device.clone());
            }
        }
        seen
    }

    /// Plan the request against everything registered, returning ranked
    /// pipelines best-first.
    pub fn plan(&self, request: &StreamRequest) -> Plan {
        plan(self, request)
    }
}

/// A ranked set of pipelines for one request. The first is the primary; the rest
/// are ordered fallbacks. Empty when nothing on this machine can service the
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The request this plan answers.
    pub request: StreamRequest,
    /// Viable pipelines, ranked best-first.
    pub pipelines: Vec<Pipeline>,
}

impl Plan {
    /// The pipeline to run, if any is viable.
    pub fn primary(&self) -> Option<&Pipeline> {
        self.pipelines.first()
    }

    /// The ordered fallbacks to try if the primary fails to start.
    pub fn fallbacks(&self) -> &[Pipeline] {
        self.pipelines.get(1..).unwrap_or(&[])
    }

    /// Whether any pipeline can service the request.
    pub fn is_viable(&self) -> bool {
        !self.pipelines.is_empty()
    }
}

/// Plan `request` against `registry`: enumerate all viable capturexencoder
/// pairings, cost each, and return them ranked best-first.
pub fn plan(registry: &Registry, request: &StreamRequest) -> Plan {
    let mut pipelines: Vec<Pipeline> = Vec::new();
    for capture in registry.captures() {
        for encoder in registry.encoders() {
            if let Some(pipeline) = evaluate(capture, encoder, request) {
                pipelines.push(pipeline);
            }
        }
    }
    // Rank by cost (reliability, then latency), with a stable id tiebreak so the
    // result is independent of registration order.
    pipelines.sort_by(|a, b| {
        a.cost
            .cmp(&b.cost)
            .then_with(|| a.tiebreak().cmp(&b.tiebreak()))
    });
    Plan {
        request: *request,
        pipelines,
    }
}

// Record types used only by the test builders below.
#[cfg(test)]
use crate::record::{
    BitDepth, Chroma, Codec, CodecSupport, Limits, Os, PixelFormat, SurfaceKind, Vendor,
};

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
mod tests {
    use super::*;

    fn pixel() -> PixelFormat {
        PixelFormat::new(Chroma::Yuv420, BitDepth::Eight)
    }

    fn nvidia() -> DeviceId {
        DeviceId::new(Vendor::Nvidia, "0000:01:00.0")
    }

    fn intel() -> DeviceId {
        DeviceId::new(Vendor::Intel, "0000:00:02.0")
    }

    fn h264_1080p() -> CodecSupport {
        CodecSupport {
            codec: Codec::H264,
            bit_depths: vec![BitDepth::Eight],
            chroma: vec![Chroma::Yuv420],
            limits: Limits::new(3840, 2160, 60),
        }
    }

    fn capture(
        backend: &str,
        device: DeviceId,
        surface: SurfaceKind,
        stability: StabilityTier,
        probe: ProbeStatus,
    ) -> CaptureCapability {
        CaptureCapability {
            backend_id: backend.to_string(),
            os: Os::Linux,
            device,
            driver_version: None,
            limits: Limits::new(3840, 2160, 60),
            output_surfaces: vec![Surface::new(surface, pixel())],
            required_permissions: vec![],
            probe,
            stability,
        }
    }

    fn encoder(
        backend: &str,
        device: DeviceId,
        surface: SurfaceKind,
        stability: StabilityTier,
        probe: ProbeStatus,
    ) -> EncoderCapability {
        EncoderCapability {
            backend_id: backend.to_string(),
            os: Os::Linux,
            device,
            driver_version: None,
            codecs: vec![h264_1080p()],
            input_surfaces: vec![Surface::new(surface, pixel())],
            required_permissions: vec![],
            probe,
            stability,
        }
    }

    #[test]
    fn pipewire_dmabuf_to_nvenc_on_one_gpu_is_zero_copy() {
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        assert_eq!(primary.conversion, Conversion::ZeroCopy);
        assert!(primary.is_zero_copy());
        assert_eq!(primary.cost.latency_score, 0);
        assert!(primary.warnings.is_empty());
    }

    #[test]
    fn pipewire_shm_to_vaapi_needs_an_upload() {
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-shm",
            intel(),
            SurfaceKind::SystemMemory,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "vaapi",
            intel(),
            SurfaceKind::VaapiSurface,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        assert_eq!(primary.conversion, Conversion::Upload);
        assert!(primary.conversion.host_roundtrip());
        assert_eq!(primary.conversion.copies(), 1);
    }

    #[test]
    fn capture_on_one_gpu_and_encoder_on_another_is_a_cross_gpu_copy() {
        // Intel iGPU captures a DMA-BUF; only the NVIDIA card can encode it.
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            intel(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        assert_eq!(primary.conversion, Conversion::CrossGpuCopy);
        assert_eq!(primary.conversion.copies(), 2);
        assert!(
            primary.warnings.iter().any(|w| w.contains("cross-GPU")),
            "cross-GPU handoff should warn: {:?}",
            primary.warnings
        );
    }

    #[test]
    fn no_encoder_for_the_codec_yields_no_viable_path() {
        // Encoder only does H.264; request AV1.
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let mut request = StreamRequest::h264_1080p60();
        request.codec = Codec::Av1;
        let plan = reg.plan(&request);
        assert!(!plan.is_viable());
        assert!(plan.primary().is_none());
    }

    #[test]
    fn a_failed_probe_or_unavailable_tier_is_excluded() {
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Failed("driver missing".into()),
        ));
        assert!(!reg.plan(&StreamRequest::h264_1080p60()).is_viable());
    }

    #[test]
    fn faster_path_ranks_ahead_of_upload_when_equally_stable() {
        // Two encoders on the NVIDIA GPU: a zero-copy DMA-BUF path and a
        // system-memory upload path, both Certified+Verified.
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-zerocopy",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-sysmem",
            nvidia(),
            SurfaceKind::SystemMemory,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        assert_eq!(plan.pipelines.len(), 2);
        assert_eq!(plan.primary().unwrap().encoder_backend_id, "nvenc-zerocopy");
        assert_eq!(plan.primary().unwrap().conversion, Conversion::ZeroCopy);
        assert_eq!(plan.fallbacks()[0].encoder_backend_id, "nvenc-sysmem");
    }

    #[test]
    fn a_certified_upload_beats_an_experimental_zero_copy() {
        // Stability dominates latency: a slower-but-trusted path is preferred
        // over a faster-but-experimental one.
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-shm",
            nvidia(),
            SurfaceKind::SystemMemory,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Experimental,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-sysmem",
            nvidia(),
            SurfaceKind::SystemMemory,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Experimental,
            ProbeStatus::Verified,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        // The certified pairing (sysmem->sysmem upload) wins despite being slower
        // than the experimental zero-copy dmabuf pairing.
        assert_eq!(primary.stability, StabilityTier::Certified);
        assert_eq!(primary.capture_backend_id, "pipewire-shm");
        assert_eq!(primary.encoder_backend_id, "nvenc-sysmem");
        // The experimental zero-copy path is still offered as a fallback.
        assert!(
            plan.fallbacks()
                .iter()
                .any(|p| p.conversion == Conversion::ZeroCopy
                    && p.stability == StabilityTier::Experimental)
        );
    }

    #[test]
    fn an_unproven_path_ranks_below_a_verified_one_of_equal_tier() {
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-verified",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc-advertised",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Advertised,
        ));
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        assert_eq!(plan.primary().unwrap().encoder_backend_id, "nvenc-verified");
        let advertised = &plan.fallbacks()[0];
        assert_eq!(advertised.encoder_backend_id, "nvenc-advertised");
        assert!(
            advertised.warnings.iter().any(|w| w.contains("advertised")),
            "advertised path should warn: {:?}",
            advertised.warnings
        );
    }

    #[test]
    fn cross_os_backends_never_pair() {
        let mut reg = Registry::new();
        let mut cap = capture(
            "wgc",
            nvidia(),
            SurfaceKind::D3D11Texture,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        );
        cap.os = Os::Windows;
        reg.register_capture(cap);
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::D3D11Texture,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        )); // Linux
        assert!(!reg.plan(&StreamRequest::h264_1080p60()).is_viable());
    }

    #[test]
    fn registry_enumerates_every_distinct_device() {
        let mut reg = Registry::new();
        reg.register_capture(capture(
            "pipewire-dmabuf",
            intel(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "vaapi",
            intel(),
            SurfaceKind::VaapiSurface,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        reg.register_encoder(encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        ));
        let devices = reg.devices();
        assert_eq!(devices.len(), 2, "two physical GPUs: {devices:?}");
        assert!(devices.contains(&intel()));
        assert!(devices.contains(&nvidia()));
    }

    #[test]
    fn same_gpu_pixel_mismatch_is_an_on_device_convert_not_a_copy_to_host() {
        // DMA-BUF on both sides, same GPU, but 4:2:0 capture vs 4:4:4 encoder
        // input: an on-device colour convert, no host roundtrip.
        let mut reg = Registry::new();
        let mut cap = capture(
            "pipewire-dmabuf",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        );
        cap.output_surfaces = vec![Surface::new(
            SurfaceKind::DmaBuf,
            PixelFormat::new(Chroma::Yuv420, BitDepth::Eight),
        )];
        reg.register_capture(cap);
        let mut enc = encoder(
            "nvenc",
            nvidia(),
            SurfaceKind::DmaBuf,
            StabilityTier::Certified,
            ProbeStatus::Verified,
        );
        enc.input_surfaces = vec![Surface::new(
            SurfaceKind::DmaBuf,
            PixelFormat::new(Chroma::Yuv444, BitDepth::Eight),
        )];
        enc.codecs = vec![CodecSupport {
            codec: Codec::H264,
            bit_depths: vec![BitDepth::Eight],
            chroma: vec![Chroma::Yuv420, Chroma::Yuv444],
            limits: Limits::new(3840, 2160, 60),
        }];
        reg.register_encoder(enc);
        let plan = reg.plan(&StreamRequest::h264_1080p60());
        let primary = plan.primary().expect("a pipeline");
        assert_eq!(primary.conversion, Conversion::Convert);
        assert!(!primary.conversion.host_roundtrip());
        assert_eq!(primary.conversion.copies(), 1);
    }
}
