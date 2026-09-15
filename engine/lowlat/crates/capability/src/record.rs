//! Structured capability records.
//!
//! A *record* is one backend's honest statement of what it can do on *this*
//! machine: which device it drives, which codecs and pixel formats it handles,
//! which surface handles it can hand off or ingest, what permissions it needs,
//! whether it has actually been probed, and how much we trust it. Backends fill
//! these in at discovery time; the [`planner`](crate::planner) never invents a
//! capability that a record did not claim.
//!
//! The design goal is *truthfulness*. The pre-1.1 code reported capabilities
//! from compile-time `cfg!` flags and flat `bool`s (a single `nvenc_h264`), so
//! a binary compiled for a platform claimed the platform's hardware whether or
//! not it was present, and a machine with two GPUs collapsed to one. These
//! records are per-device and carry a [`ProbeStatus`], so "advertised" and
//! "verified on this box" are distinguishable, and every physical device gets
//! its own entry.

use core::cmp::Ordering;
use core::fmt;

/// Operating system a backend runs on. Capture and encoder must share one to be
/// paired — a pipeline lives inside a single host process on a single machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// Linux.
    Linux,
    /// Windows.
    Windows,
    /// macOS.
    MacOs,
}

/// GPU / accelerator vendor. Used for reporting and for `DeviceId` identity; the
/// planner keys interop on the device *id*, not the vendor, so a machine with
/// two NVIDIA cards still enumerates as two devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vendor {
    /// NVIDIA.
    Nvidia,
    /// AMD.
    Amd,
    /// Intel.
    Intel,
    /// Apple.
    Apple,
    /// A CPU-only / software backend with no discrete accelerator.
    Cpu,
    /// Anything not covered above.
    Other,
}

/// A physical device on the host, identified stably per machine.
///
/// `id` is whatever the platform exposes as a durable per-boot identifier — a
/// PCI address on Linux, an adapter LUID on Windows, a registry id on macOS.
/// Two records with equal [`DeviceId`] are the *same* device, which is exactly
/// what the planner needs to tell a same-GPU zero-copy handoff from a cross-GPU
/// copy. The `Cpu` "device" is used by software backends that live in system
/// memory and have no accelerator affinity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId {
    /// The device's vendor.
    pub vendor: Vendor,
    /// A stable per-machine identifier for the physical device.
    pub id: String,
}

impl DeviceId {
    /// Construct a device id from a vendor and a stable identifier.
    pub fn new(vendor: Vendor, id: impl Into<String>) -> Self {
        Self {
            vendor,
            id: id.into(),
        }
    }

    /// The shared software "device" for CPU backends with no accelerator.
    pub fn cpu() -> Self {
        Self::new(Vendor::Cpu, "cpu")
    }
}

/// Video codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AV1.
    Av1,
}

/// Sample bit depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BitDepth {
    /// 8 bits per sample.
    Eight,
    /// 10 bits per sample.
    Ten,
}

/// Chroma subsampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chroma {
    /// 4:2:0.
    Yuv420,
    /// 4:4:4.
    Yuv444,
}

/// A concrete pixel layout: chroma subsampling plus bit depth. Two surfaces with
/// equal [`PixelFormat`] can be handed off without a colour-space conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PixelFormat {
    /// Chroma subsampling.
    pub chroma: Chroma,
    /// Bit depth.
    pub bit_depth: BitDepth,
}

impl PixelFormat {
    /// Construct a pixel format.
    pub fn new(chroma: Chroma, bit_depth: BitDepth) -> Self {
        Self { chroma, bit_depth }
    }
}

/// The kind of memory handle a frame is carried in. This is what determines
/// whether a capture→encoder handoff can avoid a copy: two backends interoperate
/// without a transfer only when they speak the same handle *and* sit on the same
/// device (see [`SurfaceKind::is_device_local`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurfaceKind {
    /// CPU / cross-process shared memory (a plain buffer, SHM, PipeWire SHM).
    /// Has no device affinity; a hardware encoder must upload it to its GPU.
    SystemMemory,
    /// A Linux DMA-BUF exported handle.
    DmaBuf,
    /// A Direct3D 11 texture handle (Windows).
    D3D11Texture,
    /// A macOS `IOSurface`.
    IoSurface,
    /// A CUDA device pointer (NVIDIA).
    CudaDevicePtr,
    /// A VAAPI surface (Intel / AMD on Linux).
    VaapiSurface,
}

impl SurfaceKind {
    /// Whether this handle names memory that lives on a specific device.
    /// [`SurfaceKind::SystemMemory`] is the only host-domain kind; every other
    /// handle is device-local and only interoperates on the same [`DeviceId`].
    pub fn is_device_local(self) -> bool {
        !matches!(self, SurfaceKind::SystemMemory)
    }
}

/// A surface a backend can produce (capture) or ingest (encoder): a handle kind
/// paired with the pixel layout carried in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Surface {
    /// The memory handle kind.
    pub kind: SurfaceKind,
    /// The pixel layout carried in the handle.
    pub pixel: PixelFormat,
}

impl Surface {
    /// Construct a surface.
    pub fn new(kind: SurfaceKind, pixel: PixelFormat) -> Self {
        Self { kind, pixel }
    }
}

/// An OS permission a backend must hold before it can run. Surfacing these in
/// the record lets the planner (and the UI above it) explain *why* an otherwise
/// capable backend is unusable, rather than silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Screen-recording consent (macOS TCC, Windows/Wayland capture consent).
    ScreenCapture,
    /// Synthetic input injection consent.
    InputInjection,
    /// Membership in a device-access group (e.g. Linux `video`/`render`).
    DeviceAccess,
}

/// Whether a record was actually exercised on this machine, or merely advertised
/// from a static table.
///
/// This is the honesty knob. A backend that has never run reports
/// [`ProbeStatus::Advertised`]; one that initialised successfully reports
/// [`ProbeStatus::Verified`]; one that tried and failed reports
/// [`ProbeStatus::Failed`] with the reason. The planner excludes `Failed`
/// records and *penalises* (but keeps) `Advertised` ones, so a verified path is
/// always preferred over an unproven one of equal stability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Listed from a static capability table; never run on this machine.
    Advertised,
    /// A probe ran and the backend initialised successfully.
    Verified,
    /// A probe ran and the backend failed to initialise, with the reason.
    Failed(String),
}

impl ProbeStatus {
    /// Whether this status permits the record to be used at all.
    pub fn is_usable(&self) -> bool {
        !matches!(self, ProbeStatus::Failed(_))
    }
}

/// How much we trust a backend, independent of whether it was probed.
///
/// Stability is a *policy* judgement (has this path been through soak testing?)
/// where [`ProbeStatus`] is a *runtime* fact (did it start today?). The planner
/// treats stability as the dominant ranking key: it never prefers an
/// `Experimental` zero-copy path over a `Certified` upload path, because a path
/// that crashes mid-session is worse than one that is merely slower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StabilityTier {
    /// Soak-tested and supported. Preferred whenever viable.
    Certified,
    /// Known to work but not exhaustively validated.
    Compatible,
    /// Usable but unproven; chosen only when nothing better exists.
    Experimental,
    /// Not usable. Excluded from planning entirely.
    Unavailable,
}

impl StabilityTier {
    /// A rank where a *higher* value is more stable. Used to pick the less
    /// stable of two tiers for a paired pipeline (a pipeline is only as stable
    /// as its weakest half).
    fn rank(self) -> u8 {
        match self {
            StabilityTier::Unavailable => 0,
            StabilityTier::Experimental => 1,
            StabilityTier::Compatible => 2,
            StabilityTier::Certified => 3,
        }
    }

    /// The less-stable ("worst") of two tiers.
    pub fn worst(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Whether this tier permits use at all.
    pub fn is_usable(self) -> bool {
        !matches!(self, StabilityTier::Unavailable)
    }
}

impl PartialOrd for StabilityTier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StabilityTier {
    /// Orders from most stable (`Certified`) to least (`Unavailable`) so that
    /// `Certified > Compatible > Experimental > Unavailable`.
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// A frame-rate/resolution ceiling. Both a capture and an encoder advertise one;
/// a request is only serviceable if it fits under both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum frame width in pixels.
    pub max_width: u32,
    /// Maximum frame height in pixels.
    pub max_height: u32,
    /// Maximum frames per second.
    pub max_fps: u32,
}

impl Limits {
    /// Construct a limits ceiling.
    pub fn new(max_width: u32, max_height: u32, max_fps: u32) -> Self {
        Self {
            max_width,
            max_height,
            max_fps,
        }
    }

    /// Whether a `width`×`height` frame at `fps` fits under this ceiling.
    pub fn admits(&self, width: u32, height: u32, fps: u32) -> bool {
        width <= self.max_width && height <= self.max_height && fps <= self.max_fps
    }
}

/// One codec an encoder supports, with the pixel variants and ceiling for *that*
/// codec. Ceilings are per-codec because hardware routinely encodes, say, H.264
/// at a higher resolution or frame rate than AV1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecSupport {
    /// The codec.
    pub codec: Codec,
    /// Bit depths this encoder can emit for the codec.
    pub bit_depths: Vec<BitDepth>,
    /// Chroma subsamplings this encoder can emit for the codec.
    pub chroma: Vec<Chroma>,
    /// Resolution/frame-rate ceiling for the codec.
    pub limits: Limits,
}

impl CodecSupport {
    /// Whether this codec entry can emit the given `codec` at `bit_depth`,
    /// `chroma`, `width`×`height`, and `fps`.
    pub fn supports(
        &self,
        codec: Codec,
        bit_depth: BitDepth,
        chroma: Chroma,
        width: u32,
        height: u32,
        fps: u32,
    ) -> bool {
        self.codec == codec
            && self.bit_depths.contains(&bit_depth)
            && self.chroma.contains(&chroma)
            && self.limits.admits(width, height, fps)
    }
}

/// A screen-capture backend's capabilities on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureCapability {
    /// Stable backend identifier, e.g. `"pipewire-dmabuf"`, `"wgc"`,
    /// `"avfoundation"`.
    pub backend_id: String,
    /// Operating system the backend runs on.
    pub os: Os,
    /// The device it captures from.
    pub device: DeviceId,
    /// Driver version, when the platform can report one.
    pub driver_version: Option<String>,
    /// Resolution/frame-rate ceiling.
    pub limits: Limits,
    /// Surfaces the backend can hand off. Order is preference order.
    pub output_surfaces: Vec<Surface>,
    /// Permissions the backend needs before it can run.
    pub required_permissions: Vec<Permission>,
    /// Whether it was probed on this machine.
    pub probe: ProbeStatus,
    /// How much it is trusted.
    pub stability: StabilityTier,
}

impl CaptureCapability {
    /// Whether the record is eligible for planning: it initialised (or is at
    /// least advertised) and is not marked unavailable.
    pub fn is_usable(&self) -> bool {
        self.probe.is_usable() && self.stability.is_usable()
    }
}

/// A video-encoder backend's capabilities on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncoderCapability {
    /// Stable backend identifier, e.g. `"nvenc"`, `"vaapi"`, `"videotoolbox"`,
    /// `"x264"`.
    pub backend_id: String,
    /// Operating system the backend runs on.
    pub os: Os,
    /// The device it encodes on. Software encoders use [`DeviceId::cpu`].
    pub device: DeviceId,
    /// Driver version, when the platform can report one.
    pub driver_version: Option<String>,
    /// Codecs it supports, each with its own pixel variants and ceiling.
    pub codecs: Vec<CodecSupport>,
    /// Surfaces the backend can ingest. Order is preference order.
    pub input_surfaces: Vec<Surface>,
    /// Permissions the backend needs before it can run.
    pub required_permissions: Vec<Permission>,
    /// Whether it was probed on this machine.
    pub probe: ProbeStatus,
    /// How much it is trusted.
    pub stability: StabilityTier,
}

impl EncoderCapability {
    /// Whether the record is eligible for planning.
    pub fn is_usable(&self) -> bool {
        self.probe.is_usable() && self.stability.is_usable()
    }

    /// The [`CodecSupport`] entry that can service the request, if any.
    pub fn codec_support(
        &self,
        codec: Codec,
        bit_depth: BitDepth,
        chroma: Chroma,
        width: u32,
        height: u32,
        fps: u32,
    ) -> Option<&CodecSupport> {
        self.codecs
            .iter()
            .find(|c| c.supports(codec, bit_depth, chroma, width, height, fps))
    }
}

/// A concrete stream the planner is asked to service: the codec parameters the
/// *encoder output* must satisfy, plus the frame geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRequest {
    /// Desired output codec.
    pub codec: Codec,
    /// Desired output bit depth.
    pub bit_depth: BitDepth,
    /// Desired output chroma.
    pub chroma: Chroma,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Frames per second.
    pub fps: u32,
}

impl StreamRequest {
    /// A common 1080p60 8-bit 4:2:0 request, handy in call sites and tests.
    pub fn h264_1080p60() -> Self {
        Self {
            codec: Codec::H264,
            bit_depth: BitDepth::Eight,
            chroma: Chroma::Yuv420,
            width: 1920,
            height: 1080,
            fps: 60,
        }
    }
}

impl fmt::Display for StreamRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let codec = match self.codec {
            Codec::H264 => "H264",
            Codec::H265 => "H265",
            Codec::Av1 => "AV1",
        };
        let bits = match self.bit_depth {
            BitDepth::Eight => 8,
            BitDepth::Ten => 10,
        };
        let chroma = match self.chroma {
            Chroma::Yuv420 => "4:2:0",
            Chroma::Yuv444 => "4:4:4",
        };
        write!(
            f,
            "{codec} {}x{}@{} {bits}-bit {chroma}",
            self.width, self.height, self.fps
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stability_orders_certified_highest_and_worst_picks_the_weaker() {
        assert!(StabilityTier::Certified > StabilityTier::Compatible);
        assert!(StabilityTier::Compatible > StabilityTier::Experimental);
        assert!(StabilityTier::Experimental > StabilityTier::Unavailable);
        assert_eq!(
            StabilityTier::Certified.worst(StabilityTier::Experimental),
            StabilityTier::Experimental
        );
        assert_eq!(
            StabilityTier::Compatible.worst(StabilityTier::Certified),
            StabilityTier::Compatible
        );
    }

    #[test]
    fn device_local_surfaces_are_everything_but_system_memory() {
        assert!(!SurfaceKind::SystemMemory.is_device_local());
        for kind in [
            SurfaceKind::DmaBuf,
            SurfaceKind::D3D11Texture,
            SurfaceKind::IoSurface,
            SurfaceKind::CudaDevicePtr,
            SurfaceKind::VaapiSurface,
        ] {
            assert!(kind.is_device_local(), "{kind:?} should be device-local");
        }
    }

    #[test]
    fn codec_support_respects_bit_depth_chroma_and_ceiling() {
        let support = CodecSupport {
            codec: Codec::H265,
            bit_depths: vec![BitDepth::Eight, BitDepth::Ten],
            chroma: vec![Chroma::Yuv420],
            limits: Limits::new(3840, 2160, 60),
        };
        assert!(support.supports(Codec::H265, BitDepth::Ten, Chroma::Yuv420, 3840, 2160, 60));
        // wrong codec
        assert!(!support.supports(Codec::H264, BitDepth::Eight, Chroma::Yuv420, 1920, 1080, 30));
        // unsupported chroma
        assert!(!support.supports(Codec::H265, BitDepth::Eight, Chroma::Yuv444, 1920, 1080, 30));
        // over the ceiling
        assert!(!support.supports(Codec::H265, BitDepth::Eight, Chroma::Yuv420, 7680, 4320, 60));
    }

    #[test]
    fn probe_and_stability_gate_usability() {
        assert!(ProbeStatus::Verified.is_usable());
        assert!(ProbeStatus::Advertised.is_usable());
        assert!(!ProbeStatus::Failed("no device".into()).is_usable());
        assert!(StabilityTier::Certified.is_usable());
        assert!(!StabilityTier::Unavailable.is_usable());
    }
}
