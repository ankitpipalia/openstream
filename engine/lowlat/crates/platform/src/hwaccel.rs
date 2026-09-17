//! Hardware-accelerator discovery shared by host adapters.
//!
//! Detection reads the filesystem where that settles the question and
//! otherwise asks the encoder itself, by spawning a bounded probe. It never
//! links or `dlopen`s a driver, so this module still builds on every target.
//! Callers combine the report with their negotiated capabilities to pick an
//! FFmpeg encoder profile; the profiles themselves are spelled out in
//! [`ffmpeg_profile_args`] so every adapter uses identical flags.

/// Accelerators visible on this machine right now.
///
/// Every accelerator is recorded per codec. H.264 and HEVC encode are
/// separate hardware capabilities -- a device can have one and not the
/// other, and older NVIDIA and Intel parts commonly do -- so no single flag
/// may stand for both. The same applies to VAAPI: a `/dev/dri/renderD*`
/// node proves a render device exists, not that it encodes anything, and
/// selecting `hevc_vaapi` because a node is present is how a session
/// negotiates a codec that fails when FFmpeg opens the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HwReport {
    /// At least one `/dev/dri/renderD*` node exists.
    ///
    /// Reported for diagnostics. A render node is a device, not an encoder:
    /// it says nothing about which codecs that device can encode, so it
    /// never selects one on its own.
    pub vaapi_node: bool,
    /// VAAPI can encode H.264 here.
    pub vaapi_h264: bool,
    /// VAAPI can encode HEVC here.
    pub vaapi_hevc: bool,
    /// NVENC can encode H.264 here.
    pub nvenc_h264: bool,
    /// NVENC can encode HEVC here.
    pub nvenc_hevc: bool,
    /// `nvidia-smi` answers, i.e. an NVIDIA kernel driver is loaded.
    ///
    /// Reported for diagnostics only. It is deliberately not a precondition
    /// for NVENC: a container that ships the encode library without the
    /// management tool has no `nvidia-smi` on `PATH` and encodes perfectly
    /// well, and gating on it turned that into a silent fallback to
    /// software.
    pub nvidia_smi: bool,
}

impl HwReport {
    /// Probe the running machine. Never fails; absence is data.
    pub fn probe() -> Self {
        // Ask each encoder whether it works, in the environment the host
        // child will inherit. Nothing here is inferred from a file existing:
        // a library path and a render node are both evidence that userspace
        // is installed, neither is evidence that a codec encodes.
        //
        // The probes run concurrently. Each spawns its own FFmpeg and they
        // share nothing, so running them in sequence only meant that a host
        // with one wedged driver paid every timeout one after another --
        // five bounded waits is a long startup when the whole point of the
        // bound is that something is already broken. Concurrently the worst
        // case is one timeout, not the sum of them.
        let render_node = vaapi_render_node();
        let node = render_node.as_deref();
        let (vaapi_h264, vaapi_hevc, nvenc_h264, nvenc_hevc, nvidia_smi) =
            std::thread::scope(|scope| {
                let vaapi_h264 = scope.spawn(|| vaapi_encoder_usable("h264_vaapi", node));
                let vaapi_hevc = scope.spawn(|| vaapi_encoder_usable("hevc_vaapi", node));
                let nvenc_h264 = scope.spawn(|| ffmpeg_encoder_usable("h264_nvenc"));
                let nvenc_hevc = scope.spawn(|| ffmpeg_encoder_usable("hevc_nvenc"));
                let nvidia_smi = scope.spawn(|| command_exists("nvidia-smi"));
                // A probe thread only panics if the probe itself does, which
                // would be a bug here rather than a property of the machine;
                // treat it as "not available" rather than taking the host
                // down during startup.
                (
                    vaapi_h264.join().unwrap_or(false),
                    vaapi_hevc.join().unwrap_or(false),
                    nvenc_h264.join().unwrap_or(false),
                    nvenc_hevc.join().unwrap_or(false),
                    nvidia_smi.join().unwrap_or(false),
                )
            });
        Self {
            vaapi_node: render_node.is_some(),
            vaapi_h264,
            vaapi_hevc,
            nvenc_h264,
            nvenc_hevc,
            nvidia_smi,
        }
    }

    /// Return the render node selected for VAAPI, if this report found one.
    ///
    /// The node is resolved again rather than stored in the compact boolean
    /// report so callers can construct synthetic reports in tests and so the
    /// public report remains cheap to copy.
    pub fn vaapi_render_node(&self) -> Option<String> {
        self.vaapi_node.then(vaapi_render_node).flatten()
    }

    /// Return the discovered NVIDIA encode library path, if any.
    ///
    /// A machine can encode with NVENC and still report `None` here: the
    /// library may live somewhere the path list does not name, which is
    /// exactly the case the capability probe exists to cover.
    pub fn nvenc_library_location(&self) -> Option<String> {
        nvenc_library_location()
    }

    /// Best FFmpeg encoder this report supports for `codec`, or `None` when
    /// only software encoding is available.
    pub fn preferred_encoder(&self, codec: EncoderCodec) -> Option<&'static str> {
        match codec {
            EncoderCodec::H264 if self.nvenc_h264 => Some("h264_nvenc"),
            EncoderCodec::H265 if self.nvenc_hevc => Some("hevc_nvenc"),
            EncoderCodec::H264 if self.vaapi_h264 => Some("h264_vaapi"),
            EncoderCodec::H265 if self.vaapi_hevc => Some("hevc_vaapi"),
            _ => None,
        }
    }
}

/// Filter-chain suffix an encoder needs appended to `-vf`, if any.
///
/// A VAAPI encoder consumes hardware surfaces, so the software frames coming
/// out of the capture filter have to be converted and uploaded first.
/// Without this FFmpeg fails with "Impossible to convert between the
/// formats", which is the second half of the reason the VAAPI path never
/// produced a frame.
#[must_use]
pub fn encoder_filter_suffix(encoder: &str) -> Option<&'static str> {
    match encoder {
        "h264_vaapi" | "hevc_vaapi" => Some("format=nv12,hwupload"),
        _ => None,
    }
}

/// Decoder implementation requested by the client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderBackend {
    /// Prefer a native zero-copy decoder, then the compatibility fallbacks.
    Auto,
    /// Apple VideoToolbox backed decode.
    VideoToolbox,
    /// FFmpeg process/library decode.
    Ffmpeg,
    /// A CPU decoder owned by the session runner.
    Software,
}

impl DecoderBackend {
    /// Parse a user-facing decoder name. Unknown values remain conservative.
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "videotoolbox" | "vt" => Self::VideoToolbox,
            "ffmpeg" => Self::Ffmpeg,
            "software" | "cpu" => Self::Software,
            _ => Self::Auto,
        }
    }
}

/// A decoder capability with a user-safe reason for unavailability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Ready,
    Unavailable(String),
}

impl Capability {
    pub fn ready() -> Self {
        Self::Ready
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable(reason.into())
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Ready => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// Runtime decoder capabilities discovered by the platform/session layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderCapabilities {
    pub videotoolbox: Capability,
    pub ffmpeg: Capability,
    pub software: Capability,
}

/// Why a requested decoder could not be selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderSelectionError {
    Unavailable {
        backend: DecoderBackend,
        reason: String,
    },
}

impl std::fmt::Display for DecoderSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { backend, reason } => {
                write!(formatter, "{backend:?} decoder unavailable: {reason}")
            }
        }
    }
}

impl std::error::Error for DecoderSelectionError {}

/// Select a decoder without silently claiming that a native path is usable.
/// `Auto` follows the product order VideoToolbox -> FFmpeg -> software; an
/// explicit request returns the recorded capability reason instead.
pub fn resolve_decoder(
    requested: DecoderBackend,
    capabilities: &DecoderCapabilities,
) -> Result<DecoderBackend, DecoderSelectionError> {
    let candidates = [
        (DecoderBackend::VideoToolbox, &capabilities.videotoolbox),
        (DecoderBackend::Ffmpeg, &capabilities.ffmpeg),
        (DecoderBackend::Software, &capabilities.software),
    ];
    if requested == DecoderBackend::Auto {
        if let Some((backend, _)) = candidates
            .iter()
            .find(|(_, capability)| matches!(capability, &&Capability::Ready))
        {
            return Ok(*backend);
        }
        let reason = candidates
            .iter()
            .filter_map(|(backend, capability)| {
                capability
                    .reason()
                    .map(|reason| format!("{backend:?}: {reason}"))
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DecoderSelectionError::Unavailable {
            backend: DecoderBackend::Auto,
            reason,
        });
    }

    let capability = match requested {
        DecoderBackend::VideoToolbox => &capabilities.videotoolbox,
        DecoderBackend::Ffmpeg => &capabilities.ffmpeg,
        DecoderBackend::Software => &capabilities.software,
        DecoderBackend::Auto => unreachable!("auto is handled above"),
    };
    match capability {
        Capability::Ready => Ok(requested),
        Capability::Unavailable(reason) => Err(DecoderSelectionError::Unavailable {
            backend: requested,
            reason: reason.clone(),
        }),
    }
}

/// Codec requested for hardware encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderCodec {
    H264,
    H265,
}

/// Upper bound accepted from environment/configuration before it reaches an
/// encoder process.  Keeping this bound in the shared profile builder means
/// every host adapter rejects the same pathological value.
pub const MAX_VIDEO_BITRATE_MBPS: f64 = 200.0;

impl EncoderCodec {
    /// Parse `h264`/`h265`/`hevc` (case-insensitive).
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "h264" | "avc" => Some(Self::H264),
            "h265" | "hevc" => Some(Self::H265),
            _ => None,
        }
    }
}

const NVENC_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libnvidia-encode.so.1",
    "/usr/lib/x86_64-linux-gnu/nvidia/current/libnvidia-encode.so.1",
    "/usr/lib/x86_64-linux-gnu/nvidia/libnvidia-encode.so.1",
    "/usr/lib/aarch64-linux-gnu/libnvidia-encode.so.1",
    "/usr/lib/aarch64-linux-gnu/nvidia/current/libnvidia-encode.so.1",
    "/usr/lib/aarch64-linux-gnu/nvidia/libnvidia-encode.so.1",
    "/usr/lib64/libnvidia-encode.so.1",
    "/usr/lib/libnvidia-encode.so.1",
    "/usr/lib/wsl/lib/libnvidia-encode.so.1",
    "/run/opengl-driver/lib/libnvidia-encode.so.1",
];

fn path_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

fn nvenc_library_location() -> Option<String> {
    if let Ok(path) = std::env::var("OPENSTREAM_NVENC_LIBRARY")
        && !path.trim().is_empty()
        && path_exists(&path)
    {
        return Some(path);
    }
    NVENC_CANDIDATES
        .iter()
        .find(|path| path_exists(path))
        .map(|path| (*path).to_string())
}

/// Whether FFmpeg can actually open an NVENC encoder session here.
///
/// A list of well-known library paths is not a capability. On a host where
/// the NVIDIA userspace lives somewhere unlisted -- a Flatpak GL runtime,
/// for instance -- every candidate path is absent, NVENC is declared
/// unavailable, and the host silently falls back to VAAPI even though
/// `ffmpeg -encoders` lists `h264_nvenc` and it works. This asks the
/// question that actually matters, in the environment the host child will
/// inherit, by encoding a single tiny frame.
///
/// It spawns a process, so it is not free; callers probe once at startup.
/// How long one encoder probe may take.
///
/// Encoding a single 64x64 frame is sub-second work everywhere it works at
/// all; this bound is for a driver that has wedged, not a slow one. Probes
/// run concurrently, so this is also the worst case for the whole report.
const ENCODER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether FFmpeg can actually open a VAAPI encoder session here.
///
/// A VAAPI encode needs more than the encoder name: it needs the device and
/// the upload that turns software frames into the hardware surfaces the
/// encoder consumes. Probing without them would fail on every machine and
/// prove nothing, so the probe runs the same shape the host will.
fn vaapi_encoder_usable(encoder: &str, render_node: Option<&str>) -> bool {
    let Some(render_node) = render_node else {
        return false;
    };
    let Some(filter) = encoder_filter_suffix(encoder) else {
        return false;
    };
    let ffmpeg = std::env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string());
    run_bounded(
        std::process::Command::new(ffmpeg)
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-vaapi_device",
                render_node,
                "-f",
                "lavfi",
                "-i",
                "nullsrc=s=64x64:d=0.04:r=25",
                "-vf",
                filter,
                "-c:v",
                encoder,
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        ENCODER_PROBE_TIMEOUT,
    )
}

fn ffmpeg_encoder_usable(encoder: &str) -> bool {
    let ffmpeg = std::env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string());
    run_bounded(
        std::process::Command::new(ffmpeg)
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "nullsrc=s=64x64:d=0.04:r=25",
                "-c:v",
                encoder,
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        ENCODER_PROBE_TIMEOUT,
    )
}

/// Order `/dev/dri` entry names into the render nodes, low index first.
///
/// Pulled out of [`vaapi_render_nodes`] so the multi-GPU ordering is a pure
/// function testable without a `/dev/dri` to read: it keeps only `renderD<n>`
/// names and sorts them by their numeric index, so `renderD128` precedes
/// `renderD129` and a stray `card0`/`by-path` entry is dropped.
fn ordered_render_node_names(names: Vec<String>) -> Vec<String> {
    let mut nodes = names
        .into_iter()
        .filter_map(|name| {
            let index = name.strip_prefix("renderD")?.parse::<u32>().ok()?;
            Some((index, name))
        })
        .collect::<Vec<_>>();
    nodes.sort_by_key(|(index, _)| *index);
    nodes.into_iter().map(|(_, name)| name).collect()
}

/// Every VAAPI render node on this host, low index first.
///
/// A multi-GPU host exposes `renderD128`, `renderD129`, ... -- one per DRM
/// render device -- and which one can encode is a per-device question. The
/// pre-1.1 code resolved only the first node and probed VAAPI against it alone,
/// so a second GPU that was the only one able to encode went unseen. This
/// enumerates them all; callers probe per node.
///
/// `OPENSTREAM_VAAPI_RENDER_NODE` still pins exactly one node when set, for a
/// host that has to override discovery.
pub fn vaapi_render_nodes() -> Vec<String> {
    if let Ok(path) = std::env::var("OPENSTREAM_VAAPI_RENDER_NODE") {
        let path = path.trim();
        if path.is_empty() {
            return Vec::new();
        }
        return if path.starts_with("/dev/dri/renderD") && path_exists(path) {
            vec![path.to_string()]
        } else {
            Vec::new()
        };
    }
    let names = std::fs::read_dir("/dev/dri")
        .ok()
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ordered_render_node_names(names)
        .into_iter()
        .map(|name| format!("/dev/dri/{name}"))
        .collect()
}

/// Return the first render node, or `None`. Multi-GPU hosts commonly expose
/// `renderD129`+; enumerate every node with [`vaapi_render_nodes`] when more
/// than the first matters.
pub(crate) fn vaapi_render_node() -> Option<String> {
    vaapi_render_nodes().into_iter().next()
}

fn command_exists(program: &str) -> bool {
    run_bounded(
        std::process::Command::new(program)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        std::time::Duration::from_secs(2),
    )
}

/// Run a command and report whether it succeeded within `limit`. A probe
/// that hangs is a probe that failed; it is never allowed to wedge startup.
fn run_bounded(command: &mut std::process::Command, limit: std::time::Duration) -> bool {
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// FFmpeg output arguments for one hardware encoder profile.
///
/// Bitrate is expressed in Mbps to match `OPENSTREAM_VIDEO_MBPS`. The
/// profiles pin low-latency flags (`zerolatency`-style tuning, no B-frames
/// beyond the encoder default, intra refresh where supported) so a hardware
/// path never silently trades latency for compression.
pub fn ffmpeg_profile_args(
    encoder: &str,
    width: u16,
    height: u16,
    fps: u16,
    bitrate_mbps: f64,
    pix_fmt: &str,
) -> Result<Vec<String>, String> {
    if width == 0 || height == 0 || fps == 0 {
        return Err("encoder dimensions and frame rate must be nonzero".into());
    }
    if !bitrate_mbps.is_finite() || bitrate_mbps <= 0.0 || bitrate_mbps > MAX_VIDEO_BITRATE_MBPS {
        return Err(format!(
            "encoder bitrate must be in the range (0, {MAX_VIDEO_BITRATE_MBPS}] Mbps"
        ));
    }
    let rate = format!("{:.2}M", bitrate_mbps);
    let size = format!("{width}x{height}");
    let rate_fps = fps.to_string();
    let mut args = vec![
        "-s".to_string(),
        size,
        "-r".to_string(),
        rate_fps,
        "-pix_fmt".to_string(),
        pix_fmt.to_string(),
    ];
    match encoder {
        "h264_nvenc" | "hevc_nvenc" => {
            // One frame of VBV. The profile used twice the bitrate, which at
            // 10 Mbps is two seconds of buffer the rate controller may spend
            // before it has to converge -- latency no network tuning
            // recovers. An interactive stream wants the encoder to meet its
            // budget every frame instead.
            let vbv = format!("{:.2}M", bitrate_mbps / f64::from(fps.max(1)));
            args.extend(
                [
                    "-c:v",
                    encoder,
                    "-preset",
                    "p1",
                    // Ultra-low latency, not merely low: `ll` still leaves
                    // the encoder a reordering window.
                    "-tune",
                    "ull",
                    // NVENC defaults `-delay` to INT_MAX and `-zerolatency`
                    // to false, so by default it may hold frames back before
                    // emitting any output. For a desktop driven
                    // interactively that delay buys nothing -- there are no
                    // B-frames to reorder around -- and is paid every frame.
                    "-zerolatency",
                    "1",
                    "-delay",
                    "0",
                    "-rc",
                    "cbr",
                    "-b:v",
                    &rate,
                    "-maxrate",
                    &rate,
                    "-bufsize",
                    &vbv,
                    "-g",
                    &fps.saturating_mul(2).to_string(),
                    "-bf",
                    "0",
                ]
                .iter()
                .map(|flag| flag.to_string()),
            );
        }
        "h264_vaapi" | "hevc_vaapi" => {
            let render_node = vaapi_render_node()
                .ok_or_else(|| "no usable VAAPI render node was found".to_string())?;
            args.extend(
                [
                    // FFmpeg has no `-va_device`. It was spelled that way
                    // here, so every VAAPI encode died on "Unrecognized
                    // option 'va_device'" before a single frame was
                    // produced -- and VAAPI is the fallback chosen whenever
                    // NVENC is not detected, so the fallback never worked.
                    "-vaapi_device",
                    &render_node,
                    "-c:v",
                    encoder,
                    "-b:v",
                    &rate,
                    "-maxrate",
                    &rate,
                    "-g",
                    &fps.saturating_mul(2).to_string(),
                    "-bf",
                    "0",
                ]
                .iter()
                .map(|flag| flag.to_string()),
            );
        }
        "libx264" | "libx265" => {
            args.extend(
                [
                    "-c:v",
                    encoder,
                    "-preset",
                    "ultrafast",
                    "-tune",
                    "zerolatency",
                    "-b:v",
                    &rate,
                    "-maxrate",
                    &rate,
                    "-bufsize",
                    &format!("{:.2}M", bitrate_mbps * 2.0),
                    "-g",
                    &fps.saturating_mul(2).to_string(),
                    "-bf",
                    "0",
                ]
                .iter()
                .map(|flag| flag.to_string()),
            );
        }
        other => return Err(format!("unsupported encoder profile '{other}'")),
    }
    Ok(args)
}

/// Validate a caller-supplied pixel format against the negotiated profile.
pub fn validate_pix_fmt(pix_fmt: &str, allow_10_bit: bool, allow_444: bool) -> Result<(), String> {
    match pix_fmt {
        "yuv420p" => Ok(()),
        "yuv444p" if allow_444 => Ok(()),
        "yuv444p" => Err("yuv444p was not negotiated".into()),
        "yuv420p10le" if allow_10_bit => Ok(()),
        "yuv420p10le" => Err("10-bit output was not negotiated".into()),
        other => Err(format!("unsupported pixel format '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_total_and_repeatable() {
        let first = HwReport::probe();
        let second = HwReport::probe();
        assert_eq!(first, second);
    }

    #[test]
    fn software_only_report_selects_no_encoder() {
        let report = HwReport::default();
        assert_eq!(report.preferred_encoder(EncoderCodec::H264), None);
        assert_eq!(report.preferred_encoder(EncoderCodec::H265), None);
    }

    #[test]
    fn nvenc_wins_over_vaapi_when_both_are_present() {
        let report = HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            vaapi_hevc: true,
            nvenc_h264: true,
            nvenc_hevc: true,
            nvidia_smi: true,
        };
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H264),
            Some("h264_nvenc")
        );
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H265),
            Some("hevc_nvenc")
        );
        let vaapi_only = HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            ..HwReport::default()
        };
        assert_eq!(
            vaapi_only.preferred_encoder(EncoderCodec::H264),
            Some("h264_vaapi")
        );
    }

    /// The exact VAAPI argv, pinned.
    ///
    /// This profile shipped with `-va_device`, which FFmpeg does not
    /// accept, so every VAAPI encode failed on argument parsing before
    /// producing a frame -- and VAAPI is what the host falls back to
    /// whenever NVENC is not detected. A spelling mistake in a fallback is
    /// invisible until the fallback is the only thing left, so the flag is
    /// asserted literally here.
    #[test]
    fn the_vaapi_profile_uses_the_option_ffmpeg_actually_has() {
        let Some(node) = vaapi_render_node() else {
            // No render node on this machine; the profile cannot be built
            // and there is nothing to pin.
            return;
        };
        let args = ffmpeg_profile_args("h264_vaapi", 1920, 1080, 60, 10.0, "yuv420p")
            .expect("a render node exists, so the profile builds");

        assert!(
            args.iter().any(|arg| arg == "-vaapi_device"),
            "FFmpeg has no -va_device: {args:?}"
        );
        assert!(
            !args.iter().any(|arg| arg == "-va_device"),
            "the misspelled option must not come back: {args:?}"
        );
        let device = args
            .windows(2)
            .find(|pair| pair[0] == "-vaapi_device")
            .map(|pair| pair[1].clone())
            .expect("-vaapi_device carries the render node");
        assert_eq!(device, node);
    }

    /// A VAAPI encoder takes hardware surfaces, so the filter chain has to
    /// upload them. Without this FFmpeg refuses the conversion, which is
    /// the other half of why the VAAPI path never produced a frame.
    #[test]
    fn hardware_frame_encoders_declare_their_upload_filter() {
        assert_eq!(
            encoder_filter_suffix("h264_vaapi"),
            Some("format=nv12,hwupload")
        );
        assert_eq!(
            encoder_filter_suffix("hevc_vaapi"),
            Some("format=nv12,hwupload")
        );
        // NVENC takes software frames directly.
        assert_eq!(encoder_filter_suffix("h264_nvenc"), None);
        assert_eq!(encoder_filter_suffix("libx264"), None);
    }

    /// H.264 and HEVC NVENC are separate hardware capabilities.
    ///
    /// A card that encodes H.264 need not encode HEVC -- older NVIDIA
    /// silicon routinely does not -- so proving one must never advertise
    /// the other. A single flag derived from an H.264 probe did exactly
    /// that, and the session would negotiate HEVC the machine cannot encode.
    #[test]
    fn h264_nvenc_does_not_imply_hevc_nvenc() {
        let h264_only = HwReport {
            nvenc_h264: true,
            ..HwReport::default()
        };
        assert_eq!(
            h264_only.preferred_encoder(EncoderCodec::H264),
            Some("h264_nvenc")
        );
        assert_eq!(
            h264_only.preferred_encoder(EncoderCodec::H265),
            None,
            "HEVC was never probed, so it must not be offered"
        );

        // ...and a card with only HEVC still offers HEVC.
        let hevc_only = HwReport {
            nvenc_hevc: true,
            ..HwReport::default()
        };
        assert_eq!(hevc_only.preferred_encoder(EncoderCodec::H264), None);
        assert_eq!(
            hevc_only.preferred_encoder(EncoderCodec::H265),
            Some("hevc_nvenc")
        );
    }

    /// NVENC must not require `nvidia-smi`.
    ///
    /// A container that ships the encode library without the management
    /// tool has no `nvidia-smi` on `PATH` and encodes perfectly well.
    /// Gating on it turned that into a silent fallback to VAAPI or software.
    #[test]
    fn nvenc_does_not_require_the_management_tool() {
        let report = HwReport {
            nvenc_h264: true,
            nvenc_hevc: true,
            nvidia_smi: false,
            ..HwReport::default()
        };
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H264),
            Some("h264_nvenc")
        );
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H265),
            Some("hevc_nvenc")
        );
    }

    /// With no NVENC, a VAAPI encoder that was actually probed is used.
    #[test]
    fn vaapi_is_the_fallback_when_nvenc_is_absent() {
        let report = HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            vaapi_hevc: true,
            ..HwReport::default()
        };
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H264),
            Some("h264_vaapi")
        );
        assert_eq!(
            report.preferred_encoder(EncoderCodec::H265),
            Some("hevc_vaapi")
        );
    }

    /// A probe that will not finish is abandoned, promptly, and reaped.
    ///
    /// The bound exists for a wedged driver, and it runs during host
    /// startup, so it has to return within the limit rather than when the
    /// child feels like it, and must not leave the child behind.
    ///
    /// What this does *not* check is that the wait yields the core between
    /// polls: a spin loop would satisfy every assertion below while burning
    /// a CPU for the whole timeout, on precisely the machine already in
    /// trouble. That property is held by the `sleep` in `run_bounded` and
    /// is verified by reading it, not by this test.
    #[test]
    fn a_probe_that_never_finishes_is_bounded_and_reaped() {
        let mut command = std::process::Command::new("sleep");
        command
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let started = std::time::Instant::now();
        let usable = run_bounded(&mut command, std::time::Duration::from_millis(200));
        let elapsed = started.elapsed();

        assert!(!usable, "a child that never exits is not a working encoder");
        assert!(
            elapsed >= std::time::Duration::from_millis(200),
            "returned before the limit: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "waited far past the limit: {elapsed:?}"
        );
        // `run_bounded` kills and then waits, so the child is reaped rather
        // than left as a zombie. If it had not been waited on, this test
        // process would accumulate one per run.
    }

    /// A probe that exits reports its status, and does not wait out the
    /// limit to do it.
    #[test]
    fn a_probe_that_finishes_is_answered_immediately() {
        let mut ok = std::process::Command::new("true");
        ok.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let started = std::time::Instant::now();
        assert!(run_bounded(&mut ok, std::time::Duration::from_secs(5)));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a child that exits at once must not wait out the limit"
        );

        let mut fails = std::process::Command::new("false");
        fails
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        assert!(!run_bounded(&mut fails, std::time::Duration::from_secs(5)));

        // A program that does not exist is not a working encoder either.
        let mut missing = std::process::Command::new("openstream-no-such-binary");
        assert!(!run_bounded(
            &mut missing,
            std::time::Duration::from_secs(5)
        ));
    }

    /// A render node is a device, not an encoder.
    ///
    /// `/dev/dri/renderD*` existing proves a DRM render device is present.
    /// It does not prove the device encodes H.264, and it certainly does not
    /// prove HEVC -- older Intel and AMD parts commonly have one without the
    /// other. Selecting an encoder from node presence is the same
    /// capability-from-presence mistake the NVENC probe just stopped making,
    /// and it fails later and less legibly: FFmpeg opens the encoder and
    /// dies after the session has already negotiated the codec.
    #[test]
    fn a_render_node_alone_selects_nothing() {
        let node_only = HwReport {
            vaapi_node: true,
            ..HwReport::default()
        };
        assert_eq!(node_only.preferred_encoder(EncoderCodec::H264), None);
        assert_eq!(node_only.preferred_encoder(EncoderCodec::H265), None);
    }

    /// VAAPI H.264 without HEVC is a real configuration, and must not
    /// advertise HEVC.
    #[test]
    fn vaapi_h264_does_not_imply_vaapi_hevc() {
        let h264_only = HwReport {
            vaapi_node: true,
            vaapi_h264: true,
            ..HwReport::default()
        };
        assert_eq!(
            h264_only.preferred_encoder(EncoderCodec::H264),
            Some("h264_vaapi")
        );
        assert_eq!(
            h264_only.preferred_encoder(EncoderCodec::H265),
            None,
            "HEVC VAAPI was never probed, so it must not be offered"
        );
    }

    /// NVENC still wins over VAAPI per codec: a card with NVENC H.264 and
    /// VAAPI HEVC uses each where it has it.
    #[test]
    fn each_codec_picks_its_own_best_encoder() {
        let mixed = HwReport {
            vaapi_node: true,
            vaapi_hevc: true,
            nvenc_h264: true,
            ..HwReport::default()
        };
        assert_eq!(
            mixed.preferred_encoder(EncoderCodec::H264),
            Some("h264_nvenc")
        );
        assert_eq!(
            mixed.preferred_encoder(EncoderCodec::H265),
            Some("hevc_vaapi")
        );
    }

    #[test]
    fn nvenc_profile_pins_low_latency_flags() {
        let args = ffmpeg_profile_args("h264_nvenc", 1920, 1080, 60, 10.0, "yuv420p")
            .expect("nvenc profile");
        let joined = args.join(" ");
        assert!(joined.contains("-preset p1"));
        // `ull`, not `ll`: the merely-low tuning still leaves the encoder a
        // reordering window, which an interactive desktop pays for on every
        // frame and gains nothing from.
        assert!(joined.contains("-tune ull"));
        assert!(joined.contains("-b:v 10.00M"));
        assert!(joined.contains("-bf 0"));
    }

    #[test]
    fn vaapi_profile_names_the_render_node() {
        match vaapi_render_node() {
            Some(node) => {
                let args = ffmpeg_profile_args("h264_vaapi", 1280, 720, 30, 4.0, "yuv420p")
                    .expect("vaapi profile");
                assert!(args.iter().any(|argument| argument == &node));
            }
            None => {
                assert!(ffmpeg_profile_args("h264_vaapi", 1280, 720, 30, 4.0, "yuv420p").is_err())
            }
        }
    }

    #[test]
    fn invalid_profiles_are_rejected_before_ffmpeg_starts() {
        assert!(ffmpeg_profile_args("h264_nvenc", 0, 1080, 60, 10.0, "yuv420p").is_err());
        assert!(ffmpeg_profile_args("mpeg2video", 1920, 1080, 60, 10.0, "yuv420p").is_err());
        assert!(ffmpeg_profile_args("h264_nvenc", 1920, 1080, 60, f64::NAN, "yuv420p").is_err());
        assert!(
            ffmpeg_profile_args(
                "h264_nvenc",
                1920,
                1080,
                60,
                MAX_VIDEO_BITRATE_MBPS + 0.1,
                "yuv420p"
            )
            .is_err()
        );
    }

    /// NVENC must not be left free to hold frames back.
    ///
    /// It defaults `-delay` to INT_MAX and `-zerolatency` to false, so out of
    /// the box the encoder may buffer before emitting anything. For a desktop
    /// being driven interactively that delay buys nothing -- there are no
    /// B-frames to reorder around -- and it is paid on every frame.
    #[test]
    fn the_nvenc_profile_does_not_let_the_encoder_hold_frames() {
        let args = ffmpeg_profile_args("h264_nvenc", 1920, 1080, 60, 12.0, "yuv420p")
            .expect("the NVENC profile builds without probing hardware");
        let pair = |flag: &str, value: &str| {
            args.windows(2)
                .any(|window| window[0] == flag && window[1] == value)
        };

        assert!(pair("-zerolatency", "1"), "{args:?}");
        assert!(pair("-delay", "0"), "{args:?}");
        assert!(pair("-tune", "ull"), "{args:?}");
        assert!(pair("-bf", "0"), "no B-frames to reorder around: {args:?}");

        // One frame of VBV, not a multiple of the bitrate. At 12 Mbps and
        // 60 fps that is 0.20 Mb, where twice the bitrate would have been
        // 24 Mb -- two seconds of slack for the rate controller to spend.
        let bufsize = args
            .windows(2)
            .find(|window| window[0] == "-bufsize")
            .map(|window| window[1].clone())
            .expect("the profile sets a VBV size");
        assert_eq!(bufsize, "0.20M", "one frame of VBV at 12 Mbps / 60 fps");
    }

    /// Multi-GPU render nodes enumerate in device order, and non-render `/dev/dri`
    /// entries are ignored.
    ///
    /// The pre-1.1 code took the first node and probed VAAPI against it alone.
    /// On a laptop with an Intel iGPU on `renderD128` and a discrete GPU on
    /// `renderD129`, that hid whichever device was not first -- including the
    /// case where only the second one can encode. Ordering is by numeric index,
    /// not directory-listing order, so it does not depend on how the kernel
    /// happens to return entries.
    #[test]
    fn render_nodes_enumerate_in_device_order() {
        let names = vec![
            "renderD129".to_string(),
            "card0".to_string(),
            "renderD128".to_string(),
            "by-path".to_string(),
            "renderD130".to_string(),
        ];
        assert_eq!(
            ordered_render_node_names(names),
            vec!["renderD128", "renderD129", "renderD130"]
        );
    }

    #[test]
    fn a_host_with_no_render_nodes_enumerates_empty() {
        assert!(ordered_render_node_names(vec!["card0".into(), "controlD64".into()]).is_empty());
    }

    #[test]
    fn pix_fmt_follows_negotiation() {
        assert!(validate_pix_fmt("yuv420p", false, false).is_ok());
        assert!(validate_pix_fmt("yuv444p", false, false).is_err());
        assert!(validate_pix_fmt("yuv444p", false, true).is_ok());
        assert!(validate_pix_fmt("yuv420p10le", false, false).is_err());
        assert!(validate_pix_fmt("yuv420p10le", true, false).is_ok());
        assert!(validate_pix_fmt("rgb24", true, true).is_err());
    }

    #[test]
    fn codec_names_parse_case_insensitively() {
        assert_eq!(EncoderCodec::parse("H264"), Some(EncoderCodec::H264));
        assert_eq!(EncoderCodec::parse("hevc"), Some(EncoderCodec::H265));
        assert_eq!(EncoderCodec::parse("av1"), None);
    }

    #[test]
    fn auto_decoder_prefers_videotoolbox_then_ffmpeg_then_software() {
        let capabilities = DecoderCapabilities {
            videotoolbox: Capability::ready(),
            ffmpeg: Capability::ready(),
            software: Capability::ready(),
        };
        assert_eq!(
            resolve_decoder(DecoderBackend::Auto, &capabilities),
            Ok(DecoderBackend::VideoToolbox)
        );

        let capabilities = DecoderCapabilities {
            videotoolbox: Capability::unavailable("not on this target"),
            ..capabilities
        };
        assert_eq!(
            resolve_decoder(DecoderBackend::Auto, &capabilities),
            Ok(DecoderBackend::Ffmpeg)
        );

        let capabilities = DecoderCapabilities {
            videotoolbox: Capability::unavailable("not on this target"),
            ffmpeg: Capability::unavailable("ffmpeg missing"),
            ..capabilities
        };
        assert_eq!(
            resolve_decoder(DecoderBackend::Auto, &capabilities),
            Ok(DecoderBackend::Software)
        );
    }

    #[test]
    fn explicit_decoder_requests_fail_with_the_capability_reason() {
        let capabilities = DecoderCapabilities {
            videotoolbox: Capability::unavailable("VideoToolbox requires macOS"),
            ffmpeg: Capability::ready(),
            software: Capability::ready(),
        };
        assert_eq!(
            resolve_decoder(DecoderBackend::VideoToolbox, &capabilities),
            Err(DecoderSelectionError::Unavailable {
                backend: DecoderBackend::VideoToolbox,
                reason: "VideoToolbox requires macOS".to_string(),
            })
        );
        assert_eq!(
            resolve_decoder(DecoderBackend::Ffmpeg, &capabilities),
            Ok(DecoderBackend::Ffmpeg)
        );
    }
}
