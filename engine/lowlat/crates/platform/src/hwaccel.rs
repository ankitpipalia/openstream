//! Hardware-accelerator discovery shared by host adapters.
//!
//! Detection is filesystem-only (no linked drivers, no dlopen here) so this
//! module builds on every target. Callers combine the report with their
//! negotiated capabilities to pick an FFmpeg encoder profile; the profiles
//! themselves are spelled out in [`ffmpeg_profile_args`] so every adapter
//! uses identical flags.

/// Accelerators visible on this machine right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HwReport {
    /// At least one `/dev/dri/renderD*` node exists (VAAPI candidate).
    pub vaapi_node: bool,
    /// The NVIDIA userspace encode library is installed.
    pub nvenc_library: bool,
    /// `nvidia-smi` answers, i.e. an NVIDIA kernel driver is loaded.
    pub nvidia_smi: bool,
}

impl HwReport {
    /// Probe the running machine. Never fails; absence is data.
    pub fn probe() -> Self {
        let nvidia_smi = command_exists("nvidia-smi");
        // Prefer the cheap answer, but do not let an unlisted library path
        // demote a working encoder to the software/VAAPI fallback. The
        // capability probe only runs when the driver is loaded and the
        // library search came up empty, so the common cases stay free.
        let nvenc_library = nvenc_library_location().is_some()
            || (nvidia_smi && ffmpeg_encoder_usable("h264_nvenc"));
        Self {
            vaapi_node: vaapi_node_present(),
            nvenc_library,
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
    pub fn nvenc_library_location(&self) -> Option<String> {
        self.nvenc_library.then(nvenc_library_location).flatten()
    }

    /// Best FFmpeg encoder this report supports for `codec`, or `None` when
    /// only software encoding is available.
    pub fn preferred_encoder(&self, codec: EncoderCodec) -> Option<&'static str> {
        match codec {
            EncoderCodec::H264 => {
                if self.nvenc_library && self.nvidia_smi {
                    Some("h264_nvenc")
                } else if self.vaapi_node {
                    Some("h264_vaapi")
                } else {
                    None
                }
            }
            EncoderCodec::H265 => {
                if self.nvenc_library && self.nvidia_smi {
                    Some("hevc_nvenc")
                } else if self.vaapi_node {
                    Some("hevc_vaapi")
                } else {
                    None
                }
            }
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

fn vaapi_node_present() -> bool {
    vaapi_render_node().is_some()
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
        std::time::Duration::from_secs(10),
    )
}

/// Return a real render node instead of assuming the first GPU is always
/// `renderD128`. Multi-GPU hosts commonly expose renderD129+ and selecting the
/// wrong node makes FFmpeg fail after negotiation.
fn vaapi_render_node() -> Option<String> {
    if let Ok(path) = std::env::var("OPENSTREAM_VAAPI_RENDER_NODE") {
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        return (path.starts_with("/dev/dri/renderD") && path_exists(path))
            .then(|| path.to_string());
    }
    let mut nodes = std::fs::read_dir("/dev/dri")
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            name.strip_prefix("renderD")?.parse::<u32>().ok()?;
            Some((name, entry.path()))
        })
        .collect::<Vec<_>>();
    nodes.sort_by_key(|(name, _)| {
        name.strip_prefix("renderD")
            .and_then(|number| number.parse::<u32>().ok())
    });
    nodes
        .into_iter()
        .next()
        .map(|(_, path)| path.to_string_lossy().into_owned())
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
            args.extend(
                [
                    "-c:v",
                    encoder,
                    "-preset",
                    "p1",
                    "-tune",
                    "ll",
                    "-rc",
                    "vbr",
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
            nvenc_library: true,
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

    #[test]
    fn nvenc_library_without_a_loaded_driver_is_not_selected() {
        let report = HwReport {
            nvenc_library: true,
            ..HwReport::default()
        };
        assert_eq!(report.preferred_encoder(EncoderCodec::H264), None);
    }

    #[test]
    fn nvenc_profile_pins_low_latency_flags() {
        let args = ffmpeg_profile_args("h264_nvenc", 1920, 1080, 60, 10.0, "yuv420p")
            .expect("nvenc profile");
        let joined = args.join(" ");
        assert!(joined.contains("-preset p1"));
        assert!(joined.contains("-tune ll"));
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
