use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod descriptors;

pub use descriptors::{
    CapabilityState, SettingApplyMode, SettingDescriptor, SettingScope, SettingVisibility,
    setting_descriptors,
};

/// The on-disk schema version. This is deliberately independent from the
/// application, protocol, and database versions.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;
const MAX_NAME_BYTES: usize = 128;
const MAX_ORIGIN_BYTES: usize = 2048;
const MAX_FFMPEG_PATH_BYTES: usize = 4096;

macro_rules! string_mode {
    ($name:ident { $( $variant:ident => $text:literal ),+ $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $( $variant, )+
            Unknown(String),
        }

        impl Default for $name {
            fn default() -> Self { Self::Auto }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                let text = match self {
                    $( Self::$variant => $text, )+
                    Self::Unknown(value) => value.as_str(),
                };
                serializer.serialize_str(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Ok(match value.as_str() {
                    $( $text => Self::$variant, )+
                    _ => Self::Unknown(value),
                })
            }
        }
    };
}

macro_rules! string_mode_with_default {
    ($name:ident, $default:ident { $( $variant:ident => $text:literal ),+ $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $( $variant, )+
            Unknown(String),
        }

        impl Default for $name {
            fn default() -> Self { Self::$default }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                let text = match self {
                    $( Self::$variant => $text, )+
                    Self::Unknown(value) => value.as_str(),
                };
                serializer.serialize_str(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Ok(match value.as_str() {
                    $( $text => Self::$variant, )+
                    _ => Self::Unknown(value),
                })
            }
        }
    };
}

string_mode_with_default!(StreamProfile, Balanced {
    Performance => "performance",
    Balanced => "balanced",
    Quality => "quality",
    Custom => "custom",
});

string_mode_with_default!(WindowMode, Windowed {
    Windowed => "windowed",
    Borderless => "borderless",
    Fullscreen => "fullscreen",
});

string_mode_with_default!(VsyncMode, Auto {
    Auto => "auto",
    On => "on",
    Off => "off",
});

/// Compatibility spelling for callers that capitalize the acronym.
pub type VSyncMode = VsyncMode;

string_mode_with_default!(ChromaPreference, Auto {
    Auto => "auto",
    Yuv420 => "yuv420",
    Yuv444 => "yuv444",
});

string_mode_with_default!(BitDepthPreference, Auto {
    Auto => "auto",
    Eight => "8",
    Ten => "10",
});

string_mode_with_default!(AudioCodec, Opus {
    Opus => "opus",
});

string_mode_with_default!(AudioLatencyMode, Balanced {
    Low => "low",
    Balanced => "balanced",
    Quality => "quality",
});

string_mode_with_default!(CongestionIntent, Balanced {
    LowLatency => "low_latency",
    Balanced => "balanced",
    Throughput => "throughput",
});

string_mode!(RendererMode {
    Auto => "auto",
    Software => "software",
    Metal => "metal",
    Vulkan => "vulkan",
    Dx12 => "dx12",
});

string_mode!(DecoderMode {
    Auto => "auto",
    Hardware => "hardware",
    Software => "software",
    VideoToolbox => "videotoolbox",
});

string_mode!(EncoderMode {
    Auto => "auto",
    Software => "software",
    H264Nvenc => "h264_nvenc",
    HevcNvenc => "hevc_nvenc",
    H264Vaapi => "h264_vaapi",
    HevcVaapi => "hevc_vaapi",
});

string_mode!(CaptureMode {
    Auto => "auto",
    X11 => "x11grab",
    Pipewire => "pipewire",
    Drm => "drm",
});

string_mode!(CodecPreference {
    Auto => "auto",
    H264 => "h264",
    H265 => "h265",
});

string_mode!(PixelFormat {
    Auto => "auto",
    Yuv420p => "yuv420p",
    Yuv444p => "yuv444p",
    Yuv420p10le => "yuv420p10le",
});

string_mode!(ApprovalMode {
    Auto => "auto",
    Prompt => "prompt",
});

/// A reference into a platform secret store. The reference is safe to persist;
/// the secret value is intentionally not representable by this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(name: impl Into<String>) -> Result<Self, SettingsError> {
        let name = name.into();
        if name.is_empty() || name.len() > 128 {
            return Err(SettingsError::InvalidSecretReference {
                reason: "name must contain 1..=128 bytes".to_string(),
            });
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(SettingsError::InvalidSecretReference {
                reason: "name may contain only ASCII letters, digits, '-', '_' or '.'".to_string(),
            });
        }
        Ok(Self(name))
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "current_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub device: DeviceConfig,
    #[serde(default)]
    pub client: ClientConfig,
    #[serde(default)]
    pub host: HostConfig,
    #[serde(default)]
    pub video: VideoConfig,
    #[serde(default)]
    pub audio: AudioConfig,
    #[serde(default)]
    pub input: InputConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceConfig {
    #[serde(default = "default_device_name")]
    pub name: String,
    #[serde(default)]
    pub identity_key: Option<SecretRef>,
    #[serde(default)]
    pub control_credential: Option<SecretRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_signal_origin")]
    pub signal_origin: String,
    #[serde(default)]
    pub profile: StreamProfile,
    #[serde(default)]
    pub window_mode: WindowMode,
    #[serde(default)]
    pub renderer: RendererMode,
    #[serde(default)]
    pub decoder: DecoderMode,
    #[serde(default)]
    pub codec: CodecPreference,
    #[serde(default)]
    pub vsync: VsyncMode,
    #[serde(default)]
    pub chroma: ChromaPreference,
    #[serde(default)]
    pub bit_depth: BitDepthPreference,
    #[serde(default)]
    pub immersive: bool,
    #[serde(default = "default_true")]
    pub show_warnings: bool,
    #[serde(default)]
    pub bandwidth_cap_mbps: Option<f64>,
    #[serde(default = "default_true")]
    pub overlay: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_host_name")]
    pub name: String,
    #[serde(default)]
    pub stay_awake: bool,
    #[serde(default)]
    pub capture: CaptureMode,
    #[serde(default)]
    pub encoder: EncoderMode,
    #[serde(default)]
    pub aggregate_bandwidth_cap_mbps: Option<f64>,
    #[serde(default)]
    pub approval: ApprovalMode,
    #[serde(default = "default_max_guests")]
    pub max_guests: u8,
    #[serde(default)]
    pub selected_display: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoConfig {
    #[serde(default = "default_width")]
    pub width: u32,
    #[serde(default = "default_height")]
    pub height: u32,
    #[serde(default = "default_fps")]
    pub fps: u16,
    #[serde(default = "default_bitrate")]
    pub bitrate_mbps: f64,
    #[serde(default = "default_min_bitrate")]
    pub min_bitrate_mbps: f64,
    #[serde(default)]
    pub codec: CodecPreference,
    #[serde(default)]
    pub pixel_format: PixelFormat,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub codec: AudioCodec,
    #[serde(default = "default_audio_bitrate")]
    pub bitrate_kbps: u16,
    #[serde(default)]
    pub latency_mode: AudioLatencyMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub keyboard: bool,
    #[serde(default)]
    pub mouse: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub gamepad: bool,
    #[serde(default)]
    pub microphone: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub upnp: bool,
    #[serde(default)]
    pub ice: bool,
    #[serde(default)]
    pub turn: bool,
    #[serde(default)]
    pub force_relay: bool,
    #[serde(default)]
    pub local_no_auth: bool,
    #[serde(default)]
    pub udp_port: Option<u16>,
    #[serde(default)]
    pub client_port: Option<u16>,
    #[serde(default)]
    pub host_start_port: Option<u16>,
    #[serde(default)]
    pub congestion: CongestionIntent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyConfig {
    #[serde(default = "default_true")]
    pub redact_diagnostics: bool,
    #[serde(default)]
    pub remember_last_host: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvancedConfig {
    #[serde(default)]
    pub ffmpeg_path: Option<String>,
    #[serde(default)]
    pub ffmpeg_reconfigure: bool,
    #[serde(default = "default_session_seconds")]
    pub max_session_seconds: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettingsFile {
    pub path: PathBuf,
    pub config: AppConfig,
    pub migrated_from: Option<u32>,
}

/// A validated configuration after profile policy and explicit low-level
/// overrides have been resolved. This is an in-memory contract and is never
/// written as the settings file shape.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveConfig {
    pub schema_version: u32,
    pub device: DeviceConfig,
    pub profile: StreamProfile,
    pub client: ClientConfig,
    pub host: HostConfig,
    pub video: VideoConfig,
    pub audio: AudioConfig,
    pub input: InputConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug)]
pub enum SettingsError {
    Io { path: PathBuf, source: io::Error },
    Json(String),
    UnsupportedSchema { found: u32, supported: u32 },
    InvalidField { field: String, reason: String },
    InvalidSecretReference { reason: String },
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "settings I/O at {}: {source}", path.display())
            }
            Self::Json(reason) => write!(formatter, "invalid settings JSON: {reason}"),
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "settings schema {found} is newer than supported schema {supported}"
            ),
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid settings field {field}: {reason}")
            }
            Self::InvalidSecretReference { reason } => {
                write!(formatter, "invalid secret reference: {reason}")
            }
        }
    }
}

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), SettingsError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(SettingsError::UnsupportedSchema {
                found: self.schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
        validate_text("device.name", &self.device.name, 1, MAX_NAME_BYTES)?;
        validate_text("host.name", &self.host.name, 1, MAX_NAME_BYTES)?;
        validate_text(
            "client.signal_origin",
            &self.client.signal_origin,
            1,
            MAX_ORIGIN_BYTES,
        )?;
        if self.client.signal_origin.chars().any(char::is_whitespace) {
            return invalid("client.signal_origin", "must not contain whitespace");
        }
        validate_mode("client.profile", &self.client.profile, is_profile_known)?;
        validate_mode("client.window_mode", &self.client.window_mode, is_window_known)?;
        validate_mode("client.renderer", &self.client.renderer, is_renderer_known)?;
        validate_mode("client.decoder", &self.client.decoder, is_decoder_known)?;
        validate_mode("client.codec", &self.client.codec, is_codec_known)?;
        validate_mode("client.vsync", &self.client.vsync, is_vsync_known)?;
        validate_mode("client.chroma", &self.client.chroma, is_chroma_known)?;
        validate_mode(
            "client.bit_depth",
            &self.client.bit_depth,
            is_bit_depth_known,
        )?;
        validate_mode("host.capture", &self.host.capture, is_capture_known)?;
        validate_mode("host.encoder", &self.host.encoder, is_encoder_known)?;
        validate_mode("host.approval", &self.host.approval, is_approval_known)?;
        validate_mode("audio.codec", &self.audio.codec, is_audio_codec_known)?;
        validate_mode(
            "audio.latency_mode",
            &self.audio.latency_mode,
            is_audio_latency_known,
        )?;
        validate_mode(
            "network.congestion",
            &self.network.congestion,
            is_congestion_known,
        )?;
        validate_mode("video.codec", &self.video.codec, is_codec_known)?;
        validate_mode(
            "video.pixel_format",
            &self.video.pixel_format,
            is_pixel_known,
        )?;
        if !(1..=32).contains(&self.host.max_guests) {
            return invalid("host.max_guests", "must be in 1..=32");
        }
        if !(64..=7680).contains(&self.video.width) {
            return invalid("video.width", "must be in 64..=7680");
        }
        if !(64..=4320).contains(&self.video.height) {
            return invalid("video.height", "must be in 64..=4320");
        }
        if !(1..=240).contains(&self.video.fps) {
            return invalid("video.fps", "must be in 1..=240");
        }
        validate_rate("video.bitrate_mbps", self.video.bitrate_mbps, 0.1, 200.0)?;
        validate_rate(
            "video.min_bitrate_mbps",
            self.video.min_bitrate_mbps,
            0.1,
            200.0,
        )?;
        if self.video.min_bitrate_mbps > self.video.bitrate_mbps {
            return invalid(
                "video.min_bitrate_mbps",
                "must not exceed video.bitrate_mbps",
            );
        }
        if let Some(rate) = self.client.bandwidth_cap_mbps {
            validate_rate("client.bandwidth_cap_mbps", rate, 0.1, 1000.0)?;
        }
        if let Some(rate) = self.host.aggregate_bandwidth_cap_mbps {
            validate_rate("host.aggregate_bandwidth_cap_mbps", rate, 0.1, 1000.0)?;
        }
        if !(8..=512).contains(&self.audio.bitrate_kbps) {
            return invalid("audio.bitrate_kbps", "must be in 8..=512");
        }
        if let Some(port) = self.network.udp_port {
            if port == 0 {
                return invalid("network.udp_port", "must not be zero");
            }
        }
        if let Some(port) = self.network.client_port {
            if port == 0 {
                return invalid("network.client_port", "must not be zero");
            }
        }
        if let Some(port) = self.network.host_start_port {
            if port == 0 {
                return invalid("network.host_start_port", "must not be zero");
            }
        }
        if let Some(display) = &self.host.selected_display {
            validate_text("host.selected_display", display, 1, 128)?;
        }
        if let Some(path) = &self.advanced.ffmpeg_path {
            validate_text("advanced.ffmpeg_path", path, 1, MAX_FFMPEG_PATH_BYTES)?;
        }
        if !(1..=86_400).contains(&self.advanced.max_session_seconds) {
            return invalid("advanced.max_session_seconds", "must be in 1..=86400");
        }
        if let Some(reference) = &self.device.identity_key {
            SecretRef::new(reference.name().to_string())?;
        }
        if let Some(reference) = &self.device.control_credential {
            SecretRef::new(reference.name().to_string())?;
        }
        Ok(())
    }

    /// Resolve the selected profile and any low-level overrides into the
    /// configuration consumed by a session or host runner.
    #[must_use]
    pub fn effective(&self) -> EffectiveConfig {
        effective_config(self)
    }
}

/// Return a complete safe configuration for a first local session.
pub fn default_config() -> AppConfig {
    AppConfig {
        schema_version: CURRENT_SCHEMA_VERSION,
        device: DeviceConfig::default(),
        client: ClientConfig::default(),
        host: HostConfig::default(),
        video: VideoConfig::default(),
        audio: AudioConfig::default(),
        input: InputConfig::default(),
        network: NetworkConfig::default(),
        privacy: PrivacyConfig::default(),
        advanced: AdvancedConfig::default(),
    }
}

/// Resolve platform defaults, the selected profile, and explicit low-level
/// edits in a stable order. Values that differ from the Balanced baseline are
/// treated as explicit overrides when a named profile is selected; this keeps
/// profile policy from being copied into the persisted settings blob.
pub fn effective_config(config: &AppConfig) -> EffectiveConfig {
    let baseline = profile_config(StreamProfile::Balanced);
    let selected_profile = config.client.profile.clone();
    let named_profile = matches!(
        &selected_profile,
        StreamProfile::Performance | StreamProfile::Balanced | StreamProfile::Quality
    );
    let resolved_profile = resolve_profile(config, &baseline);
    let mut effective = EffectiveConfig::from_config(config, resolved_profile.clone());

    if named_profile {
        let policy = profile_config(selected_profile);
        apply_profile_policy(&mut effective, config, &baseline, &policy);
    }

    effective.profile = resolved_profile.clone();
    effective.client.profile = resolved_profile;
    effective
}

fn resolve_profile(config: &AppConfig, baseline: &AppConfig) -> StreamProfile {
    if matches!(config.client.profile, StreamProfile::Custom) {
        return StreamProfile::Custom;
    }
    if profile_overridden(config, baseline) {
        StreamProfile::Custom
    } else {
        config.client.profile.clone()
    }
}

fn profile_overridden(config: &AppConfig, baseline: &AppConfig) -> bool {
    config.client.renderer != baseline.client.renderer
        || config.client.decoder != baseline.client.decoder
        || config.client.codec != baseline.client.codec
        || config.client.vsync != baseline.client.vsync
        || config.client.chroma != baseline.client.chroma
        || config.client.bit_depth != baseline.client.bit_depth
        || config.client.bandwidth_cap_mbps != baseline.client.bandwidth_cap_mbps
        || config.video != baseline.video
}

fn apply_profile_policy(
    effective: &mut EffectiveConfig,
    source: &AppConfig,
    baseline: &AppConfig,
    policy: &AppConfig,
) {
    if source.client.renderer == baseline.client.renderer {
        effective.client.renderer = policy.client.renderer.clone();
    }
    if source.client.decoder == baseline.client.decoder {
        effective.client.decoder = policy.client.decoder.clone();
    }
    if source.client.codec == baseline.client.codec {
        effective.client.codec = policy.client.codec.clone();
    }
    if source.client.vsync == baseline.client.vsync {
        effective.client.vsync = policy.client.vsync.clone();
    }
    if source.client.chroma == baseline.client.chroma {
        effective.client.chroma = policy.client.chroma.clone();
    }
    if source.client.bit_depth == baseline.client.bit_depth {
        effective.client.bit_depth = policy.client.bit_depth.clone();
    }
    if source.client.bandwidth_cap_mbps == baseline.client.bandwidth_cap_mbps {
        effective.client.bandwidth_cap_mbps = policy.client.bandwidth_cap_mbps;
    }

    if source.video.width == baseline.video.width {
        effective.video.width = policy.video.width;
    }
    if source.video.height == baseline.video.height {
        effective.video.height = policy.video.height;
    }
    if source.video.fps == baseline.video.fps {
        effective.video.fps = policy.video.fps;
    }
    if source.video.bitrate_mbps == baseline.video.bitrate_mbps {
        effective.video.bitrate_mbps = policy.video.bitrate_mbps;
    }
    if source.video.min_bitrate_mbps == baseline.video.min_bitrate_mbps {
        effective.video.min_bitrate_mbps = policy.video.min_bitrate_mbps;
    }
    if source.video.codec == baseline.video.codec {
        effective.video.codec = policy.video.codec.clone();
    }
    if source.video.pixel_format == baseline.video.pixel_format {
        effective.video.pixel_format = policy.video.pixel_format.clone();
    }
}

fn profile_config(profile: StreamProfile) -> AppConfig {
    let mut config = default_config();
    config.client.profile = profile.clone();
    match profile {
        StreamProfile::Performance => {
            config.client.decoder = DecoderMode::Hardware;
            config.client.codec = CodecPreference::H264;
            config.client.chroma = ChromaPreference::Yuv420;
            config.client.bit_depth = BitDepthPreference::Eight;
            config.video.width = 1280;
            config.video.height = 720;
            config.video.bitrate_mbps = 6.0;
            config.video.min_bitrate_mbps = 1.0;
            config.video.codec = CodecPreference::H264;
            config.video.pixel_format = PixelFormat::Yuv420p;
        }
        StreamProfile::Balanced => {}
        StreamProfile::Quality => {
            config.client.codec = CodecPreference::H265;
            config.client.chroma = ChromaPreference::Yuv444;
            config.client.bit_depth = BitDepthPreference::Auto;
            config.video.width = 2560;
            config.video.height = 1440;
            config.video.bitrate_mbps = 25.0;
            config.video.min_bitrate_mbps = 2.0;
            config.video.codec = CodecPreference::H265;
            config.video.pixel_format = PixelFormat::Yuv444p;
        }
        StreamProfile::Custom | StreamProfile::Unknown(_) => {}
    }
    config
}

impl EffectiveConfig {
    fn from_config(config: &AppConfig, profile: StreamProfile) -> Self {
        Self {
            schema_version: config.schema_version,
            device: config.device.clone(),
            profile,
            client: config.client.clone(),
            host: config.host.clone(),
            video: config.video.clone(),
            audio: config.audio.clone(),
            input: config.input.clone(),
            network: config.network.clone(),
            privacy: config.privacy.clone(),
            advanced: config.advanced.clone(),
        }
    }
}

/// Read and migrate a settings file without rewriting it implicitly.
pub fn load(path: impl AsRef<Path>) -> Result<SettingsFile, SettingsError> {
    let path = path.as_ref().to_path_buf();
    let bytes = fs::read(&path).map_err(|source| SettingsError::Io {
        path: path.clone(),
        source,
    })?;
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|error| SettingsError::Json(error.to_string()))?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let version = u32::try_from(version).map_err(|_| SettingsError::UnsupportedSchema {
        found: u32::MAX,
        supported: CURRENT_SCHEMA_VERSION,
    })?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(SettingsError::UnsupportedSchema {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    let migrated_from = (version < CURRENT_SCHEMA_VERSION).then_some(version);
    match version {
        0 => migrate_schema_zero(&mut value)?,
        1 => migrate_schema_one(&mut value)?,
        _ => {}
    }
    let config: AppConfig =
        serde_json::from_value(value).map_err(|error| SettingsError::Json(error.to_string()))?;
    config.validate()?;
    Ok(SettingsFile {
        path,
        config,
        migrated_from,
    })
}

/// Atomically replace a settings file, creating private parent/file
/// permissions where the platform exposes them.
pub fn save_atomic(path: impl AsRef<Path>, config: &AppConfig) -> Result<(), SettingsError> {
    let path = resolve_save_path(path.as_ref())?;
    let path = path.as_path();
    config.validate()?;
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_exists = parent.exists();
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    if !parent_exists {
        set_private_dir(parent)?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{nonce}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("settings"),
        std::process::id()
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_file(&mut options);
        let mut file = options
            .open(&temporary)
            .map_err(|source| io_error(&temporary, source))?;
        let mut bytes = serde_json::to_vec_pretty(config)
            .map_err(|error| SettingsError::Json(error.to_string()))?;
        bytes.push(b'\n');
        file.write_all(&bytes)
            .map_err(|source| io_error(&temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error(&temporary, source))?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn resolve_save_path(path: &Path) -> Result<PathBuf, SettingsError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let mut extended = windows_extended_path(path)?;
    extended.pop();
    Ok(PathBuf::from(OsString::from_wide(&extended)))
}

#[cfg(not(windows))]
fn resolve_save_path(path: &Path) -> Result<PathBuf, SettingsError> {
    Ok(path.to_path_buf())
}

/// Apply known developer/headless environment overrides without persisting
/// them. Unknown environment variables are intentionally ignored.
pub fn apply_environment_overrides(config: &mut AppConfig) -> Result<(), SettingsError> {
    apply_overrides(config, std::env::vars())
}

pub fn apply_overrides<I, K, V>(config: &mut AppConfig, variables: I) -> Result<(), SettingsError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut candidate = config.clone();
    for (key, value) in variables {
        apply_one(&mut candidate, key.as_ref(), value.as_ref())?;
    }
    candidate.validate()?;
    *config = candidate;
    Ok(())
}

fn apply_one(config: &mut AppConfig, key: &str, value: &str) -> Result<(), SettingsError> {
    match key {
        "OPENSTREAM_DEVICE_NAME" => config.device.name = value.to_string(),
        "OPENSTREAM_SIGNAL_ORIGIN" => config.client.signal_origin = value.to_string(),
        "OPENSTREAM_HOSTING_ENABLED" => config.host.enabled = parse_bool(key, value)?,
        "OPENSTREAM_VIDEO_MBPS" => config.video.bitrate_mbps = parse_f64(key, value)?,
        "OPENSTREAM_VIDEO_MIN_MBPS" => config.video.min_bitrate_mbps = parse_f64(key, value)?,
        "OPENSTREAM_VIDEO_FPS" => config.video.fps = parse_u16(key, value)?,
        "OPENSTREAM_VIDEO_WIDTH" => config.video.width = parse_u32(key, value)?,
        "OPENSTREAM_VIDEO_HEIGHT" => config.video.height = parse_u32(key, value)?,
        "OPENSTREAM_RENDERER" => config.client.renderer = mode_from_string(key, value)?,
        "OPENSTREAM_DECODER" => config.client.decoder = mode_from_string(key, value)?,
        "OPENSTREAM_VIDEO_CODEC" => {
            let mode: CodecPreference = mode_from_string(key, value)?;
            config.client.codec = mode.clone();
            config.video.codec = mode;
        }
        "OPENSTREAM_VIDEO_ENCODER" => config.host.encoder = mode_from_string(key, value)?,
        "OPENSTREAM_CAPTURE_BACKEND" => config.host.capture = mode_from_string(key, value)?,
        "OPENSTREAM_AUDIO" => config.audio.enabled = parse_bool(key, value)?,
        "OPENSTREAM_ENABLE_INPUT" => {
            let enabled = parse_bool(key, value)?;
            config.input.enabled = enabled;
            if enabled {
                config.input.keyboard = true;
                config.input.mouse = true;
            }
        }
        "OPENSTREAM_ENABLE_KEYBOARD" => config.input.keyboard = parse_bool(key, value)?,
        "OPENSTREAM_ENABLE_MOUSE" => config.input.mouse = parse_bool(key, value)?,
        "OPENSTREAM_CLIPBOARD" => config.input.clipboard = parse_bool(key, value)?,
        "OPENSTREAM_GAMEPAD" => config.input.gamepad = parse_bool(key, value)?,
        "OPENSTREAM_MIC" => config.input.microphone = parse_bool(key, value)?,
        "OPENSTREAM_UPNP" => config.network.upnp = parse_bool(key, value)?,
        "OPENSTREAM_ICE" => config.network.ice = parse_bool(key, value)?,
        "OPENSTREAM_FORCE_RELAY" => config.network.force_relay = parse_bool(key, value)?,
        "OPENSTREAM_LOCAL_NO_AUTH" => config.network.local_no_auth = parse_bool(key, value)?,
        "OPENSTREAM_FFMPEG_RECONFIGURE" => {
            config.advanced.ffmpeg_reconfigure = parse_bool(key, value)?
        }
        "OPENSTREAM_FFMPEG" => config.advanced.ffmpeg_path = Some(value.to_string()),
        _ => {}
    }
    Ok(())
}

fn migrate_schema_zero(value: &mut Value) -> Result<(), SettingsError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| SettingsError::Json("settings root must be an object".to_string()))?;
    object.insert(
        "schema_version".to_string(),
        Value::from(CURRENT_SCHEMA_VERSION),
    );
    for section in [
        "device", "client", "host", "video", "audio", "input", "network", "privacy", "advanced",
    ] {
        object
            .entry(section.to_string())
            .or_insert_with(|| Value::Object(Default::default()));
    }
    Ok(())
}

fn migrate_schema_one(value: &mut Value) -> Result<(), SettingsError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| SettingsError::Json("settings root must be an object".to_string()))?;
    object.insert(
        "schema_version".to_string(),
        Value::from(CURRENT_SCHEMA_VERSION),
    );

    // Schema v1 had one coarse input switch. Preserve the user's explicit
    // enablement for the two production input categories introduced in v2;
    // fields already present in a hand-written v1 file remain authoritative.
    if let Some(input) = object.get_mut("input").and_then(Value::as_object_mut) {
        let enabled = input.get("enabled").cloned().unwrap_or(Value::Bool(false));
        input.entry("keyboard").or_insert_with(|| enabled.clone());
        input.entry("mouse").or_insert(enabled);
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), SettingsError> {
    windows_replace_file(temporary, destination)
}

#[cfg(unix)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), SettingsError> {
    unix_replace_file_with_sync(temporary, destination, |parent| {
        fs::File::open(parent).and_then(|directory| directory.sync_all())
    })
}

#[cfg(unix)]
fn unix_replace_file_with_sync<F>(
    temporary: &Path,
    destination: &Path,
    sync_parent: F,
) -> Result<(), SettingsError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    fs::rename(temporary, destination).map_err(|source| io_error(destination, source))?;
    // The rename is the commit point. Directory fsync improves crash durability,
    // but failing after commit would falsely tell callers that replacement failed.
    let _best_effort_durability =
        sync_parent(destination.parent().unwrap_or_else(|| Path::new(".")));
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), SettingsError> {
    fs::rename(temporary, destination).map_err(|source| io_error(destination, source))
}

#[cfg(windows)]
fn windows_replace_file(temporary: &Path, destination: &Path) -> Result<(), SettingsError> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
    };

    let temporary_wide = windows_extended_path(temporary)?;
    let destination_wide = windows_extended_path(destination)?;
    replace_existing_or_create(
        || {
            // SAFETY: The buffers are NUL-terminated and remain alive for the call.
            let result = unsafe {
                ReplaceFileW(
                    destination_wide.as_ptr(),
                    temporary_wide.as_ptr(),
                    std::ptr::null(),
                    REPLACEFILE_WRITE_THROUGH,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            (result != 0)
                .then_some(())
                .ok_or_else(io::Error::last_os_error)
        },
        || {
            // No replace flag: a destination created by a racer is never overwritten
            // through the metadata-losing creation path.
            let result = unsafe {
                MoveFileExW(
                    temporary_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            };
            (result != 0)
                .then_some(())
                .ok_or_else(io::Error::last_os_error)
        },
    )
    .map_err(|source| io_error(destination, source))
}

#[cfg(windows)]
fn windows_extended_path(path: &Path) -> Result<Vec<u16>, SettingsError> {
    use std::os::windows::ffi::OsStrExt;

    let input: Vec<u16> = path.as_os_str().encode_wide().collect();
    if input.contains(&0) {
        return Err(io_error(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL character"),
        ));
    }

    const EXTENDED: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    if input.starts_with(EXTENDED) {
        let mut extended = input;
        extended.push(0);
        return Ok(extended);
    }

    let absolute_path = windows_absolute_path(path)?;
    let absolute: Vec<u16> = absolute_path.as_os_str().encode_wide().collect();

    let mut extended = Vec::with_capacity(absolute.len() + 8);
    if absolute.starts_with(&[b'\\' as u16, b'\\' as u16]) {
        extended.extend("\\\\?\\UNC\\".encode_utf16());
        extended.extend_from_slice(&absolute[2..]);
    } else {
        extended.extend("\\\\?\\".encode_utf16());
        extended.extend_from_slice(&absolute);
    }
    extended.push(0);
    Ok(extended)
}

#[cfg(windows)]
fn windows_absolute_path(path: &Path) -> Result<PathBuf, SettingsError> {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Prefix};

    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io_error(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL character"),
        ));
    }
    if encoded.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]) {
        return Ok(path.to_path_buf());
    }

    let mut components = path.components();
    let drive_relative = match components.next() {
        Some(Component::Prefix(prefix)) if !path.has_root() => match prefix.kind() {
            Prefix::Disk(drive) => Some(drive),
            _ => None,
        },
        _ => None,
    };

    let joined = if let Some(drive) = drive_relative {
        // Resolve only the short per-drive base through the standard library.
        // The caller's potentially long tail never reaches GetFullPathNameW.
        let drive_base = PathBuf::from(format!("{}:.", char::from(drive)));
        let mut base = std::path::absolute(&drive_base).map_err(|source| io_error(path, source))?;
        for component in path.components().skip(1) {
            base.push(component.as_os_str());
        }
        base
    } else if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = std::env::current_dir().map_err(|source| io_error(path, source))?;
        base.join(path)
    };

    Ok(lexically_normalize_absolute(&joined))
}

#[cfg(windows)]
fn lexically_normalize_absolute(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

#[cfg(any(test, windows))]
fn replace_existing_or_create<R, M>(mut replace: R, mut move_new: M) -> io::Result<()>
where
    R: FnMut() -> io::Result<()>,
    M: FnMut() -> io::Result<()>,
{
    match replace() {
        Ok(()) => Ok(()),
        Err(error) if is_windows_missing(&error) => match move_new() {
            Ok(()) => Ok(()),
            Err(error) if is_windows_exists(&error) => replace(),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

#[cfg(any(test, windows))]
fn is_windows_missing(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(2 | 3))
}

#[cfg(any(test, windows))]
fn is_windows_exists(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(80 | 183))
}

fn io_error(path: &Path, source: io::Error) -> SettingsError {
    SettingsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), SettingsError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<(), SettingsError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file(_options: &mut OpenOptions) {}

fn validate_text(
    field: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), SettingsError> {
    if value.len() < minimum || value.len() > maximum || value.chars().any(char::is_control) {
        return invalid(
            field,
            "must be bounded, non-empty, and contain no control characters",
        );
    }
    Ok(())
}

fn validate_rate(field: &str, value: f64, minimum: f64, maximum: f64) -> Result<(), SettingsError> {
    if !value.is_finite() || !(minimum..=maximum).contains(&value) {
        return invalid(field, "must be finite and within the supported range");
    }
    Ok(())
}

fn validate_mode<T>(field: &str, mode: &T, known: fn(&T) -> bool) -> Result<(), SettingsError> {
    if !known(mode) {
        return invalid(field, "unknown value");
    }
    Ok(())
}

fn invalid(field: &str, reason: &str) -> Result<(), SettingsError> {
    Err(SettingsError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    })
}

fn is_renderer_known(value: &RendererMode) -> bool {
    !matches!(value, RendererMode::Unknown(_))
}
fn is_decoder_known(value: &DecoderMode) -> bool {
    !matches!(value, DecoderMode::Unknown(_))
}
fn is_encoder_known(value: &EncoderMode) -> bool {
    !matches!(value, EncoderMode::Unknown(_))
}
fn is_capture_known(value: &CaptureMode) -> bool {
    !matches!(value, CaptureMode::Unknown(_))
}
fn is_codec_known(value: &CodecPreference) -> bool {
    !matches!(value, CodecPreference::Unknown(_))
}
fn is_pixel_known(value: &PixelFormat) -> bool {
    !matches!(value, PixelFormat::Unknown(_))
}
fn is_approval_known(value: &ApprovalMode) -> bool {
    !matches!(value, ApprovalMode::Unknown(_))
}
fn is_profile_known(value: &StreamProfile) -> bool {
    !matches!(value, StreamProfile::Unknown(_))
}
fn is_window_known(value: &WindowMode) -> bool {
    !matches!(value, WindowMode::Unknown(_))
}
fn is_vsync_known(value: &VsyncMode) -> bool {
    !matches!(value, VsyncMode::Unknown(_))
}
fn is_chroma_known(value: &ChromaPreference) -> bool {
    !matches!(value, ChromaPreference::Unknown(_))
}
fn is_bit_depth_known(value: &BitDepthPreference) -> bool {
    !matches!(value, BitDepthPreference::Unknown(_))
}
fn is_audio_codec_known(value: &AudioCodec) -> bool {
    !matches!(value, AudioCodec::Unknown(_))
}
fn is_audio_latency_known(value: &AudioLatencyMode) -> bool {
    !matches!(value, AudioLatencyMode::Unknown(_))
}
fn is_congestion_known(value: &CongestionIntent) -> bool {
    !matches!(value, CongestionIntent::Unknown(_))
}

fn parse_bool(field: &str, value: &str) -> Result<bool, SettingsError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" => Ok(false),
        _ => Err(SettingsError::InvalidField {
            field: field.to_string(),
            reason: "expected 0/1 or true/false".to_string(),
        }),
    }
}

fn parse_f64(field: &str, value: &str) -> Result<f64, SettingsError> {
    value.parse().map_err(|_| SettingsError::InvalidField {
        field: field.to_string(),
        reason: "expected a number".to_string(),
    })
}
fn parse_u16(field: &str, value: &str) -> Result<u16, SettingsError> {
    value.parse().map_err(|_| SettingsError::InvalidField {
        field: field.to_string(),
        reason: "expected an unsigned 16-bit integer".to_string(),
    })
}
fn parse_u32(field: &str, value: &str) -> Result<u32, SettingsError> {
    value.parse().map_err(|_| SettingsError::InvalidField {
        field: field.to_string(),
        reason: "expected an unsigned 32-bit integer".to_string(),
    })
}

fn mode_from_string<T>(field: &str, value: &str) -> Result<T, SettingsError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(Value::String(value.to_string())).map_err(|_| {
        SettingsError::InvalidField {
            field: field.to_string(),
            reason: "expected a string mode".to_string(),
        }
    })
}

const fn current_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}
fn default_device_name() -> String {
    "OpenStream device".to_string()
}
fn default_host_name() -> String {
    "OpenStream host".to_string()
}
fn default_signal_origin() -> String {
    "http://127.0.0.1:8080".to_string()
}
const fn default_true() -> bool {
    true
}
const fn default_max_guests() -> u8 {
    1
}
const fn default_width() -> u32 {
    1920
}
const fn default_height() -> u32 {
    1080
}
const fn default_fps() -> u16 {
    60
}
const fn default_bitrate() -> f64 {
    10.0
}
const fn default_min_bitrate() -> f64 {
    1.0
}
const fn default_audio_bitrate() -> u16 {
    128
}
const fn default_session_seconds() -> u32 {
    3600
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            name: default_device_name(),
            identity_key: None,
            control_credential: None,
        }
    }
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            signal_origin: default_signal_origin(),
            profile: StreamProfile::Balanced,
            window_mode: WindowMode::Windowed,
            renderer: RendererMode::Auto,
            decoder: DecoderMode::Auto,
            codec: CodecPreference::Auto,
            vsync: VsyncMode::Auto,
            chroma: ChromaPreference::Auto,
            bit_depth: BitDepthPreference::Auto,
            immersive: false,
            show_warnings: true,
            bandwidth_cap_mbps: None,
            overlay: true,
        }
    }
}
impl Default for HostConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_host_name(),
            stay_awake: false,
            capture: CaptureMode::Auto,
            encoder: EncoderMode::Auto,
            aggregate_bandwidth_cap_mbps: None,
            approval: ApprovalMode::Auto,
            max_guests: default_max_guests(),
            selected_display: None,
        }
    }
}
impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            width: default_width(),
            height: default_height(),
            fps: default_fps(),
            bitrate_mbps: default_bitrate(),
            min_bitrate_mbps: default_min_bitrate(),
            codec: CodecPreference::H264,
            pixel_format: PixelFormat::Auto,
        }
    }
}
impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            codec: AudioCodec::Opus,
            bitrate_kbps: default_audio_bitrate(),
            latency_mode: AudioLatencyMode::Balanced,
        }
    }
}
impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            redact_diagnostics: true,
            remember_last_host: false,
        }
    }
}
impl Default for InputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keyboard: false,
            mouse: false,
            clipboard: false,
            gamepad: false,
            microphone: false,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            upnp: false,
            ice: false,
            turn: false,
            force_relay: false,
            local_no_auth: false,
            udp_port: None,
            client_port: None,
            host_start_port: None,
            congestion: CongestionIntent::Balanced,
        }
    }
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            ffmpeg_path: None,
            ffmpeg_reconfigure: false,
            max_session_seconds: default_session_seconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_overrides, default_config, effective_config, load, save_atomic, setting_descriptors,
        CapabilityState, ChromaPreference, CURRENT_SCHEMA_VERSION, DecoderMode, EncoderMode,
        RendererMode, SecretRef, SettingVisibility, StreamProfile, WindowMode, SettingsError,
    };
    use serde_json::json;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openstream-settings-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn cleanup(path: &PathBuf) {
        let _ = fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn default_config_is_valid_and_has_safe_local_defaults() {
        let config = default_config();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(!config.host.enabled);
        assert!(!config.input.enabled);
        assert!(!config.audio.enabled);
        assert_eq!(config.client.renderer, RendererMode::Auto);
        assert_eq!(config.client.decoder, DecoderMode::Auto);
        assert_eq!(config.host.encoder, EncoderMode::Auto);
        config.validate().expect("default configuration is valid");
    }

    #[test]
    fn unknown_fields_are_ignored_but_newer_schema_is_rejected() {
        let path = temp_path("unknown");
        let value = json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "device": { "name": "test", "future": { "ignored": true } },
            "future_top_level": "ignored"
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = load(&path).expect("unknown fields are forward-compatible");
        assert_eq!(loaded.config.device.name, "test");
        cleanup(&path);

        let newer = temp_path("newer");
        fs::write(
            &newer,
            serde_json::to_vec(&json!({"schema_version": CURRENT_SCHEMA_VERSION + 1})).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(&newer),
            Err(SettingsError::UnsupportedSchema { .. })
        ));
        cleanup(&newer);
    }

    #[test]
    fn schema_zero_migrates_deterministically() {
        let path = temp_path("migration");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": 0,
                "device": {"name": "old-name"},
                "host": {"enabled": true}
            }))
            .unwrap(),
        )
        .unwrap();
        let loaded = load(&path).expect("schema zero migrates");
        assert_eq!(loaded.config.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.config.device.name, "old-name");
        assert!(loaded.config.host.enabled);
        assert_eq!(loaded.migrated_from, Some(0));
        cleanup(&path);
    }

    #[test]
    fn schema_v1_migrates_explicitly_to_v2_with_balanced_defaults() {
        let path = temp_path("schema-v1-migration");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "client": {
                    "renderer": "metal",
                    "overlay": false
                },
                "input": {
                    "enabled": true,
                    "clipboard": true
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = load(&path).expect("schema v1 migrates");
        assert_eq!(loaded.config.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.migrated_from, Some(1));
        assert_eq!(loaded.config.client.profile, StreamProfile::Balanced);
        assert_eq!(loaded.config.client.window_mode, WindowMode::Windowed);
        assert!(loaded.config.input.keyboard);
        assert!(loaded.config.input.mouse);
        assert!(loaded.config.input.clipboard);
        assert_eq!(loaded.config.client.renderer, RendererMode::Metal);
        cleanup(&path);
    }

    #[test]
    fn v2_input_permissions_remain_independent() {
        let path = temp_path("independent-input");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": CURRENT_SCHEMA_VERSION,
                "input": {
                    "keyboard": true,
                    "mouse": false,
                    "gamepad": true,
                    "clipboard": false,
                    "microphone": true
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = load(&path).expect("v2 input permissions load");
        assert!(loaded.config.input.keyboard);
        assert!(!loaded.config.input.mouse);
        assert!(loaded.config.input.gamepad);
        assert!(!loaded.config.input.clipboard);
        assert!(loaded.config.input.microphone);
        cleanup(&path);
    }

    #[test]
    fn unknown_modes_round_trip_without_selecting_a_known_backend() {
        let mode: RendererMode = serde_json::from_str("\"future-renderer\"").unwrap();
        assert_eq!(mode, RendererMode::Unknown("future-renderer".to_string()));
        assert_eq!(serde_json::to_string(&mode).unwrap(), "\"future-renderer\"");
    }

    #[test]
    fn profile_resolution_is_deterministic_and_low_level_edits_become_custom() {
        let mut balanced = default_config();
        balanced.client.profile = StreamProfile::Balanced;
        let first = effective_config(&balanced);
        let second = effective_config(&balanced);
        assert_eq!(first, second);
        assert_eq!(first.profile, StreamProfile::Balanced);

        let mut edited = balanced;
        edited.client.profile = StreamProfile::Quality;
        edited.video.fps = 120;
        let effective = effective_config(&edited);
        assert_eq!(effective.profile, StreamProfile::Custom);
        assert_eq!(effective.video.fps, 120);
        assert_eq!(effective.video.bitrate_mbps, 25.0);
    }

    #[test]
    fn descriptor_catalog_exposes_truthful_metadata() {
        let descriptors = setting_descriptors();
        let native_drm = descriptors
            .iter()
            .find(|descriptor| descriptor.key == "host.capture.drm")
            .expect("native DRM descriptor");
        assert_eq!(native_drm.visibility, SettingVisibility::Experimental);
        assert_eq!(native_drm.capability, CapabilityState::Experimental);

        for key in [
            "input.keyboard",
            "input.mouse",
            "input.gamepad",
            "input.clipboard",
            "input.microphone",
        ] {
            assert!(
                descriptors.iter().any(|descriptor| descriptor.key == key),
                "missing descriptor {key}"
            );
        }
    }

    #[test]
    fn invalid_values_are_rejected_instead_of_clamped() {
        let mut config = default_config();
        config.device.name.clear();
        assert!(
            matches!(config.validate(), Err(SettingsError::InvalidField { field, .. }) if field == "device.name")
        );

        let mut config = default_config();
        config.video.bitrate_mbps = 0.0;
        assert!(
            matches!(config.validate(), Err(SettingsError::InvalidField { field, .. }) if field == "video.bitrate_mbps")
        );

        let mut config = default_config();
        config.client.renderer = RendererMode::Unknown("not-a-renderer".into());
        assert!(
            matches!(config.validate(), Err(SettingsError::InvalidField { field, .. }) if field == "client.renderer")
        );
    }

    #[test]
    fn secret_refs_serialize_without_secret_material() {
        let reference = SecretRef::new("device-identity").expect("valid secret name");
        let mut config = default_config();
        config.device.identity_key = Some(reference);
        let encoded = serde_json::to_string(&config).unwrap();
        assert!(encoded.contains("device-identity"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("token"));
    }

    #[test]
    fn save_is_atomic_and_creates_private_settings_file() {
        let root = temp_path("atomic");
        let path = root.join("config.json");
        save_atomic(&path, &default_config()).expect("settings save");
        let loaded = load(&path).expect("settings load");
        assert_eq!(loaded.config, default_config());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let parent_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(parent_mode, 0o700);
        }
        cleanup(&path);
    }

    #[test]
    fn save_atomic_replaces_an_existing_settings_file() {
        let root = temp_path("replace-existing");
        let path = root.join("config.json");
        let mut replacement = default_config();
        replacement.device.name = "replacement".to_string();

        save_atomic(&path, &default_config()).expect("initial settings save");
        save_atomic(&path, &replacement).expect("replacement settings save");

        assert_eq!(
            load(&path).expect("replacement settings load").config,
            replacement
        );
        cleanup(&path);
    }

    #[test]
    fn failed_replace_preserves_existing_destination() {
        let root = temp_path("failed-replace");
        fs::create_dir_all(&root).expect("create test directory");
        let destination = root.join("config.json");
        let missing_temporary = root.join("missing.tmp");
        fs::write(&destination, b"old settings").expect("write existing destination");

        let error = super::replace_file(&missing_temporary, &destination)
            .expect_err("missing replacement must fail");

        assert!(matches!(error, SettingsError::Io { .. }));
        assert_eq!(
            fs::read(&destination).expect("existing destination remains"),
            b"old settings"
        );
        cleanup(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn unix_directory_sync_failure_is_best_effort_after_rename_commits() {
        let root = temp_path("directory-sync-failure");
        fs::create_dir_all(&root).expect("create test directory");
        let destination = root.join("config.json");
        let temporary = root.join("config.tmp");
        fs::write(&destination, b"old settings").expect("write existing destination");
        fs::write(&temporary, b"new settings").expect("write replacement");

        let result = super::unix_replace_file_with_sync(&temporary, &destination, |_| {
            Err(io::Error::other("simulated directory fsync failure"))
        });

        result.expect("rename already committed, so durability sync is best effort");
        assert_eq!(
            fs::read(&destination).expect("read committed destination"),
            b"new settings"
        );
        assert!(!temporary.exists());
        cleanup(&destination);
    }

    #[test]
    fn windows_replacement_prefers_replace_for_existing_destination() {
        let calls = RefCell::new(Vec::new());

        super::replace_existing_or_create(
            || {
                calls.borrow_mut().push("replace");
                Ok(())
            },
            || {
                calls.borrow_mut().push("move");
                Ok(())
            },
        )
        .expect("existing destination replacement");

        assert_eq!(*calls.borrow(), ["replace"]);
    }

    #[test]
    fn windows_replacement_creates_only_after_destination_is_missing() {
        let calls = RefCell::new(Vec::new());

        super::replace_existing_or_create(
            || {
                calls.borrow_mut().push("replace");
                Err(io::Error::from_raw_os_error(2))
            },
            || {
                calls.borrow_mut().push("move");
                Ok(())
            },
        )
        .expect("new destination creation");

        assert_eq!(*calls.borrow(), ["replace", "move"]);
    }

    #[test]
    fn windows_replacement_retries_replace_when_creation_loses_a_race() {
        let calls = RefCell::new(Vec::new());
        let replace_attempts = Cell::new(0);

        super::replace_existing_or_create(
            || {
                calls.borrow_mut().push("replace");
                replace_attempts.set(replace_attempts.get() + 1);
                if replace_attempts.get() == 1 {
                    Err(io::Error::from_raw_os_error(2))
                } else {
                    Ok(())
                }
            },
            || {
                calls.borrow_mut().push("move");
                Err(io::Error::from_raw_os_error(183))
            },
        )
        .expect("racing destination replacement");

        assert_eq!(*calls.borrow(), ["replace", "move", "replace"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_replace_primitive_replaces_an_existing_destination() {
        let root = temp_path("windows-replace-api");
        fs::create_dir_all(&root).expect("create test directory");
        let destination = root.join("config.json");
        let temporary = root.join("config.tmp");
        fs::write(&destination, b"old settings").expect("write existing destination");
        fs::write(&temporary, b"new settings").expect("write replacement");

        super::windows_replace_file(&temporary, &destination).expect("atomic Windows replace");

        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"new settings"
        );
        assert!(!temporary.exists());
        cleanup(&destination);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_are_absolute_extended_paths_for_drive_relative_and_unc_inputs() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::Path;

        let relative = super::windows_extended_path(Path::new("relative\\config.json"))
            .expect("relative path conversion");
        let drive_relative = super::windows_extended_path(Path::new("C:settings\\config.json"))
            .expect("drive-relative path conversion");
        let drive = super::windows_extended_path(Path::new("C:\\settings\\config.json"))
            .expect("drive path conversion");
        let unc =
            super::windows_extended_path(Path::new("\\\\settings-server\\share\\config.json"))
                .expect("UNC path conversion");

        let decode = |wide: &[u16]| {
            OsString::from_wide(&wide[..wide.len() - 1])
                .to_string_lossy()
                .into_owned()
        };
        assert!(decode(&relative).starts_with("\\\\?\\"));
        assert!(decode(&drive_relative).starts_with("\\\\?\\C:\\"));
        assert!(decode(&drive_relative).ends_with("\\settings\\config.json"));
        assert_eq!(decode(&drive), "\\\\?\\C:\\settings\\config.json");
        assert_eq!(
            decode(&unc),
            "\\\\?\\UNC\\settings-server\\share\\config.json"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_conversion_accepts_an_unprefixed_path_longer_than_max_path() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::Path;

        let path = format!("C:\\{}\\config.json", "segment".repeat(40));
        assert!(path.encode_utf16().count() > 260);

        let extended = super::windows_extended_path(Path::new(&path))
            .expect("long unprefixed path conversion");
        let decoded = OsString::from_wide(&extended[..extended.len() - 1])
            .to_string_lossy()
            .into_owned();

        assert_eq!(decoded, format!("\\\\?\\{path}"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_conversion_rejects_embedded_nul() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0,
            b'x' as u16,
        ]));
        let error = super::windows_extended_path(&path).expect_err("embedded NUL must fail");

        assert!(matches!(
            error,
            SettingsError::Io { source, .. } if source.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn environment_overrides_use_the_same_validation_and_are_not_persisted() {
        let mut vars = BTreeMap::new();
        vars.insert("OPENSTREAM_DEVICE_NAME", "LAN host".to_string());
        vars.insert("OPENSTREAM_HOSTING_ENABLED", "1".to_string());
        vars.insert("OPENSTREAM_VIDEO_MBPS", "15".to_string());
        vars.insert("OPENSTREAM_RENDERER", "metal".to_string());
        vars.insert("OPENSTREAM_VIDEO_ENCODER", "h264_nvenc".to_string());
        vars.insert("OPENSTREAM_ENABLE_INPUT", "0".to_string());
        let mut config = default_config();
        apply_overrides(&mut config, vars).expect("valid overrides");
        assert_eq!(config.device.name, "LAN host");
        assert!(config.host.enabled);
        assert!((config.video.bitrate_mbps - 15.0).abs() < f64::EPSILON);
        assert_eq!(config.client.renderer, RendererMode::Metal);
        assert_eq!(config.host.encoder, EncoderMode::H264Nvenc);
        assert!(!config.input.enabled);

        let path = temp_path("override");
        save_atomic(&path, &default_config()).unwrap();
        assert_eq!(load(&path).unwrap().config, default_config());
        cleanup(&path);
    }
}
