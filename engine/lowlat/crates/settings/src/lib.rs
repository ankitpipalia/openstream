use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The on-disk schema version. This is deliberately independent from the
/// application, protocol, and database versions.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
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
    pub renderer: RendererMode,
    #[serde(default)]
    pub decoder: DecoderMode,
    #[serde(default)]
    pub codec: CodecPreference,
    #[serde(default)]
    pub bandwidth_cap_mbps: Option<f64>,
    #[serde(default = "default_true")]
    pub overlay: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub capture: CaptureMode,
    #[serde(default)]
    pub encoder: EncoderMode,
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
    #[serde(default = "default_audio_bitrate")]
    pub bitrate_kbps: u16,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct InputConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub gamepad: bool,
    #[serde(default)]
    pub microphone: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub upnp: bool,
    #[serde(default)]
    pub ice: bool,
    #[serde(default)]
    pub force_relay: bool,
    #[serde(default)]
    pub local_no_auth: bool,
    #[serde(default)]
    pub udp_port: Option<u16>,
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
        validate_text(
            "client.signal_origin",
            &self.client.signal_origin,
            1,
            MAX_ORIGIN_BYTES,
        )?;
        if self.client.signal_origin.chars().any(char::is_whitespace) {
            return invalid("client.signal_origin", "must not contain whitespace");
        }
        validate_mode("client.renderer", &self.client.renderer, is_renderer_known)?;
        validate_mode("client.decoder", &self.client.decoder, is_decoder_known)?;
        validate_mode("client.codec", &self.client.codec, is_codec_known)?;
        validate_mode("host.capture", &self.host.capture, is_capture_known)?;
        validate_mode("host.encoder", &self.host.encoder, is_encoder_known)?;
        validate_mode("host.approval", &self.host.approval, is_approval_known)?;
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
        if !(8..=512).contains(&self.audio.bitrate_kbps) {
            return invalid("audio.bitrate_kbps", "must be in 8..=512");
        }
        if let Some(port) = self.network.udp_port {
            if port == 0 {
                return invalid("network.udp_port", "must not be zero");
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
    if version == 0 {
        migrate_schema_zero(&mut value)?;
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
    let path = path.as_ref();
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
        "OPENSTREAM_ENABLE_INPUT" => config.input.enabled = parse_bool(key, value)?,
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

fn replace_file(temporary: &Path, destination: &Path) -> Result<(), SettingsError> {
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination).map_err(|source| io_error(destination, source))?;
    }
    fs::rename(temporary, destination).map_err(|source| io_error(destination, source))
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
            renderer: RendererMode::Auto,
            decoder: DecoderMode::Auto,
            codec: CodecPreference::Auto,
            bandwidth_cap_mbps: None,
            overlay: true,
        }
    }
}
impl Default for HostConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capture: CaptureMode::Auto,
            encoder: EncoderMode::Auto,
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
            bitrate_kbps: default_audio_bitrate(),
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
        CURRENT_SCHEMA_VERSION, DecoderMode, EncoderMode, RendererMode, SecretRef, SettingsError,
        apply_overrides, default_config, load, save_atomic,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
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
