//! Bounded supervision for the OpenStream host process.
//!
//! The agent owns the host child, not the desktop shell. Its policy is
//! deliberately driven by an injected clock and child factory so restart,
//! shutdown, and health behavior can be verified without launching FFmpeg.
//! The Tokio implementation is a thin process adapter; no shell is involved.

use openstream_app_core::AppErrorCode;
use openstream_local_ipc::RequestId;
use openstream_platform::host_heartbeat::{self, HostPhase};
use openstream_settings::{AppConfig, CaptureMode, host_config_revision};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Hard upper bound for one child argument.
const MAX_ARGUMENT_BYTES: usize = 4096;
/// Hard upper bound for one environment value.
const MAX_ENV_VALUE_BYTES: usize = 16 * 1024;
/// Hard upper bound for the configured child command.
const MAX_PROGRAM_BYTES: usize = 4096;
/// Hard upper bound for the agent backend label.
const MAX_BACKEND_BYTES: usize = 128;
const MAX_PAIRING_FILE_BYTES: u64 = 64 * 1024;
const STOP_GRACE_PERIOD: Duration = Duration::from_secs(2);
/// A host child is only healthy while its encoded-frame heartbeat is fresh.
const FRAME_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(3);
/// Consecutive non-live observations required before a ready child is
/// restarted for frame-liveness.
///
/// One observation is not evidence. The heartbeat is a file written by
/// another process, so a single read can come back stale or unreadable for
/// reasons that have nothing to do with the capture pipeline -- a slow
/// filesystem, a transient permission error, a publisher that has not
/// completed its first write. Restarting a working stream on one such read is
/// worse than noticing a real stall one tick later, and
/// [`FRAME_HEARTBEAT_TIMEOUT`] already means each observation covers three
/// seconds of missing frames.
const FRAME_LIVENESS_STRIKES: u32 = 3;

/// How long a host that says it is streaming may go without a first frame.
///
/// Phases relax the frame deadline for a host that has not claimed to be
/// streaming. Without a bound here that relaxation leaks into the streaming
/// phase itself: a counter still at zero cannot have "stopped advancing", so
/// a capture or encoder that never produces its first frame would read as
/// healthy forever -- exactly the dead pipeline behind a live process that
/// this heartbeat exists to catch.
///
/// Measured from the moment the host first reports [`HostPhase::Streaming`],
/// not from process start, because a peer can arrive hours after the host
/// does. Generous relative to [`FRAME_HEARTBEAT_TIMEOUT`] because it covers
/// one-off costs an established stream never pays again: encoder
/// initialisation, capture negotiation, the first keyframe.
const FIRST_FRAME_DEADLINE: Duration = Duration::from_secs(15);

/// How much of the heartbeat file is read.
///
/// The file is one short line. Bounded because it is written by another
/// process and this one must not be led into reading an arbitrary amount by
/// whatever is at that path.
const HEARTBEAT_READ_LIMIT: u64 = 64;
/// The oldest supported host-agent IPC protocol version.
pub const HOST_AGENT_PROTOCOL_VERSION: u32 = 1;

/// Typed failures exposed to the application shell and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostErrorCode {
    InvalidConfig,
    SpawnFailed,
    ChildFailed,
    RestartLimit,
    StopFailed,
    LifetimeExceeded,
    PreflightUnavailable,
    FrameLivenessTimeout,
}

impl HostErrorCode {
    /// Whether retrying may change the outcome without operator changes.
    pub const fn retryable(self) -> bool {
        !matches!(self, Self::InvalidConfig | Self::RestartLimit)
    }

    /// Map the host-specific status to the stable application error vocabulary.
    pub const fn app_error_code(self) -> AppErrorCode {
        match self {
            Self::InvalidConfig => AppErrorCode::InvalidRequest,
            Self::SpawnFailed | Self::ChildFailed | Self::LifetimeExceeded => {
                AppErrorCode::Unavailable
            }
            Self::RestartLimit | Self::StopFailed => AppErrorCode::Internal,
            Self::PreflightUnavailable => AppErrorCode::DeviceUnavailable,
            Self::FrameLivenessTimeout => AppErrorCode::Unavailable,
        }
    }
}

/// A process exit returned by a managed child.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildExit {
    pub success: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ChildExit {
    pub const fn success() -> Self {
        Self {
            success: true,
            code: Some(0),
            signal: None,
        }
    }

    pub const fn code(code: i32) -> Self {
        Self {
            success: code == 0,
            code: Some(code),
            signal: None,
        }
    }

    pub const fn signal(signal: i32) -> Self {
        Self {
            success: false,
            code: None,
            signal: Some(signal),
        }
    }

    /// Synthetic termination used by deterministic test children.
    pub const fn terminated() -> Self {
        Self::signal(15)
    }
}

/// Stable classification of a child termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildExitReason {
    Clean,
    ExitCode(i32),
    Signal(i32),
    Unknown,
    LifetimeExceeded,
    FrameLivenessTimeout,
}

impl From<ChildExit> for ChildExitReason {
    fn from(exit: ChildExit) -> Self {
        if exit.success {
            Self::Clean
        } else if let Some(signal) = exit.signal {
            Self::Signal(signal)
        } else if let Some(code) = exit.code {
            Self::ExitCode(code)
        } else {
            Self::Unknown
        }
    }
}

impl ChildExitReason {
    const fn should_restart(self) -> bool {
        matches!(
            self,
            Self::ExitCode(_)
                | Self::Signal(_)
                | Self::Unknown
                | Self::LifetimeExceeded
                | Self::FrameLivenessTimeout
        )
    }
}

/// Lifecycle reported by HostHealth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildState {
    Stopped,
    Starting,
    Ready,
    Stopping,
    Backoff,
    Failed,
}

/// A bounded, shell-free command description.
///
/// Values are retained for process creation, but the custom Debug
/// implementation never prints argument or environment values. Callers must
/// put credentials in a protected environment/provider boundary, never in an
/// argument. Suspicious credential-shaped arguments are rejected as an
/// additional guard against accidental command-line disclosure.
#[derive(Clone)]
pub struct ChildSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: BTreeMap<String, String>,
    pairing_file: Option<String>,
}

impl fmt::Debug for ChildSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut environment_keys = self.env.keys().map(String::as_str).collect::<Vec<_>>();
        if self.pairing_file.is_some() {
            environment_keys.push("OPENSTREAM_PAIRING_FILE");
        }
        formatter
            .debug_struct("ChildSpec")
            .field("program", &"<configured>")
            .field("argument_count", &self.args.len())
            .field("environment_keys", &environment_keys)
            .finish()
    }
}

impl ChildSpec {
    /// Create a command with no arguments or environment overrides.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, AgentError> {
        let spec = Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            pairing_file: None,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Append one non-secret argument.
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.args.push(argument.into());
        self
    }

    /// Add an environment value. Debug output always redacts the value.
    pub fn env(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AgentError> {
        self.env.insert(key.into(), value.into());
        self.validate()?;
        Ok(self)
    }

    /// Validate bounds and reject credential-shaped command arguments.
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.program.as_os_str().is_empty()
            || self.program.as_os_str().to_string_lossy().len() > MAX_PROGRAM_BYTES
            || self.program.as_os_str().to_string_lossy().contains('\0')
        {
            return Err(AgentError::InvalidConfig);
        }
        if self.args.len() > 128 {
            return Err(AgentError::InvalidConfig);
        }
        for argument in &self.args {
            let text = argument.to_string_lossy();
            if text.is_empty()
                || text.len() > MAX_ARGUMENT_BYTES
                || text.chars().any(char::is_control)
                || contains_secret_marker(&text)
            {
                return Err(AgentError::InvalidConfig);
            }
        }
        if self.env.len() > 128 {
            return Err(AgentError::InvalidConfig);
        }
        for (key, value) in &self.env {
            if key.is_empty()
                || key.len() > 256
                || is_pairing_environment_key(key)
                || key.chars().any(|character| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
                })
                || value.len() > MAX_ENV_VALUE_BYTES
                || value.contains('\0')
            {
                return Err(AgentError::InvalidConfig);
            }
        }
        if let Some(path) = &self.pairing_file {
            validate_private_pairing_file(Path::new(path))?;
        }
        Ok(())
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    fn set_pairing_file(&mut self, path: String) {
        self.pairing_file = Some(path);
    }

    /// Return the validated pairing-file path, if one was configured.
    ///
    /// The path is not secret material; the file contents are. Custom child
    /// factories should use this accessor to propagate the dedicated pairing
    /// file without exposing the raw pairing JSON environment escape hatch.
    pub fn pairing_file(&self) -> Option<&Path> {
        self.pairing_file.as_deref().map(Path::new)
    }
}

fn validate_private_pairing_file(path: &Path) -> Result<String, AgentError> {
    if !path.is_absolute() {
        return Err(AgentError::InvalidConfig);
    }
    let link_metadata = path
        .symlink_metadata()
        .map_err(|_| AgentError::InvalidConfig)?;
    if link_metadata.file_type().is_symlink() {
        return Err(AgentError::InvalidConfig);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the final path component without traversing a reparse point.
        // The metadata check above is retained for a clear fast-fail, while
        // this handle-level flag closes the check/open race on Windows.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|_| AgentError::InvalidConfig)?;
    let metadata = file.metadata().map_err(|_| AgentError::InvalidConfig)?;
    if !metadata.is_file() || metadata.len() > MAX_PAIRING_FILE_BYTES {
        return Err(AgentError::InvalidConfig);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AgentError::InvalidConfig);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid
            || metadata.mode() & 0o077 != 0
            || metadata.mode() & 0o400 == 0
        {
            return Err(AgentError::InvalidConfig);
        }
    }

    path.to_str()
        .map(str::to_owned)
        .ok_or(AgentError::InvalidConfig)
}

fn is_pairing_environment_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("OPENSTREAM_PAIRING_JSON")
        || key.eq_ignore_ascii_case("OPENSTREAM_PAIRING_FILE")
}

fn contains_secret_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let normalized = upper.replace('-', "_");
    [
        "PAIRING_JSON",
        "TOKEN",
        "PASSWORD",
        "PRIVATE_KEY",
        "SECRET",
        "TURN_CREDENTIAL",
        "RELAY_TICKET",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

/// Restart/backoff policy. Values are milliseconds to keep the public
/// configuration serde-safe and deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildPolicy {
    pub max_restarts: u32,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub reset_after_ms: u64,
}

impl Default for ChildPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            base_backoff_ms: 500,
            max_backoff_ms: 30_000,
            reset_after_ms: 60_000,
        }
    }
}

impl ChildPolicy {
    pub fn validate(self) -> Result<Self, AgentError> {
        if self.max_restarts > 100
            || self.base_backoff_ms == 0
            || self.base_backoff_ms > self.max_backoff_ms
            || self.max_backoff_ms > 3_600_000
            || self.reset_after_ms > 86_400_000
        {
            return Err(AgentError::InvalidConfig);
        }
        Ok(self)
    }

    fn delay_ms(self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(63);
        let factor = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
        self.base_backoff_ms
            .saturating_mul(factor)
            .min(self.max_backoff_ms)
    }
}

/// Fully validated host-agent configuration.
#[derive(Clone, Debug)]
pub struct HostAgentConfig {
    child: ChildSpec,
    policy: ChildPolicy,
    backend: String,
    startup_grace_ms: u64,
    max_child_lifetime_ms: Option<u64>,
    frame_heartbeat_file: Option<PathBuf>,
    config_revision: String,
}

impl HostAgentConfig {
    pub fn new(child: ChildSpec) -> Result<Self, AgentError> {
        child.validate()?;
        let config = Self {
            child,
            policy: ChildPolicy::default(),
            backend: "ffmpeg-fallback".to_string(),
            startup_grace_ms: 5_000,
            max_child_lifetime_ms: None,
            frame_heartbeat_file: None,
            config_revision: "unversioned".to_string(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Project only non-secret settings into the host child environment.
    /// Pairing material and private keys are intentionally not read from
    /// AppConfig and must be supplied by a separate runtime secret boundary
    /// when the product shell is ready.
    pub fn from_settings(
        settings: &AppConfig,
        executable: impl Into<PathBuf>,
    ) -> Result<Self, AgentError> {
        settings.validate().map_err(|_| AgentError::InvalidConfig)?;
        let effective = settings.effective();
        let mut child = ChildSpec::new(executable)?;
        child = child.env(
            "OPENSTREAM_SIGNAL_ORIGIN",
            effective.client.signal_origin.clone(),
        )?;
        child = child.env("OPENSTREAM_WIDTH", effective.video.width.to_string())?;
        child = child.env("OPENSTREAM_HEIGHT", effective.video.height.to_string())?;
        child = child.env("OPENSTREAM_FPS", effective.video.fps.to_string())?;
        child = child.env(
            "OPENSTREAM_VIDEO_MBPS",
            format!("{:.6}", effective.video.bitrate_mbps),
        )?;
        child = child.env(
            "OPENSTREAM_VIDEO_MIN_MBPS",
            format!("{:.6}", effective.video.min_bitrate_mbps),
        )?;
        child = child.env("OPENSTREAM_VIDEO_CODEC", mode_text(&effective.video.codec)?)?;
        child = child.env(
            "OPENSTREAM_PIXEL_FORMAT",
            mode_text(&effective.video.pixel_format)?,
        )?;
        child = child.env("OPENSTREAM_AUDIO", bool_text(effective.audio.enabled))?;
        child = child.env("OPENSTREAM_AUDIO_CODEC", mode_text(&effective.audio.codec)?)?;
        child = child.env(
            "OPENSTREAM_AUDIO_BITRATE_KBPS",
            effective.audio.bitrate_kbps.to_string(),
        )?;
        child = child.env(
            "OPENSTREAM_AUDIO_LATENCY",
            mode_text(&effective.audio.latency_mode)?,
        )?;
        child = child.env("OPENSTREAM_HOST_NAME", effective.host.name.clone())?;
        child = child.env(
            "OPENSTREAM_STAY_AWAKE",
            bool_text(effective.host.stay_awake),
        )?;
        child = child.env(
            "OPENSTREAM_MAX_GUESTS",
            effective.host.max_guests.to_string(),
        )?;
        child = child.env("OPENSTREAM_APPROVAL", mode_text(&effective.host.approval)?)?;
        child = child.env(
            "OPENSTREAM_ENABLE_INPUT",
            bool_text(effective.input.enabled),
        )?;
        child = child.env(
            "OPENSTREAM_ENABLE_KEYBOARD",
            bool_text(effective.input.enabled && effective.input.keyboard),
        )?;
        child = child.env(
            "OPENSTREAM_ENABLE_MOUSE",
            bool_text(effective.input.enabled && effective.input.mouse),
        )?;
        child = child.env(
            "OPENSTREAM_GAMEPAD",
            bool_text(effective.input.enabled && effective.input.gamepad),
        )?;
        child = child.env(
            "OPENSTREAM_CLIPBOARD",
            bool_text(effective.input.enabled && effective.input.clipboard),
        )?;
        child = child.env(
            "OPENSTREAM_MIC",
            bool_text(effective.input.enabled && effective.input.microphone),
        )?;
        child = child.env(
            "OPENSTREAM_HOST_PORT",
            effective
                .network
                .host_start_port
                .or(effective.network.udp_port)
                .map_or_else(|| "0".to_string(), |port| port.to_string()),
        )?;
        child = child.env("OPENSTREAM_UPNP", bool_text(effective.network.upnp))?;
        child = child.env("OPENSTREAM_ICE", bool_text(effective.network.ice))?;
        child = child.env(
            "OPENSTREAM_FORCE_RELAY",
            bool_text(effective.network.force_relay),
        )?;
        child = child.env(
            "OPENSTREAM_CONGESTION",
            mode_text(&effective.network.congestion)?,
        )?;
        child = child.env(
            "OPENSTREAM_FFMPEG_RECONFIGURE",
            if effective.advanced.ffmpeg_reconfigure {
                "restart"
            } else {
                "disabled"
            },
        )?;
        if let Some(cap) = effective.host.aggregate_bandwidth_cap_mbps {
            child = child.env("OPENSTREAM_HOST_BANDWIDTH_MBPS", format!("{cap:.6}"))?;
        }
        if let Some(display) = &effective.host.selected_display {
            child = child.env("OPENSTREAM_DISPLAY", display.clone())?;
        }
        child = child.env(
            "OPENSTREAM_HOST_SECONDS",
            effective.advanced.max_session_seconds.to_string(),
        )?;
        if let Some(ffmpeg) = &effective.advanced.ffmpeg_path {
            child = child.env("OPENSTREAM_FFMPEG", ffmpeg.clone())?;
        }
        if !matches!(effective.host.capture, CaptureMode::Auto) {
            child = child.env(
                "OPENSTREAM_CAPTURE_BACKEND",
                mode_text(&effective.host.capture)?,
            )?;
        }
        child = child.env(
            "OPENSTREAM_VIDEO_ENCODER",
            mode_text(&effective.host.encoder)?,
        )?;
        let mut config = Self::new(child)?;
        config.config_revision = host_config_revision(settings);
        config.child.env.insert(
            "OPENSTREAM_CONFIG_REVISION".to_string(),
            config.config_revision.clone(),
        );
        config.validate()?;
        Ok(config)
    }

    pub fn with_policy(mut self, policy: ChildPolicy) -> Result<Self, AgentError> {
        self.policy = policy.validate()?;
        Ok(self)
    }

    pub fn with_backend(mut self, backend: impl Into<String>) -> Result<Self, AgentError> {
        self.backend = backend.into();
        self.validate()?;
        Ok(self)
    }

    pub fn with_startup_grace(mut self, grace: Duration) -> Self {
        self.startup_grace_ms = duration_millis(grace);
        self
    }

    pub fn with_max_child_lifetime(
        mut self,
        lifetime: Option<Duration>,
    ) -> Result<Self, AgentError> {
        self.max_child_lifetime_ms = lifetime.map(duration_millis);
        self.validate()?;
        Ok(self)
    }

    /// Add a runtime environment value. This is intentionally separate from
    /// from_settings so secret providers can inject a value without making
    /// it persistable or placing it in argv. Values never appear in Debug.
    pub fn with_runtime_env(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AgentError> {
        self.child = self.child.env(key, value)?;
        self.validate()?;
        Ok(self)
    }

    /// Add the persistent agent's pairing file after validating its secure
    /// filesystem boundary. Generic runtime environment insertion cannot set
    /// either pairing variable.
    pub fn with_pairing_file(mut self, path: impl AsRef<Path>) -> Result<Self, AgentError> {
        let path = validate_private_pairing_file(path.as_ref())?;
        self.child.set_pairing_file(path);
        self.validate()?;
        Ok(self)
    }

    /// Require the child to update a private heartbeat after encoded frames
    /// are emitted. A missing or stale heartbeat keeps the agent in Starting
    /// and then triggers bounded restart rather than reporting process-only
    /// readiness. The path itself is metadata, never secret material.
    pub fn with_frame_heartbeat_file(mut self, path: impl AsRef<Path>) -> Result<Self, AgentError> {
        let path = validate_private_runtime_path(path.as_ref())?;
        self.child.env.insert(
            "OPENSTREAM_FRAME_HEARTBEAT_FILE".to_string(),
            path.to_string(),
        );
        self.frame_heartbeat_file = Some(PathBuf::from(path));
        self.validate()?;
        Ok(self)
    }

    /// Override the revision for a configuration assembled by a service
    /// broker. Revisions are labels only; the settings file remains the source
    /// of actual values and secrets are never placed in this field.
    pub fn with_config_revision(mut self, revision: impl Into<String>) -> Result<Self, AgentError> {
        self.config_revision = revision.into();
        if self.config_revision.is_empty() || self.config_revision.len() > 128 {
            return Err(AgentError::InvalidConfig);
        }
        self.child.env.insert(
            "OPENSTREAM_CONFIG_REVISION".to_string(),
            self.config_revision.clone(),
        );
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AgentError> {
        self.child.validate()?;
        self.policy.validate()?;
        if self.backend.is_empty()
            || self.backend.len() > MAX_BACKEND_BYTES
            || self.backend.chars().any(char::is_control)
            || self.startup_grace_ms > 300_000
            || self
                .max_child_lifetime_ms
                .is_some_and(|value| !(1..=86_400_000).contains(&value))
            || self.config_revision.is_empty()
            || self.config_revision.len() > 128
        {
            return Err(AgentError::InvalidConfig);
        }
        Ok(())
    }

    pub fn child(&self) -> &ChildSpec {
        &self.child
    }

    pub const fn policy(&self) -> ChildPolicy {
        self.policy
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn frame_heartbeat_file(&self) -> Option<&Path> {
        self.frame_heartbeat_file.as_deref()
    }

    pub fn config_revision(&self) -> &str {
        &self.config_revision
    }
}

fn validate_private_runtime_path(path: &Path) -> Result<String, AgentError> {
    if !path.is_absolute()
        || path.as_os_str().to_string_lossy().len() > MAX_ARGUMENT_BYTES
        || path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
    {
        return Err(AgentError::InvalidConfig);
    }
    let parent = path.parent().ok_or(AgentError::InvalidConfig)?;
    if parent.exists() {
        let metadata = parent
            .symlink_metadata()
            .map_err(|_| AgentError::InvalidConfig)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AgentError::InvalidConfig);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(AgentError::InvalidConfig);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(AgentError::InvalidConfig);
            }
        }
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or(AgentError::InvalidConfig)
}

fn bool_text(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn mode_text<T: Serialize>(mode: &T) -> Result<String, AgentError> {
    serde_json::to_value(mode)
        .map_err(|_| AgentError::InvalidConfig)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(AgentError::InvalidConfig)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

/// Preflight result used to select a truthful capture path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBackend {
    NativeDrm,
    FfmpegX11,
    FfmpegPipewire,
    FfmpegFallback,
    Unavailable,
}

impl HostBackend {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NativeDrm => "native-drm",
            Self::FfmpegX11 => "x11-ffmpeg",
            Self::FfmpegPipewire => "pipewire-ffmpeg",
            Self::FfmpegFallback => "ffmpeg-fallback",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Redacted capability result; it contains no command output or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub native_drm_reachable: bool,
    pub native_drm_usable: bool,
    pub x11_available: bool,
    pub pipewire_available: bool,
    pub ffmpeg_available: bool,
    pub selected: HostBackend,
    pub reason: Option<HostErrorCode>,
}

/// Select a backend only from explicit preflight capabilities.
///
/// `native_drm_reachable` is a diagnostic scanout result. It is not sufficient
/// to select the native backend; callers must separately prove and explicitly
/// enable the native pipeline through `native_drm_usable`.
pub fn run_preflight(
    requested: &CaptureMode,
    native_drm_reachable: bool,
    native_drm_usable: bool,
    x11_available: bool,
    pipewire_available: bool,
    ffmpeg_available: bool,
) -> PreflightReport {
    let native_drm_usable = native_drm_reachable && native_drm_usable;
    let selected = match requested {
        CaptureMode::Drm if native_drm_usable => HostBackend::NativeDrm,
        CaptureMode::Drm => HostBackend::Unavailable,
        CaptureMode::Pipewire if pipewire_available && ffmpeg_available => {
            HostBackend::FfmpegPipewire
        }
        CaptureMode::X11 if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        CaptureMode::Auto if native_drm_usable => HostBackend::NativeDrm,
        CaptureMode::Auto if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        CaptureMode::Auto if pipewire_available && ffmpeg_available => HostBackend::FfmpegPipewire,
        _ if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        _ if pipewire_available && ffmpeg_available => HostBackend::FfmpegPipewire,
        _ if ffmpeg_available => HostBackend::FfmpegFallback,
        _ => HostBackend::Unavailable,
    };
    PreflightReport {
        native_drm_reachable,
        native_drm_usable,
        x11_available,
        pipewire_available,
        ffmpeg_available,
        selected,
        reason: (selected == HostBackend::Unavailable)
            .then_some(HostErrorCode::PreflightUnavailable),
    }
}

/// Errors returned by the supervisor. They intentionally contain no command,
/// environment, pairing, or arbitrary child output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    InvalidConfig,
    SpawnFailed,
    ChildIo(io::ErrorKind),
    StopFailed,
    UnsupportedPlatform,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid host-agent configuration"),
            Self::SpawnFailed => formatter.write_str("host child could not be started"),
            Self::ChildIo(kind) => write!(formatter, "host child I/O failed: {kind}"),
            Self::StopFailed => formatter.write_str("host child could not be stopped"),
            Self::UnsupportedPlatform => formatter.write_str("host-agent platform is unsupported"),
        }
    }
}

impl std::error::Error for AgentError {}

/// Process operations needed by the deterministic supervisor.
pub trait ManagedChild: Send {
    fn pid(&self) -> Option<u32>;
    fn try_wait(&mut self) -> Result<Option<ChildExit>, AgentError>;
    fn terminate(&mut self) -> Result<(), AgentError>;
    fn force_kill(&mut self) -> Result<(), AgentError> {
        self.terminate()
    }
    /// Best-effort cleanup that runs after the managed leader is reaped but
    /// before the supervisor drops process ownership or reports a transition.
    fn cleanup_after_reap(&mut self) {}
}

/// Factory seam used by tests and future platform-specific launchers.
pub trait ChildFactory: Send + Sync {
    fn spawn(&self, spec: &ChildSpec) -> Result<Box<dyn ManagedChild>, AgentError>;
}

/// Tokio process factory. It passes a validated argv vector directly to the
/// OS and redirects output so child logs cannot accidentally disclose secrets.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioChildFactory;

struct TokioManagedChild {
    child: tokio::process::Child,
    #[cfg(unix)]
    process_group: Option<u32>,
}

impl ManagedChild for TokioManagedChild {
    fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> Result<Option<ChildExit>, AgentError> {
        self.child
            .try_wait()
            .map_err(|error| AgentError::ChildIo(error.kind()))
            .map(|status| status.map(exit_from_status))
    }

    fn terminate(&mut self) -> Result<(), AgentError> {
        #[cfg(unix)]
        {
            signal_process_group(self.child.id(), 15)
        }
        #[cfg(not(unix))]
        {
            self.child.start_kill().map_err(|_| AgentError::StopFailed)
        }
    }

    fn force_kill(&mut self) -> Result<(), AgentError> {
        #[cfg(unix)]
        {
            signal_process_group(self.child.id(), 9)
        }
        #[cfg(not(unix))]
        {
            self.child.start_kill().map_err(|_| AgentError::StopFailed)
        }
    }

    fn cleanup_after_reap(&mut self) {
        #[cfg(unix)]
        {
            // The leader PID disappears after reap, but the process-group ID
            // remains valid while descendants survive. Cleanup is best effort:
            // an absent group means there is nothing left to kill.
            let _ = signal_process_group(self.process_group, 9);
        }
    }
}

/// Whether a group id may be signalled with a negated pid.
///
/// **A safety gate, not a validation nicety.** `kill` gives two pid values a
/// meaning that has nothing to do with the number itself:
///
/// ```text
/// kill(-1, sig)   every process the caller may signal
/// kill(0, sig)    the caller's own process group -- including the caller
/// ```
///
/// So negating a group id of 1 does not target "process group 1"; it targets
/// every process this user is running, the agent and the desktop shell
/// included. A group id of 0 would take out the agent itself. Neither can be
/// a real child's group, so both are refused here rather than at each call
/// site, where one of them will eventually be forgotten.
///
/// The same gate exists in the desktop session supervisor. Both are kept
/// because both call `kill` with a negated pid; neither can rely on the other
/// having checked.
#[cfg(unix)]
const fn is_signallable_group(group: i32) -> bool {
    group > 1
}

#[cfg(unix)]
fn signal_process_group(pid: Option<u32>, signal: i32) -> Result<(), AgentError> {
    let pid = pid.ok_or(AgentError::StopFailed)?;
    // Checked, not `as`. A pid that does not fit in an `i32` would wrap to a
    // negative value, and negating that produces a positive number naming
    // some unrelated process -- a truncation bug that presents as signalling
    // a stranger.
    let group = i32::try_from(pid).map_err(|_| AgentError::StopFailed)?;
    if !is_signallable_group(group) {
        return Err(AgentError::StopFailed);
    }
    // SAFETY: `group` is a positive pid greater than 1, so negating it names
    // the child's process group and nothing else. See `is_signallable_group`.
    let result = unsafe { libc::kill(-group, signal) };
    if result == 0 {
        return Ok(());
    }
    // ESRCH means the group is already gone, which is the outcome this was
    // asking for. Reporting it as a failure to stop makes a clean exit look
    // like a stuck child.
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(AgentError::StopFailed)
}

impl ChildFactory for TokioChildFactory {
    fn spawn(&self, spec: &ChildSpec) -> Result<Box<dyn ManagedChild>, AgentError> {
        use std::process::Stdio;
        let mut command = tokio::process::Command::new(spec.program());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        configure_child_environment(&mut command, spec);
        command
            .args(spec.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|_| AgentError::SpawnFailed)?;
        #[cfg(unix)]
        let process_group = child.id();
        Ok(Box::new(TokioManagedChild {
            child,
            #[cfg(unix)]
            process_group,
        }))
    }
}

fn configure_child_environment(command: &mut tokio::process::Command, spec: &ChildSpec) {
    command
        .env_remove("OPENSTREAM_PAIRING_JSON")
        .env_remove("OPENSTREAM_PAIRING_FILE")
        .envs(spec.environment());
    if let Some(path) = spec.pairing_file() {
        command.env("OPENSTREAM_PAIRING_FILE", path);
    }
}

#[cfg(unix)]
fn exit_from_status(status: std::process::ExitStatus) -> ChildExit {
    use std::os::unix::process::ExitStatusExt;
    ChildExit {
        success: status.success(),
        code: status.code(),
        signal: status.signal(),
    }
}

#[cfg(not(unix))]
fn exit_from_status(status: std::process::ExitStatus) -> ChildExit {
    ChildExit {
        success: status.success(),
        code: status.code(),
        signal: None,
    }
}

/// Commands accepted by the state-machine API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostAgentCommand {
    Start,
    Stop,
    Tick,
    Shutdown,
}

/// Events emitted after a command or tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostAgentEvent {
    Started { pid: Option<u32> },
    Ready,
    ChildExited { reason: ChildExitReason },
    RestartScheduled { delay_ms: u64, attempt: u32 },
    Stopped,
    Failed { code: HostErrorCode },
}

/// Commands accepted by the host-agent Unix-socket service.
///
/// `Eq` is deliberately absent: `StartWithSettings` carries an `AppConfig`,
/// which holds floating-point bitrate and gain values. `PartialEq` is enough
/// for the comparisons this type is actually used for, and claiming a total
/// equivalence over IEEE-754 would be wrong rather than merely unnecessary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AgentIpcCommand {
    Start,
    /// Start using a validated, secret-free product configuration supplied by
    /// the desktop shell. Pairing/private identity material is never part of
    /// this message; the agent still obtains it only through its protected
    /// file/provider boundary.
    ///
    /// Boxed so one large variant does not set the size of every command in
    /// this enum -- `Health` and `Tick` are the ones sent constantly. `Box`
    /// is transparent to serde, so the IPC JSON is unchanged.
    StartWithSettings {
        settings: Box<AppConfig>,
    },
    Stop,
    Tick,
    Health,
    Shutdown,
}

/// One bounded local request. It contains no credentials or user content.
///
/// Not `Eq`, for the reason given on [`AgentIpcCommand`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentIpcRequest {
    pub version: u32,
    pub request_id: RequestId,
    pub command: AgentIpcCommand,
}

/// Truth state for the child-produced frame heartbeat. Process state alone is
/// intentionally insufficient: a compositor or capture source can be dead
/// while FFmpeg remains alive and accepting no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameLiveness {
    /// No heartbeat file is configured, so nothing is being claimed.
    NotConfigured,
    /// The host is up and reporting, but is not streaming yet -- it is
    /// starting, or waiting for a peer that has not arrived.
    ///
    /// This is a healthy state and may persist indefinitely. A host is
    /// routinely started long before its client, and the establishment
    /// protocol has no deadline of its own, so neither can this.
    Waiting,
    /// A peer is present and the session is being established.
    Negotiating,
    /// Streaming, with a frame counter that is advancing.
    Live,
    /// The host stopped reporting, or claims to be streaming while its frame
    /// counter has stopped advancing. This is the only faulty reading.
    Stale,
}

/// One reading of the heartbeat file: facts only, no verdict.
///
/// Kept as a struct rather than a tuple because the three fields are easy to
/// transpose and two of them are numbers; a caller that swapped age and
/// frames would still compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeartbeatObservation {
    /// How long ago the file was written, or `None` if that cannot be read.
    age: Option<u64>,
    phase: HostPhase,
    frames: u64,
}

impl HeartbeatObservation {
    /// The reading for a heartbeat file that exists in name only -- missing,
    /// or rejected for not being a file this agent will read.
    ///
    /// No age, so it is judged stale, which is the right answer: a host that
    /// is not writing its heartbeat is not reporting, whatever it is doing.
    const fn silent() -> Self {
        Self {
            age: None,
            phase: HostPhase::Starting,
            frames: 0,
        }
    }
}

impl FrameLiveness {
    /// Whether this reading is evidence of a working host.
    ///
    /// Everything except [`Self::Stale`] is. The distinction matters because
    /// the supervisor used to require [`Self::Live`], which made every
    /// non-streaming phase indistinguishable from a dead capture and got a
    /// host waiting for its client killed at the end of the startup grace.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        !matches!(self, Self::Stale)
    }
}

/// One bounded local response. Errors carry only typed status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentIpcResponse {
    Accepted {
        version: u32,
        request_id: RequestId,
        events: Vec<HostAgentEvent>,
    },
    Health {
        version: u32,
        request_id: RequestId,
        health: HostHealth,
    },
    Error {
        version: u32,
        request_id: RequestId,
        code: HostErrorCode,
        retryable: bool,
    },
}

impl AgentIpcRequest {
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.version != HOST_AGENT_PROTOCOL_VERSION {
            return Err(AgentError::InvalidConfig);
        }
        Ok(())
    }
}

/// Bounded, redacted health snapshot for the UI/IPC boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHealth {
    pub state: ChildState,
    pub backend: String,
    pub pid: Option<u32>,
    pub restart_count: u32,
    pub next_restart_in_ms: Option<u64>,
    pub last_exit: Option<ChildExitReason>,
    pub last_error: Option<HostErrorCode>,
    pub config_revision: String,
    pub frame_liveness: FrameLiveness,
    pub frames_seen: u64,
    pub last_frame_age_ms: Option<u64>,
}

/// Host child supervisor. F is public only to make deterministic factories
/// possible; production uses the default Tokio factory.
pub struct HostAgent<F: ChildFactory = TokioChildFactory> {
    factory: F,
    config: HostAgentConfig,
    state: ChildState,
    child: Option<Box<dyn ManagedChild>>,
    restart_count: u32,
    next_restart_at: Option<Instant>,
    started_at: Option<Instant>,
    last_exit: Option<ChildExitReason>,
    last_error: Option<HostErrorCode>,
    stop_requested: bool,
    stop_deadline: Option<Instant>,
    pending_termination: Option<ChildExitReason>,
    force_kill_sent: bool,
    frames_seen: u64,
    /// When the frame counter last moved to a *higher* value.
    ///
    /// Kept separately from the heartbeat file's freshness because they are
    /// different facts. The publisher rewrites the file on a timer whether or
    /// not the encoder produced anything, so a fresh file proves the child is
    /// alive and says nothing about frames flowing. This is the second half:
    /// the same rule the client's `Liveness` already follows -- progress is
    /// the counter advancing, not the counter being republished.
    frames_advanced_at: Option<Instant>,
    /// When the child first said it was streaming, for the first-frame
    /// deadline. Cleared whenever it reports any other phase, so a host that
    /// loses its peer and later regains one gets a fresh deadline rather than
    /// one measured from a stream that already ended.
    streaming_since: Option<Instant>,
    /// Consecutive non-live heartbeat observations. Reset by any live one.
    liveness_strikes: u32,
}

impl<F: ChildFactory> fmt::Debug for HostAgent<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostAgent")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("has_child", &self.child.is_some())
            .field("restart_count", &self.restart_count)
            .field("last_exit", &self.last_exit)
            .field("last_error", &self.last_error)
            .finish()
    }
}

impl HostAgent<TokioChildFactory> {
    pub fn new(config: HostAgentConfig) -> Result<Self, AgentError> {
        Self::with_factory(config, TokioChildFactory)
    }
}

impl<F: ChildFactory> HostAgent<F> {
    pub fn with_factory(config: HostAgentConfig, factory: F) -> Result<Self, AgentError> {
        config.validate()?;
        Ok(Self {
            factory,
            config,
            state: ChildState::Stopped,
            child: None,
            restart_count: 0,
            next_restart_at: None,
            started_at: None,
            last_exit: None,
            last_error: None,
            stop_requested: false,
            stop_deadline: None,
            pending_termination: None,
            force_kill_sent: false,
            frames_seen: 0,
            frames_advanced_at: None,
            streaming_since: None,
            liveness_strikes: 0,
        })
    }

    pub fn dispatch(
        &mut self,
        command: HostAgentCommand,
        now: Instant,
    ) -> Result<Vec<HostAgentEvent>, AgentError> {
        match command {
            HostAgentCommand::Start => self.start(now),
            HostAgentCommand::Stop | HostAgentCommand::Shutdown => self.stop(now),
            HostAgentCommand::Tick => self.tick(now),
        }
    }

    pub fn start(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        if matches!(
            self.state,
            ChildState::Starting | ChildState::Ready | ChildState::Stopping | ChildState::Backoff
        ) {
            return Ok(Vec::new());
        }
        self.restart_count = 0;
        self.last_error = None;
        self.stop_requested = false;
        self.spawn(now)
    }

    /// Replace the child configuration while no child is running. This is the
    /// only configuration mutation path: a running or stopping child must be
    /// fully reaped before a new configuration can be applied, preventing a
    /// quick UI Stop/Start sequence from leaving two differently configured
    /// hosts alive at once.
    pub fn replace_config(&mut self, config: HostAgentConfig) -> Result<(), AgentError> {
        if self.child.is_some() || self.state == ChildState::Stopping {
            return Err(AgentError::InvalidConfig);
        }
        config.validate()?;
        self.config = config;
        self.state = ChildState::Stopped;
        self.restart_count = 0;
        self.next_restart_at = None;
        self.started_at = None;
        self.last_exit = None;
        self.last_error = None;
        self.stop_requested = false;
        self.stop_deadline = None;
        self.pending_termination = None;
        self.force_kill_sent = false;
        self.frames_seen = 0;
        self.frames_advanced_at = None;
        self.streaming_since = None;
        self.liveness_strikes = 0;
        Ok(())
    }

    pub fn stop(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        if self.state == ChildState::Stopped
            && self.child.is_none()
            && self.next_restart_at.is_none()
        {
            return Ok(Vec::new());
        }
        self.stop_requested = true;
        self.next_restart_at = None;
        if self.child.is_none() {
            self.started_at = None;
            self.state = ChildState::Stopped;
            return Ok(vec![HostAgentEvent::Stopped]);
        }
        if self.state != ChildState::Stopping {
            self.begin_stopping(now, None)?;
        }
        Ok(Vec::new())
    }

    pub fn tick(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        if self.state == ChildState::Stopping {
            return self.tick_stopping(now);
        }
        if self.state == ChildState::Backoff {
            if self.next_restart_at.is_some_and(|deadline| now >= deadline) {
                self.next_restart_at = None;
                return self.spawn(now);
            }
            return Ok(Vec::new());
        }

        if self.child.is_some() {
            let exit = self
                .child
                .as_mut()
                .expect("child checked above")
                .try_wait()?;
            if let Some(exit) = exit {
                self.child
                    .as_mut()
                    .expect("child checked above")
                    .cleanup_after_reap();
                return self.handle_exit(ChildExitReason::from(exit), now);
            }

            if self.max_lifetime_reached(now) {
                return self.handle_lifetime(now);
            }

            // Two questions, deliberately not one. "Is the host working?" is
            // what the supervisor acts on; "is it streaming?" is only one of
            // the ways it can be working. Collapsing them is what made a host
            // waiting for its client indistinguishable from a dead capture,
            // and got it killed at the end of the startup grace for doing
            // exactly what the establishment protocol allows.
            let healthy = if let Some(observation) = self.heartbeat_observation() {
                // Record advancement first: the verdict below asks when the
                // counter last moved, not what it currently reads.
                if observation.frames > self.frames_seen {
                    self.frames_seen = observation.frames;
                    self.frames_advanced_at = Some(now);
                }
                // Record the phase transition before judging, so the verdict
                // can ask how long this host has claimed to be streaming.
                if observation.phase.expects_frames() {
                    self.streaming_since.get_or_insert(now);
                } else {
                    self.streaming_since = None;
                }
                self.judge_liveness(observation, now).is_healthy()
            } else {
                true
            };
            if healthy {
                self.liveness_strikes = 0;
            } else {
                self.liveness_strikes = self.liveness_strikes.saturating_add(1);
            }
            if self.state == ChildState::Starting {
                if healthy {
                    // Ready means the service is up and reporting, not that
                    // pixels are moving. A host with no peer yet is ready in
                    // every sense the supervisor can act on, and it may stay
                    // that way for hours.
                    self.state = ChildState::Ready;
                    return Ok(vec![HostAgentEvent::Ready]);
                }
                if self.started_at.is_some_and(|started| {
                    now.saturating_duration_since(started)
                        >= Duration::from_millis(self.config.startup_grace_ms)
                }) {
                    // Nothing was ever published here. The startup grace
                    // covers a slow start; a host that has not written its
                    // heartbeat by the end of it is not starting slowly.
                    self.last_error = Some(HostErrorCode::FrameLivenessTimeout);
                    self.begin_stopping(now, Some(ChildExitReason::FrameLivenessTimeout))?;
                }
            } else if self.state == ChildState::Ready
                && self.liveness_strikes >= FRAME_LIVENESS_STRIKES
            {
                // A ready child is working until several consecutive
                // observations say otherwise. See [`FRAME_LIVENESS_STRIKES`].
                self.last_error = Some(HostErrorCode::FrameLivenessTimeout);
                self.begin_stopping(now, Some(ChildExitReason::FrameLivenessTimeout))?;
            }
        }
        Ok(Vec::new())
    }

    fn spawn(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        if self.child.is_some() || self.state == ChildState::Stopping {
            return Ok(Vec::new());
        }
        let child = match self.factory.spawn(&self.config.child) {
            Ok(child) => child,
            Err(error) => {
                let mut events = Vec::new();
                self.last_error = Some(HostErrorCode::SpawnFailed);
                self.schedule_restart(now, HostErrorCode::SpawnFailed, &mut events);
                return Err(error);
            }
        };
        let pid = child.pid();
        self.child = Some(child);
        self.state = ChildState::Starting;
        self.started_at = Some(now);
        self.next_restart_at = None;
        self.stop_deadline = None;
        self.pending_termination = None;
        self.force_kill_sent = false;
        self.frames_seen = 0;
        self.frames_advanced_at = None;
        self.streaming_since = None;
        self.liveness_strikes = 0;
        if let Some(path) = self.config.frame_heartbeat_file.as_deref() {
            // A previous child must not make a newly spawned child look live.
            // The child recreates this bounded metadata file on its first
            // encoded frame.
            let _ = std::fs::remove_file(path);
        }
        Ok(vec![HostAgentEvent::Started { pid }])
    }

    fn handle_exit(
        &mut self,
        reason: ChildExitReason,
        now: Instant,
    ) -> Result<Vec<HostAgentEvent>, AgentError> {
        let was_long_running = self.started_at.is_some_and(|started| {
            now.saturating_duration_since(started)
                >= Duration::from_millis(self.config.policy.reset_after_ms)
        });
        self.child = None;
        self.started_at = None;
        self.last_exit = Some(reason);
        let mut events = vec![HostAgentEvent::ChildExited { reason }];

        if self.stop_requested || !reason.should_restart() {
            self.next_restart_at = None;
            self.state = ChildState::Stopped;
            events.push(HostAgentEvent::Stopped);
            return Ok(events);
        }
        if was_long_running {
            self.restart_count = 0;
        }
        self.schedule_restart(now, HostErrorCode::ChildFailed, &mut events);
        Ok(events)
    }

    fn handle_lifetime(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        self.begin_stopping(now, Some(ChildExitReason::LifetimeExceeded))?;
        Ok(Vec::new())
    }

    fn begin_stopping(
        &mut self,
        now: Instant,
        pending_termination: Option<ChildExitReason>,
    ) -> Result<(), AgentError> {
        self.state = ChildState::Stopping;
        self.pending_termination = pending_termination;
        self.force_kill_sent = false;
        match self
            .child
            .as_mut()
            .expect("stopping requires child")
            .terminate()
        {
            Ok(()) => {
                self.stop_deadline = Some(now + STOP_GRACE_PERIOD);
                Ok(())
            }
            Err(error) => {
                self.stop_deadline = Some(now);
                self.last_error = Some(HostErrorCode::StopFailed);
                Err(error)
            }
        }
    }

    fn tick_stopping(&mut self, now: Instant) -> Result<Vec<HostAgentEvent>, AgentError> {
        let exit = self
            .child
            .as_mut()
            .expect("stopping retains child")
            .try_wait()?;
        if exit.is_some() {
            self.child
                .as_mut()
                .expect("stopping retains child")
                .cleanup_after_reap();
            // Same crash-forgiveness rule as `handle_exit`. A child that ran
            // long enough to be healthy must not spend the restart budget:
            // ending a session at its configured lifetime cap is the normal
            // outcome, and without this reset a host that never crashes still
            // reaches `max_restarts` after a few sessions and stops for good.
            let was_long_running = self.started_at.is_some_and(|started| {
                now.saturating_duration_since(started)
                    >= Duration::from_millis(self.config.policy.reset_after_ms)
            });
            let pending = self.pending_termination.take();
            self.child = None;
            self.started_at = None;
            self.stop_deadline = None;
            self.force_kill_sent = false;
            if let Some(reason) = pending {
                self.last_exit = Some(reason);
                let mut events = vec![HostAgentEvent::ChildExited { reason }];
                if self.stop_requested {
                    self.next_restart_at = None;
                    self.state = ChildState::Stopped;
                    events.push(HostAgentEvent::Stopped);
                    return Ok(events);
                }
                if was_long_running {
                    self.restart_count = 0;
                }
                let error = match reason {
                    ChildExitReason::LifetimeExceeded => HostErrorCode::LifetimeExceeded,
                    ChildExitReason::FrameLivenessTimeout => HostErrorCode::FrameLivenessTimeout,
                    _ => HostErrorCode::ChildFailed,
                };
                self.schedule_restart(now, error, &mut events);
                return Ok(events);
            }
            self.state = ChildState::Stopped;
            return Ok(vec![HostAgentEvent::Stopped]);
        }
        if !self.force_kill_sent && self.stop_deadline.is_some_and(|deadline| now >= deadline) {
            if let Err(error) = self
                .child
                .as_mut()
                .expect("stopping retains child")
                .force_kill()
            {
                self.last_error = Some(HostErrorCode::StopFailed);
                return Err(error);
            }
            self.force_kill_sent = true;
        }
        Ok(Vec::new())
    }

    fn schedule_restart(
        &mut self,
        now: Instant,
        error: HostErrorCode,
        events: &mut Vec<HostAgentEvent>,
    ) {
        if self.restart_count >= self.config.policy.max_restarts {
            self.state = ChildState::Failed;
            self.next_restart_at = None;
            self.last_error = Some(HostErrorCode::RestartLimit);
            events.push(HostAgentEvent::Failed {
                code: HostErrorCode::RestartLimit,
            });
            return;
        }
        self.restart_count = self.restart_count.saturating_add(1);
        let delay_ms = self.config.policy.delay_ms(self.restart_count);
        self.state = ChildState::Backoff;
        self.next_restart_at = Some(now + Duration::from_millis(delay_ms));
        self.last_error = Some(error);
        events.push(HostAgentEvent::RestartScheduled {
            delay_ms,
            attempt: self.restart_count,
        });
    }

    fn max_lifetime_reached(&self, now: Instant) -> bool {
        let Some(lifetime) = self.config.max_child_lifetime_ms else {
            return false;
        };
        let Some(started) = self.started_at else {
            return false;
        };
        now.saturating_duration_since(started) >= Duration::from_millis(lifetime)
    }

    pub fn health(&self, now: Instant) -> HostHealth {
        let next_restart_in_ms = self.next_restart_at.map(|deadline| {
            deadline
                .saturating_duration_since(now)
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
        });
        let (frame_liveness, last_frame_age_ms, heartbeat_frames) = self.heartbeat_status(now);
        HostHealth {
            state: self.state,
            backend: self.config.backend.clone(),
            pid: self.child.as_ref().and_then(|child| child.pid()),
            restart_count: self.restart_count,
            next_restart_in_ms,
            last_exit: self.last_exit,
            last_error: self.last_error,
            config_revision: self.config.config_revision.clone(),
            frame_liveness,
            frames_seen: self.frames_seen.max(heartbeat_frames),
            last_frame_age_ms,
        }
    }

    /// One reading of the heartbeat file: how fresh it is, and what count it
    /// carries. Deliberately reports observations rather than a verdict --
    /// the verdict needs history this cannot see.
    fn heartbeat_observation(&self) -> Option<HeartbeatObservation> {
        let path = self.config.frame_heartbeat_file.as_deref()?;
        let Ok(link_metadata) = std::fs::symlink_metadata(path) else {
            return Some(HeartbeatObservation::silent());
        };
        if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
            return Some(HeartbeatObservation::silent());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if link_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                // Same answer as the symlink and wrong-ownership rejections
                // above: the path exists but is not a heartbeat file this
                // agent will read, so there is no age and no count to report.
                return Some(HeartbeatObservation::silent());
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = unsafe { libc::geteuid() };
            if link_metadata.uid() != uid || link_metadata.mode() & 0o077 != 0 {
                return Some(HeartbeatObservation::silent());
            }
        }
        let age = link_metadata
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        let mut contents = String::new();
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        // An unreadable or unparseable line is not "zero frames in the phase
        // that promises least". It is the absence of a report, and it has to
        // be represented as one -- keeping the file's fresh age while
        // inventing a phase for it would make a host writing garbage four
        // times a second look healthier than one writing nothing at all.
        let Some((phase, frames)) = options
            .open(path)
            .and_then(|file| {
                file.take(HEARTBEAT_READ_LIMIT)
                    .read_to_string(&mut contents)
            })
            .ok()
            .and_then(|_| host_heartbeat::parse(&contents))
        else {
            return Some(HeartbeatObservation::silent());
        };
        Some(HeartbeatObservation { age, phase, frames })
    }

    /// Judge frame liveness from an observation plus the recorded history.
    ///
    /// Two separate conditions, because they answer two separate questions:
    ///
    /// ```text
    /// publisher alive = the heartbeat file is fresh
    /// frames flowing  = the counter advanced within the timeout
    /// ```
    ///
    /// Only the second is what `Ready` is supposed to mean. The publisher
    /// rewrites the file on a timer regardless of whether the encoder
    /// produced anything, so treating a fresh file as proof of frames would
    /// report a host as healthy forever after its first frame -- which is
    /// exactly the failure this heartbeat exists to catch.
    fn judge_liveness(&self, observation: HeartbeatObservation, now: Instant) -> FrameLiveness {
        let timeout_ms = u64::try_from(FRAME_HEARTBEAT_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        // Is the host reporting at all? This is the one question that applies
        // in every phase: a process that has stopped writing its heartbeat is
        // wedged whatever it last claimed to be doing.
        if !observation.age.is_some_and(|age| age <= timeout_ms) {
            return FrameLiveness::Stale;
        }
        if !observation.phase.expects_frames() {
            return match observation.phase {
                HostPhase::Negotiating => FrameLiveness::Negotiating,
                _ => FrameLiveness::Waiting,
            };
        }
        // Streaming, so the counter is now load-bearing. A host that has said
        // it is streaming and produced nothing at all is not yet streaming in
        // any useful sense, but it is also not faulty -- the first frame has
        // its own grace through the startup window.
        if observation.frames == 0 {
            // Bounded, unlike the wait for a peer. A host that has claimed
            // the streaming phase has said capture and encode are running, so
            // a counter still at zero is a pipeline that never started -- and
            // "the counter stopped advancing" can never catch it, because it
            // has nothing to advance from.
            let overdue = self
                .streaming_since
                .is_some_and(|since| now.saturating_duration_since(since) > FIRST_FRAME_DEADLINE);
            return if overdue {
                FrameLiveness::Stale
            } else {
                FrameLiveness::Waiting
            };
        }
        let advanced_recently = self.frames_advanced_at.is_some_and(|at| {
            u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX)
                <= timeout_ms
        });
        if advanced_recently {
            FrameLiveness::Live
        } else {
            FrameLiveness::Stale
        }
    }

    fn heartbeat_status(&self, now: Instant) -> (FrameLiveness, Option<u64>, u64) {
        let Some(observation) = self.heartbeat_observation() else {
            return (FrameLiveness::NotConfigured, None, self.frames_seen);
        };
        let liveness = self.judge_liveness(observation, now);
        (liveness, observation.age, observation.frames)
    }

    pub fn app_error_code(&self) -> Option<AppErrorCode> {
        self.last_error.map(HostErrorCode::app_error_code)
    }

    pub const fn state(&self) -> ChildState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentError, ChildExit, ChildExitReason, ChildFactory, ChildSpec, ChildState,
        FIRST_FRAME_DEADLINE, FRAME_LIVENESS_STRIKES, FrameLiveness, HostAgent, HostAgentConfig,
        HostAgentEvent, HostErrorCode, HostPhase, ManagedChild, configure_child_environment,
        host_heartbeat,
    };
    use openstream_settings::default_config;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Clone, Default)]
    struct FakeFactory {
        outcomes: Arc<Mutex<VecDeque<FakeSpawnOutcome>>>,
        spawned: Arc<Mutex<Vec<ChildSpec>>>,
    }

    #[derive(Clone)]
    enum FakeSpawnOutcome {
        Child(FakeChild),
        Error,
    }

    #[derive(Clone)]
    struct FakeChild {
        pid: u32,
        exit: Option<ChildExit>,
        graceful_exit: Option<ChildExit>,
        force_exit: Option<ChildExit>,
        force_error: bool,
        terminate_error: bool,
        signals: Arc<Mutex<FakeChildSignals>>,
    }

    #[derive(Default)]
    struct FakeChildSignals {
        terminate_calls: usize,
        force_kill_calls: usize,
        reap_order: Vec<&'static str>,
    }

    impl FakeChild {
        fn running(pid: u32) -> Self {
            Self {
                pid,
                exit: None,
                graceful_exit: None,
                force_exit: Some(ChildExit::terminated()),
                force_error: false,
                terminate_error: false,
                signals: Arc::new(Mutex::new(FakeChildSignals::default())),
            }
        }

        fn exits_after_graceful(pid: u32) -> Self {
            Self {
                graceful_exit: Some(ChildExit::terminated()),
                ..Self::running(pid)
            }
        }

        fn stubborn(pid: u32) -> (Self, Arc<Mutex<FakeChildSignals>>) {
            let signals = Arc::new(Mutex::new(FakeChildSignals::default()));
            (
                Self {
                    pid,
                    exit: None,
                    graceful_exit: None,
                    force_exit: Some(ChildExit::terminated()),
                    force_error: false,
                    terminate_error: false,
                    signals: Arc::clone(&signals),
                },
                signals,
            )
        }

        fn force_kill_fails(pid: u32) -> (Self, Arc<Mutex<FakeChildSignals>>) {
            let signals = Arc::new(Mutex::new(FakeChildSignals::default()));
            (
                Self {
                    pid,
                    exit: None,
                    graceful_exit: None,
                    force_exit: None,
                    force_error: true,
                    terminate_error: false,
                    signals: Arc::clone(&signals),
                },
                signals,
            )
        }

        fn terminate_fails(pid: u32) -> (Self, Arc<Mutex<FakeChildSignals>>) {
            let signals = Arc::new(Mutex::new(FakeChildSignals::default()));
            (
                Self {
                    pid,
                    exit: None,
                    graceful_exit: None,
                    force_exit: Some(ChildExit::terminated()),
                    force_error: false,
                    terminate_error: true,
                    signals: Arc::clone(&signals),
                },
                signals,
            )
        }
    }

    impl ManagedChild for FakeChild {
        fn pid(&self) -> Option<u32> {
            Some(self.pid)
        }

        fn try_wait(&mut self) -> Result<Option<ChildExit>, AgentError> {
            let exit = self.exit.take();
            if exit.is_some() {
                self.signals
                    .lock()
                    .expect("signals lock")
                    .reap_order
                    .push("reap");
            }
            Ok(exit)
        }

        fn terminate(&mut self) -> Result<(), AgentError> {
            self.signals.lock().expect("signals lock").terminate_calls += 1;
            if self.terminate_error {
                return Err(AgentError::StopFailed);
            }
            self.exit = self.graceful_exit;
            Ok(())
        }

        fn force_kill(&mut self) -> Result<(), AgentError> {
            self.signals.lock().expect("signals lock").force_kill_calls += 1;
            if self.force_error {
                return Err(AgentError::StopFailed);
            }
            self.exit = self.force_exit;
            Ok(())
        }

        fn cleanup_after_reap(&mut self) {
            self.signals
                .lock()
                .expect("signals lock")
                .reap_order
                .push("cleanup");
        }
    }

    impl ChildFactory for FakeFactory {
        fn spawn(&self, spec: &ChildSpec) -> Result<Box<dyn ManagedChild>, AgentError> {
            self.spawned.lock().expect("spawn lock").push(spec.clone());
            match self.outcomes.lock().expect("outcome lock").pop_front() {
                Some(FakeSpawnOutcome::Child(child)) => Ok(Box::new(child)),
                Some(FakeSpawnOutcome::Error) | None => Err(AgentError::SpawnFailed),
            }
        }
    }

    fn config() -> HostAgentConfig {
        HostAgentConfig::new(
            ChildSpec::new("openstream-ffmpeg-host")
                .expect("program")
                .arg("--test"),
        )
        .expect("config")
        .with_startup_grace(Duration::from_millis(10))
        .with_policy(super::ChildPolicy {
            max_restarts: 2,
            base_backoff_ms: 20,
            max_backoff_ms: 100,
            reset_after_ms: 100,
        })
        .expect("valid config")
    }

    fn instant() -> Instant {
        Instant::now()
    }

    #[test]
    fn start_is_idempotent_and_becomes_ready_after_grace() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(7)));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory.clone()).expect("agent");

        assert_eq!(
            agent.start(now).expect("start"),
            vec![HostAgentEvent::Started { pid: Some(7) }]
        );
        assert!(agent.start(now).expect("idempotent start").is_empty());
        assert_eq!(agent.health(now).state, ChildState::Starting);
        assert_eq!(
            agent.tick(now + Duration::from_millis(10)).expect("tick"),
            vec![HostAgentEvent::Ready]
        );
        assert_eq!(agent.health(now).state, ChildState::Ready);
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);
    }

    /// A private runtime directory and heartbeat path for one test.
    ///
    /// The suffix comes from a counter rather than a clock. These tests run
    /// concurrently and each one deletes its own directory at the end, so two
    /// of them sharing a name means one removes the other's heartbeat file
    /// mid-run. A counter cannot collide; an elapsed-time reading taken
    /// immediately after `Instant::now()` is always zero and always does.
    fn heartbeat_config() -> (HostAgentConfig, PathBuf, PathBuf) {
        static NEXT_HEARTBEAT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "openstream-heartbeat-test-{}-{}",
            std::process::id(),
            NEXT_HEARTBEAT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).expect("heartbeat test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private heartbeat directory");
        }
        let path = directory.join("frames");
        let config = config()
            .with_frame_heartbeat_file(&path)
            .expect("heartbeat config");
        (config, path, directory)
    }

    fn publish_frames(path: &PathBuf, frames: u64) {
        // Deliberately the legacy bare-count format, so the existing suite
        // keeps proving an older host binary is still read correctly.
        fs::write(path, format!("{frames}\n")).expect("publish heartbeat");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private heartbeat file");
        }
    }

    /// Write raw bytes as the heartbeat, private-mode included.
    ///
    /// The permissions matter to the test, not just to the product: a file
    /// left at the default mode is rejected before it ever reaches the
    /// parser, so a malformed-content test that skipped this would pass
    /// without exercising the parse path at all.
    fn publish_raw(path: &PathBuf, contents: &str) {
        fs::write(path, contents).expect("publish heartbeat");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private heartbeat file");
        }
    }

    fn publish_phase(path: &PathBuf, phase: HostPhase, frames: u64) {
        fs::write(path, host_heartbeat::render(phase, frames)).expect("publish heartbeat");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private heartbeat file");
        }
    }

    /// The two pid values `kill` reserves must never be treated as a child's
    /// process group.
    ///
    /// Asserted by inspection only. A test that actually called the helper
    /// with one of these would signal every process this user is running.
    #[cfg(unix)]
    #[test]
    fn the_agent_never_signals_a_reserved_process_group() {
        assert!(!super::is_signallable_group(-1));
        assert!(!super::is_signallable_group(0));
        assert!(
            !super::is_signallable_group(1),
            "negating 1 is kill's every-process wildcard, not process group 1"
        );
        assert!(super::is_signallable_group(2));

        // Signal 0 delivers nothing, so these calls are inert even if the
        // guard were wrong about the value -- but the guard is what is being
        // asserted, and it rejects before reaching `kill`.
        assert_eq!(
            super::signal_process_group(Some(u32::MAX), 0),
            Err(AgentError::StopFailed),
            "a pid that does not fit an i32 must be refused, not truncated"
        );
        assert_eq!(
            super::signal_process_group(Some(1), 0),
            Err(AgentError::StopFailed)
        );
        assert_eq!(
            super::signal_process_group(None, 0),
            Err(AgentError::StopFailed)
        );
    }

    /// A host that claims to be streaming owes a first frame, on a clock.
    ///
    /// The phase relaxes the frame deadline for hosts that have not claimed
    /// to be streaming. Without a bound that relaxation leaks into the
    /// streaming phase: a counter still at zero cannot have "stopped
    /// advancing", so a capture or encoder that never produces its first
    /// frame would read as healthy forever -- a dead pipeline behind a live
    /// process, which is what this heartbeat exists to catch.
    #[test]
    fn a_streaming_host_that_never_produces_a_first_frame_is_stopped() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(26)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // Fresh heartbeats throughout: the publisher thread is alive and the
        // host keeps insisting it is streaming. Only the frames never come.
        publish_phase(&path, HostPhase::Streaming, 0);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        assert_eq!(
            agent.health(now).state,
            ChildState::Ready,
            "the first frame gets a grace period, not an instant verdict"
        );

        // Still inside the deadline.
        publish_phase(&path, HostPhase::Streaming, 0);
        let inside = Duration::from_millis(20) + FIRST_FRAME_DEADLINE / 2;
        agent.tick(now + inside).expect("within the deadline");
        assert_eq!(agent.health(now + inside).state, ChildState::Ready);

        // Past it, strikes start accumulating.
        let mut elapsed = Duration::from_millis(20) + FIRST_FRAME_DEADLINE;
        for strike in 1..FRAME_LIVENESS_STRIKES {
            publish_phase(&path, HostPhase::Streaming, 0);
            elapsed += Duration::from_secs(1);
            agent.tick(now + elapsed).expect("overdue observation");
            assert_eq!(
                agent.health(now + elapsed).state,
                ChildState::Ready,
                "stopped after only {strike} overdue observation(s)"
            );
        }
        publish_phase(&path, HostPhase::Streaming, 0);
        elapsed += Duration::from_secs(1);
        agent
            .tick(now + elapsed)
            .expect("final overdue observation");
        assert_ne!(
            agent.health(now + elapsed).state,
            ChildState::Ready,
            "a streaming host that never produced a frame must be stopped"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// The deadline is measured from entering the streaming phase, not from
    /// process start.
    ///
    /// A peer can arrive hours after the host does. Measuring from start
    /// would put every such host past its first-frame deadline before capture
    /// had been asked to produce anything.
    #[test]
    fn the_first_frame_deadline_runs_from_the_phase_not_from_process_start() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(27)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // A long wait for a peer, far beyond the first-frame deadline.
        let mut elapsed = Duration::from_millis(20);
        for _ in 0..8 {
            publish_phase(&path, HostPhase::WaitingForPeer, 0);
            agent.tick(now + elapsed).expect("waiting observation");
            elapsed += FIRST_FRAME_DEADLINE;
        }
        assert_eq!(agent.health(now + elapsed).state, ChildState::Ready);

        // The peer finally arrives and the host starts streaming. Its first
        // frame is late but inside the deadline, measured from here.
        publish_phase(&path, HostPhase::Streaming, 0);
        agent.tick(now + elapsed).expect("streaming begins");
        elapsed += FIRST_FRAME_DEADLINE / 2;
        publish_phase(&path, HostPhase::Streaming, 1);
        agent.tick(now + elapsed).expect("first frame arrives");
        assert_eq!(
            agent.health(now + elapsed).state,
            ChildState::Ready,
            "the deadline must not have been spent while waiting for a peer"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// Garbage written frequently must not outrank silence.
    ///
    /// A parse failure used to keep the file's fresh age and invent a phase
    /// for it, which made a host writing junk four times a second look
    /// healthier than one writing nothing at all. An unreadable line is the
    /// absence of a report and has to be judged as one.
    #[test]
    fn a_fresh_but_unreadable_heartbeat_is_not_evidence_of_health() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(28)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // Rewritten on every tick, so the file is always fresh.
        let mut elapsed = Duration::from_millis(20);
        for _ in 0..FRAME_LIVENESS_STRIKES {
            publish_raw(&path, "not-a-heartbeat\n");
            agent.tick(now + elapsed).expect("unreadable observation");
            elapsed += Duration::from_millis(10);
        }
        assert_ne!(
            agent.health(now + elapsed).state,
            ChildState::Ready,
            "a host that never publishes a readable heartbeat is not ready"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// A host that was streaming and then starts writing garbage is stopped.
    #[test]
    fn a_ready_host_that_starts_writing_garbage_is_stopped() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(29)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_phase(&path, HostPhase::Streaming, 1);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        assert_eq!(agent.health(now).state, ChildState::Ready);

        let mut elapsed = Duration::from_millis(30);
        for strike in 1..FRAME_LIVENESS_STRIKES {
            publish_raw(&path, "streaming not-a-number\n");
            agent.tick(now + elapsed).expect("unreadable observation");
            assert_eq!(
                agent.health(now + elapsed).state,
                ChildState::Ready,
                "stopped after only {strike} unreadable observation(s)"
            );
            elapsed += Duration::from_millis(10);
        }
        publish_raw(&path, "streaming not-a-number\n");
        agent
            .tick(now + elapsed)
            .expect("final unreadable observation");
        assert_ne!(agent.health(now + elapsed).state, ChildState::Ready);
        let _ = fs::remove_dir_all(&directory);
    }

    /// The reported blocker: a host with no client yet must not be restarted.
    ///
    /// The establishment protocol deliberately lets a host wait for a peer
    /// indefinitely -- that is the whole point of starting a host before the
    /// person who will connect to it. The supervisor used to require
    /// `FrameLiveness::Live`, which no waiting host can produce, so it struck
    /// once per tick and killed the child the moment the startup grace ran
    /// out. This drives well past that deadline.
    #[test]
    fn a_host_waiting_for_a_peer_stays_ready_indefinitely() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(21)));
        let (config, path, directory) = heartbeat_config();
        let grace = config.startup_grace_ms;
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // Zero frames, forever, because there is nobody to send them to.
        publish_phase(&path, HostPhase::WaitingForPeer, 0);
        assert_eq!(
            agent
                .tick(now + Duration::from_millis(20))
                .expect("becomes ready"),
            vec![HostAgentEvent::Ready],
            "a host that is up and reporting is ready, peer or no peer"
        );

        for step in 1..=20_u64 {
            publish_phase(&path, HostPhase::WaitingForPeer, 0);
            let elapsed = Duration::from_millis(20 + step * (grace / 2 + 1));
            agent.tick(now + elapsed).expect("waiting observation");
            let health = agent.health(now + elapsed);
            assert_eq!(
                health.state,
                ChildState::Ready,
                "a host waiting for a peer must not be restarted at step {step}, \
                 well past the {grace}ms startup grace"
            );
            assert_eq!(health.frame_liveness, FrameLiveness::Waiting);
        }
        let _ = fs::remove_dir_all(&directory);
    }

    /// Waiting for a peer is healthy; ceasing to report is not.
    ///
    /// The phase must not become a way for a wedged host to excuse itself. A
    /// process that stops writing the file entirely is stale whatever it last
    /// claimed to be doing.
    #[test]
    fn a_host_that_stops_reporting_is_stale_even_while_waiting_for_a_peer() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(22)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_phase(&path, HostPhase::WaitingForPeer, 0);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        assert_eq!(agent.health(now).state, ChildState::Ready);

        // The host process wedges: the file stops being refreshed.
        fs::remove_file(&path).expect("remove heartbeat");
        for strike in 1..FRAME_LIVENESS_STRIKES {
            agent
                .tick(now + Duration::from_millis(30 + u64::from(strike) * 10))
                .expect("stale observation");
            assert_eq!(
                agent.health(now).state,
                ChildState::Ready,
                "stopped after only {strike} silent observation(s)"
            );
        }
        agent
            .tick(now + Duration::from_millis(1_000))
            .expect("final silent observation");
        assert_ne!(
            agent.health(now).state,
            ChildState::Ready,
            "a host that stopped reporting is not healthy just because it was waiting"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// Establishment is its own phase, and it is healthy.
    #[test]
    fn a_negotiating_host_is_healthy_and_reported_as_negotiating() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(23)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_phase(&path, HostPhase::Negotiating, 0);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        let health = agent.health(now);
        assert_eq!(health.state, ChildState::Ready);
        assert_eq!(health.frame_liveness, FrameLiveness::Negotiating);
        let _ = fs::remove_dir_all(&directory);
    }

    /// Frame enforcement still applies once the host says it is streaming.
    ///
    /// The phase relaxes the deadline for hosts that have not claimed to be
    /// streaming. It must not relax it for one that has -- that would undo
    /// the stall detection this heartbeat exists for.
    #[test]
    fn a_streaming_host_with_a_frozen_counter_is_still_stopped() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(24)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_phase(&path, HostPhase::Streaming, 1);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        assert_eq!(agent.health(now).state, ChildState::Ready);

        // The file stays fresh -- the publisher thread is alive -- while the
        // counter never moves again. This is a dead capture behind a live
        // process, which is exactly what must still be caught. Ticking stops
        // at the transition so the fake factory is never asked for a
        // replacement child it was not given.
        for strike in 1..FRAME_LIVENESS_STRIKES {
            publish_phase(&path, HostPhase::Streaming, 1);
            agent
                .tick(now + Duration::from_millis(20 + u64::from(strike) * 5_000))
                .expect("frozen observation");
            assert_eq!(
                agent.health(now).state,
                ChildState::Ready,
                "stopped after only {strike} frozen observation(s)"
            );
        }
        publish_phase(&path, HostPhase::Streaming, 1);
        agent
            .tick(now + Duration::from_millis(60_000))
            .expect("final frozen observation");
        assert_ne!(
            agent.health(now).state,
            ChildState::Ready,
            "a streaming host whose counter stopped must still be stopped"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// A host that reaches streaming and then goes back to waiting for a peer
    /// is not stalling; it lost its client.
    #[test]
    fn returning_to_waiting_after_a_peer_leaves_is_not_a_stall() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(25)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_phase(&path, HostPhase::Streaming, 5);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");

        // The peer disconnects. The counter is frozen at its last value, and
        // under a phase-blind rule that alone would restart the host.
        for step in 1..=8_u64 {
            publish_phase(&path, HostPhase::WaitingForPeer, 5);
            let elapsed = Duration::from_millis(20 + step * 5_000);
            agent.tick(now + elapsed).expect("post-peer observation");
            assert_eq!(
                agent.health(now + elapsed).state,
                ChildState::Ready,
                "losing a peer is not a capture fault (step {step})"
            );
        }
        let _ = fs::remove_dir_all(&directory);
    }

    /// A live process that never publishes a heartbeat at all is not a ready
    /// host.
    ///
    /// Note what this does *not* say. It is about a host that reports
    /// nothing, not a host that reports no frames -- a host waiting for a
    /// peer legitimately has no frames and is covered by
    /// `a_host_waiting_for_a_peer_stays_ready_indefinitely`.
    #[test]
    fn a_child_that_publishes_no_heartbeat_never_reaches_ready() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(11)));
        let (config, _path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // Past the startup grace with no heartbeat at all: the process is
        // alive, and that is explicitly not evidence of a working capture.
        agent
            .tick(now + Duration::from_millis(50))
            .expect("liveness tick");
        assert_ne!(agent.health(now).state, ChildState::Ready);
        let _ = fs::remove_dir_all(&directory);
    }

    /// One unreadable observation must not restart a working stream.
    ///
    /// The heartbeat is a file written by another process. A single read can
    /// come back stale for reasons that have nothing to do with capture, and
    /// tearing down a live session for one of them is worse than noticing a
    /// real stall a tick later.
    #[test]
    fn a_ready_child_survives_a_single_stale_heartbeat_observation() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(12)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_frames(&path, 1);
        assert_eq!(
            agent
                .tick(now + Duration::from_millis(20))
                .expect("becomes ready"),
            vec![HostAgentEvent::Ready]
        );

        // Remove the file to simulate the worst observation available: no
        // count at all.
        fs::remove_file(&path).expect("remove heartbeat");
        agent
            .tick(now + Duration::from_millis(30))
            .expect("first stale observation");
        assert_eq!(
            agent.health(now).state,
            ChildState::Ready,
            "one stale read must not stop a ready child"
        );

        // A fresh count clears the strike, so a recovered stall leaves no
        // residue behind.
        publish_frames(&path, 2);
        agent
            .tick(now + Duration::from_millis(40))
            .expect("recovered observation");
        assert_eq!(agent.health(now).state, ChildState::Ready);
        fs::remove_file(&path).expect("remove heartbeat again");
        agent
            .tick(now + Duration::from_millis(50))
            .expect("stale after recovery");
        assert_eq!(
            agent.health(now).state,
            ChildState::Ready,
            "a recovered stall must not carry its strike forward"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// A republished-but-unchanging count is a stall, however fresh the file.
    ///
    /// The publisher rewrites the heartbeat on a timer whether or not the
    /// encoder produced anything, so a fresh file proves only that the child
    /// process is alive. Treating that as frame liveness would report a host
    /// as healthy forever after its very first frame, which is precisely the
    /// failure this heartbeat exists to catch.
    #[test]
    fn a_frozen_frame_counter_is_a_stall_even_while_the_file_stays_fresh() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(14)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        // One frame, then the encoder stops. The publisher keeps going.
        publish_frames(&path, 1);
        assert_eq!(
            agent
                .tick(now + Duration::from_millis(20))
                .expect("becomes ready"),
            vec![HostAgentEvent::Ready]
        );
        assert_eq!(agent.health(now).state, ChildState::Ready);

        // Republish the same count, keeping the file's mtime fresh, and let
        // the clock pass the frame-liveness timeout.
        let stalled_from = now + super::FRAME_HEARTBEAT_TIMEOUT + Duration::from_millis(100);
        for strike in 0..super::FRAME_LIVENESS_STRIKES {
            publish_frames(&path, 1);
            agent
                .tick(stalled_from + Duration::from_millis(u64::from(strike)))
                .expect("stalled observation");
        }
        assert_ne!(
            agent.health(stalled_from).state,
            ChildState::Ready,
            "a fresh heartbeat file carrying a frozen count is still a stall"
        );
        assert_eq!(
            agent.health(stalled_from).last_error,
            Some(HostErrorCode::FrameLivenessTimeout)
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// A counter that keeps advancing keeps the child ready.
    #[test]
    fn an_advancing_frame_counter_keeps_the_child_ready() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(15)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");

        publish_frames(&path, 1);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        for step in 1..=6_u64 {
            publish_frames(&path, 1 + step);
            agent
                .tick(now + Duration::from_millis(20 + step * 1_000))
                .expect("advancing observation");
            assert_eq!(
                agent.health(now).state,
                ChildState::Ready,
                "an advancing counter must keep the child ready at step {step}"
            );
        }
        let _ = fs::remove_dir_all(&directory);
    }

    /// A real stall still stops the child, just not on the first read.
    #[test]
    fn a_ready_child_stops_after_consecutive_stale_heartbeats() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(13)));
        let (config, path, directory) = heartbeat_config();
        let now = instant();
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");
        agent.start(now).expect("start");
        publish_frames(&path, 1);
        agent
            .tick(now + Duration::from_millis(20))
            .expect("becomes ready");
        assert_eq!(agent.health(now).state, ChildState::Ready);

        fs::remove_file(&path).expect("remove heartbeat");
        for strike in 1..super::FRAME_LIVENESS_STRIKES {
            agent
                .tick(now + Duration::from_millis(30 + u64::from(strike)))
                .expect("stale observation");
            assert_eq!(
                agent.health(now).state,
                ChildState::Ready,
                "stopped after only {strike} stale observation(s)"
            );
        }
        agent
            .tick(now + Duration::from_millis(60))
            .expect("final stale observation");
        assert_ne!(
            agent.health(now).state,
            ChildState::Ready,
            "a sustained stall must still stop the child"
        );
        assert_eq!(
            agent.health(now).last_error,
            Some(HostErrorCode::FrameLivenessTimeout)
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn failed_child_uses_bounded_backoff_and_restarts() {
        let factory = FakeFactory::default();
        {
            let mut outcomes = factory.outcomes.lock().expect("outcome lock");
            outcomes.push_back(FakeSpawnOutcome::Child(FakeChild {
                pid: 1,
                exit: Some(ChildExit::code(9)),
                ..FakeChild::running(1)
            }));
            outcomes.push_back(FakeSpawnOutcome::Child(FakeChild::running(2)));
        }
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory.clone()).expect("agent");
        agent.start(now).expect("start");
        let events = agent.tick(now).expect("failed child tick");
        assert_eq!(
            events[0],
            HostAgentEvent::ChildExited {
                reason: ChildExitReason::ExitCode(9)
            }
        );
        assert_eq!(
            events[1],
            HostAgentEvent::RestartScheduled {
                delay_ms: 20,
                attempt: 1
            }
        );
        assert_eq!(agent.health(now).state, ChildState::Backoff);
        assert!(
            agent
                .tick(now + Duration::from_millis(19))
                .expect("early tick")
                .is_empty()
        );
        assert_eq!(
            agent
                .tick(now + Duration::from_millis(20))
                .expect("restart tick"),
            vec![HostAgentEvent::Started { pid: Some(2) }]
        );
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 2);
    }

    #[test]
    fn healthy_lifetime_cycles_do_not_exhaust_the_restart_budget() {
        // A host that never crashes and only ever ends sessions by reaching
        // its configured lifetime cap must keep coming back. `tick` routes a
        // stopping child to `tick_stopping`, which previously skipped the
        // crash-forgiveness reset that `handle_exit` performs, so the restart
        // budget was spent once per healthy session and the agent wedged in
        // `Failed` on the cycle after `max_restarts`.
        let factory = FakeFactory::default();
        {
            let mut outcomes = factory.outcomes.lock().expect("outcome lock");
            for pid in 0..6 {
                outcomes.push_back(FakeSpawnOutcome::Child(FakeChild::exits_after_graceful(
                    pid,
                )));
            }
        }
        let lifetime = Duration::from_millis(200);
        let config = config()
            .with_max_child_lifetime(Some(lifetime))
            .expect("lifetime");
        let mut agent = HostAgent::with_factory(config, factory).expect("agent");

        let mut now = instant();
        agent.start(now).expect("start");
        // `max_restarts` is 2 here, so five healthy cycles is well past the
        // point the old behaviour failed at.
        for cycle in 0..5 {
            now += lifetime + Duration::from_millis(1);
            agent.tick(now).expect("lifetime tick");
            now += Duration::from_millis(1);
            agent.tick(now).expect("stopping tick");
            assert_ne!(
                agent.health(now).state,
                ChildState::Failed,
                "agent wedged in Failed on healthy lifetime cycle {cycle}"
            );
            now += Duration::from_millis(200);
            agent.tick(now).expect("restart tick");
        }
        assert_ne!(agent.health(now).state, ChildState::Failed);
    }

    #[test]
    fn spawn_failure_enters_bounded_backoff() {
        let factory = FakeFactory::default();
        {
            let mut outcomes = factory.outcomes.lock().expect("outcome lock");
            outcomes.push_back(FakeSpawnOutcome::Error);
            outcomes.push_back(FakeSpawnOutcome::Child(FakeChild::running(8)));
        }
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory.clone()).expect("agent");
        assert_eq!(agent.start(now), Err(AgentError::SpawnFailed));
        let health = agent.health(now);
        assert_eq!(health.state, ChildState::Backoff);
        assert_eq!(health.next_restart_in_ms, Some(20));
        assert_eq!(
            agent.tick(now + Duration::from_millis(20)).expect("retry"),
            vec![HostAgentEvent::Started { pid: Some(8) }]
        );
    }

    #[test]
    fn stop_waits_for_child_reap_before_reporting_stopped() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::exits_after_graceful(1)));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory.clone()).expect("agent");
        agent.start(now).expect("start");
        assert!(agent.stop(now).expect("stop").is_empty());
        assert_eq!(agent.health(now).pid, Some(1));
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert!(
            agent
                .tick(now + Duration::from_millis(1))
                .expect("reap tick")
                .contains(&HostAgentEvent::Stopped)
        );
        assert!(agent.stop(now).expect("idempotent stop").is_empty());
        agent
            .tick(now + Duration::from_secs(1))
            .expect("post-stop tick");
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);
        assert_eq!(agent.health(now).state, ChildState::Stopped);
    }

    #[test]
    fn restart_limit_is_reported_as_typed_failure() {
        let factory = FakeFactory::default();
        {
            let mut outcomes = factory.outcomes.lock().expect("outcome lock");
            for pid in 1..=3 {
                outcomes.push_back(FakeSpawnOutcome::Child(FakeChild {
                    pid,
                    exit: Some(ChildExit::code(pid as i32)),
                    ..FakeChild::running(pid)
                }));
            }
        }
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");
        agent.tick(now).expect("first failure");
        agent
            .tick(now + Duration::from_millis(20))
            .expect("first restart");
        let events = agent
            .tick(now + Duration::from_millis(20))
            .expect("second failure");
        assert_eq!(
            events[1],
            HostAgentEvent::RestartScheduled {
                delay_ms: 40,
                attempt: 2
            }
        );
        agent
            .tick(now + Duration::from_millis(60))
            .expect("second restart");
        let events = agent
            .tick(now + Duration::from_millis(60))
            .expect("third failure");
        assert!(events.contains(&HostAgentEvent::Failed {
            code: HostErrorCode::RestartLimit
        }));
        assert_eq!(agent.health(now).state, ChildState::Failed);
    }

    #[test]
    fn lifetime_exceeded_is_classified_and_restarted() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::stubborn(3).0));
        let now = instant();
        let cfg = config()
            .with_max_child_lifetime(Some(Duration::from_millis(5)))
            .expect("lifetime");
        let mut agent = HostAgent::with_factory(cfg, factory).expect("agent");
        agent.start(now).expect("start");
        let events = agent
            .tick(now + Duration::from_millis(5))
            .expect("lifetime tick");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, HostAgentEvent::RestartScheduled { .. }))
        );
        assert_eq!(agent.health(now).pid, Some(3));
    }

    #[test]
    fn prompt_graceful_termination_is_reaped_before_stopped() {
        let factory = FakeFactory::default();
        let child = FakeChild::exits_after_graceful(9);
        let signals = Arc::clone(&child.signals);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");

        assert!(agent.stop(now).expect("stop").is_empty());
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert!(
            agent
                .tick(now + Duration::from_millis(1))
                .expect("reap")
                .contains(&HostAgentEvent::Stopped)
        );
        let signals = signals.lock().expect("signals lock");
        assert_eq!(signals.terminate_calls, 1);
        assert_eq!(signals.force_kill_calls, 0);
        assert_eq!(signals.reap_order, ["reap", "cleanup"]);
    }

    #[test]
    fn ignored_graceful_termination_is_force_killed_then_reaped() {
        let factory = FakeFactory::default();
        let (child, signals) = FakeChild::stubborn(10);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");
        agent.stop(now).expect("stop");

        agent
            .tick(now + Duration::from_millis(1_999))
            .expect("grace period tick");
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 0);

        assert!(
            agent
                .tick(now + Duration::from_secs(2))
                .expect("force-kill tick")
                .is_empty()
        );
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert_eq!(agent.health(now).pid, Some(10));
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 1);

        assert!(
            agent
                .tick(now + Duration::from_secs(2) + Duration::from_millis(1))
                .expect("reap after force-kill")
                .contains(&HostAgentEvent::Stopped)
        );
        assert_eq!(agent.health(now).state, ChildState::Stopped);
    }

    #[test]
    fn force_kill_failure_keeps_child_owned_and_reports_typed_error() {
        let factory = FakeFactory::default();
        let (child, signals) = FakeChild::force_kill_fails(11);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");
        agent.stop(now).expect("stop");

        assert_eq!(
            agent.tick(now + Duration::from_secs(2)),
            Err(AgentError::StopFailed)
        );
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert_eq!(agent.health(now).pid, Some(11));
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 1);
    }

    #[test]
    fn lifetime_restart_waits_until_force_kill_is_reaped() {
        let factory = FakeFactory::default();
        let (child, signals) = FakeChild::stubborn(12);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(13)));
        let now = instant();
        let cfg = config()
            .with_max_child_lifetime(Some(Duration::from_millis(5)))
            .expect("lifetime");
        let mut agent = HostAgent::with_factory(cfg, factory.clone()).expect("agent");
        agent.start(now).expect("start");

        assert!(
            !agent
                .tick(now + Duration::from_millis(5))
                .expect("lifetime request")
                .iter()
                .any(|event| matches!(event, HostAgentEvent::RestartScheduled { .. }))
        );
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);

        agent
            .tick(now + Duration::from_secs(2) + Duration::from_millis(5))
            .expect("force-kill lifetime child");
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 1);
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);

        let events = agent
            .tick(now + Duration::from_secs(2) + Duration::from_millis(6))
            .expect("reap lifetime child");
        assert!(events.contains(&HostAgentEvent::ChildExited {
            reason: ChildExitReason::LifetimeExceeded
        }));
        assert!(events.contains(&HostAgentEvent::RestartScheduled {
            delay_ms: 20,
            attempt: 1
        }));
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);

        agent
            .tick(now + Duration::from_secs(2) + Duration::from_millis(26))
            .expect("replacement spawn");
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 2);
    }

    #[test]
    fn shutdown_during_lifetime_stop_reaps_without_scheduling_replacement() {
        let factory = FakeFactory::default();
        let child = FakeChild::exits_after_graceful(16);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild::running(17)));
        let now = instant();
        let cfg = config()
            .with_max_child_lifetime(Some(Duration::from_millis(5)))
            .expect("lifetime");
        let mut agent = HostAgent::with_factory(cfg, factory.clone()).expect("agent");
        agent.start(now).expect("start");
        agent
            .tick(now + Duration::from_millis(5))
            .expect("lifetime stop");

        agent
            .stop(now + Duration::from_millis(5))
            .expect("shutdown");
        let events = agent
            .tick(now + Duration::from_millis(6))
            .expect("reap after shutdown");

        assert!(events.contains(&HostAgentEvent::Stopped));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, HostAgentEvent::RestartScheduled { .. }))
        );
        assert_eq!(agent.health(now).state, ChildState::Stopped);
        agent
            .tick(now + Duration::from_secs(1))
            .expect("post-shutdown tick");
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);
    }

    #[test]
    fn failed_graceful_stop_enters_immediate_escalation_and_retains_child() {
        let factory = FakeFactory::default();
        let (child, signals) = FakeChild::terminate_fails(18);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");

        assert_eq!(agent.stop(now), Err(AgentError::StopFailed));
        assert_eq!(agent.health(now).state, ChildState::Stopping);
        assert_eq!(agent.health(now).pid, Some(18));
        assert_eq!(
            agent.health(now).last_error,
            Some(HostErrorCode::StopFailed)
        );

        agent.tick(now).expect("immediate force kill");
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 1);
        assert!(
            agent
                .tick(now + Duration::from_millis(1))
                .expect("reap")
                .contains(&HostAgentEvent::Stopped)
        );
    }

    #[test]
    fn failed_lifetime_terminate_enters_immediate_escalation_and_retains_child() {
        let factory = FakeFactory::default();
        let (child, signals) = FakeChild::terminate_fails(19);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let cfg = config()
            .with_max_child_lifetime(Some(Duration::from_millis(5)))
            .expect("lifetime");
        let mut agent = HostAgent::with_factory(cfg, factory).expect("agent");
        agent.start(now).expect("start");

        assert_eq!(
            agent.tick(now + Duration::from_millis(5)),
            Err(AgentError::StopFailed)
        );
        assert_eq!(agent.health(now).state, ChildState::Stopping);
        assert_eq!(agent.health(now).pid, Some(19));
        assert_eq!(
            agent.health(now).last_error,
            Some(HostErrorCode::StopFailed)
        );

        agent
            .tick(now + Duration::from_millis(5))
            .expect("immediate force kill");
        assert_eq!(signals.lock().expect("signals lock").force_kill_calls, 1);
    }

    #[test]
    fn shutdown_during_restart_backoff_cancels_without_child() {
        let factory = FakeFactory::default();
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(FakeChild {
                exit: Some(ChildExit::code(1)),
                ..FakeChild::running(14)
            }));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory.clone()).expect("agent");
        agent.start(now).expect("start");
        agent.tick(now).expect("child exit");
        assert_eq!(agent.health(now).state, ChildState::Backoff);

        assert_eq!(
            agent.stop(now).expect("shutdown").as_slice(),
            [HostAgentEvent::Stopped]
        );
        assert_eq!(agent.health(now).state, ChildState::Stopped);
        agent
            .tick(now + Duration::from_secs(1))
            .expect("post-shutdown tick");
        assert_eq!(factory.spawned.lock().expect("spawn lock").len(), 1);
    }

    #[test]
    fn shutdown_while_starting_waits_for_reap_before_stopped() {
        let factory = FakeFactory::default();
        let child = FakeChild::exits_after_graceful(15);
        factory
            .outcomes
            .lock()
            .expect("outcome lock")
            .push_back(FakeSpawnOutcome::Child(child));
        let now = instant();
        let mut agent = HostAgent::with_factory(config(), factory).expect("agent");
        agent.start(now).expect("start");
        assert_eq!(agent.health(now).state, ChildState::Starting);

        assert!(agent.stop(now).expect("shutdown").is_empty());
        assert_eq!(format!("{:?}", agent.health(now).state), "Stopping");
        assert!(
            agent
                .tick(now + Duration::from_millis(1))
                .expect("reap starting child")
                .contains(&HostAgentEvent::Stopped)
        );
    }

    #[test]
    fn settings_projection_never_places_pairing_or_token_in_child_spec() {
        let settings = default_config();
        let cfg =
            HostAgentConfig::from_settings(&settings, "openstream-ffmpeg-host").expect("config");
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("PAIRING_JSON"));
        assert!(!debug.contains("token-sentinel"));
        assert!(
            cfg.child()
                .args()
                .iter()
                .all(|arg| arg != &OsString::from("PAIRING_JSON"))
        );
        assert!(
            !cfg.child()
                .environment()
                .contains_key("OPENSTREAM_CAPTURE_BACKEND")
        );
    }

    #[test]
    fn credential_shaped_argument_is_rejected() {
        assert!(
            ChildSpec::new("host")
                .expect("program")
                .arg("--pairing-json")
                .validate()
                .is_err()
        );
    }

    fn private_pairing_file(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openstream-host-agent-lib-{label}-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, b"{}\n").expect("write pairing fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("protect pairing fixture");
        }
        path
    }

    #[test]
    fn dedicated_pairing_file_is_redacted_from_configuration_debug() {
        let path = private_pairing_file("debug-redaction");
        let config = HostAgentConfig::from_settings(&default_config(), "host")
            .expect("config")
            .with_pairing_file(&path)
            .expect("validated pairing file");
        let debug = format!("{config:?}");
        assert!(debug.contains("OPENSTREAM_PAIRING_FILE"));
        assert!(!debug.contains(&path.to_string_lossy().into_owned()));
        fs::remove_file(path).expect("remove pairing fixture");
    }

    #[test]
    fn pairing_file_errors_do_not_echo_path() {
        let path = std::env::temp_dir().join("openstream-pairing-secret-sentinel");
        let config = HostAgentConfig::from_settings(&default_config(), "host").expect("config");
        let error = config
            .with_pairing_file(&path)
            .expect_err("missing pairing file must be rejected");
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains(path.to_string_lossy().as_ref()));
        assert!(!display.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn raw_pairing_json_runtime_environment_is_rejected() {
        let result = HostAgentConfig::from_settings(&default_config(), "host")
            .expect("config")
            .with_runtime_env("OPENSTREAM_PAIRING_JSON", "raw-token-sentinel");

        assert!(matches!(result, Err(AgentError::InvalidConfig)));
    }

    #[test]
    fn generic_runtime_environment_rejects_pairing_file() {
        for key in [
            "OPENSTREAM_PAIRING_JSON",
            "OPENSTREAM_PAIRING_FILE",
            "openstream_pairing_json",
            "openstream_pairing_file",
        ] {
            let child = ChildSpec::new("host")
                .expect("child spec")
                .env(key, "/private/pairing.json");
            assert!(matches!(child, Err(AgentError::InvalidConfig)), "{key}");

            let config = HostAgentConfig::from_settings(&default_config(), "host")
                .expect("config")
                .with_runtime_env(key, "/private/pairing.json");
            assert!(matches!(config, Err(AgentError::InvalidConfig)), "{key}");
        }
    }

    #[test]
    fn persistent_child_removes_inherited_pairing_variables_then_adds_validated_file() {
        let path = private_pairing_file("spawn-boundary");
        let config = HostAgentConfig::from_settings(&default_config(), "host")
            .expect("config")
            .with_pairing_file(&path)
            .expect("validated pairing file");
        let mut command = tokio::process::Command::new("host");

        configure_child_environment(&mut command, config.child());

        let configured = command
            .as_std()
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(OsString::from)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            configured.get(std::ffi::OsStr::new("OPENSTREAM_PAIRING_JSON")),
            Some(&None)
        );
        assert_eq!(
            configured.get(std::ffi::OsStr::new("OPENSTREAM_PAIRING_FILE")),
            Some(&Some(path.as_os_str().to_owned()))
        );
        fs::remove_file(path).expect("remove pairing fixture");
    }

    #[test]
    fn dedicated_pairing_file_rejects_relative_directory_and_oversized_paths() {
        let base = HostAgentConfig::from_settings(&default_config(), "host").expect("config");
        assert!(matches!(
            base.clone().with_pairing_file("relative-pairing.json"),
            Err(AgentError::InvalidConfig)
        ));
        assert!(matches!(
            base.clone().with_pairing_file(std::env::temp_dir()),
            Err(AgentError::InvalidConfig)
        ));

        let path = private_pairing_file("oversized");
        fs::write(&path, vec![b'x'; 64 * 1024 + 1]).expect("write oversized fixture");
        assert!(matches!(
            base.with_pairing_file(&path),
            Err(AgentError::InvalidConfig)
        ));
        fs::remove_file(path).expect("remove pairing fixture");
    }

    #[cfg(unix)]
    #[test]
    fn dedicated_pairing_file_rejects_symlink_and_insecure_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let base = HostAgentConfig::from_settings(&default_config(), "host").expect("config");
        let target = private_pairing_file("symlink-target");
        let link = target.with_extension("link");
        symlink(&target, &link).expect("create pairing symlink");
        assert!(matches!(
            base.clone().with_pairing_file(&link),
            Err(AgentError::InvalidConfig)
        ));

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("make pairing fixture insecure");
        assert!(matches!(
            base.with_pairing_file(&target),
            Err(AgentError::InvalidConfig)
        ));
        fs::set_permissions(&target, fs::Permissions::from_mode(0o000))
            .expect("remove pairing fixture read permission");
        let base = HostAgentConfig::from_settings(&default_config(), "host").expect("config");
        assert!(matches!(
            base.with_pairing_file(&target),
            Err(AgentError::InvalidConfig)
        ));
        fs::remove_file(link).expect("remove pairing symlink");
        fs::remove_file(target).expect("remove pairing fixture");
    }

    #[test]
    fn preflight_never_selects_native_drm_without_positive_probe() {
        let settings = default_config();
        let report = super::run_preflight(&settings.host.capture, false, false, true, false, true);
        assert_eq!(report.selected, super::HostBackend::FfmpegX11);
        assert!(!report.native_drm_reachable);
        assert!(!report.native_drm_usable);
    }

    #[test]
    fn explicit_drm_does_not_silently_fall_back_when_native_is_unusable() {
        let report = super::run_preflight(
            &openstream_settings::CaptureMode::Drm,
            false,
            false,
            true,
            true,
            true,
        );

        assert_eq!(report.selected, super::HostBackend::Unavailable);
        assert_eq!(
            report.reason,
            Some(super::HostErrorCode::PreflightUnavailable)
        );
    }

    #[test]
    fn auto_uses_x11_when_drm_is_reachable_but_not_usable() {
        let report = super::run_preflight(
            &openstream_settings::CaptureMode::Auto,
            true,
            false,
            true,
            false,
            true,
        );

        assert_eq!(report.selected, super::HostBackend::FfmpegX11);
        assert!(report.native_drm_reachable);
        assert!(!report.native_drm_usable);
    }

    #[test]
    fn auto_uses_native_drm_only_when_the_pipeline_is_usable() {
        let report = super::run_preflight(
            &openstream_settings::CaptureMode::Auto,
            true,
            true,
            true,
            true,
            true,
        );

        assert_eq!(report.selected, super::HostBackend::NativeDrm);
    }

    #[test]
    fn auto_prefers_pipewire_when_x11_is_unavailable() {
        let report = super::run_preflight(
            &openstream_settings::CaptureMode::Auto,
            false,
            false,
            false,
            true,
            true,
        );

        assert_eq!(report.selected, super::HostBackend::FfmpegPipewire);
    }

    #[test]
    fn auto_reports_unavailable_without_a_usable_capture_backend() {
        let report = super::run_preflight(
            &openstream_settings::CaptureMode::Auto,
            false,
            false,
            false,
            false,
            false,
        );

        assert_eq!(report.selected, super::HostBackend::Unavailable);
        assert_eq!(
            report.reason,
            Some(super::HostErrorCode::PreflightUnavailable)
        );
    }
}
