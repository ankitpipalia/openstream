//! Bounded supervision for the OpenStream host process.
//!
//! The agent owns the host child, not the desktop shell. Its policy is
//! deliberately driven by an injected clock and child factory so restart,
//! shutdown, and health behavior can be verified without launching FFmpeg.
//! The Tokio implementation is a thin process adapter; no shell is involved.

use openstream_app_core::AppErrorCode;
use openstream_local_ipc::RequestId;
use openstream_settings::{AppConfig, CaptureMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Hard upper bound for one child argument.
const MAX_ARGUMENT_BYTES: usize = 4096;
/// Hard upper bound for one environment value.
const MAX_ENV_VALUE_BYTES: usize = 16 * 1024;
/// Hard upper bound for the configured child command.
const MAX_PROGRAM_BYTES: usize = 4096;
/// Hard upper bound for the agent backend label.
const MAX_BACKEND_BYTES: usize = 128;
const STOP_GRACE_PERIOD: Duration = Duration::from_secs(2);
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
            Self::ExitCode(_) | Self::Signal(_) | Self::Unknown | Self::LifetimeExceeded
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
}

impl fmt::Debug for ChildSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildSpec")
            .field("program", &"<configured>")
            .field("argument_count", &self.args.len())
            .field("environment_keys", &self.env.keys().collect::<Vec<_>>())
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
                || key == "OPENSTREAM_PAIRING_JSON"
                || key.chars().any(|character| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
                })
                || value.len() > MAX_ENV_VALUE_BYTES
                || value.contains('\0')
            {
                return Err(AgentError::InvalidConfig);
            }
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
        let mut child = ChildSpec::new(executable)?;
        child = child.env(
            "OPENSTREAM_SIGNAL_ORIGIN",
            settings.client.signal_origin.clone(),
        )?;
        child = child.env("OPENSTREAM_WIDTH", settings.video.width.to_string())?;
        child = child.env("OPENSTREAM_HEIGHT", settings.video.height.to_string())?;
        child = child.env("OPENSTREAM_FPS", settings.video.fps.to_string())?;
        child = child.env(
            "OPENSTREAM_VIDEO_MBPS",
            format!("{:.6}", settings.video.bitrate_mbps),
        )?;
        child = child.env(
            "OPENSTREAM_VIDEO_MIN_MBPS",
            format!("{:.6}", settings.video.min_bitrate_mbps),
        )?;
        child = child.env("OPENSTREAM_AUDIO", bool_text(settings.audio.enabled))?;
        child = child.env("OPENSTREAM_ENABLE_INPUT", bool_text(settings.input.enabled))?;
        child = child.env(
            "OPENSTREAM_HOST_SECONDS",
            settings.advanced.max_session_seconds.to_string(),
        )?;
        if !matches!(settings.host.capture, CaptureMode::Auto) {
            child = child.env(
                "OPENSTREAM_CAPTURE_BACKEND",
                mode_text(&settings.host.capture)?,
            )?;
        }
        child = child.env(
            "OPENSTREAM_VIDEO_ENCODER",
            mode_text(&settings.host.encoder)?,
        )?;
        Self::new(child)
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
    pub x11_available: bool,
    pub pipewire_available: bool,
    pub ffmpeg_available: bool,
    pub selected: HostBackend,
    pub reason: Option<HostErrorCode>,
}

/// Select a backend only from explicit preflight capabilities.
pub fn run_preflight(
    requested: &CaptureMode,
    native_drm_reachable: bool,
    x11_available: bool,
    pipewire_available: bool,
    ffmpeg_available: bool,
) -> PreflightReport {
    let selected = match requested {
        CaptureMode::Drm if native_drm_reachable => HostBackend::NativeDrm,
        CaptureMode::Pipewire if pipewire_available && ffmpeg_available => {
            HostBackend::FfmpegPipewire
        }
        CaptureMode::X11 if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        CaptureMode::Auto if native_drm_reachable => HostBackend::NativeDrm,
        CaptureMode::Auto if pipewire_available && ffmpeg_available => HostBackend::FfmpegPipewire,
        CaptureMode::Auto if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        _ if x11_available && ffmpeg_available => HostBackend::FfmpegX11,
        _ if pipewire_available && ffmpeg_available => HostBackend::FfmpegPipewire,
        _ if ffmpeg_available => HostBackend::FfmpegFallback,
        _ => HostBackend::Unavailable,
    };
    PreflightReport {
        native_drm_reachable,
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

#[cfg(unix)]
fn signal_process_group(pid: Option<u32>, signal: i32) -> Result<(), AgentError> {
    let pid = pid.ok_or(AgentError::StopFailed)?;
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let result = unsafe { kill(-(pid as i32), signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(AgentError::StopFailed)
    }
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
        .envs(spec.environment())
        .env_remove("OPENSTREAM_PAIRING_JSON");
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentIpcCommand {
    Start,
    Stop,
    Tick,
    Health,
    Shutdown,
}

/// One bounded local request. It contains no credentials or user content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIpcRequest {
    pub version: u32,
    pub request_id: RequestId,
    pub command: AgentIpcCommand,
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

            if self.state == ChildState::Starting
                && self.started_at.is_some_and(|started| {
                    now.saturating_duration_since(started)
                        >= Duration::from_millis(self.config.startup_grace_ms)
                })
            {
                self.state = ChildState::Ready;
                return Ok(vec![HostAgentEvent::Ready]);
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
                self.schedule_restart(now, HostErrorCode::LifetimeExceeded, &mut events);
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
        HostHealth {
            state: self.state,
            backend: self.config.backend.clone(),
            pid: self.child.as_ref().and_then(|child| child.pid()),
            restart_count: self.restart_count,
            next_restart_in_ms,
            last_exit: self.last_exit,
            last_error: self.last_error,
        }
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
        AgentError, ChildExit, ChildExitReason, ChildFactory, ChildSpec, ChildState, HostAgent,
        HostAgentConfig, HostAgentEvent, HostErrorCode, ManagedChild, configure_child_environment,
    };
    use openstream_settings::default_config;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
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

    #[test]
    fn runtime_secret_is_redacted_from_configuration_debug() {
        let config = HostAgentConfig::from_settings(&default_config(), "host")
            .expect("config")
            .with_runtime_env("OPENSTREAM_PAIRING_FILE", "/private/pairing.json")
            .expect("runtime secret");
        let debug = format!("{config:?}");
        assert!(debug.contains("OPENSTREAM_PAIRING_FILE"));
        assert!(!debug.contains("/private/pairing.json"));
    }

    #[test]
    fn raw_pairing_json_runtime_environment_is_rejected() {
        let result = HostAgentConfig::from_settings(&default_config(), "host")
            .expect("config")
            .with_runtime_env("OPENSTREAM_PAIRING_JSON", "raw-token-sentinel");

        assert!(matches!(result, Err(AgentError::InvalidConfig)));
    }

    #[test]
    fn persistent_child_explicitly_removes_inherited_raw_pairing_json() {
        let spec = ChildSpec::new("host")
            .expect("child spec")
            .env("OPENSTREAM_PAIRING_FILE", "/private/pairing.json")
            .expect("pairing file environment");
        let mut command = tokio::process::Command::new("host");

        configure_child_environment(&mut command, &spec);

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
            Some(&Some(OsString::from("/private/pairing.json")))
        );
    }

    #[test]
    fn preflight_never_selects_native_drm_without_positive_probe() {
        let settings = default_config();
        let report = super::run_preflight(&settings.host.capture, false, true, false, true);
        assert_eq!(report.selected, super::HostBackend::FfmpegX11);
        assert!(!report.native_drm_reachable);
    }
}
