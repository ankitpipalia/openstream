use openstream_app_core::{
    AppCommand, AppError, AppErrorCode, AppEvent, AppModel, AppSnapshot, DiagnosticSnapshot,
    HostStatus, PermissionSet, MAX_REQUEST_ID_BYTES,
};
use openstream_settings::{
    default_config, load, save_atomic, setting_descriptors, AppConfig, SettingApplyMode,
    SettingDescriptor, SettingsError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::host_agent::HostAgentBridgeError;
use openstream_host_agent::{ChildState, HostAgentEvent, HostErrorCode, HostHealth};

/// Errors crossing the desktop runtime boundary contain stable categories and
/// codes, never app-core's free-form diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeError {
    SettingsUnavailable,
    InvalidSettings,
    StateUnavailable,
    CommandRejected { code: AppErrorCode, retryable: bool },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SettingsUnavailable => formatter.write_str("settings unavailable"),
            Self::InvalidSettings => formatter.write_str("invalid settings"),
            Self::StateUnavailable => formatter.write_str("runtime state unavailable"),
            Self::CommandRejected { code, .. } => {
                write!(formatter, "runtime command rejected: {code:?}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<AppError> for RuntimeError {
    fn from(error: AppError) -> Self {
        Self::CommandRejected {
            code: error.code(),
            retryable: error.retryable,
        }
    }
}

/// The commands the WebView may express. This is deliberately limited to
/// plain user intent: authentication succeeding, negotiation, a session
/// actually connecting or dropping, host readiness or failure, and the
/// passage of time are all authoritative outcomes decided in Rust, and none
/// of them can be named by a deserialized frontend payload. See
/// `RuntimeState::dispatch`, which drives those outcomes itself through
/// app-core's `AppCommand`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeCommand {
    SignIn,
    Connect {
        device_id: String,
        requested: PermissionSet,
    },
    ApproveRequest {
        request_id: String,
        available: PermissionSet,
    },
    RejectRequest {
        request_id: String,
    },
    Disconnect,
    /// Acknowledge a terminal failure and return to a usable idle state.
    /// Without this the shell has no exit from `AppState::Failed`.
    ClearFailure,
    EnableHosting,
    DisableHosting,
}

/// Map a host-agent bridge failure to a fixed, typed description. Only a
/// static per-variant string and error code cross into app-core's
/// vocabulary or back to a caller; the bridge's own internals (socket
/// paths, frame bytes, protocol numbers) never do.
fn describe_host_failure(error: HostAgentBridgeError) -> (&'static str, AppErrorCode, bool) {
    match error {
        HostAgentBridgeError::ConnectionFailed => (
            "host agent connection failed",
            AppErrorCode::Unavailable,
            true,
        ),
        HostAgentBridgeError::Timeout => (
            "host agent request timed out",
            AppErrorCode::Unavailable,
            true,
        ),
        HostAgentBridgeError::UnsupportedPlatform => (
            "host agent is unavailable on this platform",
            AppErrorCode::Unavailable,
            false,
        ),
        HostAgentBridgeError::ProtocolMismatch => (
            "host agent protocol version mismatch",
            AppErrorCode::Internal,
            false,
        ),
        HostAgentBridgeError::InvalidResponse => (
            "host agent response was invalid",
            AppErrorCode::Internal,
            false,
        ),
        HostAgentBridgeError::AgentRejected { retryable, .. } => (
            "host agent rejected the request",
            AppErrorCode::Internal,
            retryable,
        ),
    }
}

/// Decide what an accepted `Start` request actually proved.
///
/// `HostAgent::start` reports `Started { pid }` for a child that has only
/// just been spawned and has not yet passed its startup grace period, and
/// reports nothing at all when the agent was already `Starting`, `Ready`,
/// `Stopping`, or in `Backoff`. Neither is evidence that a host is up, so
/// neither produces a command: the model stays in the `Starting` its
/// intent already set, and the health reconciler settles it.
fn host_start_command(events: &[HostAgentEvent]) -> Option<AppCommand> {
    let mut command = None;
    for event in events {
        match event {
            HostAgentEvent::Ready => command = Some(AppCommand::HostReady),
            HostAgentEvent::Failed { code } => {
                command = Some(AppCommand::HostFailed {
                    message: describe_host_error(Some(*code)).to_string(),
                    retryable: code.retryable(),
                });
            }
            // A spawn, a scheduled restart, a child exit the agent will
            // handle itself, and a stop all leave the model where it is.
            HostAgentEvent::Started { .. }
            | HostAgentEvent::RestartScheduled { .. }
            | HostAgentEvent::ChildExited { .. }
            | HostAgentEvent::Stopped => {}
        }
    }
    command
}

/// A fixed, operator-facing description of a typed host failure. As with
/// `describe_host_failure`, only a static per-variant string crosses into
/// app-core's vocabulary -- never a path, a child environment, or a
/// process's own output.
fn describe_host_error(code: Option<HostErrorCode>) -> &'static str {
    match code {
        Some(HostErrorCode::InvalidConfig) => "host configuration is invalid",
        Some(HostErrorCode::SpawnFailed) => "the host process could not be started",
        Some(HostErrorCode::ChildFailed) => "the host process exited with a failure",
        Some(HostErrorCode::RestartLimit) => "the host process exhausted its restart budget",
        Some(HostErrorCode::StopFailed) => "the host process could not be stopped",
        Some(HostErrorCode::LifetimeExceeded) => "the host process exceeded its lifetime limit",
        Some(HostErrorCode::PreflightUnavailable) => "no usable host capture backend was found",
        None => "the host process failed",
    }
}

/// Rust's own clock, in milliseconds since the Unix epoch. Every
/// `RuntimeCommand` that used to accept a frontend-supplied `now_ms` reads
/// this instead.
///
/// The epoch reading is taken once, at first use, and every later reading
/// advances it with a monotonic `Instant`. A bare `SystemTime::now()` is
/// the wrong clock to enforce a deadline with: it steps when an operator
/// corrects it, when NTP disciplines it, and when a virtual machine
/// resumes from a snapshot, and a backwards step silently extends the
/// 30-second approval window app-core derives from these values by the
/// length of the step. Anchoring it this way keeps the absolute value
/// meaningful to a human reading a timestamp while making the differences
/// app-core actually compares monotonic.
fn current_time_ms() -> u64 {
    static ORIGIN: OnceLock<(Instant, u64)> = OnceLock::new();
    let (started, epoch_ms) = *ORIGIN.get_or_init(|| {
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        (Instant::now(), epoch_ms)
    });
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    epoch_ms.saturating_add(elapsed_ms)
}

/// Generate a bounded, non-secret request id. `RuntimeCommand::Connect` no
/// longer accepts one from the frontend: app-core's idempotency and expiry
/// rules both depend on Rust being the sole author of this value.
fn generate_request_id() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let now_ms = current_time_ms();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut id = format!("connect-{now_ms:x}-{sequence:x}");
    id.truncate(MAX_REQUEST_ID_BYTES);
    id
}

/// Return whether the persisted value named by a `setting_descriptors()`
/// key differs between two configurations. Every current descriptor key has
/// an arm; a key with no arm is treated as unchanged, so a newly added
/// descriptor needs a matching arm here to ever appear as pending.
fn setting_value_changed(key: &str, before: &AppConfig, after: &AppConfig) -> bool {
    match key {
        "client.profile" => before.client.profile != after.client.profile,
        "client.window_mode" => before.client.window_mode != after.client.window_mode,
        "client.renderer" => before.client.renderer != after.client.renderer,
        "client.vsync" => before.client.vsync != after.client.vsync,
        "client.decoder" => before.client.decoder != after.client.decoder,
        "client.codec" => before.client.codec != after.client.codec,
        "client.chroma" => before.client.chroma != after.client.chroma,
        "client.bit_depth" => before.client.bit_depth != after.client.bit_depth,
        "client.immersive" => before.client.immersive != after.client.immersive,
        "host.enabled" => before.host.enabled != after.host.enabled,
        "host.name" => before.host.name != after.host.name,
        "host.capture.drm" | "host.capture.x11" => before.host.capture != after.host.capture,
        "host.stay_awake" => before.host.stay_awake != after.host.stay_awake,
        "input.keyboard" => before.input.keyboard != after.input.keyboard,
        "input.mouse" => before.input.mouse != after.input.mouse,
        "input.gamepad" => before.input.gamepad != after.input.gamepad,
        "input.clipboard" => before.input.clipboard != after.input.clipboard,
        "input.microphone" => before.input.microphone != after.input.microphone,
        "network.client_port" => before.network.client_port != after.network.client_port,
        "network.host_start_port" => {
            before.network.host_start_port != after.network.host_start_port
        }
        "network.upnp" => before.network.upnp != after.network.upnp,
        "network.turn" => before.network.turn != after.network.turn,
        _ => false,
    }
}

/// The one setting `AppModel::from_config` reads directly: it selects
/// `DeploymentMode`, and therefore the initial `AppState`, for the whole
/// session. It is deliberately absent from `setting_descriptors()` because
/// it is not a per-feature preference -- changing it redefines which state
/// machine the running app is. It is never applied live: rebuilding
/// `AppModel` in place would silently discard an active session, a pending
/// request, or a running host, which is the exact "mutate part of the
/// runtime and leave the rest stale" failure this fix removes.
const DEPLOYMENT_MODE_SETTING_KEY: &str = "network.local_no_auth";

/// State and persisted configuration owned by the desktop process.
///
/// The three `applied_*` baselines are what makes a pending change
/// revertible. Pending state used to be a set of flags that only ever
/// accumulated: changing capture from X11 to DRM raised
/// `host_restart_required`, and changing it straight back left the flag
/// raised and the key listed even though the persisted value now matched
/// the running one exactly. Each baseline records the configuration
/// actually in force for one apply class, so what is pending is always
/// recomputed as the difference between a baseline and the persisted
/// config, and an edit that returns a value to its running value cancels
/// itself.
#[derive(Debug)]
pub struct RuntimeState {
    app: AppModel,
    settings: AppConfig,
    settings_path: Option<PathBuf>,
    descriptors: Vec<SettingDescriptor>,
    /// Values in force for `SettingApplyMode::Reconnect` keys.
    ///
    /// Nothing advances this yet: a reconnect picks the new values up, and
    /// the session runner that would perform one does not exist (R-01). A
    /// `Reconnect`-classed change therefore stays pending for the life of
    /// the process, which is the honest answer while no session can be
    /// established at all. When the runner lands, it advances this the way
    /// `note_host_started` advances the host baseline.
    applied_reconnect: AppConfig,
    /// Values in force for `SettingApplyMode::RestartHost` keys.
    ///
    /// Nothing advances this yet either, and for a sharper reason than the
    /// reconnect baseline: the agent cannot say which configuration its
    /// child is running. See
    /// [`Self::host_config_revision_is_proven`].
    applied_host: AppConfig,
    /// Values in force for `SettingApplyMode::RestartApplication` keys and
    /// for the deployment mode. Only a process restart advances this, and a
    /// process restart rebuilds `RuntimeState` from the settings file, so
    /// it is simply whatever was loaded at construction.
    applied_application: AppConfig,
}

/// Secret-free state returned to the product shell.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeSnapshot {
    pub app: AppSnapshot,
    pub settings: AppConfig,
    pub descriptors: Vec<SettingDescriptor>,
    /// True once a change requires an application restart to take effect.
    pub restart_required: bool,
    /// True once a change requires only the host to restart to take effect.
    pub host_restart_required: bool,
    /// Keys, from `descriptors` plus the deployment mode, whose persisted
    /// value is not yet reflected in the running application.
    pub pending_settings: Vec<String>,
}

/// Result of an accepted runtime command.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeDispatchResult {
    pub snapshot: RuntimeSnapshot,
    pub events: Vec<AppEvent>,
}

impl RuntimeState {
    pub fn from_settings_path(path: Option<PathBuf>) -> Result<Self, RuntimeError> {
        let settings = match &path {
            Some(path) => match load(path) {
                Ok(file) => file.config,
                Err(SettingsError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
                    default_config()
                }
                Err(_) => return Err(RuntimeError::SettingsUnavailable),
            },
            None => default_config(),
        };
        let app = AppModel::from_config(&settings).map_err(|_| RuntimeError::InvalidSettings)?;

        Ok(Self {
            app,
            applied_reconnect: settings.clone(),
            applied_host: settings.clone(),
            applied_application: settings.clone(),
            settings,
            settings_path: path,
            descriptors: setting_descriptors(),
        })
    }

    #[cfg(test)]
    pub fn for_test() -> Self {
        Self::from_settings_path(None).expect("test runtime state uses valid defaults")
    }

    pub fn settings(&self) -> &AppConfig {
        &self.settings
    }

    pub fn update_settings(&mut self, settings: AppConfig) -> Result<(), RuntimeError> {
        settings
            .validate()
            .map_err(|_| RuntimeError::InvalidSettings)?;
        if let Some(path) = &self.settings_path {
            save_atomic(path, &settings).map_err(|_| RuntimeError::SettingsUnavailable)?;
        }
        // Validation and the durable write both succeeded, so this config is
        // now the persisted one. Nothing else needs reconciling: what is
        // pending is derived from the baselines on every read, never stored.
        // `AppModel` caches no client/host/input preference of its own -- the
        // persisted `AppConfig` handed back in each snapshot is the single
        // source of truth -- so a `Live`-classed change is in effect the
        // moment this assignment lands.
        self.settings = settings;
        Ok(())
    }

    /// The baseline a key's apply mode is measured against.
    fn baseline_for(&self, mode: SettingApplyMode) -> &AppConfig {
        match mode {
            // A live setting is in force as soon as it is persisted, so it
            // is measured against the persisted config and can never differ.
            SettingApplyMode::Live => &self.settings,
            SettingApplyMode::Reconnect => &self.applied_reconnect,
            SettingApplyMode::RestartHost => &self.applied_host,
            SettingApplyMode::RestartApplication => &self.applied_application,
        }
    }

    /// Keys whose persisted value differs from the value actually in force.
    fn pending_setting_keys(&self) -> BTreeSet<String> {
        let mut pending = BTreeSet::new();
        if self.applied_application.network.local_no_auth != self.settings.network.local_no_auth {
            pending.insert(DEPLOYMENT_MODE_SETTING_KEY.to_string());
        }
        for descriptor in &self.descriptors {
            let baseline = self.baseline_for(descriptor.apply_mode);
            if setting_value_changed(descriptor.key, baseline, &self.settings) {
                pending.insert(descriptor.key.to_string());
            }
        }
        pending
    }

    /// Whether any pending change needs the whole application to restart:
    /// a `RestartApplication`-classed setting, or the deployment mode,
    /// which decides which state machine the running app even is.
    fn restart_required(&self) -> bool {
        if self.applied_application.network.local_no_auth != self.settings.network.local_no_auth {
            return true;
        }
        self.any_pending_in(SettingApplyMode::RestartApplication)
    }

    /// Whether any pending change needs only the host to restart.
    fn host_restart_required(&self) -> bool {
        self.any_pending_in(SettingApplyMode::RestartHost)
    }

    fn any_pending_in(&self, mode: SettingApplyMode) -> bool {
        let baseline = self.baseline_for(mode);
        self.descriptors
            .iter()
            .filter(|descriptor| descriptor.apply_mode == mode)
            .any(|descriptor| setting_value_changed(descriptor.key, baseline, &self.settings))
    }

    /// Whether the agent has proved which configuration its child is
    /// running.
    ///
    /// It has not, and cannot yet. `HostReady` says a child reached a ready
    /// state; it says nothing about what that child was configured with.
    /// The agent builds its `HostAgentConfig` once, at daemon startup, from
    /// `default_config()` plus environment overrides -- it never reads this
    /// shell's `settings.json`, and an IPC `Start` carries no settings --
    /// so a stop/start cycle re-runs the child under the agent's original
    /// configuration, not the edited one.
    ///
    /// Advancing `applied_host` on `HostReady` therefore reports a
    /// restart-host setting as applied while the running child still has
    /// the old value: the exact false "already in effect" state these
    /// baselines exist to prevent, just one step further along. Until the
    /// agent can report the configuration revision it actually consumed,
    /// the honest answer is that the change is still pending, so nothing
    /// advances this baseline.
    ///
    /// The mechanism that would close this is a config revision carried
    /// through `Start` and echoed in `HostHealth`; that belongs with the
    /// runtime controller in R-01, which is where configuration application
    /// stops being inferred from process state.
    const fn host_config_revision_is_proven() -> bool {
        false
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            app: self.app.snapshot(DiagnosticSnapshot::default()),
            settings: self.settings.clone(),
            descriptors: self.descriptors.clone(),
            restart_required: self.restart_required(),
            host_restart_required: self.host_restart_required(),
            pending_settings: self.pending_setting_keys().into_iter().collect(),
        }
    }

    /// Advance app-core's request-expiry clock using Rust's own wall clock
    /// before handling any command, so a pending request expires even when
    /// the frontend issues no further commands. `Tick` never fails.
    fn advance_clock(&mut self) -> Vec<AppEvent> {
        self.app
            .dispatch(AppCommand::Tick {
                now_ms: current_time_ms(),
            })
            .expect("app-core's Tick command never fails")
    }

    /// Reject an `ApproveRequest`/`RejectRequest` naming anything other
    /// than the one pending request app-core is actually holding. The
    /// frontend supplies this id because it is acting on a specific
    /// approval prompt it was shown, not because it is trusted to name an
    /// arbitrary in-flight request.
    fn require_pending_request(&self, request_id: &str) -> Result<(), RuntimeError> {
        let pending = self
            .app
            .snapshot(DiagnosticSnapshot::default())
            .pending_request;
        match pending {
            Some(request) if request.request_id == request_id => Ok(()),
            _ => Err(RuntimeError::CommandRejected {
                code: AppErrorCode::InvalidRequest,
                retryable: false,
            }),
        }
    }

    /// Translate one user-intent command into app-core's vocabulary. The
    /// request id and clock are generated here in Rust, and a stale or
    /// fabricated pending-request id is rejected here, before either can
    /// reach app-core.
    fn resolve_app_command(&self, command: RuntimeCommand) -> Result<AppCommand, RuntimeError> {
        let now_ms = current_time_ms();
        match command {
            RuntimeCommand::SignIn => Ok(AppCommand::BeginAuthentication),
            RuntimeCommand::Connect {
                device_id,
                requested,
            } => Ok(AppCommand::Connect {
                device_id,
                request_id: generate_request_id(),
                requested,
                now_ms,
            }),
            RuntimeCommand::ApproveRequest {
                request_id,
                available,
            } => {
                self.require_pending_request(&request_id)?;
                Ok(AppCommand::ApproveRequest {
                    request_id,
                    available,
                    now_ms,
                })
            }
            RuntimeCommand::RejectRequest { request_id } => {
                self.require_pending_request(&request_id)?;
                Ok(AppCommand::RejectRequest { request_id, now_ms })
            }
            RuntimeCommand::Disconnect => Ok(AppCommand::Disconnect),
            RuntimeCommand::ClearFailure => Ok(AppCommand::ClearFailure),
            RuntimeCommand::EnableHosting => Ok(AppCommand::EnableHosting),
            RuntimeCommand::DisableHosting => Ok(AppCommand::DisableHosting),
        }
    }

    pub fn dispatch(
        &mut self,
        command: RuntimeCommand,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        let mut events = self.advance_clock();
        let app_command = self.resolve_app_command(command)?;
        events.extend(self.app.dispatch(app_command).map_err(RuntimeError::from)?);
        Ok(RuntimeDispatchResult {
            snapshot: self.snapshot(),
            events,
        })
    }

    /// Apply the real outcome of a `HostAgentClient::start()` call. Called
    /// only after the caller has released the state mutex for the
    /// `.await` that produced `outcome`; see `lib.rs`'s host-lifecycle
    /// dispatch, which is the only caller.
    ///
    /// An accepted request is not a running host. This used to map any
    /// `Ok` to `AppCommand::HostReady`, which reported a host as ready the
    /// instant the agent accepted the request -- before the child had
    /// passed its startup grace period, and even when the agent returned
    /// no events at all because it was already stopping or backing off.
    /// The shell would then sit on `Ready` while the child crashed behind
    /// it. Only an event that actually proves readiness moves the model
    /// out of `Starting`; anything else leaves it there for
    /// [`Self::reconcile_host_health`] to resolve against the agent.
    pub(crate) fn apply_host_start_outcome(
        &mut self,
        outcome: Result<Vec<HostAgentEvent>, HostAgentBridgeError>,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        let command = match outcome {
            Ok(events) => host_start_command(&events),
            Err(error) => {
                let (message, _code, retryable) = describe_host_failure(error);
                Some(AppCommand::HostFailed {
                    message: message.to_string(),
                    retryable,
                })
            }
        };
        let events = match command {
            Some(command) => self.apply_host_command(command)?,
            None => Vec::new(),
        };
        Ok(RuntimeDispatchResult {
            snapshot: self.snapshot(),
            events,
        })
    }

    /// Dispatch one host-lifecycle command.
    ///
    /// A `HostReady` deliberately does not advance the host settings
    /// baseline; see [`Self::host_config_revision_is_proven`] for why a
    /// ready child is not evidence that it consumed the edited settings.
    fn apply_host_command(&mut self, command: AppCommand) -> Result<Vec<AppEvent>, RuntimeError> {
        if matches!(command, AppCommand::HostReady) && Self::host_config_revision_is_proven() {
            self.applied_host = self.settings.clone();
        }
        self.app.dispatch(command).map_err(RuntimeError::from)
    }

    /// Reconcile `AppModel` with what the host agent reports it is actually
    /// doing.
    ///
    /// Nothing else closes the gap between the two. The agent supervises
    /// its child on its own clock: it restarts a crashed child, backs off,
    /// and gives up, none of which is a reply to a request the shell made.
    /// A desktop shell also starts from `HostStatus::Disabled` and has no
    /// idea whether an agent that was already running is hosting. The
    /// agent is the authority in every disagreement, and this adopts its
    /// answer -- including switching the model to `Starting` when a child
    /// the model believed was ready is being restarted.
    ///
    /// The one thing an observation must never do is overturn the
    /// operator's decision: if the model says hosting is disabled and the
    /// agent reports a terminal failure, that failure is not news, and the
    /// model stays disabled.
    pub(crate) fn reconcile_host_health(
        &mut self,
        health: &HostHealth,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        let status = self.app.host_status();
        let commands: Vec<AppCommand> = match health.state {
            ChildState::Ready => match status {
                HostStatus::Ready => Vec::new(),
                HostStatus::Starting => vec![AppCommand::HostReady],
                // The agent is hosting and the model does not know it: a
                // shell opened over an agent that was already running, or
                // one whose child recovered on its own after a failure.
                HostStatus::Disabled | HostStatus::Failed { .. } => {
                    vec![AppCommand::EnableHosting, AppCommand::HostReady]
                }
            },
            ChildState::Starting | ChildState::Backoff => match status {
                HostStatus::Starting => Vec::new(),
                HostStatus::Disabled => vec![AppCommand::EnableHosting],
                HostStatus::Ready | HostStatus::Failed { .. } => vec![AppCommand::HostStarting],
            },
            ChildState::Stopped | ChildState::Stopping => match status {
                HostStatus::Disabled => Vec::new(),
                _ => vec![AppCommand::DisableHosting],
            },
            ChildState::Failed => match status {
                // Hosting is off because the operator turned it off. The
                // agent's last failure does not switch the model into a
                // failed state nobody can act on.
                HostStatus::Disabled | HostStatus::Failed { .. } => Vec::new(),
                _ => vec![AppCommand::HostFailed {
                    message: describe_host_error(health.last_error).to_string(),
                    retryable: health.last_error.is_none_or(HostErrorCode::retryable),
                }],
            },
        };

        let mut events = Vec::new();
        for command in commands {
            events.extend(self.apply_host_command(command)?);
        }
        Ok(RuntimeDispatchResult {
            snapshot: self.snapshot(),
            events,
        })
    }

    /// Apply the real outcome of a `HostAgentClient::stop()` call.
    /// `DisableHosting`'s intent phase has already moved `host_status` to
    /// `Disabled` unconditionally -- app-core has no "stopping" state -- so
    /// a failed stop is reported as a typed, standalone error rather than
    /// forced through `AppCommand::HostFailed`, which app-core refuses once
    /// hosting is already disabled.
    pub(crate) fn apply_host_stop_outcome(
        &mut self,
        outcome: Result<Vec<HostAgentEvent>, HostAgentBridgeError>,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        match outcome {
            Ok(_events) => Ok(RuntimeDispatchResult {
                snapshot: self.snapshot(),
                events: Vec::new(),
            }),
            Err(error) => {
                let (_message, code, retryable) = describe_host_failure(error);
                Err(RuntimeError::CommandRejected { code, retryable })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        current_time_ms, AppCommand, AppErrorCode, AppEvent, HostAgentBridgeError, HostAgentEvent,
        HostErrorCode, RuntimeCommand, RuntimeError, RuntimeState,
    };
    use openstream_app_core::{ConnectionRejectReason, DeviceSummary, HostStatus, PermissionSet};
    use openstream_settings::{load, CaptureMode, StreamProfile, CURRENT_SCHEMA_VERSION};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openstream-runtime-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    /// `for_test()` defaults to Secure mode (signed out), matching a real
    /// first run. Tests that exercise `Connect` need the Ready state, which
    /// in Secure mode only follows a completed sign-in, so this drives that
    /// sign-in through the same commands the frontend would use, plus the
    /// internal outcome only Rust can apply.
    fn ready_state_for_test() -> RuntimeState {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::SignIn).unwrap();
        state
            .app
            .dispatch(AppCommand::AuthenticationSucceeded)
            .expect("seeded sign-in succeeds");
        state
    }

    #[test]
    fn absent_settings_start_from_safe_defaults() {
        let state = RuntimeState::from_settings_path(Some(temp_path("missing"))).unwrap();
        assert_eq!(state.settings().schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(state.settings().client.profile, StreamProfile::Balanced);
    }

    #[test]
    fn valid_settings_update_is_persisted_and_invalid_update_is_atomic() {
        let path = temp_path("settings");
        let mut state = RuntimeState::from_settings_path(Some(path.clone())).unwrap();
        let mut updated = state.settings().clone();
        updated.client.bandwidth_cap_mbps = Some(20.0);
        state.update_settings(updated.clone()).unwrap();
        assert_eq!(load(&path).unwrap().config, updated);

        let mut invalid = updated.clone();
        invalid.video.fps = 0;
        assert!(state.update_settings(invalid).is_err());
        assert_eq!(load(path).unwrap().config, updated);
    }

    #[test]
    fn dispatch_returns_only_secret_free_snapshot_and_events() {
        let mut state = RuntimeState::for_test();
        let result = state.dispatch(RuntimeCommand::SignIn).unwrap();
        assert!(serde_json::to_string(&result)
            .unwrap()
            .contains("AuthenticationStarted"));
        assert!(!serde_json::to_string(&result).unwrap().contains("pairing"));
    }

    /// FIX 1: the WebView must never be able to construct an authoritative
    /// internal outcome by naming it in a JSON payload.
    #[test]
    fn internal_outcomes_do_not_deserialize_into_runtime_command() {
        let connection_established =
            r#"{"ConnectionEstablished":{"session_id":"fake","generation":1}}"#;
        assert!(serde_json::from_str::<RuntimeCommand>(connection_established).is_err());
        assert!(serde_json::from_str::<RuntimeCommand>("\"HostReady\"").is_err());
        assert!(serde_json::from_str::<RuntimeCommand>("\"AuthenticationSucceeded\"").is_err());
    }

    /// FIX 2: `Connect` no longer accepts a request id from the frontend;
    /// `RuntimeState` must generate one itself.
    #[test]
    fn connect_dispatch_generates_its_own_request_id() {
        let mut state = ready_state_for_test();
        state
            .app
            .add_device(DeviceSummary::online("mac-1", "Mac client"));
        let result = state
            .dispatch(RuntimeCommand::Connect {
                device_id: "mac-1".into(),
                requested: PermissionSet::view_only(),
            })
            .unwrap();
        let pending = result
            .snapshot
            .app
            .pending_request
            .expect("connect creates a pending request");
        assert!(!pending.request_id.is_empty());
    }

    /// FIX 2: an `ApproveRequest`/`RejectRequest` naming an id that is not
    /// the actual pending request must be rejected by `RuntimeState`
    /// itself, never forwarded to app-core as if it were legitimate.
    #[test]
    fn approve_request_naming_a_different_id_is_rejected() {
        let mut state = ready_state_for_test();
        state
            .app
            .add_device(DeviceSummary::online("mac-1", "Mac client"));
        state
            .dispatch(RuntimeCommand::Connect {
                device_id: "mac-1".into(),
                requested: PermissionSet::view_only(),
            })
            .unwrap();

        let error = state
            .dispatch(RuntimeCommand::ApproveRequest {
                request_id: "not-the-pending-request".into(),
                available: PermissionSet::full(),
            })
            .expect_err("a mismatched request id must never reach app-core");
        assert_eq!(
            error,
            RuntimeError::CommandRejected {
                code: AppErrorCode::InvalidRequest,
                retryable: false,
            }
        );
    }

    /// FIX 2: request expiry must advance from Rust's own clock even
    /// though no `RuntimeCommand` carries a timestamp. A request is seeded
    /// directly through app-core with an artificially old clock reading, so
    /// the very next dispatch -- using the real wall clock -- observes it
    /// as already expired.
    #[test]
    fn expiry_advances_across_dispatches_without_a_frontend_timestamp() {
        let mut state = ready_state_for_test();
        state
            .app
            .add_device(DeviceSummary::online("mac-1", "Mac client"));
        state
            .app
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "seed-request".into(),
                requested: PermissionSet::view_only(),
                now_ms: 1,
            })
            .expect("seed a pending request whose expiry is far in the past");

        let result = state.dispatch(RuntimeCommand::DisableHosting).unwrap();
        assert!(result.events.iter().any(|event| matches!(
            event,
            AppEvent::ConnectionRejected { request_id, reason: ConnectionRejectReason::Expired }
                if request_id == "seed-request"
        )));
    }

    /// The clock driving app-core's expiry must never step backwards.
    ///
    /// `SystemTime::now()` can: an operator correcting the clock, NTP
    /// disciplining it, or a virtual machine resuming from a snapshot all
    /// move it, and a backwards step extends a 30-second approval window by
    /// the length of the step. The epoch is therefore read once and every
    /// later reading advances it with a monotonic `Instant`, so the
    /// differences app-core compares can only move forward while the
    /// absolute value stays a meaningful timestamp.
    #[test]
    fn the_expiry_clock_is_monotonic_and_still_epoch_anchored() {
        let first = current_time_ms();
        let mut previous = first;
        for _ in 0..1_000 {
            let reading = current_time_ms();
            assert!(
                reading >= previous,
                "the expiry clock stepped backwards: {reading} < {previous}"
            );
            previous = reading;
        }

        // Still anchored to the wall clock, so a timestamp remains readable
        // to a human, and close to it because the anchor is taken at first
        // use rather than at some fixed past point.
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis() as u64;
        assert!(
            wall_ms.abs_diff(first) < 60_000,
            "the clock is no longer anchored near the wall clock"
        );
    }

    /// FIX 3: a `live`-classed setting is already in effect the moment the
    /// snapshot reflects it; nothing about it is left pending.
    #[test]
    fn live_setting_change_needs_no_restart_and_is_not_pending() {
        let path = temp_path("live-setting");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let mut updated = state.settings().clone();
        updated.host.name = "New host name".to_string();
        state.update_settings(updated).unwrap();

        let snapshot = state.snapshot();
        assert_eq!(snapshot.settings.host.name, "New host name");
        assert!(!snapshot.restart_required);
        assert!(!snapshot.host_restart_required);
        assert!(snapshot.pending_settings.is_empty());
    }

    /// FIX 3: a `restart_host`-classed setting is persisted immediately but
    /// flagged as not yet effective until the host restarts.
    #[test]
    fn restart_host_setting_change_is_pending_and_flags_host_restart() {
        let path = temp_path("restart-host-setting");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let mut updated = state.settings().clone();
        updated.host.enabled = !updated.host.enabled;
        state.update_settings(updated).unwrap();

        let snapshot = state.snapshot();
        assert!(snapshot.host_restart_required);
        assert!(!snapshot.restart_required);
        assert!(snapshot
            .pending_settings
            .iter()
            .any(|key| key == "host.enabled"));
    }

    /// Reverting a change back to the running value cancels it.
    ///
    /// Pending state used to be a set of flags that only ever accumulated:
    /// switching capture from X11 to DRM raised `host_restart_required`,
    /// and switching it straight back left the flag raised and the key
    /// listed for the rest of the session, so the shell demanded a restart
    /// to apply a configuration that was already running.
    #[test]
    fn reverting_a_pending_change_clears_it() {
        let path = temp_path("revert-host-setting");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let original = state.settings().clone();

        let mut updated = original.clone();
        updated.host.capture = match original.host.capture {
            CaptureMode::X11 => CaptureMode::Drm,
            _ => CaptureMode::X11,
        };
        state.update_settings(updated).unwrap();
        assert!(state.snapshot().host_restart_required);

        state.update_settings(original.clone()).unwrap();
        let snapshot = state.snapshot();
        assert!(
            !snapshot.host_restart_required,
            "a config identical to the running one needs no host restart"
        );
        assert!(
            snapshot.pending_settings.is_empty(),
            "nothing is pending once the persisted config matches the running one: {:?}",
            snapshot.pending_settings
        );
        assert_eq!(snapshot.settings, original);
    }

    /// The same invariant for the deployment mode, which is the one key
    /// that is not in `setting_descriptors()` and drives
    /// `restart_required` on its own.
    #[test]
    fn reverting_the_deployment_mode_clears_the_restart_requirement() {
        let path = temp_path("revert-deployment-mode");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let original = state.settings().clone();

        let mut updated = original.clone();
        updated.network.local_no_auth = !original.network.local_no_auth;
        state.update_settings(updated).unwrap();
        assert!(state.snapshot().restart_required);

        state.update_settings(original).unwrap();
        let snapshot = state.snapshot();
        assert!(!snapshot.restart_required);
        assert!(snapshot.pending_settings.is_empty());
    }

    /// A ready child is not proof that it consumed the edited settings.
    ///
    /// The agent builds its configuration once, at daemon startup, from
    /// defaults plus environment overrides; it never reads this shell's
    /// settings file, and an IPC `Start` carries no settings. So a
    /// stop/start cycle re-runs the child under the agent's original
    /// configuration. Clearing the host-restart requirement on `HostReady`
    /// would report a capture-mode change as applied while the running
    /// child still had the old mode -- the same false "already in effect"
    /// state the baselines exist to prevent.
    #[test]
    fn a_ready_child_does_not_clear_a_pending_restart_host_setting() {
        let path = temp_path("host-restart-baseline");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let mut updated = state.settings().clone();
        updated.host.capture = match updated.host.capture {
            CaptureMode::X11 => CaptureMode::Drm,
            _ => CaptureMode::X11,
        };
        state.update_settings(updated).unwrap();
        assert!(state.snapshot().host_restart_required);

        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state
            .apply_host_start_outcome(Ok(vec![HostAgentEvent::Ready]))
            .unwrap();
        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);

        let snapshot = state.snapshot();
        assert!(
            snapshot.host_restart_required,
            "a ready child carries no evidence of which configuration it consumed"
        );
        assert!(
            snapshot
                .pending_settings
                .iter()
                .any(|key| key.starts_with("host.capture")),
            "the capture change is still pending: {:?}",
            snapshot.pending_settings
        );
    }

    /// The revert path still works, and is the one thing that legitimately
    /// clears a restart-host requirement without the agent proving
    /// anything: the persisted value is the value already running.
    #[test]
    fn reverting_a_restart_host_setting_still_clears_it_after_a_ready_child() {
        let path = temp_path("host-restart-revert");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let original = state.settings().clone();
        let mut updated = original.clone();
        updated.host.capture = match original.host.capture {
            CaptureMode::X11 => CaptureMode::Drm,
            _ => CaptureMode::X11,
        };
        state.update_settings(updated).unwrap();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        state
            .apply_host_start_outcome(Ok(vec![HostAgentEvent::Ready]))
            .unwrap();
        assert!(state.snapshot().host_restart_required);

        state.update_settings(original).unwrap();
        let snapshot = state.snapshot();
        assert!(!snapshot.host_restart_required);
        assert!(snapshot.pending_settings.is_empty());
    }

    /// FIX 3: a `reconnect`-classed setting is persisted immediately but
    /// flagged as not yet effective until the next connection, without
    /// requiring any restart.
    #[test]
    fn reconnect_setting_change_is_pending_without_a_restart_flag() {
        let path = temp_path("reconnect-setting");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let mut updated = state.settings().clone();
        updated.network.upnp = !updated.network.upnp;
        state.update_settings(updated).unwrap();

        let snapshot = state.snapshot();
        assert!(!snapshot.restart_required);
        assert!(!snapshot.host_restart_required);
        assert!(snapshot
            .pending_settings
            .iter()
            .any(|key| key == "network.upnp"));
    }

    /// FIX 3: the deployment mode is the one setting `AppModel` actually
    /// derives from config. Changing it must never silently leave the
    /// running model under the old mode: it is recorded as an
    /// application-restart-requiring change, and `self.app` is left
    /// untouched until the process actually restarts.
    #[test]
    fn deployment_mode_change_sets_restart_required_and_leaves_app_model_untouched() {
        let path = temp_path("mode-setting");
        let mut state = RuntimeState::from_settings_path(Some(path)).unwrap();
        let mode_before = state.app.is_local_mode();

        let mut updated = state.settings().clone();
        updated.network.local_no_auth = !updated.network.local_no_auth;
        state.update_settings(updated).unwrap();

        let snapshot = state.snapshot();
        assert!(snapshot.restart_required);
        assert!(snapshot
            .pending_settings
            .iter()
            .any(|key| key == "network.local_no_auth"));
        assert_eq!(state.app.is_local_mode(), mode_before);
    }

    /// FIX 3: an update rejected by validation must not leave any
    /// pending-effect bookkeeping behind either -- the whole update is
    /// atomic, not just the settings file.
    #[test]
    fn invalid_update_leaves_pending_effects_and_app_model_untouched() {
        let path = temp_path("invalid-setting");
        let mut state = RuntimeState::from_settings_path(Some(path.clone())).unwrap();

        let mut valid = state.settings().clone();
        valid.host.name = "Confirmed host name".to_string();
        state.update_settings(valid.clone()).unwrap();
        let mode_before = state.app.is_local_mode();
        let snapshot_before = state.snapshot();

        let mut invalid = valid.clone();
        invalid.network.local_no_auth = !invalid.network.local_no_auth;
        invalid.video.fps = 0;
        assert!(state.update_settings(invalid).is_err());

        assert_eq!(load(&path).unwrap().config, valid);
        assert_eq!(state.app.is_local_mode(), mode_before);
        let snapshot_after = state.snapshot();
        assert_eq!(
            snapshot_after.restart_required,
            snapshot_before.restart_required
        );
        assert_eq!(
            snapshot_after.pending_settings,
            snapshot_before.pending_settings
        );
    }

    /// An accepted start that carried no events proves nothing about the
    /// child, so the model stays where the intent left it. `HostAgent::start`
    /// returns an empty event list whenever it was already starting, ready,
    /// stopping, or in backoff; treating that as readiness is how the shell
    /// came to claim a host was up while its child was crashing.
    #[test]
    fn an_accepted_start_with_no_events_leaves_the_host_starting() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state.apply_host_start_outcome(Ok(Vec::new())).unwrap();
        assert_eq!(result.snapshot.app.host_status, HostStatus::Starting);
        assert!(result.events.is_empty());
    }

    /// A spawned child is not a ready child: `Started` is reported before
    /// the startup grace period has passed.
    #[test]
    fn a_spawned_child_is_not_yet_a_ready_host() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state
            .apply_host_start_outcome(Ok(vec![HostAgentEvent::Started { pid: Some(11) }]))
            .unwrap();
        assert_eq!(result.snapshot.app.host_status, HostStatus::Starting);
    }

    /// The agent's own `Ready` event is the one thing that does prove it.
    #[test]
    fn an_agent_ready_event_transitions_to_ready() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state
            .apply_host_start_outcome(Ok(vec![HostAgentEvent::Ready]))
            .unwrap();
        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }

    /// A typed agent failure in the accepted response becomes a typed
    /// failed state carrying a fixed description, never the agent's own
    /// output.
    #[test]
    fn an_agent_failure_event_transitions_to_a_typed_failure() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state
            .apply_host_start_outcome(Ok(vec![HostAgentEvent::Failed {
                code: HostErrorCode::PreflightUnavailable,
            }]))
            .unwrap();
        match result.snapshot.app.host_status {
            HostStatus::Failed { message, retryable } => {
                assert_eq!(message, "no usable host capture backend was found");
                assert!(retryable);
            }
            other => panic!("expected a typed failure, got {other:?}"),
        }
    }

    /// FIX 4: a failing host-agent start call must leave `AppModel` in a
    /// typed failed state, never an optimistic ready one.
    #[test]
    fn host_start_failure_outcome_is_a_typed_failed_state_not_an_optimistic_ready_one() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state
            .apply_host_start_outcome(Err(HostAgentBridgeError::ConnectionFailed))
            .unwrap();
        assert!(matches!(
            result.snapshot.app.host_status,
            HostStatus::Failed { .. }
        ));
    }

    /// FIX 4: `DisableHosting`'s intent has already moved `host_status` to
    /// `Disabled`; a failed stop call must still be surfaced as a typed
    /// error rather than silently discarded.
    #[test]
    fn host_stop_failure_outcome_is_a_typed_error() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        state.apply_host_start_outcome(Ok(Vec::new())).unwrap();
        state.dispatch(RuntimeCommand::DisableHosting).unwrap();

        let error = state
            .apply_host_stop_outcome(Err(HostAgentBridgeError::Timeout))
            .expect_err("a failed stop must not be silently swallowed");
        assert_eq!(
            error,
            RuntimeError::CommandRejected {
                code: AppErrorCode::Unavailable,
                retryable: true,
            }
        );
    }
}
