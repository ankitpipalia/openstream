use openstream_app_core::{
    AppCommand, AppError, AppErrorCode, AppEvent, AppModel, AppSnapshot, DiagnosticSnapshot,
    PermissionSet, MAX_REQUEST_ID_BYTES,
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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::host_agent::HostAgentBridgeError;
use openstream_host_agent::HostAgentEvent;

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

/// Rust's own reading of the wall clock, in milliseconds since the Unix
/// epoch. Every `RuntimeCommand` that used to accept a frontend-supplied
/// `now_ms` reads this instead.
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
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
#[derive(Debug)]
pub struct RuntimeState {
    app: AppModel,
    settings: AppConfig,
    settings_path: Option<PathBuf>,
    descriptors: Vec<SettingDescriptor>,
    /// Settings whose new, already-persisted value is not yet reflected
    /// anywhere but the settings file itself: `self.app` was built from an
    /// older config and stays that way until a reconnect, host restart, or
    /// full application restart naturally rebuilds it.
    pending_setting_keys: BTreeSet<String>,
    /// Set once a pending change needs the whole application to restart
    /// before it is effective: a `restart_application`-classed setting, or
    /// the deployment mode itself.
    restart_required: bool,
    /// Set once a pending change needs only the host to restart.
    host_restart_required: bool,
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
            settings,
            settings_path: path,
            descriptors: setting_descriptors(),
            pending_setting_keys: BTreeSet::new(),
            restart_required: false,
            host_restart_required: false,
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
        self.reconcile_settings(&settings);
        self.settings = settings;
        Ok(())
    }

    /// Reconcile `self.app` and the pending-effect bookkeeping with a
    /// config that has already been validated and durably saved. This is
    /// only ever called after both of those succeed, so a rejected update
    /// can never leave `self.app` or the pending-effect fields touched.
    fn reconcile_settings(&mut self, next: &AppConfig) {
        let previous = &self.settings;

        if previous.network.local_no_auth != next.network.local_no_auth {
            self.restart_required = true;
            self.pending_setting_keys
                .insert(DEPLOYMENT_MODE_SETTING_KEY.to_string());
        }

        for descriptor in &self.descriptors {
            if !setting_value_changed(descriptor.key, previous, next) {
                continue;
            }
            match descriptor.apply_mode {
                // `AppModel` does not cache any client/host/input
                // preference itself (see its field list in app-core); the
                // persisted `AppConfig` handed back in every snapshot is
                // already the single source of truth for these, so a live
                // setting is already in effect once `self.settings` below
                // is updated. Nothing on `self.app` needs reconciling.
                SettingApplyMode::Live => {}
                SettingApplyMode::Reconnect => {
                    self.pending_setting_keys.insert(descriptor.key.to_string());
                }
                SettingApplyMode::RestartHost => {
                    self.host_restart_required = true;
                    self.pending_setting_keys.insert(descriptor.key.to_string());
                }
                SettingApplyMode::RestartApplication => {
                    self.restart_required = true;
                    self.pending_setting_keys.insert(descriptor.key.to_string());
                }
            }
        }
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            app: self.app.snapshot(DiagnosticSnapshot::default()),
            settings: self.settings.clone(),
            descriptors: self.descriptors.clone(),
            restart_required: self.restart_required,
            host_restart_required: self.host_restart_required,
            pending_settings: self.pending_setting_keys.iter().cloned().collect(),
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
    pub(crate) fn apply_host_start_outcome(
        &mut self,
        outcome: Result<Vec<HostAgentEvent>, HostAgentBridgeError>,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        let command = match outcome {
            Ok(_events) => AppCommand::HostReady,
            Err(error) => {
                let (message, _code, retryable) = describe_host_failure(error);
                AppCommand::HostFailed {
                    message: message.to_string(),
                    retryable,
                }
            }
        };
        let events = self.app.dispatch(command).map_err(RuntimeError::from)?;
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
        AppCommand, AppErrorCode, AppEvent, HostAgentBridgeError, RuntimeCommand, RuntimeError,
        RuntimeState,
    };
    use openstream_app_core::{ConnectionRejectReason, DeviceSummary, HostStatus, PermissionSet};
    use openstream_settings::{load, StreamProfile, CURRENT_SCHEMA_VERSION};
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

    /// FIX 4: a successful host-agent start outcome is applied as a real,
    /// typed `HostReady` transition.
    #[test]
    fn host_start_success_outcome_transitions_to_ready() {
        let mut state = RuntimeState::for_test();
        state.dispatch(RuntimeCommand::EnableHosting).unwrap();
        let result = state.apply_host_start_outcome(Ok(Vec::new())).unwrap();
        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
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
