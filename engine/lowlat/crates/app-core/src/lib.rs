use openstream_settings::AppConfig;
pub use openstream_settings::setting_descriptors;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const DEFAULT_REQUEST_TTL_MS: u64 = 30_000;
pub const MAX_DEVICES: usize = 256;
pub const MAX_REQUEST_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentMode {
    Local,
    Secure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppState {
    SignedOut,
    Authenticating,
    Ready,
    RequestingConnection {
        device_id: String,
        request_id: String,
    },
    WaitingForApproval {
        device_id: String,
        request_id: String,
    },
    Connecting {
        device_id: String,
    },
    Negotiating {
        device_id: String,
    },
    Connected {
        device_id: String,
        session_id: String,
        generation: u64,
    },
    Reconnecting {
        device_id: String,
        session_id: String,
    },
    Disconnecting {
        device_id: String,
    },
    Failed {
        code: AppErrorCode,
        retryable: bool,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Disabled,
    Starting,
    Ready,
    Failed { message: String, retryable: bool },
}

/// Absent fields deserialize to "not granted", so a broker that omits a class
/// this build knows about can only ever narrow the set, never silently widen
/// it, and a partial object is a smaller grant rather than a parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PermissionSet {
    pub view: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub gamepad: bool,
    pub clipboard: bool,
    pub microphone: bool,
    pub tablet: bool,
    pub virtual_usb: bool,
}

impl PermissionSet {
    /// Zero authority. This is what an idle, signed-out, or failed app holds:
    /// `view_only` still grants the right to see the remote screen, which is
    /// not something a session that does not exist should confer.
    pub const fn none() -> Self {
        Self {
            view: false,
            keyboard: false,
            mouse: false,
            gamepad: false,
            clipboard: false,
            microphone: false,
            tablet: false,
            virtual_usb: false,
        }
    }

    /// True when no capability at all is granted.
    pub const fn is_empty(self) -> bool {
        !(self.view
            || self.keyboard
            || self.mouse
            || self.gamepad
            || self.clipboard
            || self.microphone
            || self.tablet
            || self.virtual_usb)
    }

    pub const fn view_only() -> Self {
        Self {
            view: true,
            keyboard: false,
            mouse: false,
            gamepad: false,
            clipboard: false,
            microphone: false,
            tablet: false,
            virtual_usb: false,
        }
    }

    pub const fn full() -> Self {
        Self {
            view: true,
            keyboard: true,
            mouse: true,
            gamepad: true,
            clipboard: true,
            microphone: true,
            tablet: true,
            virtual_usb: true,
        }
    }

    pub const fn intersect(self, available: Self) -> Self {
        Self {
            view: self.view && available.view,
            keyboard: self.keyboard && available.keyboard,
            mouse: self.mouse && available.mouse,
            gamepad: self.gamepad && available.gamepad,
            clipboard: self.clipboard && available.clipboard,
            microphone: self.microphone && available.microphone,
            tablet: self.tablet && available.tablet,
            virtual_usb: self.virtual_usb && available.virtual_usb,
        }
    }
}

impl Default for PermissionSet {
    /// A permission set that materialises from nothing -- a `#[serde(default)]`
    /// field, a `Default::default()` placeholder -- must grant nothing. A
    /// caller that wants the view right has to ask for it by name.
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub online: bool,
    pub hosting_enabled: bool,
    pub connected_guests: u16,
}

impl DeviceSummary {
    pub fn online(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            platform: "unknown".to_string(),
            online: true,
            hosting_enabled: true,
            connected_guests: 0,
        }
    }

    pub fn offline(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut device = Self::online(id, name);
        device.online = false;
        device.hosting_enabled = false;
        device
    }
}

/// Repository-neutral identity captured when a device joins the control plane.
/// The public key is durable identity material, not a bearer credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: [u8; 32],
    pub enrolled_at_ms: u64,
}

/// Durable trust state for an enrolled device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    Pending,
    Trusted,
    Revoked,
}

/// Repository-neutral update used for both trust and revocation changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustUpdate {
    pub device_id: String,
    pub state: DeviceTrustState,
    pub changed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRequest {
    pub request_id: String,
    pub device_id: String,
    pub requested: PermissionSet,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl ConnectionRequest {
    /// Return whether the request can no longer be approved or rejected as a
    /// live request.
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    fn validate(&self, now_ms: u64) -> Result<(), AppError> {
        validate_id("request_id", &self.request_id)?;
        validate_id("device_id", &self.device_id)?;
        if !self.requested.view {
            return Err(AppError::new(
                AppErrorCode::PermissionDenied,
                false,
                "a connection request must include view permission",
            ));
        }
        if self.expires_at_ms <= self.created_at_ms || self.is_expired(now_ms) {
            return Err(AppError::new(
                AppErrorCode::ExpiredRequest,
                false,
                "connection request is expired",
            ));
        }
        if self.expires_at_ms - self.created_at_ms > DEFAULT_REQUEST_TTL_MS {
            return Err(AppError::new(
                AppErrorCode::InvalidRequest,
                false,
                "connection request lifetime exceeds the supported bound",
            ));
        }
        Ok(())
    }
}

/// Runtime truth for one diagnostic probe.
///
/// This is a closed set decided in Rust, never inferred by a consumer from
/// prose. A shell that has to guess -- treating any string it does not
/// recognise as working -- turns "not implemented", "disabled", or "not
/// configured" into a green check, which is precisely the failure mode that
/// makes hardware debugging miserable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticState {
    /// Probed and working.
    Available,
    /// Not probed yet, or waiting on something else to start.
    Pending,
    /// Implemented and usable, but not covered by the acceptance gates.
    Experimental,
    /// Implemented, but unusable here: absent hardware, denied permission,
    /// or a policy that switches it off.
    Unavailable,
    /// No implementation exists on this platform. Distinct from
    /// `Unavailable`, which a configuration change could resolve.
    NotImplemented,
}

impl DiagnosticState {
    /// Whether the probe reports a working capability. Nothing but
    /// `Available` does.
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// One probe result: a machine-readable state plus operator-facing prose.
/// Consumers render `detail`; they branch only on `state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub state: DiagnosticState,
    pub detail: String,
}

impl Diagnostic {
    pub fn new(state: DiagnosticState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
        }
    }

    pub fn available(detail: impl Into<String>) -> Self {
        Self::new(DiagnosticState::Available, detail)
    }

    pub fn pending(detail: impl Into<String>) -> Self {
        Self::new(DiagnosticState::Pending, detail)
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(DiagnosticState::Unavailable, detail)
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(DiagnosticState::NotImplemented, detail)
    }
}

impl Default for Diagnostic {
    fn default() -> Self {
        Self::pending("Not probed yet.")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiagnosticSnapshot {
    pub signal: Diagnostic,
    pub direct_udp: Diagnostic,
    pub stun: Diagnostic,
    pub relay: Diagnostic,
    pub turn: Diagnostic,
    pub capture_backend: Diagnostic,
    pub encoder: Diagnostic,
    pub decoder: Diagnostic,
    pub renderer: Diagnostic,
    pub audio: Diagnostic,
    pub input: Diagnostic,
    pub virtual_devices: Diagnostic,
    pub last_error: Option<AppErrorCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppErrorCode {
    InvalidCommand,
    InvalidRequest,
    InvalidState,
    DeviceUnavailable,
    DuplicateRequest,
    ExpiredRequest,
    PermissionDenied,
    AuthenticationRequired,
    Unavailable,
    Transport,
    Internal,
}

impl AppErrorCode {
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::DeviceUnavailable | Self::Unavailable | Self::Transport
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppError {
    pub code: AppErrorCode,
    pub retryable: bool,
    pub message: String,
}

impl AppError {
    fn new(code: AppErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> AppErrorCode {
        self.code
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

/// Why a connection request was rejected. Expiry is a domain outcome rather
/// than an untyped timeout, so both peers can render and audit it consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionRejectReason {
    Denied,
    Expired,
}

/// Short name used by control-plane implementations and future repositories.
pub type RejectReason = ConnectionRejectReason;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppCommand {
    BeginAuthentication,
    AuthenticationSucceeded,
    AuthenticationFailed {
        retryable: bool,
    },
    SignOut,
    Connect {
        device_id: String,
        request_id: String,
        requested: PermissionSet,
        now_ms: u64,
    },
    ApproveRequest {
        request_id: String,
        available: PermissionSet,
        now_ms: u64,
    },
    RejectRequest {
        request_id: String,
        now_ms: u64,
    },
    Tick {
        now_ms: u64,
    },
    ConnectionNegotiating,
    ConnectionEstablished {
        session_id: String,
        generation: u64,
    },
    /// Establishment failed before an authenticated session existed. This is
    /// distinct from `ConnectionLost`: there is no active session to put into
    /// reconnecting state, but the caller still needs a typed terminal
    /// outcome instead of leaving the model stuck in `Connecting`.
    ConnectionFailed {
        retryable: bool,
    },
    ConnectionLost {
        retryable: bool,
    },
    Disconnect,
    Disconnected,
    EnableHosting,
    DisableHosting,
    /// The agent observed its child leave a ready state and start again --
    /// a crash followed by a restart, or a backoff wait. This is an
    /// observation, not an intent: it never enables hosting the operator
    /// turned off, so a `Disabled` model stays disabled.
    HostStarting,
    HostReady,
    HostFailed {
        message: String,
        retryable: bool,
    },
    /// Acknowledge a terminal failure and return to a usable idle state.
    /// Without this there is no exit from `AppState::Failed`.
    ClearFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppEvent {
    AuthenticationStarted,
    AuthenticationFailed {
        retryable: bool,
    },
    SignedOut,
    AuthenticationRequired,
    ApprovalRequired(ConnectionRequest),
    ConnectionApproved {
        request_id: String,
        permissions: PermissionSet,
    },
    ConnectionRejected {
        request_id: String,
        reason: ConnectionRejectReason,
    },
    ConnectionNegotiationStarted,
    ConnectionReady {
        session_id: String,
        generation: u64,
    },
    ConnectionFailed {
        retryable: bool,
    },
    ReconnectStarted,
    DisconnectRequested,
    Disconnected,
    HostStartRequested,
    /// The agent's child left a ready state and is starting again.
    HostStarting,
    HostReady,
    HostStopRequested,
    HostFailed {
        code: AppErrorCode,
    },
    FailureCleared,
}

#[derive(Debug, Clone)]
pub struct AppModel {
    mode: DeploymentMode,
    state: AppState,
    host_status: HostStatus,
    devices: Vec<DeviceSummary>,
    pending_request: Option<ConnectionRequest>,
    used_request_ids: Vec<String>,
    active_device_id: Option<String>,
    active_session_id: Option<String>,
    active_permissions: PermissionSet,
}

/// Secret-free snapshot exposed to a product shell over local IPC.
///
/// Session credentials, pairing JSON, relay tickets, and private keys are
/// deliberately absent. The shell receives state and capability observations;
/// the Rust control/session owners retain all bearer material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub mode: DeploymentMode,
    pub state: AppState,
    pub host_status: HostStatus,
    pub devices: Vec<DeviceSummary>,
    pub pending_request: Option<ConnectionRequest>,
    pub active_device_id: Option<String>,
    pub active_session_id: Option<String>,
    pub active_permissions: PermissionSet,
    pub diagnostics: DiagnosticSnapshot,
}

impl AppModel {
    pub fn local_default() -> Self {
        Self {
            mode: DeploymentMode::Local,
            state: AppState::Ready,
            host_status: HostStatus::Disabled,
            devices: Vec::new(),
            pending_request: None,
            used_request_ids: Vec::new(),
            active_device_id: None,
            active_session_id: None,
            active_permissions: PermissionSet::none(),
        }
    }

    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        config.validate().map_err(|error| {
            AppError::new(AppErrorCode::InvalidRequest, false, error.to_string())
        })?;
        let mut model = Self::local_default();
        model.mode = if config.network.local_no_auth {
            DeploymentMode::Local
        } else {
            DeploymentMode::Secure
        };
        model.state = if model.mode == DeploymentMode::Local {
            AppState::Ready
        } else {
            AppState::SignedOut
        };
        Ok(model)
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn host_status(&self) -> HostStatus {
        self.host_status.clone()
    }

    pub const fn is_local_mode(&self) -> bool {
        matches!(self.mode, DeploymentMode::Local)
    }

    pub const fn active_permissions(&self) -> PermissionSet {
        self.active_permissions
    }

    /// Drop every trace of an active session. Terminal paths must all go
    /// through here so none of them can leave a live `active_permissions`
    /// behind a dead session.
    fn clear_active_session(&mut self) {
        self.active_device_id = None;
        self.active_session_id = None;
        self.active_permissions = PermissionSet::none();
        self.pending_request = None;
    }

    pub fn add_device(&mut self, device: DeviceSummary) {
        if let Some(existing) = self.devices.iter_mut().find(|item| item.id == device.id) {
            *existing = device;
        } else if self.devices.len() < MAX_DEVICES {
            self.devices.push(device);
        }
    }

    /// Replace the discovery result supplied by the authenticated control
    /// plane. The UI cannot call this through `AppCommand`; only the runtime
    /// reconciliation boundary may replace server observations.
    pub fn replace_devices(&mut self, devices: Vec<DeviceSummary>) {
        self.devices = devices.into_iter().take(MAX_DEVICES).collect();
    }

    pub fn devices(&self) -> &[DeviceSummary] {
        &self.devices
    }

    /// Build a UI-safe state snapshot without exposing session bearer data.
    pub fn snapshot(&self, diagnostics: DiagnosticSnapshot) -> AppSnapshot {
        AppSnapshot {
            mode: self.mode,
            state: self.state.clone(),
            host_status: self.host_status.clone(),
            devices: self.devices.clone(),
            pending_request: self.pending_request.clone(),
            active_device_id: self.active_device_id.clone(),
            active_session_id: self.active_session_id.clone(),
            active_permissions: self.active_permissions,
            diagnostics,
        }
    }

    pub fn dispatch(&mut self, command: AppCommand) -> Result<Vec<AppEvent>, AppError> {
        match command {
            AppCommand::BeginAuthentication => {
                if self.mode == DeploymentMode::Local {
                    return Err(AppError::new(
                        AppErrorCode::InvalidState,
                        false,
                        "local mode does not require account authentication",
                    ));
                }
                if !matches!(self.state, AppState::SignedOut) {
                    return Err(invalid_state(
                        "authentication can start only from signed out",
                    ));
                }
                self.state = AppState::Authenticating;
                Ok(vec![AppEvent::AuthenticationStarted])
            }
            AppCommand::AuthenticationSucceeded => {
                if !matches!(self.state, AppState::Authenticating) {
                    return Err(invalid_state("authentication succeeded in the wrong state"));
                }
                self.state = AppState::Ready;
                Ok(Vec::new())
            }
            AppCommand::AuthenticationFailed { retryable } => {
                if !matches!(self.state, AppState::Authenticating) {
                    return Err(invalid_state("authentication failed in the wrong state"));
                }
                self.state = AppState::SignedOut;
                Ok(vec![AppEvent::AuthenticationFailed { retryable }])
            }
            AppCommand::SignOut => {
                if !matches!(self.state, AppState::Ready) {
                    return Err(invalid_state("sign out requires an idle ready state"));
                }
                self.clear_active_session();
                self.state = if self.mode == DeploymentMode::Local {
                    AppState::Ready
                } else {
                    AppState::SignedOut
                };
                Ok(vec![AppEvent::SignedOut])
            }
            AppCommand::Connect {
                device_id,
                request_id,
                requested,
                now_ms,
            } => self.connect(device_id, request_id, requested, now_ms),
            AppCommand::ApproveRequest {
                request_id,
                available,
                now_ms,
            } => self.approve(request_id, available, now_ms),
            AppCommand::RejectRequest { request_id, now_ms } => {
                let request = self.take_pending(&request_id, now_ms)?;
                self.state = AppState::Ready;
                Ok(vec![AppEvent::ConnectionRejected {
                    request_id: request.request_id,
                    reason: ConnectionRejectReason::Denied,
                }])
            }
            AppCommand::Tick { now_ms } => {
                if let Some(request) = &self.pending_request {
                    if request.is_expired(now_ms) {
                        let request_id = request.request_id.clone();
                        self.pending_request = None;
                        self.state = AppState::Ready;
                        return Ok(vec![AppEvent::ConnectionRejected {
                            request_id,
                            reason: ConnectionRejectReason::Expired,
                        }]);
                    }
                }
                Ok(Vec::new())
            }
            AppCommand::ConnectionNegotiating => {
                let device_id = match &self.state {
                    AppState::Connecting { device_id } => device_id.clone(),
                    _ => return Err(invalid_state("negotiation requires a connecting request")),
                };
                self.state = AppState::Negotiating { device_id };
                Ok(vec![AppEvent::ConnectionNegotiationStarted])
            }
            AppCommand::ConnectionEstablished {
                session_id,
                generation,
            } => {
                validate_id("session_id", &session_id)?;
                if generation == 0 {
                    return Err(AppError::new(
                        AppErrorCode::InvalidRequest,
                        false,
                        "session generation must be positive",
                    ));
                }
                let device_id = match (&self.state, &self.active_device_id) {
                    (AppState::Connecting { device_id }, _)
                    | (AppState::Negotiating { device_id }, _) => device_id.clone(),
                    (AppState::Reconnecting { device_id, .. }, _) => device_id.clone(),
                    _ => return Err(invalid_state("connection established in the wrong state")),
                };
                self.active_device_id = Some(device_id.clone());
                self.active_session_id = Some(session_id.clone());
                self.state = AppState::Connected {
                    device_id,
                    session_id: session_id.clone(),
                    generation,
                };
                Ok(vec![AppEvent::ConnectionReady {
                    session_id,
                    generation,
                }])
            }
            AppCommand::ConnectionFailed { retryable } => {
                let active = matches!(
                    self.state,
                    AppState::RequestingConnection { .. }
                        | AppState::WaitingForApproval { .. }
                        | AppState::Connecting { .. }
                        | AppState::Negotiating { .. }
                        | AppState::Reconnecting { .. }
                );
                if !active {
                    return Err(invalid_state(
                        "connection failure requires an active connection attempt",
                    ));
                }
                self.clear_active_session();
                self.state = AppState::Failed {
                    code: if retryable {
                        AppErrorCode::Unavailable
                    } else {
                        AppErrorCode::Transport
                    },
                    retryable,
                    message: if retryable {
                        "connection could not be established".into()
                    } else {
                        "connection could not be established and cannot be retried".into()
                    },
                };
                Ok(vec![AppEvent::ConnectionFailed { retryable }])
            }
            AppCommand::ConnectionLost { retryable } => {
                // A reconnect attempt can itself fail, so a loss is accepted
                // from `Reconnecting` as well as `Connected`.
                let (device_id, session_id) = match &self.state {
                    AppState::Connected {
                        device_id,
                        session_id,
                        ..
                    }
                    | AppState::Reconnecting {
                        device_id,
                        session_id,
                    } => (device_id.clone(), session_id.clone()),
                    _ => return Err(invalid_state("connection loss requires an active session")),
                };
                if retryable {
                    self.state = AppState::Reconnecting {
                        device_id,
                        session_id,
                    };
                    Ok(vec![AppEvent::ReconnectStarted])
                } else {
                    // Terminal loss is a teardown. Holding the session id and
                    // the granted permissions here would leave the model
                    // advertising the authority of a session that is gone.
                    self.clear_active_session();
                    self.state = AppState::Failed {
                        code: AppErrorCode::Transport,
                        retryable: false,
                        message: "connection ended and cannot be retried".into(),
                    };
                    Ok(vec![AppEvent::Disconnected])
                }
            }
            AppCommand::ClearFailure => {
                if !matches!(self.state, AppState::Failed { .. }) {
                    return Err(invalid_state("no failure to clear"));
                }
                self.clear_active_session();
                self.state = if self.mode == DeploymentMode::Local {
                    AppState::Ready
                } else {
                    AppState::SignedOut
                };
                Ok(vec![AppEvent::FailureCleared])
            }
            AppCommand::Disconnect => {
                let device_id = match &self.state {
                    AppState::Connected { device_id, .. }
                    | AppState::Reconnecting { device_id, .. } => device_id.clone(),
                    AppState::WaitingForApproval { .. }
                    | AppState::Connecting { .. }
                    | AppState::Negotiating { .. } => {
                        self.pending_request = None;
                        self.state = AppState::Ready;
                        return Ok(vec![AppEvent::Disconnected]);
                    }
                    _ => return Err(invalid_state("nothing is connected")),
                };
                self.state = AppState::Disconnecting { device_id };
                Ok(vec![AppEvent::DisconnectRequested])
            }
            AppCommand::Disconnected => {
                if !matches!(self.state, AppState::Disconnecting { .. }) {
                    return Err(invalid_state("disconnect completion is not expected"));
                }
                self.clear_active_session();
                self.state = AppState::Ready;
                Ok(vec![AppEvent::Disconnected])
            }
            AppCommand::EnableHosting => match self.host_status {
                HostStatus::Disabled | HostStatus::Failed { .. } => {
                    self.host_status = HostStatus::Starting;
                    Ok(vec![AppEvent::HostStartRequested])
                }
                HostStatus::Starting | HostStatus::Ready => Ok(Vec::new()),
            },
            AppCommand::DisableHosting => {
                let was_active = !matches!(self.host_status, HostStatus::Disabled);
                self.host_status = HostStatus::Disabled;
                Ok(if was_active {
                    vec![AppEvent::HostStopRequested]
                } else {
                    Vec::new()
                })
            }
            AppCommand::HostStarting => {
                // Only a model that already believes hosting is wanted may
                // be moved back to `Starting`. `Disabled` is the operator's
                // decision and an agent observation does not overturn it.
                if matches!(self.host_status, HostStatus::Disabled) {
                    return Err(AppError::new(
                        AppErrorCode::InvalidState,
                        false,
                        "hosting is disabled",
                    ));
                }
                if matches!(self.host_status, HostStatus::Starting) {
                    return Ok(Vec::new());
                }
                self.host_status = HostStatus::Starting;
                Ok(vec![AppEvent::HostStarting])
            }
            AppCommand::HostReady => {
                if !matches!(self.host_status, HostStatus::Starting | HostStatus::Ready) {
                    return Err(invalid_state("host is not starting"));
                }
                self.host_status = HostStatus::Ready;
                Ok(vec![AppEvent::HostReady])
            }
            AppCommand::HostFailed { message, retryable } => {
                if matches!(self.host_status, HostStatus::Disabled) {
                    return Err(invalid_state("disabled host cannot report a failure"));
                }
                self.host_status = HostStatus::Failed { message, retryable };
                Ok(vec![AppEvent::HostFailed {
                    code: if retryable {
                        AppErrorCode::Unavailable
                    } else {
                        AppErrorCode::Internal
                    },
                }])
            }
        }
    }

    fn connect(
        &mut self,
        device_id: String,
        request_id: String,
        requested: PermissionSet,
        now_ms: u64,
    ) -> Result<Vec<AppEvent>, AppError> {
        if !matches!(self.state, AppState::Ready) {
            return Err(invalid_state("connect requires the ready state"));
        }
        validate_id("device_id", &device_id)?;
        validate_id("request_id", &request_id)?;
        if self.used_request_ids.iter().any(|item| item == &request_id) {
            return Err(AppError::new(
                AppErrorCode::DuplicateRequest,
                false,
                "request ID has already been used",
            ));
        }
        let device = self
            .devices
            .iter()
            .find(|item| item.id == device_id)
            .ok_or_else(|| {
                AppError::new(
                    AppErrorCode::DeviceUnavailable,
                    true,
                    "device is not in the directory",
                )
            })?;
        if !device.online || !device.hosting_enabled {
            return Err(AppError::new(
                AppErrorCode::DeviceUnavailable,
                true,
                "device is offline or hosting is disabled",
            ));
        }
        let expires_at_ms = now_ms.checked_add(DEFAULT_REQUEST_TTL_MS).ok_or_else(|| {
            AppError::new(
                AppErrorCode::InvalidRequest,
                false,
                "request timestamp overflow",
            )
        })?;
        let request = ConnectionRequest {
            request_id: request_id.clone(),
            device_id: device_id.clone(),
            requested,
            created_at_ms: now_ms,
            expires_at_ms,
        };
        request.validate(now_ms)?;
        self.used_request_ids.push(request_id.clone());
        if self.used_request_ids.len() > 256 {
            self.used_request_ids.remove(0);
        }
        self.pending_request = Some(request.clone());
        self.state = AppState::WaitingForApproval {
            device_id,
            request_id,
        };
        Ok(vec![AppEvent::ApprovalRequired(request)])
    }

    fn approve(
        &mut self,
        request_id: String,
        available: PermissionSet,
        now_ms: u64,
    ) -> Result<Vec<AppEvent>, AppError> {
        let request = self.take_pending(&request_id, now_ms)?;
        let permissions = request.requested.intersect(available);
        if request.requested.view && !permissions.view {
            return Err(AppError::new(
                AppErrorCode::PermissionDenied,
                false,
                "host cannot grant the required view permission",
            ));
        }
        let device_id = request.device_id.clone();
        self.active_permissions = permissions;
        self.active_device_id = Some(device_id.clone());
        self.state = AppState::Connecting { device_id };
        Ok(vec![AppEvent::ConnectionApproved {
            request_id,
            permissions,
        }])
    }

    fn take_pending(
        &mut self,
        request_id: &str,
        now_ms: u64,
    ) -> Result<ConnectionRequest, AppError> {
        let request = self
            .pending_request
            .as_ref()
            .ok_or_else(|| invalid_state("no connection request is awaiting a decision"))?;
        if request.request_id != request_id {
            return Err(AppError::new(
                AppErrorCode::InvalidRequest,
                false,
                "request ID does not match the pending request",
            ));
        }
        if now_ms >= request.expires_at_ms {
            self.pending_request = None;
            self.state = AppState::Ready;
            return Err(AppError::new(
                AppErrorCode::ExpiredRequest,
                false,
                "connection request expired",
            ));
        }
        self.pending_request
            .take()
            .ok_or_else(|| invalid_state("pending request disappeared"))
    }
}

fn validate_id(field: &str, value: &str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(AppError::new(
            AppErrorCode::InvalidRequest,
            false,
            format!("{field} is empty, too long, or contains control characters"),
        ));
    }
    Ok(())
}

fn invalid_state(message: &str) -> AppError {
    AppError::new(AppErrorCode::InvalidState, false, message)
}

#[cfg(test)]
mod tests {
    use super::{
        AppCommand, AppErrorCode, AppEvent, AppModel, AppState, DiagnosticSnapshot, HostStatus,
        PermissionSet,
    };
    use openstream_settings::{CapabilityState, SettingVisibility, setting_descriptors};

    fn model() -> AppModel {
        AppModel::local_default()
    }

    #[test]
    fn local_mode_starts_ready_without_account_authentication() {
        let model = model();
        assert_eq!(model.state(), &AppState::Ready);
        assert_eq!(model.host_status(), HostStatus::Disabled);
        assert!(model.is_local_mode());
    }

    #[test]
    fn connect_requires_an_online_known_device_and_enters_approval() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        let events = model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .expect("known device connects");
        assert!(
            matches!(model.state(), AppState::WaitingForApproval { request_id, .. } if request_id == "request-1")
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, AppEvent::ApprovalRequired(_)))
        );
    }

    #[test]
    fn expired_or_duplicate_requests_fail_closed() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .unwrap();
        let error = model
            .dispatch(AppCommand::ApproveRequest {
                request_id: "request-1".into(),
                available: PermissionSet::full(),
                now_ms: 100_001,
            })
            .expect_err("expired request cannot be approved");
        assert_eq!(error.code(), AppErrorCode::ExpiredRequest);

        let error = model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100_002,
            })
            .expect_err("duplicate request id is not reusable");
        assert_eq!(error.code(), AppErrorCode::DuplicateRequest);
    }

    #[test]
    fn approval_can_only_reduce_requested_permissions() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet {
                    view: true,
                    keyboard: true,
                    mouse: true,
                    gamepad: true,
                    clipboard: true,
                    microphone: true,
                    tablet: true,
                    virtual_usb: true,
                },
                now_ms: 100,
            })
            .unwrap();
        let available = PermissionSet {
            view: true,
            keyboard: false,
            mouse: false,
            gamepad: true,
            clipboard: false,
            microphone: false,
            tablet: false,
            virtual_usb: false,
        };
        model
            .dispatch(AppCommand::ApproveRequest {
                request_id: "request-1".into(),
                available,
                now_ms: 200,
            })
            .expect("approval succeeds");
        assert!(matches!(model.state(), AppState::Connecting { .. }));
        assert!(model.active_permissions().gamepad);
        assert!(!model.active_permissions().keyboard);
    }

    #[test]
    fn invalid_request_cannot_escalate_or_disconnect_another_session() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        let error = model
            .dispatch(AppCommand::Connect {
                device_id: "unknown".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .expect_err("unknown device is refused");
        assert_eq!(error.code(), AppErrorCode::DeviceUnavailable);
        assert_eq!(model.state(), &AppState::Ready);
        let error = model
            .dispatch(AppCommand::Disconnect)
            .expect_err("nothing is connected");
        assert_eq!(error.code(), AppErrorCode::InvalidState);
    }

    #[test]
    fn connection_reconnect_and_disconnect_are_explicit_state_transitions() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .unwrap();
        model
            .dispatch(AppCommand::ApproveRequest {
                request_id: "request-1".into(),
                available: PermissionSet::view_only(),
                now_ms: 200,
            })
            .unwrap();
        model
            .dispatch(AppCommand::ConnectionEstablished {
                session_id: "session-1".into(),
                generation: 1,
            })
            .unwrap();
        assert!(matches!(model.state(), AppState::Connected { .. }));
        model
            .dispatch(AppCommand::ConnectionLost { retryable: true })
            .unwrap();
        assert!(matches!(model.state(), AppState::Reconnecting { .. }));
        model
            .dispatch(AppCommand::ConnectionEstablished {
                session_id: "session-1".into(),
                generation: 2,
            })
            .unwrap();
        model.dispatch(AppCommand::Disconnect).unwrap();
        model.dispatch(AppCommand::Disconnected).unwrap();
        assert!(matches!(model.state(), AppState::Ready));
    }

    fn connected_model() -> AppModel {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::full(),
                now_ms: 100,
            })
            .unwrap();
        model
            .dispatch(AppCommand::ApproveRequest {
                request_id: "request-1".into(),
                available: PermissionSet::full(),
                now_ms: 200,
            })
            .unwrap();
        model
            .dispatch(AppCommand::ConnectionEstablished {
                session_id: "session-1".into(),
                generation: 1,
            })
            .unwrap();
        model
    }

    #[test]
    fn terminal_connection_loss_drops_session_identity_and_permissions() {
        let mut model = connected_model();
        assert!(
            model
                .snapshot(DiagnosticSnapshot::default())
                .active_session_id
                .is_some()
        );
        assert!(
            model
                .snapshot(DiagnosticSnapshot::default())
                .active_permissions
                .keyboard
        );

        let events = model
            .dispatch(AppCommand::ConnectionLost { retryable: false })
            .unwrap();
        assert_eq!(events, vec![AppEvent::Disconnected]);

        let snapshot = model.snapshot(DiagnosticSnapshot::default());
        assert!(matches!(snapshot.state, AppState::Failed { .. }));
        // The authority of a dead session must not survive it. Not even the
        // view right: with no session there is nothing to view, and a
        // non-empty `active_permissions` is exactly the stale grant a later
        // caller would read as "this much is still allowed".
        assert_eq!(snapshot.active_device_id, None);
        assert_eq!(snapshot.active_session_id, None);
        assert_eq!(snapshot.active_permissions, PermissionSet::none());
        assert!(snapshot.active_permissions.is_empty());
        assert!(snapshot.pending_request.is_none());
    }

    #[test]
    fn a_terminal_failure_can_be_cleared_back_to_a_usable_state() {
        let mut model = connected_model();
        model
            .dispatch(AppCommand::ConnectionLost { retryable: false })
            .unwrap();
        assert!(matches!(model.state(), AppState::Failed { .. }));

        let events = model.dispatch(AppCommand::ClearFailure).unwrap();
        assert_eq!(events, vec![AppEvent::FailureCleared]);
        assert!(matches!(model.state(), AppState::Ready));

        // Clearing is only valid from a failed state.
        assert!(model.dispatch(AppCommand::ClearFailure).is_err());
    }

    #[test]
    fn a_reconnect_attempt_can_itself_fail_terminally() {
        let mut model = connected_model();
        model
            .dispatch(AppCommand::ConnectionLost { retryable: true })
            .unwrap();
        assert!(matches!(model.state(), AppState::Reconnecting { .. }));

        model
            .dispatch(AppCommand::ConnectionLost { retryable: false })
            .unwrap();
        let snapshot = model.snapshot(DiagnosticSnapshot::default());
        assert!(matches!(snapshot.state, AppState::Failed { .. }));
        assert_eq!(snapshot.active_session_id, None);
        assert!(snapshot.active_permissions.is_empty());
    }

    /// A child that crashes right after it was reported ready must be able
    /// to move the model back to `Starting`. Without this transition the
    /// shell keeps claiming a host is up while the agent is restarting it.
    #[test]
    fn a_restarting_child_moves_a_ready_host_back_to_starting() {
        let mut model = model();
        model.dispatch(AppCommand::EnableHosting).unwrap();
        model.dispatch(AppCommand::HostReady).unwrap();
        assert_eq!(model.host_status(), HostStatus::Ready);

        let events = model.dispatch(AppCommand::HostStarting).unwrap();
        assert_eq!(events, vec![AppEvent::HostStarting]);
        assert_eq!(model.host_status(), HostStatus::Starting);

        // Already starting is a no-op, not a repeated event.
        assert!(model.dispatch(AppCommand::HostStarting).unwrap().is_empty());
    }

    /// `HostStarting` is an observation of the agent, never an intent. It
    /// must not be able to switch hosting back on after the operator
    /// disabled it.
    #[test]
    fn a_restart_observation_cannot_re_enable_disabled_hosting() {
        let mut model = model();
        assert_eq!(model.host_status(), HostStatus::Disabled);
        assert!(model.dispatch(AppCommand::HostStarting).is_err());
        assert_eq!(model.host_status(), HostStatus::Disabled);
    }

    #[test]
    fn host_lifecycle_is_idempotent_and_reports_failures() {
        let mut model = model();
        model.dispatch(AppCommand::EnableHosting).unwrap();
        assert_eq!(model.host_status(), HostStatus::Starting);
        model.dispatch(AppCommand::HostReady).unwrap();
        assert_eq!(model.host_status(), HostStatus::Ready);
        model.dispatch(AppCommand::EnableHosting).unwrap();
        assert_eq!(model.host_status(), HostStatus::Ready);
        model
            .dispatch(AppCommand::HostFailed {
                message: "capture unavailable".into(),
                retryable: true,
            })
            .unwrap();
        assert!(matches!(model.host_status(), HostStatus::Failed { .. }));
        model.dispatch(AppCommand::DisableHosting).unwrap();
        assert_eq!(model.host_status(), HostStatus::Disabled);
    }

    #[test]
    fn domain_commands_and_state_round_trip_without_secrets() {
        let command = AppCommand::Connect {
            device_id: "mac-1".into(),
            request_id: "request-1".into(),
            requested: PermissionSet::view_only(),
            now_ms: 100,
        };
        let encoded = serde_json::to_string(&command).expect("command serializes");
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("private_key"));
        let decoded: AppCommand = serde_json::from_str(&encoded).expect("command deserializes");
        assert_eq!(decoded, command);

        let state = AppState::Connected {
            device_id: "linux-host".into(),
            session_id: "session-1".into(),
            generation: 2,
        };
        let encoded = serde_json::to_string(&state).expect("state serializes");
        let decoded: AppState = serde_json::from_str(&encoded).expect("state deserializes");
        assert_eq!(decoded, state);
    }

    #[test]
    fn app_core_exposes_the_rust_owned_settings_descriptor_catalog() {
        let descriptors = super::setting_descriptors();
        assert!(descriptors.iter().any(|descriptor| {
            descriptor.key == "client.profile"
                && descriptor.capability == CapabilityState::Available
        }));
        assert!(descriptors.iter().any(|descriptor| {
            descriptor.key == "host.capture.drm"
                && descriptor.visibility == SettingVisibility::Experimental
        }));

        let direct = setting_descriptors();
        assert_eq!(descriptors, direct);
    }

    #[test]
    fn device_control_contract_is_repository_neutral_and_secret_free() {
        let enrollment = super::DeviceEnrollment {
            device_id: "mac-1".into(),
            name: "MacBook Pro".into(),
            platform: "macos".into(),
            public_key: [7; 32],
            enrolled_at_ms: 100,
        };
        let trusted = super::DeviceTrustUpdate {
            device_id: enrollment.device_id.clone(),
            state: super::DeviceTrustState::Trusted,
            changed_at_ms: 101,
        };
        let revoked = super::DeviceTrustUpdate {
            device_id: enrollment.device_id.clone(),
            state: super::DeviceTrustState::Revoked,
            changed_at_ms: 102,
        };
        let encoded =
            serde_json::to_string(&(enrollment.clone(), trusted.clone(), revoked.clone()))
                .expect("device control values serialize");
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("private_key"));

        let decoded: (
            super::DeviceEnrollment,
            super::DeviceTrustUpdate,
            super::DeviceTrustUpdate,
        ) = serde_json::from_str(&encoded).expect("device control values deserialize");
        assert_eq!(decoded, (enrollment, trusted, revoked));
    }

    #[test]
    fn expired_request_is_a_typed_connection_rejection_event() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .expect("request is created");

        let events = model
            .dispatch(AppCommand::Tick { now_ms: 30_100 })
            .expect("expired request is observed");
        assert_eq!(
            events,
            vec![AppEvent::ConnectionRejected {
                request_id: "request-1".into(),
                reason: super::ConnectionRejectReason::Expired,
            }]
        );
    }

    #[test]
    fn explicit_request_rejection_has_a_typed_reason() {
        let mut model = model();
        model.add_device(super::DeviceSummary::online("mac-1", "Mac client"));
        model
            .dispatch(AppCommand::Connect {
                device_id: "mac-1".into(),
                request_id: "request-1".into(),
                requested: PermissionSet::view_only(),
                now_ms: 100,
            })
            .expect("request is created");

        let events = model
            .dispatch(AppCommand::RejectRequest {
                request_id: "request-1".into(),
                now_ms: 200,
            })
            .expect("request is rejected");
        assert_eq!(
            events,
            vec![AppEvent::ConnectionRejected {
                request_id: "request-1".into(),
                reason: super::ConnectionRejectReason::Denied,
            }]
        );
    }

    #[test]
    fn product_snapshot_is_serializable_and_contains_no_bearer_fields() {
        let model = AppModel::local_default();
        let snapshot = model.snapshot(DiagnosticSnapshot::default());
        let encoded = serde_json::to_string(&snapshot).expect("snapshot serializes");

        assert!(encoded.contains("host_status"));
        assert!(encoded.contains("diagnostics"));
        assert!(!encoded.contains("pairing_json"));
        assert!(!encoded.contains("relay_ticket"));
        assert!(!encoded.contains("private_key"));
    }
}
