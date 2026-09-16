use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use control_plane::{ControlPlaneClient, ControlPlaneError, DeviceTrust as ServerDeviceTrust};
use device_store::{DeviceStore, DeviceStoreError};
use host_agent::{HostAgentBridgeError, HostAgentClient};
use openstream_host_agent::HostHealth;
use openstream_settings::AppConfig;
use runtime::{
    RuntimeCommand, RuntimeDispatchResult, RuntimeError, RuntimeSnapshot, RuntimeState,
    TrustedDeviceSnapshot,
};
use session::{SessionError, SessionHealth, SessionProcessState, SessionSupervisor};
use tauri::Manager;

pub mod connect_flow;
mod control_plane;
pub mod device_store;
pub mod host_agent;
pub mod runtime;
pub mod session;

/// How often the background reconciler asks the host agent what it is
/// actually doing. The agent supervises its child on its own clock -- it
/// restarts a crashed child, backs off, and eventually gives up, none of
/// which is a reply to anything the shell asked for -- so without a poll
/// the shell's `HostStatus` only ever changes when the operator happens to
/// press a button.
const HOST_HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const SESSION_HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(250);
const HOST_STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Serialises every operation that may start or stop the host agent.
///
/// Enable and disable are each individually idempotent at the agent, which
/// is not the same as being safe to interleave. Two overlapping Tauri
/// invocations used to apply their intents under the state mutex, drop it
/// for their respective `.await`s, and then apply their outcomes in
/// whatever order the replies happened to arrive -- so a disable that won
/// the race to `AppModel` could be followed by a start that won the race to
/// the agent, leaving a running host behind a shell that said `Disabled`.
/// Holding this across the whole intent-to-outcome transaction makes the
/// order the agent sees the order the model recorded.
#[derive(Debug, Default)]
pub struct HostLifecycleLock(tokio::sync::Mutex<()>);

/// Runtime state shared between the Tauri commands and the background
/// host-health reconciler.
type SharedRuntime = Arc<Mutex<RuntimeState>>;

/// The lifecycle lock, shared the same way.
type SharedHostLock = Arc<HostLifecycleLock>;

/// Owns the native session runner. Its mutex is asynchronous because process
/// start/stop and status polling must never hold the synchronous app-state
/// mutex across an await.
type SharedSession = Arc<tokio::sync::Mutex<SessionSupervisor>>;

type SharedDeviceStore = Arc<Mutex<DeviceStore>>;

/// Holds short-lived control-plane credentials in Rust memory only. The
/// WebView receives account/device observations, never the bearer values.
type SharedControlPlane = Arc<tokio::sync::Mutex<ControlPlaneClient>>;

#[tauri::command]
fn runtime_snapshot(
    state: tauri::State<'_, SharedRuntime>,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.snapshot())
}

#[tauri::command]
fn runtime_settings(state: tauri::State<'_, SharedRuntime>) -> Result<AppConfig, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.settings().clone())
}

#[tauri::command]
async fn runtime_update_settings(
    state: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    settings: AppConfig,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let (previous, origin_changed, snapshot) = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        let previous = runtime.settings().clone();
        if previous.client.signal_origin != settings.client.signal_origin
            && !matches!(
                runtime.app_state(),
                openstream_app_core::AppState::SignedOut | openstream_app_core::AppState::Ready
            )
        {
            return Err(RuntimeError::CommandRejected {
                code: openstream_app_core::AppErrorCode::InvalidState,
                retryable: false,
            });
        }
        runtime.update_settings(settings)?;
        let origin_changed =
            previous.client.signal_origin != runtime.settings().client.signal_origin;
        (previous, origin_changed, runtime.snapshot())
    };
    if origin_changed {
        let origin = snapshot.settings.client.signal_origin.clone();
        let result = {
            let mut client = control_plane.lock().await;
            client.reconfigure(&origin)
        };
        if let Err(error) = result {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            runtime.update_settings(previous)?;
            return Err(control_plane_error_runtime(error));
        }
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        if matches!(runtime.app_state(), openstream_app_core::AppState::Ready) {
            let _ = runtime.dispatch(RuntimeCommand::SignOut)?;
            runtime.replace_devices(Vec::new());
            runtime.set_trusted_devices(Vec::new());
        }
        return Ok(runtime.snapshot());
    }
    Ok(snapshot)
}

#[tauri::command]
async fn runtime_update_setting(
    state: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    key: String,
    value: serde_json::Value,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let (previous, origin_changed, snapshot) = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        let previous = runtime.settings().clone();
        if key == "client.signal_origin"
            && !matches!(
                runtime.app_state(),
                openstream_app_core::AppState::SignedOut | openstream_app_core::AppState::Ready
            )
        {
            return Err(RuntimeError::CommandRejected {
                code: openstream_app_core::AppErrorCode::InvalidState,
                retryable: false,
            });
        }
        let snapshot = runtime.update_setting(&key, value)?;
        let origin_changed =
            previous.client.signal_origin != snapshot.settings.client.signal_origin;
        (previous, origin_changed, snapshot)
    };
    if !origin_changed {
        return Ok(snapshot);
    }
    let origin = snapshot.settings.client.signal_origin.clone();
    let result = {
        let mut client = control_plane.lock().await;
        client.reconfigure(&origin)
    };
    if let Err(error) = result {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.update_settings(previous)?;
        return Err(control_plane_error_runtime(error));
    }
    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    if matches!(runtime.app_state(), openstream_app_core::AppState::Ready) {
        let _ = runtime.dispatch(RuntimeCommand::SignOut)?;
        runtime.replace_devices(Vec::new());
        runtime.set_trusted_devices(Vec::new());
    }
    Ok(runtime.snapshot())
}

fn control_plane_retryable(error: ControlPlaneError) -> bool {
    matches!(
        error,
        ControlPlaneError::Transport
            | ControlPlaneError::ServerUnavailable
            | ControlPlaneError::RateLimited
    )
}

fn control_plane_error_runtime(error: ControlPlaneError) -> RuntimeError {
    let (code, retryable) = match error {
        ControlPlaneError::InvalidOrigin | ControlPlaneError::InvalidInput => {
            (openstream_app_core::AppErrorCode::InvalidRequest, false)
        }
        ControlPlaneError::IdentityUnavailable => {
            (openstream_app_core::AppErrorCode::Unavailable, false)
        }
        ControlPlaneError::Unauthorized | ControlPlaneError::NotAuthenticated => (
            openstream_app_core::AppErrorCode::AuthenticationRequired,
            false,
        ),
        ControlPlaneError::NotFound => {
            (openstream_app_core::AppErrorCode::DeviceUnavailable, false)
        }
        ControlPlaneError::Conflict | ControlPlaneError::Forbidden => {
            (openstream_app_core::AppErrorCode::PermissionDenied, false)
        }
        ControlPlaneError::RateLimited
        | ControlPlaneError::ServerUnavailable
        | ControlPlaneError::Transport => (openstream_app_core::AppErrorCode::Transport, true),
        ControlPlaneError::InvalidResponse => (openstream_app_core::AppErrorCode::Internal, false),
    };
    RuntimeError::CommandRejected { code, retryable }
}

fn control_plane_runtime_error(_error: RuntimeError) -> ControlPlaneError {
    ControlPlaneError::Transport
}

fn device_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn configured_device_name(state: &Mutex<RuntimeState>) -> Result<String, ControlPlaneError> {
    let runtime = state.lock().map_err(|_| ControlPlaneError::Transport)?;
    Ok(runtime.settings().device.name.clone())
}

fn to_runtime_trusted_device(device: &control_plane::PublicDevice) -> TrustedDeviceSnapshot {
    let trust = match device.trust {
        ServerDeviceTrust::Pending => openstream_app_core::DeviceTrustState::Pending,
        ServerDeviceTrust::Trusted => openstream_app_core::DeviceTrustState::Trusted,
        ServerDeviceTrust::Revoked => openstream_app_core::DeviceTrustState::Revoked,
    };
    TrustedDeviceSnapshot {
        device_id: device.device_id.clone(),
        name: device.name.clone(),
        platform: device.platform.clone(),
        enrolled_at_ms: device.enrolled_at_ms,
        trust,
        last_seen_ms: device.last_seen_ms,
        public_key_fingerprint: device.public_key_fingerprint.clone(),
    }
}

fn to_directory_device(device: &control_plane::PublicDevice) -> openstream_app_core::DeviceSummary {
    // Presence now reaches the shell through the device listing, so a device
    // the control plane last saw announcing itself is offered as connectable
    // and everything else stays visible for trust management only. The online
    // flag is advisory: the broker re-checks presence when a session is
    // actually requested, so a stale "online" costs one refused request, never
    // a session started against a machine that is not there.
    let mut summary = if device.online {
        openstream_app_core::DeviceSummary::online(device.device_id.clone(), device.name.clone())
    } else {
        openstream_app_core::DeviceSummary::offline(device.device_id.clone(), device.name.clone())
    };
    summary.platform = device.platform.clone();
    summary
}

fn apply_control_plane_devices(
    runtime: &mut RuntimeState,
    devices: &[control_plane::PublicDevice],
) {
    runtime.set_trusted_devices(devices.iter().map(to_runtime_trusted_device).collect());
    runtime.replace_devices(devices.iter().map(to_directory_device).collect());
}

async fn authenticate_account(
    runtime: &Mutex<RuntimeState>,
    control_plane: &SharedControlPlane,
    username: String,
    password: String,
    register: bool,
) -> Result<RuntimeSnapshot, ControlPlaneError> {
    let device_name = configured_device_name(runtime)?;
    {
        let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
        state
            .dispatch(RuntimeCommand::SignIn)
            .map_err(control_plane_runtime_error)?;
    }

    let auth = {
        let mut client = control_plane.lock().await;
        if register {
            client
                .register(&username, &password, &device_name, device_platform())
                .await
        } else {
            client
                .sign_in(&username, &password, &device_name, device_platform())
                .await
        }
    };
    let _account = match auth {
        Ok(account) => account,
        Err(error) => {
            let mut client = control_plane.lock().await;
            client.clear_credentials();
            drop(client);
            let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
            let _ = state.authentication_failed(control_plane_retryable(error));
            return Err(error);
        }
    };

    let devices = {
        let mut client = control_plane.lock().await;
        client.devices().await
    };
    let devices = match devices {
        Ok(devices) => devices,
        Err(error) => {
            // Authentication is not complete until the initial account
            // reconciliation succeeds. Do not leave valid bearer values in
            // the runtime while AppModel is returned to SignedOut.
            {
                let mut client = control_plane.lock().await;
                client.clear_credentials();
            }
            let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
            let _ = state.authentication_failed(control_plane_retryable(error));
            return Err(error);
        }
    };
    let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
    let _ = state
        .authentication_succeeded()
        .map_err(control_plane_runtime_error)?;
    apply_control_plane_devices(&mut state, &devices);
    Ok(state.snapshot())
}

#[tauri::command]
async fn control_plane_sign_in(
    runtime: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    username: String,
    password: String,
) -> Result<RuntimeSnapshot, ControlPlaneError> {
    authenticate_account(
        runtime.inner(),
        control_plane.inner(),
        username,
        password,
        false,
    )
    .await
}

#[tauri::command]
async fn control_plane_register(
    runtime: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    username: String,
    password: String,
) -> Result<RuntimeSnapshot, ControlPlaneError> {
    authenticate_account(
        runtime.inner(),
        control_plane.inner(),
        username,
        password,
        true,
    )
    .await
}

#[tauri::command]
async fn control_plane_refresh_devices(
    runtime: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
) -> Result<RuntimeSnapshot, ControlPlaneError> {
    let devices = {
        let mut client = control_plane.lock().await;
        client.devices().await
    }?;
    let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
    apply_control_plane_devices(&mut state, &devices);
    Ok(state.snapshot())
}

#[tauri::command]
async fn control_plane_sign_out(
    runtime: tauri::State<'_, SharedRuntime>,
    control_plane: tauri::State<'_, SharedControlPlane>,
) -> Result<RuntimeSnapshot, ControlPlaneError> {
    {
        let state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
        if !matches!(state.app_state(), openstream_app_core::AppState::Ready) {
            return Err(ControlPlaneError::InvalidInput);
        }
    }
    {
        let mut client = control_plane.lock().await;
        client.clear_credentials();
    }
    let mut state = runtime.lock().map_err(|_| ControlPlaneError::Transport)?;
    state
        .dispatch(RuntimeCommand::SignOut)
        .map_err(control_plane_runtime_error)?;
    state.replace_devices(Vec::new());
    state.set_trusted_devices(Vec::new());
    Ok(state.snapshot())
}

/// The single entry point for every user-intent command, hosting included.
/// `EnableHosting`/`DisableHosting` are not a thin pass-through to
/// `RuntimeState::dispatch`: they must also drive the real host agent, so
/// this command is `async` and delegates to `dispatch_command_with_session`,
/// which never holds the state mutex across an `.await`.
#[tauri::command]
async fn runtime_dispatch(
    state: tauri::State<'_, SharedRuntime>,
    host_lock: tauri::State<'_, SharedHostLock>,
    session: tauri::State<'_, SharedSession>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    dispatch_command_with_session(
        state.inner(),
        host_lock.inner(),
        session.inner(),
        control_plane.inner(),
        command,
    )
    .await
}

/// Tell the service whether this device is available to host.
///
/// Best effort on purpose. Hosting has already started or stopped locally by
/// the time this runs, and failing the whole command because a presence
/// heartbeat did not land would turn a cosmetic problem -- the device shows
/// as offline until the next beat -- into a refusal to host at all. In local
/// mode there is no control plane signed in and this is simply a no-op.
async fn announce_presence_best_effort(control_plane: &SharedControlPlane, online: bool) {
    let mut client = control_plane.lock().await;
    if !client.is_authenticated() {
        return;
    }
    let outcome = if online {
        client.announce_presence().await
    } else {
        client.withdraw_presence().await
    };
    if outcome.is_err() {
        // Not surfaced as a command failure; see above. Logged so an
        // operator wondering why a machine never appears has something to
        // find.
        eprintln!("OpenStream could not update host presence with the control plane");
    }
}

/// Requests this device is being asked to approve.
#[tauri::command]
async fn host_connect_requests(
    control_plane: tauri::State<'_, SharedControlPlane>,
) -> Result<Vec<control_plane::PendingConnectRequest>, RuntimeError> {
    let mut client = control_plane.lock().await;
    client
        .pending_connect_requests()
        .await
        .map_err(control_plane_error_runtime)
}

/// Approve a request and start hosting the session it created.
///
/// The capability goes to the host agent, which is the process that actually
/// runs the host end. It travels as a private file rather than as an IPC
/// field: the agent validates ownership and permissions before opening it,
/// and the capability never appears in a message, a log, or a crash dump of
/// either process.
///
/// Nothing about the credential is returned to the caller. The UI needs to
/// know that hosting started, not what the capability was, and handing a
/// bearer token to a WebView is how it ends up somewhere it cannot be
/// withdrawn from.
#[tauri::command]
async fn approve_connect_request(
    state: tauri::State<'_, SharedRuntime>,
    session: tauri::State<'_, SharedSession>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    request_id: String,
    granted: Option<openstream_app_core::PermissionSet>,
) -> Result<(), RuntimeError> {
    let credential = {
        let mut client = control_plane.lock().await;
        // The host chooses the granted set in the approval prompt -- a subset
        // of what was requested. When the UI provides none (an approval with no
        // request to narrow), fall back to granting what the request asked for,
        // derived from the broker's own pending record rather than trusted from
        // the WebView, so no path can widen the grant beyond the request. A
        // request no longer pending grants the empty set, which the broker
        // ignores on the idempotent retry.
        let granted = match granted {
            Some(granted) => granted,
            None => client
                .pending_connect_requests()
                .await
                .map_err(control_plane_error_runtime)?
                .into_iter()
                .find(|request| request.request_id == request_id)
                .map(|request| request.requested)
                .unwrap_or_else(openstream_app_core::PermissionSet::none),
        };
        client
            .approve_connect(&request_id, granted)
            .await
            .map_err(control_plane_error_runtime)?
    };
    if credential.role != "host" {
        // The broker answers an approval with the host side. Anything else is
        // a routing mistake above, and starting the host agent against a
        // client capability would fail later and less legibly.
        return Err(RuntimeError::StateUnavailable);
    }
    let settings = {
        let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.settings().clone()
    };
    let pairing = openstream_client_core::Pairing::from_role_credential(
        openstream_client_core::RoleCredential {
            session_id: credential.session_id,
            role: openstream_client_core::Role::Host,
            token: credential.token,
            websocket_path: credential.websocket_path,
            expires_in_seconds: 0,
            relay_address: credential.relay_address,
            relay_ticket: Some(credential.relay_ticket),
            turn: None,
        },
    );
    let path = {
        let supervisor = session.lock().await;
        supervisor.host_credential_path().to_path_buf()
    };
    session::write_private_json(&path, &pairing).map_err(session_error_to_runtime)?;
    let started = HostAgentClient::new()
        .map_err(|_| RuntimeError::StateUnavailable)?
        .start_session(&path, &settings)
        .await;
    if started.is_err() {
        // A capability on disk that nothing is going to read is a capability
        // nobody is watching.
        let _ = std::fs::remove_file(&path);
        return Err(RuntimeError::StateUnavailable);
    }
    Ok(())
}

/// Refuse a request.
#[tauri::command]
async fn deny_connect_request(
    control_plane: tauri::State<'_, SharedControlPlane>,
    request_id: String,
) -> Result<(), RuntimeError> {
    let mut client = control_plane.lock().await;
    client
        .deny_connect(&request_id)
        .await
        .map_err(control_plane_error_runtime)
}

/// Ask a device for a session, wait for a person to answer, then start it.
///
/// Polling rather than a held connection, matching the broker: a shell that
/// needed a socket per pending request would make request count a resource
/// cost, and the wait here is bounded by
/// [`connect_flow::CONNECT_WAIT`] so a forgotten prompt ends as "nobody
/// answered" rather than hanging.
async fn run_secure_connect(
    state: &Mutex<RuntimeState>,
    session: &SharedSession,
    control_plane: &SharedControlPlane,
    device_id: &str,
    requested: openstream_app_core::PermissionSet,
    mut result: RuntimeDispatchResult,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    let request_id = {
        let mut client = control_plane.lock().await;
        client
            .request_connect(device_id, requested)
            .await
            .map_err(control_plane_error_runtime)?
            .request_id
    };

    let deadline = std::time::Instant::now() + connect_flow::CONNECT_WAIT;
    let credential = loop {
        let observation = {
            let mut client = control_plane.lock().await;
            client
                .observe_connect(&request_id)
                .await
                .map_err(control_plane_error_runtime)?
        };
        match connect_flow::interpret(observation, std::time::Instant::now() >= deadline) {
            connect_flow::ConnectStep::Start(credential) => break *credential,
            connect_flow::ConnectStep::KeepWaiting => {
                tokio::time::sleep(connect_flow::CONNECT_POLL_INTERVAL).await;
            }
            // A refusal and a timeout are different things to the person who
            // pressed connect, but both end the attempt the same way: the
            // model returns to idle rather than waiting on an approval that
            // is not coming.
            connect_flow::ConnectStep::Refused | connect_flow::ConnectStep::Abandoned => {
                let failed = {
                    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                    runtime.session_failed(false)?
                };
                result.events.extend(failed.events);
                result.snapshot = failed.snapshot;
                return Ok(result);
            }
        }
    };

    let settings = {
        let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.settings().clone()
    };
    let started = {
        let mut supervisor = session.lock().await;
        supervisor
            .connect_with_credential(&settings, device_id, credential)
            .await
    };
    match started {
        Ok(_) => {
            let negotiated = {
                let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.begin_session_negotiation()?
            };
            result.events.extend(negotiated.events);
            result.snapshot = negotiated.snapshot;
            Ok(result)
        }
        Err(error) => {
            let failed = {
                let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.session_failed(false)?
            };
            result.events.extend(failed.events);
            result.snapshot = failed.snapshot;
            Err(session_error_to_runtime(error))
        }
    }
}

/// The one dispatch path. Tauri-independent so it can be exercised directly
/// in tests without a running Tauri application.
async fn dispatch_command_with_session(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    session: &SharedSession,
    control_plane: &SharedControlPlane,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    match command {
        RuntimeCommand::EnableHosting => {
            let result = dispatch_host_lifecycle(state, host_lock, true).await?;
            // Presence follows hosting. A device that is not hosting must not
            // appear connectable: offering it would produce a request nobody
            // can approve, and the person who pressed connect would watch it
            // time out with no explanation.
            announce_presence_best_effort(control_plane, true).await;
            Ok(result)
        }
        RuntimeCommand::DisableHosting => {
            let result = dispatch_host_lifecycle(state, host_lock, false).await?;
            announce_presence_best_effort(control_plane, false).await;
            Ok(result)
        }
        RuntimeCommand::RestartHosting => dispatch_restart_hosting(state, host_lock).await,
        RuntimeCommand::Connect {
            device_id,
            requested,
        } => {
            let mut result = {
                let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.dispatch(RuntimeCommand::Connect {
                    device_id: device_id.clone(),
                    requested,
                })?
            };
            let local_mode = {
                let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.is_local_mode()
            };
            if local_mode {
                let request_id = result
                    .snapshot
                    .app
                    .pending_request
                    .as_ref()
                    .map(|request| request.request_id.clone())
                    .ok_or(RuntimeError::StateUnavailable)?;
                let available = local_permissions(state)?;
                let approved = {
                    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                    runtime.approve_local_request(request_id, available)?
                };
                result.events.extend(approved.events);
                result.snapshot = approved.snapshot;
            } else {
                // Secure deployments go through the Connect broker: the host
                // device is asked, a person there approves, and only then is
                // a capability issued -- to each end separately. The runner
                // is started from that capability rather than from a pairing
                // file carrying both roles.
                return run_secure_connect(
                    state,
                    session,
                    control_plane,
                    &device_id,
                    requested,
                    result,
                )
                .await;
            }
            let started = start_session_if_connecting(state, session, &device_id).await;
            match started {
                Ok(()) => {
                    let negotiated = {
                        let mut runtime =
                            state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                        runtime.begin_session_negotiation()?
                    };
                    result.events.extend(negotiated.events);
                    result.snapshot = negotiated.snapshot;
                    Ok(result)
                }
                Err(error) => {
                    let failed = {
                        let mut runtime =
                            state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                        runtime.session_failed(false)?
                    };
                    result.events.extend(failed.events);
                    result.snapshot = failed.snapshot;
                    Err(session_error_to_runtime(error))
                }
            }
        }
        RuntimeCommand::ApproveRequest {
            request_id,
            available,
        } => {
            let result = {
                let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.dispatch(RuntimeCommand::ApproveRequest {
                    request_id,
                    available,
                })?
            };
            if let Some(device_id) = connecting_device(state)? {
                start_session_if_connecting(state, session, &device_id)
                    .await
                    .map_err(session_error_to_runtime)?;
                let negotiated = {
                    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                    runtime.begin_session_negotiation()?
                };
                return Ok(RuntimeDispatchResult {
                    snapshot: negotiated.snapshot,
                    events: result.events.into_iter().chain(negotiated.events).collect(),
                });
            }
            Ok(result)
        }
        RuntimeCommand::Disconnect => {
            let stop_result = {
                let mut supervisor = session.lock().await;
                supervisor.disconnect().await
            };
            let mut result = {
                let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                runtime.dispatch(RuntimeCommand::Disconnect)?
            };
            if let Err(error) = stop_result {
                return Err(session_error_to_runtime(error));
            }
            let should_complete = {
                let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                matches!(
                    runtime.app_state(),
                    openstream_app_core::AppState::Disconnecting { .. }
                )
            };
            if should_complete {
                let completed = {
                    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
                    runtime.complete_disconnect()?
                };
                result.events.extend(completed.events);
                result.snapshot = completed.snapshot;
            }
            Ok(result)
        }
        other => {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            runtime.dispatch(other)
        }
    }
}

fn session_error_to_runtime(error: SessionError) -> RuntimeError {
    let (code, retryable) = match error {
        SessionError::PairingUnavailable | SessionError::PairingInsecure => {
            (openstream_app_core::AppErrorCode::PermissionDenied, false)
        }
        SessionError::RunnerUnavailable
        | SessionError::AlreadyActive
        // Retryable on purpose: the previous session's processes are being
        // shut down, and a later attempt is expected to succeed once they
        // are gone. Reporting it as permanent would tell the operator to
        // restart the shell for something that clears itself.
        | SessionError::CleanupPending
        | SessionError::SpawnFailed
        | SessionError::StopFailed
        | SessionError::StatusInvalid => (openstream_app_core::AppErrorCode::Unavailable, true),
    };
    RuntimeError::CommandRejected { code, retryable }
}

fn local_permissions(
    state: &Mutex<RuntimeState>,
) -> Result<openstream_app_core::PermissionSet, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    let input = &runtime.settings().input;
    Ok(openstream_app_core::PermissionSet {
        view: true,
        keyboard: input.enabled && input.keyboard,
        mouse: input.enabled && input.mouse,
        gamepad: input.enabled && input.gamepad,
        clipboard: input.enabled && input.clipboard,
        microphone: input.enabled && input.microphone,
        tablet: false,
        virtual_usb: false,
    })
}

fn connecting_device(state: &Mutex<RuntimeState>) -> Result<Option<String>, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(match runtime.app_state() {
        openstream_app_core::AppState::Connecting { device_id }
        | openstream_app_core::AppState::Negotiating { device_id } => Some(device_id.clone()),
        _ => None,
    })
}

async fn start_session_if_connecting(
    state: &Mutex<RuntimeState>,
    session: &SharedSession,
    device_id: &str,
) -> Result<(), SessionError> {
    let settings = {
        let runtime = state.lock().map_err(|_| SessionError::StatusInvalid)?;
        runtime.settings().clone()
    };
    let mut supervisor = session.lock().await;
    if matches!(
        supervisor.health().state,
        SessionProcessState::Starting
            | SessionProcessState::Running
            | SessionProcessState::Connected
            | SessionProcessState::Stopping
    ) {
        return Err(SessionError::AlreadyActive);
    }
    supervisor
        .connect(&settings, device_id.to_string())
        .await
        .map(|_| ())?;
    let mut runtime = state.lock().map_err(|_| SessionError::StatusInvalid)?;
    runtime.mark_reconnect_applied();
    Ok(())
}

/// Enable or disable hosting through the one path that may start or stop
/// the real host agent process. Production always targets the process
/// default socket via `HostAgentClient::new`.
async fn dispatch_host_lifecycle(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    enable: bool,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    let settings = {
        let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.settings().clone()
    };
    dispatch_host_lifecycle_with_settings(
        state,
        host_lock,
        enable,
        HostAgentClient::new,
        Some(settings),
    )
    .await
}

/// Apply RestartHost settings without ever allowing two host children to
/// overlap. The ordinary stop path waits until the agent has reaped its
/// child; only then does the start-with-settings request replace the child
/// configuration and spawn the new process.
async fn dispatch_restart_hosting(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    let hosting_active = {
        let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        !matches!(
            runtime.host_status(),
            openstream_app_core::HostStatus::Disabled
        )
    };
    if !hosting_active {
        return Err(RuntimeError::CommandRejected {
            code: openstream_app_core::AppErrorCode::InvalidState,
            retryable: false,
        });
    }

    let _stopped = dispatch_host_lifecycle(state, host_lock, false).await?;
    dispatch_host_lifecycle(state, host_lock, true).await
}

/// Apply the intent, drop the mutex guard, await the host-agent call built
/// by `client_factory`, then re-lock and apply its real outcome. Each
/// `{ ... }` block below ends -- and its guard drops -- before the
/// `.await` that follows it, so the state mutex is never held across one.
///
/// The whole transaction runs under `host_lock`, so a second enable or
/// disable arriving while this one is in flight waits rather than
/// interleaving its own intent, IPC call, and outcome with this one's.
/// That lock is an async mutex precisely because it *is* held across
/// `.await`; the state mutex is the synchronous one and still is not.
///
/// `client_factory` is `HostAgentClient::new` in production; tests
/// substitute a factory that targets a private, unreachable endpoint
/// instead of the process-default socket, without adding any Tauri command
/// parameter that would let the web UI choose one.
/// Test seam: the host-lifecycle cases exercise enable/disable ordering and
/// want neither a settings payload nor a real agent socket. Production goes
/// through [`dispatch_host_lifecycle`], which always carries the settings.
#[cfg(test)]
async fn dispatch_host_lifecycle_with<F>(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    enable: bool,
    client_factory: F,
) -> Result<RuntimeDispatchResult, RuntimeError>
where
    F: FnOnce() -> Result<HostAgentClient, HostAgentBridgeError>,
{
    dispatch_host_lifecycle_with_settings(state, host_lock, enable, client_factory, None).await
}

async fn dispatch_host_lifecycle_with_settings<F>(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    enable: bool,
    client_factory: F,
    settings: Option<AppConfig>,
) -> Result<RuntimeDispatchResult, RuntimeError>
where
    F: FnOnce() -> Result<HostAgentClient, HostAgentBridgeError>,
{
    let _serialised = host_lock.0.lock().await;
    let intent = if enable {
        RuntimeCommand::EnableHosting
    } else {
        RuntimeCommand::DisableHosting
    };
    let mut events = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.dispatch(intent)?.events
    };

    let client = client_factory();
    let outcome = match &client {
        Ok(client) => {
            if enable {
                match settings.as_ref() {
                    Some(settings) => client.start_with_settings(settings).await,
                    None => client.start().await,
                }
            } else {
                match client.stop().await {
                    Ok(events) => wait_for_host_stopped(client).await.map(|()| events),
                    Err(error) => Err(error),
                }
            }
        }
        Err(error) => Err(*error),
    };

    let result = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        if enable {
            runtime.apply_host_start_outcome(outcome)?
        } else {
            runtime.apply_host_stop_outcome(outcome)?
        }
    };
    events.extend(result.events);

    // An accepted `Start` only means the agent took the request; the child
    // may still be in its startup grace period, or already gone. Ask the
    // agent what actually happened before answering the caller, so the
    // snapshot the shell renders is the agent's state and not an optimistic
    // guess. A health call that fails changes nothing: the model keeps the
    // state the outcome above gave it, and the background reconciler tries
    // again on its own schedule.
    let mut snapshot = result.snapshot;
    if let Ok(client) = &client {
        if let Ok(health) = client.health().await {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            if let Ok(reconciled) = runtime.reconcile_host_health(&health) {
                events.extend(reconciled.events);
                snapshot = reconciled.snapshot;
            }
        }
    }

    Ok(RuntimeDispatchResult { snapshot, events })
}

/// `HostAgentClient::stop` acknowledges the stop request, not necessarily the
/// final child reap. Keep the shell's completion semantics honest by waiting
/// for the agent's authoritative `Stopped` health state before returning.
async fn wait_for_host_stopped(client: &HostAgentClient) -> Result<(), HostAgentBridgeError> {
    let deadline = tokio::time::Instant::now() + HOST_STOP_WAIT_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HostAgentBridgeError::Timeout);
        }
        let health = client.health().await?;
        if health.state == openstream_host_agent::ChildState::Stopped {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50).min(remaining)).await;
    }
}

/// Poll the host agent forever, adopting its state into `AppModel`.
///
/// This is the only thing that notices a host that died, restarted, or
/// exhausted its restart budget without anyone pressing a button, and the
/// only thing that tells a freshly opened shell that an agent which was
/// already running is hosting. Every failure here is non-fatal by design:
/// an agent that is not installed, not running, or not reachable simply
/// leaves the model as it is, and the next tick tries again.
///
/// It takes the same lifecycle lock the enable/disable path takes. An
/// operation in flight is a transaction whose intent has been applied and
/// whose result has not; polling in the middle of one would read the agent's
/// pre-request state and helpfully "correct" the model back, so a tick that
/// landed between the intent and the IPC call would flip a just-requested
/// enable to disabled and back again.
async fn reconcile_host_health_forever(state: SharedRuntime, host_lock: SharedHostLock) {
    let mut ticker = tokio::time::interval(HOST_HEALTH_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let _serialised = host_lock.0.lock().await;
        let Ok(client) = HostAgentClient::new() else {
            continue;
        };
        let Ok(health) = client.health().await else {
            continue;
        };
        let Ok(mut runtime) = state.lock() else {
            continue;
        };
        let _ = runtime.reconcile_host_health(&health);
    }
}

/// Poll the native session runner and reflect only its secret-free lifecycle
/// observations into `AppModel`. The runner owns all media and network
/// buffers; this task never receives a frame and never forwards a bearer
/// credential through Tauri.
async fn reconcile_session_forever(state: SharedRuntime, session: SharedSession) {
    let mut ticker = tokio::time::interval(SESSION_HEALTH_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let health = {
            let mut supervisor = session.lock().await;
            match supervisor.poll().await {
                Ok(health) => health,
                Err(_) => continue,
            }
        };
        let Ok(mut runtime) = state.lock() else {
            continue;
        };
        runtime.reconcile_session_health(&health);
        let active = matches!(
            runtime.app_state(),
            openstream_app_core::AppState::RequestingConnection { .. }
                | openstream_app_core::AppState::WaitingForApproval { .. }
                | openstream_app_core::AppState::Connecting { .. }
                | openstream_app_core::AppState::Negotiating { .. }
                | openstream_app_core::AppState::Connected { .. }
                | openstream_app_core::AppState::Reconnecting { .. }
                | openstream_app_core::AppState::Disconnecting { .. }
        );
        match health.state {
            SessionProcessState::Connected => {
                if matches!(
                    runtime.app_state(),
                    openstream_app_core::AppState::Connecting { .. }
                        | openstream_app_core::AppState::Negotiating { .. }
                        | openstream_app_core::AppState::Reconnecting { .. }
                ) {
                    if let (Some(session_id), Some(generation)) =
                        (health.session_id.clone(), health.generation)
                    {
                        let _ = runtime.session_established(session_id, generation);
                    }
                }
            }
            SessionProcessState::Failed if active => {
                let _ = runtime.session_failed(false);
            }
            SessionProcessState::Idle
                if matches!(
                    runtime.app_state(),
                    openstream_app_core::AppState::Disconnecting { .. }
                ) =>
            {
                let _ = runtime.complete_disconnect();
            }
            SessionProcessState::Idle
            | SessionProcessState::Starting
            | SessionProcessState::Running
            | SessionProcessState::Stopping
            | SessionProcessState::Failed => {}
        }
    }
}

fn bootstrap_local_directory(runtime: &mut RuntimeState) {
    if !runtime.is_local_mode() {
        return;
    }
    let id = env::var("OPENSTREAM_TARGET_DEVICE_ID").ok().or_else(|| {
        env::var_os("OPENSTREAM_PAIRING_FILE")
            .filter(|path| !path.is_empty())
            .map(|_| "paired-host".to_string())
    });
    let Some(id) = id else {
        return;
    };
    let name =
        env::var("OPENSTREAM_TARGET_DEVICE_NAME").unwrap_or_else(|_| "OpenStream host".to_string());
    let platform =
        env::var("OPENSTREAM_TARGET_DEVICE_PLATFORM").unwrap_or_else(|_| "unknown".to_string());
    let mut device = openstream_app_core::DeviceSummary::online(id, name);
    device.platform = platform;
    runtime.add_device(device);
}

// `host_agent_health` takes no frontend-supplied endpoint: the client
// always derives the process-default socket, so the web UI has no way to
// redirect it elsewhere. `host_agent_start`/`host_agent_stop` are
// deliberately not exposed as Tauri commands: `runtime_dispatch`'s
// `EnableHosting`/`DisableHosting`, via `dispatch_host_lifecycle`, is the
// only path from *this shell* that may start or stop the host agent.
//
// That is not the same as the two never disagreeing, and this used to claim
// it was. The agent restarts, backs off, and gives up on its own schedule,
// another shell or an operator with the socket can drive it, and a shell
// that has just opened knows nothing about an agent that was already
// running. `reconcile_host_health_forever` is what keeps them in agreement;
// the agent is authoritative whenever they differ.
#[tauri::command]
async fn host_agent_health() -> Result<HostHealth, HostAgentBridgeError> {
    HostAgentClient::new()?.health().await
}

#[tauri::command]
async fn session_health(
    session: tauri::State<'_, SharedSession>,
) -> Result<SessionHealth, RuntimeError> {
    let mut supervisor = session.lock().await;
    supervisor
        .poll()
        .await
        .map_err(|_| RuntimeError::StateUnavailable)
}

#[tauri::command]
fn device_store_snapshot(
    store: tauri::State<'_, SharedDeviceStore>,
) -> Result<Vec<TrustedDeviceSnapshot>, RuntimeError> {
    let store = store.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(store
        .snapshots()
        .into_iter()
        .map(|device| TrustedDeviceSnapshot {
            device_id: device.device_id,
            name: device.name,
            platform: device.platform,
            enrolled_at_ms: device.enrolled_at_ms,
            trust: device.trust,
            last_seen_ms: device.last_seen_ms,
            public_key_fingerprint: device.public_key_fingerprint,
        })
        .collect())
}

#[tauri::command]
async fn device_store_set_trust(
    runtime: tauri::State<'_, SharedRuntime>,
    store: tauri::State<'_, SharedDeviceStore>,
    control_plane: tauri::State<'_, SharedControlPlane>,
    device_id: String,
    trust: openstream_app_core::DeviceTrustState,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let server_trust = match trust {
        openstream_app_core::DeviceTrustState::Pending => ServerDeviceTrust::Pending,
        openstream_app_core::DeviceTrustState::Trusted => ServerDeviceTrust::Trusted,
        openstream_app_core::DeviceTrustState::Revoked => ServerDeviceTrust::Revoked,
    };
    let authenticated = {
        let client = control_plane.lock().await;
        client.is_authenticated()
    };
    if authenticated {
        // Once an account is active the control plane is authoritative. Do
        // not silently mutate a local shadow record and tell the operator the
        // remote device was revoked; update the server first, then reconcile
        // the complete public device list into the runtime snapshot.
        let devices = {
            let mut client = control_plane.lock().await;
            client
                .set_device_trust(&device_id, server_trust)
                .await
                .map_err(control_plane_error_runtime)?;
            client
                .devices()
                .await
                .map_err(control_plane_error_runtime)?
        };
        let mut runtime = runtime.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        apply_control_plane_devices(&mut runtime, &devices);
        return Ok(runtime.snapshot());
    }

    // Local mode has no account server. Its protected device store remains a
    // useful development/test fallback, but it is never used after a remote
    // account has been authenticated.
    let now = current_time_ms_for_command();
    let snapshots = {
        let mut store = store.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        store
            .set_trust(&device_id, trust, Some(now))
            .map_err(device_store_error)?;
        store
            .snapshots()
            .into_iter()
            .map(|device| TrustedDeviceSnapshot {
                device_id: device.device_id,
                name: device.name,
                platform: device.platform,
                enrolled_at_ms: device.enrolled_at_ms,
                trust: device.trust,
                last_seen_ms: device.last_seen_ms,
                public_key_fingerprint: device.public_key_fingerprint,
            })
            .collect::<Vec<_>>()
    };
    let mut runtime = runtime.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    runtime.set_trusted_devices(snapshots);
    Ok(runtime.snapshot())
}

fn current_time_ms_for_command() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn device_store_error(_error: DeviceStoreError) -> RuntimeError {
    RuntimeError::InvalidSettings
}

/// Build the account control-plane client for startup.
///
/// The account client is intentionally stricter about its origin than the
/// settings layer: it refuses a private-LAN plaintext origin so account
/// credentials can never travel in the clear. But `local_no_auth` deployments
/// have no accounts and never use this client, and the settings layer
/// legitimately accepts a numeric private-LAN origin there. Constructing the
/// client unconditionally therefore aborted startup in exactly the mode the
/// settings allow. In `local_no_auth` mode we fall back to a loopback
/// placeholder so the Tauri state exists; account commands, which the
/// local-mode UI does not expose, would fail against loopback rather than
/// bringing the whole shell down.
fn control_plane_for_startup(
    signal_origin: &str,
    local_no_auth: bool,
) -> Result<ControlPlaneClient, RuntimeError> {
    match ControlPlaneClient::new(signal_origin) {
        Ok(client) => Ok(client),
        Err(_) if local_no_auth => Ok(ControlPlaneClient::new("http://127.0.0.1")
            .expect("a loopback origin is always a valid control-plane origin")),
        Err(_) => Err(RuntimeError::InvalidSettings),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .map_err(|_| RuntimeError::SettingsUnavailable)?
                .join("settings.json");
            let device_store_path = settings_path
                .parent()
                .ok_or(RuntimeError::SettingsUnavailable)?
                .join("devices.json");
            let device_store = DeviceStore::open(device_store_path).map_err(device_store_error)?;
            let mut runtime_state = RuntimeState::from_settings_path(Some(settings_path))?;
            let control_plane = control_plane_for_startup(
                &runtime_state.settings().client.signal_origin,
                runtime_state.settings().network.local_no_auth,
            )?;
            let trusted_devices = device_store
                .snapshots()
                .into_iter()
                .map(|device| TrustedDeviceSnapshot {
                    device_id: device.device_id,
                    name: device.name,
                    platform: device.platform,
                    enrolled_at_ms: device.enrolled_at_ms,
                    trust: device.trust,
                    last_seen_ms: device.last_seen_ms,
                    public_key_fingerprint: device.public_key_fingerprint,
                })
                .collect();
            runtime_state.set_trusted_devices(trusted_devices);
            bootstrap_local_directory(&mut runtime_state);
            let runtime: SharedRuntime = Arc::new(Mutex::new(runtime_state));
            let device_store: SharedDeviceStore = Arc::new(Mutex::new(device_store));
            let host_lock: SharedHostLock = Arc::new(HostLifecycleLock::default());
            let session_dir = app
                .path()
                .app_local_data_dir()
                .map_err(|_| RuntimeError::SettingsUnavailable)?
                .join("session");
            let session: SharedSession = Arc::new(tokio::sync::Mutex::new(
                SessionSupervisor::new(session_dir)
                    .map_err(|_| RuntimeError::SettingsUnavailable)?,
            ));
            app.manage(Arc::clone(&runtime));
            app.manage(Arc::clone(&host_lock));
            app.manage(Arc::clone(&session));
            app.manage(Arc::clone(&device_store));
            app.manage(Arc::new(tokio::sync::Mutex::new(control_plane)) as SharedControlPlane);
            // Adopt whatever the agent is already doing, then keep adopting
            // it. A shell that has just opened over a running agent would
            // otherwise report hosting as disabled until someone pressed a
            // button, and a child that crashed after being reported ready
            // would never be reported as anything else.
            tauri::async_runtime::spawn(reconcile_host_health_forever(
                Arc::clone(&runtime),
                Arc::clone(&host_lock),
            ));
            tauri::async_runtime::spawn(reconcile_session_forever(runtime, session));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            runtime_snapshot,
            runtime_settings,
            runtime_update_settings,
            runtime_update_setting,
            runtime_dispatch,
            control_plane_sign_in,
            control_plane_register,
            control_plane_refresh_devices,
            control_plane_sign_out,
            host_agent_health,
            session_health,
            device_store_snapshot,
            device_store_set_trust,
            host_connect_requests,
            approve_connect_request,
            deny_connect_request
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenStream desktop shell");
}

#[cfg(test)]
mod tests {
    use super::{
        control_plane_for_startup, dispatch_host_lifecycle_with, HostAgentClient,
        HostLifecycleLock, RuntimeError, RuntimeState,
    };
    use openstream_app_core::HostStatus;
    use openstream_host_agent::{
        AgentIpcCommand, AgentIpcRequest, AgentIpcResponse, ChildState, HostAgentEvent, HostHealth,
        HOST_AGENT_PROTOCOL_VERSION,
    };
    use openstream_local_ipc::{read_frame, write_frame, Endpoint};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::task::JoinHandle;

    /// Presence from the control plane decides whether the shell offers a
    /// connection. This is the desktop half of surfacing host presence: an
    /// online record maps to a connectable summary, an offline one does not,
    /// and the platform is carried through either way. Before presence was
    /// surfaced every device mapped to offline and the connect button was
    /// never live.
    #[test]
    fn to_directory_device_reflects_presence() {
        let base = super::control_plane::PublicDevice {
            device_id: "device-host".to_string(),
            name: "Studio".to_string(),
            platform: "macos".to_string(),
            trust: super::control_plane::DeviceTrust::Trusted,
            enrolled_at_ms: 0,
            last_seen_ms: None,
            public_key_fingerprint: "abcd1234".to_string(),
            online: true,
        };

        let online = super::to_directory_device(&base);
        assert!(online.online, "an online device is offered as connectable");
        assert_eq!(online.platform, "macos", "platform is carried through");

        let offline = super::to_directory_device(&super::control_plane::PublicDevice {
            online: false,
            ..base
        });
        assert!(!offline.online, "an offline device is not offered");
        assert_eq!(offline.platform, "macos", "platform is carried through");
    }

    #[test]
    fn local_no_auth_private_lan_origin_does_not_abort_startup() {
        // The settings layer accepts a numeric private-LAN origin when
        // local_no_auth is on; the account client refuses it. Startup must not
        // abort in that mode -- it falls back to a usable client instead.
        let origin = "http://192.168.1.69:8080";
        assert!(
            super::ControlPlaneClient::new(origin).is_err(),
            "precondition: the account client rejects a private-LAN plaintext origin"
        );
        assert!(
            control_plane_for_startup(origin, true).is_ok(),
            "local_no_auth startup must tolerate a private-LAN origin"
        );
    }

    #[test]
    fn private_lan_origin_still_aborts_when_accounts_are_required() {
        // With accounts enabled (not local_no_auth), a rejected origin must
        // still fail rather than silently pointing account traffic at loopback.
        assert!(matches!(
            control_plane_for_startup("http://192.168.1.69:8080", false),
            Err(RuntimeError::InvalidSettings)
        ));
    }

    #[test]
    fn valid_origins_build_a_client_in_either_mode() {
        for origin in ["https://signal.example.test", "http://127.0.0.1:8080"] {
            assert!(control_plane_for_startup(origin, false).is_ok());
            assert!(control_plane_for_startup(origin, true).is_ok());
        }
    }

    /// A socket path nothing is listening on, private to this call.
    fn unreachable_endpoint() -> Endpoint {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf =
            std::env::temp_dir().join(format!("openstream-lib-test-{nanos:x}-{sequence:x}.sock"));
        Endpoint::new(path).expect("valid test endpoint path")
    }

    /// A short, private socket path. Kept well under the AF_UNIX length
    /// limit, which a long default temporary directory can otherwise blow.
    fn short_socket_path() -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("oslb-{nanos:x}-{sequence:x}"))
            .join("s.sock")
    }

    /// A host-agent double that serves many requests, records the order it
    /// saw lifecycle commands in, and reports a programmable child state.
    ///
    /// The recorded order is the point: it is the agent's own view of what
    /// happened, and it is what the shell's `AppModel` has to agree with.
    struct RecordingAgent {
        endpoint: Endpoint,
        seen: Arc<Mutex<Vec<AgentIpcCommand>>>,
        task: JoinHandle<()>,
    }

    impl RecordingAgent {
        /// `state_after` decides the `ChildState` reported to a `Health`
        /// call, given the lifecycle commands seen so far. `start_delay`
        /// is applied while serving a `Start`, which is what lets a test
        /// detect an unserialised `Stop` overtaking it.
        async fn spawn(
            state_after: fn(&[AgentIpcCommand]) -> ChildState,
            start_delay: Duration,
        ) -> Self {
            let endpoint = Endpoint::new(short_socket_path()).expect("valid test endpoint path");
            let listener = endpoint.bind().await.expect("bind test endpoint");
            let seen: Arc<Mutex<Vec<AgentIpcCommand>>> = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&seen);
            // Each connection is served on its own task. A server that
            // handled them one at a time would serialise the client's
            // requests for it, which is exactly the property under test.
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _address)) = listener.accept().await {
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        let request: Option<AgentIpcRequest> =
                            read_frame(&mut stream).await.unwrap_or(None);
                        let Some(request) = request else { return };
                        let response = match request.command {
                            AgentIpcCommand::Health => {
                                let history = recorded.lock().expect("test lock").clone();
                                AgentIpcResponse::Health {
                                    version: HOST_AGENT_PROTOCOL_VERSION,
                                    request_id: request.request_id,
                                    health: HostHealth {
                                        state: state_after(&history),
                                        backend: "test".into(),
                                        pid: None,
                                        restart_count: 0,
                                        next_restart_in_ms: None,
                                        last_exit: None,
                                        last_error: None,
                                        config_revision: "test".into(),
                                        frame_liveness:
                                            openstream_host_agent::FrameLiveness::NotConfigured,
                                        frames_seen: 0,
                                        last_frame_age_ms: None,
                                    },
                                }
                            }
                            command => {
                                // The delay lands before the command is
                                // recorded, so a `Stop` issued concurrently
                                // with a stalled `Start` overtakes it.
                                if command == AgentIpcCommand::Start && !start_delay.is_zero() {
                                    tokio::time::sleep(start_delay).await;
                                }
                                recorded.lock().expect("test lock").push(command);
                                AgentIpcResponse::Accepted {
                                    version: HOST_AGENT_PROTOCOL_VERSION,
                                    request_id: request.request_id,
                                    events: Vec::new(),
                                }
                            }
                        };
                        let _ = write_frame(&mut stream, &response).await;
                    });
                }
            });
            Self {
                endpoint,
                seen,
                task,
            }
        }

        fn client(&self) -> HostAgentClient {
            HostAgentClient::with_endpoint(self.endpoint.clone())
        }

        fn lifecycle_commands(&self) -> Vec<AgentIpcCommand> {
            self.seen.lock().expect("test lock").clone()
        }
    }

    impl Drop for RecordingAgent {
        fn drop(&mut self) {
            self.task.abort();
            let _ = self.endpoint.cleanup();
        }
    }

    fn shared_state() -> Arc<Mutex<RuntimeState>> {
        Arc::new(Mutex::new(RuntimeState::for_test()))
    }

    /// `EnableHosting` must actually call the real host agent, and a call
    /// that cannot even connect must leave `AppModel` in a typed failed
    /// state -- never the optimistic `Ready` a frontend-driven `HostReady`
    /// command used to be able to fabricate.
    #[tokio::test]
    async fn enable_hosting_reports_a_typed_failure_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();
        let endpoint = unreachable_endpoint();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect("the intent still applies even though the agent call fails");

        assert!(matches!(
            result.snapshot.app.host_status,
            HostStatus::Failed { .. }
        ));
    }

    /// The same path for `DisableHosting` -- a stop call that cannot even
    /// connect is a typed error, not one silently accepted as success.
    #[tokio::test]
    async fn disable_hosting_reports_a_typed_error_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();
        let endpoint = unreachable_endpoint();

        let error = dispatch_host_lifecycle_with(&state, &lock, false, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect_err("a stop call that cannot connect must not be silently accepted");

        assert!(matches!(error, RuntimeError::CommandRejected { .. }));
    }

    /// An accepted `Start` is not a running host.
    ///
    /// The agent accepts the request and reports no events -- exactly what
    /// it does for a child that has only just been spawned, or when it was
    /// already starting -- and its child is still in `Starting`. The shell
    /// used to call that `Ready`, and would then sit on `Ready` while the
    /// child crashed behind it.
    #[tokio::test]
    async fn an_accepted_start_does_not_report_a_host_as_ready() {
        let agent = RecordingAgent::spawn(|_| ChildState::Starting, Duration::ZERO).await;
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, || Ok(agent.client()))
            .await
            .expect("an accepted start is not an error");

        assert_eq!(
            result.snapshot.app.host_status,
            HostStatus::Starting,
            "a spawned-but-not-ready child must not be reported as ready"
        );
    }

    /// ...and once the agent's own child reaches `Ready`, the reconciler
    /// adopts that, so the shell does report a host that really is up.
    #[tokio::test]
    async fn a_host_becomes_ready_when_the_agent_says_its_child_is_ready() {
        let agent = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, || Ok(agent.client()))
            .await
            .expect("an accepted start is not an error");

        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }

    /// The agent must see lifecycle commands in the order the model
    /// recorded the operator's intents.
    ///
    /// An enable and a disable are issued at once and the agent stalls the
    /// `Start`. Unserialised, each operation applies its intent, drops the
    /// state mutex for its own `.await`, and applies its outcome whenever
    /// its reply happens to arrive -- so the disable, which is not stalled,
    /// reaches the agent first and the model's "enable, then disable"
    /// becomes the agent's "stop, then start": a host left running behind a
    /// shell the operator just told to stop hosting.
    ///
    /// `join!` polls the enable first, so the enable's intent is the one
    /// the model records first, and the agent has to see `Start` first too.
    #[tokio::test]
    async fn concurrent_enable_and_disable_reach_the_agent_in_the_order_intended() {
        let agent = RecordingAgent::spawn(
            |history| match history.last() {
                Some(AgentIpcCommand::Start) => ChildState::Ready,
                _ => ChildState::Stopped,
            },
            Duration::from_millis(150),
        )
        .await;
        let state = shared_state();
        let lock = HostLifecycleLock::default();

        let enable =
            dispatch_host_lifecycle_with(state.as_ref(), &lock, true, || Ok(agent.client()));
        let disable =
            dispatch_host_lifecycle_with(state.as_ref(), &lock, false, || Ok(agent.client()));
        let (enable_result, disable_result) = tokio::join!(enable, disable);
        assert!(enable_result.is_ok(), "the enable transaction completed");
        assert!(disable_result.is_ok(), "the disable transaction completed");

        assert_eq!(
            agent.lifecycle_commands(),
            vec![AgentIpcCommand::Start, AgentIpcCommand::Stop],
            "the agent saw the operations in a different order than the model applied them"
        );

        // The operator's last word was "stop", and that is what stands.
        let status = state.lock().expect("test lock").snapshot().app.host_status;
        assert_eq!(status, HostStatus::Disabled);
    }

    /// A shell that opens over an agent which is already hosting must adopt
    /// that, rather than reporting hosting as disabled until someone
    /// happens to press a button.
    #[tokio::test]
    async fn an_already_hosting_agent_is_adopted_by_a_freshly_started_shell() {
        let agent = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        assert_eq!(state.snapshot().app.host_status, HostStatus::Disabled);

        let health = agent.client().health().await.expect("health call succeeds");
        let result = state
            .reconcile_host_health(&health)
            .expect("adopting a running agent is not an error");

        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }

    /// A child that crashes after being reported ready must stop being
    /// reported as ready. Nothing but the reconciler notices this: the
    /// agent restarts the child on its own, without a request from here.
    #[tokio::test]
    async fn a_child_that_crashes_after_ready_stops_being_reported_as_ready() {
        let ready = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        let health = ready.client().health().await.expect("health call succeeds");
        state.reconcile_host_health(&health).expect("adopt ready");
        assert_eq!(state.snapshot().app.host_status, HostStatus::Ready);

        let restarting = RecordingAgent::spawn(|_| ChildState::Backoff, Duration::ZERO).await;
        let health = restarting
            .client()
            .health()
            .await
            .expect("health call succeeds");
        state.reconcile_host_health(&health).expect("adopt backoff");

        assert_eq!(
            state.snapshot().app.host_status,
            HostStatus::Starting,
            "a child being restarted is not a ready host"
        );
    }

    /// The agent is authoritative about its child, but not about whether
    /// the operator wants to host at all. An agent reporting a terminal
    /// failure must not raise a failure the operator cannot act on when
    /// hosting is simply switched off.
    #[tokio::test]
    async fn an_agent_failure_does_not_disturb_deliberately_disabled_hosting() {
        let agent = RecordingAgent::spawn(|_| ChildState::Failed, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        let health = agent.client().health().await.expect("health call succeeds");

        state.reconcile_host_health(&health).expect("reconcile");

        assert_eq!(state.snapshot().app.host_status, HostStatus::Disabled);
    }

    /// `HostAgentEvent::Ready` in the accepted response is itself proof of
    /// readiness and is honoured without waiting for a health poll.
    #[tokio::test]
    async fn an_agent_that_reports_ready_in_its_response_is_believed() {
        let events = vec![
            HostAgentEvent::Started { pid: Some(7) },
            HostAgentEvent::Ready,
        ];
        let mut state = RuntimeState::for_test();
        state
            .dispatch(super::RuntimeCommand::EnableHosting)
            .expect("enable intent applies");
        let result = state
            .apply_host_start_outcome(Ok(events))
            .expect("a ready event is not an error");
        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }
}
