use std::sync::Mutex;

use host_agent::{HostAgentBridgeError, HostAgentClient};
use openstream_host_agent::HostHealth;
use openstream_settings::AppConfig;
use runtime::{RuntimeCommand, RuntimeDispatchResult, RuntimeError, RuntimeSnapshot, RuntimeState};
use tauri::Manager;

pub mod host_agent;
pub mod runtime;

#[tauri::command]
fn runtime_snapshot(
    state: tauri::State<'_, Mutex<RuntimeState>>,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.snapshot())
}

#[tauri::command]
fn runtime_settings(
    state: tauri::State<'_, Mutex<RuntimeState>>,
) -> Result<AppConfig, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.settings().clone())
}

#[tauri::command]
fn runtime_update_settings(
    state: tauri::State<'_, Mutex<RuntimeState>>,
    settings: AppConfig,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    runtime.update_settings(settings)?;
    Ok(runtime.snapshot())
}

/// The single entry point for every user-intent command, hosting included.
/// `EnableHosting`/`DisableHosting` are not a thin pass-through to
/// `RuntimeState::dispatch`: they must also drive the real host agent, so
/// this command is `async` and delegates to `dispatch_command`, which never
/// holds the state mutex across an `.await`.
#[tauri::command]
async fn runtime_dispatch(
    state: tauri::State<'_, Mutex<RuntimeState>>,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    dispatch_command(state.inner(), command).await
}

/// Tauri-independent core of `runtime_dispatch`, so it can be exercised
/// directly in tests without a running Tauri application.
async fn dispatch_command(
    state: &Mutex<RuntimeState>,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    match command {
        RuntimeCommand::EnableHosting => dispatch_host_lifecycle(state, true).await,
        RuntimeCommand::DisableHosting => dispatch_host_lifecycle(state, false).await,
        other => {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            runtime.dispatch(other)
        }
    }
}

/// Enable or disable hosting through the one path that may start or stop
/// the real host agent process. Production always targets the process
/// default socket via `HostAgentClient::new`.
async fn dispatch_host_lifecycle(
    state: &Mutex<RuntimeState>,
    enable: bool,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    dispatch_host_lifecycle_with(state, enable, HostAgentClient::new).await
}

/// Apply the intent, drop the mutex guard, await the host-agent call built
/// by `client_factory`, then re-lock and apply its real outcome. Each
/// `{ ... }` block below ends -- and its guard drops -- before the
/// `.await` that follows it, so the state mutex is never held across one.
///
/// `client_factory` is `HostAgentClient::new` in production; tests
/// substitute a factory that targets a private, unreachable endpoint
/// instead of the process-default socket, without adding any Tauri command
/// parameter that would let the web UI choose one.
async fn dispatch_host_lifecycle_with<F>(
    state: &Mutex<RuntimeState>,
    enable: bool,
    client_factory: F,
) -> Result<RuntimeDispatchResult, RuntimeError>
where
    F: FnOnce() -> Result<HostAgentClient, HostAgentBridgeError>,
{
    let intent = if enable {
        RuntimeCommand::EnableHosting
    } else {
        RuntimeCommand::DisableHosting
    };
    let mut events = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.dispatch(intent)?.events
    };

    let outcome = match client_factory() {
        Ok(client) => {
            if enable {
                client.start().await
            } else {
                client.stop().await
            }
        }
        Err(error) => Err(error),
    };

    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    let result = if enable {
        runtime.apply_host_start_outcome(outcome)?
    } else {
        runtime.apply_host_stop_outcome(outcome)?
    };
    events.extend(result.events);
    Ok(RuntimeDispatchResult {
        snapshot: result.snapshot,
        events,
    })
}

// `host_agent_health` takes no frontend-supplied endpoint: the client
// always derives the process-default socket, so the web UI has no way to
// redirect it elsewhere. `host_agent_start`/`host_agent_stop` are
// deliberately not exposed as Tauri commands: `runtime_dispatch`'s
// `EnableHosting`/`DisableHosting`, via `dispatch_host_lifecycle`, is the
// only path that may start or stop the host agent, so `AppModel` and the
// real agent process can never disagree about whether hosting is running.
#[tauri::command]
async fn host_agent_health() -> Result<HostHealth, HostAgentBridgeError> {
    HostAgentClient::new()?.health().await
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
            let runtime = RuntimeState::from_settings_path(Some(settings_path))?;
            app.manage(Mutex::new(runtime));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            runtime_snapshot,
            runtime_settings,
            runtime_update_settings,
            runtime_dispatch,
            host_agent_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenStream desktop shell");
}

#[cfg(test)]
mod tests {
    use super::{dispatch_host_lifecycle_with, HostAgentClient, RuntimeError, RuntimeState};
    use openstream_app_core::HostStatus;
    use openstream_local_ipc::Endpoint;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    /// FIX 4: `EnableHosting` must actually call the real host agent, and a
    /// call that cannot even connect must leave `AppModel` in a typed
    /// failed state -- never the optimistic `Ready` a frontend-driven
    /// `HostReady` command used to be able to fabricate.
    #[tokio::test]
    async fn enable_hosting_reports_a_typed_failure_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let endpoint = unreachable_endpoint();

        let result = dispatch_host_lifecycle_with(&state, true, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect("the intent still applies even though the agent call fails");

        assert!(matches!(
            result.snapshot.app.host_status,
            HostStatus::Failed { .. }
        ));
    }

    /// FIX 4: the same path for `DisableHosting` -- a stop call that cannot
    /// even connect is a typed error, not one silently accepted as success.
    #[tokio::test]
    async fn disable_hosting_reports_a_typed_error_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let endpoint = unreachable_endpoint();

        let error = dispatch_host_lifecycle_with(&state, false, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect_err("a stop call that cannot connect must not be silently accepted");

        assert!(matches!(error, RuntimeError::CommandRejected { .. }));
    }
}
