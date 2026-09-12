use std::sync::Mutex;

use host_agent::{HostAgentBridgeError, HostAgentClient};
use openstream_host_agent::{HostAgentEvent, HostHealth};
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

#[tauri::command]
fn runtime_dispatch(
    state: tauri::State<'_, Mutex<RuntimeState>>,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    runtime.dispatch(command)
}

// The host-agent commands take no frontend-supplied endpoint: the client
// always derives the process-default socket, so the web UI has no way to
// redirect these calls elsewhere.
#[tauri::command]
async fn host_agent_health() -> Result<HostHealth, HostAgentBridgeError> {
    HostAgentClient::new()?.health().await
}

#[tauri::command]
async fn host_agent_start() -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
    HostAgentClient::new()?.start().await
}

#[tauri::command]
async fn host_agent_stop() -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
    HostAgentClient::new()?.stop().await
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
            host_agent_health,
            host_agent_start,
            host_agent_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenStream desktop shell");
}
