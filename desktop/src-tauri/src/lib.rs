use std::sync::Mutex;

use openstream_app_core::{AppModel, AppSnapshot, DiagnosticSnapshot};
use openstream_settings::{SettingDescriptor, setting_descriptors as build_setting_descriptors};

#[tauri::command]
fn app_snapshot(state: tauri::State<'_, Mutex<AppModel>>) -> Result<AppSnapshot, String> {
    let model = state
        .lock()
        .map_err(|_| "OpenStream application state is unavailable".to_string())?;
    Ok(model.snapshot(DiagnosticSnapshot::default()))
}

#[tauri::command]
fn setting_descriptors() -> Vec<SettingDescriptor> {
    build_setting_descriptors()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(AppModel::local_default()))
        .invoke_handler(tauri::generate_handler![app_snapshot, setting_descriptors])
        .run(tauri::generate_context!())
        .expect("error while running OpenStream desktop shell");
}
