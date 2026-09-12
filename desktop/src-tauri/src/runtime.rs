use openstream_app_core::{
    AppCommand, AppError, AppErrorCode, AppEvent, AppModel, AppSnapshot, DiagnosticSnapshot,
    PermissionSet,
};
use openstream_settings::{
    default_config, load, save_atomic, setting_descriptors, AppConfig, SettingDescriptor,
    SettingsError,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;

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

/// The commands accepted from the product shell. It deliberately excludes
/// app-core's free-form failure messages and all credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeCommand {
    BeginAuthentication,
    AuthenticationSucceeded,
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
    ConnectionLost {
        retryable: bool,
    },
    Disconnect,
    Disconnected,
    EnableHosting,
    DisableHosting,
    HostReady,
    HostFailed {
        retryable: bool,
    },
}

impl RuntimeCommand {
    fn into_app_command(self) -> AppCommand {
        match self {
            Self::BeginAuthentication => AppCommand::BeginAuthentication,
            Self::AuthenticationSucceeded => AppCommand::AuthenticationSucceeded,
            Self::Connect {
                device_id,
                request_id,
                requested,
                now_ms,
            } => AppCommand::Connect {
                device_id,
                request_id,
                requested,
                now_ms,
            },
            Self::ApproveRequest {
                request_id,
                available,
                now_ms,
            } => AppCommand::ApproveRequest {
                request_id,
                available,
                now_ms,
            },
            Self::RejectRequest { request_id, now_ms } => {
                AppCommand::RejectRequest { request_id, now_ms }
            }
            Self::Tick { now_ms } => AppCommand::Tick { now_ms },
            Self::ConnectionNegotiating => AppCommand::ConnectionNegotiating,
            Self::ConnectionEstablished {
                session_id,
                generation,
            } => AppCommand::ConnectionEstablished {
                session_id,
                generation,
            },
            Self::ConnectionLost { retryable } => AppCommand::ConnectionLost { retryable },
            Self::Disconnect => AppCommand::Disconnect,
            Self::Disconnected => AppCommand::Disconnected,
            Self::EnableHosting => AppCommand::EnableHosting,
            Self::DisableHosting => AppCommand::DisableHosting,
            Self::HostReady => AppCommand::HostReady,
            Self::HostFailed { retryable } => AppCommand::HostFailed {
                message: "host failure reported by runtime".to_string(),
                retryable,
            },
        }
    }
}

/// State and persisted configuration owned by the desktop process.
#[derive(Debug)]
pub struct RuntimeState {
    app: AppModel,
    settings: AppConfig,
    settings_path: Option<PathBuf>,
    descriptors: Vec<SettingDescriptor>,
}

/// Secret-free state returned to the product shell.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeSnapshot {
    pub app: AppSnapshot,
    pub settings: AppConfig,
    pub descriptors: Vec<SettingDescriptor>,
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
        self.settings = settings;
        Ok(())
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            app: self.app.snapshot(DiagnosticSnapshot::default()),
            settings: self.settings.clone(),
            descriptors: self.descriptors.clone(),
        }
    }

    pub fn dispatch(
        &mut self,
        command: RuntimeCommand,
    ) -> Result<RuntimeDispatchResult, RuntimeError> {
        let events = self
            .app
            .dispatch(command.into_app_command())
            .map_err(RuntimeError::from)?;
        Ok(RuntimeDispatchResult {
            snapshot: self.snapshot(),
            events,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeCommand, RuntimeState};
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
        let result = state.dispatch(RuntimeCommand::BeginAuthentication).unwrap();
        assert!(serde_json::to_string(&result)
            .unwrap()
            .contains("AuthenticationStarted"));
        assert!(!serde_json::to_string(&result).unwrap().contains("pairing"));
    }
}
