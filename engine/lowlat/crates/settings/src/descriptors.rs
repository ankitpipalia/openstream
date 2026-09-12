use serde::{Deserialize, Serialize};

/// Where a setting is owned and persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingScope {
    Global,
    Client,
    Host,
    Device,
    Session,
}

/// When a changed setting becomes effective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingApplyMode {
    Live,
    Reconnect,
    RestartHost,
    RestartApplication,
}

/// Whether an option is normally shown, advanced, or experimental.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingVisibility {
    Normal,
    Advanced,
    Experimental,
}

/// Runtime truth for a setting or backend capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Experimental,
    Unavailable,
    NotImplemented,
}

/// Rust-owned metadata consumed by the desktop shell and future frontends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingDescriptor {
    pub key: &'static str,
    pub scope: SettingScope,
    pub apply_mode: SettingApplyMode,
    pub capability: CapabilityState,
    pub visibility: SettingVisibility,
}

/// Return the stable setting catalog. Keep keys additive and never reuse a key
/// for a different meaning; persisted settings and UI clients depend on them.
#[must_use]
pub fn setting_descriptors() -> Vec<SettingDescriptor> {
    vec![
        descriptor(
            "client.profile",
            SettingScope::Client,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.window_mode",
            SettingScope::Client,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.renderer",
            SettingScope::Client,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.vsync",
            SettingScope::Client,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.decoder",
            SettingScope::Client,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.codec",
            SettingScope::Session,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "client.chroma",
            SettingScope::Session,
            SettingApplyMode::Reconnect,
            CapabilityState::Experimental,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "client.bit_depth",
            SettingScope::Session,
            SettingApplyMode::Reconnect,
            CapabilityState::Experimental,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "client.immersive",
            SettingScope::Client,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "host.enabled",
            SettingScope::Host,
            SettingApplyMode::RestartHost,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "host.name",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "host.capture.drm",
            SettingScope::Host,
            SettingApplyMode::RestartHost,
            CapabilityState::Experimental,
            SettingVisibility::Experimental,
        ),
        descriptor(
            "host.capture.x11",
            SettingScope::Host,
            SettingApplyMode::RestartHost,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "host.stay_awake",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "input.keyboard",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "input.mouse",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Normal,
        ),
        descriptor(
            "input.gamepad",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Experimental,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "input.clipboard",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "input.microphone",
            SettingScope::Host,
            SettingApplyMode::Live,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "network.client_port",
            SettingScope::Global,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "network.host_start_port",
            SettingScope::Host,
            SettingApplyMode::RestartHost,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "network.upnp",
            SettingScope::Global,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
        descriptor(
            "network.turn",
            SettingScope::Global,
            SettingApplyMode::Reconnect,
            CapabilityState::Available,
            SettingVisibility::Advanced,
        ),
    ]
}

const fn descriptor(
    key: &'static str,
    scope: SettingScope,
    apply_mode: SettingApplyMode,
    capability: CapabilityState,
    visibility: SettingVisibility,
) -> SettingDescriptor {
    SettingDescriptor {
        key,
        scope,
        apply_mode,
        capability,
        visibility,
    }
}
