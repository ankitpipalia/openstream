//! Explicit host permission policy shared by every host adapter.
//!
//! Each capability defaults to off and is enabled only by an explicit
//! `=1` opt-in variable, so a host never grants input, clipboard, gamepad,
//! or microphone access by accident. Adapters log [`HostPolicy::log_line`]
//! once at startup; the line names grants without echoing any secret.

/// A device-facing capability whose status is reported separately from the
/// encrypted media protocol's coarse negotiated booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCapability {
    /// Keyboard, pointer, and wheel injection.
    Input,
    /// Text clipboard synchronization.
    Clipboard,
    /// Compressed guest microphone intake.
    Microphone,
    /// Host-side virtual gamepad injection.
    Gamepad,
    /// Full tablet/stylus semantics, including pressure and tilt.
    Tablet,
    /// An OS-visible microphone endpoint for applications on the host.
    VirtualMicrophone,
    /// Creation of an OS-level virtual monitor.
    VirtualDisplay,
    /// Privileged USB or HID passthrough.
    VirtualUsb,
}

/// Whether the current OpenStream protocol has a capability vocabulary for a
/// device feature. This is intentionally independent from the local adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    Supported,
    Unsupported,
}

/// Whether this build contains a real adapter for a device feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    Implemented,
    NotImplemented,
}

/// Result of a bounded runtime probe such as opening `/dev/uinput` or finding
/// both clipboard helper commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAvailability {
    Available,
    Unavailable(UnavailableReason),
}

/// Whether a physical-device acceptance test has been recorded for the
/// adapter. A unit test or compile check is not a hardware test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareValidation {
    Tested,
    NotTested,
}

/// Why a device capability is not available at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    DisabledByPolicy,
    UnsupportedPlatform,
    ProtocolNotSupported,
    AdapterNotImplemented,
    PermissionDenied,
    DeviceUnavailable,
    OsApiUnavailable,
}

/// A capability report keeps protocol support, implementation, runtime
/// availability, and hardware validation as independent facts. Callers must
/// use [`Self::can_advertise`] instead of inferring readiness from one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCapabilityStatus {
    pub capability: DeviceCapability,
    pub protocol: ProtocolSupport,
    pub implementation: ImplementationStatus,
    pub availability: RuntimeAvailability,
    pub hardware: HardwareValidation,
}

impl DeviceCapabilityStatus {
    /// Whether the protocol can represent this feature.
    #[must_use]
    pub const fn protocol_supported(self) -> bool {
        matches!(self.protocol, ProtocolSupport::Supported)
    }

    /// Whether this build has a real local adapter.
    #[must_use]
    pub const fn implemented(self) -> bool {
        matches!(self.implementation, ImplementationStatus::Implemented)
    }

    /// Whether the bounded local probe succeeded.
    #[must_use]
    pub const fn available(self) -> bool {
        matches!(self.availability, RuntimeAvailability::Available)
    }

    /// Whether it is truthful to advertise this feature to a peer.
    ///
    /// Hardware validation is reported separately and is deliberately not
    /// treated as a runtime promise: a present adapter can be advertised as
    /// available while the UI still says it has not passed physical testing.
    #[must_use]
    pub const fn can_advertise(self) -> bool {
        self.protocol_supported() && self.implemented() && self.available()
    }
}

/// Runtime results supplied by platform adapters to the policy report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapabilityProbes {
    pub input: RuntimeAvailability,
    pub clipboard: RuntimeAvailability,
    pub microphone: RuntimeAvailability,
}

/// Truthful host-side device capability catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostDeviceCapabilities {
    pub input: DeviceCapabilityStatus,
    pub clipboard: DeviceCapabilityStatus,
    pub microphone: DeviceCapabilityStatus,
    pub gamepad: DeviceCapabilityStatus,
    pub tablet: DeviceCapabilityStatus,
    pub virtual_microphone: DeviceCapabilityStatus,
    pub virtual_display: DeviceCapabilityStatus,
    pub virtual_usb: DeviceCapabilityStatus,
}

impl HostDeviceCapabilities {
    /// Combine explicit policy and adapter probes with compile-time platform
    /// implementation facts. Unsupported virtual devices remain unavailable
    /// even when an operator sets an unrelated opt-in environment variable.
    #[must_use]
    pub fn discover(policy: HostPolicy, probes: HostCapabilityProbes) -> Self {
        let input_implementation = desktop_implementation();
        let clipboard_implementation = desktop_implementation();
        let microphone_implementation = desktop_implementation();
        let gamepad_implementation = if cfg!(target_os = "linux") {
            ImplementationStatus::Implemented
        } else {
            ImplementationStatus::NotImplemented
        };
        let tablet_implementation = ImplementationStatus::NotImplemented;
        let virtual_implementation = ImplementationStatus::NotImplemented;

        Self {
            input: report(
                DeviceCapability::Input,
                ProtocolSupport::Supported,
                input_implementation,
                policy.input,
                probes.input,
            ),
            clipboard: report(
                DeviceCapability::Clipboard,
                ProtocolSupport::Supported,
                clipboard_implementation,
                policy.clipboard,
                probes.clipboard,
            ),
            microphone: report(
                DeviceCapability::Microphone,
                ProtocolSupport::Supported,
                microphone_implementation,
                policy.microphone,
                probes.microphone,
            ),
            gamepad: report(
                DeviceCapability::Gamepad,
                ProtocolSupport::Supported,
                gamepad_implementation,
                policy.input && policy.gamepad,
                probes.input,
            ),
            tablet: unimplemented(
                DeviceCapability::Tablet,
                ProtocolSupport::Supported,
                tablet_implementation,
            ),
            virtual_microphone: unimplemented(
                DeviceCapability::VirtualMicrophone,
                ProtocolSupport::Unsupported,
                virtual_implementation,
            ),
            virtual_display: unimplemented(
                DeviceCapability::VirtualDisplay,
                ProtocolSupport::Unsupported,
                virtual_implementation,
            ),
            virtual_usb: unimplemented(
                DeviceCapability::VirtualUsb,
                ProtocolSupport::Unsupported,
                virtual_implementation,
            ),
        }
    }

    /// Redacted startup summary. It names state, not credentials or device
    /// contents, and makes `implemented` distinct from `hardware tested`.
    #[must_use]
    pub fn log_line(self) -> String {
        format!(
            "device capabilities: input={} clipboard={} microphone={} gamepad={} tablet={} virtual_microphone={} virtual_display={} virtual_usb={}",
            self.input.log_value(),
            self.clipboard.log_value(),
            self.microphone.log_value(),
            self.gamepad.log_value(),
            self.tablet.log_value(),
            self.virtual_microphone.log_value(),
            self.virtual_display.log_value(),
            self.virtual_usb.log_value(),
        )
    }
}

impl DeviceCapabilityStatus {
    fn log_value(self) -> String {
        let protocol = match self.protocol {
            ProtocolSupport::Supported => "supported",
            ProtocolSupport::Unsupported => "unsupported",
        };
        let implementation = match self.implementation {
            ImplementationStatus::Implemented => "implemented",
            ImplementationStatus::NotImplemented => "not_implemented",
        };
        let availability = match self.availability {
            RuntimeAvailability::Available => "available".to_string(),
            RuntimeAvailability::Unavailable(reason) => {
                format!("unavailable(reason={reason:?})")
            }
        };
        let hardware = match self.hardware {
            HardwareValidation::Tested => "tested",
            HardwareValidation::NotTested => "not_tested",
        };
        format!(
            "protocol={protocol} implementation={implementation} availability={availability} hardware={hardware} advertisable={}",
            if self.can_advertise() { "yes" } else { "no" },
        )
    }
}

fn desktop_implementation() -> ImplementationStatus {
    if cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )) {
        ImplementationStatus::Implemented
    } else {
        ImplementationStatus::NotImplemented
    }
}

fn report(
    capability: DeviceCapability,
    protocol: ProtocolSupport,
    implementation: ImplementationStatus,
    policy_enabled: bool,
    probe: RuntimeAvailability,
) -> DeviceCapabilityStatus {
    let availability = if !matches!(protocol, ProtocolSupport::Supported) {
        RuntimeAvailability::Unavailable(UnavailableReason::ProtocolNotSupported)
    } else if !matches!(implementation, ImplementationStatus::Implemented) {
        RuntimeAvailability::Unavailable(UnavailableReason::AdapterNotImplemented)
    } else if !policy_enabled {
        RuntimeAvailability::Unavailable(UnavailableReason::DisabledByPolicy)
    } else {
        probe
    };
    DeviceCapabilityStatus {
        capability,
        protocol,
        implementation,
        availability,
        hardware: HardwareValidation::NotTested,
    }
}

fn unimplemented(
    capability: DeviceCapability,
    protocol: ProtocolSupport,
    implementation: ImplementationStatus,
) -> DeviceCapabilityStatus {
    report(
        capability,
        protocol,
        implementation,
        true,
        RuntimeAvailability::Unavailable(UnavailableReason::AdapterNotImplemented),
    )
}

/// How a guest session is approved before media starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Approval {
    /// Whoever presents the session bearer token joins (development and
    /// trusted-network default; the token itself is the capability).
    #[default]
    Auto,
    /// Reserved for an owner-approval prompt; adapters without a UI surface
    /// must refuse to start in this mode rather than silently downgrading.
    OwnerOnly,
}

impl Approval {
    fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "owner" | "owner-only" | "prompt" => Self::OwnerOnly,
            _ => Self::Auto,
        }
    }
}

/// Effective permission grants for one host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPolicy {
    pub input: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub clipboard: bool,
    pub gamepad: bool,
    pub microphone: bool,
    pub approval: Approval,
}

impl HostPolicy {
    /// Read the policy from the process environment.
    ///
    /// | Grant | Opt-in variable |
    /// |---|---|---|
    /// | keyboard/pointer/wheel | `OPENSTREAM_ENABLE_INPUT=1` |
    /// | clipboard sync | `OPENSTREAM_CLIPBOARD=1` |
    /// | gamepad + rumble | `OPENSTREAM_GAMEPAD=1` |
    /// | microphone passthrough | `OPENSTREAM_MIC=1` |
    /// Approval mode comes from `OPENSTREAM_APPROVAL` (`auto`/`owner`).
    pub fn from_env() -> Self {
        let flag = |name: &str| std::env::var(name).as_deref() == Ok("1");
        // Per-class grants are three-state: explicitly on ("1"), explicitly
        // off ("0"), or unset. An explicit value is authoritative, so a caller
        // that enables input but revokes one class keeps that class off; an
        // unset class inherits the master input grant as a convenience. Reading
        // it as `input || flag(class)` instead let the master flag re-enable a
        // class the caller had explicitly disabled -- the host agent emits
        // ENABLE_INPUT=1 with ENABLE_MOUSE=0 for keyboard-only, which then
        // granted pointer control the user had revoked.
        let class = |name: &str, default: bool| match std::env::var(name).as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            _ => default,
        };
        let input = flag("OPENSTREAM_ENABLE_INPUT");
        let keyboard = class("OPENSTREAM_ENABLE_KEYBOARD", input);
        let mouse = class("OPENSTREAM_ENABLE_MOUSE", input);
        Self {
            // `input` is the adapter-level grant. Explicit keyboard/mouse
            // grants are also input grants so a caller can revoke one class
            // without accidentally disabling the other class at discovery.
            input: input || keyboard || mouse,
            keyboard,
            mouse,
            clipboard: flag("OPENSTREAM_CLIPBOARD"),
            gamepad: flag("OPENSTREAM_GAMEPAD"),
            microphone: flag("OPENSTREAM_MIC"),
            approval: std::env::var("OPENSTREAM_APPROVAL")
                .ok()
                .map(|mode| Approval::parse(&mode))
                .unwrap_or_default(),
        }
    }

    /// One redacted startup-log line naming the effective grants.
    pub fn log_line(&self) -> String {
        format!(
            "host policy: input={} keyboard={} mouse={} clipboard={} gamepad={} microphone={} approval={:?}",
            as_on_off(self.input),
            as_on_off(self.keyboard),
            as_on_off(self.mouse),
            as_on_off(self.clipboard),
            as_on_off(self.gamepad),
            as_on_off(self.microphone),
            self.approval,
        )
    }

    /// Narrow this machine-wide policy to what one specific session was
    /// granted.
    ///
    /// This policy is the owner's ceiling for the machine; a session's
    /// granted permissions are a second, independent ceiling for what *that
    /// session's guest* may drive. Neither alone is enough -- an owner who
    /// enables input globally must not thereby grant it to a guest the
    /// broker scoped to view-only, and a broker grant must not re-enable a
    /// class the owner turned off here -- so the result can only be as
    /// permissive as the stricter of the two. Each `session_allows_*`
    /// parameter is the caller's already-resolved verdict for that class
    /// (true both when the session's ceiling permits it and when there is no
    /// ceiling to apply); this method only ever narrows, never widens, this
    /// policy in response.
    ///
    /// `input`, `approval`, and every other field this type may grow are
    /// deliberately left untouched: they describe the adapter and the
    /// approval flow, not a per-class grant a session can be scoped by.
    #[must_use]
    pub fn scoped_to_session(
        self,
        session_allows_keyboard: bool,
        session_allows_mouse: bool,
        session_allows_gamepad: bool,
        session_allows_clipboard: bool,
        session_allows_microphone: bool,
    ) -> Self {
        Self {
            keyboard: self.keyboard && session_allows_keyboard,
            mouse: self.mouse && session_allows_mouse,
            gamepad: self.gamepad && session_allows_gamepad,
            clipboard: self.clipboard && session_allows_clipboard,
            microphone: self.microphone && session_allows_microphone,
            ..self
        }
    }
}

fn as_on_off(granted: bool) -> &'static str {
    if granted { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_environment() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn save(keys: &[&'static str]) -> Vec<(&'static str, Option<String>)> {
        keys.iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect()
    }

    fn restore(saved: Vec<(&str, Option<String>)>) {
        for (key, value) in saved {
            unsafe {
                match value {
                    Some(previous) => std::env::set_var(key, previous),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// What the capability report advertises and what the injector will act
    /// on must agree, for every reachable policy.
    ///
    /// The interesting case is a gamepad-only grant: `input` on with
    /// `keyboard` and `mouse` both off. That is a configuration an operator
    /// can actually set, the report advertises gamepad for it, and the
    /// injector previously discarded the grant -- so the host negotiated a
    /// capability it would then refuse to use.
    #[test]
    fn advertised_gamepad_support_matches_the_injector_grant() {
        let policy = HostPolicy {
            input: true,
            keyboard: false,
            mouse: false,
            clipboard: false,
            gamepad: true,
            microphone: false,
            approval: Approval::Auto,
        };
        let capabilities = HostDeviceCapabilities::discover(
            policy,
            HostCapabilityProbes {
                input: RuntimeAvailability::Available,
                clipboard: RuntimeAvailability::Unavailable(UnavailableReason::DisabledByPolicy),
                microphone: RuntimeAvailability::Unavailable(UnavailableReason::DisabledByPolicy),
            },
        );

        // The gamepad adapter only exists on Linux, so this is the only
        // platform on which the report can advertise it at all.
        if cfg!(target_os = "linux") {
            assert!(
                capabilities.gamepad.can_advertise(),
                "a gamepad-only policy advertises gamepad support"
            );
        }

        // Whatever the report says, the injector must agree. The host adapter
        // applies the master input gate to each grant, exactly as here.
        //
        // Unix-only because `lowlat-inject` does not build for Windows; see
        // the dev-dependency's target gate in Cargo.toml.
        #[cfg(unix)]
        {
            let permissions = lowlat_inject::event::Permissions::from_keyboard_pointer_grants(
                policy.input && policy.keyboard,
                policy.input && policy.mouse,
                policy.input && policy.gamepad,
            );
            assert!(
                permissions.gamepad,
                "the injector must act on the gamepad grant the report advertised"
            );
            assert!(!permissions.keyboard);
            assert!(!permissions.pointer);
        }
    }

    #[test]
    fn everything_defaults_to_off() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
            "OPENSTREAM_ENABLE_KEYBOARD",
            "OPENSTREAM_ENABLE_MOUSE",
            "OPENSTREAM_CLIPBOARD",
            "OPENSTREAM_GAMEPAD",
            "OPENSTREAM_MIC",
            "OPENSTREAM_APPROVAL",
        ];
        let saved = save(&keys);
        unsafe {
            for key in &keys {
                std::env::remove_var(key);
            }
        }
        let policy = HostPolicy::from_env();
        assert_eq!(
            policy,
            HostPolicy {
                input: false,
                keyboard: false,
                mouse: false,
                clipboard: false,
                gamepad: false,
                microphone: false,
                approval: Approval::Auto,
            }
        );
        assert!(policy.log_line().contains("input=off"));
        restore(saved);
    }

    #[test]
    fn explicit_opt_ins_enable_each_grant() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
            "OPENSTREAM_ENABLE_KEYBOARD",
            "OPENSTREAM_ENABLE_MOUSE",
            "OPENSTREAM_CLIPBOARD",
            "OPENSTREAM_GAMEPAD",
            "OPENSTREAM_MIC",
            "OPENSTREAM_APPROVAL",
        ];
        let saved = save(&keys);
        unsafe {
            std::env::set_var("OPENSTREAM_ENABLE_INPUT", "1");
            std::env::set_var("OPENSTREAM_CLIPBOARD", "1");
            std::env::set_var("OPENSTREAM_GAMEPAD", "1");
            std::env::set_var("OPENSTREAM_MIC", "1");
            std::env::set_var("OPENSTREAM_APPROVAL", "owner");
        }
        let policy = HostPolicy::from_env();
        assert!(policy.input && policy.clipboard && policy.gamepad && policy.microphone);
        assert_eq!(policy.approval, Approval::OwnerOnly);
        let line = policy.log_line();
        assert!(line.contains("clipboard=on") && line.contains("approval=OwnerOnly"));
        restore(saved);
    }

    #[test]
    fn master_input_does_not_override_an_explicit_per_class_disable() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
            "OPENSTREAM_ENABLE_KEYBOARD",
            "OPENSTREAM_ENABLE_MOUSE",
        ];
        let saved = save(&keys);
        // Exactly what the host agent emits for keyboard-on, mouse-off:
        // the master input grant plus an explicit per-class disable.
        unsafe {
            std::env::set_var("OPENSTREAM_ENABLE_INPUT", "1");
            std::env::set_var("OPENSTREAM_ENABLE_KEYBOARD", "1");
            std::env::set_var("OPENSTREAM_ENABLE_MOUSE", "0");
        }
        let policy = HostPolicy::from_env();
        assert!(policy.keyboard, "the granted class stays on");
        assert!(
            !policy.mouse,
            "an explicitly revoked class must not be re-enabled by the master flag"
        );
        assert!(policy.input, "input is still on because a class is granted");
        restore(saved);
    }

    #[test]
    fn master_input_enables_unset_classes_by_default() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
            "OPENSTREAM_ENABLE_KEYBOARD",
            "OPENSTREAM_ENABLE_MOUSE",
        ];
        let saved = save(&keys);
        unsafe {
            std::env::set_var("OPENSTREAM_ENABLE_INPUT", "1");
            std::env::remove_var("OPENSTREAM_ENABLE_KEYBOARD");
            std::env::remove_var("OPENSTREAM_ENABLE_MOUSE");
        }
        let policy = HostPolicy::from_env();
        assert!(
            policy.keyboard && policy.mouse,
            "unset classes inherit the master input grant"
        );
        restore(saved);
    }

    #[test]
    fn a_per_class_grant_without_the_master_flag_still_enables_input() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
            "OPENSTREAM_ENABLE_KEYBOARD",
            "OPENSTREAM_ENABLE_MOUSE",
        ];
        let saved = save(&keys);
        unsafe {
            std::env::remove_var("OPENSTREAM_ENABLE_INPUT");
            std::env::set_var("OPENSTREAM_ENABLE_KEYBOARD", "1");
            std::env::remove_var("OPENSTREAM_ENABLE_MOUSE");
        }
        let policy = HostPolicy::from_env();
        assert!(policy.keyboard && policy.input && !policy.mouse);
        restore(saved);
    }

    #[test]
    fn nonstandard_values_do_not_enable_grants() {
        let _environment = lock_environment();
        let keys = ["OPENSTREAM_ENABLE_INPUT", "OPENSTREAM_CLIPBOARD"];
        let saved = save(&keys);
        unsafe {
            std::env::set_var("OPENSTREAM_ENABLE_INPUT", "yes");
            std::env::set_var("OPENSTREAM_CLIPBOARD", "true");
        }
        let policy = HostPolicy::from_env();
        assert!(!policy.input && !policy.clipboard);
        restore(saved);
    }

    fn wide_open_policy() -> HostPolicy {
        HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: true,
            gamepad: true,
            microphone: true,
            approval: Approval::Auto,
        }
    }

    /// A session granted every class changes nothing: the owner's policy is
    /// still the only ceiling in effect.
    #[test]
    fn a_session_granted_everything_leaves_the_policy_unchanged() {
        let policy = wide_open_policy();
        assert_eq!(
            policy.scoped_to_session(true, true, true, true, true),
            policy
        );
    }

    /// A session denied one class loses exactly that class, regardless of
    /// what the owner's own policy allows.
    #[test]
    fn a_session_denied_one_class_loses_only_that_class() {
        let scoped = wide_open_policy().scoped_to_session(false, true, true, true, true);
        assert!(!scoped.keyboard);
        assert!(scoped.mouse && scoped.gamepad && scoped.clipboard && scoped.microphone);
    }

    /// The session's grant can only narrow, never widen: a class the owner's
    /// own policy already denies stays denied even if the session says yes.
    #[test]
    fn the_session_cannot_re_enable_a_class_the_owner_denied() {
        let owner_denies_clipboard = HostPolicy {
            clipboard: false,
            ..wide_open_policy()
        };
        let scoped = owner_denies_clipboard.scoped_to_session(true, true, true, true, true);
        assert!(!scoped.clipboard, "the session must not override the owner");
    }

    /// `input` and `approval` describe the adapter and the approval flow,
    /// not a per-class grant, so scoping to a session must not touch them.
    #[test]
    fn scoping_never_touches_input_or_approval() {
        let policy = HostPolicy {
            approval: Approval::OwnerOnly,
            ..wide_open_policy()
        };
        let scoped = policy.scoped_to_session(false, false, false, false, false);
        assert!(
            scoped.input,
            "input describes the adapter, not a session grant"
        );
        assert_eq!(scoped.approval, Approval::OwnerOnly);
    }

    fn available_probes() -> HostCapabilityProbes {
        HostCapabilityProbes {
            input: RuntimeAvailability::Available,
            clipboard: RuntimeAvailability::Available,
            microphone: RuntimeAvailability::Available,
        }
    }

    #[test]
    fn capability_report_keeps_support_layers_separate() {
        let policy = HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: true,
            gamepad: true,
            microphone: true,
            approval: Approval::Auto,
        };
        let capabilities = HostDeviceCapabilities::discover(policy, available_probes());

        assert!(capabilities.input.implemented());
        assert!(capabilities.input.available());
        assert!(capabilities.input.can_advertise());
        assert_eq!(capabilities.input.hardware, HardwareValidation::NotTested);
        assert!(!capabilities.tablet.can_advertise());
        assert_eq!(
            capabilities.tablet.implementation,
            ImplementationStatus::NotImplemented
        );
        assert!(!capabilities.virtual_microphone.can_advertise());
        assert_eq!(
            capabilities.virtual_microphone.protocol,
            ProtocolSupport::Unsupported
        );
        assert!(!capabilities.virtual_display.can_advertise());
        assert!(!capabilities.virtual_usb.can_advertise());
    }

    #[test]
    fn policy_or_runtime_failure_never_becomes_an_advertisement() {
        let policy = HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: false,
            gamepad: true,
            microphone: true,
            approval: Approval::Auto,
        };
        let capabilities = HostDeviceCapabilities::discover(
            policy,
            HostCapabilityProbes {
                input: RuntimeAvailability::Unavailable(UnavailableReason::PermissionDenied),
                clipboard: RuntimeAvailability::Available,
                microphone: RuntimeAvailability::Unavailable(UnavailableReason::DeviceUnavailable),
            },
        );

        assert!(!capabilities.input.can_advertise());
        assert_eq!(
            capabilities.input.availability,
            RuntimeAvailability::Unavailable(UnavailableReason::PermissionDenied)
        );
        assert!(!capabilities.clipboard.can_advertise());
        assert_eq!(
            capabilities.clipboard.availability,
            RuntimeAvailability::Unavailable(UnavailableReason::DisabledByPolicy)
        );
        assert!(!capabilities.microphone.can_advertise());
        assert_eq!(
            capabilities.microphone.availability,
            RuntimeAvailability::Unavailable(UnavailableReason::DeviceUnavailable)
        );
    }

    #[test]
    fn unsupported_desktop_virtual_adapters_are_not_ready() {
        let policy = HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: false,
            gamepad: true,
            microphone: true,
            approval: Approval::Auto,
        };
        let capabilities = HostDeviceCapabilities::discover(policy, available_probes());

        assert!(!capabilities.virtual_microphone.available());
        assert!(!capabilities.virtual_display.available());
        assert!(!capabilities.virtual_usb.available());
        #[cfg(not(target_os = "linux"))]
        assert!(!capabilities.gamepad.can_advertise());
    }

    #[test]
    fn capability_log_names_each_support_layer() {
        let policy = HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: false,
            gamepad: true,
            microphone: false,
            approval: Approval::Auto,
        };
        let capabilities = HostDeviceCapabilities::discover(policy, available_probes());
        let line = capabilities.log_line();

        assert!(line.contains(&format!("input={}", capabilities.input.log_value())));
        assert!(line.contains(
            "virtual_usb=protocol=unsupported implementation=not_implemented availability=unavailable(reason=ProtocolNotSupported) hardware=not_tested advertisable=no"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_gamepad_requires_both_input_and_gamepad_policy() {
        let mut policy = HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: false,
            gamepad: false,
            microphone: false,
            approval: Approval::Auto,
        };
        assert!(
            !HostDeviceCapabilities::discover(policy, available_probes())
                .gamepad
                .can_advertise()
        );

        policy.gamepad = true;
        assert!(
            HostDeviceCapabilities::discover(policy, available_probes())
                .gamepad
                .can_advertise()
        );
    }
}
