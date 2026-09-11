//! Explicit host permission policy shared by every host adapter.
//!
//! Each capability defaults to off and is enabled only by an explicit
//! `=1` opt-in variable, so a host never grants input, clipboard, gamepad,
//! or microphone access by accident. Adapters log [`HostPolicy::log_line`]
//! once at startup; the line names grants without echoing any secret.

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
        Self {
            input: flag("OPENSTREAM_ENABLE_INPUT"),
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
            "host policy: input={} clipboard={} gamepad={} microphone={} approval={:?}",
            as_on_off(self.input),
            as_on_off(self.clipboard),
            as_on_off(self.gamepad),
            as_on_off(self.microphone),
            self.approval,
        )
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

    #[test]
    fn everything_defaults_to_off() {
        let _environment = lock_environment();
        let keys = [
            "OPENSTREAM_ENABLE_INPUT",
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
}
