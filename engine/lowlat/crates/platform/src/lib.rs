//! Compile-time platform boundary shared by desktop and mobile front ends.
//!
//! This crate reports capability policy; it does not grant any OS privilege.
//! The host daemon still has to open the display, capture, encoder, audio, and
//! input devices explicitly. Keeping this report independent of those SDKs
//! lets the protocol/client crates build for Windows, macOS, Linux, Android,
//! and iOS before each native adapter is linked.

pub mod clipboard;
pub mod clipboard_policy;
pub mod hwaccel;
pub mod policy;

/// Build-time and product capability report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub host_capable: bool,
    pub client_capable: bool,
    pub capture: CaptureBackend,
    pub render: RenderBackend,
}

/// Capture families available to the eventual host adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    LinuxDisplay,
    WindowsDesktop,
    MacScreen,
    MobileNone,
    Unsupported,
}

/// Rendering families available to the eventual client adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderBackend {
    DesktopGpu,
    AndroidSurface,
    IosMetal,
    Unsupported,
}

/// Return the capability policy compiled into this target.
pub const fn current() -> Capabilities {
    Capabilities {
        operating_system: operating_system(),
        architecture: architecture(),
        host_capable: host_capable(),
        client_capable: client_capable(),
        capture: capture_backend(),
        render: render_backend(),
    }
}

const fn operating_system() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    }
}

const fn architecture() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "other"
    }
}

const fn host_capable() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    ))
}

const fn client_capable() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android",
        target_os = "ios"
    ))
}

const fn capture_backend() -> CaptureBackend {
    if cfg!(target_os = "linux") {
        CaptureBackend::LinuxDisplay
    } else if cfg!(target_os = "windows") {
        CaptureBackend::WindowsDesktop
    } else if cfg!(target_os = "macos") {
        CaptureBackend::MacScreen
    } else if cfg!(any(target_os = "android", target_os = "ios")) {
        CaptureBackend::MobileNone
    } else {
        CaptureBackend::Unsupported
    }
}

const fn render_backend() -> RenderBackend {
    if cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )) {
        RenderBackend::DesktopGpu
    } else if cfg!(target_os = "android") {
        RenderBackend::AndroidSurface
    } else if cfg!(target_os = "ios") {
        RenderBackend::IosMetal
    } else {
        RenderBackend::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build_is_always_a_client_or_explicitly_unsupported() {
        let capabilities = current();
        assert!(capabilities.operating_system != "unknown" || !capabilities.client_capable);
    }

    #[test]
    fn desktop_targets_have_host_policy_and_mobile_targets_do_not() {
        let capabilities = current();
        if matches!(capabilities.operating_system, "linux" | "windows" | "macos") {
            assert!(capabilities.host_capable);
        }
        if matches!(capabilities.operating_system, "android" | "ios") {
            assert!(!capabilities.host_capable);
            assert!(capabilities.client_capable);
        }
    }
}
