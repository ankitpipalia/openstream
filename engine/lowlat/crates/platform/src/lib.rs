//! Compile-time platform boundary shared by desktop and mobile front ends.
//!
//! This crate reports capability *policy*; it does not grant any OS privilege.
//! The host daemon still has to open the display, capture, encoder, audio, and
//! input devices explicitly. Keeping this report independent of those SDKs
//! lets the protocol/client crates build for Windows, macOS, Linux, Android,
//! and iOS before each native adapter is linked.
//!
//! "Policy" means *which platforms have an implementation*, decided at compile
//! time -- not whether a given machine's hardware is present and working. The
//! runtime, per-device truth (does this box actually have a usable capture and
//! encoder right now?) lives in the `openstream-capability` crate, whose
//! [`host_capable`](../openstream_capability/fn.host_capable.html) inspects
//! probed device records. `host_capable()` here answering `true` means only
//! that this build *could* host; the capability registry decides whether it
//! *does*.

pub mod capability_bridge;
pub mod clipboard;
pub mod clipboard_policy;
pub mod host_heartbeat;
pub mod hwaccel;
pub mod policy;
pub mod process_containment;

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
    // Whether a *host implementation exists* for this platform -- compile-time
    // policy, not a promise that a given machine's capture/encode hardware is
    // present and working. That runtime question is answered by
    // `openstream_capability::host_capable` against probed per-device records.
    //
    // A host session is driven by the host agent, which refuses to start off
    // Unix (`#[cfg(not(unix))] fn main` exits in host-agent and ffmpeg-host).
    // Windows therefore has no host path yet and must not claim host
    // capability even though it is a desktop OS -- reporting Windows as
    // host-capable was the pre-1.1 lie this corrects. Linux and macOS both run
    // the Unix host agent and have a real ffmpeg-host capture backend, so they
    // keep host policy; Android and iOS are excluded as before.
    cfg!(any(target_os = "linux", target_os = "macos"))
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
    fn only_platforms_with_a_host_implementation_have_host_policy() {
        let capabilities = current();
        // Linux and macOS run the Unix host agent and have an ffmpeg-host
        // capture backend, so they carry host policy.
        if matches!(capabilities.operating_system, "linux" | "macos") {
            assert!(capabilities.host_capable);
        }
        // Windows is a desktop OS but has no host path yet: the host agent
        // refuses to start off Unix. It must report client-only, not host.
        if capabilities.operating_system == "windows" {
            assert!(
                !capabilities.host_capable,
                "Windows has no host backend and must not claim host capability"
            );
            assert!(capabilities.client_capable);
        }
        // Mobile targets are client-only as before.
        if matches!(capabilities.operating_system, "android" | "ios") {
            assert!(!capabilities.host_capable);
            assert!(capabilities.client_capable);
        }
    }
}
