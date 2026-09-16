//! The privileged broker binary.
//!
//! On Linux this binds the broker socket, authorises the connecting machine
//! service by peer credentials, and serves it against the real DRM capture and
//! `uinput` injection. The native server lands in a following change; this entry
//! point answers `--version` for the packaging gate and refuses to run on
//! platforms it does not support.

fn main() {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--version")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "openstream-host-broker: the protocol core is in place; the native DRM/uinput server is wired in a following change"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("openstream-host-broker runs only on Linux");
    }
}
