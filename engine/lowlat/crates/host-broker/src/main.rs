//! The privileged broker binary.
//!
//! On Linux it binds the broker socket under `/run/openstream`, authorises the
//! connecting machine service by peer credentials, and serves it against the
//! real DRM capture and `uinput` injection. It reads two settings from the
//! environment: `OPENSTREAM_BROKER_SOCKET` (the socket path) and
//! `OPENSTREAM_BROKER_SERVICE_UID` (the machine-service account to admit;
//! default `0`, i.e. only root, until a dedicated account is provisioned).

fn is_version_request() -> bool {
    std::env::args()
        .skip(1)
        .any(|argument| argument == "--version")
}

fn print_version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    if is_version_request() {
        print_version();
        return ExitCode::SUCCESS;
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openstream-host-broker: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
async fn run() -> std::io::Result<()> {
    use openstream_host_broker::server::{BrokerServer, DEFAULT_SOCKET};
    use openstream_host_broker::session::{BrokerPolicy, GrantAuthority};
    use openstream_host_ipc::peercred::AllowedPeers;

    let socket =
        std::env::var("OPENSTREAM_BROKER_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    let allowed = match std::env::var("OPENSTREAM_BROKER_SERVICE_UID") {
        Ok(value) => {
            let uid = value.trim().parse::<u32>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "OPENSTREAM_BROKER_SERVICE_UID must be a numeric uid",
                )
            })?;
            AllowedPeers::only(uid)
        }
        // Until a dedicated machine-service account exists, admit only root, so
        // both halves run privileged during bring-up rather than open to all.
        Err(_) => AllowedPeers::only(0),
    };
    // The ceiling comes from the root broker's own environment, set by its
    // systemd unit. The machine service runs as a different, unprivileged user
    // and cannot write it -- which is the point: what the broker will ever
    // grant must not be decided by the network-facing process asking.
    //
    // Unset means nothing is granted. A broker that has not been told what the
    // operator allows has not been told it may hand out the keyboard.
    let ceiling = match std::env::var("OPENSTREAM_BROKER_CEILING") {
        Ok(spec) => openstream_host_broker::session::parse_ceiling(&spec).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("OPENSTREAM_BROKER_CEILING: {error}"),
            )
        })?,
        Err(_) => openstream_host_ipc::token::Capabilities::none(),
    };
    eprintln!("openstream-host-broker: capability ceiling {ceiling:?}");
    let policy = BrokerPolicy {
        ceiling,
        ..BrokerPolicy::default()
    };
    // Who may say a session was approved.
    //
    // The key is read from a file, not from the environment: an environment
    // variable is visible in /proc to anyone who can read the process's
    // environ, and the whole point of this secret is that the unprivileged
    // machine service cannot obtain it. The file should be mode 0600 and owned
    // by the broker's user; the broker refuses to use one that anybody else
    // can read, because a secret the service can read is not a boundary.
    let authority = match std::env::var("OPENSTREAM_BROKER_GRANT_KEY_FILE") {
        Ok(path) => {
            let key = read_grant_key(&path)?;
            let device_id = std::env::var("OPENSTREAM_BROKER_DEVICE_ID").map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "OPENSTREAM_BROKER_GRANT_KEY_FILE is set but OPENSTREAM_BROKER_DEVICE_ID is not; \
                     a grant names the device it was issued for and the broker has to know which it is",
                )
            })?;
            eprintln!("openstream-host-broker: verifying approvals for device {device_id}");
            GrantAuthority::new(key, device_id)
        }
        Err(_) => {
            eprintln!(
                "openstream-host-broker: no grant key configured; every session will be refused"
            );
            GrantAuthority::unconfigured()
        }
    };
    let mut server = BrokerServer::new(socket, allowed, policy, authority);
    // Optionally hand the socket to the machine-service group so it can connect
    // unprivileged (SO_PEERCRED still gates who is served).
    if let Ok(value) = std::env::var("OPENSTREAM_BROKER_SOCKET_GID") {
        let gid = value.trim().parse::<u32>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "OPENSTREAM_BROKER_SOCKET_GID must be a numeric gid",
            )
        })?;
        server = server.with_socket_group(gid);
    }
    server.run().await
}

/// Read the grant key, refusing one anybody else can read.
///
/// A secret the machine service can read is not a boundary: it could then tag
/// a grant naming any session and any permissions, which is exactly what this
/// key exists to prevent. Permissions are checked rather than assumed, because
/// the failure is silent -- a world-readable key file works perfectly until
/// someone looks.
#[cfg(target_os = "linux")]
fn read_grant_key(path: &str) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o077;
    if mode != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{path} is readable or writable beyond its owner (mode {:o}); \
                 a grant key the machine service can read is not a boundary",
                metadata.permissions().mode() & 0o777
            ),
        ));
    }
    let key = std::fs::read(path)?;
    // Trailing newlines are what an editor or `echo` leaves behind, and a key
    // that differs from the control plane's by one byte fails every grant with
    // no clue why.
    let trimmed = key
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(&key[..0], |last| &key[..=last]);
    if trimmed.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path} is empty"),
        ));
    }
    Ok(trimmed.to_vec())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if is_version_request() {
        print_version();
        return;
    }
    eprintln!("openstream-host-broker runs only on Linux");
}
