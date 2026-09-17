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
    if std::env::args().nth(1).as_deref() == Some("provision-grant-key") {
        return match provision_grant_key() {
            Ok(path) => {
                eprintln!("openstream-host-broker: grant key written to {path}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("openstream-host-broker: provision-grant-key: {error}");
                ExitCode::FAILURE
            }
        };
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
    // machine service cannot obtain it.
    //
    // `grant_key::read` enforces the rest: the file must be owned by this
    // process's own user, be a regular file opened O_NOFOLLOW, carry no access
    // for group or other, and sit under directories nobody else can write. Mode
    // alone would not do it -- a file owned by the machine service with mode
    // 0600 is private to the machine service, and a privileged reader would
    // happily verify approvals against a key that process chose.
    let authority = match std::env::var("OPENSTREAM_BROKER_GRANT_KEY_FILE") {
        Ok(path) => {
            let key = openstream_host_broker::grant_key::read(&path)?;
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
/// Install the grant key this machine was enrolled with.
///
/// Run as the broker's own user -- root during bring-up -- because the key must
/// land in a file the unprivileged machine service cannot read, and only that
/// user can create one.
///
/// The key arrives as hex on **stdin**, not as an argument: a command line is
/// visible in `ps` to every user on the machine, so passing a secret that way
/// would leak it to exactly the process this key exists to keep it from. The
/// caller is whatever performed enrolment and received the key from the control
/// plane -- the desktop app, or an installer:
///
/// ```text
/// openstream-host-broker provision-grant-key < key.hex
/// ```
///
/// The destination is `OPENSTREAM_BROKER_GRANT_KEY_FILE`, the same variable the
/// broker reads at startup, so a machine cannot be provisioned to one path and
/// then run against another.
#[cfg(target_os = "linux")]
fn provision_grant_key() -> std::io::Result<String> {
    use std::io::Read;

    let path = std::env::var("OPENSTREAM_BROKER_GRANT_KEY_FILE").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OPENSTREAM_BROKER_GRANT_KEY_FILE is not set, so there is nowhere to put the key; \
             set it to the same path the broker's unit uses",
        )
    })?;
    let mut hex = String::new();
    std::io::stdin().read_to_string(&mut hex)?;
    let key = openstream_host_broker::grant_key::from_hex(&hex)?;
    openstream_host_broker::grant_key::write(&path, &key)?;
    Ok(path)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if is_version_request() {
        print_version();
        return;
    }
    eprintln!("openstream-host-broker runs only on Linux");
}
