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
    use openstream_host_broker::session::BrokerPolicy;
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
    let mut server = BrokerServer::new(socket, allowed, policy);
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

#[cfg(not(target_os = "linux"))]
fn main() {
    if is_version_request() {
        print_version();
        return;
    }
    eprintln!("openstream-host-broker runs only on Linux");
}
