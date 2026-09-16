//! The Linux broker server: bind the local socket, authorise the connecting
//! machine service by its peer credentials, and serve it against the real
//! capture and input devices.
//!
//! The socket lives under `/run/openstream`, a root-owned runtime directory. The
//! broker is the only privileged party, so it does the authorisation: it reads
//! the connected peer's `SO_PEERCRED` uid and admits only the configured
//! machine-service account. Filesystem permissions are the coarse gate (the
//! socket is not world-writable); the peer-credential check is the real one, and
//! is the reason a root broker can safely share a socket with an unprivileged
//! service. One service is served at a time -- there is only ever one -- and the
//! loop returns to accept its reconnect.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use openstream_host_ipc::peercred::{AllowedPeers, read_peer_identity};
use tokio::net::UnixListener;

use crate::capture::NativeFrameSource;
use crate::inject::NativeInputSink;
use crate::session::{BrokerPolicy, serve_connection};

/// The default socket path for the broker under the system runtime directory.
pub const DEFAULT_SOCKET: &str = "/run/openstream/broker.sock";

/// The broker server: where it listens, who it admits, and its capture policy.
#[derive(Debug)]
pub struct BrokerServer {
    socket_path: PathBuf,
    allowed: AllowedPeers,
    policy: BrokerPolicy,
}

impl BrokerServer {
    /// A server listening at `socket_path`, admitting only peers `allowed`
    /// accepts, and serving captures under `policy`.
    #[must_use]
    pub fn new(
        socket_path: impl Into<PathBuf>,
        allowed: AllowedPeers,
        policy: BrokerPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            allowed,
            policy,
        }
    }

    /// Bind the socket and serve connections until an unrecoverable I/O error.
    ///
    /// # Errors
    /// Returns an I/O error if the runtime directory or socket cannot be
    /// prepared, or if `accept` fails unrecoverably.
    pub async fn run(&self) -> io::Result<()> {
        let listener = self.bind()?;
        eprintln!(
            "openstream-host-broker: listening on {}",
            self.socket_path.display()
        );
        loop {
            let (stream, _addr) = listener.accept().await?;
            // Authorise before doing anything else: read the kernel-attested
            // peer uid and admit only the configured service account.
            let peer = match read_peer_identity(stream.as_raw_fd()) {
                Ok(peer) => peer,
                Err(error) => {
                    eprintln!("openstream-host-broker: could not read peer credentials: {error}");
                    continue;
                }
            };
            if !self.allowed.permits(&peer) {
                eprintln!(
                    "openstream-host-broker: refused connection from uid {} (not the machine-service account)",
                    peer.uid
                );
                continue;
            }
            eprintln!(
                "openstream-host-broker: serving machine service uid {} pid {}",
                peer.uid, peer.pid
            );

            let (mut reader, mut writer) = stream.into_split();
            let mut frames = NativeFrameSource::new();
            let mut input = NativeInputSink::new();
            if let Err(error) = serve_connection(
                &mut reader,
                &mut writer,
                peer,
                self.policy,
                &mut frames,
                &mut input,
            )
            .await
            {
                eprintln!("openstream-host-broker: connection ended: {error}");
            }
            // frames/input drop here, releasing the DRM device and uinput before
            // the next service connects.
        }
    }

    fn bind(&self) -> io::Result<UnixListener> {
        if let Some(parent) = self.socket_path.parent() {
            ensure_runtime_dir(parent)?;
        }
        // A leftover socket from a previous run would make bind fail with
        // EADDRINUSE; remove it only when it is actually a socket we own path.
        remove_stale_socket(&self.socket_path)?;
        let listener = UnixListener::bind(&self.socket_path)?;
        // Not world-accessible; the peer-credential check is the real gate, but
        // there is no reason to leave the door open to every local user.
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;
        Ok(listener)
    }
}

/// Create the runtime directory if missing, with conservative permissions. On a
/// packaged install systemd's `RuntimeDirectory=openstream` already made it; this
/// is the fallback for a manual run.
fn ensure_runtime_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Remove a leftover socket file so a fresh bind succeeds. Refuses to unlink
/// anything that is not a socket, so a misconfigured path cannot delete a real
/// file.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() {
                std::fs::remove_file(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "broker socket path exists and is not a socket",
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
