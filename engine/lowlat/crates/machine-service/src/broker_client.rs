//! The machine service's client to the privileged broker.
//!
//! The service connects to the broker's Unix socket, checks that the process on
//! the other end is actually root (it will not hand input and capture control to
//! an impostor broker running as some ordinary user), and completes the version
//! handshake. After that it holds the two socket halves so the peer loop can
//! await broker events on one while sending requests on the other.
//!
//! The handshake itself is generic over the stream, so it is unit-tested over an
//! in-memory pipe; only [`connect`] touches a real socket and is Linux-only.

use std::io;

use openstream_host_ipc::protocol::{BrokerEvent, PROTOCOL_VERSION, ServiceRequest};
use openstream_host_ipc::token::Capabilities;
use openstream_host_ipc::transport::{recv_event, send_request};
use tokio::io::{AsyncRead, AsyncWrite};

/// Perform the version handshake with the broker: announce our protocol version
/// and read the broker's `Hello`, returning the capabilities it advertises.
///
/// # Errors
/// Returns an I/O error on a transport failure, a protocol-version mismatch, or
/// an unexpected first message.
pub async fn handshake<R, W>(reader: &mut R, writer: &mut W) -> io::Result<Capabilities>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    send_request(
        writer,
        &ServiceRequest::Hello {
            protocol: PROTOCOL_VERSION,
        },
    )
    .await?;
    match recv_event(reader).await? {
        BrokerEvent::Hello {
            protocol,
            capabilities,
        } if protocol == PROTOCOL_VERSION => Ok(capabilities),
        BrokerEvent::Hello { protocol, .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("broker speaks protocol {protocol}, this service speaks {PROTOCOL_VERSION}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker did not open with Hello",
        )),
    }
}

/// A connected, handshaken broker: the two socket halves plus the capabilities
/// the broker advertised. The peer loop reads events from `reader` and sends
/// requests on `writer`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ConnectedBroker {
    /// The read half; await [`recv_event`] on it for broker events.
    pub reader: tokio::net::unix::OwnedReadHalf,
    /// The write half; [`send_request`] on it to drive the broker.
    pub writer: tokio::net::unix::OwnedWriteHalf,
    /// The capabilities the broker's policy will grant here.
    pub capabilities: Capabilities,
}

/// Connect to the broker at `socket_path`, refuse it unless it is root, and
/// complete the handshake.
///
/// # Errors
/// Returns an I/O error if the socket cannot be reached, the peer is not root,
/// or the handshake fails.
#[cfg(target_os = "linux")]
pub async fn connect(socket_path: &std::path::Path) -> io::Result<ConnectedBroker> {
    use std::os::fd::AsRawFd;

    use openstream_host_ipc::peercred::read_peer_identity;
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    // The service hands device control to the broker, so it must be sure the
    // broker is the privileged process it expects, not an ordinary user who got
    // there first. The kernel-attested peer uid settles it.
    let peer = read_peer_identity(stream.as_raw_fd())?;
    if !peer.is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "broker socket is owned by uid {}, not root; refusing",
                peer.uid
            ),
        ));
    }
    let (mut reader, mut writer) = stream.into_split();
    let capabilities = handshake(&mut reader, &mut writer).await?;
    Ok(ConnectedBroker {
        reader,
        writer,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstream_host_ipc::transport::{recv_request, send_event};

    #[tokio::test]
    async fn handshake_reads_the_broker_capabilities() {
        let (mut service, broker) = tokio::io::duplex(4096);

        // A fake broker: expect Hello, reply Hello with a capability ceiling.
        let broker_task = tokio::spawn(async move {
            let (mut broker_reader, mut broker_writer) = tokio::io::split(broker);
            let request = recv_request(&mut broker_reader).await.unwrap();
            assert_eq!(
                request,
                ServiceRequest::Hello {
                    protocol: PROTOCOL_VERSION
                }
            );
            send_event(
                &mut broker_writer,
                &BrokerEvent::Hello {
                    protocol: PROTOCOL_VERSION,
                    capabilities: Capabilities::CAPTURE.with(Capabilities::KEYBOARD),
                },
            )
            .await
            .unwrap();
        });

        let (mut reader, mut writer) = tokio::io::split(&mut service);
        let caps = handshake(&mut reader, &mut writer).await.unwrap();
        assert!(caps.contains(Capabilities::CAPTURE));
        assert!(caps.contains(Capabilities::KEYBOARD));
        broker_task.await.unwrap();
    }

    #[tokio::test]
    async fn a_version_mismatch_from_the_broker_is_an_error() {
        let (mut service, broker) = tokio::io::duplex(4096);
        let broker_task = tokio::spawn(async move {
            let (mut broker_reader, mut broker_writer) = tokio::io::split(broker);
            let _ = recv_request(&mut broker_reader).await.unwrap();
            send_event(
                &mut broker_writer,
                &BrokerEvent::Hello {
                    protocol: 999,
                    capabilities: Capabilities::all(),
                },
            )
            .await
            .unwrap();
        });
        let (mut reader, mut writer) = tokio::io::split(&mut service);
        let error = handshake(&mut reader, &mut writer).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        broker_task.await.unwrap();
    }
}
