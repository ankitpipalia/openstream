//! Encrypted UDP transport for the project-owned OpenStream protocol.
//!
//! The transport intentionally contains no NAT traversal or signaling policy.
//! A caller obtains a peer address through its signaling layer, connects a
//! UDP socket to that address, and then sends/receives only sealed protocol
//! datagrams. Keeping those concerns separate makes the socket usable from a
//! desktop host, a desktop/mobile client, or a future relay adapter.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use openstream_protocol::relay::{self, Role as RelayRole};
use openstream_protocol::{Error as ProtocolError, Kind, MAX_DATAGRAM, Packet, Session};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, timeout};

mod stun;
mod upnp;

pub use stun::Error as StunError;
pub use upnp::{Error as UpnpError, Mapping as UpnpMapping};

/// The first path generation assigned to a newly established peer path.
pub const FIRST_PATH_GENERATION: u64 = 1;

/// Monotonically increasing identifier for a selected peer path.
pub type PathGeneration = u64;

/// The kind of path carrying authenticated OpenStream datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPathKind {
    DirectUdp,
    OpaqueRelay,
    Ice,
}

/// Lifecycle state for one selected peer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    Preparing,
    Ready,
    CommitPending,
    Active,
    Draining,
    Retired,
    Failed,
    Closed,
}

/// Path-MTU discovery state exposed by a transport implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMtuState {
    Base,
    Searching,
    SearchComplete,
    Error,
    Unavailable,
}

/// Cumulative local transport observations plus a rate sample for one path.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TransportSample {
    pub path_generation: PathGeneration,
    pub sent_packets: u64,
    pub sent_wire_bytes: u64,
    pub received_packets: u64,
    pub received_wire_bytes: u64,
    pub sample_interval_ms: u64,
    pub send_rate_mbps: f64,
    pub receive_rate_mbps: f64,
}

/// Address- and credential-free telemetry for the selected peer path.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PeerTransportSnapshot {
    pub path: TransportPathKind,
    pub path_generation: PathGeneration,
    pub state: PathState,
    pub path_age_ms: u64,
    pub datagram_size: Option<usize>,
    pub path_mtu_state: PathMtuState,
    pub sample: Option<TransportSample>,
}

#[derive(Debug)]
struct TransportTelemetry {
    path_generation: AtomicU64,
    sent_packets: AtomicU64,
    sent_wire_bytes: AtomicU64,
    received_packets: AtomicU64,
    received_wire_bytes: AtomicU64,
}

impl TransportTelemetry {
    fn new() -> Self {
        Self {
            path_generation: AtomicU64::new(FIRST_PATH_GENERATION),
            sent_packets: AtomicU64::new(0),
            sent_wire_bytes: AtomicU64::new(0),
            received_packets: AtomicU64::new(0),
            received_wire_bytes: AtomicU64::new(0),
        }
    }

    fn set_path_generation(&self, generation: PathGeneration) {
        self.path_generation
            .store(generation.max(FIRST_PATH_GENERATION), Ordering::Relaxed);
    }

    fn record_sent(&self, bytes: usize) {
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.sent_wire_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn record_received(&self, bytes: usize) {
        self.received_packets.fetch_add(1, Ordering::Relaxed);
        self.received_wire_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn counters(&self) -> TransportSample {
        TransportSample {
            path_generation: self.path_generation.load(Ordering::Relaxed),
            sent_packets: self.sent_packets.load(Ordering::Relaxed),
            sent_wire_bytes: self.sent_wire_bytes.load(Ordering::Relaxed),
            received_packets: self.received_packets.load(Ordering::Relaxed),
            received_wire_bytes: self.received_wire_bytes.load(Ordering::Relaxed),
            sample_interval_ms: 0,
            send_rate_mbps: 0.0,
            receive_rate_mbps: 0.0,
        }
    }
}

/// Errors returned by the UDP wrapper.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(ProtocolError),
    Relay(relay::Error),
    Upnp(UpnpError),
    NotConnected,
    Timeout,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "UDP I/O failed: {error}"),
            Self::Protocol(error) => write!(f, "OpenStream datagram rejected: {error}"),
            Self::Relay(error) => write!(f, "relay registration failed: {error}"),
            Self::Upnp(error) => write!(f, "UPnP port mapping failed: {error}"),
            Self::NotConnected => f.write_str("UDP transport has no connected peer"),
            Self::Timeout => f.write_str("UDP operation timed out"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<relay::Error> for Error {
    fn from(error: relay::Error) -> Self {
        Self::Relay(error)
    }
}

impl From<upnp::Error> for Error {
    fn from(error: upnp::Error) -> Self {
        Self::Upnp(error)
    }
}

/// A connected UDP socket carrying authenticated OpenStream packets.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    peer: Option<SocketAddr>,
    upnp_mapping: Option<UpnpMapping>,
    telemetry: TransportTelemetry,
}

impl UdpTransport {
    /// Bind one local UDP socket. Port `0` asks the OS to choose a free port.
    pub async fn bind(local: SocketAddr) -> Result<Self, Error> {
        Ok(Self {
            socket: UdpSocket::bind(local).await?,
            peer: None,
            upnp_mapping: None,
            telemetry: TransportTelemetry::new(),
        })
    }

    /// Return the OS-assigned local address.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.socket.local_addr()?)
    }

    /// Ask a STUN server for the public address associated with this exact
    /// socket.  Keeping the socket alive matters: NAT mappings are commonly
    /// keyed by the local UDP port, so opening a second socket would produce a
    /// different candidate and make later peer traffic fail unexpectedly.
    pub async fn server_reflexive_candidate(
        &self,
        server: SocketAddr,
        wait: Duration,
    ) -> Result<SocketAddr, StunError> {
        stun::binding(&self.socket, server, wait).await
    }

    /// Ask the local Internet Gateway Device to map this socket's UDP port.
    ///
    /// UPnP is intentionally never enabled implicitly: callers must opt in
    /// because a router port mapping is a meaningful local-network policy
    /// change. The mapping is retained by the transport for the lifetime of
    /// the session and can be explicitly removed with [`Self::release_upnp`].
    pub async fn map_upnp(&mut self, lease: Duration) -> Result<SocketAddr, Error> {
        if self.upnp_mapping.is_some() {
            self.release_upnp().await?;
        }
        let mapping = upnp::map_udp_port(&self.socket, lease).await?;
        let external = mapping.external_addr();
        self.upnp_mapping = Some(mapping);
        Ok(external)
    }

    /// Remove an earlier UPnP mapping on a best-effort explicit shutdown.
    pub async fn release_upnp(&mut self) -> Result<(), Error> {
        if let Some(mapping) = self.upnp_mapping.take() {
            mapping.release().await?;
        }
        Ok(())
    }

    /// Connect the UDP socket to the candidate selected by signaling/ICE.
    pub async fn connect(&mut self, peer: SocketAddr) -> Result<(), Error> {
        timeout(Duration::from_secs(3), self.socket.connect(peer))
            .await
            .map_err(|_| Error::Timeout)??;
        self.peer = Some(peer);
        Ok(())
    }

    /// Set the generation reported with subsequent local transport samples.
    pub fn set_path_generation(&self, generation: PathGeneration) {
        self.telemetry.set_path_generation(generation);
    }

    /// Start application telemetry at activation, excluding replacement probes.
    pub fn activate_generation(&mut self, generation: PathGeneration) {
        self.telemetry = TransportTelemetry::new();
        self.telemetry.set_path_generation(generation);
    }

    /// Write a datagram already sealed by the owning session. The caller
    /// retains the single cipher/counter domain across multiple sockets.
    pub async fn send_sealed(&self, datagram: &[u8], record: bool) -> Result<usize, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        self.send_datagram(datagram, record).await
    }

    /// Read bounded wire bytes for an ingress-aware session multiplexer.
    /// Authentication and accounting belong to that single session owner.
    pub async fn recv_sealed(&self, datagram: &mut [u8; MAX_DATAGRAM]) -> Result<usize, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        self.recv_datagram(datagram, false).await
    }

    /// Return cumulative observations for completed application socket I/O.
    /// Registration and setup packets are deliberately excluded.
    pub fn telemetry_counters(&self) -> TransportSample {
        self.telemetry.counters()
    }

    /// Record a successfully received encrypted datagram after the caller has
    /// classified it as application traffic.
    pub fn record_received(&self, bytes: usize) {
        self.telemetry.record_received(bytes);
    }

    /// Register this connected socket with the optional OpenStream relay.
    /// `ticket` is a short-lived relay-only credential, never the WebSocket
    /// bearer token. Registration is the only plaintext relay packet; media
    /// datagrams that follow remain end-to-end encrypted between the peers.
    /// Registration is retried until the relay's bounded acknowledgement is
    /// received so a signaling/relay publication race cannot leave a session
    /// with a permanently missing slot.
    pub async fn register_relay(
        &self,
        session_id: &str,
        role: RelayRole,
        ticket: &str,
    ) -> Result<usize, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        let registration = relay::encode_registration(session_id, role, ticket)?;
        let deadline = Instant::now() + Duration::from_millis(750);
        let mut acknowledgement = [0_u8; 5];
        let mut sent_bytes = 0_usize;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            sent_bytes = sent_bytes.saturating_add(self.socket.send(&registration).await?);
            let remaining = deadline.saturating_duration_since(now);
            let wait = remaining.min(Duration::from_millis(75));
            match timeout(wait, self.socket.recv(&mut acknowledgement)).await {
                Ok(Ok(length)) if relay::is_ack(&acknowledgement[..length], role) => {
                    return Ok(sent_bytes);
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => return Err(Error::Io(error)),
                Err(_) => {}
            }
        }
    }

    /// Send one encrypted datagram.
    pub async fn send(
        &self,
        session: &mut Session,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<usize, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        let datagram = session.seal(kind, channel, flags, payload)?;
        self.send_datagram(&datagram, true).await
    }

    /// Send an encrypted setup datagram without including it in application
    /// telemetry. Used by bounded path nomination before a path is active.
    pub async fn send_untracked(
        &self,
        session: &mut Session,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<usize, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        let datagram = session.seal(kind, channel, flags, payload)?;
        self.send_datagram(&datagram, false).await
    }

    /// Receive, authenticate, and decode the next datagram.
    pub async fn recv(&self, session: &mut Session) -> Result<Packet, Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        let mut datagram = [0_u8; MAX_DATAGRAM];
        let length = self.recv_datagram(&mut datagram, true).await?;
        Ok(session.open(&datagram[..length])?)
    }

    /// Receive an encrypted datagram without recording it. The caller must
    /// record the returned wire length only after classifying the decoded
    /// packet as application traffic.
    pub async fn recv_untracked(&self, session: &mut Session) -> Result<(Packet, usize), Error> {
        if self.peer.is_none() {
            return Err(Error::NotConnected);
        }
        let mut datagram = [0_u8; MAX_DATAGRAM];
        let length = self.recv_datagram(&mut datagram, false).await?;
        Ok((session.open(&datagram[..length])?, length))
    }

    async fn send_datagram(&self, datagram: &[u8], record: bool) -> Result<usize, Error> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenStream datagram exceeds transport bound",
            )));
        }
        let sent = self.socket.send(datagram).await?;
        if record {
            self.telemetry.record_sent(sent);
        }
        Ok(sent)
    }

    async fn recv_datagram(
        &self,
        datagram: &mut [u8; MAX_DATAGRAM],
        record: bool,
    ) -> Result<usize, Error> {
        let received = self.socket.recv(datagram).await?;
        if record {
            self.telemetry.record_received(received);
        }
        Ok(received)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];

    #[tokio::test]
    async fn two_connected_sockets_exchange_only_authenticated_packets() {
        let mut left = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut right = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let left_addr = left.local_addr().unwrap();
        let right_addr = right.local_addr().unwrap();
        left.connect(right_addr).await.unwrap();
        right.connect(left_addr).await.unwrap();

        let mut tx = Session::new(KEY, KEY);
        let mut rx = Session::new(KEY, KEY);
        left.send(&mut tx, Kind::Control, 0, 0, br#"{"type":"hello"}"#)
            .await
            .unwrap();
        let packet = right.recv(&mut rx).await.unwrap();
        assert_eq!(packet.kind, Kind::Control);
        assert_eq!(packet.payload, br#"{"type":"hello"}"#);
    }

    #[tokio::test]
    async fn udp_counters_count_only_completed_socket_io() {
        let mut left = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut right = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let left_addr = left.local_addr().unwrap();
        let right_addr = right.local_addr().unwrap();
        left.connect(right_addr).await.unwrap();
        right.connect(left_addr).await.unwrap();

        let mut tx = Session::new(KEY, KEY);
        let mut rx = Session::new(KEY, KEY);
        let sent = left
            .send(&mut tx, Kind::Control, 0, 0, b"authenticated")
            .await
            .unwrap();
        let packet = right.recv(&mut rx).await.unwrap();

        let sent_counters = left.telemetry_counters();
        let received_counters = right.telemetry_counters();
        let sent_wire_bytes = u64::try_from(sent).expect("datagram length fits in u64");
        assert_eq!(packet.payload, b"authenticated");
        assert_eq!(sent_counters.sent_packets, 1);
        assert_eq!(sent_counters.sent_wire_bytes, sent_wire_bytes);
        assert_eq!(received_counters.received_packets, 1);
        assert_eq!(received_counters.received_wire_bytes, sent_wire_bytes);
    }

    #[tokio::test]
    async fn sending_before_connecting_is_explicitly_rejected() {
        let socket = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut session = Session::new(KEY, KEY);
        assert!(matches!(
            socket.send(&mut session, Kind::Audio, 0, 0, b"audio").await,
            Err(Error::NotConnected)
        ));
    }

    #[tokio::test]
    async fn relay_registration_retries_until_the_relay_acknowledges_it() {
        let relay = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let relay_address = relay.local_addr().unwrap();
        let mut transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        transport.connect(relay_address).await.unwrap();

        let server = tokio::spawn(async move {
            let mut packet = [0_u8; 512];
            let (length, source) = relay.recv_from(&mut packet).await.unwrap();
            let registration = relay::decode_registration(&packet[..length]).unwrap();
            assert_eq!(registration.role, RelayRole::Host);
            // Delay beyond the first client receive window to exercise the
            // bounded retry rather than only the happy path.
            tokio::time::sleep(Duration::from_millis(100)).await;
            relay
                .send_to(&relay::encode_ack(RelayRole::Host), source)
                .await
                .unwrap();
        });

        let sent = transport
            .register_relay("session", RelayRole::Host, "ticket")
            .await
            .unwrap();
        assert!(sent > 0);
        server.await.unwrap();
    }
}
