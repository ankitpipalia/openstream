//! Shared pairing and signaling client for desktop and mobile front ends.
//!
//! This crate deliberately stops at the service boundary. It does not grant
//! host privileges, inject input, or interpret media. The same code can be
//! used by a desktop GUI, an Android JNI bridge, or an iOS Swift bridge.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use openstream_protocol::control::{Channel as ControlChannel, Frame as ControlFrame};
use openstream_protocol::path_control::{PATH_CONTROL_CHANNEL, PathControl};
use openstream_protocol::relay::Role as RelayRole;
use openstream_protocol::transport_meta::{TRANSPORT_META_CHANNEL, TransportAck};
use openstream_protocol::{
    IdentityError, IdentityKey, KeyExchange, Kind, MAX_DATAGRAM, Packet, Session as CipherSession,
};
use openstream_transport::{
    FIRST_PATH_GENERATION, PathGeneration, PathState, PeerTransportSnapshot, TransportSample,
    UdpTransport,
};
use openstream_transport_policy::{
    DeliveryClassSnapshot as PolicyDeliveryClassSnapshot, DeliveryError, DeliveryEstimator,
    DeliverySnapshot as PolicyDeliverySnapshot, DeliverySnapshotView, SentPacket, TrafficClass,
};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderValue};
use webrtc_ice::agent::Agent;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::candidate::{Candidate as IceCandidate, CandidateType};
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::udp_network::{EphemeralUDP, UDPNetwork};
use webrtc_ice::url::Url as IceUrl;
use webrtc_util::conn::Conn as IceConn;

pub mod control_plane;
pub mod device_auth;
pub mod enrolment;
pub mod http;
mod keystore;
mod path;
pub mod scheduler;
pub mod transport_ack;

use path::{
    COMMIT_RETRY, MigrationAction, MigrationController, PathRuntime, PathSlot, PeerPath,
    PeerPathBackend,
};
pub use path::{
    MigrationReport, MigrationState, MigrationTarget, MigrationToken, PathMigrationError,
};
pub use scheduler::{OutboundClass, QueueOutcome};
pub use transport_ack::{
    TransportAckConfig, TransportAckConfigError, TransportAckWindow, TransportAckWindowError,
};

/// Delivery counters for one traffic class on the active portable path.
///
/// These are authenticated peer-delivery observations. They deliberately do
/// not contain addresses, credentials, payloads, or local socket counters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeliveryClassSnapshot {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub acknowledged_packets: u64,
    pub acknowledged_bytes: u64,
    pub delivery_rate_mbps: Option<f64>,
    pub in_flight: u32,
    pub stale: u64,
    pub logical_reliable_retries: u64,
    pub outer_retransmissions: u64,
}

impl From<PolicyDeliveryClassSnapshot> for DeliveryClassSnapshot {
    fn from(snapshot: PolicyDeliveryClassSnapshot) -> Self {
        Self {
            sent_packets: snapshot.sent_packets,
            sent_bytes: snapshot.sent_bytes,
            acknowledged_packets: snapshot.acknowledged_packets,
            acknowledged_bytes: snapshot.acknowledged_bytes,
            delivery_rate_mbps: snapshot.delivery_rate_mbps,
            in_flight: snapshot.in_flight,
            stale: snapshot.stale,
            logical_reliable_retries: snapshot.logical_reliable_retries,
            outer_retransmissions: snapshot.outer_retransmissions,
        }
    }
}

impl From<DeliveryClassSnapshot> for PolicyDeliveryClassSnapshot {
    fn from(snapshot: DeliveryClassSnapshot) -> Self {
        Self {
            sent_packets: snapshot.sent_packets,
            sent_bytes: snapshot.sent_bytes,
            acknowledged_packets: snapshot.acknowledged_packets,
            acknowledged_bytes: snapshot.acknowledged_bytes,
            delivery_rate_mbps: snapshot.delivery_rate_mbps,
            in_flight: snapshot.in_flight,
            stale: snapshot.stale,
            logical_reliable_retries: snapshot.logical_reliable_retries,
            outer_retransmissions: snapshot.outer_retransmissions,
        }
    }
}

/// Address- and credential-free authenticated delivery telemetry for one
/// active portable path generation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PeerDeliverySnapshot {
    pub path_generation: PathGeneration,
    pub sample_interval_ms: f64,
    pub srtt_ms: Option<f64>,
    pub aggregate: DeliveryClassSnapshot,
    pub video: DeliveryClassSnapshot,
    pub audio: DeliveryClassSnapshot,
    pub critical: DeliveryClassSnapshot,
}

impl From<PolicyDeliverySnapshot> for PeerDeliverySnapshot {
    fn from(snapshot: PolicyDeliverySnapshot) -> Self {
        Self {
            path_generation: snapshot.path_generation,
            sample_interval_ms: snapshot.sample_interval_ms,
            srtt_ms: snapshot.srtt_ms,
            aggregate: snapshot.aggregate.into(),
            video: snapshot.video.into(),
            audio: snapshot.audio.into(),
            critical: snapshot.critical.into(),
        }
    }
}

impl From<PeerDeliverySnapshot> for PolicyDeliverySnapshot {
    fn from(snapshot: PeerDeliverySnapshot) -> Self {
        Self {
            path_generation: snapshot.path_generation,
            sample_interval_ms: snapshot.sample_interval_ms,
            srtt_ms: snapshot.srtt_ms,
            aggregate: snapshot.aggregate.into(),
            video: snapshot.video.into(),
            audio: snapshot.audio.into(),
            critical: snapshot.critical.into(),
        }
    }
}

impl DeliverySnapshotView for PeerDeliverySnapshot {
    fn delivery_snapshot(&self) -> PolicyDeliverySnapshot {
        (*self).into()
    }
}

use scheduler::{OutboundScheduler, SchedulerError};

/// Wire-level capability protocol version.
pub const CAPABILITY_VERSION: u8 = 1;
pub const MAX_VIDEO_WIDTH: u16 = 7680;
pub const MAX_VIDEO_HEIGHT: u16 = 4320;
pub const MAX_VIDEO_FPS: u16 = 240;
const MAX_CODEC_ENTRIES: usize = 8;
const MAX_SIGNAL_QUEUE: usize = 128;
/// Maximum peer-supplied candidates accepted per establishment. Bounds memory
/// and the number of UDP probes a malicious peer can direct at this host.
pub const MAX_REMOTE_CANDIDATES: usize = 32;
/// ICE credentials and candidate strings are peer-controlled signaling data.
/// These limits are comfortably above values generated by WebRTC while
/// preventing oversized strings from reaching the ICE parser or agent.
const MAX_ICE_UFRAG_BYTES: usize = 32;
const MAX_ICE_PASSWORD_BYTES: usize = 256;
const MAX_CANDIDATE_BYTES: usize = 4096;
/// Per-phase establishment deadline (credentials, candidates, key exchange).
/// A stalled or malicious peer cannot hang establishment forever.
const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Maximum reliable-control messages retained per direction. This is bounded
/// so clipboard transfers can use at most 64 chunks without changing the
/// media datagram limit or allowing an unbounded control backlog.
pub const MAX_CONTROL_PENDING: usize = 64;

/// Paces client keyframe requests so a burst of detected gaps cannot flood the
/// reliable-control channel. A gap marks a single request pending; the request
/// is emitted at most once per `interval` until an actual keyframe (or a decoder
/// restart) clears it. Without this, hundreds of gaps on a fresh or lossy path
/// -- before the first keyframe lands -- queued hundreds of keyframe requests
/// and saturated the bounded control window, which tore the session down.
#[derive(Debug)]
pub struct KeyframeRequestPacer {
    waiting: bool,
    last_request: Option<Instant>,
    interval: Duration,
}

impl KeyframeRequestPacer {
    pub fn new(interval: Duration) -> Self {
        Self {
            waiting: false,
            last_request: None,
            interval,
        }
    }

    /// Record that the decoder detected a gap needing a keyframe. Any number of
    /// gaps collapse into a single pending request.
    pub fn note_gap(&mut self) {
        self.waiting = true;
    }

    /// Whether a keyframe request should be sent at `now`: only while one is
    /// pending, and at most once per `interval`.
    pub fn due(&self, now: Instant) -> bool {
        self.waiting
            && self
                .last_request
                .is_none_or(|sent| now.duration_since(sent) >= self.interval)
    }

    /// Record that a request was actually transmitted at `now`.
    pub fn note_sent(&mut self, now: Instant) {
        self.last_request = Some(now);
    }

    /// Clear the pending state. Called when an actual keyframe arrives or the
    /// decoder/session is restarted -- never merely because a request was sent.
    pub fn keyframe_received(&mut self) {
        self.waiting = false;
        self.last_request = None;
    }

    /// Whether the client is still waiting for a keyframe. Gates decoder submit:
    /// non-keyframe pictures are not fed to the decoder while recovering.
    pub fn is_waiting(&self) -> bool {
        self.waiting
    }
}
/// Maximum size accepted for a signaling JSON envelope. This is lower than
/// the server's WebSocket ceiling and prevents a client from retaining a
/// large attacker-controlled value while it waits for a later phase.
pub const MAX_SIGNAL_MESSAGE_BYTES: usize = 64 * 1024;
/// Retransmit an unacknowledged capability/control frame at a bounded cadence.
/// Establishment needs this before the normal application event loops exist.
const CAPABILITY_RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// Direct UDP has no ICE consent agent. Send an authenticated application
/// keepalive when an otherwise quiet stream reaches this interval.
/// Cadence for the authenticated application-layer keepalive. It is sent on any
/// selected path -- direct or full ICE -- so that both peers observe authenticated
/// traffic during a media pause. ICE consent freshness keeps the transport open
/// but is invisible to the application layer, so it cannot substitute for this.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// A direct path that produces no authenticated packet for this long is
/// considered dead.
const DIRECT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Video codecs understood by the initial OpenStream clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    H264,
    H265,
}

/// Audio codecs advertised during the encrypted handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioCodec {
    Opus,
}

/// Role carried inside the encrypted capability message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRole {
    Host,
    Client,
}

/// Media and device limits a peer can actually support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub version: u8,
    pub video_codecs: Vec<VideoCodec>,
    pub audio_codecs: Vec<AudioCodec>,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub input: bool,
    /// Whether the peer can decode/encode 10-bit video end to end.
    #[serde(default)]
    pub video_10_bit: bool,
    /// Whether the peer can decode/encode 4:4:4 video end to end.
    #[serde(default)]
    pub video_444: bool,
    /// Whether clipboard text synchronization is implemented and permitted.
    #[serde(default)]
    pub clipboard: bool,
    /// Whether the host can capture a microphone and the client can receive it.
    #[serde(default)]
    pub microphone: bool,
    /// Whether the host can enumerate or create additional displays.
    #[serde(default)]
    pub multi_monitor: bool,
    /// Whether pen/stylus absolute and pressure events are supported.
    #[serde(default)]
    pub pen: bool,
    /// Whether the peer can consume or generate force-feedback events.
    #[serde(default)]
    pub rumble: bool,
    /// Whether the peer explicitly supports generation-scoped path migration.
    #[serde(default)]
    pub path_migration: bool,
}

impl Capabilities {
    /// Validate a capability advertisement before it reaches an encoder,
    /// decoder, or allocation site. Keeping this check in the shared crate
    /// prevents desktop, mobile, and host adapters from interpreting zero or
    /// unexpectedly large values differently.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.version != CAPABILITY_VERSION {
            return Err(CapabilityError::UnsupportedVersion(self.version));
        }
        if self.video_codecs.is_empty() || self.video_codecs.len() > MAX_CODEC_ENTRIES {
            return Err(CapabilityError::InvalidMessage(
                "video_codecs must contain between one and eight entries".into(),
            ));
        }
        if self.audio_codecs.len() > MAX_CODEC_ENTRIES {
            return Err(CapabilityError::InvalidMessage(
                "audio_codecs contains too many entries".into(),
            ));
        }
        if self.max_width == 0
            || self.max_width > MAX_VIDEO_WIDTH
            || self.max_height == 0
            || self.max_height > MAX_VIDEO_HEIGHT
            || self.max_fps == 0
            || self.max_fps > MAX_VIDEO_FPS
        {
            return Err(CapabilityError::InvalidMessage(format!(
                "video limits must be 1..={}x1..={} at 1..={} fps",
                MAX_VIDEO_WIDTH, MAX_VIDEO_HEIGHT, MAX_VIDEO_FPS
            )));
        }
        Ok(())
    }

    /// Conservative host profile used by the FFmpeg and Linux adapters.
    pub fn host_default() -> Self {
        Self {
            version: CAPABILITY_VERSION,
            video_codecs: vec![VideoCodec::H264, VideoCodec::H265],
            audio_codecs: vec![AudioCodec::Opus],
            max_width: MAX_VIDEO_WIDTH,
            max_height: MAX_VIDEO_HEIGHT,
            max_fps: MAX_VIDEO_FPS,
            input: true,
            video_10_bit: false,
            video_444: false,
            clipboard: false,
            microphone: false,
            multi_monitor: false,
            pen: false,
            rumble: false,
            path_migration: false,
        }
    }

    /// Host profile whose limits also describe the stream the adapter will
    /// actually produce. Keeping these values aligned matters to native
    /// decoders, which need the negotiated dimensions before the first access
    /// unit arrives.
    pub fn host_with_limits(width: u16, height: u16, fps: u16) -> Self {
        let mut capabilities = Self::host_default();
        capabilities.max_width = width.clamp(1, MAX_VIDEO_WIDTH);
        capabilities.max_height = height.clamp(1, MAX_VIDEO_HEIGHT);
        capabilities.max_fps = fps.clamp(1, MAX_VIDEO_FPS);
        capabilities
    }

    /// Desktop/mobile client profile used until a native renderer supplies
    /// tighter device-specific limits.
    pub fn client_default() -> Self {
        Self {
            version: CAPABILITY_VERSION,
            video_codecs: vec![VideoCodec::H264, VideoCodec::H265],
            audio_codecs: vec![AudioCodec::Opus],
            max_width: MAX_VIDEO_WIDTH,
            max_height: MAX_VIDEO_HEIGHT,
            max_fps: MAX_VIDEO_FPS,
            input: true,
            video_10_bit: false,
            video_444: false,
            clipboard: false,
            microphone: false,
            multi_monitor: false,
            pen: false,
            rumble: true,
            path_migration: false,
        }
    }

    /// Explicitly advertise support for the path-migration control protocol.
    ///
    /// Ordinary capability profiles remain single-path by default. Migration
    /// acceptance peers opt in deliberately with this builder.
    pub fn with_path_migration(mut self) -> Self {
        self.path_migration = true;
        self
    }
}

/// The first encrypted control exchange after the UDP key handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilityMessage {
    Hello {
        role: CapabilityRole,
        capabilities: Capabilities,
    },
    HelloAck {
        capabilities: Capabilities,
    },
}

/// Result of intersecting two peers' advertised media/device support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    pub video: VideoCodec,
    pub audio: Option<AudioCodec>,
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub input: bool,
    pub video_10_bit: bool,
    pub video_444: bool,
    pub clipboard: bool,
    pub microphone: bool,
    pub multi_monitor: bool,
    pub pen: bool,
    pub rumble: bool,
    pub path_migration: bool,
}

/// Capability negotiation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidMessage(String),
    UnsupportedVersion(u8),
    UnexpectedRole,
    NoCommonVideoCodec,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(error) => write!(f, "capability message is invalid: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported capability version {version}")
            }
            Self::UnexpectedRole => f.write_str("capability hello has the wrong role"),
            Self::NoCommonVideoCodec => f.write_str("peers have no common video codec"),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// Encode a host hello for the encrypted control channel.
pub fn encode_hello(capabilities: Capabilities) -> Result<Vec<u8>, CapabilityError> {
    capabilities.validate()?;
    serde_json::to_vec(&CapabilityMessage::Hello {
        role: CapabilityRole::Host,
        capabilities,
    })
    .map_err(|error| CapabilityError::InvalidMessage(error.to_string()))
}

/// Encode a client acknowledgement for the encrypted control channel.
pub fn encode_hello_ack(capabilities: Capabilities) -> Result<Vec<u8>, CapabilityError> {
    capabilities.validate()?;
    serde_json::to_vec(&CapabilityMessage::HelloAck { capabilities })
        .map_err(|error| CapabilityError::InvalidMessage(error.to_string()))
}

/// Decode either side of the encrypted capability exchange.
pub fn decode_capability_message(payload: &[u8]) -> Result<CapabilityMessage, CapabilityError> {
    let message = serde_json::from_slice::<CapabilityMessage>(payload)
        .map_err(|error| CapabilityError::InvalidMessage(error.to_string()))?;
    let version = match &message {
        CapabilityMessage::Hello { capabilities, .. }
        | CapabilityMessage::HelloAck { capabilities } => capabilities.version,
    };
    if version != CAPABILITY_VERSION {
        return Err(CapabilityError::UnsupportedVersion(version));
    }
    match &message {
        CapabilityMessage::Hello { capabilities, .. }
        | CapabilityMessage::HelloAck { capabilities } => capabilities.validate()?,
    }
    Ok(message)
}

/// Select the first host-preferred codec and intersect the safe limits.
pub fn negotiate(
    host: &Capabilities,
    client: &Capabilities,
) -> Result<NegotiatedCapabilities, CapabilityError> {
    host.validate()?;
    client.validate()?;
    let video = host
        .video_codecs
        .iter()
        .copied()
        .find(|codec| client.video_codecs.contains(codec))
        .ok_or(CapabilityError::NoCommonVideoCodec)?;
    let audio = host
        .audio_codecs
        .iter()
        .copied()
        .find(|codec| client.audio_codecs.contains(codec));
    Ok(NegotiatedCapabilities {
        video,
        audio,
        width: host.max_width.min(client.max_width),
        height: host.max_height.min(client.max_height),
        fps: host.max_fps.min(client.max_fps),
        input: host.input && client.input,
        video_10_bit: host.video_10_bit && client.video_10_bit,
        video_444: host.video_444 && client.video_444,
        clipboard: host.clipboard && client.clipboard,
        microphone: host.microphone && client.microphone,
        multi_monitor: host.multi_monitor && client.multi_monitor,
        pen: host.pen && client.pen,
        rumble: host.rumble && client.rumble,
        path_migration: host.path_migration && client.path_migration,
    })
}

/// The two capabilities a pairing can grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Host,
    Client,
}

/// Candidate class exchanged over the role-scoped signaling channel.
///
/// `Host` is the address observed locally. `Mapped` is the address exposed by
/// an opt-in UPnP IGD mapping of the same UDP socket. `ServerReflexive` is the
/// address a STUN server observes for that socket. A later ICE/TURN layer can
/// add relay candidates without changing the encrypted packet format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Host,
    Mapped,
    ServerReflexive,
    Relay,
}

/// The selected data-path family, exposed for diagnostics and UI telemetry.
///
/// `DirectUdp` includes host, UPnP-mapped, server-reflexive nomination and the
/// project-owned opaque relay fallback; the candidate field distinguishes
/// those cases. `Ice` means the standards-based `webrtc-ice` agent selected
/// the path and is retaining it for consent freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPath {
    DirectUdp { candidate: CandidateKind },
    Ice,
}

/// Local transport counters suitable for a diagnostics overlay.
///
/// These are local observations. They do not claim to measure packets lost
/// by the peer or network; those require acknowledgements and a separate
/// metrics policy. Send bytes are encrypted wire bytes, while receive bytes
/// count authenticated payload bytes because the direct and ICE backends
/// expose different receive APIs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStats {
    pub sent_packets: u64,
    pub sent_wire_bytes: u64,
    pub received_packets: u64,
    pub received_payload_bytes: u64,
}

/// Result of one non-blocking outbound scheduler flush.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub sent_packets: usize,
    pub sent_wire_bytes: usize,
    pub pending_packets: usize,
    pub stale_evictions: u64,
    pub logical_reliable_retries: u64,
    pub outer_retransmissions: u64,
}

/// Outcome of a flush when delivery history applies bounded backpressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// The scheduler flush completed without delivery-history backpressure.
    Flushed(FlushReport),
    /// Queued application work remains until a transport ACK frees history.
    Backpressured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmittedPacket {
    queue_id: u64,
    wire_bytes: usize,
}

#[derive(Debug, Default)]
struct FlushWork {
    report: FlushReport,
    emitted: Vec<EmittedPacket>,
}

/// One address that a peer may try for the UDP data path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub address: SocketAddr,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Client => "client",
        }
    }
}

/// Short-lived credentials for one session.
///
/// # Why the role tokens are optional
///
/// A pairing used to carry both, because the only way to create a session was
/// an endpoint that returned both to one caller. That is a provisioning
/// workflow: whoever holds the file can act as either end of the session, or
/// hand either end to anybody.
///
/// The Connect broker delivers one role capability to each party, so a client
/// legitimately has no host token and a host has no client token. Making the
/// fields optional is what lets that be represented at all -- and, more
/// importantly, what makes [`Pairing::token`] able to *refuse*. A file with
/// only a client token cannot be used to act as host, because there is no
/// host token in it to present. Filling the gap with an empty string would
/// have compiled and then sent an empty bearer token to the signalling
/// server.
///
/// Both remain optional rather than one being required, because the same type
/// describes a provisioning pairing (both present) and either role's
/// credential (one present).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pairing {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_token: Option<String>,
    pub websocket_path: String,
    pub expires_in_seconds: u64,
    #[serde(default)]
    pub relay_address: Option<String>,
    /// Session-scoped TURN credentials, present when the provisioning script
    /// fetched them from `GET /v1/session/{id}/turn`. They are bearer
    /// capabilities: keep them out of logs with the pairing tokens.
    #[serde(default)]
    pub turn: Option<TurnCredentials>,
    /// Role-scoped TURN credentials. `turn` remains for older pairing files;
    /// new provisioning scripts populate both role-specific fields so a
    /// client never presents a host credential to coturn.
    #[serde(default)]
    pub turn_host: Option<TurnCredentials>,
    #[serde(default)]
    pub turn_client: Option<TurnCredentials>,
    /// Short-lived relay registration tickets. These are distinct from the
    /// WebSocket bearer tokens and are safe to use only for the matching role.
    #[serde(default)]
    pub relay_host_ticket: Option<String>,
    #[serde(default)]
    pub relay_client_ticket: Option<String>,
    /// The input and device classes granted to this pairing's role, carried
    /// from the role credential. `None` for a provisioning pairing and for
    /// older pairing files written before permission negotiation; the session
    /// runner treats a present set as the ceiling on what it will drive.
    #[serde(default)]
    pub permissions: Option<Permissions>,
    /// The control plane's signed statement that this session was approved,
    /// hex-encoded, for a host that runs behind a privileged broker.
    ///
    /// Carried to the agent and handed on unread. Nothing in this process can
    /// produce one or verify one: the broker checks it against a key only its
    /// own user can read, which is the entire point. `None` for a client
    /// pairing, for a host that does not use a broker, and for a device
    /// enrolled before grant keys existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<String>,
}

/// The input and device classes a session may drive, as the Connect broker
/// negotiated them.
///
/// The broker returns the *granted* set with each role credential -- a host
/// narrows what the client asked for during approval -- and the client carries
/// it so the session runner can scope input, clipboard and audio to what was
/// actually granted rather than to whatever a peer sends. Enforcement is a
/// later step; this type only transports the decision.
///
/// The fields are field-for-field wire-compatible with the signal server's
/// `connect::Permissions` object and `app-core`'s `PermissionSet`. It is a
/// distinct type here only because `client-core` sits below both and shares no
/// crate with them; the three should collapse into one once a common low crate
/// exists to hold it. Absent fields deserialize to "not granted", so a partial
/// object can only narrow, never silently widen, the granted set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct Permissions {
    pub view: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub gamepad: bool,
    pub clipboard: bool,
    pub microphone: bool,
    pub tablet: bool,
    pub virtual_usb: bool,
}

impl Permissions {
    /// The empty set: every class denied. Identical to `Default`.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Every class granted.
    #[must_use]
    pub fn all() -> Self {
        Self {
            view: true,
            keyboard: true,
            mouse: true,
            gamepad: true,
            clipboard: true,
            microphone: true,
            tablet: true,
            virtual_usb: true,
        }
    }

    /// True when no class is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::none()
    }

    /// Whether `class` is allowed under this ceiling, when the ceiling itself
    /// may be absent.
    ///
    /// A missing ceiling means unscoped, not denied: a pairing file written
    /// before permission negotiation existed, or a provisioning pairing that
    /// never went through Connect, must not suddenly lose every class the
    /// moment a caller starts consulting one. A *present* ceiling is
    /// authoritative -- whatever `class` reports for it is final, regardless
    /// of what any other local policy would otherwise allow.
    #[must_use]
    pub fn allows(ceiling: Option<Self>, class: impl FnOnce(Self) -> bool) -> bool {
        ceiling.is_none_or(class)
    }
}

/// One end of an approved session, as the Connect broker delivers it.
///
/// Deliberately singular. There is no shape here that can hold both roles,
/// because the broker will not return both to one caller and a type that
/// could carry them would be the first step towards asking it to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleCredential {
    pub session_id: String,
    pub role: Role,
    pub token: String,
    pub websocket_path: String,
    pub expires_in_seconds: u64,
    #[serde(default)]
    pub relay_address: Option<String>,
    #[serde(default)]
    pub relay_ticket: Option<String>,
    #[serde(default)]
    pub turn: Option<TurnCredentials>,
    /// The input and device classes the broker granted this role, or `None` for
    /// a credential minted before permission negotiation. Carried into the
    /// pairing so the session runner can scope what it drives to the grant.
    #[serde(default)]
    pub permissions: Option<Permissions>,
    /// The control plane's signed approval for this session, hex-encoded, for
    /// a host that runs behind a privileged broker. Carried into the pairing
    /// and handed on unread; only the broker can verify it.
    #[serde(default)]
    pub session_grant: Option<String>,
}

/// Maximum pairing-file size accepted by the process boundary.
///
/// Pairing responses are small, but this limit prevents a malformed or
/// attacker-controlled path from causing an unbounded allocation before the
/// JSON parser runs.
pub const MAX_PAIRING_FILE_BYTES: usize = 64 * 1024;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[cfg(windows)]
fn has_reparse_point_attribute(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Load pairing material from a private runtime file.
///
/// The path must be absolute, must name a regular file owned by the effective
/// user, and must not grant group/other permissions. Symlinks are rejected so
/// a path supplied by a launcher cannot silently redirect the client to
/// another file. The contents are bounded before JSON parsing.
pub fn load_pairing_from_file(path: impl AsRef<Path>) -> Result<Pairing, Error> {
    let path = path.as_ref();
    if !path.is_absolute() {
        return Err(Error::PairingFilePathNotAbsolute);
    }

    let link_metadata =
        std::fs::symlink_metadata(path).map_err(|_| Error::PairingFileUnavailable)?;
    if link_metadata.file_type().is_symlink() {
        return Err(Error::PairingFileInsecure);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the final path component without traversing a reparse point.
        // The metadata check above remains a clear fast-fail, while this
        // handle-level flag closes the check/open race on Windows.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::PairingFileUnavailable)?;
    let metadata = file.metadata().map_err(|_| Error::PairingFileUnavailable)?;
    if !metadata.is_file() {
        return Err(Error::PairingFileInsecure);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if has_reparse_point_attribute(metadata.file_attributes()) {
            return Err(Error::PairingFileInsecure);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode();
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(Error::PairingFileInsecure);
        }
    }
    if metadata.len() > MAX_PAIRING_FILE_BYTES as u64 {
        return Err(Error::PairingFileTooLarge);
    }

    let mut contents = Vec::new();
    let read_limit = u64::try_from(MAX_PAIRING_FILE_BYTES)
        .expect("pairing-file byte limit fits in u64")
        .saturating_add(1);
    file.take(read_limit)
        .read_to_end(&mut contents)
        .map_err(|_| Error::PairingFileUnavailable)?;
    if contents.len() > MAX_PAIRING_FILE_BYTES {
        return Err(Error::PairingFileTooLarge);
    }
    serde_json::from_slice(&contents).map_err(Error::Deserialize)
}

/// Resolve pairing material for a headless/native entrypoint.
///
/// OPENSTREAM_PAIRING_FILE is the normal runtime boundary. The historical
/// OPENSTREAM_PAIRING_JSON escape hatch is accepted only with the explicit
/// OPENSTREAM_DEVELOPER_OVERRIDE=1 marker so ordinary launchers do not place
/// bearer capabilities in process environments by accident.
pub fn load_pairing_from_environment() -> Result<Pairing, Error> {
    if let Some(path) = std::env::var_os("OPENSTREAM_PAIRING_FILE") {
        let path = path.to_str().ok_or(Error::PairingEnvironmentInvalid)?;
        return load_pairing_from_file(path);
    }
    if let Some(json) = std::env::var_os("OPENSTREAM_PAIRING_JSON") {
        if std::env::var("OPENSTREAM_DEVELOPER_OVERRIDE").as_deref() != Ok("1") {
            return Err(Error::DeveloperOverrideRequired);
        }
        let json = json.to_str().ok_or(Error::PairingEnvironmentInvalid)?;
        return serde_json::from_str(json).map_err(Error::Deserialize);
    }
    Err(Error::PairingRequired)
}

/// Session-scoped TURN credentials minted by the signaling service.
///
/// Mirrors the service's `TurnIssued` JSON so pairing files stay portable.
/// `username` embeds the expiry (`expiry:session:role`); the service's
/// `static-auth-secret` is the only other party that can verify it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub realm: String,
}

impl fmt::Debug for Pairing {
    /// Every token field here is a bearer capability for a live session, so
    /// the only thing that may be formatted is the non-secret session id and
    /// the shape of what is held.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pairing")
            .field("session_id", &self.session_id)
            .field("host_token", &"<redacted>")
            .field("client_token", &"<redacted>")
            .field("websocket_path", &self.websocket_path)
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("relay_address", &self.relay_address)
            .field("turn", &self.turn.as_ref().map(|_| "<redacted>"))
            .field("turn_host", &self.turn_host.as_ref().map(|_| "<redacted>"))
            .field(
                "turn_client",
                &self.turn_client.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "relay_host_ticket",
                &self.relay_host_ticket.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "relay_client_ticket",
                &self.relay_client_ticket.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl fmt::Debug for TurnCredentials {
    /// `username` embeds the expiry and `password` is the HMAC over it; both
    /// authenticate a relay allocation, so neither is printable.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnCredentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("urls", &self.urls.len())
            .field("realm", &self.realm)
            .finish()
    }
}

impl TurnCredentials {
    /// Build ICE URLs from `spec`, stamping these credentials only on
    /// `turn:`/`turns:` URLs. STUN URLs never carry credentials, so a mixed
    /// `OPENSTREAM_ICE_URLS` list stays safe to log after redaction.
    pub fn apply_to_spec(&self, spec: &str) -> Result<Vec<IceUrl>, Error> {
        use webrtc_ice::url::SchemeType;
        let mut urls = parse_ice_urls(spec, None, None)?;
        for url in &mut urls {
            if matches!(url.scheme, SchemeType::Turn | SchemeType::Turns) {
                url.username.clone_from(&self.username);
                url.password.clone_from(&self.password);
            }
        }
        Ok(urls)
    }
}

/// Resolve the ICE URL list for this pairing.
///
/// Explicit `OPENSTREAM_TURN_USERNAME`/`OPENSTREAM_TURN_PASSWORD` wins (lab
/// overrides), otherwise the pairing-embedded session credentials from
/// `GET /v1/session/{id}/turn` are used, otherwise URLs are credential-free.
pub fn ice_urls_for_pairing(pairing: &Pairing) -> Result<Vec<IceUrl>, Error> {
    ice_urls_for_pairing_role(pairing, Role::Client)
}

/// Resolve ICE URLs using the credentials belonging to one role.
pub fn ice_urls_for_pairing_role(pairing: &Pairing, role: Role) -> Result<Vec<IceUrl>, Error> {
    let role_turn = match role {
        Role::Host => pairing.turn_host.as_ref(),
        Role::Client => pairing.turn_client.as_ref(),
    };
    let legacy_turn = pairing.turn.as_ref();
    let turn = role_turn.or(legacy_turn);
    let configured_spec = std::env::var("OPENSTREAM_ICE_URLS").unwrap_or_default();
    let spec = if configured_spec.trim().is_empty() {
        turn.map(|credentials| credentials.urls.join(","))
            .unwrap_or_default()
    } else {
        configured_spec
    };
    if spec.trim().is_empty() {
        return Ok(Vec::new());
    }
    if let (Ok(username), Ok(password)) = (
        std::env::var("OPENSTREAM_TURN_USERNAME"),
        std::env::var("OPENSTREAM_TURN_PASSWORD"),
    ) {
        return parse_ice_urls(&spec, Some(&username), Some(&password));
    }
    if let Some(turn) = turn {
        if !turn.username.is_empty() && !turn.password.is_empty() {
            return turn.apply_to_spec(&spec);
        }
    }
    parse_ice_urls(&spec, None, None)
}

impl Pairing {
    /// Build the role-specific WebSocket URL from the HTTP service origin.
    ///
    /// The role token is deliberately not put in the URL. Native callers send
    /// it in the WebSocket `Authorization` header so a reverse proxy does not
    /// record it as a query parameter.
    ///
    /// Plaintext (`http`/`ws`) origins are accepted only for loopback hosts or
    /// when `OPENSTREAM_ALLOW_INSECURE=1` is set explicitly. Production
    /// deployments must use `https`/`wss` so session tokens and key-exchange
    /// messages are not exposed to a network attacker.
    pub fn websocket_url(&self, server_origin: &str, role: Role) -> Result<String, Error> {
        let origin = server_origin.trim_end_matches('/');
        let (scheme, rest) = origin
            .split_once("://")
            .map(|(scheme, rest)| (scheme.to_ascii_lowercase(), rest))
            .unwrap_or_else(|| ("wss".to_string(), origin));
        let host = origin_host(origin).unwrap_or_default();
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
            || is_loopback_literal(&host);
        let ws_origin = match scheme.as_str() {
            "https" => format!("wss://{rest}"),
            "wss" => origin.to_string(),
            "http" | "ws" => {
                let insecure = std::env::var("OPENSTREAM_ALLOW_INSECURE").as_deref() == Ok("1");
                let local_no_auth = std::env::var("OPENSTREAM_LOCAL_NO_AUTH").as_deref() == Ok("1");
                if !plaintext_origin_allowed(&host, loopback, insecure, local_no_auth) {
                    return Err(Error::InsecureOrigin);
                }
                format!("ws://{rest}")
            }
            _ => {
                return Err(Error::InvalidMessage(
                    "server origin has an unknown scheme".into(),
                ));
            }
        };
        Ok(format!(
            "{ws_origin}/v1/signal/{}/{role}",
            self.session_id,
            role = role.as_str()
        ))
    }

    /// Build a pairing from one role's Connect credential.
    ///
    /// The broker hands each end a single capability, so the resulting
    /// pairing carries exactly one role token and refuses to produce the
    /// other. That refusal is the security property: a client credential
    /// written to disk cannot be used to act as the host of its own session,
    /// however the file is later handed around.
    #[must_use]
    pub fn from_role_credential(credential: RoleCredential) -> Self {
        let RoleCredential {
            session_id,
            role,
            token,
            websocket_path,
            expires_in_seconds,
            relay_address,
            relay_ticket,
            turn,
            permissions,
            session_grant,
        } = credential;
        let (host_token, client_token) = match role {
            Role::Host => (Some(token), None),
            Role::Client => (None, Some(token)),
        };
        let (relay_host_ticket, relay_client_ticket) = match role {
            Role::Host => (relay_ticket, None),
            Role::Client => (None, relay_ticket),
        };
        let (turn_host, turn_client) = match role {
            Role::Host => (turn, None),
            Role::Client => (None, turn),
        };
        Self {
            session_id,
            host_token,
            client_token,
            websocket_path,
            expires_in_seconds,
            relay_address,
            // The role-blind `turn` field stays empty: it exists for pairing
            // files written before TURN credentials were role-scoped, and a
            // credential that knows its own role has no reason to populate a
            // field whose whole problem is that it does not.
            turn: None,
            turn_host,
            turn_client,
            relay_host_ticket,
            relay_client_ticket,
            // Role-blind: the broker already scoped this grant to the one role
            // the credential carries, so it passes straight through.
            permissions,
            // Likewise: the control plane issues one only for the host, so a
            // client credential simply carries `None`.
            session_grant,
        }
    }

    /// Which roles this pairing can actually act as.
    ///
    /// Useful to a launcher deciding what to start: a credential collected
    /// from the broker can do exactly one thing.
    #[must_use]
    pub fn can_act_as(&self, role: Role) -> bool {
        self.token(role).is_ok()
    }

    /// The bearer token for one role, or an error if this pairing does not
    /// carry it.
    ///
    /// Refusing is the point. A credential issued to the client end has no
    /// host token, and asking for one has to fail rather than produce
    /// something presentable.
    fn token(&self, role: Role) -> Result<&str, Error> {
        let token = match role {
            Role::Host => self.host_token.as_deref(),
            Role::Client => self.client_token.as_deref(),
        };
        token.filter(|token| !token.is_empty()).ok_or_else(|| {
            Error::InvalidMessage(format!(
                "this session credential carries no {} token",
                role.as_str()
            ))
        })
    }

    fn relay_ticket(&self, role: Role) -> Option<&str> {
        match role {
            Role::Host => self.relay_host_ticket.as_deref(),
            Role::Client => self.relay_client_ticket.as_deref(),
        }
    }
}

fn origin_host(origin: &str) -> Option<String> {
    let normalized = if origin.contains("://") {
        origin.to_string()
    } else {
        format!("wss://{origin}")
    };
    url::Url::parse(&normalized)
        .ok()?
        .host_str()
        .map(ToString::to_string)
}

/// Allow plaintext signaling only for loopback, the existing explicit lab
/// override, or an explicitly selected private-LAN numeric origin. The latter
/// is intentionally narrower than `OPENSTREAM_ALLOW_INSECURE`: hostnames,
/// shared CGNAT space, and public/documentation addresses remain rejected.
fn plaintext_origin_allowed(
    host: &str,
    loopback: bool,
    allow_insecure: bool,
    local_no_auth: bool,
) -> bool {
    loopback
        || allow_insecure
        || (local_no_auth && host.parse::<IpAddr>().is_ok_and(is_private_lan_address))
}

fn is_private_lan_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            (octets[0] == 10)
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}

/// Whether a host literal is a loopback address (numeric IPv4/IPv6 loopback).
fn is_loopback_literal(host: &str) -> bool {
    if host == "::1" {
        return true;
    }
    let mut parts = host.split('.');
    if let (Some(first), Some(a), Some(b), Some(c), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        if first == "127" {
            return [a, b, c].iter().all(|octet| octet.parse::<u8>().is_ok());
        }
    }
    false
}

/// Whether a peer-supplied candidate address may be probed.
///
/// Unspecified, multicast, and port-zero addresses are always rejected: no
/// legitimate peer advertises them. Loopback is accepted only when our own
/// socket is loopback-bound (local demo/smoke), so a remote peer cannot use
/// this host as a localhost port-scanner.
pub fn valid_peer_candidate(address: SocketAddr, local: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    let ip = address.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if ip.is_loopback() {
        return local.ip().is_loopback();
    }
    true
}

/// Parse a comma-separated list of numeric STUN endpoints such as
/// `198.51.100.7:3478,[2001:db8::7]:3478`.
pub fn parse_stun_servers(spec: &str) -> Result<Vec<SocketAddr>, Error> {
    spec.split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(|endpoint| endpoint.parse().map_err(Error::Address))
        .collect()
}

/// Parse RFC 7064/7065 ICE server URLs such as
/// `stun:stun.example:3478` or `turn:turn.example:3478?transport=udp`.
/// Credentials are supplied separately so they do not end up in shell
/// history or signaling messages by accident. Credentials are stamped only
/// on `turn:`/`turns:` URLs; STUN URLs stay credential-free so mixed lists
/// are safe to log after redaction.
pub fn parse_ice_urls(
    spec: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<IceUrl>, Error> {
    use webrtc_ice::url::SchemeType;
    spec.split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(|raw| {
            let mut url = IceUrl::parse_url(raw).map_err(|error| Error::Ice(error.to_string()))?;
            if matches!(url.scheme, SchemeType::Turn | SchemeType::Turns) {
                url.username = username.unwrap_or_default().to_string();
                url.password = password.unwrap_or_default().to_string();
            }
            Ok(url)
        })
        .collect()
}

/// Whether callers should use the complete ICE/TURN path instead of the
/// small direct-candidate development path.
pub fn full_ice_enabled() -> bool {
    std::env::var("OPENSTREAM_ICE").as_deref() == Ok("1")
        || std::env::var_os("OPENSTREAM_ICE_URLS").is_some()
}

/// Whether the process asked to force every session through a TURN relay.
///
/// Read at the host-facing entry points only, so the establish functions stay
/// free of process-global state and remain deterministic under test.
fn force_relay_requested() -> bool {
    std::env::var("OPENSTREAM_FORCE_RELAY").as_deref() == Ok("1")
}

/// The ICE candidate types to gather for a session.
///
/// With `force_relay`, only relay candidates are gathered, so a network that
/// blocks every direct path is routed through TURN. Otherwise the full set is
/// gathered and ICE picks the best working pair. Extracted so the force-relay
/// selection can be pinned by a test without standing up an ICE agent.
fn ice_candidate_types(force_relay: bool) -> Vec<CandidateType> {
    if force_relay {
        vec![CandidateType::Relay]
    } else {
        vec![
            CandidateType::Host,
            CandidateType::ServerReflexive,
            CandidateType::PeerReflexive,
            CandidateType::Relay,
        ]
    }
}

/// Read the process-level ICE/TURN configuration.
///
/// URLs intentionally contain no credentials. A deployment supplies the
/// username/password through separate environment variables, and callers
/// must keep those variables out of logs and pairing JSON.
pub fn configured_ice_urls() -> Result<Vec<IceUrl>, Error> {
    let spec = std::env::var("OPENSTREAM_ICE_URLS").unwrap_or_default();
    let username = std::env::var("OPENSTREAM_TURN_USERNAME").ok();
    let password = std::env::var("OPENSTREAM_TURN_PASSWORD").ok();
    parse_ice_urls(&spec, username.as_deref(), password.as_deref())
}

/// Errors produced by the signaling client.
#[derive(Debug)]
pub enum Error {
    PathMigration(PathMigrationError),
    Connect(Box<tokio_tungstenite::tungstenite::Error>),
    Serialize(serde_json::Error),
    Deserialize(serde_json::Error),
    Transport(openstream_transport::Error),
    Stun(openstream_transport::StunError),
    KeyExchange(getrandom::Error),
    Identity(IdentityError),
    Address(std::net::AddrParseError),
    Hex(hex::FromHexError),
    InvalidMessage(String),
    /// The device identity is held in a platform keystore that could not be
    /// read. Never recovered from by generating a replacement: doing so would
    /// enrol the machine as a different device.
    KeyStoreUnavailable(String),
    Ice(String),
    SignalBackpressure,
    NoReachableCandidate,
    Closed,
    /// A non-loopback `http`/`ws` origin without `OPENSTREAM_ALLOW_INSECURE=1`.
    InsecureOrigin,
    /// An establishment phase (credentials, candidates, key) exceeded its
    /// deadline. The peer is stalled, gone, or malicious.
    Timeout(&'static str),
    /// The peer's X25519 public key is all zero or yields an all-zero shared
    /// secret (covers low-order points against a clamped secret).
    PeerKeyRejected,
    /// The peer key fingerprint does not match
    /// `OPENSTREAM_EXPECT_PEER_IDENTITY`.
    PeerIdentityMismatch,
    /// A non-loopback connection has no pinned peer identity. This is a
    /// deliberate fail-closed default; set an identity pin or opt into the
    /// explicitly insecure lab mode.
    PeerIdentityRequired,
    /// The peer's signed ephemeral key was not produced by its identity key.
    PeerIdentityRejected,
    /// No pairing file or explicit developer pairing override was provided.
    PairingRequired,
    /// The pairing path is not an absolute runtime path.
    PairingFilePathNotAbsolute,
    /// The pairing path could not be opened or read.
    PairingFileUnavailable,
    /// The pairing path is a symlink, non-regular file, wrong owner, or
    /// exposes its contents to group/other users.
    PairingFileInsecure,
    /// The pairing file exceeded the bounded runtime input size.
    PairingFileTooLarge,
    /// A pairing environment value was not valid UTF-8.
    PairingEnvironmentInvalid,
    /// The raw JSON environment escape hatch requires an explicit marker.
    DeveloperOverrideRequired,
    /// The peer sent more candidates than `MAX_REMOTE_CANDIDATES`.
    TooManyCandidates,
    /// The bounded critical outbound queue cannot accept another packet.
    OutboundBackpressure {
        class: OutboundClass,
    },
    /// The outbound packet cannot fit the portable sealed datagram bound.
    InvalidOutboundPacket,
    /// The delivery-history slot required for the next packet is unavailable.
    OutboundHistoryFull,
    /// The requested portable wire-rate value is not a finite non-negative rate.
    InvalidWirePacingRate,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathMigration(error) => write!(f, "path migration failed: {error}"),
            Self::Connect(error) => write!(f, "signaling connection failed: {error}"),
            Self::Serialize(error) => write!(f, "signaling message could not be encoded: {error}"),
            Self::Deserialize(error) => {
                write!(f, "signaling message could not be decoded: {error}")
            }
            Self::Transport(error) => write!(f, "encrypted data transport failed: {error}"),
            Self::Stun(error) => write!(f, "STUN candidate discovery failed: {error}"),
            Self::KeyExchange(error) => write!(f, "session key generation failed: {error}"),
            Self::Identity(error) => write!(f, "peer identity key failed: {error}"),
            Self::Address(error) => write!(f, "candidate address is invalid: {error}"),
            Self::Hex(error) => write!(f, "session public key is not valid hex: {error}"),
            Self::KeyStoreUnavailable(reason) => write!(f, "{reason}"),
            Self::InvalidMessage(reason) => write!(f, "invalid signaling message: {reason}"),
            Self::Ice(reason) => write!(f, "full ICE/TURN negotiation failed: {reason}"),
            Self::SignalBackpressure => {
                f.write_str("signaling queue is full; peer negotiation is backpressured")
            }
            Self::NoReachableCandidate => {
                f.write_str("none of the advertised UDP candidates answered")
            }
            Self::Closed => f.write_str("signaling connection closed"),
            Self::InsecureOrigin => f.write_str(
                "refusing plaintext signaling to a non-loopback origin (use https/wss or set OPENSTREAM_ALLOW_INSECURE=1)",
            ),
            Self::Timeout(phase) => write!(f, "establishment phase timed out: {phase}"),
            Self::PeerKeyRejected => f.write_str("peer public key is weak or low-order"),
            Self::PeerIdentityMismatch => f.write_str(
                "peer identity fingerprint does not match OPENSTREAM_EXPECT_PEER_IDENTITY",
            ),
            Self::PeerIdentityRequired => f.write_str(
                "a pinned peer identity is required for non-loopback sessions",
            ),
            Self::PeerIdentityRejected => {
                f.write_str("peer identity signature does not authenticate its ephemeral key")
            }
            Self::PairingRequired => {
                f.write_str("pairing file is required for normal launches")
            }
            Self::PairingFilePathNotAbsolute => {
                f.write_str("pairing file path must be absolute")
            }
            Self::PairingFileUnavailable => {
                f.write_str("pairing file could not be opened or read")
            }
            Self::PairingFileInsecure => {
                f.write_str("pairing file is not a private regular file owned by this user")
            }
            Self::PairingFileTooLarge => {
                write!(f, "pairing file exceeds {MAX_PAIRING_FILE_BYTES} bytes")
            }
            Self::PairingEnvironmentInvalid => {
                f.write_str("pairing environment value is not valid UTF-8")
            }
            Self::DeveloperOverrideRequired => f.write_str(
                "OPENSTREAM_PAIRING_JSON requires OPENSTREAM_DEVELOPER_OVERRIDE=1",
            ),
            Self::TooManyCandidates => {
                write!(f, "peer sent more than {MAX_REMOTE_CANDIDATES} candidates")
            }
            Self::OutboundBackpressure { class } => {
                write!(f, "{class:?} outbound queue is full")
            }
            Self::InvalidOutboundPacket => {
                f.write_str("outbound packet is invalid or exceeds the portable wire limit")
            }
            Self::OutboundHistoryFull => f.write_str("delivery history is full"),
            Self::InvalidWirePacingRate => {
                f.write_str("wire pacing rate must be finite and non-negative")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<PathMigrationError> for Error {
    fn from(error: PathMigrationError) -> Self {
        Self::PathMigration(error)
    }
}

impl From<openstream_transport::Error> for Error {
    fn from(error: openstream_transport::Error) -> Self {
        Self::Transport(error)
    }
}

impl From<openstream_transport::StunError> for Error {
    fn from(error: openstream_transport::StunError) -> Self {
        Self::Stun(error)
    }
}

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::KeyExchange(error)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(error: std::net::AddrParseError) -> Self {
        Self::Address(error)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

/// A connected, role-scoped signaling endpoint.
#[derive(Debug)]
pub struct Endpoint {
    outgoing: mpsc::Sender<Message>,
    incoming: mpsc::Receiver<Result<Value, Error>>,
}

impl Endpoint {
    /// Connect to the service with one side of a pairing.
    pub async fn connect(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
    ) -> Result<Self, Error> {
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let url = pairing.websocket_url(server_origin, role)?;
        let mut request = url
            .into_client_request()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        let authorization = format!("Bearer {}", pairing.token(role)?);
        let authorization = HeaderValue::from_str(&authorization)
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        request.headers_mut().insert(AUTHORIZATION, authorization);
        let (stream, _) =
            tokio::time::timeout(PHASE_TIMEOUT, tokio_tungstenite::connect_async(request))
                .await
                .map_err(|_| Error::Timeout("websocket connect"))?
                .map_err(|error| Error::Connect(Box::new(error)))?;
        let (mut sink, mut source) = stream.split();
        let (outgoing, mut queued) = mpsc::channel::<Message>(MAX_SIGNAL_QUEUE);
        let (inbound, incoming) = mpsc::channel::<Result<Value, Error>>(MAX_SIGNAL_QUEUE);

        tokio::spawn(async move {
            while let Some(message) = queued.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        tokio::spawn(async move {
            loop {
                let event = match source.next().await {
                    None => Err(Error::Closed),
                    Some(Err(error)) => Err(Error::Connect(Box::new(error))),
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_SIGNAL_MESSAGE_BYTES {
                            Err(Error::InvalidMessage(
                                "signaling message exceeds the client limit".into(),
                            ))
                        } else {
                            serde_json::from_str::<Value>(&text).map_err(Error::Deserialize)
                        }
                    }
                    Some(Ok(Message::Close(_))) => Err(Error::Closed),
                    Some(Ok(_)) => continue,
                };
                let terminal = event.is_err();
                if inbound.send(event).await.is_err() || terminal {
                    break;
                }
            }
        });

        Ok(Self { outgoing, incoming })
    }

    /// Send one JSON signaling envelope to the other role.
    pub fn send(&self, message: &Value) -> Result<(), Error> {
        self.sender().send(message)
    }

    fn sender(&self) -> SignalSender {
        SignalSender {
            outgoing: self.outgoing.clone(),
        }
    }

    /// Receive the next JSON signaling envelope.
    pub async fn recv(&mut self) -> Result<Value, Error> {
        self.incoming.recv().await.ok_or(Error::Closed)?
    }

    /// Receive the next envelope, failing if the peer stalls past the phase
    /// deadline instead of hanging establishment forever.
    pub async fn recv_deadline(&mut self, phase: &'static str) -> Result<Value, Error> {
        self.recv_until(TokioInstant::now() + PHASE_TIMEOUT, phase)
            .await
    }

    async fn recv_until(
        &mut self,
        deadline: TokioInstant,
        phase: &'static str,
    ) -> Result<Value, Error> {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout(phase));
        }
        tokio::time::timeout(remaining, self.recv())
            .await
            .map_err(|_| Error::Timeout(phase))?
    }
}

/// A cloneable, bounded signaling sender used by asynchronous ICE candidate
/// callbacks. The receiver remains owned by the peer-session choreography.
#[derive(Clone, Debug)]
struct SignalSender {
    outgoing: mpsc::Sender<Message>,
}

impl SignalSender {
    fn send(&self, message: &Value) -> Result<(), Error> {
        let text = serde_json::to_string(message).map_err(Error::Serialize)?;
        self.outgoing
            .try_send(Message::Text(text))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::SignalBackpressure,
                mpsc::error::TrySendError::Closed(_) => Error::Closed,
            })
    }
}

/// An established full-ICE data path. The agent is retained for the lifetime
/// of the connection because it owns consent freshness, keepalives, and
/// candidate-pair state; the returned `Conn` carries the selected pair's data.
struct IcePath {
    _agent: Arc<Agent>,
    conn: Arc<dyn IceConn + Send + Sync>,
}

impl fmt::Debug for IcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcePath").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PathCounters {
    sent_packets: u64,
    sent_wire_bytes: u64,
    received_packets: u64,
    received_wire_bytes: u64,
}

impl PathCounters {
    fn record_sent(&mut self, bytes: usize) {
        self.sent_packets = self.sent_packets.saturating_add(1);
        self.sent_wire_bytes = self
            .sent_wire_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn record_received(&mut self, bytes: usize) {
        self.received_packets = self.received_packets.saturating_add(1);
        self.received_wire_bytes = self
            .received_wire_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn sample(self, path_generation: PathGeneration) -> TransportSample {
        TransportSample {
            path_generation,
            sent_packets: self.sent_packets,
            sent_wire_bytes: self.sent_wire_bytes,
            received_packets: self.received_packets,
            received_wire_bytes: self.received_wire_bytes,
            sample_interval_ms: 0,
            send_rate_mbps: 0.0,
            receive_rate_mbps: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PathSampleBaseline {
    observed_at: Instant,
    counters: TransportSample,
}

fn sample_path_counters(
    counters: TransportSample,
    now: Instant,
    baseline: &mut Option<PathSampleBaseline>,
) -> Option<TransportSample> {
    let previous = match baseline.replace(PathSampleBaseline {
        observed_at: now,
        counters,
    }) {
        Some(previous) if previous.counters.path_generation == counters.path_generation => previous,
        _ => return None,
    };
    let sample_interval_ms = u64::try_from(
        now.saturating_duration_since(previous.observed_at)
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    if sample_interval_ms == 0 {
        return None;
    }
    let send_rate_mbps = decimal_mbps(
        counters
            .sent_wire_bytes
            .saturating_sub(previous.counters.sent_wire_bytes),
        sample_interval_ms,
    );
    let receive_rate_mbps = decimal_mbps(
        counters
            .received_wire_bytes
            .saturating_sub(previous.counters.received_wire_bytes),
        sample_interval_ms,
    );
    Some(TransportSample {
        sample_interval_ms,
        send_rate_mbps,
        receive_rate_mbps,
        ..counters
    })
}

fn decimal_mbps(bytes: u64, interval_ms: u64) -> f64 {
    if interval_ms == 0 {
        return 0.0;
    }
    bytes as f64 * 8_000.0 / (interval_ms as f64 * 1_000_000.0)
}

/// A fully established OpenStream peer session.
///
/// This is the shared choreography used by a GUI, a mobile bridge, or a host
/// service: role-scoped WebSocket, candidate exchange, ephemeral key exchange,
/// and an authenticated UDP socket. Codec and OS-device policy remain above
/// this type.
pub struct PeerSession {
    signal: Endpoint,
    path: PathRuntime,
    cipher: CipherSession,
    stats: SessionStats,
    scheduler: OutboundScheduler,
    // The policy ring is intentionally fixed-size and allocation-free, but
    // its portable session owner keeps it off async/task stacks. This avoids
    // making a 100 Mbps / 100 ms delivery window depend on the executor's
    // thread-stack size.
    delivery: Box<DeliveryEstimator>,
    transport_ack: TransportAckWindow,
    policy_clock_origin: Instant,
    path_baseline: Option<PathSampleBaseline>,
    ice_counters: PathCounters,
    /// A peer can win the path probe and send its first capability message
    /// before the other side has left the probe loop. Preserve that
    /// authenticated packet instead of dropping it at the phase boundary.
    prefetched: Option<Packet>,
    /// Last direct-path keepalive sent by the owning event loop.
    last_keepalive: std::time::Instant,
    /// Last authenticated packet received from the peer, including transport
    /// metadata and path-control traffic that `recv()` consumes internally.
    /// Host adapters use this to release injected input after a real peer
    /// liveness gap rather than guessing from application traffic frequency.
    last_peer_activity: std::time::Instant,
    migration_enabled: bool,
    migration: MigrationController,
    migration_config: MigrationConfig,
    opening: Option<OpeningPath>,
    draining: Option<DrainingPath>,
    migration_inbox: std::collections::VecDeque<Packet>,
}

struct RelayTicket(String);

impl fmt::Debug for RelayTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayTicket([redacted])")
    }
}

#[derive(Debug)]
struct MigrationConfig {
    session_id: String,
    role: Role,
    local_candidates: Vec<Candidate>,
    peer_candidates: Vec<Candidate>,
    relay_address: Option<SocketAddr>,
    relay_ticket: Option<RelayTicket>,
}

impl MigrationConfig {
    fn new(
        pairing: &Pairing,
        role: Role,
        local_candidates: Vec<Candidate>,
        peer_candidates: Vec<Candidate>,
    ) -> Self {
        Self {
            session_id: pairing.session_id.clone(),
            role,
            local_candidates: local_candidates
                .into_iter()
                .filter(|candidate| valid_local_candidate(candidate.address))
                .take(MAX_REMOTE_CANDIDATES)
                .collect(),
            peer_candidates: peer_candidates
                .into_iter()
                .filter(|candidate| valid_local_candidate(candidate.address))
                .take(MAX_REMOTE_CANDIDATES)
                .collect(),
            relay_address: pairing
                .relay_address
                .as_deref()
                .and_then(|address| address.parse().ok())
                .filter(|address: &SocketAddr| {
                    address.port() != 0
                        && !address.ip().is_unspecified()
                        && !address.ip().is_multicast()
                }),
            relay_ticket: pairing
                .relay_ticket(role)
                .filter(|ticket| !ticket.is_empty())
                .map(|ticket| RelayTicket(ticket.to_owned())),
        }
    }
}

struct OpeningPath {
    generation: PathGeneration,
    target: MigrationTarget,
    token: MigrationToken,
    advertised: bool,
    remote: Option<SocketAddr>,
    connected: bool,
}

struct ReceivedPacket {
    packet: Packet,
    ingress: PathSlot,
    wire_bytes: Option<usize>,
}

fn new_transport_state(
    now: Instant,
    generation: PathGeneration,
) -> (
    OutboundScheduler,
    Box<DeliveryEstimator>,
    TransportAckWindow,
    Instant,
) {
    (
        OutboundScheduler::new(0.0),
        Box::new(DeliveryEstimator::new(generation)),
        TransportAckWindow::new(generation, TransportAckConfig::default()),
        now,
    )
}

fn outbound_class(kind: Kind) -> OutboundClass {
    match kind {
        Kind::Control | Kind::Input => OutboundClass::Critical,
        Kind::Audio => OutboundClass::Audio,
        Kind::Video => OutboundClass::Video,
    }
}

fn queue_error(kind: Kind, error: SchedulerError) -> Error {
    match error {
        SchedulerError::QueueFull => Error::OutboundBackpressure {
            class: outbound_class(kind),
        },
        SchedulerError::InvalidPacket => Error::InvalidOutboundPacket,
        SchedulerError::HistoryFull => Error::OutboundHistoryFull,
    }
}

fn flush_error(error: SchedulerError) -> Error {
    match error {
        SchedulerError::HistoryFull => Error::OutboundHistoryFull,
        SchedulerError::QueueFull => Error::OutboundBackpressure {
            class: OutboundClass::Critical,
        },
        SchedulerError::InvalidPacket => Error::InvalidOutboundPacket,
    }
}

fn delivery_error(error: DeliveryError) -> Error {
    Error::InvalidMessage(error.to_string())
}

fn traffic_class(kind: Kind) -> TrafficClass {
    match kind {
        Kind::Control | Kind::Input => TrafficClass::Critical,
        Kind::Audio => TrafficClass::Audio,
        Kind::Video => TrafficClass::Video,
    }
}

async fn receive_backend(
    backend: &PeerPathBackend,
    datagram: &mut [u8; MAX_DATAGRAM],
) -> Result<usize, Error> {
    match backend {
        PeerPathBackend::Direct { transport, .. } => {
            tokio::time::timeout(DIRECT_IDLE_TIMEOUT, transport.recv_sealed(datagram))
                .await
                .map_err(|_| Error::Timeout("direct data path liveness"))?
                .map_err(Error::from)
        }
        PeerPathBackend::Ice(path) => path
            .conn
            .recv(datagram)
            .await
            .map_err(|error| Error::Ice(error.to_string())),
    }
}

struct DrainingPath {
    incoming: mpsc::Receiver<(PathSlot, Vec<u8>)>,
    cancel: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl DrainingPath {
    fn new(old: PeerPath, deadline: Instant) -> Self {
        let (outgoing, incoming) = mpsc::channel(32);
        let (cancel, mut cancelled) = oneshot::channel();
        let (generation, backend) = old.into_backend();
        // This task owns the old socket and relay cleanup guard, so both the
        // receive-only lifetime and remote registration cleanup remain finite
        // even when the application's receive loop is idle or cancelled.
        let task = tokio::spawn(async move {
            let (transport, relay_registration) = match backend {
                PeerPathBackend::Direct {
                    transport,
                    relay_registration,
                    ..
                } => (Some(transport), relay_registration),
                PeerPathBackend::Ice(_) => (None, None),
            };
            if let Some(transport) = transport {
                let mut datagram = [0; MAX_DATAGRAM];
                loop {
                    let result = tokio::select! {
                        _ = &mut cancelled => break,
                        result = tokio::time::timeout_at(
                            TokioInstant::from_std(deadline),
                            transport.recv_sealed(&mut datagram),
                        ) => result,
                    };
                    let Ok(Ok(length)) = result else {
                        break;
                    };
                    if outgoing
                        .try_send((PathSlot(generation), datagram[..length].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
            if let Some(relay_registration) = relay_registration {
                let _ = relay_registration.unregister().await;
            }
        });
        Self {
            incoming,
            cancel,
            task,
        }
    }

    async fn close(self) {
        let _ = self.cancel.send(());
        let _ = self.task.await;
    }
}

async fn cleanup_peer_path(path: PeerPath) {
    let (_generation, backend) = path.into_backend();
    if let PeerPathBackend::Direct {
        relay_registration: Some(relay_registration),
        ..
    } = backend
    {
        let _ = relay_registration.unregister().await;
    }
}

impl fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSession")
            .field("connection_path", &self.connection_path())
            .field("path_generation", &self.path_generation())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Bounded ordered control helper layered over a [`PeerSession`].
///
/// Media remains datagram-oriented and best-effort. Keyframe requests, input
/// state transitions, and frame acknowledgements use this helper when a
/// caller opts in: the inner sequence provides ordering, the outer encrypted
/// counter provides authentication/replay protection, and `retry` lets the
/// caller drive retransmission from its event-loop timer without a hidden
/// unbounded task.
#[derive(Debug)]
pub struct ReliableControl {
    outbound: ControlChannel,
    inbound: ControlChannel,
}

impl ReliableControl {
    /// Create a control channel with a bounded number of queued messages.
    pub fn new(max_pending: usize) -> Self {
        Self {
            outbound: ControlChannel::new(max_pending),
            inbound: ControlChannel::new(max_pending),
        }
    }

    /// Queue and immediately transmit the oldest reliable control message.
    ///
    /// Returns `Some(sequence)` when the message was accepted into the
    /// outstanding window, and `None` when the window was full. A full window
    /// is transient backpressure -- the peer has not acknowledged enough
    /// in-flight control yet -- so this newest message is dropped rather than
    /// the session being torn down: the oldest frame is still flushed to
    /// elicit acknowledgements, and a genuinely dead peer is caught by the
    /// liveness timeout, not by a fatal error here. A genuinely oversized or
    /// empty payload is a permanent fault and is still returned as an error.
    pub async fn send(
        &mut self,
        session: &mut PeerSession,
        payload: &[u8],
    ) -> Result<Option<u32>, Error> {
        match self.outbound.queue(payload) {
            Ok(sequence) => {
                self.flush(session).await?;
                Ok(Some(sequence))
            }
            Err(openstream_protocol::control::Error::WindowFull) => {
                // Backpressure, not malformed input: drive the oldest frame so
                // its acknowledgement can open the window, and drop this one.
                self.flush(session).await?;
                Ok(None)
            }
            Err(error) => Err(Error::InvalidMessage(error.to_string())),
        }
    }

    /// Send a redundant control message only when the bounded window has
    /// room. This is intended for cumulative application acknowledgements
    /// such as video frame ACKs: dropping one is safe because a later ACK
    /// supersedes it, while allowing the queue to grow without bound is not.
    pub async fn send_if_available(
        &mut self,
        session: &mut PeerSession,
        payload: &[u8],
    ) -> Result<Option<u32>, Error> {
        if !self.outbound.has_capacity() {
            return Ok(None);
        }
        self.send(session, payload).await
    }

    /// Retransmit the oldest outstanding message, if one exists.
    ///
    /// Call this from a bounded timer. The helper intentionally does not own
    /// a timer because the host/client event loop already has the correct
    /// lifecycle and latency budget.
    pub async fn retry(&mut self, session: &mut PeerSession) -> Result<(), Error> {
        self.flush_retry(session).await
    }

    /// Consume one packet. `None` means it was ordinary/raw control data and
    /// should be handled by the caller; `Some` means the packet was a framed
    /// reliable-control packet, including an empty delivery for ACK-only or
    /// out-of-order traffic.
    pub async fn receive(
        &mut self,
        session: &mut PeerSession,
        packet: &Packet,
    ) -> Result<Option<Vec<Vec<u8>>>, Error> {
        if packet.kind != Kind::Control {
            return Ok(None);
        }
        let Ok(frame) = ControlFrame::decode(&packet.payload) else {
            return Ok(None);
        };
        let ack_only = frame.ack_only;
        if let Some(acknowledgement) = frame.acknowledgement {
            self.outbound.acknowledge(acknowledgement);
        }
        let received = self.inbound.receive(frame);
        if !ack_only {
            if let Some(acknowledgement) = self.inbound.acknowledgement_frame() {
                self.send_frame(session, &acknowledgement, false).await?;
            }
        }
        self.flush(session).await?;
        Ok(Some(received.delivered))
    }

    /// Number of messages awaiting acknowledgement.
    pub fn outstanding(&self) -> usize {
        self.outbound.outstanding()
    }

    async fn flush(&mut self, session: &mut PeerSession) -> Result<(), Error> {
        if let Some(frame) = self.outbound.next_frame() {
            self.send_frame(session, &frame, false).await?;
        }
        Ok(())
    }

    async fn flush_retry(&mut self, session: &mut PeerSession) -> Result<(), Error> {
        if let Some(frame) = self.outbound.next_frame() {
            self.send_frame(session, &frame, true).await?;
        }
        Ok(())
    }

    async fn send_frame(
        &mut self,
        session: &mut PeerSession,
        frame: &ControlFrame,
        logical_retransmission: bool,
    ) -> Result<(), Error> {
        let payload = frame
            .encode()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        session
            .send_application_with_flag(Kind::Control, 0, 0, &payload, logical_retransmission)
            .await?;
        Ok(())
    }
}

impl PeerSession {
    /// Prepare and commit a fresh direct/opaque path as the authoritative host.
    /// The peer's normal `recv` loop drives the responder. Cancellation keeps
    /// the in-session attempt durable; later recv/liveness calls drive it on.
    pub async fn migrate_to(&mut self, target: MigrationTarget) -> Result<MigrationReport, Error> {
        if !self.migration_enabled {
            return Err(PathMigrationError::CapabilityNotNegotiated.into());
        }
        let actions = self.migration.tick(Instant::now());
        self.apply_migration_actions(actions).await?;
        if self.migration.state == MigrationState::CommitUnconfirmed {
            return Err(PathMigrationError::CommitUnconfirmed.into());
        }
        if self.migration.busy() {
            return Err(PathMigrationError::MigrationAlreadyPending.into());
        }
        if self.migration.role != Role::Host {
            return Err(PathMigrationError::HostMigrationRequired.into());
        }
        self.check_migration_target(target)?;
        let previous = self.path.snapshot(Instant::now());
        let actions = self
            .migration
            .start(target, MigrationToken::random()?, Instant::now())?;
        self.apply_migration_actions(actions).await?;
        loop {
            if let Err(error) = self.drive_migration().await {
                self.abort_preparation().await;
                return Err(
                    if self.migration.state == MigrationState::CommitUnconfirmed {
                        PathMigrationError::CommitUnconfirmed.into()
                    } else {
                        error
                    },
                );
            }
            match self.migration.state {
                MigrationState::Active => {
                    let active = self.path.snapshot(Instant::now());
                    return Ok(MigrationReport {
                        previous_generation: previous.path_generation,
                        active_generation: active.path_generation,
                        previous_kind: previous.path,
                        active_kind: active.path,
                    });
                }
                MigrationState::CommitUnconfirmed => {
                    return Err(PathMigrationError::CommitUnconfirmed.into());
                }
                MigrationState::Failed => return Err(PathMigrationError::PathUnavailable.into()),
                _ => {}
            }
            match self.recv_step().await {
                Ok(Some(packet)) if self.migration_inbox.len() < MAX_CONTROL_PENDING => {
                    self.migration_inbox.push_back(packet)
                }
                Ok(_) => {}
                Err(error) => {
                    self.abort_preparation().await;
                    return Err(
                        if self.migration.state == MigrationState::CommitUnconfirmed {
                            PathMigrationError::CommitUnconfirmed.into()
                        } else {
                            error
                        },
                    );
                }
            }
        }
    }

    pub fn migration_state(&self) -> MigrationState {
        self.migration.state
    }

    pub fn path_snapshot(&mut self) -> PeerTransportSnapshot {
        self.transport_snapshot(Instant::now())
    }

    fn check_migration_target(&self, target: MigrationTarget) -> Result<(), Error> {
        if target == MigrationTarget::Ice
            || matches!(self.path.active().backend(), PeerPathBackend::Ice(_))
        {
            return Err(PathMigrationError::UnsupportedIceRestart.into());
        }
        let config = &self.migration_config;
        let available = match target {
            MigrationTarget::DirectUdp => {
                config
                    .local_candidates
                    .iter()
                    .any(|c| c.kind == CandidateKind::Host)
                    && config
                        .peer_candidates
                        .iter()
                        .any(|c| c.kind != CandidateKind::Relay)
            }
            MigrationTarget::OpaqueRelay => {
                config.relay_address.is_some() && config.relay_ticket.is_some()
            }
            MigrationTarget::Ice => false,
        };
        // Only cross-family migration is supported; re-registering an active
        // relay role would replace its slot before the commit boundary.
        let same_kind = matches!(
            (target, self.connection_path()),
            (
                MigrationTarget::OpaqueRelay,
                ConnectionPath::DirectUdp {
                    candidate: CandidateKind::Relay
                }
            ) | (
                MigrationTarget::DirectUdp,
                ConnectionPath::DirectUdp {
                    candidate: CandidateKind::Host
                        | CandidateKind::Mapped
                        | CandidateKind::ServerReflexive
                }
            )
        );
        if !available || same_kind {
            return Err(PathMigrationError::PathUnavailable.into());
        }
        Ok(())
    }

    async fn abort_preparation(&mut self) {
        let actions = self
            .migration
            .fail_preparation(openstream_protocol::path_control::AbortReason::ProbeFailed);
        let _ = self.apply_migration_actions(actions).await;
    }

    async fn apply_migration_actions(
        &mut self,
        actions: Vec<MigrationAction>,
    ) -> Result<(), Error> {
        for action in actions {
            match action {
                MigrationAction::Send(slot, record) => {
                    let bytes = record
                        .encode()
                        .map_err(|error| Error::InvalidMessage(error.to_string()))?;
                    if self
                        .send_path_control(slot, PATH_CONTROL_CHANNEL, &bytes)
                        .await
                        .is_err()
                        && slot == PathSlot(self.path_generation())
                    {
                        self.migration.old_path_failed();
                    }
                }
                MigrationAction::Open {
                    generation,
                    target,
                    token,
                } => {
                    self.opening = Some(OpeningPath {
                        generation,
                        target,
                        token,
                        advertised: false,
                        remote: None,
                        connected: false,
                    });
                }
                MigrationAction::Activate { generation } => {
                    // No await between the durable controller decision and
                    // swapping all path-local state, or before ACK emission.
                    assert_eq!(
                        self.path.prepared.as_ref().map(PeerPath::generation),
                        Some(generation)
                    );
                    self.path.mark_ready();
                    self.path.mark_commit_pending();
                    assert!(self.path.activate_prepared());
                    let now = Instant::now();
                    self.path.active_mut().activate(now);
                    self.path.begin_drain();
                    let old = self.path.prepared.take().expect("old path retained");
                    self.draining = Some(DrainingPath::new(
                        old,
                        self.migration.drain_deadline().expect("drain deadline"),
                    ));
                    self.opening = None;
                    self.path_baseline = None;
                    self.ice_counters = PathCounters::default();
                    let policy_now_ms = self.policy_now_ms(now);
                    self.scheduler.reset_generation(policy_now_ms, generation);
                    self.delivery.reset_generation(generation);
                    self.transport_ack.reset(generation);
                    self.last_keepalive = now;
                }
                MigrationAction::Retire => {
                    if let Some(draining) = self.draining.take() {
                        draining.close().await;
                    }
                }
                MigrationAction::Discard => {
                    self.opening = None;
                    if let Some(prepared) = self.path.prepared.take() {
                        cleanup_peer_path(prepared).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn drive_migration(&mut self) -> Result<(), Error> {
        if !self.migration_enabled {
            return Ok(());
        }
        let actions = self.migration.tick(Instant::now());
        self.apply_migration_actions(actions).await?;
        if matches!(
            self.migration.state,
            MigrationState::Failed | MigrationState::CommitUnconfirmed
        ) {
            return Ok(());
        }
        // Reconstruct opening work if a caller cancelled between reservation
        // and execution of an action. No second token or cipher is created.
        if self.opening.is_none() {
            if let Some(p) = &self.migration.pending {
                self.opening = Some(OpeningPath {
                    generation: p.generation,
                    target: p.target,
                    token: p.token,
                    advertised: false,
                    remote: None,
                    connected: false,
                });
            }
        }
        let Some(opening) = &self.opening else {
            return Ok(());
        };
        if opening.connected {
            return Ok(());
        }
        let deadline = self
            .migration
            .pending
            .as_ref()
            .expect("opening has pending attempt")
            .deadline;
        let result =
            tokio::time::timeout_at(TokioInstant::from_std(deadline), self.open_replacement())
                .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.abort_preparation().await;
                Err(error)
            }
            Err(_) => {
                self.abort_preparation().await;
                Err(PathMigrationError::PathUnavailable.into())
            }
        }
    }

    async fn open_replacement(&mut self) -> Result<(), Error> {
        let opening = self.opening.as_ref().expect("opening work");
        let target = opening.target;
        self.check_migration_target(target)?;
        if self.path.prepared.is_none() {
            let local = match self.path.active().backend() {
                PeerPathBackend::Direct { transport, .. } => transport.local_addr()?,
                PeerPathBackend::Ice(_) => {
                    return Err(PathMigrationError::UnsupportedIceRestart.into());
                }
            };
            let transport = UdpTransport::bind(SocketAddr::new(local.ip(), 0)).await?;
            self.path.install(PeerPath::replacement(
                PeerPathBackend::Direct {
                    transport: Box::new(transport),
                    candidate: if target == MigrationTarget::OpaqueRelay {
                        CandidateKind::Relay
                    } else {
                        CandidateKind::Host
                    },
                    relay_registration: None,
                },
                opening.generation,
                Instant::now(),
            ));
        }
        let opening = self.opening.as_mut().expect("opening work");
        let PeerPathBackend::Direct {
            transport,
            relay_registration,
            ..
        } = self
            .path
            .prepared
            .as_mut()
            .expect("replacement socket")
            .backend_mut()
        else {
            unreachable!()
        };
        if target == MigrationTarget::DirectUdp {
            if !opening.advertised {
                let local = transport.local_addr()?;
                let ip = if local.ip().is_unspecified() {
                    self.migration_config
                        .local_candidates
                        .iter()
                        .find(|candidate| {
                            candidate.kind == CandidateKind::Host
                                && candidate.address.is_ipv4() == local.is_ipv4()
                        })
                        .ok_or(PathMigrationError::PathUnavailable)?
                        .address
                        .ip()
                } else {
                    local.ip()
                };
                self.signal.send(&serde_json::json!({"type":"path_candidate", "generation":opening.generation, "token":hex::encode(opening.token.bytes()), "kind":"direct_udp", "ip":ip.to_string(), "port":local.port()}))?;
                opening.advertised = true;
            }
            let Some(remote) = opening.remote else {
                return Ok(());
            };
            transport.connect(remote).await?;
        } else {
            let config = &self.migration_config;
            transport
                .connect(
                    config
                        .relay_address
                        .ok_or(PathMigrationError::PathUnavailable)?,
                )
                .await?;
            let role = match config.role {
                Role::Host => RelayRole::Host,
                Role::Client => RelayRole::Client,
            };
            let ticket = &config
                .relay_ticket
                .as_ref()
                .ok_or(PathMigrationError::PathUnavailable)?
                .0;
            let cleanup_guard = transport.relay_registration(&config.session_id, role, ticket)?;
            let registration_result = transport
                .register_relay(&config.session_id, role, ticket)
                .await;
            // Install the guard before propagating a registration error: the
            // relay may have accepted the request even when its ACK was lost.
            *relay_registration = Some(cleanup_guard);
            registration_result?;
        }
        opening.connected = true;
        let actions = self.migration.opened(Instant::now());
        self.apply_migration_actions(actions).await
    }

    fn receive_path_candidate(&mut self, message: Value) -> Result<(), Error> {
        let invalid = || Error::InvalidMessage("unexpected or invalid path candidate".into());
        if message.to_string().len() > MAX_CANDIDATE_BYTES {
            return Err(invalid());
        }
        let opening = self.opening.as_mut().ok_or_else(invalid)?;
        if opening.target != MigrationTarget::DirectUdp || opening.remote.is_some() {
            return Err(invalid());
        }
        let object = message.as_object().ok_or_else(invalid)?;
        if object.len() != 6
            || message.get("type").and_then(Value::as_str) != Some("path_candidate")
            || message.get("kind").and_then(Value::as_str) != Some("direct_udp")
            || message.get("generation").and_then(Value::as_u64) != Some(opening.generation)
        {
            return Err(invalid());
        }
        let raw_token = message
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let mut token = [0; 16];
        hex::decode_to_slice(raw_token, &mut token).map_err(|_| invalid())?;
        if token == [0; 16] || token != opening.token.bytes() {
            return Err(invalid());
        }
        let ip: IpAddr = message
            .get("ip")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let port = message
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(invalid)?;
        let address = SocketAddr::new(ip, port);
        let PeerPathBackend::Direct { transport, .. } =
            self.path.prepared.as_ref().ok_or_else(invalid)?.backend()
        else {
            return Err(invalid());
        };
        let local = transport.local_addr()?;
        if address == local
            || address.is_ipv4() != local.is_ipv4()
            || !valid_peer_candidate(address, local)
        {
            return Err(invalid());
        }
        opening.remote = Some(address);
        Ok(())
    }

    /// Establish the control and encrypted data paths for one pairing.
    pub async fn establish(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
        local_bind: SocketAddr,
    ) -> Result<Self, Error> {
        Self::establish_with_stun(server_origin, pairing, role, local_bind, &[]).await
    }

    /// Establish using the configured connectivity profile.
    ///
    /// The default remains the small project-owned direct-candidate path for
    /// deterministic development tests. Setting `OPENSTREAM_ICE=1` (or
    /// providing `OPENSTREAM_ICE_URLS`) selects full ICE; the optional STUN
    /// server list is used only by the direct path. `OPENSTREAM_UPNP=1`
    /// additionally requests a best-effort local IGD port mapping for that
    /// direct path.
    pub async fn establish_configured(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
        local_bind: SocketAddr,
        stun_servers: &[SocketAddr],
    ) -> Result<Self, Error> {
        if full_ice_enabled() {
            let urls = ice_urls_for_pairing_role(pairing, role)?;
            Self::establish_with_ice(
                server_origin,
                pairing,
                role,
                local_bind,
                &urls,
                force_relay_requested(),
            )
            .await
        } else {
            Self::establish_with_stun(server_origin, pairing, role, local_bind, stun_servers).await
        }
    }

    /// Establish a standards-based ICE session from application-supplied
    /// configuration. This is the mobile-safe counterpart to
    /// `establish_configured`: callers do not need to mutate process
    /// environment variables, and credentials remain separate from the URL
    /// list and pairing JSON.
    pub async fn establish_with_ice_spec(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
        local_bind: SocketAddr,
        ice_urls: &str,
        turn_username: Option<&str>,
        turn_password: Option<&str>,
    ) -> Result<Self, Error> {
        let urls = parse_ice_urls(ice_urls, turn_username, turn_password)?;
        Self::establish_with_ice(
            server_origin,
            pairing,
            role,
            local_bind,
            &urls,
            force_relay_requested(),
        )
        .await
    }

    /// Establish a standards-based ICE session, optionally allocating a TURN
    /// relay from `ice_urls`.
    ///
    /// The role-authenticated WebSocket carries RFC 8445-style candidate
    /// strings and ICE username/password credentials. The ICE agent then owns
    /// candidate priorities, peer-reflexive discovery, connectivity checks,
    /// nomination, keepalives, consent freshness, and TURN allocation. The
    /// OpenStream AES-GCM datagrams are carried unchanged over the selected
    /// `Conn`, so ICE does not weaken or replace end-to-end media encryption.
    pub async fn establish_with_ice(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
        local_bind: SocketAddr,
        ice_urls: &[IceUrl],
        force_relay: bool,
    ) -> Result<Self, Error> {
        let mut signal = Endpoint::connect(server_origin, pairing, role).await?;
        // Waiting for the server-owned pair is outside the candidate/key
        // deadlines. A host and client are allowed to start at different
        // times while the session remains alive, but no ICE record may be
        // sent until both current role sockets have received this epoch.
        let establishment_generation = wait_for_ice_ready(&mut signal).await?;
        let udp_network = if local_bind.port() == 0 {
            UDPNetwork::Ephemeral(Default::default())
        } else {
            UDPNetwork::Ephemeral(
                EphemeralUDP::new(local_bind.port(), local_bind.port())
                    .map_err(|error| Error::Ice(error.to_string()))?,
            )
        };
        // `force_relay` restricts the session to TURN-relayed media. The
        // direct/STUN path already honors OPENSTREAM_FORCE_RELAY; the full ICE
        // path did not, so a caller that asked for relay-only could still
        // nominate a host or server-reflexive pair. When forced, gather relay
        // candidates only so a network that blocks every direct path is routed
        // through TURN. The env read lives in the host-facing callers, so this
        // function stays independent of process-global state.
        let candidate_types = ice_candidate_types(force_relay);
        let agent = Arc::new(
            Agent::new(AgentConfig {
                urls: ice_urls.to_vec(),
                udp_network,
                network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
                candidate_types,
                is_controlling: role == Role::Client,
                insecure_skip_verify: std::env::var("OPENSTREAM_ICE_INSECURE").as_deref()
                    == Ok("1"),
                include_loopback: std::env::var("OPENSTREAM_ICE_INCLUDE_LOOPBACK").as_deref()
                    == Ok("1"),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::Ice(error.to_string()))?,
        );

        let (candidate_tx, mut candidate_rx) = mpsc::channel::<Option<String>>(MAX_SIGNAL_QUEUE);
        let candidate_failed = Arc::new(AtomicBool::new(false));
        let candidate_failed_callback = Arc::clone(&candidate_failed);
        agent.on_candidate(Box::new(move |candidate| {
            let marshalled = candidate.map(|candidate| candidate.marshal());
            if candidate_tx.try_send(marshalled).is_err() {
                candidate_failed_callback.store(true, Ordering::Release);
            }
            Box::pin(async {})
        }));

        let sender = signal.sender();
        let candidate_failed_forwarder = Arc::clone(&candidate_failed);
        let candidate_forwarder = tokio::spawn(async move {
            let mut candidate_count = 0_usize;
            while let Some(candidate) = candidate_rx.recv().await {
                let message = match candidate {
                    Some(candidate) => {
                        candidate_count = candidate_count.saturating_add(1);
                        serde_json::json!({
                            "type": "ice_candidate_v2",
                            "establishment_generation": establishment_generation,
                            "candidate": candidate,
                        })
                    }
                    None => serde_json::json!({
                        "type": "ice_candidate_done_v2",
                        "establishment_generation": establishment_generation,
                        "count": candidate_count,
                    }),
                };
                if sender.send(&message).is_err() {
                    candidate_failed_forwarder.store(true, Ordering::Release);
                    break;
                }
            }
        });

        let (local_ufrag, local_pwd) = agent.get_local_user_credentials().await;
        signal.send(&serde_json::json!({
            "type": "ice_credentials_v2",
            "establishment_generation": establishment_generation,
            "ufrag": local_ufrag,
            "pwd": local_pwd,
        }))?;
        agent
            .gather_candidates()
            .map_err(|error| Error::Ice(error.to_string()))?;

        let mut remote_ufrag = None;
        let mut remote_pwd = None;
        let mut remote_candidates_done = false;
        let mut early_key: Option<PeerKey> = None;
        let mut remote_candidate_count = 0_usize;
        let phase_deadline = TokioInstant::now() + PHASE_TIMEOUT;
        while remote_ufrag.is_none() || remote_pwd.is_none() || !remote_candidates_done {
            let message = signal
                .recv_until(phase_deadline, "ice credentials/candidates")
                .await?;
            match message.get("type").and_then(Value::as_str) {
                Some("ice_peer_reset") => {
                    candidate_forwarder.abort();
                    return Err(Error::InvalidMessage(
                        "ICE establishment reset; reconnect for a new epoch".into(),
                    ));
                }
                Some("ice_peer_ready") => {
                    if !handle_ice_generation(&message, "ice_peer_ready", establishment_generation)?
                    {
                        continue;
                    }
                }
                Some("ice_credentials_v2") => {
                    if !handle_ice_generation(
                        &message,
                        "ice_credentials_v2",
                        establishment_generation,
                    )? {
                        continue;
                    }
                    remote_ufrag = Some(required_ice_credential(
                        &message,
                        "ufrag",
                        MAX_ICE_UFRAG_BYTES,
                    )?);
                    remote_pwd = Some(required_ice_credential(
                        &message,
                        "pwd",
                        MAX_ICE_PASSWORD_BYTES,
                    )?);
                }
                Some("ice_candidate_v2") => {
                    if !handle_ice_generation(
                        &message,
                        "ice_candidate_v2",
                        establishment_generation,
                    )? {
                        continue;
                    }
                    remote_candidate_count += 1;
                    if remote_candidate_count > MAX_REMOTE_CANDIDATES {
                        candidate_forwarder.abort();
                        return Err(Error::TooManyCandidates);
                    }
                    let raw = message
                        .get("candidate")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            Error::InvalidMessage("ice_candidate_v2.candidate is missing".into())
                        })?;
                    if raw.is_empty() || raw.len() > MAX_CANDIDATE_BYTES {
                        candidate_forwarder.abort();
                        return Err(Error::InvalidMessage(
                            "ice_candidate_v2.candidate has an invalid length".into(),
                        ));
                    }
                    let candidate =
                        unmarshal_candidate(raw).map_err(|error| Error::Ice(error.to_string()))?;
                    let candidate: Arc<dyn IceCandidate + Send + Sync> = Arc::new(candidate);
                    agent
                        .add_remote_candidate(&candidate)
                        .map_err(|error| Error::Ice(error.to_string()))?;
                }
                Some("ice_candidate_done_v2") => {
                    if !handle_ice_generation(
                        &message,
                        "ice_candidate_done_v2",
                        establishment_generation,
                    )? {
                        continue;
                    }
                    remote_candidates_done = true;
                }
                // A peer that pipelines its key before candidate_done must not
                // deadlock the later key phase: stash it for use below.
                Some("ice_key_v2") if early_key.is_none() => {
                    if !handle_ice_generation(&message, "ice_key_v2", establishment_generation)? {
                        continue;
                    }
                    early_key = Some(decode_ice_peer_key(&message, establishment_generation)?);
                }
                Some("ice_key_v2") => {}
                _ => {}
            }
        }
        if candidate_failed.load(Ordering::Acquire) {
            candidate_forwarder.abort();
            return Err(Error::SignalBackpressure);
        }

        let key_exchange = KeyExchange::generate()?;
        let identity = local_identity()?;
        signal.send(&encode_ice_key_message(
            &key_exchange,
            &identity,
            &pairing.session_id,
            establishment_generation,
            role,
        )?)?;
        let key_deadline = TokioInstant::now() + PHASE_TIMEOUT;
        let peer_public = match early_key.take() {
            Some(stashed) => stashed,
            None => loop {
                let message = signal.recv_until(key_deadline, "key exchange").await?;
                match message.get("type").and_then(Value::as_str) {
                    Some("ice_peer_reset") => {
                        candidate_forwarder.abort();
                        return Err(Error::InvalidMessage(
                            "ICE establishment reset; reconnect for a new epoch".into(),
                        ));
                    }
                    Some("ice_peer_ready") => {
                        if !handle_ice_generation(
                            &message,
                            "ice_peer_ready",
                            establishment_generation,
                        )? {
                            continue;
                        }
                    }
                    Some("ice_key_v2") => {
                        if !handle_ice_generation(&message, "ice_key_v2", establishment_generation)?
                        {
                            continue;
                        }
                        break decode_ice_peer_key(&message, establishment_generation)?;
                    }
                    _ => continue,
                }
            },
        };
        authenticate_ice_peer(
            server_origin,
            pairing,
            role,
            establishment_generation,
            &peer_public,
        )?;
        let keys = key_exchange
            .derive_session_keys(peer_public.ephemeral, &pairing.session_id)
            .map_err(|_| Error::PeerKeyRejected)?;

        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let remote_ufrag = remote_ufrag.expect("ICE credential loop checked ufrag");
        let remote_pwd = remote_pwd.expect("ICE credential loop checked password");
        let conn: Arc<dyn IceConn + Send + Sync> = if role == Role::Client {
            tokio::time::timeout(
                PHASE_TIMEOUT,
                agent.dial(cancel_rx, remote_ufrag, remote_pwd),
            )
            .await
            .map_err(|_| Error::Timeout("ICE connectivity"))?
            .map_err(|error| Error::Ice(error.to_string()))?
        } else {
            tokio::time::timeout(
                PHASE_TIMEOUT,
                agent.accept(cancel_rx, remote_ufrag, remote_pwd),
            )
            .await
            .map_err(|_| Error::Timeout("ICE connectivity"))?
            .map_err(|error| Error::Ice(error.to_string()))?
        };
        candidate_forwarder.abort();

        let now = Instant::now();
        let (scheduler, delivery, transport_ack, policy_clock_origin) =
            new_transport_state(now, FIRST_PATH_GENERATION);
        Ok(Self {
            signal,
            path: PathRuntime::initial_active(
                PeerPathBackend::Ice(IcePath {
                    _agent: agent,
                    conn,
                }),
                now,
            ),
            cipher: CipherSession::new(keys.tx, keys.rx),
            stats: SessionStats::default(),
            scheduler,
            delivery,
            transport_ack,
            policy_clock_origin,
            path_baseline: None,
            ice_counters: PathCounters::default(),
            prefetched: None,
            last_keepalive: now,
            last_peer_activity: now,
            migration_enabled: false,
            migration: MigrationController::new(role),
            migration_config: MigrationConfig::new(pairing, role, vec![], vec![]),
            opening: None,
            draining: None,
            migration_inbox: Default::default(),
        })
    }

    /// Establish a peer session while also advertising server-reflexive
    /// candidates from the supplied STUN servers.
    ///
    /// Candidates are tried in deterministic priority order with an encrypted
    /// path probe/acknowledgement before the session is returned. This is a
    /// small authenticated direct-path nomination, not a complete ICE agent:
    /// peer-reflexive candidates, consent freshness, and TURN are still above
    /// the current scope.
    pub async fn establish_with_stun(
        server_origin: &str,
        pairing: &Pairing,
        role: Role,
        local_bind: SocketAddr,
        stun_servers: &[SocketAddr],
    ) -> Result<Self, Error> {
        let mut signal = Endpoint::connect(server_origin, pairing, role).await?;
        let mut transport = UdpTransport::bind(local_bind).await?;
        let local = transport.local_addr()?;
        let mut local_candidates = host_candidates(local);
        if std::env::var("OPENSTREAM_UPNP").as_deref() == Ok("1") {
            let lease_seconds = std::env::var("OPENSTREAM_UPNP_LEASE_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(3_600);
            match transport
                .map_upnp(Duration::from_secs(lease_seconds.max(60)))
                .await
            {
                Ok(address) => {
                    local_candidates.push(Candidate {
                        kind: CandidateKind::Mapped,
                        address,
                    });
                }
                Err(error) => {
                    eprintln!("OpenStream UPnP mapping unavailable: {error}");
                }
            }
        }
        for &server in stun_servers {
            if let Ok(address) = transport
                .server_reflexive_candidate(server, Duration::from_secs(3))
                .await
            {
                if !local_candidates
                    .iter()
                    .any(|candidate| candidate.address == address)
                {
                    local_candidates.push(Candidate {
                        kind: CandidateKind::ServerReflexive,
                        address,
                    });
                }
            }
        }
        if let Some(relay_address) = pairing.relay_address.as_deref() {
            let relay_address = relay_address.parse::<SocketAddr>()?;
            let relay_candidate = Candidate {
                kind: CandidateKind::Relay,
                address: relay_address,
            };
            if !local_candidates.contains(&relay_candidate) {
                local_candidates.push(relay_candidate);
            }
        }
        let trusted_relay = pairing
            .relay_address
            .as_deref()
            .map(str::parse::<SocketAddr>)
            .transpose()?;
        let mut direct = DirectHandshake::with_candidate_policy(Some(local), trusted_relay);
        let mut local_key_exchange = None;
        let (mut peer_candidates, _peer_public, keys) = loop {
            let message = match direct.deadline() {
                Some(deadline) => {
                    let phase = direct
                        .deadline_phase()
                        .expect("a direct phase deadline has a phase");
                    signal.recv_until(deadline, phase).await?
                }
                None => signal.recv().await?,
            };
            let outcome = direct.handle(&message, TokioInstant::now())?;
            match outcome {
                DirectMessageOutcome::Ready => {
                    let generation = direct.generation();
                    for candidate in &local_candidates {
                        signal.send(&serde_json::json!({
                            "type": "direct_candidate",
                            "establishment_generation": generation,
                            "kind": candidate.kind,
                            "ip": candidate.address.ip().to_string(),
                            "port": candidate.address.port(),
                        }))?;
                    }
                    signal.send(&serde_json::json!({
                        "type": "direct_candidate_done",
                        "establishment_generation": generation,
                        "count": local_candidates.len(),
                    }))?;
                    local_key_exchange = None;
                }
                DirectMessageOutcome::Reset => {
                    // A reset invalidates every epoch-local candidate and key.
                    // The next readiness message causes a fresh key exchange.
                    local_key_exchange = None;
                }
                DirectMessageOutcome::CandidateDone => {
                    let key_exchange = KeyExchange::generate()?;
                    let identity = local_identity()?;
                    signal.send(&encode_direct_key_message(
                        &key_exchange,
                        &identity,
                        &pairing.session_id,
                        direct.generation(),
                        role,
                    )?)?;
                    local_key_exchange = Some(key_exchange);
                }
                DirectMessageOutcome::KeyAccepted => {
                    let peer_public = direct.peer_key().copied().ok_or_else(|| {
                        Error::InvalidMessage("direct key was not retained".into())
                    })?;
                    let key_exchange = local_key_exchange.take().ok_or_else(|| {
                        Error::InvalidMessage("direct key arrived before local key".into())
                    })?;
                    authenticate_direct_peer(
                        server_origin,
                        pairing,
                        role,
                        direct.generation(),
                        &peer_public,
                    )?;
                    let keys = key_exchange
                        .derive_session_keys(peer_public.ephemeral, &pairing.session_id)
                        .map_err(|_| Error::PeerKeyRejected)?;
                    break (direct.remote_candidates().to_vec(), peer_public, keys);
                }
                DirectMessageOutcome::ReadyDuplicate
                | DirectMessageOutcome::Ignored
                | DirectMessageOutcome::IgnoredStale
                | DirectMessageOutcome::CandidateAccepted
                | DirectMessageOutcome::CandidateDuplicate
                | DirectMessageOutcome::CandidateIgnored
                | DirectMessageOutcome::CandidateDoneDuplicate
                | DirectMessageOutcome::KeyDuplicate => {}
            }
        };

        peer_candidates.sort_by_key(|candidate| {
            (
                match candidate.kind {
                    CandidateKind::Host => 0_u8,
                    CandidateKind::Mapped => 1,
                    CandidateKind::ServerReflexive => 2,
                    CandidateKind::Relay => 3,
                },
                u8::from(candidate.address.ip().is_unspecified()),
                candidate.address,
            )
        });
        if peer_candidates.is_empty() {
            return Err(Error::InvalidMessage(
                "peer sent no usable candidates".into(),
            ));
        }

        let mut cipher = CipherSession::new(keys.tx, keys.rx);
        let mut transport = transport;
        let force_relay = force_relay_requested();
        let candidate_deadline = TokioInstant::now() + PHASE_TIMEOUT;
        for candidate in peer_candidates.iter().copied() {
            if TokioInstant::now() >= candidate_deadline {
                break;
            }
            if force_relay && candidate.kind != CandidateKind::Relay {
                continue;
            }
            if transport.connect(candidate.address).await.is_err() {
                continue;
            }
            let relay_registration = if candidate.kind == CandidateKind::Relay {
                let relay_role = match role {
                    Role::Host => RelayRole::Host,
                    Role::Client => RelayRole::Client,
                };
                let Some(ticket) = pairing.relay_ticket(role) else {
                    continue;
                };
                let cleanup_guard =
                    transport.relay_registration(&pairing.session_id, relay_role, ticket)?;
                let registration_result = transport
                    .register_relay(&pairing.session_id, relay_role, ticket)
                    .await;
                // On an error the guard drops on this scope and schedules an
                // unregister for a registration whose ACK may have been lost.
                registration_result?;
                Some(cleanup_guard)
            } else {
                None
            };
            // One cipher across all candidates: counters stay monotonic per
            // direction, so delayed probes from a failed candidate can never
            // collide with or pollute the winning path's counters.
            let path = PeerPathBackend::Direct {
                transport: Box::new(transport),
                candidate: candidate.kind,
                relay_registration,
            };
            if let ProbeResult::Established(prefetched) = path.probe(&mut cipher).await {
                let now = Instant::now();
                let (scheduler, delivery, transport_ack, policy_clock_origin) =
                    new_transport_state(now, FIRST_PATH_GENERATION);
                return Ok(Self {
                    signal,
                    path: PathRuntime::initial_active(path, now),
                    cipher,
                    stats: SessionStats::default(),
                    scheduler,
                    delivery,
                    transport_ack,
                    policy_clock_origin,
                    path_baseline: None,
                    ice_counters: PathCounters::default(),
                    prefetched,
                    last_keepalive: now,
                    last_peer_activity: now,
                    migration_enabled: false,
                    migration: MigrationController::new(role),
                    migration_config: MigrationConfig::new(
                        pairing,
                        role,
                        local_candidates,
                        peer_candidates,
                    ),
                    opening: None,
                    draining: None,
                    migration_inbox: Default::default(),
                });
            }
            let PeerPathBackend::Direct {
                transport: failed_transport,
                ..
            } = path
            else {
                unreachable!("direct candidate probe uses a direct backend");
            };
            transport = *failed_transport;
        }
        Err(Error::NoReachableCandidate)
    }

    /// Send a JSON control message over the established signaling channel.
    pub fn signal_send(&self, message: &Value) -> Result<(), Error> {
        self.signal.send(message)
    }

    /// Return the selected data-path family for diagnostics and telemetry.
    ///
    /// This reports only routing metadata. It never exposes bearer tokens,
    /// TURN credentials, session keys, or peer addresses.
    pub fn connection_path(&self) -> ConnectionPath {
        match self.path.active().backend() {
            PeerPathBackend::Direct { candidate, .. } => ConnectionPath::DirectUdp {
                candidate: *candidate,
            },
            PeerPathBackend::Ice(_) => ConnectionPath::Ice,
        }
    }

    /// Return the current path generation without exposing peer routing data.
    pub fn path_generation(&self) -> PathGeneration {
        self.path.active().generation()
    }

    /// Return an address- and credential-free snapshot of the selected path.
    pub fn transport_snapshot(&mut self, now: Instant) -> PeerTransportSnapshot {
        let counters = match self.path.active().backend() {
            PeerPathBackend::Direct { transport, .. } => transport.telemetry_counters(),
            PeerPathBackend::Ice(_) => self.ice_counters.sample(self.path_generation()),
        };
        let mut snapshot = self.path.snapshot(now);
        snapshot.sample = sample_path_counters(counters, now, &mut self.path_baseline);
        snapshot
    }

    /// Return a copy of the local transport counters for diagnostics.
    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// Remove an opt-in UPnP mapping during an orderly shutdown.
    ///
    /// The mapping is best-effort and is absent for the full-ICE path. A
    /// process that is terminated without reaching this method relies on the
    /// bounded router lease to expire.
    pub async fn release_upnp(&mut self) -> Result<(), Error> {
        match self.path.active_mut().backend_mut() {
            PeerPathBackend::Direct { transport, .. } => transport.release_upnp().await?,
            PeerPathBackend::Ice(_) => {}
        }
        Ok(())
    }

    /// Stop this session and perform bounded relay cleanup for every path it
    /// still owns. The transport guards also schedule best-effort cleanup when
    /// the session is dropped without an explicit close, but callers that can
    /// await shutdown should use this method so the relay slot is released
    /// immediately rather than waiting for its idle lease.
    pub async fn close(&mut self) -> Result<(), Error> {
        self.opening = None;
        self.migration_inbox.clear();
        if let Some(prepared) = self.path.prepared.take() {
            cleanup_peer_path(prepared).await;
        }
        let active_registration = match self.path.active_mut().backend_mut() {
            PeerPathBackend::Direct {
                relay_registration, ..
            } => relay_registration.take(),
            PeerPathBackend::Ice(_) => None,
        };
        if let Some(active_registration) = active_registration {
            let _ = active_registration.unregister().await;
        }
        if let Some(draining) = self.draining.take() {
            draining.close().await;
        }
        self.path.close_all();
        let generation = self.path_generation();
        let now = Instant::now();
        self.scheduler = OutboundScheduler::new(0.0);
        self.scheduler
            .reset_generation(self.policy_now_ms(now), generation);
        self.delivery.reset_generation(generation);
        self.transport_ack.reset(generation);
        Ok(())
    }

    /// Send an authenticated liveness packet for a direct UDP path when the
    /// caller's event loop reaches the keepalive interval. Full ICE already
    /// owns consent freshness, so this is intentionally a no-op there.
    pub async fn maintain_liveness(&mut self) -> Result<(), Error> {
        self.drive_migration().await?;
        if matches!(
            self.migration.state,
            MigrationState::CommitPending | MigrationState::CommitUnconfirmed
        ) {
            return Ok(());
        }
        // Keepalives are sent on any established path -- direct or full ICE.
        // ICE's own consent freshness keeps the socket open but never surfaces
        // to the application layer, so without this a peer that stops sending
        // media (a paused or idle session) would look dead to the other side's
        // authenticated-liveness timeout even though the path is healthy.
        let path_supports_keepalive = matches!(
            self.path.active().backend(),
            PeerPathBackend::Direct { .. } | PeerPathBackend::Ice(_)
        );
        if !path_supports_keepalive || self.last_keepalive.elapsed() < KEEPALIVE_INTERVAL {
            return Ok(());
        }
        self.send_path_control(PathSlot(self.path_generation()), 0, PATH_KEEPALIVE)
            .await?;
        self.last_keepalive = std::time::Instant::now();
        Ok(())
    }

    /// Receive one JSON signaling message.
    pub async fn signal_recv(&mut self) -> Result<Value, Error> {
        self.signal.recv().await
    }

    /// Queue one clear application packet without consuming a cipher counter.
    pub fn queue(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<QueueOutcome, Error> {
        self.queue_application(kind, channel, flags, payload, false)
    }

    /// Flush all application packets that are immediately serviceable.
    ///
    /// Sealing happens only after the scheduler has admitted a packet and
    /// `DeliveryEstimator::can_record` has accepted its next outer counter.
    /// Delivery history is updated only after the socket write succeeds.
    pub async fn flush_outbound(&mut self) -> Result<FlushReport, Error> {
        Ok(self.flush_outbound_inner().await?.report)
    }

    /// Flush application output while keeping delivery-history saturation
    /// recoverable for receive-driven event loops.
    ///
    /// [`Error::OutboundHistoryFull`] is returned by the underlying flush
    /// only after the scheduler has retained the packet that could not be
    /// admitted. All other errors remain fatal and are returned unchanged.
    pub async fn flush_outbound_recoverably(&mut self) -> Result<FlushOutcome, Error> {
        match self.flush_outbound().await {
            Ok(report) => Ok(FlushOutcome::Flushed(report)),
            Err(Error::OutboundHistoryFull) => Ok(FlushOutcome::Backpressured),
            Err(error) => Err(error),
        }
    }

    /// Return the exact pacer delay before the next queued packet can run.
    pub fn next_outbound_wake(&self) -> Option<Duration> {
        let now_ms = self.policy_now_ms(Instant::now());
        let wake_ms = self.scheduler.next_wake_ms(now_ms)?;
        let wait_ms = (wake_ms - now_ms).max(0.0);
        if !wait_ms.is_finite() {
            return None;
        }
        Some(Duration::from_secs_f64(wait_ms / 1_000.0))
    }

    /// Number of clear application packets retained by the scheduler.
    pub fn outbound_pending(&self) -> usize {
        self.scheduler.pending()
    }

    /// Set the independent encrypted-wire pacing ceiling in decimal Mbps.
    pub fn set_wire_pacing_rate(&mut self, rate_mbps: f64) -> Result<(), Error> {
        if !rate_mbps.is_finite() || rate_mbps < 0.0 {
            return Err(Error::InvalidWirePacingRate);
        }
        let now_ms = self.policy_now_ms(Instant::now());
        self.scheduler.set_wire_rate_mbps(now_ms, rate_mbps);
        Ok(())
    }

    /// Return the current independent wire pacing ceiling in decimal Mbps.
    pub fn wire_pacing_rate(&self) -> f64 {
        self.scheduler.wire_rate_mbps()
    }

    /// Return authenticated delivery telemetry for the active path generation.
    pub fn transport_delivery_snapshot(&mut self, now: Instant) -> PeerDeliverySnapshot {
        self.delivery.snapshot(self.policy_now_ms(now)).into()
    }

    /// Age of the most recent authenticated packet received from the peer.
    /// This is a liveness observation only; it is not a replacement for the
    /// transport's own idle timeout or for end-to-end frame acknowledgements.
    pub fn last_peer_activity_age(&self) -> Duration {
        self.last_peer_activity.elapsed()
    }

    /// Send one encrypted application packet through the bounded scheduler.
    pub async fn send(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<usize, Error> {
        self.send_application_with_flag(kind, channel, flags, payload, false)
            .await
    }

    fn queue_application(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
        logical_retransmission: bool,
    ) -> Result<QueueOutcome, Error> {
        self.queue_application_with_id(kind, channel, flags, payload, logical_retransmission)
            .map(|(outcome, _)| outcome)
    }

    fn queue_application_with_id(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
        logical_retransmission: bool,
    ) -> Result<(QueueOutcome, u64), Error> {
        if self.path.active().state() == PathState::Closed {
            return Err(PathMigrationError::PathUnavailable.into());
        }
        self.migration.application_slot()?;
        self.scheduler
            .queue_with_id(kind, channel, flags, payload, logical_retransmission)
            .map_err(|error| queue_error(kind, error))
    }

    async fn send_application_with_flag(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
        logical_retransmission: bool,
    ) -> Result<usize, Error> {
        let (_, target_queue_id) =
            self.queue_application_with_id(kind, channel, flags, payload, logical_retransmission)?;
        loop {
            let work = self.flush_outbound_inner().await?;
            if let Some(emitted) = work
                .emitted
                .iter()
                .find(|emitted| emitted.queue_id == target_queue_id)
            {
                return Ok(emitted.wire_bytes);
            }
            if self.outbound_pending() == 0 {
                return Err(Error::OutboundHistoryFull);
            }
            if let Some(wait) = self.next_outbound_wake() {
                if wait.is_zero() {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(wait).await;
                }
            } else {
                return Err(Error::OutboundHistoryFull);
            }
        }
    }

    async fn flush_outbound_inner(&mut self) -> Result<FlushWork, Error> {
        let slot = self.migration.application_slot()?;
        let generation = self.path_generation();
        let mut work = FlushWork::default();
        loop {
            let now = Instant::now();
            let now_ms = self.policy_now_ms(now);
            let next_counter = self.cipher.next_tx_counter();
            let delivery = &self.delivery;
            let packet = self
                .scheduler
                .pop_due(now_ms, next_counter, |counter| {
                    delivery.can_record(generation, counter, now_ms)
                })
                .map_err(flush_error)?;
            let Some(packet) = packet else {
                break;
            };
            let (counter, datagram) = self
                .cipher
                .seal_with_counter(packet.kind, packet.channel, packet.flags, &packet.payload)
                .map_err(|error| Error::Transport(openstream_transport::Error::Protocol(error)))?;
            let sent = self.write_sealed_on(slot, &datagram, true).await?;
            let sent_bytes = u32::try_from(sent).unwrap_or(u32::MAX);
            let outcome = self
                .delivery
                .record_sent(SentPacket {
                    generation,
                    outer_counter: counter,
                    bytes: sent_bytes,
                    sent_at_ms: now_ms,
                    traffic_class: traffic_class(packet.kind),
                    ack_eliciting: true,
                    logical_retransmission: packet.logical_retransmission,
                })
                .map_err(delivery_error)?;
            if matches!(
                self.path.at(slot).map(|path| path.backend()),
                Some(PeerPathBackend::Ice(_))
            ) {
                self.ice_counters.record_sent(sent);
            }
            self.stats.sent_packets = self.stats.sent_packets.saturating_add(1);
            self.stats.sent_wire_bytes = self.stats.sent_wire_bytes.saturating_add(sent as u64);
            work.report.sent_packets = work.report.sent_packets.saturating_add(1);
            work.report.sent_wire_bytes = work.report.sent_wire_bytes.saturating_add(sent);
            work.report.stale_evictions = work
                .report
                .stale_evictions
                .saturating_add(u64::from(outcome.stale_evicted));
            work.report.logical_reliable_retries = work
                .report
                .logical_reliable_retries
                .saturating_add(u64::from(outcome.logical_retransmission));
            work.report.outer_retransmissions = work
                .report
                .outer_retransmissions
                .saturating_add(u64::from(outcome.outer_retransmission));
            work.emitted.push(EmittedPacket {
                queue_id: packet.queue_id,
                wire_bytes: sent,
            });
        }
        work.report.pending_packets = self.scheduler.pending();
        Ok(work)
    }

    async fn send_path_control(
        &mut self,
        slot: PathSlot,
        channel: u8,
        payload: &[u8],
    ) -> Result<usize, Error> {
        self.send_immediate_on(slot, Kind::Control, channel, 0, payload)
            .await
    }

    async fn send_transport_ack(&mut self, ack: TransportAck) -> Result<usize, Error> {
        let payload = ack
            .encode()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        self.send_immediate_on(
            PathSlot(self.path_generation()),
            Kind::Control,
            TRANSPORT_META_CHANNEL,
            0,
            &payload,
        )
        .await
    }

    async fn send_immediate_on(
        &mut self,
        slot: PathSlot,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<usize, Error> {
        let (_, datagram) = self
            .cipher
            .seal_with_counter(kind, channel, flags, payload)
            .map_err(|error| Error::Transport(openstream_transport::Error::Protocol(error)))?;
        self.write_sealed_on(slot, &datagram, false).await
    }

    async fn write_sealed_on(
        &mut self,
        slot: PathSlot,
        datagram: &[u8],
        application: bool,
    ) -> Result<usize, Error> {
        let path = self
            .path
            .at(slot)
            .ok_or(PathMigrationError::PathUnavailable)?;
        match path.backend() {
            PeerPathBackend::Direct { transport, .. } => {
                Ok(transport.send_sealed(datagram, application).await?)
            }
            PeerPathBackend::Ice(path) => path
                .conn
                .send(datagram)
                .await
                .map_err(|error| Error::Ice(error.to_string())),
        }
    }

    fn policy_now_ms(&self, now: Instant) -> f64 {
        now.saturating_duration_since(self.policy_clock_origin)
            .as_secs_f64()
            * 1_000.0
    }

    /// Receive and authenticate one encrypted data packet.
    pub async fn recv(&mut self) -> Result<Packet, Error> {
        if let Some(packet) = self.migration_inbox.pop_front() {
            return Ok(packet);
        }
        loop {
            self.drive_migration().await?;
            if self.migration.state == MigrationState::CommitUnconfirmed {
                return Err(PathMigrationError::CommitUnconfirmed.into());
            }
            if let Some(packet) = self.recv_step().await? {
                return Ok(packet);
            }
        }
    }

    pub async fn recv_step(&mut self) -> Result<Option<Packet>, Error> {
        let receive_now_ms = self.policy_now_ms(Instant::now());
        let received = if let Some(wait) = self.transport_ack.next_wake(receive_now_ms) {
            if wait.is_zero() {
                self.send_due_transport_ack().await?;
                return Ok(None);
            }
            match tokio::time::timeout(wait, self.recv_ingress()).await {
                Ok(received) => received?,
                Err(_) => {
                    self.send_due_transport_ack().await?;
                    return Ok(None);
                }
            }
        } else {
            self.recv_ingress().await?
        };
        let Some(ReceivedPacket {
            packet,
            ingress,
            wire_bytes,
        }) = received
        else {
            self.send_due_transport_ack().await?;
            return Ok(None);
        };
        let now = Instant::now();
        let now_ms = self.policy_now_ms(now);
        if packet.kind == Kind::Control && packet.channel == TRANSPORT_META_CHANNEL {
            if packet.flags != 0 {
                return Err(Error::InvalidMessage(
                    "transport metadata packet has non-zero flags".into(),
                ));
            }
            let ack = TransportAck::decode(&packet.payload)
                .map_err(|error| Error::InvalidMessage(error.to_string()))?;
            if ingress == PathSlot(self.path_generation()) {
                self.delivery
                    .acknowledge(
                        ack.generation,
                        ack.largest_counter,
                        ack.received_mask,
                        ack.ack_delay_us,
                        now_ms,
                    )
                    .map_err(delivery_error)?;
            }
            return Ok(None);
        }
        if is_path_probe_packet(&packet) {
            return Ok(None);
        }
        if self.migration_enabled
            && packet.kind == Kind::Control
            && packet.channel == PATH_CONTROL_CHANNEL
        {
            if packet.flags == 0 {
                if let Ok(record) = PathControl::decode(&packet.payload) {
                    let actions = self.migration.receive(ingress, record, now);
                    self.apply_migration_actions(actions).await?;
                }
            }
            return Ok(None);
        }
        if !self.migration.accepts_application(ingress, now) {
            return Ok(None);
        }
        if let Some(bytes) = wire_bytes {
            if let Some(path) = self.path.at(ingress) {
                match path.backend() {
                    PeerPathBackend::Direct { transport, .. } => transport.record_received(bytes),
                    PeerPathBackend::Ice(_) => self.ice_counters.record_received(bytes),
                }
            }
        }
        if packet.kind == Kind::Control && packet.payload == PATH_KEEPALIVE {
            // A draining socket is receive-only; reply on the selected path.
            if self.migration.application_slot().is_ok() {
                self.send_path_control(PathSlot(self.path_generation()), 0, PATH_KEEPALIVE_ACK)
                    .await?;
            }
            return Ok(None);
        }
        if packet.kind == Kind::Control && packet.payload == PATH_KEEPALIVE_ACK {
            return Ok(None);
        }
        if ingress == PathSlot(self.path_generation()) && is_ack_eliciting_application(&packet) {
            self.transport_ack.observe(packet.counter, now_ms);
            if let Some(ack) = self.transport_ack.take(now_ms, self.path_generation()) {
                self.send_transport_ack(ack).await?;
            }
        }
        self.stats.received_packets = self.stats.received_packets.saturating_add(1);
        self.stats.received_payload_bytes = self
            .stats
            .received_payload_bytes
            .saturating_add(packet.payload.len() as u64);
        Ok(Some(packet))
    }

    async fn send_due_transport_ack(&mut self) -> Result<(), Error> {
        let now_ms = self.policy_now_ms(Instant::now());
        if let Some(ack) = self.transport_ack.take(now_ms, self.path_generation()) {
            self.send_transport_ack(ack).await?;
        }
        Ok(())
    }

    async fn recv_ingress(&mut self) -> Result<Option<ReceivedPacket>, Error> {
        if let Some(packet) = self.prefetched.take() {
            return Ok(Some(ReceivedPacket {
                packet,
                ingress: PathSlot(self.path_generation()),
                wire_bytes: None,
            }));
        }
        let mut active_bytes = [0; MAX_DATAGRAM];
        let mut prepared_bytes = [0; MAX_DATAGRAM];
        let active_slot = PathSlot(self.path_generation());
        let active = self.path.active().backend();
        let active_is_ice = matches!(active, PeerPathBackend::Ice(_));
        let prepared = self.path.prepared.as_ref().filter(|_| {
            self.opening
                .as_ref()
                .is_some_and(|opening| opening.connected)
        });
        let migration_busy = self.migration.busy();
        let event = tokio::select! {
            result = receive_backend(active, &mut active_bytes) => match result {
                Ok(length) => Some((active_slot, active_bytes[..length].to_vec())),
                Err(error) => {
                    if self.migration.state == MigrationState::CommitPending {
                        self.migration.old_path_failed();
                        None
                    } else { return Err(error); }
                }
            },
            result = async {
                if let Some(path) = prepared { receive_backend(path.backend(), &mut prepared_bytes).await.map(|length| (PathSlot(path.generation()), length)) }
                else { std::future::pending().await }
            } => match result {
                Ok((slot, length)) => Some((slot, prepared_bytes[..length].to_vec())),
                Err(_) => None,
            },
            received = async {
                if let Some(draining) = &mut self.draining { draining.incoming.recv().await }
                else { std::future::pending().await }
            } => received,
            message = self.signal.recv(), if self.migration_enabled && self.opening.as_ref().is_some_and(|opening| opening.target == MigrationTarget::DirectUdp) => {
                self.receive_path_candidate(message?)?;
                None
            },
            _ = tokio::time::sleep(COMMIT_RETRY), if migration_busy => None,
        };
        let Some((ingress, bytes)) = event else {
            return Ok(None);
        };
        let packet = match self.cipher.open(&bytes) {
            Ok(packet) => packet,
            // The multiplexer must survive delayed/replayed probes and relay
            // registration ACKs without tearing down a migration.
            Err(_) if self.migration_enabled => return Ok(None),
            Err(error) => {
                return Err(if active_is_ice {
                    Error::InvalidMessage(error.to_string())
                } else {
                    Error::Transport(openstream_transport::Error::Protocol(error))
                });
            }
        };
        self.last_peer_activity = Instant::now();
        Ok(Some(ReceivedPacket {
            packet,
            ingress,
            wire_bytes: Some(bytes.len()),
        }))
    }

    /// Run the encrypted host-side capability exchange.
    pub async fn negotiate_host(&mut self) -> Result<NegotiatedCapabilities, Error> {
        self.negotiate_host_with_capabilities(Capabilities::host_default())
            .await
    }

    /// Run the host exchange with an explicitly selected capability profile.
    pub async fn negotiate_host_with_capabilities(
        &mut self,
        host: Capabilities,
    ) -> Result<NegotiatedCapabilities, Error> {
        let hello =
            encode_hello(host.clone()).map_err(|error| Error::InvalidMessage(error.to_string()))?;
        let mut reliable = ReliableControl::new(MAX_CONTROL_PENDING);
        reliable.send(self, &hello).await?;
        let deadline = TokioInstant::now() + PHASE_TIMEOUT;
        let mut next_retry = TokioInstant::now() + CAPABILITY_RETRY_INTERVAL;
        loop {
            let deliveries = self
                .receive_reliable_packet(
                    &mut reliable,
                    deadline,
                    &mut next_retry,
                    "host capability acknowledgement",
                )
                .await?;
            let Some(payload) = deliveries.into_iter().next() else {
                continue;
            };
            let message = decode_capability_message(&payload)
                .map_err(|error| Error::InvalidMessage(error.to_string()))?;
            let CapabilityMessage::HelloAck { capabilities } = message else {
                return Err(Error::InvalidMessage(
                    "host expected a capability acknowledgement".into(),
                ));
            };
            let negotiated = negotiate(&host, &capabilities)
                .map_err(|error| Error::InvalidMessage(error.to_string()))?;
            self.migration_enabled = negotiated.path_migration;
            return Ok(negotiated);
        }
    }

    /// Run the encrypted client-side capability exchange.
    pub async fn negotiate_client(&mut self) -> Result<NegotiatedCapabilities, Error> {
        self.negotiate_client_with_capabilities(Capabilities::client_default())
            .await
    }

    /// Run the client exchange with an explicitly selected capability profile.
    pub async fn negotiate_client_with_capabilities(
        &mut self,
        client: Capabilities,
    ) -> Result<NegotiatedCapabilities, Error> {
        let mut reliable = ReliableControl::new(MAX_CONTROL_PENDING);
        let deadline = TokioInstant::now() + PHASE_TIMEOUT;
        let mut next_retry = TokioInstant::now() + CAPABILITY_RETRY_INTERVAL;
        let host = loop {
            let deliveries = self
                .receive_reliable_packet(
                    &mut reliable,
                    deadline,
                    &mut next_retry,
                    "client capability hello",
                )
                .await?;
            let mut host = None;
            for payload in deliveries {
                let message = decode_capability_message(&payload)
                    .map_err(|error| Error::InvalidMessage(error.to_string()))?;
                let CapabilityMessage::Hello {
                    role: CapabilityRole::Host,
                    capabilities,
                } = message
                else {
                    return Err(Error::InvalidMessage(
                        "client expected a host capability hello".into(),
                    ));
                };
                host = Some(capabilities);
            }
            if let Some(host) = host {
                break host;
            }
        };
        let ack = encode_hello_ack(client.clone())
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        reliable.send(self, &ack).await?;
        // The host acknowledges the client's HelloAck. Waiting for that
        // acknowledgement prevents the client from returning to its media
        // loop after a one-way packet loss and gives the host a chance to
        // finish the same ordered handshake.
        while reliable.outstanding() != 0 {
            let _ = self
                .receive_reliable_packet(
                    &mut reliable,
                    deadline,
                    &mut next_retry,
                    "client capability acknowledgement",
                )
                .await?;
        }
        let negotiated =
            negotiate(&host, &client).map_err(|error| Error::InvalidMessage(error.to_string()))?;
        self.migration_enabled = negotiated.path_migration;
        Ok(negotiated)
    }

    /// Receive one valid reliable-control frame during establishment. Raw
    /// control packets are ignored so path probes or legacy close markers do
    /// not get mistaken for capability messages. A retry is driven whenever
    /// the bounded interval elapses, and the overall phase remains finite.
    async fn receive_reliable_packet(
        &mut self,
        reliable: &mut ReliableControl,
        deadline: TokioInstant,
        next_retry: &mut TokioInstant,
        phase: &'static str,
    ) -> Result<Vec<Vec<u8>>, Error> {
        loop {
            let now = TokioInstant::now();
            if now >= deadline {
                return Err(Error::Timeout(phase));
            }
            let remaining = deadline.saturating_duration_since(now);
            let until_retry = next_retry.saturating_duration_since(now);
            let wait = remaining.min(until_retry.max(Duration::from_millis(1)));
            match tokio::time::timeout(wait, self.recv()).await {
                Ok(Ok(packet)) => {
                    if let Some(deliveries) = reliable.receive(self, &packet).await? {
                        return Ok(deliveries);
                    }
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    reliable.retry(self).await?;
                    *next_retry = TokioInstant::now() + CAPABILITY_RETRY_INTERVAL;
                }
            }
        }
    }
}

const PATH_PROBE: &[u8] = b"openstream/path-probe/v1";
const PATH_PROBE_ACK: &[u8] = b"openstream/path-probe-ack/v1";
const PATH_KEEPALIVE: &[u8] = b"openstream/path-keepalive/v1";
const PATH_KEEPALIVE_ACK: &[u8] = b"openstream/path-keepalive-ack/v1";
const DIRECT_KEY_TRANSCRIPT_DOMAIN: &[u8] = b"OpenStream direct key v2";
const ICE_KEY_TRANSCRIPT_DOMAIN: &[u8] = b"OpenStream ICE key v2";
const MAX_DIRECT_RESET_REASON_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectPhase {
    WaitingForPeer,
    Candidates,
    KeyExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMessageOutcome {
    Ignored,
    IgnoredStale,
    Ready,
    ReadyDuplicate,
    Reset,
    CandidateAccepted,
    CandidateDuplicate,
    CandidateIgnored,
    CandidateDone,
    CandidateDoneDuplicate,
    KeyAccepted,
    KeyDuplicate,
}

/// State for one server-authoritative direct-establishment epoch.
///
/// The state is deliberately independent from UDP path generations and from
/// `CipherSession`. It exists only until the authenticated direct path is
/// returned, and it can be reset without reusing any candidate or key state.
#[derive(Debug)]
struct DirectHandshake {
    generation: u64,
    phase: DirectPhase,
    deadline: Option<TokioInstant>,
    local: Option<SocketAddr>,
    trusted_relay: Option<SocketAddr>,
    remote_candidates: Vec<Candidate>,
    remote_candidate_count: Option<usize>,
    peer_key: Option<PeerKey>,
}

impl DirectHandshake {
    #[cfg(test)]
    fn new(_role: Role) -> Self {
        Self::with_candidate_policy(None, None)
    }

    fn with_candidate_policy(local: Option<SocketAddr>, trusted_relay: Option<SocketAddr>) -> Self {
        Self {
            generation: 0,
            phase: DirectPhase::WaitingForPeer,
            deadline: None,
            local,
            trusted_relay,
            remote_candidates: Vec::new(),
            remote_candidate_count: None,
            peer_key: None,
        }
    }

    #[cfg(test)]
    fn phase(&self) -> DirectPhase {
        self.phase
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn deadline(&self) -> Option<TokioInstant> {
        self.deadline
    }

    fn deadline_phase(&self) -> Option<&'static str> {
        match self.phase {
            DirectPhase::WaitingForPeer => None,
            DirectPhase::Candidates => Some("candidate exchange"),
            DirectPhase::KeyExchange => Some("key exchange"),
        }
    }

    #[cfg(test)]
    fn check_deadline(&self, now: TokioInstant) -> Option<&'static str> {
        self.deadline
            .filter(|deadline| now >= *deadline)
            .and(self.deadline_phase())
    }

    fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    fn peer_key(&self) -> Option<&PeerKey> {
        self.peer_key.as_ref()
    }

    fn handle(
        &mut self,
        message: &Value,
        now: TokioInstant,
    ) -> Result<DirectMessageOutcome, Error> {
        match message.get("type").and_then(Value::as_str) {
            Some("peer_ready") => self.handle_ready(message, now),
            Some("peer_reset") => self.handle_reset(message),
            Some("direct_candidate") => self.handle_candidate(message),
            Some("direct_candidate_done") => self.handle_candidate_done(message, now),
            Some("direct_key") => self.handle_key(message),
            // These records belong to the independent ICE choreography or to
            // server-side relay setup. Never reinterpret them as direct v2.
            Some(
                "relay_ticket_proof" | "ice_credentials" | "ice_candidate" | "ice_candidate_done"
                | "key",
            )
            | None => Ok(DirectMessageOutcome::Ignored),
            Some(_) => Ok(DirectMessageOutcome::Ignored),
        }
    }

    fn handle_ready(
        &mut self,
        message: &Value,
        now: TokioInstant,
    ) -> Result<DirectMessageOutcome, Error> {
        let generation = direct_message_generation(message, "peer_ready")?;
        if generation < self.generation {
            return Ok(DirectMessageOutcome::IgnoredStale);
        }
        if self.phase != DirectPhase::WaitingForPeer {
            if generation == self.generation {
                return Ok(DirectMessageOutcome::ReadyDuplicate);
            }
            return Err(Error::InvalidMessage(
                "peer_ready generation is future".into(),
            ));
        }
        if self.generation != 0 {
            let expected = self.generation.checked_add(1).ok_or_else(|| {
                Error::InvalidMessage("peer_ready generation cannot advance".into())
            })?;
            if generation != expected {
                return Err(Error::InvalidMessage(
                    if generation > expected {
                        "peer_ready generation is future"
                    } else {
                        "peer_ready generation is not the next epoch"
                    }
                    .into(),
                ));
            }
        }
        self.generation = generation;
        self.clear_epoch_state();
        self.phase = DirectPhase::Candidates;
        self.deadline = Some(now + PHASE_TIMEOUT);
        Ok(DirectMessageOutcome::Ready)
    }

    fn handle_reset(&mut self, message: &Value) -> Result<DirectMessageOutcome, Error> {
        let generation = direct_message_generation(message, "peer_reset")?;
        if generation < self.generation {
            return Ok(DirectMessageOutcome::IgnoredStale);
        }
        let reason = message
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidMessage("peer_reset.reason is missing".into()))?;
        if reason.is_empty()
            || reason.len() > MAX_DIRECT_RESET_REASON_BYTES
            || reason
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(Error::InvalidMessage("peer_reset.reason is invalid".into()));
        }
        self.generation = self.generation.max(generation);
        self.clear_epoch_state();
        self.phase = DirectPhase::WaitingForPeer;
        Ok(DirectMessageOutcome::Reset)
    }

    fn check_direct_generation(&self, message: &Value, message_type: &str) -> Result<u64, Error> {
        let generation = direct_message_generation(message, message_type)?;
        if generation < self.generation {
            return Ok(generation);
        }
        if self.phase == DirectPhase::WaitingForPeer {
            return Err(Error::InvalidMessage(format!(
                "{message_type} received before peer_ready"
            )));
        }
        if generation > self.generation {
            return Err(Error::InvalidMessage(format!(
                "{message_type} generation is future"
            )));
        }
        Ok(generation)
    }

    fn handle_candidate(&mut self, message: &Value) -> Result<DirectMessageOutcome, Error> {
        let generation = self.check_direct_generation(message, "direct_candidate")?;
        if generation < self.generation {
            return Ok(DirectMessageOutcome::IgnoredStale);
        }
        if self.phase != DirectPhase::Candidates {
            return Err(Error::InvalidMessage(
                "direct_candidate received after candidate_done".into(),
            ));
        }
        let candidate = decode_direct_candidate(message)?;
        if let Some(local) = self.local {
            let usable = candidate.address != local
                && (valid_peer_candidate(candidate.address, local)
                    || trusted_relay_candidate(candidate, self.trusted_relay));
            if !usable {
                return Ok(DirectMessageOutcome::CandidateIgnored);
            }
        }
        if self.remote_candidates.contains(&candidate) {
            return Ok(DirectMessageOutcome::CandidateDuplicate);
        }
        if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
            return Err(Error::TooManyCandidates);
        }
        self.remote_candidates.push(candidate);
        Ok(DirectMessageOutcome::CandidateAccepted)
    }

    fn handle_candidate_done(
        &mut self,
        message: &Value,
        now: TokioInstant,
    ) -> Result<DirectMessageOutcome, Error> {
        let generation = self.check_direct_generation(message, "direct_candidate_done")?;
        if generation < self.generation {
            return Ok(DirectMessageOutcome::IgnoredStale);
        }
        if self.phase == DirectPhase::KeyExchange {
            let count = direct_candidate_count(message)?;
            return if self.remote_candidate_count == Some(count) {
                Ok(DirectMessageOutcome::CandidateDoneDuplicate)
            } else {
                Err(Error::InvalidMessage(
                    "conflicting direct_candidate_done".into(),
                ))
            };
        }
        if self.phase != DirectPhase::Candidates {
            return Err(Error::InvalidMessage(
                "direct_candidate_done received out of order".into(),
            ));
        }
        let count = direct_candidate_count(message)?;
        self.remote_candidate_count = Some(count);
        self.phase = DirectPhase::KeyExchange;
        self.deadline = Some(now + PHASE_TIMEOUT);
        Ok(DirectMessageOutcome::CandidateDone)
    }

    fn handle_key(&mut self, message: &Value) -> Result<DirectMessageOutcome, Error> {
        let generation = self.check_direct_generation(message, "direct_key")?;
        if generation < self.generation {
            return Ok(DirectMessageOutcome::IgnoredStale);
        }
        if self.phase != DirectPhase::KeyExchange {
            return Err(Error::InvalidMessage(
                "direct_key received before candidate_done".into(),
            ));
        }
        let key = decode_direct_peer_key(message, self.generation)?;
        if let Some(existing) = self.peer_key {
            return if existing == key {
                Ok(DirectMessageOutcome::KeyDuplicate)
            } else {
                Err(Error::InvalidMessage("conflicting direct_key".into()))
            };
        }
        self.peer_key = Some(key);
        Ok(DirectMessageOutcome::KeyAccepted)
    }

    fn clear_epoch_state(&mut self) {
        self.remote_candidates.clear();
        self.remote_candidate_count = None;
        self.peer_key = None;
        self.deadline = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerKey {
    ephemeral: [u8; 32],
    identity: [u8; 32],
    signature: [u8; 64],
}

fn direct_message_generation(message: &Value, message_type: &str) -> Result<u64, Error> {
    establishment_message_generation(message, message_type)
}

fn establishment_message_generation(message: &Value, message_type: &str) -> Result<u64, Error> {
    if message.get("type").and_then(Value::as_str) != Some(message_type) {
        return Err(Error::InvalidMessage(format!(
            "expected {message_type} message"
        )));
    }
    let generation = message
        .get("establishment_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Error::InvalidMessage(format!(
                "{message_type}.establishment_generation is missing"
            ))
        })?;
    if generation == 0 {
        return Err(Error::InvalidMessage(format!(
            "{message_type}.establishment_generation must be positive"
        )));
    }
    Ok(generation)
}

async fn wait_for_ice_ready(signal: &mut Endpoint) -> Result<u64, Error> {
    loop {
        let message = signal.recv().await?;
        match message.get("type").and_then(Value::as_str) {
            Some("ice_peer_ready") => {
                return establishment_message_generation(&message, "ice_peer_ready");
            }
            Some("ice_peer_reset") => {
                // A reset before readiness only describes an epoch that is no
                // longer current. Keep waiting for the next exact pair rather
                // than starting a phase timer or accepting stale records.
                continue;
            }
            Some("error") => {
                return Err(Error::InvalidMessage(
                    "signaling server rejected ICE establishment".into(),
                ));
            }
            // Relay proof and unrelated control envelopes may arrive before
            // readiness. They are not part of the ICE transcript.
            _ => continue,
        }
    }
}

fn handle_ice_generation(
    message: &Value,
    message_type: &str,
    expected: u64,
) -> Result<bool, Error> {
    let generation = establishment_message_generation(message, message_type)?;
    if generation < expected {
        return Ok(false);
    }
    if generation > expected {
        return Err(Error::InvalidMessage(format!(
            "{message_type} generation is future"
        )));
    }
    Ok(true)
}

fn decode_direct_candidate(message: &Value) -> Result<Candidate, Error> {
    let object = message
        .as_object()
        .ok_or_else(|| Error::InvalidMessage("direct_candidate must be an object".into()))?;
    if object.len() != 5 {
        return Err(Error::InvalidMessage(
            "direct_candidate has unexpected fields".into(),
        ));
    }
    let kind = serde_json::from_value(
        object
            .get("kind")
            .cloned()
            .ok_or_else(|| Error::InvalidMessage("direct_candidate.kind is missing".into()))?,
    )
    .map_err(|error| Error::InvalidMessage(format!("direct_candidate.kind is invalid: {error}")))?;
    let ip = object
        .get("ip")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidMessage("direct_candidate.ip is missing".into()))?
        .parse::<IpAddr>()?;
    let port = object
        .get("port")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::InvalidMessage("direct_candidate.port is missing".into()))?;
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| Error::InvalidMessage("direct_candidate.port is invalid".into()))?;
    Ok(Candidate {
        kind,
        address: SocketAddr::new(ip, port),
    })
}

fn direct_candidate_count(message: &Value) -> Result<usize, Error> {
    let object = message
        .as_object()
        .ok_or_else(|| Error::InvalidMessage("direct_candidate_done must be an object".into()))?;
    if object.len() != 3 {
        return Err(Error::InvalidMessage(
            "direct_candidate_done has unexpected fields".into(),
        ));
    }
    let count = object
        .get("count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| Error::InvalidMessage("direct_candidate_done.count is invalid".into()))?;
    if !(1..=MAX_REMOTE_CANDIDATES).contains(&count) {
        return Err(Error::InvalidMessage(
            "direct_candidate_done.count is outside the supported range".into(),
        ));
    }
    Ok(count)
}

fn key_transcript(
    domain: &[u8],
    session_id: &str,
    generation: u64,
    role: Role,
    ephemeral: [u8; 32],
) -> Result<Vec<u8>, Error> {
    if generation == 0 {
        return Err(Error::InvalidMessage(
            "establishment key generation must be positive".into(),
        ));
    }
    let session_length = u32::try_from(session_id.len()).map_err(|_| {
        Error::InvalidMessage("session_id is too long for establishment key transcript".into())
    })?;
    let mut transcript = Vec::with_capacity(domain.len() + 4 + session_id.len() + 8 + 1 + 32);
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&session_length.to_be_bytes());
    transcript.extend_from_slice(session_id.as_bytes());
    transcript.extend_from_slice(&generation.to_be_bytes());
    transcript.push(identity_role(role));
    transcript.extend_from_slice(&ephemeral);
    Ok(transcript)
}

fn direct_key_transcript(
    session_id: &str,
    generation: u64,
    role: Role,
    ephemeral: [u8; 32],
) -> Result<Vec<u8>, Error> {
    key_transcript(
        DIRECT_KEY_TRANSCRIPT_DOMAIN,
        session_id,
        generation,
        role,
        ephemeral,
    )
}

fn ice_key_transcript(
    session_id: &str,
    generation: u64,
    role: Role,
    ephemeral: [u8; 32],
) -> Result<Vec<u8>, Error> {
    key_transcript(
        ICE_KEY_TRANSCRIPT_DOMAIN,
        session_id,
        generation,
        role,
        ephemeral,
    )
}

fn encode_direct_key_message(
    key_exchange: &KeyExchange,
    identity: &IdentityKey,
    session_id: &str,
    generation: u64,
    role: Role,
) -> Result<Value, Error> {
    let ephemeral = key_exchange.public_key();
    let transcript = direct_key_transcript(session_id, generation, role, ephemeral)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(identity.pkcs8())
        .map_err(|_| Error::Identity(IdentityError::InvalidKeyMaterial))?;
    let signature = key_pair.sign(&transcript);
    let signature = <[u8; 64]>::try_from(signature.as_ref())
        .map_err(|_| Error::Identity(IdentityError::SigningFailed))?;
    Ok(serde_json::json!({
        "type": "direct_key",
        "establishment_generation": generation,
        "public_key": hex::encode(ephemeral),
        "identity_public_key": hex::encode(identity.public_key()),
        "signature": hex::encode(signature),
    }))
}

fn encode_ice_key_message(
    key_exchange: &KeyExchange,
    identity: &IdentityKey,
    session_id: &str,
    generation: u64,
    role: Role,
) -> Result<Value, Error> {
    let ephemeral = key_exchange.public_key();
    let transcript = ice_key_transcript(session_id, generation, role, ephemeral)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(identity.pkcs8())
        .map_err(|_| Error::Identity(IdentityError::InvalidKeyMaterial))?;
    let signature = key_pair.sign(&transcript);
    let signature = <[u8; 64]>::try_from(signature.as_ref())
        .map_err(|_| Error::Identity(IdentityError::SigningFailed))?;
    Ok(serde_json::json!({
        "type": "ice_key_v2",
        "establishment_generation": generation,
        "public_key": hex::encode(ephemeral),
        "identity_public_key": hex::encode(identity.public_key()),
        "signature": hex::encode(signature),
    }))
}

fn decode_direct_peer_key(message: &Value, generation: u64) -> Result<PeerKey, Error> {
    let object = message
        .as_object()
        .ok_or_else(|| Error::InvalidMessage("direct_key must be an object".into()))?;
    if object.len() != 5 {
        return Err(Error::InvalidMessage(
            "direct_key has unexpected fields".into(),
        ));
    }
    let message_generation = direct_message_generation(message, "direct_key")?;
    if message_generation != generation {
        return Err(Error::InvalidMessage(
            "direct_key generation does not match the active epoch".into(),
        ));
    }
    let ephemeral = fixed_hex::<32>(
        object
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidMessage("direct_key.public_key is missing".into()))?,
        "direct_key.public_key",
    )?;
    if ephemeral == [0; 32] {
        return Err(Error::PeerKeyRejected);
    }
    let identity = fixed_hex::<32>(
        object
            .get("identity_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::InvalidMessage("direct_key.identity_public_key is missing".into())
            })?,
        "direct_key.identity_public_key",
    )?;
    let signature = fixed_hex::<64>(
        object
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidMessage("direct_key.signature is missing".into()))?,
        "direct_key.signature",
    )?;
    Ok(PeerKey {
        ephemeral,
        identity,
        signature,
    })
}

fn decode_ice_peer_key(message: &Value, generation: u64) -> Result<PeerKey, Error> {
    let object = message
        .as_object()
        .ok_or_else(|| Error::InvalidMessage("ice_key_v2 must be an object".into()))?;
    if object.len() != 5 {
        return Err(Error::InvalidMessage(
            "ice_key_v2 has unexpected fields".into(),
        ));
    }
    let message_generation = establishment_message_generation(message, "ice_key_v2")?;
    if message_generation != generation {
        return Err(Error::InvalidMessage(
            "ice_key_v2 generation does not match the active epoch".into(),
        ));
    }
    let ephemeral = fixed_hex::<32>(
        object
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidMessage("ice_key_v2.public_key is missing".into()))?,
        "ice_key_v2.public_key",
    )?;
    if ephemeral == [0; 32] {
        return Err(Error::PeerKeyRejected);
    }
    let identity = fixed_hex::<32>(
        object
            .get("identity_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::InvalidMessage("ice_key_v2.identity_public_key is missing".into())
            })?,
        "ice_key_v2.identity_public_key",
    )?;
    let signature = fixed_hex::<64>(
        object
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidMessage("ice_key_v2.signature is missing".into()))?,
        "ice_key_v2.signature",
    )?;
    Ok(PeerKey {
        ephemeral,
        identity,
        signature,
    })
}

fn verify_direct_key_signature(
    peer: &PeerKey,
    session_id: &str,
    generation: u64,
    sender_role: Role,
) -> bool {
    let Ok(transcript) = direct_key_transcript(session_id, generation, sender_role, peer.ephemeral)
    else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, peer.identity)
        .verify(&transcript, &peer.signature)
        .is_ok()
}

fn verify_ice_key_signature(
    peer: &PeerKey,
    session_id: &str,
    generation: u64,
    sender_role: Role,
) -> bool {
    let Ok(transcript) = ice_key_transcript(session_id, generation, sender_role, peer.ephemeral)
    else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, peer.identity)
        .verify(&transcript, &peer.signature)
        .is_ok()
}

fn fixed_hex<const N: usize>(encoded: &str, field: &str) -> Result<[u8; N], Error> {
    let bytes = hex::decode(encoded).map_err(Error::Hex)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| Error::InvalidMessage(format!("{field} must contain {N} bytes")))
}

fn required_ice_credential(
    message: &Value,
    field: &str,
    max_bytes: usize,
) -> Result<String, Error> {
    let value = message
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidMessage(format!("ice_credentials.{field} is missing")))?;
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(Error::InvalidMessage(format!(
            "ice_credentials.{field} has an invalid length or character"
        )));
    }
    Ok(value.to_string())
}

fn identity_role(role: Role) -> u8 {
    match role {
        Role::Host => 1,
        Role::Client => 2,
    }
}

fn opposite_role(role: Role) -> Role {
    match role {
        Role::Host => Role::Client,
        Role::Client => Role::Host,
    }
}

fn local_identity() -> Result<IdentityKey, Error> {
    if let Ok(encoded) = std::env::var("OPENSTREAM_IDENTITY_KEY") {
        if std::env::var("OPENSTREAM_DEVELOPER_OVERRIDE").as_deref() != Ok("1") {
            return Err(Error::InvalidMessage(
                "raw identity keys require OPENSTREAM_DEVELOPER_OVERRIDE=1".into(),
            ));
        }
        return identity_from_bytes(hex::decode(encoded.trim()).map_err(Error::Hex)?);
    }

    if let Ok(path) = std::env::var("OPENSTREAM_IDENTITY_KEY_FILE") {
        return load_identity_file(Path::new(&path));
    }

    let path = identity_store_path()?;
    load_or_create_identity(&path)
}

/// Return the stable public half of this process's device identity.
///
/// Product/control-plane code uses this for enrollment and trust display. The
/// private PKCS#8 material remains inside the identity loader and is never
/// serialized into a UI snapshot or sent to the control plane.
pub fn local_identity_public_key() -> Result<[u8; 32], Error> {
    Ok(local_identity()?.public_key())
}

/// Return a stable display-safe identifier derived from the public identity.
/// It is not a credential and is only used to correlate this installation
/// across control-plane restarts.
pub fn local_device_id() -> Result<String, Error> {
    let public_key = local_identity_public_key()?;
    Ok(hex::encode(&sha2::Sha256::digest(public_key)[..16]))
}

/// Resolve the durable device identity location. Production callers use this
/// path automatically; an explicit path remains useful for a service broker or
/// a test fixture but is held to the same absolute/private-file checks.
fn identity_store_path() -> Result<std::path::PathBuf, Error> {
    if let Some(path) = std::env::var_os("OPENSTREAM_IDENTITY_STORE") {
        let path = std::path::PathBuf::from(path);
        if !path.is_absolute() {
            return Err(Error::InvalidMessage(
                "OPENSTREAM_IDENTITY_STORE must be absolute".into(),
            ));
        }
        return Ok(path);
    }

    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| Error::InvalidMessage("home directory is unavailable".into()))?
        .join("Library")
        .join("Application Support")
        .join("OpenStream");
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| Error::InvalidMessage("application data directory is unavailable".into()))?
        .join("OpenStream");
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .map(|home| home.join(".local").join("state"))
        })
        .ok_or_else(|| Error::InvalidMessage("state directory is unavailable".into()))?
        .join("openstream");

    Ok(base.join("device-identity.pk8"))
}

/// Account name for this identity in the platform keystore.
///
/// Derived from the store path so two stores on one machine -- a test fixture
/// beside a real install -- cannot collide on one keystore entry.
fn keystore_account(path: &Path) -> String {
    let digest = sha2::Sha256::digest(path.as_os_str().as_encoded_bytes());
    format!("device-identity-{}", hex::encode(&digest[..8]))
}

/// Whether the operator asked for the identity to live in the platform
/// keystore. Off by default: losing a device identity is a worse failure than
/// not having hardware-backed custody, so this earns its place before it
/// becomes the default.
fn keystore_custody_requested() -> bool {
    matches!(
        std::env::var("OPENSTREAM_IDENTITY_CUSTODY")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "keystore" | "keychain"
    )
}

/// Resolve the identity through the platform keystore, falling back to the
/// file on anything that does not work.
///
/// The file is never deleted here. A keystore entry that turns out to be
/// unreadable on the next boot must not mean the identity is gone, so
/// migrating copies the key in and leaves the original where it was. The line
/// printed on migration says that removing the file is what completes it --
/// that is the operator's call, because it is the irreversible half.
/// Marker recording that this store's identity was placed in the keystore.
///
/// It holds the account name and no key material. Its only job is to tell
/// "this machine has never had an identity here" apart from "it has one in a
/// keystore I cannot read right now", which are indistinguishable otherwise
/// and call for opposite responses: mint a new identity, or refuse to.
fn keystore_marker_path(path: &Path) -> std::path::PathBuf {
    let mut marker = path.as_os_str().to_owned();
    marker.push(".keystore");
    std::path::PathBuf::from(marker)
}

/// Publish the marker atomically and privately.
///
/// Written to a temporary file and renamed, so a crash mid-write leaves
/// either the old marker or none -- never a truncated one that would be
/// mistaken for recorded custody.
///
/// **Returns an error rather than reporting one.** A keystore-only identity
/// is only protected from silent replacement by a durable marker, so a caller
/// holding one must refuse to hand it out when this fails. Treating the
/// failure as advisory is what reintroduces the defect the marker exists to
/// prevent: the next keystore outage finds no marker and mints a new device.
fn publish_keystore_marker(path: &Path, account: &str) -> Result<(), String> {
    let marker = keystore_marker_path(path);
    let Some(parent) = marker.parent() else {
        return Err("the identity store has no parent directory".into());
    };
    // Nothing else creates this directory on the keystore-only path: the file
    // loader that normally makes it is never reached when the key goes
    // straight to the keystore. Without this the marker cannot be written, no
    // custody is recorded, and a lost keystore silently mints a new identity.
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let staging = parent.join(format!(".{}.keystore.new", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&staging).and_then(|mut file| {
        use std::io::Write;
        file.write_all(account.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
    });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&staging);
        return Err(format!("could not write {}: {error}", staging.display()));
    }
    if let Err(error) = std::fs::rename(&staging, &marker) {
        let _ = std::fs::remove_file(&staging);
        return Err(format!("could not publish {}: {error}", marker.display()));
    }
    // The rename is only durable once the directory entry is, which matters
    // here: a marker lost to a crash is a marker that cannot refuse later.
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Store the key and read it back before believing the keystore took it.
///
/// A store that reports success but yields nothing afterwards would otherwise
/// publish a marker for an entry that is not there, turning the next start
/// into a refusal with no way back.
fn store_and_verify(account: &str, key: &[u8]) -> Result<(), String> {
    keystore::store(account, key)?;
    match keystore::load(account) {
        keystore::Lookup::Found(stored) if stored == key => Ok(()),
        keystore::Lookup::Found(_) => Err("the keystore returned a different key".into()),
        keystore::Lookup::Absent => Err("the keystore accepted the key and then had none".into()),
        keystore::Lookup::Unavailable(reason) => Err(reason),
    }
}

fn load_or_create_identity_in_keystore(path: &Path) -> Result<IdentityKey, Error> {
    let account = keystore_account(path);
    let recorded = keystore_marker_path(path).exists();
    let refuse = |reason: &str| {
        Err(Error::KeyStoreUnavailable(format!(
            "this device's identity is held in the platform keystore, and {reason}. Refusing to \
generate a replacement, because that would enrol this machine as a different device. Unlock or \
start the keystore and retry; if the identity is genuinely gone, remove {} to accept a new one",
            keystore_marker_path(path).display()
        )))
    };

    match keystore::load(&account) {
        keystore::Lookup::Found(stored) => match identity_from_bytes(stored) {
            Ok(identity) => {
                // Repair a marker that is missing because an earlier run was
                // interrupted between storing the key and recording it.
                if !recorded {
                    // This identity lives only in the keystore, so without a
                    // marker nothing stops a later outage minting over it.
                    publish_keystore_marker(path, &account).map_err(|error| {
                        Error::KeyStoreUnavailable(format!(
                            "the identity was read from the platform keystore, but custody could \
not be recorded beside {} ({error}). Refusing to continue, because an unrecorded keystore \
identity is one a later outage would silently replace",
                            path.display()
                        ))
                    })?;
                }
                eprintln!("OpenStream identity source=keystore");
                return Ok(identity);
            }
            Err(_) if recorded && !path.exists() => {
                return refuse("the entry it holds is unreadable");
            }
            Err(_) if recorded => eprintln!(
                "OpenStream identity: the keystore entry is unreadable; recovering this device's \
identity from the retained file fallback at {}",
                path.display()
            ),
            Err(_) => eprintln!(
                "OpenStream identity: the keystore entry is unreadable and no custody was \
recorded here; trying the file"
            ),
        },
        // Custody was recorded, so an answer of "no entry" or "cannot read"
        // means the keystore copy was lost, not that it was never created.
        // Minting a new identity here is the exact failure this marker exists to
        // prevent -- but a file->keystore migration deliberately keeps the
        // identity file as a fallback holding the same key, so recover from it
        // when it is present. Refuse only when there is nothing to recover,
        // which is the case that would otherwise enrol the machine as a
        // different device.
        keystore::Lookup::Absent if recorded && !path.exists() => {
            return refuse("the entry it held is gone");
        }
        keystore::Lookup::Absent if recorded => eprintln!(
            "OpenStream identity: the keystore entry is gone; recovering this device's identity \
from the retained file fallback at {}",
            path.display()
        ),
        keystore::Lookup::Unavailable(reason) if recorded && !path.exists() => {
            return refuse(&format!("it cannot be read ({reason})"));
        }
        keystore::Lookup::Unavailable(reason) if recorded => eprintln!(
            "OpenStream identity: the keystore is unavailable ({reason}); recovering this \
device's identity from the retained file fallback at {}",
            path.display()
        ),
        keystore::Lookup::Absent => {}
        keystore::Lookup::Unavailable(reason) => eprintln!(
            "OpenStream identity: the keystore is unavailable ({reason}) and no custody was \
recorded here"
        ),
    }

    // Whether a file is already there has to be read before anything creates
    // one, or a fresh install looks like a migration and, worse, gets its key
    // written to disk on the way past.
    if path.exists() {
        let identity = load_identity_file(path)?;
        match store_and_verify(&account, identity.pkcs8()) {
            Ok(()) => {
                // The file is still here and is the continuity guarantee, so
                // a marker that cannot be written costs the refusal but not
                // the identity. Say so rather than failing the session.
                match publish_keystore_marker(path, &account) {
                    Ok(()) => eprintln!(
                        "OpenStream identity source=migrated-to-keystore; the file at {} is kept \
as a fallback, and removing it is what completes the migration",
                        path.display()
                    ),
                    Err(error) => eprintln!(
                        "OpenStream identity source=migrated-to-keystore; custody could not be \
recorded ({error}), so do not remove the file at {}: it is now the only thing keeping this \
device's identity recoverable",
                        path.display()
                    ),
                }
            }
            Err(error) => eprintln!(
                "OpenStream identity source=file-fallback; keystore custody was requested but \
the keystore refused the key ({error}). The private key remains readable at {} by any process \
running as this user",
                path.display()
            ),
        }
        return Ok(identity);
    }

    // No file yet, so there is nothing to preserve and no reason to write one:
    // a key that only ever exists in the keystore is the point of asking for
    // keystore custody.
    let identity = IdentityKey::generate().map_err(Error::Identity)?;
    match store_and_verify(&account, identity.pkcs8()) {
        Ok(()) => {
            // Nothing else holds this key. Handing it back before custody is
            // durably recorded would leave exactly the gap the marker exists
            // to close, so the failure is the caller's problem, not a log line.
            publish_keystore_marker(path, &account).map_err(|error| {
                Error::KeyStoreUnavailable(format!(
                    "the new identity was stored in the platform keystore, but custody could not \
be recorded beside {} ({error}). Refusing to continue, because an unrecorded keystore identity \
is one a later outage would silently replace",
                    path.display()
                ))
            })?;
            eprintln!("OpenStream identity source=keystore");
            Ok(identity)
        }
        Err(error) => {
            eprintln!(
                "OpenStream identity source=file-fallback; keystore custody was requested but \
the keystore would not take a new key ({error}). The key is being written to {} instead, where \
any process running as this user can read it",
                path.display()
            );
            load_or_create_identity_file(path)
        }
    }
}

#[cfg(test)]
mod keystore_account_tests {
    use std::path::Path;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("openstream-marker-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    #[test]
    fn publishing_the_marker_leaves_no_staging_file_and_records_the_account() {
        let dir = scratch("publish");
        let store = dir.join("device-identity.pk8");
        super::publish_keystore_marker(&store, "device-identity-abcdef0123456789")
            .expect("marker published");

        let marker = super::keystore_marker_path(&store);
        let body = std::fs::read_to_string(&marker).expect("marker written");
        assert_eq!(body.trim(), "device-identity-abcdef0123456789");
        // A rename is what makes this atomic; a staging file left behind
        // would mean a crash could strand a partial marker.
        let staging: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".keystore.new"))
            .collect();
        assert!(staging.is_empty(), "staging left behind: {staging:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_marker_is_private_to_this_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let store = dir.join("device-identity.pk8");
        super::publish_keystore_marker(&store, "device-identity-0011223344556677")
            .expect("marker published");
        let marker = super::keystore_marker_path(&store);
        let mode = std::fs::metadata(&marker)
            .expect("marker")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "marker is group/world readable: {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn republishing_over_an_existing_marker_leaves_one_complete_marker() {
        // Two starts racing to record custody must not produce a torn file;
        // the rename makes the last writer win with a whole marker.
        let dir = scratch("race");
        let store = dir.join("device-identity.pk8");
        super::publish_keystore_marker(&store, "device-identity-1111111111111111")
            .expect("first publish");
        super::publish_keystore_marker(&store, "device-identity-2222222222222222")
            .expect("second publish");
        let body = std::fs::read_to_string(super::keystore_marker_path(&store)).expect("marker");
        assert!(
            body.trim() == "device-identity-1111111111111111"
                || body.trim() == "device-identity-2222222222222222",
            "torn marker: {body:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_marker_that_cannot_be_written_is_reported_rather_than_shrugged_off() {
        let dir = scratch("blocked");
        // A regular file where the store's directory would be, so the marker's
        // parent cannot be created at all. Permissions are not used to force
        // this: publication deliberately makes the directory private, which
        // would undo a read-only mode set by the test.
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a directory").expect("blocker");
        let store = blocker.join("device-identity.pk8");

        let published = super::publish_keystore_marker(&store, "device-identity-3333333333333333");
        assert!(
            published.is_err(),
            "an unwritable marker must be an error, not a warning: a keystore-only identity \
whose custody went unrecorded is one a later outage would silently replace"
        );
        assert!(!super::keystore_marker_path(&store).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_custody_marker_sits_beside_the_store_and_holds_no_key() {
        let store = Path::new("/var/lib/openstream/device-identity.pk8");
        let marker = super::keystore_marker_path(store);
        assert_eq!(
            marker,
            Path::new("/var/lib/openstream/device-identity.pk8.keystore")
        );
        // The marker records an account name, which is a digest of the store
        // path; nothing about it is secret.
        assert!(super::keystore_account(store).starts_with("device-identity-"));
    }

    #[test]
    fn the_account_is_stable_for_one_store_and_distinct_between_stores() {
        let one = Path::new("/var/lib/openstream/device-identity.pk8");
        let other = Path::new("/home/someone/.local/state/openstream/device-identity.pk8");
        assert_eq!(super::keystore_account(one), super::keystore_account(one));
        assert_ne!(
            super::keystore_account(one),
            super::keystore_account(other),
            "two stores on one machine must not share a keystore entry"
        );
    }

    #[test]
    fn the_account_carries_no_path_text() {
        // The account name is visible in keychain listings, so it must not
        // publish where the user keeps their files.
        let path =
            Path::new("/home/someone-identifiable/.local/state/openstream/device-identity.pk8");
        let account = super::keystore_account(path);
        assert!(!account.contains("someone-identifiable"), "{account}");
        assert!(account.starts_with("device-identity-"), "{account}");
    }
}

fn load_or_create_identity(path: &Path) -> Result<IdentityKey, Error> {
    if keystore_custody_requested() {
        if keystore::available() {
            return load_or_create_identity_in_keystore(path);
        }
        eprintln!(
            "OpenStream identity source=file-fallback; OPENSTREAM_IDENTITY_CUSTODY asked for the \
platform keystore, which this build has no implementation for. The key stays in a file that any \
process running as this user can read"
        );
    }
    load_or_create_identity_file(path)
}

fn load_or_create_identity_file(path: &Path) -> Result<IdentityKey, Error> {
    if !path.is_absolute() {
        return Err(Error::InvalidMessage(
            "identity store path must be absolute".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidMessage("identity store has no parent directory".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|_| Error::InvalidMessage("identity store directory is unavailable".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::InvalidMessage("identity store directory is insecure".into()))?;
    }

    // An identity that is already published is the answer, and the common
    // case by far.
    if path.exists() {
        return load_identity_file(path);
    }

    // Publishing the name and the contents has to be one step.
    //
    // Creating the final path with `create_new` and then writing into it
    // makes the file visible, under its real name, while it is still empty.
    // A second process starting at the same moment -- two peers of one
    // session on one machine, which is exactly what the ICE smoke test does
    // -- sees `AlreadyExists`, reads the empty file, and fails with
    // `InvalidKeyMaterial`. The window is small and entirely reachable.
    //
    // So the key is written to a private temporary file first and published
    // by linking it into place. `link` fails if the destination exists, which
    // makes publication atomic and gives exactly one winner: the loser
    // discards its own freshly generated key and reads the winner's, so both
    // processes end up with the same device identity rather than two.
    let identity = IdentityKey::generate().map_err(Error::Identity)?;
    let temporary = identity_staging_path(parent);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| Error::InvalidMessage("identity store could not be created".into()))?;
    let written = {
        use std::io::Write;
        file.write_all(identity.pkcs8())
            .and_then(|()| file.sync_all())
    };
    drop(file);
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(Error::InvalidMessage(
            "identity store could not be written".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return Err(Error::InvalidMessage(
                "identity store permissions could not be set".into(),
            ));
        }
    }

    let published = std::fs::hard_link(&temporary, path);
    let _ = std::fs::remove_file(&temporary);
    match published {
        Ok(()) => Ok(identity),
        // Someone else published first. Their file is complete by
        // construction, because they linked it only after writing it.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => load_identity_file(path),
        Err(_) if path.exists() => load_identity_file(path),
        Err(_) => Err(Error::InvalidMessage(
            "identity store could not be published".into(),
        )),
    }
}

/// A private staging path beside the identity store.
///
/// Unique per process and per attempt, so two publishers never share a
/// staging file, and dot-prefixed so it is not mistaken for a published
/// identity. The counter rather than a clock: two calls in the same process
/// can land in the same nanosecond, and a collision here would have one
/// publisher truncating the other's staged key.
fn identity_staging_path(parent: &Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    parent.join(format!(
        ".device-identity.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn load_identity_file(path: &Path) -> Result<IdentityKey, Error> {
    if !path.is_absolute() {
        return Err(Error::InvalidMessage(
            "identity key file path must be absolute".into(),
        ));
    }
    let link_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::InvalidMessage("identity key file is unavailable".into()))?;
    if link_metadata.file_type().is_symlink() {
        return Err(Error::InvalidMessage(
            "identity key file is a symlink".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::InvalidMessage("identity key file is unavailable".into()))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::InvalidMessage("identity key file metadata is unavailable".into()))?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(Error::InvalidMessage("identity key file is invalid".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.mode() & 0o400 == 0 {
            return Err(Error::InvalidMessage(
                "identity key file permissions are insecure".into(),
            ));
        }
    }
    // Size the buffer from the limit that is actually enforced below, not
    // from the file's claimed length: `take` bounds the read either way, so a
    // multi-gigabyte file would otherwise buy an attacker one allocation of
    // its full size before the length check ever ran.
    const MAX_IDENTITY_KEY_BYTES: usize = 4096;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_IDENTITY_KEY_BYTES)
            .min(MAX_IDENTITY_KEY_BYTES),
    );
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidMessage("identity key file could not be read".into()))?;
    if bytes.len() > 4096 {
        return Err(Error::InvalidMessage(
            "identity key file is too large".into(),
        ));
    }
    identity_from_bytes(bytes)
}

fn identity_from_bytes(bytes: Vec<u8>) -> Result<IdentityKey, Error> {
    // Environment variables are documented as hex, while a file is allowed
    // to contain either raw PKCS#8 bytes or the same hex representation. Try
    // the binary form first instead of guessing by DER length: PKCS#8 permits
    // optional attributes, so a valid identity is not required to be exactly
    // one of two historical byte lengths.
    if let Ok(identity) = IdentityKey::from_pkcs8(&bytes) {
        return Ok(identity);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidMessage("identity key is not PKCS#8 or hex".into()))?;
    let decoded = hex::decode(text.trim()).map_err(Error::Hex)?;
    IdentityKey::from_pkcs8(&decoded).map_err(Error::Identity)
}

/// Verify the peer's signature and enforce the production identity-pin
/// policy. Loopback remains convenient for local demos; non-loopback sessions
/// fail closed unless the operator pins the peer identity fingerprint or
/// explicitly opts into the unsafe lab override.
fn authenticate_direct_peer(
    server_origin: &str,
    pairing: &Pairing,
    local_role: Role,
    generation: u64,
    peer: &PeerKey,
) -> Result<(), Error> {
    let peer_role = opposite_role(local_role);
    if !verify_direct_key_signature(peer, &pairing.session_id, generation, peer_role) {
        return Err(Error::PeerIdentityRejected);
    }
    enforce_peer_identity_policy(server_origin, peer)
}

fn authenticate_ice_peer(
    server_origin: &str,
    pairing: &Pairing,
    local_role: Role,
    generation: u64,
    peer: &PeerKey,
) -> Result<(), Error> {
    let peer_role = opposite_role(local_role);
    if !verify_ice_key_signature(peer, &pairing.session_id, generation, peer_role) {
        return Err(Error::PeerIdentityRejected);
    }
    enforce_peer_identity_policy(server_origin, peer)
}

fn enforce_peer_identity_policy(server_origin: &str, peer: &PeerKey) -> Result<(), Error> {
    let expected = std::env::var("OPENSTREAM_EXPECT_PEER_IDENTITY")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let fingerprint = KeyExchange::fingerprint(peer.identity);
    eprintln!("OpenStream peer identity fingerprint {fingerprint}");
    if !expected.is_empty() {
        if fingerprint != expected {
            return Err(Error::PeerIdentityMismatch);
        }
        return Ok(());
    }
    let allow_unauthenticated =
        std::env::var("OPENSTREAM_ALLOW_UNAUTHENTICATED_PEER").as_deref() == Ok("1");
    if !allow_unauthenticated && remote_origin(server_origin) {
        return Err(Error::PeerIdentityRequired);
    }
    Ok(())
}

fn remote_origin(origin: &str) -> bool {
    let normalized = if origin.contains("://") {
        origin.to_string()
    } else {
        format!("wss://{origin}")
    };
    let Ok(url) = url::Url::parse(&normalized) else {
        return true;
    };
    let Some(host) = url.host_str() else {
        return true;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    host.parse::<IpAddr>()
        .map(|address| !address.is_loopback())
        .unwrap_or(true)
}

#[derive(Debug)]
enum ProbeResult {
    Failed,
    Established(Option<Packet>),
}

async fn probe_path(transport: &UdpTransport, cipher: &mut CipherSession) -> ProbeResult {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(750);
    let mut next_probe = tokio::time::Instant::now();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return ProbeResult::Failed;
        }
        if now >= next_probe {
            if transport
                .send_untracked(cipher, Kind::Control, 0, 0, PATH_PROBE)
                .await
                .is_err()
            {
                return ProbeResult::Failed;
            }
            // Registration and nomination can cross at the relay. Repeating
            // the authenticated probe gives both relay slots time to exist
            // without making the caller wait beyond the bounded probe phase.
            next_probe = now + Duration::from_millis(150);
        }
        let remaining = deadline.saturating_duration_since(now);
        let until_retry = next_probe.saturating_duration_since(now);
        let wait = remaining.min(until_retry.max(Duration::from_millis(1)));
        let (packet, wire_bytes) =
            match tokio::time::timeout(wait, transport.recv_untracked(cipher)).await {
                Ok(Ok(packet)) => packet,
                Ok(Err(_)) => continue,
                // The timeout normally means the retry interval elapsed. The
                // top of the loop sends the next probe or ends at the deadline.
                Err(_) => continue,
            };
        if packet.kind == Kind::Control && packet.payload == PATH_PROBE {
            if transport
                .send_untracked(cipher, Kind::Control, 0, 0, PATH_PROBE_ACK)
                .await
                .is_err()
            {
                return ProbeResult::Failed;
            }
        } else if packet.kind == Kind::Control && packet.payload == PATH_PROBE_ACK {
            // Echo the acknowledgement once before returning. Both peers may
            // probe at the same time, and a relay can deliver one ACK before
            // the other peer's probe. Without this echo, the first peer to
            // receive an ACK can leave its counterpart waiting forever for
            // the response to its own probe.
            if transport
                .send_untracked(cipher, Kind::Control, 0, 0, PATH_PROBE_ACK)
                .await
                .is_err()
            {
                return ProbeResult::Failed;
            }
            return ProbeResult::Established(None);
        } else {
            // The authenticated peer may already have moved on to capability
            // negotiation. Keep its first packet for `PeerSession::recv`.
            transport.record_received(wire_bytes);
            return ProbeResult::Established(Some(packet));
        }
    }
}

fn is_path_probe_packet(packet: &Packet) -> bool {
    packet.kind == Kind::Control
        && (packet.payload == PATH_PROBE || packet.payload == PATH_PROBE_ACK)
}

fn is_ack_eliciting_application(packet: &Packet) -> bool {
    !(packet.kind == Kind::Control
        && (packet.payload == PATH_KEEPALIVE || packet.payload == PATH_KEEPALIVE_ACK))
}

fn host_candidates(local: SocketAddr) -> Vec<Candidate> {
    if !local.ip().is_unspecified() {
        return vec![Candidate {
            kind: CandidateKind::Host,
            address: local,
        }];
    }

    let mut candidates = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let ip = interface.ip();
            if ip.is_unspecified() {
                continue;
            }
            let candidate = Candidate {
                kind: CandidateKind::Host,
                address: SocketAddr::new(ip, local.port()),
            };
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    if candidates.is_empty() {
        candidates.push(Candidate {
            kind: CandidateKind::Host,
            address: local,
        });
    }
    candidates
}

/// Accept the server-advertised relay even when it is a loopback endpoint in a
/// local development deployment. The equality check is important: a peer may
/// not turn the relay exception into a localhost port-scanning primitive by
/// inventing a different `relay` candidate.
fn trusted_relay_candidate(candidate: Candidate, trusted_relay: Option<SocketAddr>) -> bool {
    candidate.kind == CandidateKind::Relay
        && trusted_relay == Some(candidate.address)
        && candidate.address.port() != 0
        && !candidate.address.ip().is_unspecified()
        && !candidate.address.ip().is_multicast()
}

fn valid_local_candidate(address: SocketAddr) -> bool {
    address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x4d; 32];

    fn test_endpoint() -> Endpoint {
        let (outgoing, _outgoing_receiver) = mpsc::channel::<Message>(1);
        let (_incoming_sender, incoming) = mpsc::channel::<Result<Value, Error>>(1);
        Endpoint { outgoing, incoming }
    }

    /// Simultaneous loaders must agree on one identity, never observe a
    /// half-written one.
    ///
    /// Publishing used to create the final path and then write into it, so a
    /// second process could see the name, read an empty file, and fail with
    /// `InvalidKeyMaterial`. That is what the full-ICE smoke hit: two peers
    /// of one session starting together on one machine.
    ///
    /// Real threads with a shared start barrier rather than sequential calls,
    /// because sequential calls cannot reach the window at all.
    #[test]
    fn simultaneous_loaders_agree_on_one_identity() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Barrier};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        const RACERS: usize = 8;

        // Repeated, because a race that is lost by luck once is not evidence.
        for _ in 0..12 {
            let directory = std::env::temp_dir().join(format!(
                "openstream-identity-race-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&directory).expect("identity directory");
            let path = directory.join("device-identity.pk8");

            let barrier = Arc::new(Barrier::new(RACERS));
            let handles: Vec<_> = (0..RACERS)
                .map(|_| {
                    let path = path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        load_or_create_identity(&path)
                    })
                })
                .collect();

            let mut keys = Vec::new();
            for handle in handles {
                let identity = handle
                    .join()
                    .expect("loader thread")
                    .expect("every simultaneous loader must get an identity");
                keys.push(identity.public_key());
            }
            assert!(
                keys.windows(2).all(|pair| pair[0] == pair[1]),
                "simultaneous loaders must all end up with the same device identity"
            );

            // And the published file is the identity they agreed on.
            let reloaded = load_identity_file(&path).expect("published identity is readable");
            assert_eq!(reloaded.public_key(), keys[0]);

            // No staging files are left behind.
            let leftovers: Vec<_> = std::fs::read_dir(&directory)
                .expect("read identity directory")
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .filter(|name| name.to_string_lossy().ends_with(".tmp"))
                .collect();
            assert!(
                leftovers.is_empty(),
                "staging files must not survive publication: {leftovers:?}"
            );
            let _ = std::fs::remove_dir_all(&directory);
        }
    }

    /// A second load of an existing identity returns the same key.
    #[test]
    fn an_existing_identity_is_reused_rather_than_replaced() {
        let directory =
            std::env::temp_dir().join(format!("openstream-identity-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("identity directory");
        let path = directory.join("device-identity.pk8");
        let first = load_or_create_identity(&path).expect("first load creates");
        let second = load_or_create_identity(&path).expect("second load reuses");
        assert_eq!(first.public_key(), second.public_key());
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A credential issued to one end cannot act as the other.
    ///
    /// This is the property the whole Connect split exists for. Before the
    /// tokens were optional there was no way to express "client only": the
    /// field had to hold something, and whatever it held would have been sent
    /// to the signalling server as a host bearer token.
    #[test]
    fn a_role_credential_cannot_act_as_the_other_role() {
        let client = Pairing::from_role_credential(RoleCredential {
            session_grant: None,
            session_id: "session-1".into(),
            role: Role::Client,
            token: "CLIENT-CAPABILITY".into(),
            websocket_path: "/v1/signal/session-1/client".into(),
            expires_in_seconds: 60,
            relay_address: None,
            relay_ticket: Some("client-ticket".into()),
            turn: None,
            permissions: None,
        });
        assert!(client.can_act_as(Role::Client));
        assert!(
            !client.can_act_as(Role::Host),
            "a client credential must not be able to act as host"
        );
        assert_eq!(
            client.token(Role::Client).expect("its own role"),
            "CLIENT-CAPABILITY"
        );
        assert!(client.token(Role::Host).is_err());
        assert_eq!(client.relay_ticket(Role::Client), Some("client-ticket"));
        assert_eq!(client.relay_ticket(Role::Host), None);

        let host = Pairing::from_role_credential(RoleCredential {
            session_grant: None,
            session_id: "session-1".into(),
            role: Role::Host,
            token: "HOST-CAPABILITY".into(),
            websocket_path: "/v1/signal/session-1/host".into(),
            expires_in_seconds: 60,
            relay_address: None,
            relay_ticket: Some("host-ticket".into()),
            turn: None,
            permissions: None,
        });
        assert!(host.can_act_as(Role::Host));
        assert!(!host.can_act_as(Role::Client));
        assert_eq!(host.relay_ticket(Role::Host), Some("host-ticket"));
        assert_eq!(host.relay_ticket(Role::Client), None);
    }

    /// An empty token is treated as absent, not as a token.
    ///
    /// A hand-written or partially populated file must not be able to make
    /// the client present `Bearer ` to the signalling server and then report
    /// whatever that produces as a connection failure.
    #[test]
    fn an_empty_token_is_refused_like_a_missing_one() {
        let pairing = Pairing {
            session_grant: None,
            session_id: "session-1".into(),
            host_token: Some(String::new()),
            client_token: Some("client".into()),
            websocket_path: "/v1/signal/session-1/{role}".into(),
            expires_in_seconds: 60,
            relay_address: None,
            turn: None,
            turn_host: None,
            turn_client: None,
            relay_host_ticket: None,
            relay_client_ticket: None,
            permissions: None,
        };
        assert!(pairing.token(Role::Host).is_err());
        assert!(pairing.token(Role::Client).is_ok());
    }

    /// A role credential round-trips through the pairing file format.
    ///
    /// The launcher writes what the broker returned and the runner reads it
    /// back, so the two have to agree -- and the file must still carry only
    /// the one role after the trip.
    #[test]
    fn a_role_scoped_pairing_survives_serialisation() {
        let pairing = Pairing::from_role_credential(RoleCredential {
            session_grant: None,
            session_id: "session-1".into(),
            role: Role::Client,
            token: "CLIENT-CAPABILITY".into(),
            websocket_path: "/v1/signal/session-1/client".into(),
            expires_in_seconds: 60,
            relay_address: Some("203.0.113.9:7000".into()),
            relay_ticket: Some("ticket".into()),
            turn: None,
            permissions: None,
        });
        let encoded = serde_json::to_string(&pairing).expect("serialise");
        assert!(
            !encoded.contains("host_token"),
            "an absent role must not appear in the file at all: {encoded}"
        );
        let decoded: Pairing = serde_json::from_str(&encoded).expect("deserialise");
        assert_eq!(decoded, pairing);
        assert!(!decoded.can_act_as(Role::Host));
    }

    /// A role credential carries the permission classes the broker granted, and
    /// they travel into the pairing the runner reads.
    ///
    /// The host narrows what the client asked for during approval; the granted
    /// set rides with the credential so the runner can scope input, clipboard
    /// and audio to it rather than to whatever a peer happens to send.
    #[test]
    fn a_role_credential_carries_its_granted_permissions() {
        let json = r#"{
            "session_id": "session-1",
            "role": "client",
            "token": "CLIENT-CAPABILITY",
            "websocket_path": "/v1/signal/session-1/client",
            "expires_in_seconds": 60,
            "permissions": { "view": true, "keyboard": true, "mouse": true, "clipboard": true }
        }"#;
        let credential: RoleCredential =
            serde_json::from_str(json).expect("a credential with a permission grant parses");
        let granted = credential.permissions.expect("the grant is present");
        assert!(granted.view && granted.keyboard && granted.mouse && granted.clipboard);
        // A class the object omitted is denied, never silently granted.
        assert!(
            !granted.gamepad && !granted.microphone && !granted.tablet && !granted.virtual_usb,
            "an omitted class must default to denied, not granted"
        );
        // The pairing the runner consumes carries the identical grant.
        assert_eq!(
            Pairing::from_role_credential(credential).permissions,
            Some(granted),
            "the grant travels from the credential into the pairing"
        );
    }

    /// A credential minted before permission negotiation carries no grant.
    ///
    /// The field is optional so an older broker -- and the provisioning path,
    /// which does not negotiate per-class permissions -- still parses. Absent
    /// is `None` (decide at enforcement), never an empty set that would quietly
    /// deny everything.
    #[test]
    fn a_credential_without_a_permission_block_carries_none() {
        let json = r#"{
            "session_id": "session-1",
            "role": "host",
            "token": "HOST-CAPABILITY",
            "websocket_path": "/v1/signal/session-1/host",
            "expires_in_seconds": 60
        }"#;
        let credential: RoleCredential =
            serde_json::from_str(json).expect("a pre-permission credential parses");
        assert_eq!(credential.permissions, None);
        assert_eq!(Pairing::from_role_credential(credential).permissions, None);
    }

    /// The granted permissions survive the pairing-file round trip.
    ///
    /// The launcher writes the pairing and the runner reads it back, so a grant
    /// written to disk must decode to the identical set.
    #[test]
    fn granted_permissions_survive_the_pairing_file_roundtrip() {
        let granted = Permissions {
            view: true,
            keyboard: true,
            mouse: true,
            gamepad: false,
            clipboard: true,
            microphone: false,
            tablet: false,
            virtual_usb: false,
        };
        let pairing = Pairing::from_role_credential(RoleCredential {
            session_grant: None,
            session_id: "session-1".into(),
            role: Role::Client,
            token: "CLIENT-CAPABILITY".into(),
            websocket_path: "/v1/signal/session-1/client".into(),
            expires_in_seconds: 60,
            relay_address: None,
            relay_ticket: None,
            turn: None,
            permissions: Some(granted),
        });
        let encoded = serde_json::to_string(&pairing).expect("serialise");
        let decoded: Pairing = serde_json::from_str(&encoded).expect("deserialise");
        assert_eq!(decoded.permissions, Some(granted));
    }

    /// The permission-set helpers mean what they say.
    #[test]
    fn permission_set_helpers_are_consistent() {
        assert!(Permissions::none().is_empty());
        assert_eq!(Permissions::none(), Permissions::default());
        let all = Permissions::all();
        assert!(!all.is_empty());
        assert!(
            all.view
                && all.keyboard
                && all.mouse
                && all.gamepad
                && all.clipboard
                && all.microphone
                && all.tablet
                && all.virtual_usb
        );
    }

    /// No ceiling means unscoped: an older pairing or one from a path that
    /// never negotiated permissions must not lose every class the moment
    /// something starts consulting a ceiling that was never there.
    #[test]
    fn a_missing_ceiling_allows_every_class() {
        assert!(Permissions::allows(None, |permissions| permissions.keyboard));
        assert!(Permissions::allows(None, |permissions| permissions.microphone));
    }

    /// A present ceiling is authoritative in both directions: it grants
    /// exactly what it says, not more and not less.
    #[test]
    fn a_present_ceiling_grants_exactly_what_it_says() {
        let granted = Permissions {
            keyboard: true,
            clipboard: false,
            ..Permissions::none()
        };
        assert!(Permissions::allows(Some(granted), |permissions| {
            permissions.keyboard
        }));
        assert!(!Permissions::allows(Some(granted), |permissions| {
            permissions.clipboard
        }));
    }

    /// Provisioning pairings, which carry both roles, still work.
    ///
    /// The admin endpoint returns both and existing pairing files on disk
    /// contain both, so the optional fields must not have broken them.
    #[test]
    fn a_two_role_provisioning_pairing_still_grants_both() {
        let json = r#"{
            "session_id": "session-1",
            "host_token": "host",
            "client_token": "client",
            "websocket_path": "/v1/signal/session-1/{role}",
            "expires_in_seconds": 60
        }"#;
        let pairing: Pairing = serde_json::from_str(json).expect("legacy pairing parses");
        assert!(pairing.can_act_as(Role::Host));
        assert!(pairing.can_act_as(Role::Client));
        assert_eq!(pairing.token(Role::Host).expect("host"), "host");
        assert_eq!(pairing.token(Role::Client).expect("client"), "client");
    }

    #[test]
    fn pairing_and_turn_credentials_never_print_their_secrets() {
        let pairing = Pairing {
            session_grant: None,
            session_id: "session-1".into(),
            host_token: Some("HOST-BEARER-SHOULD-NOT-APPEAR".into()),
            client_token: Some("CLIENT-BEARER-SHOULD-NOT-APPEAR".into()),
            websocket_path: "/v1/signal/session-1".into(),
            expires_in_seconds: 3600,
            relay_address: None,
            turn: Some(TurnCredentials {
                username: "TURN-USER-SHOULD-NOT-APPEAR".into(),
                password: "TURN-PASS-SHOULD-NOT-APPEAR".into(),
                ttl_seconds: 3600,
                urls: vec!["turn:198.51.100.1:3478".into()],
                realm: "openstream".into(),
            }),
            turn_host: None,
            turn_client: None,
            relay_host_ticket: Some("RELAY-HOST-TICKET-SHOULD-NOT-APPEAR".into()),
            relay_client_ticket: Some("RELAY-CLIENT-TICKET-SHOULD-NOT-APPEAR".into()),
            permissions: None,
        };

        let rendered = format!("{pairing:?}");
        for secret in [
            "HOST-BEARER-SHOULD-NOT-APPEAR",
            "CLIENT-BEARER-SHOULD-NOT-APPEAR",
            "TURN-USER-SHOULD-NOT-APPEAR",
            "TURN-PASS-SHOULD-NOT-APPEAR",
            "RELAY-HOST-TICKET-SHOULD-NOT-APPEAR",
            "RELAY-CLIENT-TICKET-SHOULD-NOT-APPEAR",
        ] {
            assert!(!rendered.contains(secret), "Debug leaked {secret}");
        }
        // The non-secret session id stays useful for diagnostics.
        assert!(rendered.contains("session-1"));

        let turn_rendered = format!("{:?}", pairing.turn.as_ref().expect("turn"));
        assert!(!turn_rendered.contains("TURN-USER-SHOULD-NOT-APPEAR"));
        assert!(!turn_rendered.contains("TURN-PASS-SHOULD-NOT-APPEAR"));
    }

    #[test]
    fn direct_v2_waits_for_readiness_without_consuming_phase_timeout() {
        let started = TokioInstant::now();
        let mut handshake = DirectHandshake::new(Role::Host);

        assert_eq!(handshake.phase(), DirectPhase::WaitingForPeer);
        assert_eq!(handshake.deadline(), None);
        assert_eq!(handshake.check_deadline(started + PHASE_TIMEOUT * 2), None);

        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_ready",
                        "establishment_generation": 7,
                    }),
                    started,
                )
                .expect("current readiness"),
            DirectMessageOutcome::Ready
        );
        assert_eq!(handshake.generation(), 7);
        assert_eq!(handshake.phase(), DirectPhase::Candidates);
        assert_eq!(handshake.deadline(), Some(started + PHASE_TIMEOUT));
    }

    #[test]
    fn direct_v2_rejects_future_and_pre_ready_records_but_drops_stale_records() {
        let now = TokioInstant::now();
        let mut waiting = DirectHandshake::new(Role::Client);
        assert!(matches!(
            waiting.handle(
                &serde_json::json!({
                    "type": "direct_candidate",
                    "establishment_generation": 1,
                    "kind": "host",
                    "ip": "192.0.2.10",
                    "port": 40001,
                }),
                now,
            ),
            Err(Error::InvalidMessage(reason)) if reason.contains("before peer_ready")
        ));

        let mut handshake = DirectHandshake::new(Role::Client);
        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 7,
                }),
                now,
            )
            .expect("readiness");
        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_ready",
                        "establishment_generation": 6,
                    }),
                    now,
                )
                .expect("stale readiness"),
            DirectMessageOutcome::IgnoredStale
        );
        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_reset",
                        "establishment_generation": 6,
                        "reason": "role_replaced",
                    }),
                    now,
                )
                .expect("stale reset"),
            DirectMessageOutcome::IgnoredStale
        );
        assert!(matches!(
            handshake.handle(
                &serde_json::json!({
                    "type": "direct_candidate",
                    "establishment_generation": 8,
                    "kind": "host",
                    "ip": "192.0.2.11",
                    "port": 40002,
                }),
                now,
            ),
            Err(Error::InvalidMessage(reason)) if reason.contains("future")
        ));
    }

    #[test]
    fn direct_v2_reset_clears_epoch_state_and_allows_the_next_epoch() {
        let now = TokioInstant::now();
        let mut handshake = DirectHandshake::new(Role::Host);
        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 3,
                }),
                now,
            )
            .expect("readiness");
        handshake
            .handle(
                &serde_json::json!({
                    "type": "direct_candidate",
                    "establishment_generation": 3,
                    "kind": "host",
                    "ip": "192.0.2.10",
                    "port": 40001,
                }),
                now,
            )
            .expect("candidate");
        handshake
            .handle(
                &serde_json::json!({
                    "type": "direct_candidate_done",
                    "establishment_generation": 3,
                    "count": 1,
                }),
                now,
            )
            .expect("candidate done");
        assert_eq!(handshake.phase(), DirectPhase::KeyExchange);

        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_reset",
                        "establishment_generation": 3,
                        "reason": "role_replaced",
                    }),
                    now,
                )
                .expect("reset"),
            DirectMessageOutcome::Reset
        );
        assert_eq!(handshake.phase(), DirectPhase::WaitingForPeer);
        assert_eq!(handshake.generation(), 3);
        assert!(handshake.remote_candidates().is_empty());
        assert_eq!(handshake.deadline(), None);

        assert!(matches!(
            handshake.handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 6,
                }),
                now,
            ),
            Err(Error::InvalidMessage(reason)) if reason.contains("future")
        ));

        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 4,
                }),
                now,
            )
            .expect("next readiness");
        assert_eq!(handshake.generation(), 4);
        assert_eq!(handshake.phase(), DirectPhase::Candidates);
        assert!(handshake.remote_candidates().is_empty());
    }

    #[test]
    fn direct_v2_reconnect_reset_is_single_epoch_transition_and_old_key_is_stale() {
        let now = TokioInstant::now();
        let mut handshake = DirectHandshake::new(Role::Client);
        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 1,
                }),
                now,
            )
            .expect("initial readiness");
        handshake
            .handle(
                &serde_json::json!({
                    "type": "direct_candidate",
                    "establishment_generation": 1,
                    "kind": "host",
                    "ip": "192.0.2.10",
                    "port": 40001,
                }),
                now,
            )
            .expect("initial candidate");

        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_reset",
                        "establishment_generation": 1,
                        "reason": "role_replaced",
                    }),
                    now,
                )
                .expect("initial reset"),
            DirectMessageOutcome::Reset
        );
        assert_eq!(handshake.phase(), DirectPhase::WaitingForPeer);
        assert_eq!(handshake.deadline(), None);
        assert!(handshake.remote_candidates().is_empty());

        // Duplicate reset delivery is stale after the state transition and
        // cannot trigger another recovery or clear a later epoch.
        assert_eq!(
            handshake
                .handle(
                    &serde_json::json!({
                        "type": "peer_reset",
                        "establishment_generation": 1,
                        "reason": "role_replaced",
                    }),
                    now,
                )
                .expect("duplicate reset"),
            DirectMessageOutcome::Reset
        );

        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 2,
                }),
                now,
            )
            .expect("replacement readiness");
        let identity = IdentityKey::generate().expect("identity");
        let key = KeyExchange::generate().expect("old ephemeral key");
        let stale_key = encode_direct_key_message(&key, &identity, "session", 1, Role::Host)
            .expect("signed old-generation key");
        assert_eq!(
            handshake
                .handle(&stale_key, now)
                .expect("stale signed key is ignored"),
            DirectMessageOutcome::IgnoredStale
        );
        assert!(handshake.peer_key().is_none());
        assert_eq!(handshake.generation(), 2);
    }

    #[test]
    fn direct_v2_transcript_is_exact_and_binds_session_epoch_role_and_key() {
        let ephemeral = [0x11; 32];
        let mut expected = Vec::new();
        expected.extend_from_slice(b"OpenStream direct key v2");
        expected.extend_from_slice(&7_u32.to_be_bytes());
        expected.extend_from_slice(b"session");
        expected.extend_from_slice(&9_u64.to_be_bytes());
        expected.push(1);
        expected.extend_from_slice(&ephemeral);
        assert_eq!(
            direct_key_transcript("session", 9, Role::Host, ephemeral).expect("transcript"),
            expected
        );

        let identity = IdentityKey::generate().expect("identity");
        let key = KeyExchange::generate().expect("ephemeral key");
        let message = encode_direct_key_message(&key, &identity, "session", 9, Role::Host)
            .expect("direct key");
        let peer = decode_direct_peer_key(&message, 9).expect("decode direct key");
        assert!(verify_direct_key_signature(&peer, "session", 9, Role::Host,));
        assert!(!verify_direct_key_signature(
            &peer,
            "session",
            9,
            Role::Client,
        ));
        assert!(!verify_direct_key_signature(
            &peer,
            "other-session",
            9,
            Role::Host,
        ));
        assert!(!verify_direct_key_signature(
            &peer,
            "session",
            10,
            Role::Host,
        ));
        let changed_key = KeyExchange::generate().expect("changed ephemeral key");
        let changed_transcript =
            direct_key_transcript("session", 9, Role::Host, changed_key.public_key())
                .expect("changed transcript");
        assert_ne!(
            changed_transcript,
            direct_key_transcript("session", 9, Role::Host, peer.ephemeral)
                .expect("original transcript")
        );
    }

    #[test]
    fn direct_v2_duplicate_candidates_done_and_keys_are_idempotent_but_conflicts_fail() {
        let now = TokioInstant::now();
        let mut handshake = DirectHandshake::new(Role::Client);
        handshake
            .handle(
                &serde_json::json!({
                    "type": "peer_ready",
                    "establishment_generation": 1,
                }),
                now,
            )
            .expect("readiness");
        let candidate = serde_json::json!({
            "type": "direct_candidate",
            "establishment_generation": 1,
            "kind": "host",
            "ip": "192.0.2.10",
            "port": 40001,
        });
        assert_eq!(
            handshake.handle(&candidate, now).expect("candidate"),
            DirectMessageOutcome::CandidateAccepted
        );
        assert_eq!(
            handshake
                .handle(&candidate, now)
                .expect("duplicate candidate"),
            DirectMessageOutcome::CandidateDuplicate
        );
        let done = serde_json::json!({
            "type": "direct_candidate_done",
            "establishment_generation": 1,
            "count": 1,
        });
        assert_eq!(
            handshake.handle(&done, now).expect("done"),
            DirectMessageOutcome::CandidateDone
        );
        assert_eq!(
            handshake.handle(&done, now).expect("duplicate done"),
            DirectMessageOutcome::CandidateDoneDuplicate
        );
        assert!(matches!(
            handshake.handle(
                &serde_json::json!({
                    "type": "direct_candidate_done",
                    "establishment_generation": 1,
                    "count": 2,
                }),
                now,
            ),
            Err(Error::InvalidMessage(reason)) if reason.contains("conflicting")
        ));

        let identity = IdentityKey::generate().expect("identity");
        let key = KeyExchange::generate().expect("key");
        let message = encode_direct_key_message(&key, &identity, "session", 1, Role::Host)
            .expect("key message");
        assert_eq!(
            handshake.handle(&message, now).expect("key"),
            DirectMessageOutcome::KeyAccepted
        );
        assert_eq!(
            handshake.handle(&message, now).expect("duplicate key"),
            DirectMessageOutcome::KeyDuplicate
        );
        let other_identity = IdentityKey::generate().expect("other identity");
        let other_key = KeyExchange::generate().expect("other key");
        let conflicting =
            encode_direct_key_message(&other_key, &other_identity, "session", 1, Role::Host)
                .expect("conflicting key");
        assert!(matches!(
            handshake.handle(&conflicting, now),
            Err(Error::InvalidMessage(reason)) if reason.contains("conflicting")
        ));
    }

    #[test]
    fn direct_v2_does_not_consume_ice_vocabulary_or_server_proof_as_direct_handshake() {
        let now = TokioInstant::now();
        let mut handshake = DirectHandshake::new(Role::Host);
        for message in [
            serde_json::json!({"type":"relay_ticket_proof","socket_generation":1,"proof":"redacted"}),
            serde_json::json!({"type":"ice_candidate","candidate":"candidate"}),
            serde_json::json!({"type":"ice_candidate_done"}),
            serde_json::json!({"type":"key","public_key":"00"}),
        ] {
            assert_eq!(
                handshake
                    .handle(&message, now)
                    .expect("unrelated signaling"),
                DirectMessageOutcome::Ignored
            );
        }
        assert_eq!(handshake.phase(), DirectPhase::WaitingForPeer);
        assert!(handshake.peer_key().is_none());
    }

    fn direct_test_session(transport: UdpTransport) -> PeerSession {
        let now = Instant::now();
        let (scheduler, delivery, transport_ack, policy_clock_origin) =
            new_transport_state(now, FIRST_PATH_GENERATION);
        PeerSession {
            signal: test_endpoint(),
            path: PathRuntime::initial_active(
                PeerPathBackend::Direct {
                    transport: Box::new(transport),
                    candidate: CandidateKind::Host,
                    relay_registration: None,
                },
                now,
            ),
            cipher: CipherSession::new(TEST_KEY, TEST_KEY),
            stats: SessionStats::default(),
            scheduler,
            delivery,
            transport_ack,
            policy_clock_origin,
            path_baseline: None,
            ice_counters: PathCounters::default(),
            prefetched: None,
            last_keepalive: now,
            last_peer_activity: now,
            migration_enabled: false,
            migration: MigrationController::new(Role::Host),
            migration_config: MigrationConfig::new(&pairing(), Role::Host, vec![], vec![]),
            opening: None,
            draining: None,
            migration_inbox: Default::default(),
        }
    }

    #[tokio::test]
    async fn full_reliable_control_window_is_backpressure_not_fatal() {
        let mut sender = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sink = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        sender.connect(sink.local_addr().unwrap()).await.unwrap();
        // `sink` is never read, so no control frame is ever acknowledged and
        // the outbound window cannot drain.
        let mut session = direct_test_session(sender);
        let mut control = ReliableControl::new(4);
        for index in 0..4 {
            let accepted = control
                .send(&mut session, format!("m{index}").as_bytes())
                .await
                .expect("send must not error while the window has room");
            assert!(
                accepted.is_some(),
                "message {index} should enter the window"
            );
        }
        // The window is full and nothing can acknowledge it. Every further send
        // must be backpressure -- Ok(None) -- never a fatal or malformed-input
        // error that would tear the session down.
        for _ in 0..200 {
            match control.send(&mut session, b"overflow").await {
                Ok(None) => {}
                other => panic!("a full window must backpressure, got {other:?}"),
            }
        }
        assert_eq!(control.outstanding(), 4);
    }

    #[test]
    fn force_relay_gathers_relay_candidates_only() {
        use super::ice_candidate_types;
        use webrtc_ice::candidate::CandidateType;

        // Forced: relay only, so a network that blocks direct paths must use TURN.
        assert_eq!(ice_candidate_types(true), vec![CandidateType::Relay]);

        // Unforced: the full set, with ICE free to pick the best working pair.
        let full = ice_candidate_types(false);
        assert!(full.contains(&CandidateType::Host));
        assert!(full.contains(&CandidateType::ServerReflexive));
        assert!(full.contains(&CandidateType::PeerReflexive));
        assert!(full.contains(&CandidateType::Relay));
        assert!(full.len() > 1);
    }

    #[test]
    fn stale_epoch_ice_messages_are_ignored_not_applied() {
        // Leftover ICE traffic from a previous establishment epoch must be
        // ignored (Ok(false)) so it can neither advance nor revive the current
        // one; the current generation is accepted; a future one is rejected.
        let message = |generation: u64| {
            serde_json::json!({
                "type": "ice_credentials_v2",
                "establishment_generation": generation,
                "ufrag": "u",
                "pwd": "p",
            })
        };
        assert!(
            !handle_ice_generation(&message(1), "ice_credentials_v2", 2).unwrap(),
            "a stale epoch must be ignored, never applied"
        );
        assert!(
            handle_ice_generation(&message(2), "ice_credentials_v2", 2).unwrap(),
            "the current epoch must be accepted"
        );
        assert!(
            handle_ice_generation(&message(3), "ice_credentials_v2", 2).is_err(),
            "a future epoch is a protocol error"
        );
    }

    #[test]
    fn keyframe_pacer_coalesces_many_gaps_into_bounded_requests() {
        let interval = Duration::from_millis(250);
        let mut pacer = KeyframeRequestPacer::new(interval);
        let start = Instant::now();
        // With no gap detected, nothing is ever due.
        assert!(!pacer.due(start));

        // Hundreds of gaps arriving rapidly within a single interval.
        let mut sent = 0_u32;
        for step in 0..500_u64 {
            pacer.note_gap();
            let now = start + Duration::from_micros(step * 100);
            if pacer.due(now) {
                pacer.note_sent(now);
                sent += 1;
            }
        }
        assert_eq!(
            sent, 1,
            "hundreds of gaps within one interval must coalesce to a single request"
        );

        // Still waiting after the interval elapses: exactly one more request.
        let later = start + interval + Duration::from_millis(1);
        assert!(pacer.due(later));
        pacer.note_sent(later);
        assert!(!pacer.due(later + Duration::from_millis(1)));

        // An actual keyframe clears the pending state; nothing is due afterwards.
        pacer.keyframe_received();
        assert!(!pacer.is_waiting());
        assert!(!pacer.due(later + interval * 10));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_releases_draining_path_before_deadline() {
        use openstream_protocol::relay;

        let relay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay");
        let relay_address = relay_socket.local_addr().expect("relay address");
        let (unregisters, mut observed) = mpsc::channel(4);
        let (ack_release, ack_gate) = oneshot::channel();
        let relay_task = tokio::spawn(async move {
            let mut ack_gate = Some(ack_gate);
            let mut packet = [0; MAX_DATAGRAM];
            let mut unregister_count = 0;
            loop {
                let (length, source) = relay_socket
                    .recv_from(&mut packet)
                    .await
                    .expect("receive relay packet");
                if let Ok(registration) = relay::decode_registration(&packet[..length]) {
                    relay_socket
                        .send_to(&relay::encode_ack(registration.role), source)
                        .await
                        .expect("ack registration");
                } else if let Ok(unregister) = relay::decode_unregister(&packet[..length]) {
                    unregister_count += 1;
                    unregisters
                        .send(unregister_count)
                        .await
                        .expect("observe unregister");
                    if let Some(ack_gate) = ack_gate.take() {
                        ack_gate.await.expect("release unregister ACK");
                    }
                    relay_socket
                        .send_to(&relay::encode_unregister_ack(unregister.role), source)
                        .await
                        .expect("ack unregister");
                }
            }
        });

        let mut draining_transport = UdpTransport::bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind draining transport");
        draining_transport
            .connect(relay_address)
            .await
            .expect("connect draining transport");
        let registration = draining_transport
            .relay_registration("session", RelayRole::Host, "ticket")
            .expect("create relay registration");
        draining_transport
            .register_relay("session", RelayRole::Host, "ticket")
            .await
            .expect("register draining transport");

        let active_transport = UdpTransport::bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind active transport");
        let mut session = direct_test_session(active_transport);
        let deadline = Instant::now() + Duration::from_secs(2);
        session.draining = Some(DrainingPath::new(
            PeerPath::replacement(
                PeerPathBackend::Direct {
                    transport: Box::new(draining_transport),
                    candidate: CandidateKind::Relay,
                    relay_registration: Some(registration),
                },
                2,
                Instant::now(),
            ),
            deadline,
        ));

        {
            let close = session.close();
            tokio::pin!(close);
            tokio::time::timeout(Duration::from_millis(500), async {
                let first = tokio::select! {
                    biased;
                    result = &mut close => {
                        result.expect("close session");
                        panic!("close returned before relay cleanup was observed");
                    }
                    first = observed.recv() => first.expect("relay cleanup observation"),
                };
                assert_eq!(first, 1, "drain cleanup must unregister once");
                ack_release.send(()).expect("release unregister ACK");
                close.await.expect("close session");
            })
            .await
            .expect("draining close was not prompt");
        }
        session.close().await.expect("close session again");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), observed.recv())
                .await
                .is_err(),
            "repeated close sent a duplicate unregister"
        );
        assert!(
            Instant::now() < deadline,
            "cleanup reached the drain deadline"
        );

        relay_task.abort();
    }

    #[tokio::test]
    async fn path_migration_api_gates_without_changing_the_active_socket() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut peer = direct_test_session(transport);
        assert!(matches!(
            peer.migrate_to(MigrationTarget::OpaqueRelay).await,
            Err(Error::PathMigration(
                PathMigrationError::CapabilityNotNegotiated
            ))
        ));
        peer.migration_enabled = true;
        assert!(matches!(
            peer.migrate_to(MigrationTarget::Ice).await,
            Err(Error::PathMigration(
                PathMigrationError::UnsupportedIceRestart
            ))
        ));
        assert!(matches!(
            peer.migrate_to(MigrationTarget::OpaqueRelay).await,
            Err(Error::PathMigration(PathMigrationError::PathUnavailable))
        ));
        peer.migration.role = Role::Client;
        assert!(matches!(
            peer.migrate_to(MigrationTarget::DirectUdp).await,
            Err(Error::PathMigration(
                PathMigrationError::HostMigrationRequired
            ))
        ));
        assert_eq!(peer.path_generation(), 1);
        assert_eq!(peer.migration_state(), MigrationState::Idle);
    }

    fn migration_endpoints() -> (Endpoint, Endpoint) {
        let (host_out, mut host_messages) = mpsc::channel::<Message>(32);
        let (client_out, mut client_messages) = mpsc::channel::<Message>(32);
        let (host_in, host_recv) = mpsc::channel(32);
        let (client_in, client_recv) = mpsc::channel(32);
        tokio::spawn(async move {
            while let Some(Message::Text(text)) = host_messages.recv().await {
                if client_in
                    .send(Ok(serde_json::from_str(&text).unwrap()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(Message::Text(text)) = client_messages.recv().await {
                if host_in
                    .send(Ok(serde_json::from_str(&text).unwrap()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        (
            Endpoint {
                outgoing: host_out,
                incoming: host_recv,
            },
            Endpoint {
                outgoing: client_out,
                incoming: client_recv,
            },
        )
    }

    #[tokio::test]
    async fn path_migration_direct_relay_direct_preserves_cipher_and_resets_snapshot() {
        use openstream_protocol::relay;
        use openstream_transport::{PathMtuState, PathState, TransportPathKind};
        let relay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_socket.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let mut slots = [None, None];
            let mut buffer = [0; MAX_DATAGRAM];
            loop {
                let (len, source) = relay_socket.recv_from(&mut buffer).await.unwrap();
                if let Ok(reg) = relay::decode_registration(&buffer[..len]) {
                    assert_eq!(reg.session_id, "session");
                    let index = match reg.role {
                        RelayRole::Host => 0,
                        RelayRole::Client => 1,
                    };
                    assert_eq!(
                        reg.token,
                        if index == 0 {
                            "host-ticket"
                        } else {
                            "client-ticket"
                        }
                    );
                    slots[index] = Some(source);
                    relay_socket
                        .send_to(&relay::encode_ack(reg.role), source)
                        .await
                        .unwrap();
                } else if let Some(index) = slots.iter().position(|slot| *slot == Some(source)) {
                    if let Some(destination) = slots[1 - index] {
                        relay_socket
                            .send_to(&buffer[..len], destination)
                            .await
                            .unwrap();
                    }
                }
            }
        });
        let mut ht = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut ct = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let ha = ht.local_addr().unwrap();
        let ca = ct.local_addr().unwrap();
        ht.connect(ca).await.unwrap();
        ct.connect(ha).await.unwrap();
        let mut host = direct_test_session(ht);
        let mut client = direct_test_session(ct);
        (host.signal, client.signal) = migration_endpoints();
        let mut pairing = pairing();
        pairing.session_id = "session".into();
        pairing.relay_address = Some(relay_address.to_string());
        pairing.relay_host_ticket = Some("host-ticket".into());
        pairing.relay_client_ticket = Some("client-ticket".into());
        host.migration_config = MigrationConfig::new(
            &pairing,
            Role::Host,
            vec![Candidate {
                kind: CandidateKind::Host,
                address: ha,
            }],
            vec![Candidate {
                kind: CandidateKind::Host,
                address: ca,
            }],
        );
        client.migration_config = MigrationConfig::new(
            &pairing,
            Role::Client,
            vec![Candidate {
                kind: CandidateKind::Host,
                address: ca,
            }],
            vec![Candidate {
                kind: CandidateKind::Host,
                address: ha,
            }],
        );
        client.migration = MigrationController::new(Role::Client);
        let run = async {
            let (h, c) = tokio::join!(
                host.negotiate_host_with_capabilities(
                    Capabilities::host_default().with_path_migration()
                ),
                client.negotiate_client_with_capabilities(
                    Capabilities::client_default().with_path_migration()
                )
            );
            assert!(h.unwrap().path_migration);
            assert!(c.unwrap().path_migration);
            let host_work = async {
                for (target, generation, kind) in [
                    (
                        MigrationTarget::OpaqueRelay,
                        2,
                        TransportPathKind::OpaqueRelay,
                    ),
                    (MigrationTarget::DirectUdp, 3, TransportPathKind::DirectUdp),
                ] {
                    let report = host.migrate_to(target).await.unwrap();
                    assert_eq!(report.previous_generation, generation - 1);
                    assert_eq!(report.active_generation, generation);
                    assert_eq!(report.active_kind, kind);
                    let snapshot = host.path_snapshot();
                    assert_eq!(snapshot.path_generation, generation);
                    assert_eq!(snapshot.state, PathState::Active);
                    assert_eq!(snapshot.datagram_size, Some(1200));
                    assert_eq!(snapshot.path_mtu_state, PathMtuState::Unavailable);
                    assert!(
                        snapshot.sample.is_none(),
                        "new generation starts a fresh baseline"
                    );
                    assert!(snapshot.path_age_ms < 250);
                    host.send(Kind::Input, 1, 0, b"ping").await.unwrap();
                    assert_eq!(host.recv().await.unwrap().payload, b"pong");
                    tokio::time::sleep(Duration::from_millis(260)).await;
                }
            };
            let client_work = async {
                let mut counter = 0;
                for generation in [2, 3] {
                    let packet = client.recv().await.unwrap();
                    assert_eq!(packet.payload, b"ping");
                    assert!(
                        packet.counter > counter,
                        "one counter domain across generations"
                    );
                    counter = packet.counter;
                    assert_eq!(client.path_generation(), generation);
                    assert_eq!(client.migration_state(), MigrationState::Active);
                    client.send(Kind::Input, 1, 0, b"pong").await.unwrap();
                }
            };
            tokio::join!(host_work, client_work);
        };
        let result = tokio::time::timeout(Duration::from_secs(8), run).await;
        relay_task.abort();
        result.unwrap();
        assert!(!format!("{:?}", host.migration_config).contains("host-ticket"));
    }

    #[tokio::test]
    async fn delayed_setup_packets_do_not_pollute_application_counters() {
        let mut sender = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut receiver = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        sender.connect(receiver_addr).await.unwrap();
        receiver.connect(sender_addr).await.unwrap();
        let mut peer = direct_test_session(receiver);
        let baseline_at = Instant::now();
        assert!(peer.transport_snapshot(baseline_at).sample.is_none());

        let mut cipher = CipherSession::new(TEST_KEY, TEST_KEY);
        sender
            .send(&mut cipher, Kind::Control, 0, 0, PATH_PROBE)
            .await
            .unwrap();
        let sent_application = sender
            .send(&mut cipher, Kind::Control, 0, 0, b"application")
            .await
            .unwrap();

        let packet = peer.recv().await.unwrap();
        assert_eq!(packet.payload, b"application");
        let sample = peer
            .transport_snapshot(baseline_at + Duration::from_secs(1))
            .sample
            .expect("application sample");
        assert_eq!(sample.received_packets, 1);
        assert_eq!(
            sample.received_wire_bytes,
            u64::try_from(sent_application).expect("wire length fits")
        );
    }

    #[tokio::test]
    async fn prefetched_application_io_is_preserved_across_probe_boundary() {
        let mut probe_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut peer_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let probe_addr = probe_transport.local_addr().unwrap();
        let peer_addr = peer_transport.local_addr().unwrap();
        probe_transport.connect(peer_addr).await.unwrap();
        peer_transport.connect(probe_addr).await.unwrap();

        let peer = tokio::spawn(async move {
            let mut cipher = CipherSession::new(TEST_KEY, TEST_KEY);
            let probe = peer_transport.recv(&mut cipher).await.unwrap();
            assert_eq!(probe.payload, PATH_PROBE);
            peer_transport
                .send(&mut cipher, Kind::Control, 0, 0, b"prefetched")
                .await
                .unwrap()
        });
        let mut cipher = CipherSession::new(TEST_KEY, TEST_KEY);
        let result = probe_path(&probe_transport, &mut cipher).await;
        let prefetched_wire_bytes = peer.await.unwrap();

        let ProbeResult::Established(Some(packet)) = result else {
            panic!("probe did not preserve the prefetched application packet");
        };
        assert_eq!(packet.payload, b"prefetched");
        let counters = probe_transport.telemetry_counters();
        assert_eq!(counters.sent_packets, 0);
        assert_eq!(counters.received_packets, 1);
        assert_eq!(
            counters.received_wire_bytes,
            u64::try_from(prefetched_wire_bytes).expect("wire length fits")
        );
    }

    fn pairing() -> Pairing {
        Pairing {
            session_grant: None,
            session_id: "session".into(),
            host_token: Some("host-token".into()),
            client_token: Some("client-token".into()),
            websocket_path: "/v1/signal/session/{host|client}".into(),
            expires_in_seconds: 60,
            relay_address: None,
            turn: None,
            turn_host: None,
            turn_client: None,
            relay_host_ticket: None,
            relay_client_ticket: None,
            permissions: None,
        }
    }

    fn pairing_file_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        static NEXT_PAIRING_FILE: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_PAIRING_FILE.fetch_add(1, AtomicOrdering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "openstream-client-core-pairing-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create pairing test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("make pairing test directory private");
        }
        directory.join(format!("{label}.json"))
    }

    #[test]
    fn pairing_file_loader_requires_a_private_absolute_regular_file() {
        let path = pairing_file_path("valid");
        let json = serde_json::to_vec(&pairing()).expect("encode pairing");
        std::fs::write(&path, json).expect("write pairing file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("make pairing file private");
        }

        let decoded = load_pairing_from_file(&path).expect("load private pairing file");
        assert_eq!(decoded, pairing());
        assert!(matches!(
            load_pairing_from_file(std::path::Path::new("pairing.json")),
            Err(Error::PairingFilePathNotAbsolute)
        ));
        assert!(matches!(
            load_pairing_from_file(path.with_extension("missing")),
            Err(Error::PairingFileUnavailable)
        ));
        std::fs::remove_dir_all(path.parent().expect("test directory"))
            .expect("remove pairing test directory");
    }

    #[cfg(unix)]
    #[test]
    fn pairing_file_loader_rejects_insecure_permissions_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let path = pairing_file_path("permissions");
        std::fs::write(
            &path,
            serde_json::to_vec(&pairing()).expect("encode pairing"),
        )
        .expect("write pairing file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("make pairing file group-readable");
        assert!(matches!(
            load_pairing_from_file(&path),
            Err(Error::PairingFileInsecure)
        ));

        let target = path.with_file_name("target.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&pairing()).expect("encode pairing"),
        )
        .expect("write pairing target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("make pairing target private");
        let link = path.with_file_name("link.json");
        std::os::unix::fs::symlink(&target, &link).expect("create pairing symlink");
        assert!(matches!(
            load_pairing_from_file(&link),
            Err(Error::PairingFileInsecure)
        ));
        std::fs::remove_dir_all(path.parent().expect("test directory"))
            .expect("remove pairing test directory");
    }

    #[test]
    fn pairing_file_loader_rejects_oversized_or_invalid_material_without_echoing_it() {
        let path = pairing_file_path("oversized");
        std::fs::write(&path, vec![b'x'; MAX_PAIRING_FILE_BYTES + 1])
            .expect("write oversized pairing file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("make oversized pairing file private");
        }
        let error = load_pairing_from_file(&path).expect_err("oversized pairing accepted");
        assert!(matches!(error, Error::PairingFileTooLarge));
        assert!(!format!("{:?}", error).contains('x'));

        std::fs::write(&path, b"not pairing json").expect("write invalid pairing file");
        let error = load_pairing_from_file(&path).expect_err("invalid pairing accepted");
        assert!(matches!(error, Error::Deserialize(_)));
        assert!(!format!("{}", error).contains("not pairing json"));
        std::fs::remove_dir_all(path.parent().expect("test directory"))
            .expect("remove pairing test directory");
    }

    #[cfg(windows)]
    #[test]
    fn windows_pairing_file_reparse_attribute_guard_is_exact() {
        assert!(!has_reparse_point_attribute(0));
        assert!(has_reparse_point_attribute(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(has_reparse_point_attribute(
            FILE_ATTRIBUTE_REPARSE_POINT | 0x20
        ));
    }

    #[test]
    fn pairing_environment_requires_a_file_or_an_explicit_developer_override() {
        use std::sync::Mutex;

        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("pairing environment lock");
        let old_file = std::env::var_os("OPENSTREAM_PAIRING_FILE");
        let old_json = std::env::var_os("OPENSTREAM_PAIRING_JSON");
        let old_override = std::env::var_os("OPENSTREAM_DEVELOPER_OVERRIDE");
        unsafe {
            std::env::remove_var("OPENSTREAM_PAIRING_FILE");
            std::env::remove_var("OPENSTREAM_PAIRING_JSON");
            std::env::remove_var("OPENSTREAM_DEVELOPER_OVERRIDE");
        }
        assert!(matches!(
            load_pairing_from_environment(),
            Err(Error::PairingRequired)
        ));

        let path = pairing_file_path("environment");
        std::fs::write(
            &path,
            serde_json::to_vec(&pairing()).expect("encode pairing"),
        )
        .expect("write environment pairing");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("make environment pairing private");
        }
        unsafe {
            std::env::set_var("OPENSTREAM_PAIRING_FILE", &path);
            std::env::set_var("OPENSTREAM_PAIRING_JSON", "this-json-must-not-be-consumed");
            std::env::remove_var("OPENSTREAM_DEVELOPER_OVERRIDE");
        }
        assert_eq!(
            load_pairing_from_environment().expect("private file has precedence"),
            pairing()
        );
        std::fs::remove_dir_all(path.parent().expect("test directory"))
            .expect("remove environment pairing directory");

        unsafe {
            std::env::remove_var("OPENSTREAM_PAIRING_FILE");
            std::env::set_var(
                "OPENSTREAM_PAIRING_JSON",
                serde_json::to_string(&pairing()).expect("encode pairing"),
            );
        }
        assert!(matches!(
            load_pairing_from_environment(),
            Err(Error::DeveloperOverrideRequired)
        ));

        unsafe {
            std::env::set_var("OPENSTREAM_DEVELOPER_OVERRIDE", "1");
        }
        assert_eq!(
            load_pairing_from_environment().expect("explicit developer override"),
            pairing()
        );

        unsafe {
            match old_file {
                Some(value) => std::env::set_var("OPENSTREAM_PAIRING_FILE", value),
                None => std::env::remove_var("OPENSTREAM_PAIRING_FILE"),
            }
            match old_json {
                Some(value) => std::env::set_var("OPENSTREAM_PAIRING_JSON", value),
                None => std::env::remove_var("OPENSTREAM_PAIRING_JSON"),
            }
            match old_override {
                Some(value) => std::env::set_var("OPENSTREAM_DEVELOPER_OVERRIDE", value),
                None => std::env::remove_var("OPENSTREAM_DEVELOPER_OVERRIDE"),
            }
        }
    }

    fn pairing_with_turn() -> Pairing {
        let mut pairing = pairing();
        pairing.turn = Some(TurnCredentials {
            username: "1700003600:session:host".into(),
            password: "session-password".into(),
            ttl_seconds: 3600,
            urls: vec!["turn:turn.example:3478".into()],
            realm: "openstream".into(),
        });
        pairing
    }

    #[test]
    fn role_url_contains_the_correct_capability() {
        let pairing = pairing();
        assert_eq!(
            pairing
                .websocket_url("http://localhost:8080/", Role::Host)
                .expect("loopback plaintext"),
            "ws://localhost:8080/v1/signal/session/host"
        );
        assert_eq!(
            pairing
                .websocket_url("https://example.test", Role::Client)
                .expect("tls origin"),
            "wss://example.test/v1/signal/session/client"
        );
    }

    #[test]
    fn plaintext_non_loopback_origin_is_rejected() {
        let pairing = pairing();
        assert!(matches!(
            pairing.websocket_url("http://example.test/", Role::Host),
            Err(Error::InsecureOrigin)
        ));
        assert!(matches!(
            pairing.websocket_url("ws://example.test/", Role::Host),
            Err(Error::InsecureOrigin)
        ));
        // Explicit lab override restores the old behavior.
        // SAFETY: no other test in this process reads this variable.
        unsafe {
            std::env::set_var("OPENSTREAM_ALLOW_INSECURE", "1");
        }
        assert_eq!(
            pairing
                .websocket_url("http://example.test/", Role::Host)
                .expect("override"),
            "ws://example.test/v1/signal/session/host"
        );
        // SAFETY: same single-threaded test context as above.
        unsafe {
            std::env::remove_var("OPENSTREAM_ALLOW_INSECURE");
        }
    }

    #[test]
    fn local_no_auth_plaintext_requires_a_private_numeric_origin() {
        assert!(plaintext_origin_allowed("192.168.1.69", false, false, true));
        assert!(plaintext_origin_allowed("fd00::69", false, false, true));
        assert!(plaintext_origin_allowed("fe80::69", false, false, true));
        assert!(!plaintext_origin_allowed("100.64.0.1", false, false, true));
        assert!(!plaintext_origin_allowed(
            "example.test",
            false,
            false,
            true
        ));
        assert!(!plaintext_origin_allowed(
            "2001:db8::69",
            false,
            false,
            true
        ));
        assert!(plaintext_origin_allowed("localhost", true, false, false));
    }

    #[test]
    fn peer_candidate_validation_rejects_scan_primitives() {
        let local: SocketAddr = "192.0.2.10:9000".parse().unwrap();
        let loopback_local: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        // Unspecified, multicast, and port-zero are never valid.
        assert!(!valid_peer_candidate(
            "0.0.0.0:9000".parse().unwrap(),
            local
        ));
        assert!(!valid_peer_candidate("[::]:9000".parse().unwrap(), local));
        assert!(!valid_peer_candidate(
            "224.0.0.1:9000".parse().unwrap(),
            local
        ));
        assert!(!valid_peer_candidate("192.0.2.1:0".parse().unwrap(), local));
        // Loopback is valid only for loopback-bound locals (local demo).
        assert!(!valid_peer_candidate(
            "127.0.0.1:9000".parse().unwrap(),
            local
        ));
        assert!(valid_peer_candidate(
            "127.0.0.1:9000".parse().unwrap(),
            loopback_local
        ));
        // Ordinary LAN and global addresses are fine.
        assert!(valid_peer_candidate(
            "192.0.2.1:9000".parse().unwrap(),
            local
        ));
        assert!(valid_peer_candidate(
            "203.0.113.7:3478".parse().unwrap(),
            local
        ));
    }

    #[test]
    fn only_the_pairing_relay_address_gets_the_loopback_exception() {
        let relay: SocketAddr = "127.0.0.1:18185".parse().unwrap();
        assert!(trusted_relay_candidate(
            Candidate {
                kind: CandidateKind::Relay,
                address: relay,
            },
            Some(relay),
        ));
        assert!(!trusted_relay_candidate(
            Candidate {
                kind: CandidateKind::Relay,
                address: "127.0.0.1:18186".parse().unwrap(),
            },
            Some(relay),
        ));
        assert!(!trusted_relay_candidate(
            Candidate {
                kind: CandidateKind::Host,
                address: relay,
            },
            Some(relay),
        ));
    }

    #[test]
    fn turn_credentials_stamp_only_turn_urls() {
        let urls = parse_ice_urls(
            "stun:stun.example:3478,turn:turn.example:3478",
            Some("user"),
            Some("pass"),
        )
        .expect("parse");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].username.is_empty());
        assert!(urls[0].password.is_empty());
        assert_eq!(urls[1].username, "user");
        assert_eq!(urls[1].password, "pass");
    }

    #[test]
    fn pairing_round_trips_as_json() {
        let original = pairing();
        let encoded = serde_json::to_string(&original).expect("encode pairing");
        let decoded: Pairing = serde_json::from_str(&encoded).expect("decode pairing");
        assert_eq!(decoded, original);
    }

    #[test]
    fn parses_numeric_stun_endpoints() {
        assert_eq!(
            parse_stun_servers("198.51.100.7:3478, [2001:db8::7]:3478").unwrap(),
            vec![
                "198.51.100.7:3478".parse().unwrap(),
                "[2001:db8::7]:3478".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parses_ice_urls_and_keeps_credentials_out_of_the_url_spec() {
        let urls = parse_ice_urls(
            "stun:stun.example:3478,turn:turn.example:3478?transport=udp",
            Some("user"),
            Some("password"),
        )
        .expect("parse ICE URLs");
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].host, "stun.example");
        assert_eq!(urls[1].host, "turn.example");
        assert_eq!(urls[1].username, "user");
        assert_eq!(urls[1].password, "password");
    }

    #[test]
    fn connection_path_serializes_without_addresses_or_credentials() {
        let direct = ConnectionPath::DirectUdp {
            candidate: CandidateKind::Relay,
        };
        assert_eq!(
            serde_json::to_string(&direct).expect("encode connection path"),
            r#"{"direct_udp":{"candidate":"relay"}}"#
        );
        assert_eq!(
            serde_json::to_string(&ConnectionPath::Ice).expect("encode ICE path"),
            r#""ice""#
        );
        let mapped = ConnectionPath::DirectUdp {
            candidate: CandidateKind::Mapped,
        };
        assert_eq!(
            serde_json::to_string(&mapped).expect("encode mapped path"),
            r#"{"direct_udp":{"candidate":"mapped"}}"#
        );
    }

    #[test]
    fn capability_intersection_prefers_h264_and_clamps_limits() {
        let mut host = Capabilities::host_default();
        host.max_width = 3840;
        host.max_height = 2160;
        host.max_fps = 144;
        let mut client = Capabilities::client_default();
        client.video_codecs = vec![VideoCodec::H264];
        client.max_width = 1920;
        client.max_height = 1080;
        client.max_fps = 60;
        let negotiated = negotiate(&host, &client).expect("common profile");
        assert_eq!(negotiated.video, VideoCodec::H264);
        assert_eq!(
            (negotiated.width, negotiated.height, negotiated.fps),
            (1920, 1080, 60)
        );
        assert_eq!(negotiated.audio, Some(AudioCodec::Opus));
        assert!(negotiated.input);
        assert!(!negotiated.video_10_bit);
        assert!(!negotiated.video_444);
        assert!(!negotiated.clipboard);
        assert!(!negotiated.microphone);
        assert!(!negotiated.multi_monitor);
        assert!(!negotiated.pen);
        assert!(!negotiated.rumble);
    }

    #[test]
    fn extended_capabilities_are_intersected_and_legacy_json_defaults_safely() {
        let legacy = br#"{"version":1,"video_codecs":["h264"],"audio_codecs":[],"max_width":1920,"max_height":1080,"max_fps":60,"input":false}"#;
        let decoded: Capabilities = serde_json::from_slice(legacy).expect("legacy capabilities");
        assert!(!decoded.video_10_bit);
        assert!(!decoded.clipboard);
        assert!(!decoded.rumble);
        assert!(!decoded.path_migration);

        let mut host = Capabilities::host_default();
        host.video_10_bit = true;
        host.video_444 = true;
        host.clipboard = true;
        host.microphone = true;
        host.multi_monitor = true;
        host.pen = true;
        host.rumble = true;
        let mut client = Capabilities::client_default();
        client.video_10_bit = true;
        client.video_444 = false;
        client.clipboard = true;
        client.microphone = true;
        client.multi_monitor = true;
        client.pen = true;
        client.rumble = false;
        let negotiated = negotiate(&host, &client).expect("extended profile");
        assert!(negotiated.video_10_bit);
        assert!(!negotiated.video_444);
        assert!(negotiated.clipboard);
        assert!(negotiated.microphone);
        assert!(negotiated.multi_monitor);
        assert!(negotiated.pen);
        assert!(!negotiated.rumble);
    }

    #[test]
    fn path_migration_requires_explicit_opt_in_from_both_peers() {
        let old_host = Capabilities::host_default();
        let old_client = Capabilities::client_default();
        assert!(!old_host.path_migration);
        assert!(!old_client.path_migration);
        assert!(
            !negotiate(&old_host, &old_client)
                .expect("legacy peers negotiate")
                .path_migration
        );

        let migration_host = Capabilities::host_default().with_path_migration();
        let migration_client = Capabilities::client_default().with_path_migration();
        assert!(
            !negotiate(&migration_host, &old_client)
                .expect("old client declines migration")
                .path_migration
        );
        assert!(
            !negotiate(&old_host, &migration_client)
                .expect("old host declines migration")
                .path_migration
        );
        assert!(
            negotiate(&migration_host, &migration_client)
                .expect("both peers opt in")
                .path_migration
        );
    }

    #[test]
    fn capability_messages_are_version_checked_and_role_checked() {
        let payload = encode_hello(Capabilities::host_default()).expect("encode hello");
        assert!(matches!(
            decode_capability_message(&payload).expect("decode hello"),
            CapabilityMessage::Hello {
                role: CapabilityRole::Host,
                ..
            }
        ));
        let mut capabilities = Capabilities::client_default();
        capabilities.version = CAPABILITY_VERSION + 1;
        let payload = serde_json::to_vec(&CapabilityMessage::HelloAck { capabilities })
            .expect("encode incompatible ack");
        assert!(matches!(
            decode_capability_message(&payload),
            Err(CapabilityError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn session_turn_credentials_stamp_only_turn_urls() {
        let pairing = pairing_with_turn();
        let turn = pairing.turn.as_ref().expect("pairing carries TURN");
        let urls = turn
            .apply_to_spec("stun:stun.example:3478,turn:turn.example:3478?transport=udp")
            .expect("apply TURN credentials");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].username.is_empty());
        assert!(urls[0].password.is_empty());
        assert_eq!(urls[1].username, "1700003600:session:host");
        assert_eq!(urls[1].password, "session-password");
    }

    #[test]
    fn pairing_without_turn_leaves_urls_credential_free() {
        let saved_urls = std::env::var("OPENSTREAM_ICE_URLS").ok();
        let saved_user = std::env::var("OPENSTREAM_TURN_USERNAME").ok();
        let saved_password = std::env::var("OPENSTREAM_TURN_PASSWORD").ok();
        unsafe {
            std::env::set_var(
                "OPENSTREAM_ICE_URLS",
                "stun:stun.example:3478,turn:turn.example:3478",
            );
            std::env::remove_var("OPENSTREAM_TURN_USERNAME");
            std::env::remove_var("OPENSTREAM_TURN_PASSWORD");
        }
        let urls = ice_urls_for_pairing(&pairing()).expect("credential-free URLs");
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().all(|url| url.username.is_empty()));
        let urls = ice_urls_for_pairing(&pairing_with_turn()).expect("session TURN URLs");
        assert_eq!(urls[1].username, "1700003600:session:host");
        unsafe {
            std::env::set_var("OPENSTREAM_TURN_USERNAME", "lab-user");
            std::env::set_var("OPENSTREAM_TURN_PASSWORD", "lab-password");
        }
        // Explicit lab credentials win over pairing-embedded session ones.
        let urls = ice_urls_for_pairing(&pairing_with_turn()).expect("lab override URLs");
        assert_eq!(urls[1].username, "lab-user");
        assert_eq!(urls[1].password, "lab-password");
        unsafe {
            match saved_urls {
                Some(previous) => std::env::set_var("OPENSTREAM_ICE_URLS", previous),
                None => std::env::remove_var("OPENSTREAM_ICE_URLS"),
            }
            match saved_user {
                Some(previous) => std::env::set_var("OPENSTREAM_TURN_USERNAME", previous),
                None => std::env::remove_var("OPENSTREAM_TURN_USERNAME"),
            }
            match saved_password {
                Some(previous) => std::env::set_var("OPENSTREAM_TURN_PASSWORD", previous),
                None => std::env::remove_var("OPENSTREAM_TURN_PASSWORD"),
            }
        }
    }

    #[test]
    fn pairing_with_turn_round_trips_as_json() {
        let original = pairing_with_turn();
        let encoded = serde_json::to_string(&original).expect("encode pairing");
        let decoded: Pairing = serde_json::from_str(&encoded).expect("decode pairing");
        assert_eq!(decoded, original);
        // Legacy pairing files without credentials decode with no TURN.
        let legacy = serde_json::to_string(&pairing()).expect("encode legacy pairing");
        let legacy_value: serde_json::Value =
            serde_json::from_str(&legacy).expect("decode legacy JSON");
        assert_eq!(legacy_value.get("turn"), Some(&serde_json::Value::Null));
        let decoded: Pairing = serde_json::from_str(&legacy).expect("decode legacy pairing");
        assert_eq!(decoded.turn, None);
    }

    #[test]
    fn generation_local_path_baseline_uses_decimal_mbps() {
        let now = std::time::Instant::now();
        let mut baseline = None;
        let initial = openstream_transport::TransportSample {
            path_generation: openstream_transport::FIRST_PATH_GENERATION,
            sent_packets: 0,
            sent_wire_bytes: 0,
            received_packets: 0,
            received_wire_bytes: 0,
            sample_interval_ms: 0,
            send_rate_mbps: 0.0,
            receive_rate_mbps: 0.0,
        };
        assert_eq!(sample_path_counters(initial, now, &mut baseline), None);

        let sampled = sample_path_counters(
            openstream_transport::TransportSample {
                sent_packets: 1,
                sent_wire_bytes: 125_000,
                received_packets: 2,
                received_wire_bytes: 250_000,
                ..initial
            },
            now + Duration::from_secs(1),
            &mut baseline,
        )
        .expect("one-second sample");
        assert_eq!(sampled.sample_interval_ms, 1_000);
        assert!((sampled.send_rate_mbps - 1.0).abs() < f64::EPSILON);
        assert!((sampled.receive_rate_mbps - 2.0).abs() < f64::EPSILON);
    }
}
