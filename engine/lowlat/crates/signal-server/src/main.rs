//! Small self-hosted signaling service for OpenStream.
//!
//! This is intentionally an application-owned control plane. It does not
//! accept Parsec credentials and it does not pretend to be the Parsec service.
//! A pairing response gives the host and client separate, short-lived bearer
//! capabilities. WebSocket messages are validated as JSON objects and then
//! forwarded only to the opposite role in the same session.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{Sink, SinkExt, StreamExt};
use openstream_protocol::relay;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use uuid::Uuid;

mod turn;

/// Relay-ticket issuance and verification (H11).
///
/// The role bearer token must never transit the UDP relay path: it is a
/// WebSocket API capability. Instead, role holders fetch a relay ticket over
/// the authenticated REST API (`GET /v1/session/{id}/relay`) and present
/// that in the plaintext relay registration. A ticket is
/// `hex(HMAC-SHA256(server HMAC input, "relay-ticket-v2" || 0x00 || session_id ||
/// 0x00 || role_class || 0x00 || subject || 0x00 || socket_generation_be ||
/// optional proof digest)) || "." || socket_generation || "." || subject`
/// for the initial pairing ticket, or the same fields followed by
/// `"." || proof_digest_hex` for a ticket minted after a WebSocket connection
/// proves ownership of its current socket. The proof digest is included in
/// the MAC and in the opaque ticket, but the proof itself is never serialized
/// into a relay ticket or logged. This binds reissued tickets to the current
/// role, socket generation, and per-connection proof while keeping the first
/// pairing ticket usable before either WebSocket exists. The subject is an
/// opaque role name (`host`/`client`) or guest id; it is not a bearer token.
mod relay_ticket {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Role classes a ticket can be bound to. Guests register as `client`.
    pub(crate) fn role_class(host: bool) -> &'static str {
        if host { "host" } else { "client" }
    }

    const MAX_SUBJECT_BYTES: usize = 64;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Verified {
        pub class: &'static str,
        pub subject: String,
        pub socket_generation: u64,
        /// A bound ticket carries only the digest of the current socket
        /// proof. The raw proof remains confined to the authenticated REST
        /// request and the current WebSocket task.
        pub proof_digest: Option<[u8; 32]>,
    }

    pub(crate) fn mint(
        secret: &[u8],
        session_id: &str,
        class: &str,
        subject: &str,
        socket_generation: u64,
    ) -> String {
        mint_with_digest(secret, session_id, class, subject, socket_generation, None)
    }

    /// Mint a ticket bound to the proof delivered to one current signaling
    /// socket. The proof is reduced to a domain-separated digest before it is
    /// included in the relay-only capability, so the raw proof cannot leak
    /// through a relay registration or ticket rendering.
    pub(crate) fn mint_bound(
        secret: &[u8],
        session_id: &str,
        class: &str,
        subject: &str,
        socket_generation: u64,
        proof: &str,
    ) -> String {
        let digest = proof_digest(proof);
        mint_with_digest(
            secret,
            session_id,
            class,
            subject,
            socket_generation,
            Some(digest),
        )
    }

    pub(crate) fn proof_digest(proof: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"openstream relay proof v1\x00");
        hasher.update(proof.as_bytes());
        hasher.finalize().into()
    }

    fn mint_with_digest(
        secret: &[u8],
        session_id: &str,
        class: &str,
        subject: &str,
        socket_generation: u64,
        proof_digest: Option<[u8; 32]>,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key");
        mac.update(b"relay-ticket-v2");
        mac.update(b"\x00");
        mac.update(session_id.as_bytes());
        mac.update(b"\x00");
        mac.update(class.as_bytes());
        mac.update(b"\x00");
        mac.update(subject.as_bytes());
        mac.update(b"\x00");
        mac.update(&socket_generation.to_be_bytes());
        if let Some(proof_digest) = proof_digest {
            mac.update(b"\x00proof-digest-v1\x00");
            mac.update(&proof_digest);
        }
        let bytes = mac.finalize().into_bytes();
        let generation = socket_generation.to_string();
        let mut out = String::with_capacity(
            66 + generation.len() + subject.len() + proof_digest.map_or(0, |_| 65),
        );
        for byte in bytes {
            let _ = core::fmt::write(&mut out, format_args!("{byte:02x}"));
        }
        out.push('.');
        out.push_str(&generation);
        out.push('.');
        out.push_str(subject);
        if let Some(proof_digest) = proof_digest {
            out.push('.');
            for byte in proof_digest {
                let _ = core::fmt::write(&mut out, format_args!("{byte:02x}"));
            }
        }
        out
    }

    /// Verify a presented ticket against both role classes in constant time.
    /// Returns the matched class, non-secret principal subject, and the
    /// primary socket generation to which the ticket is bound.
    pub(crate) fn verify(secret: &[u8], session_id: &str, ticket: &str) -> Option<Verified> {
        let (mac, rest) = ticket.split_once('.')?;
        let (generation_text, subject_and_proof) = rest.split_once('.')?;
        let socket_generation = generation_text.parse::<u64>().ok()?;
        let (subject, proof_digest) = match subject_and_proof.rsplit_once('.') {
            Some((subject, encoded)) if encoded.len() == 64 => {
                let mut digest = [0_u8; 32];
                for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
                    let high = u8::try_from((chunk[0] as char).to_digit(16)?).ok()?;
                    let low = u8::try_from((chunk[1] as char).to_digit(16)?).ok()?;
                    digest[index] = (high << 4) | low;
                }
                (subject, Some(digest))
            }
            _ => (subject_and_proof, None),
        };
        if mac.len() != 64
            || socket_generation == 0
            || socket_generation.to_string() != generation_text
            || subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || !subject
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return None;
        }
        [role_class(true), role_class(false)]
            .into_iter()
            .find(|class| {
                let expected = mint_with_digest(
                    secret,
                    session_id,
                    class,
                    subject,
                    socket_generation,
                    proof_digest,
                );
                super::ct_eq(&expected, ticket)
            })
            .map(|class| Verified {
                class,
                subject: subject.to_string(),
                socket_generation,
                proof_digest,
            })
    }
}

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_TTL_SECONDS: u64 = 3600;
const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_PENDING_MESSAGES: usize = 128;
// A fresh socket receives its proof before its pending queue. Reserve one
// additional slot so a full pending queue can still be transferred without
// turning a valid reconnect into fail-closed admission failure.
const MAX_OUTBOUND_MESSAGES: usize = MAX_PENDING_MESSAGES + 1;
const MAX_DIRECT_CANDIDATES: u64 = 32;
const RESET_REASON_ROLE_REPLACED: &str = "role_replaced";
const RESET_REASON_PEER_DISCONNECTED: &str = "peer_disconnected";
const RESET_REASON_DELIVERY_FAILED: &str = "delivery_failed";
const RELAY_PROOF_HEADER: &str = "x-openstream-connection-proof";
const TERMINAL_WRITE_TIMEOUT: Duration = Duration::from_millis(500);
/// Maximum queued signaling bytes per pending queue. Queues are dropped-new
/// past this so a flooding peer cannot flush handshake messages or grow a
/// session's memory without bound.
const MAX_PENDING_BYTES: usize = 1024 * 1024;
const MAX_SESSION_CREATES_PER_MINUTE: usize = 60;
const SESSION_CREATE_WINDOW: Duration = Duration::from_secs(60);
/// Default cap on admitted guest tokens per session (active + parked).
const DEFAULT_MAX_GUESTS: usize = 4;
/// Hard ceiling for the per-session guest cap.
const MAX_GUESTS_CEILING: usize = 16;
/// Cap on live sessions per process. Creation past this fails with 503 so one
/// tenant cannot grow the map without bound.
const MAX_LIVE_SESSIONS: usize = 4096;
/// Idle time after which an unused relay slot is reaped.
const RELAY_SLOT_IDLE: Duration = Duration::from_secs(60);
/// WebSocket control connections are kept alive with protocol-level pings so
/// dead NAT mappings and mobile-suspended peers are removed without waiting
/// for a session TTL.
const SIGNAL_PING_INTERVAL: Duration = Duration::from_secs(15);
const SIGNAL_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Expired sessions are reaped even when no client sends another request and
/// the optional relay is disabled.
const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(30);
/// An administrator token is a network capability, so a one-character token
/// is almost certainly an accidental insecure deployment.
const MIN_ADMIN_TOKEN_BYTES: usize = 16;
/// A valid relay ticket is still only a capability for one bounded data path.
/// These budgets stop it becoming an unlimited bandwidth amplification tool.
const RELAY_BYTES_PER_SECOND: usize = 8 * 1024 * 1024;
const RELAY_PACKETS_PER_SECOND: u32 = 10_000;

/// Length-timing-safe equality for bearer tokens.
///
/// Not a substitute for short random tokens (which these are: 128-bit
/// UUIDv4), but avoids the early-exit oracle of `==` as hygiene.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    session_creates: Arc<Mutex<CreationLimiter>>,
    admin_token: Option<String>,
    /// Explicit loopback development mode. With no admin token and without
    /// this flag, management endpoints refuse every request.
    allow_no_auth: bool,
    relay_address: Option<SocketAddr>,
    turn: Option<turn::TurnConfig>,
    /// Server-side secret for relay-ticket MACs. Random per boot unless
    /// `OPENSTREAM_RELAY_SECRET` is set (tickets do not survive restarts
    /// with a random secret, which is acceptable: clients re-fetch).
    relay_secret: Vec<u8>,
}

impl core::fmt::Debug for AppState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppState")
            .field("sessions", &self.sessions)
            .field("session_creates", &self.session_creates)
            // Tokens and the relay secret never render in logs.
            .field(
                "admin_token",
                &self.admin_token.as_ref().map(|_| "[redacted]"),
            )
            .field("allow_no_auth", &self.allow_no_auth)
            .field("relay_address", &self.relay_address)
            .field("turn", &self.turn)
            .field("relay_secret", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct CreationLimiter {
    events: VecDeque<Instant>,
}

impl CreationLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        self.events
            .retain(|created| now.saturating_duration_since(*created) < SESSION_CREATE_WINDOW);
        if self.events.len() >= MAX_SESSION_CREATES_PER_MINUTE {
            return false;
        }
        self.events.push_back(now);
        true
    }
}

struct Session {
    expires_at: Instant,
    host_token: String,
    client_token: String,
    host: Option<mpsc::Sender<Message>>,
    client: Option<mpsc::Sender<Message>>,
    /// Per-current-socket relay proofs. These are delivered only to the
    /// authenticated WebSocket that owns the corresponding generation and
    /// are required before the REST API will mint a replacement ticket.
    host_relay_proof: Option<String>,
    client_relay_proof: Option<String>,
    /// Cancellation channels owned by the corresponding WebSocket tasks.
    /// They are independent of the bounded outbound queues so fail-closed
    /// teardown cannot be defeated by queue saturation.
    host_cancel: Option<oneshot::Sender<()>>,
    client_cancel: Option<oneshot::Sender<()>>,
    /// Connection generations: incremented on every admit, captured by the
    /// connection task, and compared on disconnect cleanup so a stale
    /// connection can never clear a newer connection's sender.
    host_generation: u64,
    client_generation: u64,
    /// Monotonic server-owned direct-establishment epoch. This is separate
    /// from the per-role socket generations above.
    establishment_generation: u64,
    /// The only direct epoch currently usable by the exact current pair.
    ready_pair: Option<ReadyPair>,
    pending_host: VecDeque<Message>,
    pending_client: VecDeque<Message>,
    pending_host_bytes: usize,
    pending_client_bytes: usize,
    relay_host: Option<RelaySlot>,
    relay_client: Option<RelaySlot>,
    guests: VecDeque<Guest>,
    max_guests: usize,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("expires_at", &self.expires_at)
            .field("host_token", &"[redacted]")
            .field("client_token", &"[redacted]")
            .field("host_connected", &self.host.is_some())
            .field("client_connected", &self.client.is_some())
            .field("host_cancellable", &self.host_cancel.is_some())
            .field("client_cancellable", &self.client_cancel.is_some())
            .field("establishment_generation", &self.establishment_generation)
            .field("ready_pair", &self.ready_pair)
            .field("pending_host", &self.pending_host.len())
            .field("pending_client", &self.pending_client.len())
            .field("relay_host", &self.relay_host)
            .field("relay_client", &self.relay_client)
            .field("guests", &self.guests)
            .field("max_guests", &self.max_guests)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadyPair {
    establishment_generation: u64,
    host_generation: u64,
    client_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimaryRole {
    Host,
    Client,
}

impl PrimaryRole {
    fn opposite(self) -> Self {
        match self {
            Self::Host => Self::Client,
            Self::Client => Self::Host,
        }
    }
}

#[derive(Debug)]
enum DirectRoute {
    Forward(mpsc::Sender<Message>),
    DropStale,
    NotReady,
    Future,
    StaleSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectDispatch {
    Sent,
    DropStale,
    NotReady,
    Future,
    StaleSocket,
    Missing,
    SendFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenericDispatch {
    Sent,
    Queued,
    Missing,
    StaleSocket,
    SendFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessError {
    CounterExhausted,
    DeliveryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionError {
    SocketGenerationExhausted,
    Readiness(ReadinessError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalDelivery {
    Delivered,
    NotDelivered,
}

/// Drive a WebSocket writer with a bounded normal queue and an out-of-band
/// terminal command. The terminal command is deliberately selected while a
/// normal `Sink::send` is in flight: canceling that future and dropping the
/// sink is safer than allowing a protocol error to wait indefinitely behind a
/// stalled socket. A terminal message is reported as delivered only after
/// its own send/flush future completes successfully.
async fn writer_loop<S>(
    mut sink: S,
    mut out_rx: mpsc::Receiver<Message>,
    mut terminal_rx: oneshot::Receiver<Message>,
    result_tx: oneshot::Sender<TerminalDelivery>,
) where
    S: Sink<Message> + Unpin,
    S::Error: Send + 'static,
{
    loop {
        tokio::select! {
            biased;
            terminal = &mut terminal_rx => {
                let Ok(terminal) = terminal else {
                    return;
                };
                let delivery = match tokio::time::timeout(
                    TERMINAL_WRITE_TIMEOUT,
                    sink.send(terminal),
                )
                .await
                {
                    Ok(Ok(())) => TerminalDelivery::Delivered,
                    Ok(Err(_)) | Err(_) => TerminalDelivery::NotDelivered,
                };
                let _ = result_tx.send(delivery);
                return;
            }
            message = out_rx.recv() => {
                let Some(message) = message else {
                    return;
                };
                // Once a normal send has started, keep the terminal command
                // able to cancel it. This branch intentionally does not try
                // to reuse the sink after cancellation: a Sink may have
                // accepted the normal item into internal buffers, so closing
                // by dropping the sink avoids claiming either item was sent.
                tokio::select! {
                    biased;
                    terminal = &mut terminal_rx => {
                        let _ = terminal;
                        let _ = result_tx.send(TerminalDelivery::NotDelivered);
                        return;
                    }
                    result = sink.send(message) => {
                        if result.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// One relay endpoint registration: the source address plus which session
/// token owns it, and when it last carried traffic (idle slots are reaped).
#[derive(Clone)]
struct RelaySlot {
    addr: SocketAddr,
    /// Redacted owner identity: "host", "client", or a guest id.
    owner: String,
    /// Primary/guest signaling-socket generation bound into the ticket.
    socket_generation: u64,
    /// Hash of the registration ticket. Keeping only a digest lets the relay
    /// distinguish a stale cleanup request from a newer registration without
    /// retaining or rendering the bearer capability itself.
    ticket_digest: [u8; 32],
    last_seen: Instant,
    window_started: Instant,
    window_bytes: usize,
    window_packets: u32,
}

impl core::fmt::Debug for RelaySlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelaySlot")
            .field("addr", &self.addr)
            .field("owner", &self.owner)
            .field("socket_generation", &self.socket_generation)
            .field("ticket_digest", &"[redacted]")
            .field("last_seen", &self.last_seen)
            .field("window_started", &self.window_started)
            .field("window_bytes", &self.window_bytes)
            .field("window_packets", &self.window_packets)
            .finish()
    }
}

fn relay_ticket_digest(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

impl RelaySlot {
    fn accept(&mut self, bytes: usize, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.window_bytes = 0;
            self.window_packets = 0;
        }
        if self.window_packets >= RELAY_PACKETS_PER_SECOND
            || self.window_bytes.saturating_add(bytes) > RELAY_BYTES_PER_SECOND
        {
            return false;
        }
        self.window_packets = self.window_packets.saturating_add(1);
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        self.last_seen = now;
        true
    }
}

/// One admitted guest: a bearer token plus its permission tier.
///
/// Media stays 1:1 -- the first connected guest (or the legacy client token
/// holder) is bridged to the host while further guests park. Permissions
/// are recorded here and reported to the host; hosts apply them.
struct Guest {
    /// Stable opaque id for listings (random at admission, safe to log).
    id: String,
    token: String,
    input: bool,
    sender: Option<mpsc::Sender<Message>>,
    pending: VecDeque<Message>,
    pending_bytes: usize,
    active: bool,
    /// Connection generation, mirroring the host/client scheme.
    generation: u64,
    /// Proof delivered to this guest's current WebSocket. It is required for
    /// reissuing a relay ticket after a guest socket replacement.
    relay_proof: Option<String>,
}

impl core::fmt::Debug for Guest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Guest")
            .field("id", &self.id)
            .field("token", &"[redacted]")
            .field("input", &self.input)
            .field("connected", &self.sender.is_some())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Guest {
    fn redacted(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "input": self.input,
            "connected": self.sender.is_some(),
            "active": self.active,
        })
    }
}

/// Per-session guest cap from `OPENSTREAM_MAX_GUESTS`, bounded to
/// `1..=MAX_GUESTS_CEILING` so one deployment cannot mint unbounded tokens.
fn max_guests_for_new_session() -> usize {
    std::env::var("OPENSTREAM_MAX_GUESTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_GUESTS)
        .clamp(1, MAX_GUESTS_CEILING)
}

#[derive(Debug, Deserialize)]
struct CreateSession {
    ttl_seconds: Option<u64>,
}

/// Whether this guest may send input (default false: observe-only).
#[derive(Debug, Deserialize)]
struct CreateGuest {
    #[serde(default)]
    input: bool,
}

#[derive(Debug, Serialize)]
struct GuestCreated {
    /// Stable non-secret identifier used by management endpoints. The bearer
    /// token is returned separately and must never be placed in a URL.
    guest_id: String,
    guest_token: String,
    input: bool,
}

/// Admit one guest. Authenticated by the host role token or the admin token:
/// admission is the host's decision (operators holding only the admin token
/// can admit for recovery), and the token is returned once here, never logged.
async fn create_guest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(request): Json<CreateGuest>,
) -> Response {
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
    };
    if session.expires_at <= Instant::now() {
        sessions.remove(&session_id);
        return (StatusCode::GONE, "session expired\n").into_response();
    }
    let host = supplied_token_is_host(&headers, session);
    let admin = admin_allowed(&state, &headers);
    if !(host || admin) {
        return (StatusCode::UNAUTHORIZED, "host authorization required\n").into_response();
    }
    if session.guests.len() >= session.max_guests {
        return (StatusCode::CONFLICT, "guest cap reached\n").into_response();
    }
    let token = Uuid::new_v4().simple().to_string();
    let guest_id = Uuid::new_v4().simple().to_string();
    session.guests.push_back(Guest {
        id: guest_id.clone(),
        token: token.clone(),
        input: request.input,
        sender: None,
        pending: VecDeque::new(),
        pending_bytes: 0,
        active: false,
        generation: 0,
        relay_proof: None,
    });
    Json(GuestCreated {
        guest_id,
        guest_token: token,
        input: request.input,
    })
    .into_response()
}

/// List admitted guests with tokens redacted to an id prefix.
/// Authenticated by the host role token or the admin token.
async fn list_guests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
    };
    if session.expires_at <= Instant::now() {
        sessions.remove(&session_id);
        return (StatusCode::GONE, "session expired\n").into_response();
    }
    let host = supplied_token_is_host(&headers, session);
    let admin = admin_allowed(&state, &headers);
    if !(host || admin) {
        return (StatusCode::UNAUTHORIZED, "host authorization required\n").into_response();
    }
    let guests: Vec<serde_json::Value> = session.guests.iter().map(Guest::redacted).collect();
    Json(guests).into_response()
}

/// Kick one admitted guest by its stable non-secret id. Authenticated by the
/// host role token or the admin token; the guest WebSocket is closed promptly.
async fn kick_guest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((session_id, guest_id)): Path<(String, String)>,
) -> Response {
    let (sender, promotion) = {
        let mut sessions = state.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
        };
        if session.expires_at <= Instant::now() {
            sessions.remove(&session_id);
            return (StatusCode::GONE, "session expired\n").into_response();
        }
        let host = supplied_token_is_host(&headers, session);
        let admin = admin_allowed(&state, &headers);
        if !(host || admin) {
            return (StatusCode::UNAUTHORIZED, "host authorization required\n").into_response();
        }
        let Some(position) = session.guests.iter().position(|guest| guest.id == guest_id) else {
            return (StatusCode::NOT_FOUND, "unknown guest\n").into_response();
        };
        let kicked = session
            .guests
            .remove(position)
            .expect("guest position checked");
        // A kicked guest must lose the data path too: clear any relay slot
        // it owned so it cannot keep pushing media until session expiry.
        let kicked_id = kicked.id.clone();
        for slot in [&mut session.relay_host, &mut session.relay_client] {
            if slot.as_ref().is_some_and(|owned| owned.owner == kicked_id) {
                *slot = None;
            }
        }
        let promotion = if kicked.active {
            take_promotion_sender(session)
        } else {
            None
        };
        (kicked.sender, promotion)
    };
    if let Some(sender) = sender {
        let _ = sender.try_send(Message::Close(None));
    }
    if let Some(promotion) = promotion {
        let _ = promotion.try_send(Message::Text("{\"type\":\"promoted\"}".into()));
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}

/// Promote the first parked connected guest after the active one leaves.
/// Collects the notice sender while the caller holds the session map lock;
/// the caller sends after releasing it so a stalled guest cannot block all
/// session administration behind one bounded channel.
fn take_promotion_sender(session: &mut Session) -> Option<mpsc::Sender<Message>> {
    let next = session
        .guests
        .iter_mut()
        .find(|guest| guest.sender.is_some() && !guest.active)?;
    next.active = true;
    next.sender.clone()
}

fn supplied_token_is_host(headers: &HeaderMap, session: &Session) -> bool {
    bearer_token(headers).is_some_and(|token| ct_eq(token, &session.host_token))
}

#[derive(Debug, Serialize)]
struct SessionCreated {
    session_id: String,
    host_token: String,
    client_token: String,
    websocket_path: String,
    expires_in_seconds: u64,
    relay_address: Option<String>,
    relay_host_ticket: String,
    relay_client_ticket: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    Host,
    Client,
    Guest(String),
}

impl Role {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "host" => Some(Self::Host),
            "client" => Some(Self::Client),
            _ => None,
        }
    }

    fn token(&self, session: &Session) -> Option<String> {
        match self {
            Self::Host => Some(session.host_token.clone()),
            Self::Client => Some(session.client_token.clone()),
            Self::Guest(token) => session
                .guests
                .iter()
                .any(|guest| ct_eq(&guest.token, token))
                .then(|| token.clone()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("OPENSTREAM_SIGNAL_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let address: SocketAddr = bind.parse()?;
    let relay_bind = std::env::var("OPENSTREAM_RELAY_BIND")
        .ok()
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    let relay_address = std::env::var("OPENSTREAM_RELAY_ENDPOINT")
        .ok()
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    if relay_address.is_some() && relay_bind.is_none() {
        return Err("OPENSTREAM_RELAY_ENDPOINT requires OPENSTREAM_RELAY_BIND".into());
    }
    let relay_secret = match std::env::var("OPENSTREAM_RELAY_SECRET") {
        Ok(secret) if secret.len() >= 16 => secret.into_bytes(),
        Ok(_) => {
            return Err("OPENSTREAM_RELAY_SECRET must be at least 16 bytes".into());
        }
        Err(std::env::VarError::NotPresent) => {
            eprintln!(
                "OPENSTREAM_RELAY_SECRET is unset; using a boot-random relay secret (relay tickets do not survive restarts)"
            );
            Uuid::new_v4().into_bytes().to_vec()
        }
        Err(error) => return Err(format!("failed to read OPENSTREAM_RELAY_SECRET: {error}").into()),
    };
    let admin_token = match std::env::var("OPENSTREAM_ADMIN_TOKEN") {
        Ok(token) if token.len() >= MIN_ADMIN_TOKEN_BYTES => Some(token),
        Ok(_) => {
            return Err(format!(
                "OPENSTREAM_ADMIN_TOKEN must be at least {MIN_ADMIN_TOKEN_BYTES} bytes"
            )
            .into());
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(format!("failed to read OPENSTREAM_ADMIN_TOKEN: {error}").into()),
    };
    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
        admin_token,
        allow_no_auth: std::env::var("OPENSTREAM_ALLOW_NO_AUTH").as_deref() == Ok("1"),
        relay_address,
        turn: turn::TurnConfig::from_env(),
        relay_secret,
    };
    if !state.allow_no_auth && state.admin_token.is_none() {
        eprintln!(
            "OPENSTREAM_ADMIN_TOKEN is unset and OPENSTREAM_ALLOW_NO_AUTH is not 1: session management endpoints will refuse every request"
        );
    }
    // Fail closed: a non-loopback bind without an admin token would expose
    // management to the network with no authentication.
    if state.admin_token.is_none() && !address.ip().is_loopback() {
        return Err(
            "refusing non-loopback OPENSTREAM_SIGNAL_BIND without OPENSTREAM_ADMIN_TOKEN".into(),
        );
    }
    let admin_enabled = state.admin_token.is_some();
    if state.turn.is_none() {
        eprintln!(
            "OPENSTREAM_TURN_SECRET/OPENSTREAM_TURN_URLS are unset; the /turn endpoint reports unavailable"
        );
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/session", post(create_session))
        .route(
            "/v1/session/{session_id}",
            axum::routing::delete(revoke_session),
        )
        .route("/v1/session/{session_id}/turn", get(session_turn))
        .route("/v1/session/{session_id}/relay", get(session_relay_ticket))
        .route(
            "/v1/session/{session_id}/guests",
            post(create_guest).get(list_guests),
        )
        .route(
            "/v1/session/{session_id}/guests/{guest_id}",
            axum::routing::delete(kick_guest),
        )
        .route("/v1/signal/{session_id}/{role}", get(signal_socket))
        .with_state(state.clone());

    println!("openstream-signal-server listening on http://{address}");
    if !admin_enabled {
        eprintln!(
            "OPENSTREAM_ADMIN_TOKEN is unset; management endpoints require OPENSTREAM_ALLOW_NO_AUTH=1 (loopback development only)"
        );
    }
    let listener = tokio::net::TcpListener::bind(address).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let relay_task = if let Some(relay_bind) = relay_bind {
        let socket = UdpSocket::bind(relay_bind).await?;
        println!("openstream UDP relay listening on {relay_bind}");
        Some(tokio::spawn(run_relay(
            socket,
            state.clone(),
            shutdown_rx.clone(),
        )))
    } else {
        None
    };
    let reaper_task = tokio::spawn(reap_sessions(state.clone(), shutdown_rx.clone()));
    let signal_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
        .await;
    let _ = shutdown_tx.send(true);
    if let Some(task) = relay_task {
        let _ = task.await;
    }
    let _ = reaper_task.await;
    signal_task.abort();
    result?;
    Ok(())
}

/// Wait for the shared shutdown flag used by HTTP, relay, and reaper tasks.
async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

/// Handle both Ctrl-C in a terminal and SIGTERM from systemd on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn healthz() -> &'static str {
    "ok\n"
}

/// Remove expired sessions independently of request and relay traffic.
///
/// Without this task, an otherwise idle service can retain expired sessions
/// and their role senders indefinitely when the built-in relay is disabled.
/// The map is bounded, but retaining stale capabilities makes memory usage and
/// operational state depend on future session creation instead of TTL.
async fn reap_sessions(state: AppState, shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(SESSION_REAP_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let senders = reap_expired_sessions(&state).await;
                for sender in senders {
                    let _ = sender.try_send(Message::Close(None));
                }
            }
            _ = wait_for_shutdown(shutdown.clone()) => break,
        }
    }
}

/// Remove expired sessions and return their live WebSocket senders for a
/// close notice after the map lock is released.
async fn reap_expired_sessions(state: &AppState) -> Vec<mpsc::Sender<Message>> {
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    let expired = sessions
        .iter()
        .filter(|(_, session)| session.expires_at <= now)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let mut senders = Vec::new();
    for id in expired {
        let Some(mut session) = sessions.remove(&id) else {
            continue;
        };
        if let Some(cancel) = session.host_cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(cancel) = session.client_cancel.take() {
            let _ = cancel.send(());
        }
        senders.extend(session.host.take());
        senders.extend(session.client.take());
        senders.extend(
            session
                .guests
                .iter_mut()
                .filter_map(|guest| guest.sender.take()),
        );
    }
    senders
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSession>,
) -> Response {
    if !admin_allowed(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "admin authorization required\n").into_response();
    }
    if !state.session_creates.lock().await.allow(Instant::now()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "session creation rate limit exceeded\n",
        )
            .into_response();
    }
    let ttl = request
        .ttl_seconds
        .unwrap_or(DEFAULT_TTL_SECONDS)
        .clamp(1, MAX_TTL_SECONDS);
    let id = Uuid::new_v4().simple().to_string();
    let host_token = Uuid::new_v4().simple().to_string();
    let client_token = Uuid::new_v4().simple().to_string();

    let session = Session {
        expires_at: Instant::now() + Duration::from_secs(ttl),
        host_token: host_token.clone(),
        client_token: client_token.clone(),
        host: None,
        client: None,
        host_relay_proof: None,
        client_relay_proof: None,
        host_cancel: None,
        client_cancel: None,
        host_generation: 0,
        client_generation: 0,
        establishment_generation: 0,
        ready_pair: None,
        pending_host: VecDeque::new(),
        pending_client: VecDeque::new(),
        pending_host_bytes: 0,
        pending_client_bytes: 0,
        relay_host: None,
        relay_client: None,
        guests: VecDeque::new(),
        max_guests: max_guests_for_new_session(),
    };
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, existing| existing.expires_at > now);
    if sessions.len() >= MAX_LIVE_SESSIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "session capacity reached\n",
        )
            .into_response();
    }
    sessions.insert(id.clone(), session);

    let websocket_path = format!("/v1/signal/{id}/{{host|client}}");
    // The first admitted primary socket for each role is generation one. The
    // ticket returned with the pairing therefore remains usable when the
    // role connects for the first time, but cannot be reused after replace.
    let relay_host_ticket = relay_ticket::mint(&state.relay_secret, &id, "host", "host", 1);
    let relay_client_ticket = relay_ticket::mint(&state.relay_secret, &id, "client", "client", 1);
    // The tokens are capabilities, so return them only over the create
    // response. The service never logs them.
    Json(SessionCreated {
        session_id: id,
        host_token,
        client_token,
        websocket_path,
        expires_in_seconds: ttl,
        relay_address: state.relay_address.map(|address| address.to_string()),
        relay_host_ticket,
        relay_client_ticket,
    })
    .into_response()
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    if !admin_allowed(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "admin authorization required\n").into_response();
    }
    // Take every sender out while holding the map lock, then close after
    // releasing it. Guests are closed too: revocation ends the session for
    // all roles, and merely removing the map entry would leave idle guest
    // sockets half-open until TTL.
    let senders = {
        let mut sessions = state.sessions.lock().await;
        let Some(mut session) = sessions.remove(&session_id) else {
            return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
        };
        let mut senders = Vec::with_capacity(2 + session.guests.len());
        if let Some(cancel) = session.host_cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(cancel) = session.client_cancel.take() {
            let _ = cancel.send(());
        }
        senders.extend(session.host.take());
        senders.extend(session.client.take());
        senders.extend(
            session
                .guests
                .iter_mut()
                .filter_map(|guest| guest.sender.take()),
        );
        senders
    };
    for sender in senders {
        let _ = sender.try_send(Message::Close(None));
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}

#[derive(Debug, Serialize)]
struct TurnIssued {
    username: String,
    password: String,
    ttl_seconds: u64,
    urls: Vec<String>,
    realm: String,
}

/// Issue session-scoped TURN credentials for one session role.
///
/// Authentication reuses the role bearer token from the pairing response, so
/// only the admitted host, client, or active guest can mint credentials
/// bound to their own session. Guests mint `client`-class credentials: on
/// TURN-only networks the bridged guest is the media peer. The password is
/// returned once in this response and never logged.
///
/// The issued TTL never exceeds the session's remaining lifetime, so a
/// credential minted just before expiry cannot outlive the session at coturn
/// (instant revocation at coturn is still unsupported: keep TURN TTLs short).
async fn session_turn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    let Some(turn) = state.turn.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "TURN credential issuance is not configured\n",
        )
            .into_response();
    };
    let sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(&session_id) else {
        return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
    };
    if session.expires_at <= Instant::now() {
        return (StatusCode::GONE, "session expired\n").into_response();
    }
    let supplied_token = bearer_token(&headers);
    let role = match supplied_token {
        Some(token) if ct_eq(token, &session.host_token) => "host",
        Some(token) if ct_eq(token, &session.client_token) => "client",
        Some(token)
            if session
                .guests
                .iter()
                .any(|guest| guest.active && ct_eq(&guest.token, token)) =>
        {
            "client"
        }
        _ => return (StatusCode::UNAUTHORIZED, "invalid session token\n").into_response(),
    };
    let remaining = session
        .expires_at
        .saturating_duration_since(Instant::now())
        .as_secs();
    let Some(issued) = turn.issue_for_session(&session_id, role, turn::now_unix(), remaining)
    else {
        // The TURN REST API has a minimum useful credential lifetime. Refuse
        // a nearly expired session instead of minting a credential that would
        // remain valid after the OpenStream session is gone.
        return (
            StatusCode::CONFLICT,
            "session expires too soon for a TURN credential\n",
        )
            .into_response();
    };
    Json(TurnIssued {
        username: issued.username,
        password: issued.password,
        ttl_seconds: issued.ttl_seconds,
        urls: issued.urls,
        realm: issued.realm,
    })
    .into_response()
}

/// Issue a relay ticket for one session role (see [`relay_ticket`]).
///
/// Authenticated with the role bearer plus the proof delivered to that role's
/// current WebSocket (including the active guest). The initial pairing
/// response remains the only source of an unbound generation-one ticket; this
/// endpoint mints only a proof-bound replacement ticket. The ticket is
/// relay-only: it cannot be used on any WebSocket or REST management API.
async fn session_relay_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    let sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(&session_id) else {
        return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
    };
    if session.expires_at <= Instant::now() {
        return (StatusCode::GONE, "session expired\n").into_response();
    }
    let supplied_token = bearer_token(&headers);
    let supplied_proof = connection_proof(&headers);
    let (class, subject, socket_generation, proof) =
        if supplied_token.is_some_and(|token| ct_eq(token, &session.host_token)) {
            let Some(proof) = session.host_relay_proof.as_deref() else {
                return (
                    StatusCode::UNAUTHORIZED,
                    "current connection proof required\n",
                )
                    .into_response();
            };
            if session.host.is_none()
                || !supplied_proof.is_some_and(|candidate| ct_eq(candidate, proof))
            {
                return (
                    StatusCode::UNAUTHORIZED,
                    "current connection proof required\n",
                )
                    .into_response();
            }
            (
                "host",
                "host".to_string(),
                session.host_generation,
                Some(proof.to_string()),
            )
        } else if supplied_token.is_some_and(|token| ct_eq(token, &session.client_token)) {
            let Some(proof) = session.client_relay_proof.as_deref() else {
                return (
                    StatusCode::UNAUTHORIZED,
                    "current connection proof required\n",
                )
                    .into_response();
            };
            if session.client.is_none()
                || !supplied_proof.is_some_and(|candidate| ct_eq(candidate, proof))
            {
                return (
                    StatusCode::UNAUTHORIZED,
                    "current connection proof required\n",
                )
                    .into_response();
            }
            (
                "client",
                "client".to_string(),
                session.client_generation,
                Some(proof.to_string()),
            )
        } else if let Some(guest) = supplied_token.and_then(|token| {
            session.guests.iter().find(|guest| {
                guest.active
                    && guest.sender.is_some()
                    && ct_eq(&guest.token, token)
                    && guest.relay_proof.as_deref().is_some_and(|proof| {
                        supplied_proof.is_some_and(|candidate| ct_eq(candidate, proof))
                    })
            })
        }) {
            (
                "client",
                guest.id.clone(),
                guest.generation,
                guest.relay_proof.clone(),
            )
        } else {
            return (StatusCode::UNAUTHORIZED, "invalid session token\n").into_response();
        };
    #[derive(serde::Serialize)]
    struct RelayTicket {
        ticket: String,
        session_id: String,
        role_class: &'static str,
    }
    Json(RelayTicket {
        ticket: relay_ticket::mint_bound(
            &state.relay_secret,
            &session_id,
            class,
            &subject,
            socket_generation,
            proof
                .as_deref()
                .expect("authenticated current socket proof"),
        ),
        session_id: session_id.clone(),
        role_class: class,
    })
    .into_response()
}

/// Whether management endpoints (create/revoke/list/kick) may proceed.
///
/// With a configured admin token, the request must present it (constant-time
/// comparison, either header form). Without one, every request is refused
/// unless the operator explicitly opted into loopback development with
/// `OPENSTREAM_ALLOW_NO_AUTH=1` -- and startup already refuses a non-loopback
/// bind in that case, so the open mode cannot reach the network.
fn admin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    match state.admin_token.as_deref() {
        Some(expected) => authorized(headers, Some(expected)),
        None => state.allow_no_auth,
    }
}

fn authorized(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    if expected.is_empty() {
        return false;
    }
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let alternate = headers
        .get("x-openstream-admin-token")
        .and_then(|value| value.to_str().ok());
    bearer.is_some_and(|token| ct_eq(token, expected))
        || alternate.is_some_and(|token| ct_eq(token, expected))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn connection_proof(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(RELAY_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// Generate a fresh, non-loggable proof for one admitted signaling socket.
/// UUIDv4 supplies 128 bits of entropy and its simple representation is safe
/// in an HTTP header and in the authenticated server-generated envelope.
fn new_relay_proof() -> String {
    Uuid::new_v4().simple().to_string()
}

fn relay_proof_message(socket_generation: u64, proof: &str) -> Message {
    Message::Text(
        serde_json::json!({
            "type": "relay_ticket_proof",
            "socket_generation": socket_generation,
            "proof": proof,
        })
        .to_string()
        .into(),
    )
}

fn direct_ready_message(generation: u64) -> Message {
    Message::Text(
        serde_json::json!({
            "type": "peer_ready",
            "establishment_generation": generation,
        })
        .to_string()
        .into(),
    )
}

fn direct_reset_message(generation: u64, reason: &'static str) -> Message {
    Message::Text(
        serde_json::json!({
            "type": "peer_reset",
            "establishment_generation": generation,
            "reason": reason,
        })
        .to_string()
        .into(),
    )
}

fn direct_message_generation(message: &Message) -> Option<u64> {
    let Message::Text(text) = message else {
        return None;
    };
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let message_type = value.get("type").and_then(serde_json::Value::as_str)?;
    matches!(
        message_type,
        "direct_candidate" | "direct_candidate_done" | "direct_key"
    )
    .then(|| {
        value
            .get("establishment_generation")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    })
}

fn prune_direct_queue(queue: &mut VecDeque<Message>, queued_bytes: &mut usize) {
    queue.retain(|message| !is_direct_establishment_message(message));
    *queued_bytes = queue.iter().map(message_len).sum();
}

/// Remove only project-owned direct-establishment records. ICE and unrelated
/// signaling envelopes remain available to a reconnecting socket.
fn prune_direct_establishment_messages(session: &mut Session) {
    prune_direct_queue(&mut session.pending_host, &mut session.pending_host_bytes);
    prune_direct_queue(
        &mut session.pending_client,
        &mut session.pending_client_bytes,
    );
    for guest in &mut session.guests {
        prune_direct_queue(&mut guest.pending, &mut guest.pending_bytes);
    }
}

fn close_sender(sender: &mpsc::Sender<Message>) {
    let _ = sender.try_send(Message::Close(None));
}

/// Remove and close both primary senders, and revoke both primary relay
/// registrations. This is the only safe outcome when a readiness/reset or
/// admission operation cannot be completed atomically.
fn close_primary_pair(session: &mut Session) {
    if let Some(cancel) = session.host_cancel.take() {
        let _ = cancel.send(());
    }
    if let Some(cancel) = session.client_cancel.take() {
        let _ = cancel.send(());
    }
    let host = session.host.take();
    let client = session.client.take();
    session.host_relay_proof = None;
    session.client_relay_proof = None;
    if let Some(host) = host.as_ref() {
        close_sender(host);
    }
    if let Some(client) = client.as_ref() {
        close_sender(client);
    }
    clear_relay_owner(session, "host");
    clear_relay_owner(session, "client");
    session.ready_pair = None;
}

fn expire_primary_pair(session: &mut Session) {
    close_primary_pair(session);
    session.expires_at = Instant::now();
}

/// Publish one server-authoritative direct epoch to the exact current host and
/// client sockets. The generation is reserved before the two bounded enqueue
/// operations, so an enqueue failure burns the epoch rather than ever
/// allowing it to be reused.
fn publish_ready(session: &mut Session) -> Result<u64, ReadinessError> {
    let Some(host) = session.host.clone() else {
        close_primary_pair(session);
        return Err(ReadinessError::DeliveryFailed);
    };
    let Some(client) = session.client.clone() else {
        close_primary_pair(session);
        return Err(ReadinessError::DeliveryFailed);
    };
    let Some(generation) = session.establishment_generation.checked_add(1) else {
        expire_primary_pair(session);
        return Err(ReadinessError::CounterExhausted);
    };
    session.establishment_generation = generation;
    session.ready_pair = None;
    prune_direct_establishment_messages(session);

    let mut accepted_host = false;
    let mut accepted_client = false;
    if host.try_send(direct_ready_message(generation)).is_ok() {
        accepted_host = true;
    }
    if client.try_send(direct_ready_message(generation)).is_ok() {
        accepted_client = true;
    }
    if accepted_host && accepted_client {
        session.ready_pair = Some(ReadyPair {
            establishment_generation: generation,
            host_generation: session.host_generation,
            client_generation: session.client_generation,
        });
        return Ok(generation);
    }

    // A partial readiness publication is never a usable pair. Compensate the
    // sender that accepted readiness, then remove both current senders so the
    // next epoch can only be formed by a clean pair of sockets.
    if accepted_host {
        let reset = direct_reset_message(generation, RESET_REASON_DELIVERY_FAILED);
        if host.try_send(reset).is_err() {
            close_sender(&host);
        }
        close_sender(&host);
    }
    if accepted_client {
        let reset = direct_reset_message(generation, RESET_REASON_DELIVERY_FAILED);
        if client.try_send(reset).is_err() {
            close_sender(&client);
        }
        close_sender(&client);
    }
    close_primary_pair(session);
    Err(ReadinessError::DeliveryFailed)
}

/// Invalidate a currently published epoch while preserving the single current
/// sender for the role that did not change. A failed reset is fail-closed: the
/// survivor is dropped and no replacement readiness may be published.
fn invalidate_ready_epoch(
    session: &mut Session,
    reason: &'static str,
    survivor: Option<PrimaryRole>,
) -> Result<(), ReadinessError> {
    let Some(previous) = session.ready_pair.take() else {
        prune_direct_establishment_messages(session);
        return Ok(());
    };
    prune_direct_establishment_messages(session);
    let Some(survivor) = survivor else {
        return Ok(());
    };
    let sender = match survivor {
        PrimaryRole::Host => session.host.as_ref(),
        PrimaryRole::Client => session.client.as_ref(),
    };
    let Some(sender) = sender else {
        return Ok(());
    };
    if sender
        .try_send(direct_reset_message(
            previous.establishment_generation,
            reason,
        ))
        .is_err()
    {
        close_primary_pair(session);
        return Err(ReadinessError::DeliveryFailed);
    }
    Ok(())
}

/// Install a current host/client sender and, when the pair is complete,
/// publish the next direct epoch. This helper is deliberately synchronous
/// under the session-map lock so a replacement cannot race readiness.
fn admit_primary_socket(
    session: &mut Session,
    role: PrimaryRole,
    out_tx: &mpsc::Sender<Message>,
    cancel: oneshot::Sender<()>,
) -> Result<u64, AdmissionError> {
    let next_socket_generation = match role {
        PrimaryRole::Host => match session.host_generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                expire_primary_pair(session);
                return Err(AdmissionError::SocketGenerationExhausted);
            }
        },
        PrimaryRole::Client => match session.client_generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                expire_primary_pair(session);
                return Err(AdmissionError::SocketGenerationExhausted);
            }
        },
    };
    let replacing = match role {
        PrimaryRole::Host => session.host.is_some(),
        PrimaryRole::Client => session.client.is_some(),
    };
    if replacing {
        invalidate_ready_epoch(session, RESET_REASON_ROLE_REPLACED, Some(role.opposite()))
            .map_err(AdmissionError::Readiness)?;
    } else {
        // A disconnected role invalidates any stale direct queues even if the
        // previous ready pair was already cleared by cleanup.
        prune_direct_establishment_messages(session);
    }

    // A replacement must not inherit the old socket's relay registration. The
    // new connection will fetch/register a fresh ticket, while the old
    // registration is revoked immediately rather than waiting for stale task
    // cleanup.
    match role {
        PrimaryRole::Host => clear_relay_owner(session, "host"),
        PrimaryRole::Client => clear_relay_owner(session, "client"),
    }
    let relay_proof = new_relay_proof();

    let (old, old_cancel) = match role {
        PrimaryRole::Host => {
            session.host_generation = next_socket_generation;
            session.host_relay_proof = Some(relay_proof.clone());
            (
                session.host.replace(out_tx.clone()),
                session.host_cancel.replace(cancel),
            )
        }
        PrimaryRole::Client => {
            session.client_generation = next_socket_generation;
            session.client_relay_proof = Some(relay_proof.clone());
            (
                session.client.replace(out_tx.clone()),
                session.client_cancel.replace(cancel),
            )
        }
    };
    if let Some(old_cancel) = old_cancel {
        let _ = old_cancel.send(());
    }
    if let Some(old) = old.as_ref() {
        close_sender(old);
    }

    // The proof is a server-generated capability delivered only to the
    // current authenticated WebSocket. It must be queued before pending
    // generic signaling so a fresh connection can immediately reissue a
    // generation-bound relay ticket without exposing the proof in logs or
    // URLs. Failure is fail-closed just like readiness delivery.
    if out_tx
        .try_send(relay_proof_message(next_socket_generation, &relay_proof))
        .is_err()
    {
        close_primary_pair(session);
        return Err(AdmissionError::Readiness(ReadinessError::DeliveryFailed));
    }

    let pending = match role {
        PrimaryRole::Host => (&mut session.pending_host, &mut session.pending_host_bytes),
        PrimaryRole::Client => (
            &mut session.pending_client,
            &mut session.pending_client_bytes,
        ),
    };
    if !drain_into(pending.0, pending.1, out_tx) {
        close_primary_pair(session);
        return Err(AdmissionError::Readiness(ReadinessError::DeliveryFailed));
    }

    if session.host.is_some() && session.client.is_some() {
        publish_ready(session).map_err(AdmissionError::Readiness)?;
    }
    Ok(next_socket_generation)
}

/// Remove a primary sender only when the cleanup belongs to the current socket.
/// Stale tasks have no authority to invalidate the current direct epoch.
fn cleanup_primary_socket(session: &mut Session, role: PrimaryRole, generation: u64) -> bool {
    let current_generation = match role {
        PrimaryRole::Host => session.host_generation,
        PrimaryRole::Client => session.client_generation,
    };
    if current_generation != generation {
        return false;
    }
    match role {
        PrimaryRole::Host => {
            session.host.take();
            session.host_cancel.take();
            session.host_relay_proof.take();
        }
        PrimaryRole::Client => {
            session.client.take();
            session.client_cancel.take();
            session.client_relay_proof.take();
        }
    }
    let survivor = if session.host.is_some() {
        Some(PrimaryRole::Host)
    } else if session.client.is_some() {
        Some(PrimaryRole::Client)
    } else {
        None
    };
    let _ = invalidate_ready_epoch(session, RESET_REASON_PEER_DISCONNECTED, survivor);
    true
}

fn primary_socket_is_current(
    session: &Session,
    role: PrimaryRole,
    generation: u64,
    sender: &mpsc::Sender<Message>,
) -> bool {
    match role {
        PrimaryRole::Host => {
            session.host_generation == generation
                && session
                    .host
                    .as_ref()
                    .is_some_and(|current| current.same_channel(sender))
        }
        PrimaryRole::Client => {
            session.client_generation == generation
                && session
                    .client
                    .as_ref()
                    .is_some_and(|current| current.same_channel(sender))
        }
    }
}

/// Check that a WebSocket task still owns the sender published for its role.
/// The token check identifies the guest slot, while the generation and channel
/// checks prevent a stale task from forwarding or queueing after replacement.
fn role_socket_is_current(
    session: &Session,
    role: &Role,
    generation: u64,
    sender: &mpsc::Sender<Message>,
) -> bool {
    match role {
        Role::Host => primary_socket_is_current(session, PrimaryRole::Host, generation, sender),
        Role::Client => primary_socket_is_current(session, PrimaryRole::Client, generation, sender),
        Role::Guest(token) => session.guests.iter().any(|guest| {
            ct_eq(&guest.token, token)
                && guest.generation == generation
                && guest
                    .sender
                    .as_ref()
                    .is_some_and(|current| current.same_channel(sender))
        }),
    }
}

/// Validate the source and enqueue generic signaling while the session lock
/// is held. Keeping target selection and `try_send` in this critical section
/// prevents an old target sender from being copied, the role being replaced,
/// and the message then being delivered asynchronously to the stale socket.
fn dispatch_generic_message(
    session: &mut Session,
    role: &Role,
    generation: u64,
    sender: &mpsc::Sender<Message>,
    message: Message,
) -> GenericDispatch {
    if !role_socket_is_current(session, role, generation, sender) {
        return GenericDispatch::StaleSocket;
    }

    let peers = match role {
        Role::Host => {
            // Host announcements fan out to the legacy client and the active
            // guest.
            let mut peers = Vec::with_capacity(2);
            if let Some(client) = session.client.as_ref() {
                peers.push(client.clone());
            }
            if let Some(guest) = session
                .guests
                .iter()
                .find(|guest| guest.active)
                .and_then(|guest| guest.sender.as_ref())
            {
                peers.push(guest.clone());
            }
            peers
        }
        Role::Client | Role::Guest(_) => session
            .host
            .as_ref()
            .map(|host| vec![host.clone()])
            .unwrap_or_default(),
    };

    if peers.is_empty() {
        // Drop-new past the bounds: the oldest queued messages are usually
        // the handshake, which must survive a flooding peer.
        match role {
            Role::Host => {
                // Prefer the active guest's queue when one is bridged;
                // otherwise use the legacy client queue.
                if let Some(guest) = session.guests.iter_mut().find(|guest| guest.active) {
                    queue_pending(&mut guest.pending, &mut guest.pending_bytes, message);
                } else {
                    queue_pending(
                        &mut session.pending_client,
                        &mut session.pending_client_bytes,
                        message,
                    );
                }
            }
            Role::Client | Role::Guest(_) => {
                queue_pending(
                    &mut session.pending_host,
                    &mut session.pending_host_bytes,
                    message,
                );
            }
        }
        return GenericDispatch::Queued;
    }

    for peer in peers {
        if peer.try_send(message.clone()).is_err() {
            return GenericDispatch::SendFailed;
        }
    }
    GenericDispatch::Sent
}

fn direct_message_route(
    session: &Session,
    role: PrimaryRole,
    socket_generation: u64,
    establishment_generation: u64,
) -> DirectRoute {
    let current_socket_generation = match role {
        PrimaryRole::Host => session.host_generation,
        PrimaryRole::Client => session.client_generation,
    };
    if current_socket_generation != socket_generation {
        return DirectRoute::StaleSocket;
    }
    let Some(ready) = session.ready_pair else {
        return DirectRoute::NotReady;
    };
    let expected_socket_generation = match role {
        PrimaryRole::Host => ready.host_generation,
        PrimaryRole::Client => ready.client_generation,
    };
    if expected_socket_generation != socket_generation {
        return DirectRoute::StaleSocket;
    }
    if establishment_generation < ready.establishment_generation {
        return DirectRoute::DropStale;
    }
    if establishment_generation > ready.establishment_generation {
        return DirectRoute::Future;
    }
    let peer = match role {
        PrimaryRole::Host => session.client.clone(),
        PrimaryRole::Client => session.host.clone(),
    };
    peer.map(DirectRoute::Forward)
        .unwrap_or(DirectRoute::NotReady)
}

async fn signal_socket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path((session_id, role_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    // Axum's defaults are much larger than the JSON control messages this
    // service needs. Pin both WebSocket limits to the same bound checked
    // below so an oversized frame is rejected before it can create pressure
    // in the parser or the per-session forwarding queues.
    let ws = ws
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES);
    if role_name != "guest" {
        let Some(role) = Role::parse(&role_name) else {
            return (
                StatusCode::BAD_REQUEST,
                "role must be host, client, or guest\n",
            )
                .into_response();
        };
        {
            let mut sessions = state.sessions.lock().await;
            let Some(session) = sessions.get_mut(&session_id) else {
                return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
            };
            if session.expires_at <= Instant::now() {
                sessions.remove(&session_id);
                return (StatusCode::GONE, "session expired\n").into_response();
            }
            // Header-only authentication: query-string tokens end up in
            // proxy and access logs, so `?token=` is no longer accepted.
            let expected = role.token(session);
            let valid = bearer_token(&headers)
                .is_some_and(|token| expected.as_deref().is_some_and(|want| ct_eq(token, want)));
            if !valid {
                return (StatusCode::UNAUTHORIZED, "invalid session token\n").into_response();
            }
        }

        return ws
            .on_upgrade(move |socket| handle_socket(state, session_id, role, socket))
            .into_response();
    }

    // Guest role: the bearer token selects the admitted guest. The first
    // connected guest with no legacy client attached becomes active and is
    // bridged to the host; later guests park until promoted.
    let supplied_token = bearer_token(&headers).unwrap_or_default().to_string();
    let role = {
        let mut sessions = state.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return (StatusCode::NOT_FOUND, "unknown session\n").into_response();
        };
        if session.expires_at <= Instant::now() {
            sessions.remove(&session_id);
            return (StatusCode::GONE, "session expired\n").into_response();
        }
        if !session
            .guests
            .iter()
            .any(|guest| ct_eq(&guest.token, &supplied_token))
        {
            return (StatusCode::UNAUTHORIZED, "invalid session token\n").into_response();
        }
        Role::Guest(supplied_token)
    };

    ws.on_upgrade(move |socket| handle_socket(state, session_id, role, socket))
        .into_response()
}

async fn handle_socket(state: AppState, session_id: String, role: Role, socket: WebSocket) {
    let (sink, mut source) = socket.split();
    // This queue is deliberately bounded. Signaling messages are small and
    // infrequent; backpressure is preferable to allowing a stalled peer to
    // consume unbounded memory in the service.
    let (out_tx, out_rx) = mpsc::channel::<Message>(MAX_OUTBOUND_MESSAGES);
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let mut cancel_tx = Some(cancel_tx);
    let mut cancel_rx = Some(cancel_rx);

    let (expires_at, generation) = {
        let mut sessions = state.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return;
        };
        if session.expires_at <= Instant::now() {
            sessions.remove(&session_id);
            return;
        }
        let expires_at = session.expires_at;
        let generation = match &role {
            Role::Host => {
                let Ok(generation) = admit_primary_socket(
                    session,
                    PrimaryRole::Host,
                    &out_tx,
                    cancel_tx.take().expect("host cancellation sender"),
                ) else {
                    return;
                };
                generation
            }
            Role::Client => {
                let Ok(generation) = admit_primary_socket(
                    session,
                    PrimaryRole::Client,
                    &out_tx,
                    cancel_tx.take().expect("client cancellation sender"),
                ) else {
                    return;
                };
                // The media path stays 1:1: a legacy client claim parks any
                // bridged guest so two writers never race the host.
                let parked = session
                    .guests
                    .iter_mut()
                    .find(|guest| guest.active)
                    .map(|active| {
                        active.active = false;
                        (active.id.clone(), active.sender.clone())
                    });
                if let Some((active_id, notice)) = parked {
                    // Parking a guest revokes its media ownership immediately;
                    // otherwise its still-valid client-class relay ticket can
                    // continue forwarding opaque datagrams until the slot is
                    // replaced or times out.
                    clear_relay_owner(session, &active_id);
                    if let Some(notice) = notice {
                        let _ = notice.try_send(Message::Text("{\"type\":\"parked\"}".into()));
                    }
                }
                generation
            }
            Role::Guest(token) => {
                drop(cancel_tx.take());
                cancel_rx = None;
                let position = session
                    .guests
                    .iter()
                    .position(|guest| ct_eq(&guest.token, token));
                let Some(position) = position else {
                    return;
                };
                let next_generation = match session.guests[position].generation.checked_add(1) {
                    Some(generation) => generation,
                    None => return,
                };
                let relay_proof = new_relay_proof();
                // Reconnecting the same guest replaces its old socket. Preserve
                // its active state during that replacement; otherwise the new
                // connection would be told "parked" while the old task is
                // later ignored by generation-aware cleanup.
                let was_active = session.guests[position].active;
                let can_activate = was_active
                    || (session.client.is_none()
                        && !session
                            .guests
                            .iter()
                            .enumerate()
                            .any(|(index, other)| index != position && other.active));
                // Publish the sender only after the parked/drain notice
                // succeeds; a half-published dead sender would block
                // promotion and fan-out for this slot permanently.
                if can_activate {
                    if out_tx
                        .try_send(relay_proof_message(next_generation, &relay_proof))
                        .is_err()
                    {
                        return;
                    }
                    let pending_ok = {
                        let guest = &mut session.guests[position];
                        drain_into(&mut guest.pending, &mut guest.pending_bytes, &out_tx)
                    };
                    if !pending_ok {
                        return;
                    }
                    let guest_id = session.guests[position].id.clone();
                    clear_relay_owner(session, &guest_id);
                    let guest = &mut session.guests[position];
                    if let Some(old) = guest.sender.replace(out_tx.clone()) {
                        let _ = old.try_send(Message::Close(None));
                    }
                    guest.generation = next_generation;
                    guest.active = true;
                    guest.relay_proof = Some(relay_proof);
                    guest.generation
                } else {
                    if out_tx
                        .try_send(relay_proof_message(next_generation, &relay_proof))
                        .is_err()
                        || out_tx
                            .try_send(Message::Text("{\"type\":\"parked\"}".into()))
                            .is_err()
                    {
                        return;
                    }
                    let guest_id = session.guests[position].id.clone();
                    clear_relay_owner(session, &guest_id);
                    let guest = &mut session.guests[position];
                    if let Some(old) = guest.sender.replace(out_tx.clone()) {
                        let _ = old.try_send(Message::Close(None));
                    }
                    guest.generation = next_generation;
                    guest.active = false;
                    guest.relay_proof = Some(relay_proof);
                    guest.generation
                }
            }
        };
        (expires_at, generation)
    };

    let (terminal_tx, terminal_rx) = oneshot::channel::<Message>();
    let mut terminal_tx = Some(terminal_tx);
    let (terminal_result_tx, mut terminal_result_rx) = oneshot::channel();
    let mut writer = tokio::spawn(writer_loop(sink, out_rx, terminal_rx, terminal_result_tx));
    let mut writer_finished = false;
    let cancellation = async move {
        if let Some(receiver) = cancel_rx {
            let _ = receiver.await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(cancellation);
    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + SIGNAL_PING_INTERVAL,
        SIGNAL_PING_INTERVAL,
    );
    let mut last_activity = Instant::now();

    'socket: loop {
        tokio::select! {
            message = source.next() => {
                let Some(message) = message else {
                    break;
                };
                let message = match message {
                    Ok(message) => message,
                    Err(_) => break,
                };
                last_activity = Instant::now();
                let Message::Text(text) = message else {
                    match message {
                        Message::Ping(payload) => {
                            if out_tx.try_send(Message::Pong(payload)).is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        Message::Binary(_) | Message::Pong(_) => {}
                        Message::Text(_) => unreachable!("text handled above"),
                    }
                    continue;
                };
                // Size before parse: an oversized message is rejected without
                // allocating a JSON value for it.
                if text.len() > MAX_MESSAGE_BYTES {
                    if out_tx.try_send(Message::Text(
                        "{\"type\":\"error\",\"reason\":\"message_too_large\"}".into(),
                    )).is_err() {
                        break;
                    }
                    continue;
                }
                if let Err(reason) = validate_signal_message(&text) {
                    if out_tx.try_send(Message::Text(
                        format!("{{\"type\":\"error\",\"reason\":\"{reason}\"}}").into(),
                    )).is_err() {
                        break;
                    }
                    continue;
                }

                let message = Message::Text(text);
                if let Some(establishment_generation) = direct_message_generation(&message) {
                    let dispatch = {
                        let mut sessions = state.sessions.lock().await;
                        if sessions
                            .get(&session_id)
                            .is_some_and(|session| session.expires_at <= Instant::now())
                        {
                            sessions.remove(&session_id);
                        }
                        match sessions.get(&session_id) {
                            None => DirectDispatch::Missing,
                            Some(session) => {
                                let route = match &role {
                                    Role::Host => direct_message_route(
                                        session,
                                        PrimaryRole::Host,
                                        generation,
                                        establishment_generation,
                                    ),
                                    Role::Client => direct_message_route(
                                        session,
                                        PrimaryRole::Client,
                                        generation,
                                        establishment_generation,
                                    ),
                                    // Guests use the legacy client fan-out path and
                                    // cannot participate in direct-v2 establishment.
                                    Role::Guest(_) => DirectRoute::NotReady,
                                };
                                match route {
                                    DirectRoute::Forward(peer) => {
                                        if peer.try_send(message).is_ok() {
                                            DirectDispatch::Sent
                                        } else {
                                            DirectDispatch::SendFailed
                                        }
                                    }
                                    DirectRoute::DropStale => DirectDispatch::DropStale,
                                    DirectRoute::NotReady => DirectDispatch::NotReady,
                                    DirectRoute::Future => DirectDispatch::Future,
                                    DirectRoute::StaleSocket => DirectDispatch::StaleSocket,
                                }
                            }
                        }
                    };
                    match dispatch {
                        DirectDispatch::Sent | DirectDispatch::DropStale => continue,
                        DirectDispatch::Missing
                        | DirectDispatch::StaleSocket
                        | DirectDispatch::SendFailed => break 'socket,
                        DirectDispatch::NotReady => {
                            let error = Message::Text(
                                "{\"type\":\"error\",\"reason\":\"direct_establishment_not_ready\"}"
                                    .into(),
                            );
                            if let Some(sender) = terminal_tx.take() {
                                if sender.send(error).is_ok() {
                                    let _ = tokio::time::timeout(
                                        TERMINAL_WRITE_TIMEOUT,
                                        &mut terminal_result_rx,
                                    )
                                    .await;
                                }
                            }
                            break 'socket;
                        }
                        DirectDispatch::Future => {
                            let error = Message::Text(
                                "{\"type\":\"error\",\"reason\":\"direct_generation_future\"}"
                                    .into(),
                            );
                            if let Some(sender) = terminal_tx.take() {
                                if sender.send(error).is_ok() {
                                    let _ = tokio::time::timeout(
                                        TERMINAL_WRITE_TIMEOUT,
                                        &mut terminal_result_rx,
                                    )
                                    .await;
                                }
                            }
                            break 'socket;
                        }
                    }
                }
                let dispatch = {
                    let mut sessions = state.sessions.lock().await;
                    // An expired session stops forwarding immediately; the
                    // entry is reaped here rather than lingering until the
                    // next create or relay tick.
                    if sessions
                        .get(&session_id)
                        .is_some_and(|session| session.expires_at <= Instant::now())
                    {
                        sessions.remove(&session_id);
                    }
                    match sessions.get_mut(&session_id) {
                        None => GenericDispatch::Missing,
                        Some(session) => dispatch_generic_message(
                            session,
                            &role,
                            generation,
                            &out_tx,
                            message,
                        ),
                    }
                };
                match dispatch {
                    GenericDispatch::Sent | GenericDispatch::Queued => {}
                    GenericDispatch::Missing
                    | GenericDispatch::StaleSocket
                    | GenericDispatch::SendFailed => break 'socket,
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)) => {
                break;
            }
            _ = heartbeat.tick() => {
                if last_activity.elapsed() >= SIGNAL_IDLE_TIMEOUT
                    || out_tx.try_send(Message::Ping(Vec::new().into())).is_err()
                {
                    break;
                }
            }
            _ = &mut writer => {
                // The peer-facing writer failed or was closed. Do not leave
                // this role published in the session map while its reader is
                // still able to accept and queue messages.
                writer_finished = true;
                break;
            }
            _ = &mut cancellation => {
                // Fail-closed teardown uses this cancellation path because
                // the bounded outbound queue may already be full.
                break;
            }
        }
    }

    writer.abort();
    if !writer_finished {
        let _ = writer.await;
    }
    // Disconnect cleanup honors connection generations: a stale task that
    // was replaced by a newer connection must not clear the new sender.
    // Relay slots owned by the departing connection are cleared so a
    // disconnected guest cannot keep pushing media.
    let promotion = {
        let mut sessions = state.sessions.lock().await;
        if sessions
            .get(&session_id)
            .is_some_and(|session| session.expires_at <= Instant::now())
        {
            sessions.remove(&session_id);
            None
        } else if let Some(session) = sessions.get_mut(&session_id) {
            match &role {
                Role::Host => {
                    if cleanup_primary_socket(session, PrimaryRole::Host, generation) {
                        clear_relay_owner(session, "host");
                    }
                    None
                }
                Role::Client => {
                    if cleanup_primary_socket(session, PrimaryRole::Client, generation) {
                        clear_relay_owner(session, "client");
                    }
                    None
                }
                Role::Guest(token) => {
                    let position = session
                        .guests
                        .iter()
                        .position(|guest| ct_eq(&guest.token, token));
                    match position {
                        None => None,
                        Some(position) => {
                            let id = session.guests[position].id.clone();
                            if session.guests[position].generation != generation {
                                // Replaced by a newer connection; leave it.
                                None
                            } else {
                                let was_active = session.guests[position].active;
                                session.guests[position].sender.take();
                                session.guests[position].active = false;
                                session.guests[position].relay_proof.take();
                                clear_relay_owner(session, &id);
                                if was_active {
                                    take_promotion_sender(session)
                                } else {
                                    None
                                }
                            }
                        }
                    }
                }
            }
        } else {
            None
        }
    };
    if let Some(promotion) = promotion {
        let _ = promotion.try_send(Message::Text("{\"type\":\"promoted\"}".into()));
    }
}

/// Validate every signaling envelope before it is forwarded to another
/// authenticated role. Forwarding opaque JSON is convenient during early
/// development, but accepting arbitrary object types allows malformed or
/// unexpected messages to reach every peer and makes protocol evolution
/// ambiguous. The exact field semantics are validated again by
/// `openstream-client-core`; this layer establishes a small, bounded message
/// vocabulary and protects the signaling service itself.
fn validate_signal_message(text: &str) -> Result<(), &'static str> {
    let value = serde_json::from_str::<serde_json::Value>(text).map_err(|_| "invalid_json")?;
    let object = value.as_object().ok_or("message_must_be_object")?;
    let message_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("message_type_missing")?;

    match message_type {
        "peer_ready" | "peer_reset" | "relay_ticket_proof" => {
            return Err("server_generated_message");
        }
        // The historical untyped direct envelopes are deliberately not a
        // compatibility mode: direct establishment is direct-v2 only. ICE
        // continues to use its distinct `ice_*` vocabulary below.
        "candidate" | "candidate_done" => {
            return Err("legacy_direct_establishment_unsupported");
        }
        "direct_candidate" => {
            if object.len() != 5 {
                return Err("direct_candidate_fields_invalid");
            }
            let generation = object
                .get("establishment_generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or("direct_candidate_generation_missing")?;
            if generation == 0 {
                return Err("direct_candidate_generation_invalid");
            }
            let kind = object
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .ok_or("direct_candidate_kind_missing")?;
            if !matches!(kind, "host" | "mapped" | "server_reflexive" | "relay") {
                return Err("direct_candidate_kind_invalid");
            }
            let ip = object
                .get("ip")
                .and_then(serde_json::Value::as_str)
                .ok_or("direct_candidate_ip_missing")?;
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err("direct_candidate_ip_invalid");
            }
            let port = object
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .ok_or("direct_candidate_port_missing")?;
            if !(1..=u64::from(u16::MAX)).contains(&port) {
                return Err("direct_candidate_port_invalid");
            }
        }
        "direct_candidate_done" => {
            if object.len() != 3 {
                return Err("direct_candidate_done_fields_invalid");
            }
            let generation = object
                .get("establishment_generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or("direct_candidate_done_generation_missing")?;
            if generation == 0 {
                return Err("direct_candidate_done_generation_invalid");
            }
            let count = object
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .ok_or("direct_candidate_done_count_missing")?;
            if !(1..=MAX_DIRECT_CANDIDATES).contains(&count) {
                return Err("direct_candidate_done_count_invalid");
            }
        }
        "direct_key" => {
            if object.len() != 5 {
                return Err("direct_key_fields_invalid");
            }
            let generation = object
                .get("establishment_generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or("direct_key_generation_missing")?;
            if generation == 0 {
                return Err("direct_key_generation_invalid");
            }
            if !valid_hex_field(object, "public_key", 32)
                || !valid_hex_field(object, "identity_public_key", 32)
                || !valid_hex_field(object, "signature", 64)
            {
                return Err("direct_key_encoding_invalid");
            }
        }
        "path_candidate" => {
            if object.len() != 6
                || object.get("kind").and_then(serde_json::Value::as_str) != Some("direct_udp")
                || !valid_hex_field(object, "token", 16)
            {
                return Err("path_candidate_fields_invalid");
            }
            let generation = object
                .get("generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or("path_candidate_generation_missing")?;
            if generation == 0 {
                return Err("path_candidate_generation_invalid");
            }
            let ip = object
                .get("ip")
                .and_then(serde_json::Value::as_str)
                .ok_or("path_candidate_ip_missing")?;
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err("path_candidate_ip_invalid");
            }
            let port = object
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .ok_or("path_candidate_port_missing")?;
            if !(1..=u64::from(u16::MAX)).contains(&port) {
                return Err("path_candidate_port_invalid");
            }
        }
        "key" => {
            if !valid_hex_field(object, "public_key", 32)
                || !valid_hex_field(object, "identity_public_key", 32)
                || !valid_hex_field(object, "signature", 64)
            {
                return Err("key_encoding_invalid");
            }
        }
        "ice_credentials" => {
            if !bounded_string_field(object, "ufrag", 1, 32)
                || !bounded_string_field(object, "pwd", 1, 256)
            {
                return Err("ice_credentials_invalid");
            }
        }
        "ice_candidate" => {
            if !bounded_string_field(object, "candidate", 1, 4096) {
                return Err("ice_candidate_invalid");
            }
        }
        "ice_candidate_done" => {}
        _ => return Err("unsupported_message_type"),
    }
    Ok(())
}

fn bounded_string_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> bool {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.len() >= minimum && value.len() <= maximum)
}

fn valid_hex_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    bytes: usize,
) -> bool {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| {
            value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Clear the relay slot owned by `owner` ("host", "client", or a guest id),
/// if any. Called on disconnect and kick so departed peers lose the data
/// path immediately instead of at session expiry.
fn clear_relay_owner(session: &mut Session, owner: &str) {
    for slot in [&mut session.relay_host, &mut session.relay_client] {
        if slot.as_ref().is_some_and(|owned| owned.owner == owner) {
            *slot = None;
        }
    }
}

/// Return the relay owner only when a verified ticket still belongs to the
/// currently admitted signaling socket for that principal. A ticket issued
/// to an earlier socket generation remains cryptographically valid, but it is
/// deliberately unusable after that socket is replaced.
fn relay_owner_for_ticket(
    session: &Session,
    role: relay::Role,
    ticket: &relay_ticket::Verified,
) -> Option<String> {
    match role {
        relay::Role::Host
            if ticket.class == "host"
                && ticket.subject == "host"
                && session.host.is_some()
                && ticket.socket_generation == session.host_generation
                && relay_ticket_matches_proof(ticket, session.host_relay_proof.as_deref()) =>
        {
            Some("host".to_string())
        }
        relay::Role::Client if ticket.class == "client" => {
            if ticket.subject == "client" {
                (session.client.is_some()
                    && ticket.socket_generation == session.client_generation
                    && relay_ticket_matches_proof(ticket, session.client_relay_proof.as_deref()))
                .then(|| "client".to_string())
            } else {
                session
                    .guests
                    .iter()
                    .find(|guest| {
                        guest.active
                            && guest.sender.is_some()
                            && guest.id == ticket.subject
                            && guest.generation == ticket.socket_generation
                            && relay_ticket_matches_proof(ticket, guest.relay_proof.as_deref())
                    })
                    .map(|guest| guest.id.clone())
            }
        }
        _ => None,
    }
}

/// Initial pairing tickets are intentionally unbound because they must be
/// usable before either signaling socket exists. Reissued tickets must carry
/// the digest of the current socket proof. The generation check in the caller
/// prevents an initial generation-one ticket from surviving replacement.
fn relay_ticket_matches_proof(
    ticket: &relay_ticket::Verified,
    current_proof: Option<&str>,
) -> bool {
    match ticket.proof_digest {
        None => ticket.socket_generation == 1,
        Some(expected) => current_proof.is_some_and(|proof| {
            let actual = relay_ticket::proof_digest(proof);
            actual
                .iter()
                .zip(expected.iter())
                .fold(0_u8, |difference, (actual, expected)| {
                    difference | (actual ^ expected)
                })
                == 0
        }),
    }
}

/// Drain a bounded pending queue into a fresh WebSocket sender. Returns
/// false when backpressure never clears (the caller drops the connection),
/// shared by every role so the bound means the same thing everywhere.
fn drain_into(
    pending: &mut VecDeque<Message>,
    pending_bytes: &mut usize,
    out_tx: &mpsc::Sender<Message>,
) -> bool {
    while let Some(message) = pending.pop_front() {
        let size = message_len(&message);
        if let Err(error) = out_tx.try_send(message) {
            // `try_send` returns ownership of the message on both full and
            // closed errors. Put it back so a temporarily full fresh queue
            // does not silently discard the entire pending handshake. Drain
            // used to remove the remaining entries without adjusting the
            // byte counter, which also poisoned the queue's future capacity.
            pending.push_front(error.into_inner());
            *pending_bytes = pending.iter().fold(0, |total, message| {
                total.saturating_add(message_len(message))
            });
            return false;
        }
        *pending_bytes = pending_bytes.saturating_sub(size);
    }
    *pending_bytes = 0;
    true
}

/// Wire bytes a queued message holds, for the pending-bytes bound.
fn message_len(message: &Message) -> usize {
    match message {
        Message::Text(text) => text.len(),
        Message::Binary(bytes) => bytes.len(),
        Message::Ping(bytes) => bytes.len(),
        Message::Pong(bytes) => bytes.len(),
        Message::Close(_) => 0,
    }
}

/// Queue one message for a peer that is not connected yet. Drop-new past the
/// count or byte bound: evicting the oldest would flush handshake-critical
/// messages a malicious or buggy peer could then re-trigger forever.
fn queue_pending(queue: &mut VecDeque<Message>, queued_bytes: &mut usize, message: Message) {
    if is_direct_establishment_message(&message) {
        return;
    }
    let size = message_len(&message);
    if queue.len() >= MAX_PENDING_MESSAGES || *queued_bytes + size > MAX_PENDING_BYTES {
        return;
    }
    *queued_bytes += size;
    queue.push_back(message);
}

fn is_direct_establishment_message(message: &Message) -> bool {
    let Message::Text(text) = message else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| {
            value
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(|message_type| {
                    matches!(
                        message_type,
                        "direct_candidate" | "direct_candidate_done" | "direct_key"
                    )
                })
        })
        .unwrap_or(false)
}

/// Forward opaque encrypted datagrams between the validated host and client
/// addresses for each live session. This deliberately stays in the signaling
/// process so revocation removes the relay mapping at the same time as the
/// WebSocket capabilities.
///
/// Registration presents a relay ticket (see [`relay_ticket`]), never a
/// WebSocket bearer token. Forwarded datagrams are capped at the protocol
/// `MAX_DATAGRAM`; larger ones are dropped rather than relayed. Session
/// expiry is reaped on a timer, not per datagram, so a UDP flood cannot turn
/// the map cleanup into a control-plane stall.
async fn run_relay(socket: UdpSocket, state: AppState, shutdown: watch::Receiver<bool>) {
    use openstream_protocol::MAX_DATAGRAM;
    // Keep one sentinel byte so UDP truncation is observable. A buffer sized
    // exactly to MAX_DATAGRAM would silently turn an oversized datagram into
    // a truncated packet and forward it as if it were valid.
    let mut buffer = [0_u8; MAX_DATAGRAM + 1];
    let mut reap = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = received else {
                    continue;
                };
                if length > MAX_DATAGRAM {
                    continue;
                }
                let datagram = &buffer[..length];
                if let Ok(unregister) = relay::decode_unregister(datagram) {
                    let acknowledged = {
                        let mut sessions = state.sessions.lock().await;
                        match sessions.get_mut(unregister.session_id) {
                            None => false,
                            Some(session) if session.expires_at <= Instant::now() => false,
                            Some(session) => {
                                let verified = relay_ticket::verify(
                                    &state.relay_secret,
                                    unregister.session_id,
                                    unregister.token,
                                );
                                let owner = verified.as_ref().and_then(|ticket| {
                                    relay_owner_for_ticket(session, unregister.role, ticket)
                                });
                                if let Some(owner) = owner {
                                    let ticket_digest = relay_ticket_digest(unregister.token);
                                    let socket_generation = verified
                                        .as_ref()
                                        .expect("owner requires a verified relay ticket")
                                        .socket_generation;
                                    let slot = match unregister.role {
                                        relay::Role::Host => &mut session.relay_host,
                                        relay::Role::Client => &mut session.relay_client,
                                    };
                                    // A cleanup request is acknowledged even
                                    // when it is stale or duplicated, but it
                                    // can clear only the exact
                                    // source/owner/ticket tuple.
                                    if slot.as_ref().is_some_and(|current| {
                                        current.addr == source
                                            && current.owner == owner
                                            && current.socket_generation == socket_generation
                                            && current.ticket_digest == ticket_digest
                                    }) {
                                        *slot = None;
                                    }
                                    true
                                } else {
                                    false
                                }
                            }
                        }
                    };
                    if acknowledged {
                        let _ = socket
                            .send_to(&relay::encode_unregister_ack(unregister.role), source)
                            .await;
                    }
                    continue;
                }
                if let Ok(registration) = relay::decode_registration(datagram) {
                    let accepted = {
                        let mut sessions = state.sessions.lock().await;
                        match sessions.get_mut(registration.session_id) {
                            None => false,
                            Some(session) if session.expires_at <= Instant::now() => false,
                            Some(session) => {
                                // Ticket-only: raw role tokens are rejected so
                                // a registration observer learns nothing usable
                                // on the WebSocket API.
                                match relay_ticket::verify(
                                    &state.relay_secret,
                                    registration.session_id,
                                    registration.token,
                                ) {
                                    None => false,
                                    Some(ticket) => {
                                        if let Some(owner) = relay_owner_for_ticket(
                                            session,
                                            registration.role,
                                            &ticket,
                                        ) {
                                            let now = Instant::now();
                                            let slot = RelaySlot {
                                                addr: source,
                                                owner,
                                                socket_generation: ticket.socket_generation,
                                                ticket_digest: relay_ticket_digest(
                                                    registration.token,
                                                ),
                                                last_seen: now,
                                                window_started: now,
                                                window_bytes: 0,
                                                window_packets: 0,
                                            };
                                            match registration.role {
                                                relay::Role::Host => {
                                                    // Last registration wins,
                                                    // but only within one role
                                                    // class.
                                                    session.relay_host = Some(slot);
                                                }
                                                relay::Role::Client => {
                                                    session.relay_client = Some(slot);
                                                }
                                            }
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                }
                            }
                        }
                    };
                    if accepted {
                        let _ = socket
                            .send_to(&relay::encode_ack(registration.role), source)
                            .await;
                    }
                    continue;
                }

                if length > MAX_DATAGRAM {
                    continue;
                }
                let destination = {
                    let mut sessions = state.sessions.lock().await;
                    sessions.values_mut().find_map(|session| {
                        if session.expires_at <= Instant::now() {
                            return None;
                        }
                        if session.relay_host.as_ref().is_some_and(|slot| slot.addr == source) {
                            if let Some(slot) = session.relay_host.as_mut() {
                                let now = Instant::now();
                                if !slot.accept(length, now) {
                                    return Some(None);
                                }
                            }
                            Some(session.relay_client.as_ref().map(|slot| slot.addr))
                        } else if session
                            .relay_client
                            .as_ref()
                            .is_some_and(|slot| slot.addr == source)
                        {
                            if let Some(slot) = session.relay_client.as_mut() {
                                let now = Instant::now();
                                if !slot.accept(length, now) {
                                    return Some(None);
                                }
                            }
                            Some(session.relay_host.as_ref().map(|slot| slot.addr))
                        } else {
                            None
                        }
                    })
                };
                if let Some(Some(destination)) = destination {
                    let _ = socket.send_to(datagram, destination).await;
                }
            }
            _ = reap.tick() => {
                let senders = reap_expired_sessions(&state).await;
                for sender in senders {
                    let _ = sender.try_send(Message::Close(None));
                }
                let mut sessions = state.sessions.lock().await;
                let now = Instant::now();
                // Drop idle relay slots so mappings never live the full
                // session TTL without traffic.
                for session in sessions.values_mut() {
                    for slot in [&mut session.relay_host, &mut session.relay_client] {
                        if slot.as_ref().is_some_and(|owned| {
                            now.saturating_duration_since(owned.last_seen) > RELAY_SLOT_IDLE
                        }) {
                            *slot = None;
                        }
                    }
                }
            }
            _ = wait_for_shutdown(shutdown.clone()) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionError, AppState, CreationLimiter, DirectRoute, GenericDispatch, Guest,
        MAX_GUESTS_CEILING, MAX_SESSION_CREATES_PER_MINUTE, PrimaryRole, RELAY_BYTES_PER_SECOND,
        RELAY_PACKETS_PER_SECOND, ReadinessError, RelaySlot, Role, SESSION_CREATE_WINDOW, Session,
        admit_primary_socket as admit_primary_socket_with_cancel, authorized, bearer_token,
        cleanup_primary_socket, close_primary_pair, direct_message_route, dispatch_generic_message,
        max_guests_for_new_session, prune_direct_establishment_messages, publish_ready,
        queue_pending, reap_expired_sessions, relay_owner_for_ticket, relay_ticket, signal_socket,
        validate_signal_message,
    };
    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::ws::Message;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::get;
    use futures_util::task::{Context, Poll};
    use futures_util::{Sink, SinkExt, StreamExt};
    use openstream_protocol::relay;
    use std::collections::{HashMap, VecDeque};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::{Mutex, mpsc, oneshot};
    use tokio::time::timeout;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    fn test_session() -> Session {
        Session {
            expires_at: Instant::now() + Duration::from_secs(60),
            host_token: "host-token".into(),
            client_token: "client-token".into(),
            host: None,
            client: None,
            host_relay_proof: None,
            client_relay_proof: None,
            host_cancel: None,
            client_cancel: None,
            host_generation: 0,
            client_generation: 0,
            establishment_generation: 0,
            ready_pair: None,
            pending_host: std::collections::VecDeque::new(),
            pending_client: std::collections::VecDeque::new(),
            pending_host_bytes: 0,
            pending_client_bytes: 0,
            relay_host: None,
            relay_client: None,
            guests: std::collections::VecDeque::new(),
            max_guests: 1,
        }
    }

    fn admit_primary_socket(
        session: &mut Session,
        role: PrimaryRole,
        out_tx: &mpsc::Sender<Message>,
    ) -> Result<u64, AdmissionError> {
        let (cancel, _receiver) = oneshot::channel();
        admit_primary_socket_with_cancel(session, role, out_tx, cancel)
    }

    fn message_text(message: Message) -> String {
        match message {
            Message::Text(text) => text.to_string(),
            other => panic!("expected text message, got {other:?}"),
        }
    }

    struct BlockedSink;

    impl Sink<Message> for BlockedSink {
        type Error = Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    struct RecordingSink(Arc<StdMutex<Vec<Message>>>);

    impl Sink<Message> for RecordingSink {
        type Error = Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut()
                .0
                .lock()
                .expect("recording sink lock")
                .push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn assert_peer_ready(message: Message, generation: u64) {
        let text = message_text(message);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text)
                .expect("peer_ready JSON")
                .get("type")
                .and_then(serde_json::Value::as_str),
            Some("peer_ready")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text)
                .expect("peer_ready JSON")
                .get("establishment_generation")
                .and_then(serde_json::Value::as_u64),
            Some(generation)
        );
    }

    fn assert_relay_proof(message: Message, generation: u64) {
        let text = message_text(message);
        let value = serde_json::from_str::<serde_json::Value>(&text).expect("relay proof JSON");
        assert_eq!(
            value.get("type").and_then(serde_json::Value::as_str),
            Some("relay_ticket_proof")
        );
        assert_eq!(
            value
                .get("socket_generation")
                .and_then(serde_json::Value::as_u64),
            Some(generation)
        );
        assert_eq!(
            value
                .get("proof")
                .and_then(serde_json::Value::as_str)
                .map(str::len),
            Some(32)
        );
    }

    fn assert_client_relay_proof(message: ClientMessage, generation: u64) {
        let ClientMessage::Text(text) = message else {
            panic!("expected relay proof text message, got {message:?}");
        };
        let value = serde_json::from_str::<serde_json::Value>(&text).expect("relay proof JSON");
        assert_eq!(
            value.get("type").and_then(serde_json::Value::as_str),
            Some("relay_ticket_proof")
        );
        assert_eq!(
            value
                .get("socket_generation")
                .and_then(serde_json::Value::as_u64),
            Some(generation)
        );
        assert_eq!(
            value
                .get("proof")
                .and_then(serde_json::Value::as_str)
                .map(str::len),
            Some(32)
        );
    }

    #[test]
    fn no_admin_token_refuses_everything_without_explicit_dev_opt_in() {
        // Fail closed: no token means no access, even with empty headers.
        assert!(!authorized(&HeaderMap::new(), None));
    }

    #[test]
    fn production_mode_requires_the_configured_admin_capability() {
        let mut headers = HeaderMap::new();
        assert!(!authorized(&headers, Some("secret")));

        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        assert!(authorized(&headers, Some("secret")));
        assert!(!authorized(&headers, Some("")));

        headers.remove("authorization");
        headers.insert(
            "x-openstream-admin-token",
            HeaderValue::from_static("secret"),
        );
        assert!(authorized(&headers, Some("secret")));

        headers.insert(
            "x-openstream-admin-token",
            HeaderValue::from_static("wrong-secret"),
        );
        assert!(!authorized(&headers, Some("secret")));
    }

    #[test]
    fn role_token_can_be_read_from_the_websocket_authorization_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer role-token"),
        );
        assert_eq!(bearer_token(&headers), Some("role-token"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Basic role-token"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn guest_listing_uses_opaque_ids_never_token_prefixes() {
        let guest = Guest {
            id: "guest-id-1".into(),
            token: "abcdefghijklmnop".into(),
            input: true,
            sender: None,
            pending: std::collections::VecDeque::new(),
            pending_bytes: 0,
            active: false,
            generation: 0,
            relay_proof: None,
        };
        let redacted = guest.redacted();
        assert_eq!(redacted["id"], "guest-id-1");
        assert_eq!(redacted["input"], true);
        assert_eq!(redacted["connected"], false);
        // The full bearer token never appears in the listing.
        assert!(!redacted.to_string().contains("abcdefghijklmnop"));
    }

    #[test]
    fn relay_tickets_verify_per_class_and_reject_forgeries() {
        let secret = b"test-relay-secret-0123456789";
        let host = relay_ticket::mint(secret, "session-1", "host", "host", 1);
        let client = relay_ticket::mint(secret, "session-1", "client", "client", 1);
        let verified_host =
            relay_ticket::verify(secret, "session-1", &host).expect("host ticket verifies");
        assert_eq!(verified_host.class, "host");
        assert_eq!(verified_host.subject, "host");
        let verified_client =
            relay_ticket::verify(secret, "session-1", &client).expect("client ticket verifies");
        assert_eq!(verified_client.class, "client");
        assert_eq!(verified_client.subject, "client");
        let guest = relay_ticket::mint(secret, "session-1", "client", "guest-id-1", 1);
        assert_eq!(
            relay_ticket::verify(secret, "session-1", &guest)
                .expect("guest ticket verifies")
                .subject,
            "guest-id-1"
        );
        assert_ne!(host, client);
        assert_ne!(client, guest);
        // Wrong session, wrong secret, tampered ticket: all rejected.
        assert_eq!(relay_ticket::verify(secret, "session-2", &host), None);
        assert_eq!(
            relay_ticket::verify(b"other-secret-01234567890123", "session-1", &host),
            None
        );
        let mut forged = host.clone();
        forged.pop();
        forged.push('0');
        assert_eq!(relay_ticket::verify(secret, "session-1", &forged), None);
        assert_eq!(relay_ticket::verify(secret, "session-1", ""), None);
    }

    #[test]
    fn relay_tickets_bind_to_the_primary_socket_generation() {
        let secret = b"test-relay-secret-0123456789";
        let first = relay_ticket::mint(secret, "session-1", "host", "host", 1);
        let replacement = relay_ticket::mint(secret, "session-1", "host", "host", 2);
        assert_ne!(first, replacement);
        assert_eq!(
            relay_ticket::verify(secret, "session-1", &first)
                .expect("first ticket verifies")
                .socket_generation,
            1
        );
        assert_eq!(
            relay_ticket::verify(secret, "session-1", &replacement)
                .expect("replacement ticket verifies")
                .socket_generation,
            2
        );
    }

    #[test]
    fn guest_relay_tickets_require_the_current_guest_socket_proof() {
        let secret = b"test-relay-secret-0123456789";
        let (sender, _) = mpsc::channel(1);
        let mut session = test_session();
        session.guests.push_back(Guest {
            id: "guest-id-1".into(),
            token: "guest-token".into(),
            input: false,
            sender: Some(sender),
            pending: VecDeque::new(),
            pending_bytes: 0,
            active: true,
            generation: 1,
            relay_proof: Some("proof-1".into()),
        });

        let old_ticket =
            relay_ticket::mint_bound(secret, "session-1", "client", "guest-id-1", 1, "proof-1");
        let old_verified =
            relay_ticket::verify(secret, "session-1", &old_ticket).expect("guest ticket");
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Client, &old_verified),
            Some("guest-id-1".into())
        );
        assert!(!old_ticket.contains("proof-1"));

        session.guests[0].generation = 2;
        session.guests[0].relay_proof = Some("proof-2".into());
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Client, &old_verified),
            None
        );

        let new_ticket =
            relay_ticket::mint_bound(secret, "session-1", "client", "guest-id-1", 2, "proof-2");
        let new_verified =
            relay_ticket::verify(secret, "session-1", &new_ticket).expect("new guest ticket");
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Client, &new_verified),
            Some("guest-id-1".into())
        );
    }

    #[test]
    fn old_relay_ticket_cannot_reclaim_ownership_after_primary_replacement() {
        let secret = b"test-relay-secret-0123456789";
        let (host_sender, _) = mpsc::channel(1);
        let mut session = test_session();
        session.host = Some(host_sender);
        session.host_generation = 1;
        session.host_relay_proof = Some("proof-1".into());

        let old_ticket =
            relay_ticket::mint_bound(secret, "session-1", "host", "host", 1, "proof-1");
        let old_verified =
            relay_ticket::verify(secret, "session-1", &old_ticket).expect("old ticket verifies");
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Host, &old_verified),
            Some("host".into())
        );

        session.host_generation = 2;
        session.host_relay_proof = Some("proof-2".into());
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Host, &old_verified),
            None
        );

        let new_ticket =
            relay_ticket::mint_bound(secret, "session-1", "host", "host", 2, "proof-2");
        let new_verified = relay_ticket::verify(secret, "session-1", &new_ticket)
            .expect("replacement ticket verifies");
        assert_eq!(
            relay_owner_for_ticket(&session, relay::Role::Host, &new_verified),
            Some("host".into())
        );
    }

    #[test]
    fn relay_slot_enforces_packet_and_byte_budgets() {
        let start = Instant::now();
        let mut slot = RelaySlot {
            addr: "127.0.0.1:9000".parse().expect("address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [0; 32],
            last_seen: start,
            window_started: start,
            window_bytes: 0,
            window_packets: 0,
        };
        assert!(slot.accept(RELAY_BYTES_PER_SECOND, start));
        assert!(!slot.accept(1, start));
        assert!(slot.accept(1, start + Duration::from_secs(1)));

        slot.window_started = start;
        slot.window_bytes = 0;
        slot.window_packets = RELAY_PACKETS_PER_SECOND;
        assert!(!slot.accept(1, start));
    }

    #[test]
    fn guest_cap_is_bounded_and_defaults_sanely() {
        assert!(max_guests_for_new_session() >= 1);
        assert!(max_guests_for_new_session() <= MAX_GUESTS_CEILING);
    }

    #[tokio::test]
    async fn full_primary_queues_still_cancel_both_fail_closed_tasks() {
        let (host_tx, mut host_rx) = mpsc::channel(1);
        host_tx
            .try_send(Message::Text("full".into()))
            .expect("fill host queue");
        let (client_tx, mut client_rx) = mpsc::channel(1);
        client_tx
            .try_send(Message::Text("full".into()))
            .expect("fill client queue");
        let (host_cancel, host_cancelled) = oneshot::channel();
        let (client_cancel, client_cancelled) = oneshot::channel();
        let host_task = tokio::spawn(async move {
            host_cancelled.await.expect("host cancellation");
        });
        let client_task = tokio::spawn(async move {
            client_cancelled.await.expect("client cancellation");
        });
        let mut session = test_session();
        session.host = Some(host_tx);
        session.client = Some(client_tx);
        session.host_cancel = Some(host_cancel);
        session.client_cancel = Some(client_cancel);

        close_primary_pair(&mut session);

        timeout(Duration::from_secs(1), host_task)
            .await
            .expect("host task is cancelled")
            .expect("host task joins");
        timeout(Duration::from_secs(1), client_task)
            .await
            .expect("client task is cancelled")
            .expect("client task joins");
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(host_rx.try_recv().is_ok());
        assert!(client_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn direct_not_ready_error_reaches_client_before_socket_closes() {
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            admin_token: None,
            allow_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        state
            .sessions
            .lock()
            .await
            .insert("session-1".into(), test_session());

        let app = Router::new()
            .route("/v1/signal/{session_id}/{role}", get(signal_socket))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        let mut request = format!("ws://{address}/v1/signal/session-1/host")
            .into_client_request()
            .expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            "Bearer host-token".parse().expect("authorization header"),
        );
        let (mut socket, _) = connect_async(request).await.expect("host connects");
        assert_client_relay_proof(
            timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("relay proof arrives")
                .expect("socket yields proof")
                .expect("proof frame is valid"),
            1,
        );
        socket
            .send(ClientMessage::Text(
                r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.10","port":40001}"#.into(),
            ))
            .await
            .expect("send not-ready direct message");

        let response = timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("protocol error arrives before timeout")
            .expect("socket yields a frame")
            .expect("websocket frame is valid");
        assert!(matches!(
            response,
            ClientMessage::Text(text) if text.contains("direct_establishment_not_ready")
        ));
        let _ = timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("socket closes after protocol error");

        server.abort();
    }

    #[tokio::test]
    async fn terminal_request_cancels_in_flight_blocked_write_without_claiming_delivery() {
        let (out_tx, out_rx) = mpsc::channel(1);
        out_tx
            .send(Message::Text("previous queued message".into()))
            .await
            .expect("queue previous message");
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let writer = tokio::spawn(super::writer_loop(
            BlockedSink,
            out_rx,
            terminal_rx,
            result_tx,
        ));

        // Let the writer enter Sink::poll_flush for the queued message. The
        // terminal command must then cancel that in-flight write rather than
        // waiting forever behind it or falsely claiming delivery.
        tokio::task::yield_now().await;
        terminal_tx
            .send(Message::Text("terminal error".into()))
            .expect("send terminal command");

        assert_eq!(
            timeout(Duration::from_secs(1), result_rx)
                .await
                .expect("writer reports terminal outcome")
                .expect("terminal outcome channel remains open"),
            super::TerminalDelivery::NotDelivered
        );
        timeout(Duration::from_secs(1), writer)
            .await
            .expect("blocked writer exits")
            .expect("blocked writer joins");
    }

    #[tokio::test]
    async fn terminal_request_reports_delivery_after_terminal_send_flushes() {
        let (out_tx, out_rx) = mpsc::channel(1);
        drop(out_tx);
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let writer = tokio::spawn(super::writer_loop(
            RecordingSink(Arc::clone(&sent)),
            out_rx,
            terminal_rx,
            result_tx,
        ));

        terminal_tx
            .send(Message::Text("terminal error".into()))
            .expect("send terminal command");
        assert_eq!(
            timeout(Duration::from_secs(1), result_rx)
                .await
                .expect("writer reports terminal outcome")
                .expect("terminal outcome channel remains open"),
            super::TerminalDelivery::Delivered
        );
        timeout(Duration::from_secs(1), writer)
            .await
            .expect("writer exits after terminal delivery")
            .expect("writer joins");

        let sent = sent.lock().expect("recording sink lock");
        assert!(matches!(
            sent.as_slice(),
            [Message::Text(text)] if text.as_str() == "terminal error"
        ));
    }

    #[test]
    fn generic_dispatch_uses_only_the_current_target_after_replacement() {
        let (old_host, mut old_host_rx) = mpsc::channel(1);
        old_host
            .try_send(Message::Text("occupied".into()))
            .expect("fill old target queue");
        let (new_host, mut new_host_rx) = mpsc::channel(1);
        let (client, _client_rx) = mpsc::channel(1);
        let mut session = test_session();
        session.host = Some(old_host);
        session.host_generation = 1;
        session.client = Some(client.clone());
        session.client_generation = 1;

        // The replacement is installed before the source is dispatched. The
        // dispatch must use the current target, never a sender copied from the
        // previous ownership epoch.
        session.host = Some(new_host);
        session.host_generation = 2;
        assert_eq!(
            dispatch_generic_message(
                &mut session,
                &Role::Client,
                1,
                &client,
                Message::Text(r#"{"type":"ice_candidate_done"}"#.into()),
            ),
            GenericDispatch::Sent
        );
        assert!(matches!(
            new_host_rx.try_recv(),
            Ok(Message::Text(text)) if text.contains("ice_candidate_done")
        ));
        assert!(matches!(
            old_host_rx.try_recv(),
            Ok(Message::Text(text)) if text == "occupied"
        ));
    }

    #[tokio::test]
    async fn replaced_guest_socket_cannot_forward_or_queue_generic_signaling() {
        let (host_sender, mut host_receiver) = mpsc::channel(8);
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            admin_token: None,
            allow_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        state.sessions.lock().await.insert(
            "session-1".into(),
            Session {
                expires_at: Instant::now() + Duration::from_secs(60),
                host_token: "host-token".into(),
                client_token: "client-token".into(),
                host: Some(host_sender),
                client: None,
                host_relay_proof: None,
                client_relay_proof: None,
                host_cancel: None,
                client_cancel: None,
                host_generation: 1,
                client_generation: 0,
                establishment_generation: 0,
                ready_pair: None,
                pending_host: std::collections::VecDeque::new(),
                pending_client: std::collections::VecDeque::new(),
                pending_host_bytes: 0,
                pending_client_bytes: 0,
                relay_host: None,
                relay_client: None,
                guests: std::collections::VecDeque::from([Guest {
                    id: "guest-id-1".into(),
                    token: "guest-token".into(),
                    input: false,
                    sender: None,
                    pending: std::collections::VecDeque::new(),
                    pending_bytes: 0,
                    active: false,
                    generation: 0,
                    relay_proof: None,
                }]),
                max_guests: 1,
            },
        );

        let app = Router::new()
            .route("/v1/signal/{session_id}/{role}", get(signal_socket))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        let websocket_request = || {
            let mut request = format!("ws://{address}/v1/signal/session-1/guest")
                .into_client_request()
                .expect("websocket request");
            request.headers_mut().insert(
                "authorization",
                "Bearer guest-token".parse().expect("authorization header"),
            );
            request
        };
        let (mut stale_socket, _) = connect_async(websocket_request())
            .await
            .expect("first guest connects");
        let (mut current_socket, _) = connect_async(websocket_request())
            .await
            .expect("replacement guest connects");

        timeout(Duration::from_secs(1), async {
            loop {
                if state.sessions.lock().await["session-1"].guests[0].generation == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement generation is installed");

        stale_socket
            .send(ClientMessage::Text(
                r#"{"type":"ice_candidate_done"}"#.into(),
            ))
            .await
            .expect("stale socket can submit a frame");
        assert!(
            timeout(Duration::from_millis(100), host_receiver.recv())
                .await
                .is_err()
        );

        current_socket
            .send(ClientMessage::Text(
                r#"{"type":"ice_candidate_done"}"#.into(),
            ))
            .await
            .expect("current socket can submit a frame");
        assert!(matches!(
            timeout(Duration::from_millis(100), host_receiver.recv())
                .await
                .expect("current socket forwards")
                .expect("host receiver remains connected"),
            Message::Text(text) if text.contains("ice_candidate_done")
        ));

        state
            .sessions
            .lock()
            .await
            .get_mut("session-1")
            .expect("test session")
            .host = None;
        stale_socket
            .send(ClientMessage::Text(
                r#"{"type":"ice_candidate","candidate":"candidate:1"}"#.into(),
            ))
            .await
            .expect("stale socket can submit another frame");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let session = state.sessions.lock().await;
        assert!(session["session-1"].pending_host.is_empty());
        drop(session);

        let _ = stale_socket.close(None).await;
        let _ = current_socket.close(None).await;
        server.abort();
    }

    #[test]
    fn session_creation_limiter_is_bounded_and_expires_old_events() {
        let start = Instant::now();
        let mut limiter = CreationLimiter::default();
        for _ in 0..MAX_SESSION_CREATES_PER_MINUTE {
            assert!(limiter.allow(start));
        }
        assert!(!limiter.allow(start));
        assert!(limiter.allow(start + SESSION_CREATE_WINDOW));
        assert_eq!(limiter.events.len(), 1);
        assert!(limiter.allow(start + SESSION_CREATE_WINDOW + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn expired_sessions_are_removed_and_their_sockets_are_closed() {
        let (sender, mut receiver) = mpsc::channel(2);
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            admin_token: None,
            allow_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        state.sessions.lock().await.insert(
            "expired".into(),
            Session {
                expires_at: Instant::now() - Duration::from_secs(1),
                host_token: "host-token".into(),
                client_token: "client-token".into(),
                host: Some(sender),
                client: None,
                host_relay_proof: None,
                client_relay_proof: None,
                host_cancel: None,
                client_cancel: None,
                host_generation: 1,
                client_generation: 0,
                establishment_generation: 0,
                ready_pair: None,
                pending_host: std::collections::VecDeque::new(),
                pending_client: std::collections::VecDeque::new(),
                pending_host_bytes: 0,
                pending_client_bytes: 0,
                relay_host: None,
                relay_client: None,
                guests: std::collections::VecDeque::new(),
                max_guests: 1,
            },
        );

        let senders = reap_expired_sessions(&state).await;
        assert_eq!(senders.len(), 1);
        assert!(state.sessions.lock().await.is_empty());
        senders[0]
            .try_send(Message::Close(None))
            .expect("close fits in the bounded queue");
        assert!(matches!(receiver.recv().await, Some(Message::Close(None))));
    }

    #[tokio::test]
    async fn relay_unregistration_is_idempotent_and_preserves_newer_registration() {
        let secret = b"test-relay-secret-0123456789".to_vec();
        let (host_sender, _) = mpsc::channel(1);
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            admin_token: None,
            allow_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: secret.clone(),
        };
        state.sessions.lock().await.insert(
            "session-1".into(),
            Session {
                expires_at: Instant::now() + Duration::from_secs(60),
                host_token: "host-token".into(),
                client_token: "client-token".into(),
                host: Some(host_sender),
                client: None,
                host_relay_proof: None,
                client_relay_proof: None,
                host_cancel: None,
                client_cancel: None,
                host_generation: 1,
                client_generation: 0,
                establishment_generation: 0,
                ready_pair: None,
                pending_host: std::collections::VecDeque::new(),
                pending_client: std::collections::VecDeque::new(),
                pending_host_bytes: 0,
                pending_client_bytes: 0,
                relay_host: None,
                relay_client: None,
                guests: std::collections::VecDeque::new(),
                max_guests: 1,
            },
        );

        let relay_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let relay_address = relay_socket.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(super::run_relay(relay_socket, state.clone(), shutdown_rx));

        let old_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let new_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let ticket = relay_ticket::mint(&secret, "session-1", "host", "host", 1);

        old_socket
            .send_to(
                &relay::encode_registration("session-1", relay::Role::Host, &ticket)
                    .expect("encode old registration"),
                relay_address,
            )
            .await
            .unwrap();
        receive_relay_ack(&old_socket, relay::Role::Host).await;

        new_socket
            .send_to(
                &relay::encode_registration("session-1", relay::Role::Host, &ticket)
                    .expect("encode new registration"),
                relay_address,
            )
            .await
            .unwrap();
        receive_relay_ack(&new_socket, relay::Role::Host).await;

        old_socket
            .send_to(
                &relay::encode_unregister("session-1", relay::Role::Host, &ticket)
                    .expect("encode stale unregister"),
                relay_address,
            )
            .await
            .unwrap();
        receive_unregister_ack(&old_socket, relay::Role::Host).await;

        {
            let sessions = state.sessions.lock().await;
            assert_eq!(
                sessions["session-1"]
                    .relay_host
                    .as_ref()
                    .map(|slot| slot.addr),
                Some(new_socket.local_addr().unwrap())
            );
        }

        new_socket
            .send_to(
                &relay::encode_unregister("session-1", relay::Role::Host, &ticket)
                    .expect("encode current unregister"),
                relay_address,
            )
            .await
            .unwrap();
        receive_unregister_ack(&new_socket, relay::Role::Host).await;
        assert!(
            state.sessions.lock().await["session-1"]
                .relay_host
                .is_none()
        );

        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay exits")
            .expect("relay task joins");
    }

    #[tokio::test]
    async fn replaced_connection_cannot_reissue_or_register_old_relay_ticket() {
        let secret = b"test-relay-secret-0123456789".to_vec();
        let (host_sender, _) = mpsc::channel(1);
        let mut session = test_session();
        session.host = Some(host_sender);
        session.host_generation = 1;
        session.host_relay_proof = Some("proof-1".into());
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::from([("session-1".into(), session)]))),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            admin_token: None,
            allow_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: secret.clone(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer host-token"),
        );
        headers.insert(
            "x-openstream-connection-proof",
            HeaderValue::from_static("proof-1"),
        );
        let response = super::session_relay_ticket(
            axum::extract::State(state.clone()),
            headers.clone(),
            axum::extract::Path("session-1".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("initial relay response body");
        let first_ticket = serde_json::from_slice::<serde_json::Value>(&body)
            .expect("initial relay response JSON")["ticket"]
            .as_str()
            .expect("initial relay ticket")
            .to_string();

        {
            let mut sessions = state.sessions.lock().await;
            let session = sessions.get_mut("session-1").expect("test session");
            session.host_generation = 2;
            session.host_relay_proof = Some("proof-2".into());
            session.relay_host = None;
        }

        // The old process still has the stable role bearer and its old
        // connection proof, but it must not mint a generation-two ticket.
        let stale_response = super::session_relay_ticket(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Path("session-1".into()),
        )
        .await;
        assert_eq!(stale_response.status(), StatusCode::UNAUTHORIZED);

        let mut current_headers = HeaderMap::new();
        current_headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer host-token"),
        );
        current_headers.insert(
            "x-openstream-connection-proof",
            HeaderValue::from_static("proof-2"),
        );
        let current_response = super::session_relay_ticket(
            axum::extract::State(state.clone()),
            current_headers,
            axum::extract::Path("session-1".into()),
        )
        .await;
        assert_eq!(current_response.status(), StatusCode::OK);
        let body = to_bytes(current_response.into_body(), 4096)
            .await
            .expect("replacement relay response body");
        let replacement_ticket = serde_json::from_slice::<serde_json::Value>(&body)
            .expect("replacement relay response JSON")["ticket"]
            .as_str()
            .expect("replacement relay ticket")
            .to_string();
        assert_eq!(
            relay_ticket::verify(&secret, "session-1", &replacement_ticket)
                .expect("replacement ticket verifies")
                .socket_generation,
            2
        );

        let relay_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("bind relay");
        let relay_address = relay_socket.local_addr().expect("relay address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(super::run_relay(relay_socket, state.clone(), shutdown_rx));
        let old_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("bind old socket");
        old_socket
            .send_to(
                &relay::encode_registration("session-1", relay::Role::Host, &first_ticket)
                    .expect("encode stale registration"),
                relay_address,
            )
            .await
            .expect("send stale registration");
        let mut bytes = [0_u8; 5];
        assert!(
            timeout(Duration::from_millis(200), old_socket.recv_from(&mut bytes))
                .await
                .is_err()
        );
        assert!(
            state.sessions.lock().await["session-1"]
                .relay_host
                .is_none()
        );

        let current_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("bind current socket");
        current_socket
            .send_to(
                &relay::encode_registration("session-1", relay::Role::Host, &replacement_ticket)
                    .expect("encode current registration"),
                relay_address,
            )
            .await
            .expect("send current registration");
        receive_relay_ack(&current_socket, relay::Role::Host).await;
        assert_eq!(
            state.sessions.lock().await["session-1"]
                .relay_host
                .as_ref()
                .expect("current registration owns relay")
                .addr,
            current_socket.local_addr().expect("current address")
        );

        shutdown_tx.send(true).expect("stop relay");
        timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay exits")
            .expect("relay task joins");
    }

    async fn receive_relay_ack(socket: &UdpSocket, role: relay::Role) {
        let mut bytes = [0_u8; 5];
        let (length, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
            .await
            .expect("registration ACK arrives")
            .expect("receive registration ACK");
        assert!(relay::is_ack(&bytes[..length], role));
    }

    async fn receive_unregister_ack(socket: &UdpSocket, role: relay::Role) {
        let mut bytes = [0_u8; 5];
        let (length, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
            .await
            .expect("unregister ACK arrives")
            .expect("receive unregister ACK");
        assert!(relay::is_unregister_ack(&bytes[..length], role));
    }

    #[test]
    fn signaling_validator_accepts_current_establishment_messages() {
        assert!(validate_signal_message(&format!(
            r#"{{"type":"path_candidate","generation":2,"token":"{}","kind":"direct_udp","ip":"127.0.0.1","port":4001}}"#,
            "aa".repeat(16),
        ))
        .is_ok());
        assert!(
            validate_signal_message(&format!(
                r#"{{"type":"key","public_key":"{}","identity_public_key":"{}","signature":"{}"}}"#,
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(64),
            ))
            .is_ok()
        );
        assert!(
            validate_signal_message(
                r#"{"type":"ice_credentials","ufrag":"short","pwd":"long-password"}"#
            )
            .is_ok()
        );
        assert!(validate_signal_message(
            r#"{"type":"ice_candidate","candidate":"candidate:1 1 udp 1 127.0.0.1 4000 typ host"}"#
        )
        .is_ok());
        assert!(validate_signal_message(r#"{"type":"ice_candidate_done"}"#).is_ok());
    }

    #[test]
    fn signaling_validator_rejects_unknown_and_malformed_messages() {
        for message in [
            r#"[]"#,
            r#"{"type":"unknown"}"#,
            r#"{"type":"candidate","kind":"host","ip":"127.0.0.1","port":4000}"#,
            r#"{"type":"candidate_done","count":1}"#,
            r#"{"type":"candidate","kind":"host","ip":"not-an-ip","port":4000}"#,
            r#"{"type":"candidate","kind":"host","ip":"127.0.0.1","port":0}"#,
            r#"{"type":"path_candidate","generation":2,"token":"00","kind":"direct_udp","ip":"127.0.0.1","port":4001}"#,
            r#"{"type":"key","public_key":"00"}"#,
            r#"{"type":"ice_candidate","candidate":""}"#,
        ] {
            assert!(
                validate_signal_message(message).is_err(),
                "accepted {message}"
            );
        }
    }

    #[test]
    fn direct_v2_validator_requires_bounded_positive_epoch_and_exact_fields() {
        assert!(validate_signal_message(
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.10","port":40001}"#
        )
        .is_ok());
        assert!(
            validate_signal_message(
                r#"{"type":"direct_candidate_done","establishment_generation":1,"count":2}"#
            )
            .is_ok()
        );
        assert!(validate_signal_message(&format!(
            r#"{{"type":"direct_key","establishment_generation":1,"public_key":"{}","identity_public_key":"{}","signature":"{}"}}"#,
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(64),
        ))
        .is_ok());

        for message in [
            r#"{"type":"direct_candidate","kind":"host","ip":"192.0.2.10","port":40001}"#,
            r#"{"type":"direct_candidate","establishment_generation":0,"kind":"host","ip":"192.0.2.10","port":40001}"#,
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"unknown","ip":"192.0.2.10","port":40001}"#,
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"not-an-ip","port":40001}"#,
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.10","port":0}"#,
            r#"{"type":"direct_candidate_done","establishment_generation":1,"count":0}"#,
            r#"{"type":"direct_candidate_done","establishment_generation":1,"count":33}"#,
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.10","port":40001,"extra":true}"#,
            r#"{"type":"direct_key","establishment_generation":1,"public_key":"00","identity_public_key":"00","signature":"00"}"#,
        ] {
            assert!(
                validate_signal_message(message).is_err(),
                "accepted malformed direct message {message}"
            );
        }
    }

    #[test]
    fn readiness_and_reset_are_server_generated_only() {
        assert!(
            validate_signal_message(r#"{"type":"peer_ready","establishment_generation":1}"#)
                .is_err()
        );
        assert!(
            validate_signal_message(
                r#"{"type":"peer_reset","establishment_generation":1,"reason":"role_replaced"}"#
            )
            .is_err()
        );
        assert!(
            validate_signal_message(
                r#"{"type":"peer_reset","establishment_generation":1,"reason":"a"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn pending_queue_drops_direct_records_but_preserves_ice_and_supported_messages() {
        let mut queue = std::collections::VecDeque::new();
        let mut queued_bytes = 0;
        queue_pending(
            &mut queue,
            &mut queued_bytes,
            Message::Text(
                r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.10","port":40001}"#.into(),
            ),
        );
        queue_pending(
            &mut queue,
            &mut queued_bytes,
            Message::Text(r#"{"type":"ice_candidate_done"}"#.into()),
        );
        queue_pending(
            &mut queue,
            &mut queued_bytes,
            Message::Text(r#"{"type":"ice_candidate","candidate":"candidate:1"}"#.into()),
        );

        assert_eq!(queue.len(), 2);
        assert_eq!(
            queued_bytes,
            queue.iter().map(super::message_len).sum::<usize>()
        );
        assert!(
            matches!(queue.front(), Some(Message::Text(text)) if text.contains("ice_candidate_done"))
        );
    }

    #[test]
    fn first_role_waits_and_complete_pair_gets_one_ready_record_per_socket() {
        let mut session = test_session();
        let (host_tx, mut host_rx) = mpsc::channel(8);
        assert_eq!(
            admit_primary_socket(&mut session, PrimaryRole::Host, &host_tx)
                .expect("first role is admitted"),
            1
        );
        assert!(session.ready_pair.is_none());
        assert_relay_proof(host_rx.try_recv().expect("host proof"), 1);
        assert!(host_rx.try_recv().is_err());

        let (client_tx, mut client_rx) = mpsc::channel(8);
        assert_eq!(
            admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx)
                .expect("second role is admitted"),
            1
        );
        assert_eq!(session.establishment_generation, 1);
        assert_relay_proof(client_rx.try_recv().expect("client proof"), 1);
        assert_peer_ready(host_rx.try_recv().expect("host readiness"), 1);
        assert_peer_ready(client_rx.try_recv().expect("client readiness"), 1);
        assert!(host_rx.try_recv().is_err());
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn replacement_sends_reset_before_next_ready_and_keeps_generations_distinct() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        assert_relay_proof(old_host_rx.try_recv().expect("initial host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("initial client proof"), 1);
        session.relay_host = Some(RelaySlot {
            addr: "127.0.0.1:40001".parse().expect("relay address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [7; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        assert_peer_ready(old_host_rx.try_recv().expect("initial host readiness"), 1);
        assert_peer_ready(client_rx.try_recv().expect("initial client readiness"), 1);

        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        assert_eq!(
            admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx)
                .expect("replacement host"),
            2
        );
        assert_eq!(session.establishment_generation, 2);
        assert_eq!(
            session
                .ready_pair
                .expect("replacement readiness")
                .host_generation,
            2
        );
        assert_eq!(
            session
                .ready_pair
                .expect("replacement readiness")
                .client_generation,
            1
        );
        assert!(session.relay_host.is_none());

        assert_relay_proof(new_host_rx.try_recv().expect("replacement host proof"), 2);
        let reset = message_text(client_rx.try_recv().expect("reset reaches survivor"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reset).expect("reset JSON")["type"],
            "peer_reset"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reset).expect("reset JSON")["establishment_generation"],
            1
        );
        assert_peer_ready(client_rx.try_recv().expect("next readiness"), 2);
        assert_peer_ready(new_host_rx.try_recv().expect("replacement readiness"), 2);
        assert!(client_rx.try_recv().is_err());
        assert!(old_host_rx.try_recv().is_ok());
    }

    #[test]
    fn partial_readiness_delivery_is_compensated_and_closes_the_pair() {
        let mut session = test_session();
        let (host_tx, mut host_rx) = mpsc::channel(8);
        let (client_tx, _client_rx) = mpsc::channel(1);
        client_tx
            .try_send(Message::Text("already-full".into()))
            .expect("fill client queue");
        session.host = Some(host_tx);
        session.client = Some(client_tx);
        session.host_generation = 1;
        session.client_generation = 1;
        session.relay_host = Some(RelaySlot {
            addr: "127.0.0.1:40001".parse().expect("host relay address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [3; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        session.relay_client = Some(RelaySlot {
            addr: "127.0.0.1:40002".parse().expect("client relay address"),
            owner: "client".into(),
            socket_generation: 1,
            ticket_digest: [4; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });

        assert!(publish_ready(&mut session).is_err());
        assert!(session.ready_pair.is_none());
        assert_eq!(session.establishment_generation, 1);
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(session.relay_host.is_none());
        assert!(session.relay_client.is_none());
        assert_peer_ready(host_rx.try_recv().expect("accepted readiness"), 1);
        let reset = message_text(host_rx.try_recv().expect("compensating reset"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reset).expect("reset JSON")["type"],
            "peer_reset"
        );
        assert!(matches!(host_rx.try_recv(), Ok(Message::Close(None))));
    }

    #[test]
    fn reset_delivery_failure_closes_survivor_and_publishes_no_replacement_epoch() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        session.relay_host = Some(RelaySlot {
            addr: "127.0.0.1:40001".parse().expect("host relay address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [5; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        session.relay_client = Some(RelaySlot {
            addr: "127.0.0.1:40002".parse().expect("client relay address"),
            owner: "client".into(),
            socket_generation: 1,
            ticket_digest: [6; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        assert_relay_proof(old_host_rx.try_recv().expect("initial host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("initial client proof"), 1);
        assert_peer_ready(old_host_rx.try_recv().expect("initial host readiness"), 1);
        assert_peer_ready(client_rx.try_recv().expect("initial client readiness"), 1);
        for _ in 0..8 {
            client_tx
                .try_send(Message::Text("full".into()))
                .expect("fill survivor queue");
        }

        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        assert!(admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx).is_err());
        assert!(session.ready_pair.is_none());
        assert_eq!(session.establishment_generation, 1);
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(session.relay_host.is_none());
        assert!(session.relay_client.is_none());
        assert!(new_host_rx.try_recv().is_err());
        assert!(matches!(old_host_rx.try_recv(), Ok(Message::Close(None))));
    }

    #[test]
    fn pending_drain_failure_closes_both_primary_sockets_and_revokes_relays() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        assert_relay_proof(old_host_rx.try_recv().expect("initial host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("initial client proof"), 1);
        assert_peer_ready(old_host_rx.try_recv().expect("initial host readiness"), 1);
        assert_peer_ready(client_rx.try_recv().expect("initial client readiness"), 1);
        session
            .pending_host
            .push_back(Message::Text(r#"{"type":"ice_candidate_done"}"#.into()));
        session.pending_host_bytes = session.pending_host.iter().map(super::message_len).sum();
        session.relay_host = Some(RelaySlot {
            addr: "127.0.0.1:40001".parse().expect("host relay address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [8; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        session.relay_client = Some(RelaySlot {
            addr: "127.0.0.1:40002".parse().expect("client relay address"),
            owner: "client".into(),
            socket_generation: 1,
            ticket_digest: [9; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });

        let (replacement_tx, mut replacement_rx) = mpsc::channel(1);
        replacement_tx
            .try_send(Message::Text("full".into()))
            .expect("fill replacement queue");
        assert!(admit_primary_socket(&mut session, PrimaryRole::Host, &replacement_tx).is_err());
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(session.ready_pair.is_none());
        assert!(session.relay_host.is_none());
        assert!(session.relay_client.is_none());
        assert!(matches!(old_host_rx.try_recv(), Ok(Message::Close(None))));
        assert!(
            matches!(client_rx.try_recv(), Ok(Message::Text(text)) if text.contains("peer_reset"))
        );
        assert!(matches!(client_rx.try_recv(), Ok(Message::Close(None))));
        assert!(matches!(replacement_rx.try_recv(), Ok(Message::Text(text)) if text == "full"));
    }

    #[test]
    fn epoch_overflow_expires_session_and_drops_current_senders() {
        let mut session = test_session();
        let (host_tx, mut host_rx) = mpsc::channel(2);
        let (client_tx, mut client_rx) = mpsc::channel(2);
        session.host = Some(host_tx);
        session.client = Some(client_tx);
        session.host_generation = 1;
        session.client_generation = 1;
        session.establishment_generation = u64::MAX;

        assert_eq!(
            publish_ready(&mut session),
            Err(ReadinessError::CounterExhausted)
        );
        assert!(session.expires_at <= Instant::now());
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(matches!(host_rx.try_recv(), Ok(Message::Close(None))));
        assert!(matches!(client_rx.try_recv(), Ok(Message::Close(None))));
    }

    #[test]
    fn socket_generation_overflow_expires_and_drops_the_complete_primary_pair() {
        let mut session = test_session();
        let (host_tx, mut host_rx) = mpsc::channel(4);
        let (client_tx, mut client_rx) = mpsc::channel(4);
        session.host = Some(host_tx);
        session.client = Some(client_tx);
        session.host_generation = u64::MAX;
        session.client_generation = 1;
        session.relay_host = Some(RelaySlot {
            addr: "127.0.0.1:40001".parse().expect("host relay address"),
            owner: "host".into(),
            socket_generation: 1,
            ticket_digest: [1; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });
        session.relay_client = Some(RelaySlot {
            addr: "127.0.0.1:40002".parse().expect("client relay address"),
            owner: "client".into(),
            socket_generation: 1,
            ticket_digest: [2; 32],
            last_seen: Instant::now(),
            window_started: Instant::now(),
            window_bytes: 0,
            window_packets: 0,
        });

        let (replacement_tx, mut replacement_rx) = mpsc::channel(4);
        assert_eq!(
            admit_primary_socket(&mut session, PrimaryRole::Host, &replacement_tx),
            Err(AdmissionError::SocketGenerationExhausted)
        );
        assert!(session.expires_at <= Instant::now());
        assert!(session.host.is_none());
        assert!(session.client.is_none());
        assert!(session.relay_host.is_none());
        assert!(session.relay_client.is_none());
        assert!(matches!(host_rx.try_recv(), Ok(Message::Close(None))));
        assert!(matches!(client_rx.try_recv(), Ok(Message::Close(None))));
        assert!(replacement_rx.try_recv().is_err());
    }

    #[test]
    fn stale_cleanup_cannot_clear_or_reset_a_replacement_socket() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        assert_relay_proof(old_host_rx.try_recv().expect("initial host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("initial client proof"), 1);
        assert_peer_ready(old_host_rx.try_recv().expect("initial host readiness"), 1);
        assert_peer_ready(client_rx.try_recv().expect("initial client readiness"), 1);
        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx).expect("replacement");
        let _ = client_rx.try_recv();
        let _ = client_rx.try_recv();
        let _ = new_host_rx.try_recv();
        let _ = new_host_rx.try_recv();

        assert!(!cleanup_primary_socket(&mut session, PrimaryRole::Host, 1));
        assert_eq!(session.host_generation, 2);
        assert_eq!(
            session
                .ready_pair
                .expect("current epoch")
                .establishment_generation,
            2
        );
        assert!(new_host_rx.try_recv().is_err());
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn direct_forwarding_requires_current_socket_and_ready_generation() {
        let mut session = test_session();
        let (host_tx, _host_rx) = mpsc::channel(8);
        let (client_tx, _client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");

        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::Forward(_)
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 0),
            DirectRoute::DropStale
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 2),
            DirectRoute::Future
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 0, 1),
            DirectRoute::StaleSocket
        ));

        session.ready_pair = None;
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::NotReady
        ));
    }

    #[test]
    fn epoch_pruning_removes_only_direct_v2_records_and_recomputes_queue_bytes() {
        let mut session = test_session();
        session.pending_host.push_back(Message::Text(
            r#"{"type":"direct_candidate","establishment_generation":1,"kind":"host","ip":"192.0.2.1","port":4000}"#.into(),
        ));
        session
            .pending_host
            .push_back(Message::Text(r#"{"type":"ice_candidate_done"}"#.into()));
        session.pending_host.push_back(Message::Text(
            r#"{"type":"path_candidate","generation":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"direct_udp","ip":"192.0.2.2","port":4001}"#.into(),
        ));
        session.pending_host_bytes = session.pending_host.iter().map(super::message_len).sum();

        prune_direct_establishment_messages(&mut session);

        assert_eq!(session.pending_host.len(), 2);
        assert!(
            session
                .pending_host
                .iter()
                .all(|message| !super::is_direct_establishment_message(message))
        );
        assert_eq!(
            session.pending_host_bytes,
            session
                .pending_host
                .iter()
                .map(super::message_len)
                .sum::<usize>()
        );
        assert!(
            session
                .pending_host
                .iter()
                .any(|message| message_text(message.clone()).contains("ice_candidate_done"))
        );
        assert!(
            session
                .pending_host
                .iter()
                .any(|message| message_text(message.clone()).contains("path_candidate"))
        );
    }
}
