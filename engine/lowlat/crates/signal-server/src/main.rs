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
use futures_util::{SinkExt, StreamExt};
use openstream_protocol::relay;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

mod turn;

/// Relay-ticket issuance and verification (H11).
///
/// The role bearer token must never transit the UDP relay path: it is a
/// WebSocket API capability. Instead, role holders fetch a relay ticket over
/// the authenticated REST API (`GET /v1/session/{id}/relay`) and present
/// that in the plaintext relay registration. A ticket is
/// `hex(HMAC-SHA256(relay_secret, "relay-ticket-v1" || 0x00 || session_id ||
/// 0x00 || role_class || 0x00 || subject)) || "." || subject`, so it is
/// session-, role-class-, and principal-bound, relay-only (useless on the
/// WebSocket API), and invalidated by session expiry/revocation and by server
/// restart when the secret is boot-random. The subject is an opaque role name
/// (`host`/`client`) or guest id; it is not a bearer token.
mod relay_ticket {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

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
    }

    pub(crate) fn mint(secret: &[u8], session_id: &str, class: &str, subject: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key");
        mac.update(b"relay-ticket-v1");
        mac.update(b"\x00");
        mac.update(session_id.as_bytes());
        mac.update(b"\x00");
        mac.update(class.as_bytes());
        mac.update(b"\x00");
        mac.update(subject.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = String::with_capacity(65 + subject.len());
        for byte in bytes {
            let _ = core::fmt::write(&mut out, format_args!("{byte:02x}"));
        }
        out.push('.');
        out.push_str(subject);
        out
    }

    /// Verify a presented ticket against both role classes in constant time.
    /// Returns the matched class and the non-secret principal subject.
    pub(crate) fn verify(secret: &[u8], session_id: &str, ticket: &str) -> Option<Verified> {
        let (mac, subject) = ticket.split_once('.')?;
        if mac.len() != 64
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
            .find(|class| super::ct_eq(&mint(secret, session_id, class, subject), ticket))
            .map(|class| Verified {
                class,
                subject: subject.to_string(),
            })
    }
}

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_TTL_SECONDS: u64 = 3600;
const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_PENDING_MESSAGES: usize = 128;
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
    /// Connection generations: incremented on every admit, captured by the
    /// connection task, and compared on disconnect cleanup so a stale
    /// connection can never clear a newer connection's sender.
    host_generation: u64,
    client_generation: u64,
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
            .field("pending_host", &self.pending_host.len())
            .field("pending_client", &self.pending_client.len())
            .field("relay_host", &self.relay_host)
            .field("relay_client", &self.relay_client)
            .field("guests", &self.guests)
            .field("max_guests", &self.max_guests)
            .finish_non_exhaustive()
    }
}

/// One relay endpoint registration: the source address plus which session
/// token owns it, and when it last carried traffic (idle slots are reaped).
#[derive(Debug, Clone)]
struct RelaySlot {
    addr: SocketAddr,
    /// Redacted owner identity: "host", "client", or a guest id.
    owner: String,
    last_seen: Instant,
    window_started: Instant,
    window_bytes: usize,
    window_packets: u32,
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
    session.guests.push_back(Guest {
        id: Uuid::new_v4().simple().to_string(),
        token: token.clone(),
        input: request.input,
        sender: None,
        pending: VecDeque::new(),
        pending_bytes: 0,
        active: false,
        generation: 0,
    });
    Json(GuestCreated {
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

/// Kick one admitted guest by full token. Authenticated by the host role
/// token or the admin token; the guest WebSocket is closed promptly.
async fn kick_guest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((session_id, guest_token)): Path<(String, String)>,
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
        let Some(position) = session
            .guests
            .iter()
            .position(|guest| ct_eq(&guest.token, &guest_token))
        else {
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
    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
        admin_token: std::env::var("OPENSTREAM_ADMIN_TOKEN")
            .ok()
            .filter(|token| !token.is_empty()),
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

    if let Some(relay_bind) = relay_bind {
        let socket = UdpSocket::bind(relay_bind).await?;
        println!("openstream UDP relay listening on {relay_bind}");
        tokio::spawn(run_relay(socket, state.clone()));
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
            "/v1/session/{session_id}/guests/{guest_token}",
            axum::routing::delete(kick_guest),
        )
        .route("/v1/signal/{session_id}/{role}", get(signal_socket))
        .with_state(state);

    println!("openstream-signal-server listening on http://{address}");
    if !admin_enabled {
        eprintln!(
            "OPENSTREAM_ADMIN_TOKEN is unset; management endpoints require OPENSTREAM_ALLOW_NO_AUTH=1 (loopback development only)"
        );
    }
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok\n"
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
        host_generation: 0,
        client_generation: 0,
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
    let relay_host_ticket = relay_ticket::mint(&state.relay_secret, &id, "host", "host");
    let relay_client_ticket = relay_ticket::mint(&state.relay_secret, &id, "client", "client");
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
        .as_secs()
        .max(1);
    let mut issued = turn.issue(&session_id, role, turn::now_unix());
    if issued.ttl_seconds > remaining {
        issued = turn.issue_with_ttl(&session_id, role, turn::now_unix(), remaining);
    }
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
/// Authenticated exactly like [`session_turn`], including the active guest.
/// The ticket is relay-only: it cannot be used on any WebSocket or REST
/// management API.
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
    let (class, subject) = if supplied_token.is_some_and(|token| ct_eq(token, &session.host_token))
    {
        ("host", "host".to_string())
    } else if supplied_token.is_some_and(|token| ct_eq(token, &session.client_token)) {
        ("client", "client".to_string())
    } else if let Some(guest) = supplied_token.and_then(|token| {
        session
            .guests
            .iter()
            .find(|guest| guest.active && ct_eq(&guest.token, token))
    }) {
        ("client", guest.id.clone())
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
        ticket: relay_ticket::mint(&state.relay_secret, &session_id, class, &subject),
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
    let (mut sink, mut source) = socket.split();
    // This queue is deliberately bounded. Signaling messages are small and
    // infrequent; backpressure is preferable to allowing a stalled peer to
    // consume unbounded memory in the service.
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(MAX_PENDING_MESSAGES);

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
                session.host_generation = session.host_generation.wrapping_add(1);
                let generation = session.host_generation;
                // A duplicate host connection replaces the old one: close it
                // promptly (try_send never blocks under the map lock) so the
                // stale task cannot keep forwarding as this role.
                if let Some(old) = session.host.replace(out_tx.clone()) {
                    let _ = old.try_send(Message::Close(None));
                }
                if !drain_into(
                    &mut session.pending_host,
                    &mut session.pending_host_bytes,
                    &out_tx,
                ) {
                    session.host.take();
                    return;
                }
                generation
            }
            Role::Client => {
                session.client_generation = session.client_generation.wrapping_add(1);
                let generation = session.client_generation;
                if let Some(old) = session.client.replace(out_tx.clone()) {
                    let _ = old.try_send(Message::Close(None));
                }
                if !drain_into(
                    &mut session.pending_client,
                    &mut session.pending_client_bytes,
                    &out_tx,
                ) {
                    session.client.take();
                    return;
                }
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
                let position = session
                    .guests
                    .iter()
                    .position(|guest| ct_eq(&guest.token, token));
                let Some(position) = position else {
                    return;
                };
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
                    let pending_ok = {
                        let guest = &mut session.guests[position];
                        drain_into(&mut guest.pending, &mut guest.pending_bytes, &out_tx)
                    };
                    if !pending_ok {
                        return;
                    }
                    let guest = &mut session.guests[position];
                    if let Some(old) = guest.sender.replace(out_tx.clone()) {
                        let _ = old.try_send(Message::Close(None));
                    }
                    guest.generation = guest.generation.wrapping_add(1);
                    guest.active = true;
                    guest.generation
                } else if out_tx
                    .try_send(Message::Text("{\"type\":\"parked\"}".into()))
                    .is_err()
                {
                    return;
                } else {
                    let guest = &mut session.guests[position];
                    if let Some(old) = guest.sender.replace(out_tx.clone()) {
                        let _ = old.try_send(Message::Close(None));
                    }
                    guest.generation = guest.generation.wrapping_add(1);
                    guest.active = false;
                    guest.generation
                }
            }
        };
        (expires_at, generation)
    };

    let mut writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
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
                let valid_object = serde_json::from_str::<serde_json::Value>(&text)
                    .map(|value| value.is_object())
                    .unwrap_or(false);
                if !valid_object {
                    if out_tx.try_send(Message::Text(
                        "{\"type\":\"error\",\"reason\":\"invalid_json\"}".into(),
                    )).is_err() {
                        break;
                    }
                    continue;
                }

                let message = Message::Text(text);
                let peers = {
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
                    sessions.get(&session_id).map(|session| match &role {
                            // Host announcements fan out to the legacy
                            // client and the active guest.
                            Role::Host => {
                                let mut peers = Vec::with_capacity(2);
                                if let Some(client) = session.client.clone() {
                                    peers.push(client);
                                }
                                if let Some(guest) = session
                                    .guests
                                    .iter()
                                    .find(|guest| guest.active)
                                    .and_then(|guest| guest.sender.clone())
                                {
                                    peers.push(guest);
                                }
                                peers
                            }
                            Role::Client | Role::Guest(_) => session
                                .host
                                .clone()
                                .map(|host| vec![host])
                                .unwrap_or_default(),
                        })
                };
                match peers {
                    None => break 'socket,
                    Some(peers) if peers.is_empty() => {
                        let mut sessions = state.sessions.lock().await;
                        if let Some(session) = sessions.get_mut(&session_id) {
                            if session.expires_at <= Instant::now() {
                                sessions.remove(&session_id);
                            } else {
                                // Drop-new past the bounds: the oldest queued
                                // messages are usually the handshake, which
                                // must survive a flooding peer.
                                match &role {
                                    Role::Host => {
                                        // Prefer the active guest's queue when
                                        // one is bridged; otherwise legacy.
                                        if let Some(guest) = session
                                            .guests
                                            .iter_mut()
                                            .find(|guest| guest.active)
                                        {
                                            let queue = &mut guest.pending;
                                            let bytes = &mut guest.pending_bytes;
                                            queue_pending(queue, bytes, message);
                                        } else {
                                            let queue = &mut session.pending_client;
                                            let bytes = &mut session.pending_client_bytes;
                                            queue_pending(queue, bytes, message);
                                        }
                                    }
                                    Role::Client | Role::Guest(_) => {
                                        let queue = &mut session.pending_host;
                                        let bytes = &mut session.pending_host_bytes;
                                        queue_pending(queue, bytes, message);
                                    }
                                }
                            }
                        }
                    }
                    Some(peers) => {
                        for peer in peers {
                            if !matches!(
                                tokio::time::timeout(
                                    Duration::from_secs(2),
                                    peer.send(message.clone()),
                                )
                                .await,
                                Ok(Ok(()))
                            ) {
                                break 'socket;
                            }
                        }
                    }
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
                break;
            }
        }
    }

    writer.abort();
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
                    if session.host_generation == generation {
                        session.host.take();
                    }
                    clear_relay_owner(session, "host");
                    None
                }
                Role::Client => {
                    if session.client_generation == generation {
                        session.client.take();
                    }
                    clear_relay_owner(session, "client");
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
    let size = message_len(&message);
    if queue.len() >= MAX_PENDING_MESSAGES || *queued_bytes + size > MAX_PENDING_BYTES {
        return;
    }
    *queued_bytes += size;
    queue.push_back(message);
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
async fn run_relay(socket: UdpSocket, state: AppState) {
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
                                        let class_matches = match registration.role {
                                            relay::Role::Host => {
                                                ticket.class == "host" && ticket.subject == "host"
                                            }
                                            relay::Role::Client => ticket.class == "client",
                                        };
                                        if !class_matches {
                                            false
                                        } else {
                                            let owner = match registration.role {
                                                relay::Role::Host => "host".to_string(),
                                                relay::Role::Client => {
                                                    ticket.subject.clone()
                                                }
                                            };
                                            // A valid ticket is not enough on
                                            // its own: require the bound
                                            // principal's live signaling
                                            // connection. This prevents a
                                            // parked/kicked guest from using a
                                            // previously issued client-class
                                            // ticket after losing admission.
                                            let principal_connected = match registration.role {
                                                relay::Role::Host => {
                                                    session.host.is_some()
                                                        && ticket.subject == "host"
                                                }
                                                relay::Role::Client => {
                                                    if ticket.subject == "client" {
                                                        session.client.is_some()
                                                    } else {
                                                        session.guests.iter().any(|guest| {
                                                            guest.active
                                                                && guest.sender.is_some()
                                                                && guest.id == ticket.subject
                                                        })
                                                    }
                                                }
                                            };
                                            if principal_connected {
                                                let slot = RelaySlot {
                                                    addr: source,
                                                    owner,
                                                    last_seen: Instant::now(),
                                                    window_started: Instant::now(),
                                                    window_bytes: 0,
                                                    window_packets: 0,
                                                };
                                                match registration.role {
                                                    relay::Role::Host => {
                                                        // Last registration wins,
                                                        // but only within one role
                                                        // class: host and client
                                                        // slots are separate, so a
                                                        // guest can never hijack
                                                        // the host slot.
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
                let mut sessions = state.sessions.lock().await;
                let now = Instant::now();
                sessions.retain(|_, session| session.expires_at > now);
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreationLimiter, Guest, MAX_GUESTS_CEILING, MAX_SESSION_CREATES_PER_MINUTE,
        RELAY_BYTES_PER_SECOND, RELAY_PACKETS_PER_SECOND, RelaySlot, SESSION_CREATE_WINDOW,
        authorized, bearer_token, max_guests_for_new_session, relay_ticket,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use std::time::{Duration, Instant};

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
        let host = relay_ticket::mint(secret, "session-1", "host", "host");
        let client = relay_ticket::mint(secret, "session-1", "client", "client");
        let verified_host =
            relay_ticket::verify(secret, "session-1", &host).expect("host ticket verifies");
        assert_eq!(verified_host.class, "host");
        assert_eq!(verified_host.subject, "host");
        let verified_client =
            relay_ticket::verify(secret, "session-1", &client).expect("client ticket verifies");
        assert_eq!(verified_client.class, "client");
        assert_eq!(verified_client.subject, "client");
        let guest = relay_ticket::mint(secret, "session-1", "client", "guest-id-1");
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
    fn relay_slot_enforces_packet_and_byte_budgets() {
        let start = Instant::now();
        let mut slot = RelaySlot {
            addr: "127.0.0.1:9000".parse().expect("address"),
            owner: "host".into(),
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
}
