//! Small self-hosted signaling service for OpenStream.
//!
//! This is intentionally an application-owned control plane. It does not
//! accept Parsec credentials and it does not pretend to be the Parsec service.
//! A pairing response gives the host and client separate, short-lived bearer
//! capabilities. WebSocket messages are validated as JSON objects and then
//! forwarded only to the opposite role in the same session.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures_util::{Sink, SinkExt, StreamExt};
use openstream_protocol::relay;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use uuid::Uuid;

mod connect;
mod control_plane;
mod turn;
use control_plane::{
    AccountPrincipal, AccountStore, ControlPlaneError, DeviceRegistration, DeviceTrust,
    IssuedTokens, PublicDevice, PublicUser,
};

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
// A fresh primary socket receives the relay proof and both server-authoritative
// establishment readiness records before its queued generic signaling. Keep
// those control records reserved even when the pending queue is full.
const MAX_OUTBOUND_MESSAGES: usize = MAX_PENDING_MESSAGES + 3;
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
/// Password verification is deliberately expensive, which makes an
/// unauthenticated request a lever on server CPU: one `/v1/auth/login` call
/// costs a PBKDF2 run at [`control_plane`]'s iteration count, and the store
/// is behind one mutex, so concurrent attempts serialize behind each other.
/// Without a bound, an attacker with a trickle of requests keeps the control
/// plane permanently busy.
///
/// This is a service-wide bound, matching [`CreationLimiter`]: the service
/// does not track per-source state, and inventing an unauthenticated identity
/// to bucket on would be its own spoofing problem. The consequence is honest
/// and worth stating -- a flood can exhaust the window and make legitimate
/// sign-in fail while it lasts -- but a refused login is recoverable, and an
/// exhausted control plane is not. Interactive sign-in is rare enough that
/// this bound is far above real use.
const MAX_AUTH_ATTEMPTS_PER_MINUTE: usize = 30;
const AUTH_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
/// Refresh has its own budget.
///
/// It is cheap -- a digest and a store write, no key derivation -- and it is
/// what a signed-in client does routinely. Sharing the password budget would
/// mean a stranger spending the login allowance could also stop every
/// legitimate session from renewing its credentials, which turns a nuisance
/// into an outage.
const MAX_REFRESH_ATTEMPTS_PER_MINUTE: usize = 240;
// Checked at compile time: renewal is the cheap, routine operation and its
// budget must never be the scarce one. Inverting these would let password
// spam starve every signed-in client's ability to stay signed in.
const _: () = assert!(MAX_REFRESH_ATTEMPTS_PER_MINUTE > MAX_AUTH_ATTEMPTS_PER_MINUTE);
/// Per-source budgets, applied alongside the service-wide ones.
///
/// The service-wide budget bounds total cost; it does not stop one source
/// spending the whole allowance and locking everyone else out. These are the
/// share any single source gets, and they are deliberately a small fraction
/// of the service total: a real operator signs in occasionally, and a source
/// that needs more than this is not a real operator.
const MAX_AUTH_ATTEMPTS_PER_SOURCE: usize = 6;
const MAX_REFRESH_ATTEMPTS_PER_SOURCE: usize = 60;
// Checked at compile time: a per-source share that equalled the service total
// would not be a share at all -- one source could still spend everything.
const _: () = assert!(MAX_AUTH_ATTEMPTS_PER_SOURCE < MAX_AUTH_ATTEMPTS_PER_MINUTE);
const _: () = assert!(MAX_REFRESH_ATTEMPTS_PER_SOURCE < MAX_REFRESH_ATTEMPTS_PER_MINUTE);
/// How many distinct sources are tracked at once.
///
/// Bounded because the keys come from unauthenticated requests: an attacker
/// with a range of addresses would otherwise grow this map for free. When it
/// is full the oldest-used entry is evicted, which costs that source its
/// history and nothing else -- the service-wide budget is still underneath.
const MAX_TRACKED_AUTH_SOURCES: usize = 4096;

/// Concurrent password derivations.
///
/// Each one is hundreds of milliseconds of CPU. They no longer hold the
/// account-store lock, so without a bound an accepted burst would simply
/// occupy every blocking thread instead. Two at a time keeps sign-in
/// responsive while leaving the machine to the media path.
const MAX_CONCURRENT_PASSWORD_DERIVATIONS: usize = 2;
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
/// Inbound signalling is bursty but tiny: candidate exchange, a key, a
/// capability round. An authenticated peer that exceeds this is either broken
/// or abusive, and every frame it sends costs a lock acquisition and a JSON
/// parse. The idle timeout bounds a silent socket; this bounds a loud one.
const MAX_INBOUND_MESSAGES_PER_SECOND: u32 = 120;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    AdminToken,
    LoopbackNoAuth,
    PrivateLanNoAuth,
    LockedDown,
}

/// Return whether an address belongs to an explicitly local-only network.
///
/// This deliberately does not treat shared CGNAT space, documentation space,
/// or arbitrary hostnames as private LAN addresses. Private-LAN no-account
/// mode must use a numeric bind address so it cannot accidentally expose an
/// unauthenticated wildcard or public listener.
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

/// Validate the startup authentication/bind combination before the listener
/// is created. `bind_explicit` is separate from the parsed address so private
/// LAN mode cannot silently fall back to the loopback default.
fn validate_startup_auth(
    address: SocketAddr,
    bind_explicit: bool,
    admin_token_configured: bool,
    allow_no_auth: bool,
    local_no_auth: bool,
) -> Result<AuthMode, &'static str> {
    if allow_no_auth && local_no_auth {
        return Err("OPENSTREAM_ALLOW_NO_AUTH and OPENSTREAM_LOCAL_NO_AUTH cannot both be enabled");
    }
    if local_no_auth {
        if admin_token_configured {
            return Err("OPENSTREAM_LOCAL_NO_AUTH requires OPENSTREAM_ADMIN_TOKEN to be unset");
        }
        if !bind_explicit {
            return Err(
                "OPENSTREAM_LOCAL_NO_AUTH requires an explicit OPENSTREAM_SIGNAL_BIND address",
            );
        }
        if !is_private_lan_address(address.ip()) {
            return Err(
                "OPENSTREAM_LOCAL_NO_AUTH requires an explicit RFC1918, ULA, or link-local bind",
            );
        }
        return Ok(AuthMode::PrivateLanNoAuth);
    }
    if allow_no_auth && !address.ip().is_loopback() {
        return Err("OPENSTREAM_ALLOW_NO_AUTH requires a loopback bind");
    }
    if admin_token_configured {
        return Ok(AuthMode::AdminToken);
    }
    if !address.ip().is_loopback() {
        return Err(
            "non-loopback signaling requires OPENSTREAM_ADMIN_TOKEN or explicit local mode",
        );
    }
    if allow_no_auth {
        Ok(AuthMode::LoopbackNoAuth)
    } else {
        Ok(AuthMode::LockedDown)
    }
}

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
    /// Bounds unauthenticated password-verification work. See
    /// [`MAX_AUTH_ATTEMPTS_PER_MINUTE`].
    auth_attempts: Arc<Mutex<RateWindow>>,
    /// Separate budget for credential renewal. See
    /// [`MAX_REFRESH_ATTEMPTS_PER_MINUTE`].
    refresh_attempts: Arc<Mutex<RateWindow>>,
    /// Per-source shares of the two budgets above, so one source cannot
    /// spend the whole service allowance.
    auth_sources: Arc<Mutex<SourceLimiter>>,
    refresh_sources: Arc<Mutex<SourceLimiter>>,
    /// Reverse proxies whose forwarding header may be believed.
    trusted_proxies: Arc<Vec<IpAddr>>,
    /// Admission control for concurrent key derivations. See
    /// [`MAX_CONCURRENT_PASSWORD_DERIVATIONS`].
    password_derivations: Arc<tokio::sync::Semaphore>,
    /// Whether an unauthenticated caller may create an account. See
    /// [`authorize_registration`].
    open_registration: bool,
    accounts: Arc<Mutex<AccountStore>>,
    /// The secure Connect broker: presence, connection requests, approvals,
    /// and single-delivery role credentials. See [`connect`].
    connect: Arc<Mutex<connect::ConnectBroker>>,
    admin_token: Option<String>,
    /// Explicit loopback development mode. With no admin token and without
    /// this flag, management endpoints refuse every request.
    allow_no_auth: bool,
    /// Explicit private-LAN no-account mode. This bypasses only management
    /// admin authentication after startup verifies a private numeric bind;
    /// role/session capabilities remain mandatory everywhere else.
    local_no_auth: bool,
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
            .field("open_registration", &self.open_registration)
            .field("accounts", &"[redacted durable store]")
            // Tokens and the relay secret never render in logs.
            .field(
                "admin_token",
                &self.admin_token.as_ref().map(|_| "[redacted]"),
            )
            .field("allow_no_auth", &self.allow_no_auth)
            .field("local_no_auth", &self.local_no_auth)
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
    /// How much of the window's budget is currently spent.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.events.len()
    }

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

/// Per-source fixed-window counters, bounded in number.
///
/// Keyed by the caller's address rather than by anything the caller asserts
/// about itself, except where an operator has said a hop may be believed --
/// see [`request_source`].
#[derive(Debug, Default)]
struct SourceLimiter {
    sources: HashMap<IpAddr, (RateWindow, Instant)>,
}

impl SourceLimiter {
    /// Whether this source has room under its per-source cap, without recording.
    /// The source's last-seen time is refreshed even on a check so a
    /// throttled-but-active source is not evicted and thereby handed a fresh
    /// budget.
    fn has_capacity(
        &mut self,
        source: IpAddr,
        now: Instant,
        limit: usize,
        window: Duration,
    ) -> bool {
        match self.sources.get_mut(&source) {
            Some((events, seen)) => {
                *seen = now;
                events.has_capacity(now, limit, window)
            }
            // A source with no history has room as long as the cap is non-zero.
            None => limit > 0,
        }
    }

    /// Record one event for this source, evicting the stalest tracked source
    /// first when the table is full and this source is new.
    fn record(&mut self, source: IpAddr, now: Instant) {
        if self.sources.len() >= MAX_TRACKED_AUTH_SOURCES && !self.sources.contains_key(&source) {
            // Drop whichever source has been quiet longest. Evicting on
            // last-use rather than insertion means an active attacker cannot
            // push out an active operator by churning through addresses.
            if let Some(stalest) = self
                .sources
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(address, _)| *address)
            {
                self.sources.remove(&stalest);
            }
        }
        let entry = self
            .sources
            .entry(source)
            .or_insert_with(|| (RateWindow::default(), now));
        entry.1 = now;
        entry.0.record(now);
    }

    /// Check this source's budget and, if there is room, record one event.
    /// The multi-budget auth path uses `has_capacity` + `record` instead, so a
    /// request refused by another budget consumes nothing here. Retained as a
    /// single-budget convenience for tests.
    #[cfg(test)]
    fn allow(&mut self, source: IpAddr, now: Instant, limit: usize, window: Duration) -> bool {
        if self.has_capacity(source, now, limit, window) {
            self.record(source, now);
            true
        } else {
            false
        }
    }
}

/// The address a request is attributed to for rate limiting.
///
/// The peer address by default. `X-Forwarded-For` is believed only when the
/// direct peer is one of the operator's configured trusted proxies. Believing
/// it from an arbitrary peer would be worse than having no per-source limiting
/// at all: an attacker would get an unlimited supply of identities simply by
/// choosing a new header value.
///
/// # Why the whole list, walked from the right
///
/// `X-Forwarded-For` can arrive as several header fields, and each field can
/// carry several comma-separated hops. HTTP says repeated fields are one list
/// in order, so reading a single field -- which is what this did -- silently
/// ignores every hop recorded by a proxy that appended its own field instead
/// of extending the first.
///
/// The entries the client controls are on the *left*: it can send whatever
/// prefix it likes, and each proxy appends the address it actually observed.
/// Only the rightmost entries, contributed by hops the operator trusts, mean
/// anything. So the list is walked right to left, skipping trusted proxies,
/// and the first address that is not a trusted proxy is the attribution -- it
/// is the closest hop that a trusted proxy vouched for.
///
/// With `client -> Cloudflare -> nginx -> OpenStream`, taking only the last
/// entry attributes every request to nginx, which collapses the whole
/// internet into one rate-limit bucket. Walking past both trusted hops
/// reaches the client.
///
/// A malformed entry stops the walk rather than being skipped: past it the
/// list can no longer be trusted to be what a proxy wrote, and attributing
/// the request to the last hop that was still verifiable is the conservative
/// answer.
fn request_source(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    let forwarded: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    let mut attributed = peer;
    for entry in forwarded.iter().rev() {
        // Parsed during the right-to-left walk, never before it. Rejecting
        // the whole list up front would let a client put one unparseable
        // entry at the left -- the end it controls -- and force every request
        // back onto the proxy's own shared bucket, which is the limiter
        // failing open.
        let Ok(candidate) = entry.parse::<IpAddr>() else {
            break;
        };
        attributed = candidate;
        if !trusted_proxies.contains(&candidate) {
            break;
        }
    }
    attributed
}

/// Trusted reverse proxies, from `OPENSTREAM_TRUSTED_PROXIES`.
///
/// Exact addresses only, comma separated. Empty by default, which means no
/// forwarding header is ever believed.
fn trusted_proxies_from_environment() -> Vec<IpAddr> {
    std::env::var("OPENSTREAM_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
        .collect()
}

/// A fixed-window counter with an explicit bound and window.
///
/// Same shape as [`CreationLimiter`], parameterised because the auth window
/// needs different limits. Bounded by construction: the retained events can
/// never exceed the limit, so a flood cannot grow this.
#[derive(Debug, Default)]
struct RateWindow {
    events: VecDeque<Instant>,
}

impl RateWindow {
    /// Whether another event fits under `limit` in the trailing `window`,
    /// pruning expired events. This records nothing, so a caller can check
    /// several budgets and consume them only when all of them have room.
    fn has_capacity(&mut self, now: Instant, limit: usize, window: Duration) -> bool {
        self.events
            .retain(|event| now.saturating_duration_since(*event) < window);
        self.events.len() < limit
    }

    /// Record one event at `now`.
    fn record(&mut self, now: Instant) {
        self.events.push_back(now);
    }

    /// Check capacity and, if there is room, record one event. Retained as a
    /// single-budget convenience for tests; the auth path composes several
    /// budgets with `has_capacity` + `record` so a rejection consumes nothing.
    #[cfg(test)]
    fn allow(&mut self, now: Instant, limit: usize, window: Duration) -> bool {
        if self.has_capacity(now, limit, window) {
            self.record(now);
            true
        } else {
            false
        }
    }
}

struct Session {
    expires_at: Instant,
    /// Who this session belongs to, and who the two ends are.
    ///
    /// A session used to be an anonymous pair of capabilities with a TTL.
    /// That is enough to stream and not enough to administer: an operator
    /// cannot see whose session is running, cannot revoke every session
    /// belonging to a compromised account, and cannot answer "which device
    /// was this" after the fact. `None` means a provisioning session created
    /// through the admin endpoint, which by construction has no account.
    ownership: Option<SessionOwnership>,
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
            .field("ownership", &self.ownership)
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

/// Who a session belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionOwnership {
    account_id: String,
    /// The device that asked for the session, which holds the client role.
    requester_device_id: String,
    /// The device that approved it, which holds the host role.
    target_device_id: String,
    /// The broker request this session came from, for audit.
    request_id: String,
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
    // Answer --version before anything starts. A release binary that cannot
    // say what it is gives the packaging gate nothing to check, and starting
    // a server in reply to a version query is worse than staying silent.
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--version")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let configured_bind = std::env::var("OPENSTREAM_SIGNAL_BIND").ok();
    let bind = configured_bind
        .as_deref()
        .unwrap_or(DEFAULT_BIND)
        .to_string();
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
    let account_path = control_plane::default_store_path();
    let accounts = AccountStore::open(&account_path).map_err(|error| {
        format!(
            "failed to open control-plane state store {}: {error}",
            account_path.display()
        )
    })?;
    // The count, not the contents. An operator needs to know whether the
    // durable store was actually found -- an empty one after a restart means
    // the path moved, and that looks identical to a working service until
    // someone tries to sign in.
    eprintln!(
        "control-plane state store {} loaded with {} account(s)",
        account_path.display(),
        accounts.account_count()
    );
    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
        auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
        refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
        auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
        refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
        trusted_proxies: Arc::new(trusted_proxies_from_environment()),
        password_derivations: Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_PASSWORD_DERIVATIONS,
        )),
        open_registration: std::env::var("OPENSTREAM_ALLOW_OPEN_REGISTRATION").as_deref()
            == Ok("1"),
        accounts: Arc::new(Mutex::new(accounts)),
        connect: Arc::new(Mutex::new(connect::ConnectBroker::default())),
        admin_token,
        allow_no_auth: std::env::var("OPENSTREAM_ALLOW_NO_AUTH").as_deref() == Ok("1"),
        local_no_auth: std::env::var("OPENSTREAM_LOCAL_NO_AUTH").as_deref() == Ok("1"),
        relay_address,
        turn: turn::TurnConfig::from_env(),
        relay_secret,
    };
    let auth_mode = validate_startup_auth(
        address,
        configured_bind.is_some(),
        state.admin_token.is_some(),
        state.allow_no_auth,
        state.local_no_auth,
    )
    .map_err(|reason| format!("invalid signaling authentication/bind configuration: {reason}"))?;
    if matches!(auth_mode, AuthMode::LockedDown) {
        eprintln!(
            "OPENSTREAM_ADMIN_TOKEN is unset and OPENSTREAM_ALLOW_NO_AUTH is not 1: session management endpoints will refuse every request"
        );
    }
    if matches!(auth_mode, AuthMode::PrivateLanNoAuth) {
        eprintln!(
            "WARNING: OPENSTREAM_LOCAL_NO_AUTH is enabled on private-LAN bind {address}; management authentication is disabled for trusted local-network use only"
        );
    }
    if state.turn.is_none() {
        eprintln!(
            "OPENSTREAM_TURN_SECRET/OPENSTREAM_TURN_URLS are unset; the /turn endpoint reports unavailable"
        );
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version_info))
        .route("/v1/auth/registration", get(registration_capability))
        .route("/v1/auth/register", post(register_account))
        .route("/v1/auth/login", post(login_account))
        .route("/v1/auth/refresh", post(refresh_account))
        .route(
            "/v1/devices",
            get(list_account_devices).post(enroll_account_device),
        )
        .route(
            "/v1/devices/{device_id}/trust",
            patch(set_account_device_trust),
        )
        .route(
            "/v1/presence",
            post(connect_presence).delete(connect_offline),
        )
        .route("/v1/connect", post(connect_request))
        .route("/v1/connect/pending", get(connect_pending))
        .route("/v1/connect/{request_id}", get(connect_observe))
        .route("/v1/connect/{request_id}/approve", post(connect_approve))
        .route("/v1/connect/{request_id}/deny", post(connect_deny))
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
        // Authentication and registration bodies are small by construction:
        // no endpoint in this service accepts arbitrary file or media data.
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state.clone());

    println!("openstream-signal-server listening on http://{address}");
    if matches!(auth_mode, AuthMode::LockedDown) {
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
    // `into_make_service_with_connect_info` is what makes the peer address
    // available to the handlers. Without it the `ConnectInfo` extractor in the
    // authentication routes cannot resolve and those requests fail.
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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

/// What revision is actually running.
///
/// `/healthz` proves the process answers; it says nothing about which commit
/// it was built from, which is exactly what makes a stale or partial deploy
/// indistinguishable from a good one. `git_sha` is baked in at compile time
/// (see `build.rs`) rather than read at runtime, so it can't be spoofed by
/// anything reachable through the network stack this binary serves.
async fn version_info() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("OPENSTREAM_BUILD_SHA"),
    })
}

/// Whether this deployment will accept an anonymous `POST /v1/auth/register`
/// right now.
///
/// The shell offered "Create an account" unconditionally, but a closed
/// deployment only accepts anonymous registration for the very first account
/// (see [`authorize_registration`]). Every later user therefore saw a button
/// that could not succeed and a generic failure after pressing it, which reads
/// as a broken product rather than a closed one.
///
/// Advertising it leaks nothing that was not already probeable: anyone can
/// discover the same fact by attempting the registration this answers for.
/// The admin-token path is deliberately not reflected here -- that is an
/// authenticated capability and this endpoint is unauthenticated, so it
/// answers only the question the login screen actually asks.
async fn registration_capability(State(state): State<AppState>) -> Json<RegistrationCapability> {
    let open = if state.open_registration {
        true
    } else {
        state.accounts.lock().await.account_count() == 0
    };
    Json(RegistrationCapability { open })
}

#[derive(Debug, Serialize)]
struct RegistrationCapability {
    open: bool,
}

#[derive(Debug, Serialize)]
struct VersionInfo {
    name: &'static str,
    version: &'static str,
    git_sha: &'static str,
}

#[derive(Debug, Deserialize)]
struct AccountCredentials {
    username: String,
    password: String,
    #[serde(default)]
    device: Option<DeviceRegistrationRequest>,
}

#[derive(Debug, Deserialize)]
struct RefreshAccount {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct DeviceRegistrationRequest {
    device_id: String,
    name: String,
    platform: String,
    /// Public identity keys cross the JSON boundary as hex. The raw key is
    /// accepted only by the authenticated control-plane request and is never
    /// copied into a UI snapshot or diagnostic record.
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTrustRequest {
    trust: DeviceTrust,
}

#[derive(Debug, Serialize)]
struct AccountAuthResponse {
    access_token: String,
    refresh_token: String,
    access_expires_in_seconds: u64,
    refresh_expires_in_seconds: u64,
    user: PublicUser,
    device: Option<PublicDevice>,
}

impl From<IssuedTokens> for AccountAuthResponse {
    fn from(tokens: IssuedTokens) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            access_expires_in_seconds: tokens.access_expires_in_seconds,
            refresh_expires_in_seconds: tokens.refresh_expires_in_seconds,
            user: tokens.user,
            device: tokens.device,
        }
    }
}

/// Consume one slot from a service-wide window and a per-source window, but
/// only when both have room. Returns whether the request is allowed.
///
/// The order matters: an earlier version recorded the service-wide event before
/// the per-source check, so a source over its own cap still burned the shared
/// budget on every refused request and could throttle every other client.
/// Recording only when both budgets have capacity makes a refused request cost
/// nothing.
fn consume_dual_budget(
    attempts: &mut RateWindow,
    sources: &mut SourceLimiter,
    source: IpAddr,
    now: Instant,
    total_limit: usize,
    per_source_limit: usize,
    window: Duration,
) -> bool {
    if attempts.has_capacity(now, total_limit, window)
        && sources.has_capacity(source, now, per_source_limit, window)
    {
        attempts.record(now);
        sources.record(source, now);
        true
    } else {
        false
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], ControlPlaneError> {
    let bytes =
        hex::decode(value).map_err(|_| ControlPlaneError::InvalidInput("public key is invalid"))?;
    bytes
        .try_into()
        .map_err(|_| ControlPlaneError::InvalidInput("public key is invalid"))
}

fn device_registration(
    request: DeviceRegistrationRequest,
) -> Result<DeviceRegistration, ControlPlaneError> {
    Ok(DeviceRegistration {
        device_id: request.device_id,
        name: request.name,
        platform: request.platform,
        public_key: decode_public_key(&request.public_key)?,
    })
}

fn control_error_response(error: ControlPlaneError) -> Response {
    let status = match error {
        ControlPlaneError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        ControlPlaneError::AlreadyExists => StatusCode::CONFLICT,
        ControlPlaneError::NotFound => StatusCode::NOT_FOUND,
        ControlPlaneError::Unauthorized | ControlPlaneError::DeviceIdentityRevoked { .. } => {
            StatusCode::UNAUTHORIZED
        }
        ControlPlaneError::DevicePending | ControlPlaneError::DeviceRevoked => {
            StatusCode::FORBIDDEN
        }
        ControlPlaneError::InvalidStore | ControlPlaneError::Io(_) | ControlPlaneError::Json(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    // A store fault is the operator's problem to fix and they cannot fix what
    // they cannot see, so the cause goes to the service log. It never goes to
    // the client: a 5xx is all a caller can act on, and the alternative leaks
    // store paths and parser offsets to an unauthenticated request.
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        let cause = std::error::Error::source(&error)
            .map_or_else(|| error.to_string(), ToString::to_string);
        eprintln!("control-plane store failure: {cause}");
    }
    // Keep password, token, path and parser details out of a network error.
    // The status code is enough for the client to select a safe recovery path.
    (status, "control-plane request failed\n").into_response()
}

fn unauthorized_response() -> Response {
    (StatusCode::UNAUTHORIZED, "account authorization required\n").into_response()
}

/// Consume one slot from the unauthenticated password-verification budget.
///
/// Applied before the store lock is taken, so a refused attempt costs nothing
/// beyond the counter and cannot queue behind an in-flight PBKDF2 run.
#[allow(
    clippy::result_large_err,
    reason = "the error is the finished axum Response this handler will return; \
boxing it would allocate once per refused request to move bytes that are \
constructed either way"
)]
async fn allow_auth_attempt(state: &AppState, source: IpAddr) -> Result<(), Response> {
    let now = Instant::now();
    let mut attempts = state.auth_attempts.lock().await;
    let mut sources = state.auth_sources.lock().await;
    if consume_dual_budget(
        &mut attempts,
        &mut sources,
        source,
        now,
        MAX_AUTH_ATTEMPTS_PER_MINUTE,
        MAX_AUTH_ATTEMPTS_PER_SOURCE,
        AUTH_ATTEMPT_WINDOW,
    ) {
        return Ok(());
    }
    Err((
        StatusCode::TOO_MANY_REQUESTS,
        "authentication rate limit exceeded\n",
    )
        .into_response())
}

/// Consume one slot from the credential-renewal budget.
#[allow(
    clippy::result_large_err,
    reason = "the error is the finished axum Response this handler will return; \
boxing it would allocate once per refused request to move bytes that are \
constructed either way"
)]
async fn allow_refresh_attempt(state: &AppState, source: IpAddr) -> Result<(), Response> {
    let now = Instant::now();
    // Same all-or-nothing accounting as authentication: a request refused by
    // the per-source cap must not consume the shared renewal budget.
    let mut attempts = state.refresh_attempts.lock().await;
    let mut sources = state.refresh_sources.lock().await;
    if consume_dual_budget(
        &mut attempts,
        &mut sources,
        source,
        now,
        MAX_REFRESH_ATTEMPTS_PER_MINUTE,
        MAX_REFRESH_ATTEMPTS_PER_SOURCE,
        AUTH_ATTEMPT_WINDOW,
    ) {
        return Ok(());
    }
    Err((
        StatusCode::TOO_MANY_REQUESTS,
        "credential renewal rate limit exceeded\n",
    )
        .into_response())
}

/// Run a synchronous, CPU-bound step without stalling the executor.
///
/// On the multi-threaded runtime the service actually runs on,
/// `block_in_place` hands the current worker's other tasks to a sibling
/// thread first, so a key derivation cannot stall unrelated WebSocket
/// forwarding that happens to share a worker.
///
/// `block_in_place` panics on a current-thread runtime, which is what
/// `#[tokio::test]` builds by default, so the flavor is checked rather than
/// assumed. Running inline there is correct: a test has no co-scheduled
/// session traffic to protect.
fn without_blocking_the_executor<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

/// Derive a password verifier under admission control, holding no store lock.
///
/// This is the expensive half of authentication and it is deliberately
/// performed between two short locked sections rather than inside one. Two
/// things follow: a burst of accepted attempts does not serialize behind the
/// account store, so device listing and session creation stay responsive
/// while someone is signing in; and the number of simultaneous derivations is
/// bounded, so an accepted burst cannot occupy every blocking thread.
#[allow(
    clippy::result_large_err,
    reason = "the error is the finished axum Response this handler will return; \
boxing it would allocate once per refused request to move bytes that are \
constructed either way"
)]
async fn derive_password_bounded(
    state: &AppState,
    password: &str,
    salt: [u8; 16],
) -> Result<[u8; 32], Response> {
    derive_password_bounded_with(
        state,
        password,
        salt,
        control_plane::PasswordScheme::current(),
    )
    .await
}

/// Derive under an explicit scheme, still bounded and still off the executor.
///
/// Verification must reproduce the scheme the stored record was written with,
/// so the cost cannot be a constant at this layer.
#[allow(clippy::result_large_err, reason = "the error is an HTTP response")]
async fn derive_password_bounded_with(
    state: &AppState,
    password: &str,
    salt: [u8; 16],
    scheme: control_plane::PasswordScheme,
) -> Result<[u8; 32], Response> {
    let Ok(_permit) = state.password_derivations.clone().acquire_owned().await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "control plane is shutting down\n",
        )
            .into_response());
    };
    Ok(without_blocking_the_executor(|| {
        control_plane::derive_password_with(password, &salt, scheme)
    }))
}

/// On what basis a request is allowed to create an account.
///
/// Carried rather than collapsed to a `bool` because the basis has to be
/// re-checked when the registration actually completes. Authorization happens
/// under one lock, the key derivation happens with no lock at all, and the
/// insertion happens under a later one -- so a condition that was true at the
/// first step is only a claim by the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationAuthorization {
    /// The administrator capability was presented.
    Admin,
    /// The operator deliberately runs an open endpoint.
    ExplicitlyOpen,
    /// The store was empty: this is a first-run bootstrap, and it stays valid
    /// only while the store is *still* empty at insertion time.
    Bootstrap,
}

impl RegistrationAuthorization {
    /// Whether completion must re-prove an empty store.
    const fn requires_empty_store(self) -> bool {
        matches!(self, Self::Bootstrap)
    }
}

/// On what basis, if any, this request may create an account.
///
/// Registration is closed by default. An open endpoint on a reachable service
/// lets a stranger create accounts and, because a 409 distinguishes a taken
/// username from a free one, enumerate the ones that already exist -- a
/// channel no amount of constant-time password comparison closes.
///
/// Two ways remain open, both deliberate:
///
/// - an empty store accepts the first account, so a freshly installed
///   self-hosted service can be bootstrapped by whoever reaches it first,
///   which is the same trust model as the rest of first-run setup;
/// - `OPENSTREAM_ALLOW_OPEN_REGISTRATION=1` restores an open endpoint for a
///   deployment that actually wants one.
///
/// Otherwise the administrator capability is required, and the 409 is only
/// ever visible to someone already holding it.
async fn authorize_registration(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<RegistrationAuthorization> {
    if admin_allowed(state, headers) {
        return Some(RegistrationAuthorization::Admin);
    }
    if state.open_registration {
        return Some(RegistrationAuthorization::ExplicitlyOpen);
    }
    (state.accounts.lock().await.account_count() == 0)
        .then_some(RegistrationAuthorization::Bootstrap)
}

#[allow(
    clippy::result_large_err,
    reason = "the error is the finished axum Response this handler will return; \
boxing it would allocate once per refused request to move bytes that are \
constructed either way"
)]
async fn account_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AccountPrincipal, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized_response());
    };
    let mut accounts = state.accounts.lock().await;
    accounts
        .authorize_access(token, control_plane::now_ms())
        .ok_or_else(unauthorized_response)
}

async fn register_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AccountCredentials>,
) -> Response {
    let source = request_source(peer.ip(), &headers, &state.trusted_proxies);
    let Some(authorization) = authorize_registration(&state, &headers).await else {
        return (StatusCode::FORBIDDEN, "account registration is closed\n").into_response();
    };
    if let Err(response) = allow_auth_attempt(&state, source).await {
        return response;
    }
    let device = match request.device.map(device_registration).transpose() {
        Ok(device) => device,
        Err(error) => return control_error_response(error),
    };
    if let Err(error) = control_plane::validate_password(&request.password) {
        return control_error_response(error);
    }
    let salt = match AccountStore::registration_salt() {
        Ok(salt) => salt,
        Err(error) => return control_error_response(error),
    };
    // Derived with no lock held; see `derive_password_bounded`.
    let derived = match derive_password_bounded(&state, &request.password, salt).await {
        Ok(derived) => derived,
        Err(response) => return response,
    };
    let mut accounts = state.accounts.lock().await;
    match accounts.register_derived(
        &request.username,
        salt,
        derived,
        device,
        authorization.requires_empty_store(),
        control_plane::now_ms(),
    ) {
        Ok(tokens) => Json(AccountAuthResponse::from(tokens)).into_response(),
        Err(error) => control_error_response(error),
    }
}

async fn login_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AccountCredentials>,
) -> Response {
    let source = request_source(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = allow_auth_attempt(&state, source).await {
        return response;
    }
    let device = match request.device.map(device_registration).transpose() {
        Ok(device) => device,
        Err(error) => return control_error_response(error),
    };
    if let Err(error) = control_plane::validate_password(&request.password) {
        return control_error_response(error);
    }
    // Three steps: read the challenge under the lock, derive without it, then
    // verify and mutate under it again. The expensive middle step is what
    // must not be serialized behind the store.
    let (salt, scheme) = {
        let accounts = state.accounts.lock().await;
        accounts.password_challenge_scheme(&request.username)
    };
    // Verified with the scheme the stored record was made under, not with
    // whatever this build would choose today. That is what makes the cost
    // changeable at all: without it, raising the iteration count locks out
    // every existing account.
    let derived = match derive_password_bounded_with(&state, &request.password, salt, scheme).await
    {
        Ok(derived) => derived,
        Err(response) => return response,
    };
    let outdated = {
        let mut accounts = state.accounts.lock().await;
        let response = match accounts.login_derived(
            &request.username,
            salt,
            derived,
            device,
            control_plane::now_ms(),
        ) {
            Ok(tokens) => Json(AccountAuthResponse::from(tokens)).into_response(),
            // A changed device key auto-revoked the device: end its live sessions
            // too, not just its tokens, then answer with the same 401 an ordinary
            // rejection gives so the mismatch stays indistinguishable to a caller.
            Err(ControlPlaneError::DeviceIdentityRevoked {
                account_id,
                device_id,
            }) => {
                drop(accounts);
                let senders = revoke_owned_sessions(&state, &account_id, Some(&device_id)).await;
                for sender in senders {
                    let _ = sender.try_send(Message::Close(None));
                }
                return control_error_response(ControlPlaneError::Unauthorized);
            }
            Err(error) => return control_error_response(error),
        };
        if !accounts.password_is_outdated(&request.username) {
            return response;
        }
        response
    };

    // The sign-in has already succeeded. Rehashing is an upgrade performed
    // on the way past, so every failure below is swallowed: turning a
    // successful login into an error because a re-encode did not work would
    // lock the user out of their account for the sake of tidiness.
    let Ok(new_salt) = AccountStore::registration_salt() else {
        return outdated;
    };
    let current = control_plane::PasswordScheme::current();
    let Ok(rehashed) =
        derive_password_bounded_with(&state, &request.password, new_salt, current).await
    else {
        return outdated;
    };
    let mut accounts = state.accounts.lock().await;
    let _ = accounts.rehash_password(&request.username, new_salt, rehashed, current);
    outdated
}

async fn refresh_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RefreshAccount>,
) -> Response {
    let source = request_source(peer.ip(), &headers, &state.trusted_proxies);
    // Its own budget: renewal is cheap and routine, and must not be starved
    // by someone spending the password allowance.
    if let Err(response) = allow_refresh_attempt(&state, source).await {
        return response;
    }
    let mut accounts = state.accounts.lock().await;
    match accounts.refresh(&request.refresh_token, control_plane::now_ms()) {
        Ok(tokens) => Json(AccountAuthResponse::from(tokens)).into_response(),
        Err(error) => control_error_response(error),
    }
}

async fn list_account_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let principal = match account_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mut devices = {
        let accounts = state.accounts.lock().await;
        if let Err(error) = accounts.can_manage_devices(&principal) {
            return control_error_response(error);
        }
        match accounts.list_devices(&principal.account_id) {
            Ok(devices) => devices,
            Err(error) => return control_error_response(error),
        }
    };
    // Layer live presence over the stored records. The account store knows a
    // device exists and whether it is trusted; only the Connect broker knows
    // whether it is online right now, and a device the owner cannot see as
    // online is one the shell will never offer to connect to. The accounts
    // lock is released above before the broker lock is taken, so this adds no
    // new lock-ordering edge. `is_online` is scoped to the caller's account,
    // so one account's listing can never reveal another's presence.
    {
        let now = Instant::now();
        let broker = state.connect.lock().await;
        for device in &mut devices {
            device.online = broker.is_online(&principal.account_id, &device.device_id, now);
        }
    }
    Json(devices).into_response()
}

async fn enroll_account_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Response {
    let principal = match account_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let registration = match device_registration(request) {
        Ok(registration) => registration,
        Err(error) => return control_error_response(error),
    };
    let mut accounts = state.accounts.lock().await;
    if let Err(error) = accounts.can_manage_devices(&principal) {
        return control_error_response(error);
    }
    match accounts.enroll_device(&principal.account_id, registration, control_plane::now_ms()) {
        Ok(device) => Json(device).into_response(),
        Err(error) => control_error_response(error),
    }
}

async fn set_account_device_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(request): Json<DeviceTrustRequest>,
) -> Response {
    if request.trust == DeviceTrust::Pending {
        return control_error_response(ControlPlaneError::InvalidInput(
            "pending is assigned by enrollment",
        ));
    }
    let principal = match account_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mut accounts = state.accounts.lock().await;
    if let Err(error) = accounts.can_manage_devices(&principal) {
        return control_error_response(error);
    }
    let result = accounts.set_device_trust(
        &principal.account_id,
        &device_id,
        request.trust,
        control_plane::now_ms(),
    );
    // Release the account lock before touching sessions: session teardown takes
    // the sessions lock, and no other path holds accounts across it.
    drop(accounts);
    match result {
        Ok(device) => {
            // Revoking a device must end its live sessions, not just its tokens:
            // otherwise a compromised device keeps its signaling and relay path
            // alive until the session TTL. Trusting a device changes nothing live.
            if request.trust == DeviceTrust::Revoked {
                let senders =
                    revoke_owned_sessions(&state, &principal.account_id, Some(&device_id)).await;
                for sender in senders {
                    let _ = sender.try_send(Message::Close(None));
                }
            }
            Json(device).into_response()
        }
        Err(error) => control_error_response(error),
    }
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

/// The ids of sessions owned by `account_id`, optionally narrowed to a single
/// `device_id` (matching either the requester/client device or the target/host
/// device). Provisioning sessions (no ownership) never match, so an admin
/// session is never torn down by an account revocation.
///
/// Pure over the session map so the ownership selection is unit-testable without
/// a running service.
fn sessions_owned_by(
    sessions: &HashMap<String, Session>,
    account_id: &str,
    device_id: Option<&str>,
) -> Vec<String> {
    sessions
        .iter()
        .filter(|(_, session)| {
            session.ownership.as_ref().is_some_and(|owner| {
                owner.account_id == account_id
                    && device_id.is_none_or(|device| {
                        owner.requester_device_id == device || owner.target_device_id == device
                    })
            })
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// Remove every live session owned by `account_id` (optionally just those
/// involving `device_id`), cancelling their sockets, and return the live senders
/// so a close notice can be sent after the map lock is released.
///
/// This is what makes revocation effective on the media path: invalidating a
/// device's tokens stops it minting *new* credentials, but without this an
/// already-established session keeps its signaling and relay path alive until
/// its TTL. Revoking a compromised device must end its sessions now.
async fn revoke_owned_sessions(
    state: &AppState,
    account_id: &str,
    device_id: Option<&str>,
) -> Vec<mpsc::Sender<Message>> {
    let mut sessions = state.sessions.lock().await;
    let owned = sessions_owned_by(&sessions, account_id, device_id);
    let mut senders = Vec::new();
    for id in owned {
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

// ---------------------------------------------------------------------------
// Secure Connect: presence, requests, approval, and split role credentials.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ConnectRequestBody {
    target_device_id: String,
    /// The permission classes the requester is asking for. Defaulted so a
    /// client that predates permission negotiation asks for nothing rather
    /// than failing to parse.
    #[serde(default)]
    requested: connect::Permissions,
}

/// The optional body of an approval: the permission classes the target grants.
/// Absent or partial defaults to the empty set, so an old client that approves
/// with no body grants nothing rather than everything.
#[derive(Debug, Default, Deserialize)]
struct ConnectApproveBody {
    #[serde(default)]
    granted: connect::Permissions,
}

#[derive(Debug, Serialize)]
struct ConnectRequestCreated {
    request_id: String,
    state: connect::ConnectState,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
struct PendingConnectRequest {
    request_id: String,
    requester_device_id: String,
    expires_in_seconds: u64,
    /// What the requester asked for, so the target approves against the actual
    /// request rather than granting blind.
    requested: connect::Permissions,
}

#[derive(Debug, Serialize)]
struct ConnectObserved {
    state: connect::ConnectState,
}

/// One end of an approved session: a session id and exactly one role token.
///
/// There is deliberately no shape in this API that carries both. The absence
/// is the security property -- a struct with two token fields is one careless
/// handler away from being returned to the wrong party.
#[derive(Debug, Serialize)]
struct ConnectCredential {
    session_id: String,
    role: &'static str,
    token: String,
    websocket_path: String,
    relay_address: Option<String>,
    relay_ticket: String,
    /// The classes the target granted, delivered to each end so both agree on
    /// the session's scope. The runner enforces it; the broker only negotiates.
    permissions: connect::Permissions,
}

fn connect_error_response(error: connect::ConnectError) -> Response {
    use connect::ConnectError;
    let status = match error {
        // Collapsed on purpose. Distinguishing "no such request" from "not
        // yours" turns request ids into an existence oracle: a caller could
        // enumerate ids and learn which ones belong to somebody else.
        ConnectError::NotFound | ConnectError::Forbidden => StatusCode::NOT_FOUND,
        ConnectError::InvalidState => StatusCode::CONFLICT,
        // Retryable: the credentials exist but their session does not yet.
        // 503 rather than 409 so a client knows to try again rather than to
        // give up on the request.
        ConnectError::NotPublished => StatusCode::SERVICE_UNAVAILABLE,
        // Never rendered: the approve handler turns this into a collection.
        // Mapped anyway so a future caller cannot reach a panic through it.
        ConnectError::AlreadyApproved => StatusCode::CONFLICT,
        ConnectError::TargetOffline | ConnectError::TargetNotConnectable => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        ConnectError::Busy => StatusCode::TOO_MANY_REQUESTS,
    };
    (status, "connect request failed\n").into_response()
}

/// The device behind an authenticated request.
///
/// Every Connect operation is device-scoped: presence belongs to a device,
/// a request is made by one and answered by another, and a credential is
/// delivered to exactly one. An account token with no device cannot take part,
/// which is why this is a separate step from [`account_principal`].
// `Response` is large, and deliberately so: it is axum's own type and the
// error path here returns a real HTTP response rather than a code to be
// rendered later. Boxing it would add an allocation to every refusal to buy
// back stack that is never hot.
#[allow(clippy::result_large_err, reason = "the error is an HTTP response")]
async fn connect_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), Response> {
    let principal = account_principal(state, headers).await?;
    let Some(device_id) = principal.device_id.clone() else {
        return Err((
            StatusCode::FORBIDDEN,
            "this operation requires an enrolled device\n",
        )
            .into_response());
    };
    Ok((principal.account_id, device_id))
}

fn seconds_until(deadline: Instant, now: Instant) -> u64 {
    deadline.saturating_duration_since(now).as_secs()
}

/// Announce that this device is online and able to host.
async fn connect_presence(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    // Presence is a claim about a device being ready to host, so it is only
    // accepted from a device the account has actually trusted. A pending or
    // revoked device announcing itself would appear in its owner's list as a
    // connectable machine.
    {
        let accounts = state.accounts.lock().await;
        if let Err(error) = accounts.can_create_session(&control_plane::AccountPrincipal {
            account_id: account_id.clone(),
            device_id: Some(device_id.clone()),
        }) {
            return control_error_response(error);
        }
    }
    state
        .connect
        .lock()
        .await
        .heartbeat(&account_id, &device_id, Instant::now());
    StatusCode::NO_CONTENT.into_response()
}

/// Stop advertising this device as available.
async fn connect_offline(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (_, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    state.connect.lock().await.go_offline(&device_id);
    StatusCode::NO_CONTENT.into_response()
}

/// Ask a device of this account for a session.
async fn connect_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConnectRequestBody>,
) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    // The target has to be a device this account owns and trusts. Checked
    // against the store rather than inferred from the broker, because
    // presence is soft state and trust is not.
    {
        let accounts = state.accounts.lock().await;
        let devices = match accounts.list_devices(&account_id) {
            Ok(devices) => devices,
            Err(error) => return control_error_response(error),
        };
        let connectable = devices.iter().any(|device| {
            device.device_id == body.target_device_id
                && device.trust == control_plane::DeviceTrust::Trusted
        });
        if !connectable {
            return connect_error_response(connect::ConnectError::TargetNotConnectable);
        }
    }
    let now = Instant::now();
    let request_id = Uuid::new_v4().simple().to_string();
    let mut broker = state.connect.lock().await;
    match broker.request_scoped(
        request_id,
        &account_id,
        &device_id,
        &body.target_device_id,
        body.requested,
        now,
    ) {
        Ok(request) => Json(ConnectRequestCreated {
            request_id: request.request_id,
            state: request.state,
            expires_in_seconds: seconds_until(request.expires_at, now),
        })
        .into_response(),
        Err(error) => connect_error_response(error),
    }
}

/// What this device is being asked to approve.
async fn connect_pending(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let now = Instant::now();
    let pending = state
        .connect
        .lock()
        .await
        .pending_for_target(&account_id, &device_id, now);
    let body: Vec<PendingConnectRequest> = pending
        .into_iter()
        .map(|request| PendingConnectRequest {
            request_id: request.request_id,
            requester_device_id: request.requester_device_id,
            expires_in_seconds: seconds_until(request.expires_at, now),
            requested: request.requested,
        })
        .collect();
    Json(body).into_response()
}

/// Approve a request, and receive the host capability -- only the host one.
async fn connect_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    // The classes the target is granting. An empty or absent body -- a client
    // that predates permission negotiation -- parses to the empty set rather
    // than a blanket grant, and a malformed one is treated the same way rather
    // than failing an approval the person already made.
    let granted = serde_json::from_slice::<ConnectApproveBody>(&body)
        .map(|body| body.granted)
        .unwrap_or_default();
    let now = Instant::now();
    let party = connect::Party {
        account_id: &account_id,
        device_id: &device_id,
    };

    // Approve first. If this is refused -- the request expired, or this is
    // not the device being asked -- no session is created, so a rejected
    // approval cannot leave an orphan session behind holding capacity.
    //
    // An approval this device already made is *not* a refusal. Its response
    // was lost, and the only thing it can usefully be sent now is the
    // credential it never received, so that case falls through to collection
    // below. Anything else, including the rate limit, applies only to an
    // approval that is actually creating a session: a retry must not consume
    // a creation slot for a session that already exists.
    let fresh = {
        let mut broker = state.connect.lock().await;
        match broker.approve_scoped(
            &request_id,
            party,
            connect::SessionGrant {
                session_id: Uuid::new_v4().simple().to_string(),
                host_credential: Uuid::new_v4().simple().to_string(),
                client_credential: Uuid::new_v4().simple().to_string(),
            },
            granted,
            now,
        ) {
            Ok(request) => Some(request),
            Err(connect::ConnectError::AlreadyApproved) => None,
            Err(error) => return connect_error_response(error),
        }
    };

    if let Some(approved) = fresh {
        if !state.session_creates.lock().await.allow(Instant::now()) {
            state.connect.lock().await.withdraw(&request_id);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "session creation rate limit exceeded\n",
            )
                .into_response();
        }
        let Some(session_id) = approved.session_id.clone() else {
            state.connect.lock().await.withdraw(&request_id);
            return connect_error_response(connect::ConnectError::InvalidState);
        };
        let (host_token, client_token) = match state
            .connect
            .lock()
            .await
            .minted_credentials(&request_id, party)
        {
            Ok(pair) => pair,
            Err(error) => return connect_error_response(error),
        };
        let session = build_session(
            DEFAULT_TTL_SECONDS,
            host_token,
            client_token,
            Some(SessionOwnership {
                account_id: account_id.clone(),
                requester_device_id: approved.requester_device_id.clone(),
                target_device_id: device_id.clone(),
                request_id: request_id.clone(),
            }),
        );
        if let Err(response) = insert_session(&state, session_id, session).await {
            // The session could not be published, so the approval must not
            // stand: leaving it would hand out credentials for a session that
            // does not exist, which the client cannot distinguish from a
            // network fault.
            state.connect.lock().await.withdraw(&request_id);
            return response;
        }
        // Only now may either end collect. Between the mint above and this
        // line the credentials name a session that does not exist.
        state.connect.lock().await.mark_published(&request_id);
    }

    let mut broker = state.connect.lock().await;
    match broker.collect_host_credential(&request_id, party, now) {
        Ok((session_id, token)) => Json(ConnectCredential {
            websocket_path: format!("/v1/signal/{session_id}/host"),
            relay_ticket: relay_ticket::mint(&state.relay_secret, &session_id, "host", "host", 1),
            relay_address: state.relay_address.map(|address| address.to_string()),
            permissions: broker.granted_permissions(&request_id),
            session_id,
            role: "host",
            token,
        })
        .into_response(),
        Err(error) => connect_error_response(error),
    }
}

/// Refuse a request.
async fn connect_deny(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .connect
        .lock()
        .await
        .deny(&request_id, &account_id, &device_id, Instant::now())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => connect_error_response(error),
    }
}

/// Poll a request, and collect the client capability once it is approved.
async fn connect_observe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    let (account_id, device_id) = match connect_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let now = Instant::now();
    let mut broker = state.connect.lock().await;
    let observed = match broker.observe(&request_id, &account_id, &device_id, now) {
        Ok(state) => state,
        Err(error) => return connect_error_response(error),
    };
    if observed != connect::ConnectState::Approved {
        return Json(ConnectObserved { state: observed }).into_response();
    }
    match broker.collect_client_credential(
        &request_id,
        connect::Party {
            account_id: &account_id,
            device_id: &device_id,
        },
        now,
    ) {
        Ok((session_id, token)) => Json(ConnectCredential {
            websocket_path: format!("/v1/signal/{session_id}/client"),
            relay_ticket: relay_ticket::mint(
                &state.relay_secret,
                &session_id,
                "client",
                "client",
                1,
            ),
            relay_address: state.relay_address.map(|address| address.to_string()),
            permissions: broker.granted_permissions(&request_id),
            session_id,
            role: "client",
            token,
        })
        .into_response(),
        Err(error) => connect_error_response(error),
    }
}

/// Build an empty session with the given lifetime, role tokens and owner.
///
/// Shared by the provisioning endpoint and the Connect broker so the two
/// cannot drift: a session created through an approval must be the same kind
/// of object as one created by an operator, or every downstream check has two
/// cases to get right.
fn build_session(
    ttl: u64,
    host_token: String,
    client_token: String,
    ownership: Option<SessionOwnership>,
) -> Session {
    Session {
        expires_at: Instant::now() + Duration::from_secs(ttl),
        ownership,
        host_token,
        client_token,
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
    }
}

/// Publish a session, refusing if the service is at capacity.
///
/// The expiry sweep runs here rather than only on the reaper's timer, so
/// capacity is measured against sessions that are actually live.
#[allow(clippy::result_large_err, reason = "the error is an HTTP response")]
async fn insert_session(state: &AppState, id: String, session: Session) -> Result<(), Response> {
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, existing| existing.expires_at > now);
    if sessions.len() >= MAX_LIVE_SESSIONS {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "session capacity reached\n",
        )
            .into_response());
    }
    sessions.insert(id, session);
    Ok(())
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSession>,
) -> Response {
    // Provisioning only.
    //
    // This endpoint returns *both* role capabilities to one caller, which is
    // a developer and operator workflow: whoever calls it can act as either
    // end, or hand either end to anybody. That is the wrong shape for a
    // product, where the person asking for a session must never receive the
    // capability that controls the machine they are asking to use. Account
    // holders go through `/v1/connect`, which delivers one role to each
    // party and nothing to anyone else.
    if !admin_allowed(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            "session provisioning requires admin authorization; \
             account holders use POST /v1/connect\n",
        )
            .into_response();
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
        // No account owns a provisioning session: this endpoint exists for
        // an operator or a developer with the admin token, and there is no
        // principal behind it to attribute the session to.
        ownership: None,
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
    if let Err(response) = insert_session(&state, id.clone(), session).await {
        return response;
    }

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
/// `OPENSTREAM_ALLOW_NO_AUTH=1` or private-LAN development with
/// `OPENSTREAM_LOCAL_NO_AUTH=1`. Startup validation constrains those modes to
/// their respective bind scopes. This helper is used only by management
/// endpoints; role/session bearer checks remain independent.
fn admin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    match state.admin_token.as_deref() {
        Some(expected) => authorized(headers, Some(expected)),
        None => state.allow_no_auth || state.local_no_auth,
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

/// Fixed-window inbound message budget for one socket.
///
/// The idle timeout bounds a silent peer; this bounds a loud one. Every
/// inbound frame costs a lock acquisition and a JSON parse, so an
/// authenticated peer must not be able to spend the server's time freely.
#[derive(Debug)]
struct InboundRateWindow {
    started: Instant,
    count: u32,
}

impl InboundRateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            count: 0,
        }
    }

    /// Record one frame and report whether the socket stays within budget.
    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= MAX_INBOUND_MESSAGES_PER_SECOND
    }
}

/// Typed refusal sent before closing a socket that exceeded the inbound rate.
/// It carries no detail a caller could use to probe the limit precisely.
fn rate_limited_message() -> Message {
    Message::Text(
        serde_json::json!({
            "type": "error",
            "error": "rate_limited",
        })
        .to_string()
        .into(),
    )
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

fn ice_ready_message(generation: u64) -> Message {
    Message::Text(
        serde_json::json!({
            "type": "ice_peer_ready",
            "establishment_generation": generation,
        })
        .to_string()
        .into(),
    )
}

fn ice_reset_message(generation: u64, reason: &'static str) -> Message {
    Message::Text(
        serde_json::json!({
            "type": "ice_peer_reset",
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

fn ice_message_generation(message: &Message) -> Option<u64> {
    let Message::Text(text) = message else {
        return None;
    };
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let message_type = value.get("type").and_then(serde_json::Value::as_str)?;
    matches!(
        message_type,
        "ice_credentials_v2" | "ice_candidate_v2" | "ice_candidate_done_v2" | "ice_key_v2"
    )
    .then(|| {
        value
            .get("establishment_generation")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    })
}

fn prune_direct_queue(queue: &mut VecDeque<Message>, queued_bytes: &mut usize) {
    queue.retain(|message| !is_establishment_message(message));
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
    if host.try_send(direct_ready_message(generation)).is_ok()
        && host.try_send(ice_ready_message(generation)).is_ok()
    {
        accepted_host = true;
    }
    if client.try_send(direct_ready_message(generation)).is_ok()
        && client.try_send(ice_ready_message(generation)).is_ok()
    {
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
        let ice_reset = ice_reset_message(generation, RESET_REASON_DELIVERY_FAILED);
        if host.try_send(reset).is_err() || host.try_send(ice_reset).is_err() {
            close_sender(&host);
        }
        close_sender(&host);
    }
    if accepted_client {
        let reset = direct_reset_message(generation, RESET_REASON_DELIVERY_FAILED);
        let ice_reset = ice_reset_message(generation, RESET_REASON_DELIVERY_FAILED);
        if client.try_send(reset).is_err() || client.try_send(ice_reset).is_err() {
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
        || sender
            .try_send(ice_reset_message(previous.establishment_generation, reason))
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
    let mut inbound_rate = InboundRateWindow::new(Instant::now());

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
                if !inbound_rate.allow(Instant::now()) {
                    let _ = out_tx.try_send(rate_limited_message());
                    break;
                }
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
                if let Some(establishment_generation) = direct_message_generation(&message)
                    .or_else(|| ice_message_generation(&message))
                {
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
                                    // cannot participate in primary establishment.
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
                                "{\"type\":\"error\",\"reason\":\"establishment_not_ready\"}"
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
                                "{\"type\":\"error\",\"reason\":\"establishment_generation_future\"}"
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
        "peer_ready" | "peer_reset" | "ice_peer_ready" | "ice_peer_reset"
        | "relay_ticket_proof" => {
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
        "key" | "ice_credentials" | "ice_candidate" | "ice_candidate_done" => {
            return Err("legacy_ice_establishment_unsupported");
        }
        "ice_credentials_v2" => {
            if object.len() != 4
                || !valid_establishment_generation(object, "establishment_generation")
                || !bounded_string_field(object, "ufrag", 1, 32)
                || !bounded_string_field(object, "pwd", 1, 256)
            {
                return Err("ice_credentials_v2_invalid");
            }
        }
        "ice_candidate_v2" => {
            if object.len() != 3
                || !valid_establishment_generation(object, "establishment_generation")
                || !bounded_string_field(object, "candidate", 1, 4096)
            {
                return Err("ice_candidate_v2_invalid");
            }
        }
        "ice_candidate_done_v2" => {
            if object.len() != 3
                || !valid_establishment_generation(object, "establishment_generation")
                || object
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .is_none()
                || object
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|count| count > MAX_DIRECT_CANDIDATES)
            {
                return Err("ice_candidate_done_v2_invalid");
            }
        }
        "ice_key_v2" => {
            if object.len() != 5
                || !valid_establishment_generation(object, "establishment_generation")
                || !valid_hex_field(object, "public_key", 32)
                || !valid_hex_field(object, "identity_public_key", 32)
                || !valid_hex_field(object, "signature", 64)
            {
                return Err("ice_key_v2_invalid");
            }
        }
        _ => return Err("unsupported_message_type"),
    }
    Ok(())
}

fn valid_establishment_generation(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> bool {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|generation| generation > 0)
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
    if is_establishment_message(&message) {
        return;
    }
    let size = message_len(&message);
    if queue.len() >= MAX_PENDING_MESSAGES || *queued_bytes + size > MAX_PENDING_BYTES {
        return;
    }
    *queued_bytes += size;
    queue.push_back(message);
}

/// Whether a queued record belongs to an establishment epoch.
///
/// Both families are named here on purpose. These records are scoped to one
/// server-authoritative generation, so they must be dropped when the epoch
/// is invalidated; every other signaling message is generation-independent
/// and has to survive, which is why this is an explicit allow-list rather
/// than a prefix test.
fn is_establishment_message(message: &Message) -> bool {
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
                        "direct_candidate"
                            | "direct_candidate_done"
                            | "direct_key"
                            | "ice_credentials_v2"
                            | "ice_candidate_v2"
                            | "ice_candidate_done_v2"
                            | "ice_key_v2"
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
    use super::control_plane::AccountStore;
    use super::{
        AUTH_ATTEMPT_WINDOW, AdmissionError, AppState, AuthMode, CreationLimiter, DirectRoute,
        GenericDispatch, Guest, MAX_AUTH_ATTEMPTS_PER_MINUTE, MAX_AUTH_ATTEMPTS_PER_SOURCE,
        MAX_CONCURRENT_PASSWORD_DERIVATIONS, MAX_GUESTS_CEILING, MAX_REFRESH_ATTEMPTS_PER_MINUTE,
        MAX_SESSION_CREATES_PER_MINUTE, MAX_TRACKED_AUTH_SOURCES, PrimaryRole,
        RELAY_BYTES_PER_SECOND, RELAY_PACKETS_PER_SECOND, RateWindow, ReadinessError,
        RegistrationAuthorization, RelaySlot, Role, SESSION_CREATE_WINDOW, Session,
        SessionOwnership, SourceLimiter, admin_allowed,
        admit_primary_socket as admit_primary_socket_with_cancel, authorize_registration,
        authorized, bearer_token, cleanup_primary_socket, close_primary_pair, connect_approve,
        connect_deny, connect_observe, connect_offline, connect_pending, connect_presence,
        connect_request, consume_dual_budget, create_session, direct_message_route,
        dispatch_generic_message, enroll_account_device, healthz, is_private_lan_address,
        list_account_devices, login_account, max_guests_for_new_session,
        prune_direct_establishment_messages, publish_ready, queue_pending, reap_expired_sessions,
        register_account, registration_capability, relay_owner_for_ticket, relay_ticket,
        request_source, revoke_owned_sessions, sessions_owned_by, set_account_device_trust,
        signal_socket, supplied_token_is_host, validate_signal_message, validate_startup_auth,
        version_info,
    };
    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::ConnectInfo;
    use axum::extract::ws::Message;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::{get, post};
    use futures_util::task::{Context, Poll};
    use futures_util::{Sink, SinkExt, StreamExt};
    use openstream_protocol::relay;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::{HashMap, VecDeque};
    use std::convert::Infallible;
    use std::net::IpAddr;
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
            ownership: None,
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

    /// An account store in a directory of this test's own.
    ///
    /// The store takes ownership of its parent -- it chmods it to 0700 -- so
    /// the parent must never be the shared temp directory itself.
    fn test_accounts() -> Arc<Mutex<AccountStore>> {
        let path = std::env::temp_dir()
            .join(format!(
                "openstream-signal-account-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ))
            .join("control-state.json");
        Arc::new(Mutex::new(
            AccountStore::open(path).expect("test account store"),
        ))
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

    /// Consume one socket's readiness announcement.
    ///
    /// One epoch is announced as two records, `peer_ready` and
    /// `ice_peer_ready`, carrying the same generation. Both establishment
    /// vocabularies are separate on the wire -- a direct key and an ICE key
    /// are signed over different transcript domains, so a record from one
    /// must never be readable as the other -- but they describe the same
    /// server-authoritative pair. Taking both here keeps every following
    /// "and nothing else was queued" assertion meaningful.
    fn assert_peer_ready(receiver: &mut mpsc::Receiver<Message>, generation: u64) {
        for expected in ["peer_ready", "ice_peer_ready"] {
            let message = receiver
                .try_recv()
                .unwrap_or_else(|error| panic!("{expected} readiness record: {error}"));
            let text = message_text(message);
            let value = serde_json::from_str::<serde_json::Value>(&text).expect("readiness JSON");
            assert_eq!(
                value.get("type").and_then(serde_json::Value::as_str),
                Some(expected)
            );
            assert_eq!(
                value
                    .get("establishment_generation")
                    .and_then(serde_json::Value::as_u64),
                Some(generation)
            );
        }
    }

    /// Consume one socket's epoch-invalidation announcement.
    ///
    /// The mirror of [`assert_peer_ready`]: an invalidated epoch is also
    /// announced once per establishment vocabulary, so both records have to
    /// be taken before a test can claim the queue is empty.
    fn assert_peer_reset(receiver: &mut mpsc::Receiver<Message>, generation: u64) {
        for expected in ["peer_reset", "ice_peer_reset"] {
            let message = receiver
                .try_recv()
                .unwrap_or_else(|error| panic!("{expected} record: {error}"));
            let text = message_text(message);
            let value = serde_json::from_str::<serde_json::Value>(&text).expect("reset JSON");
            assert_eq!(
                value.get("type").and_then(serde_json::Value::as_str),
                Some(expected)
            );
            assert_eq!(
                value
                    .get("establishment_generation")
                    .and_then(serde_json::Value::as_u64),
                Some(generation)
            );
        }
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

    fn signed_direct_key_message(session_id: &str, generation: u64) -> Message {
        let ephemeral = [0x42_u8; 32];
        let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("generate test direct identity");
        let key_pair =
            Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("parse test direct identity");
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"OpenStream direct key v2");
        transcript.extend_from_slice(
            &u32::try_from(session_id.len())
                .expect("test session id fits transcript")
                .to_be_bytes(),
        );
        transcript.extend_from_slice(session_id.as_bytes());
        transcript.extend_from_slice(&generation.to_be_bytes());
        transcript.push(1); // authenticated host role
        transcript.extend_from_slice(&ephemeral);
        let signature = key_pair.sign(&transcript);
        Message::Text(
            serde_json::json!({
                "type": "direct_key",
                "establishment_generation": generation,
                "public_key": test_hex(ephemeral),
                "identity_public_key": test_hex(key_pair.public_key()),
                "signature": test_hex(signature.as_ref()),
            })
            .to_string()
            .into(),
        )
    }

    fn test_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn no_admin_token_refuses_everything_without_explicit_dev_opt_in() {
        // Fail closed: no token means no access, even with empty headers.
        assert!(!authorized(&HeaderMap::new(), None));
    }

    #[test]
    fn private_lan_no_auth_accepts_explicit_private_and_link_local_binds() {
        assert!(is_private_lan_address(
            "192.168.1.69".parse().expect("private IPv4")
        ));
        assert!(is_private_lan_address(
            "fd00::69".parse().expect("ULA IPv6")
        ));
        assert!(is_private_lan_address(
            "fe80::69".parse().expect("link-local IPv6")
        ));
        assert_eq!(
            validate_startup_auth(
                "192.168.1.69:8080".parse().expect("private bind"),
                true,
                false,
                false,
                true,
            ),
            Ok(AuthMode::PrivateLanNoAuth)
        );
        assert_eq!(
            validate_startup_auth(
                "[fd00::69]:8080".parse().expect("ULA bind"),
                true,
                false,
                false,
                true,
            ),
            Ok(AuthMode::PrivateLanNoAuth)
        );
    }

    #[test]
    fn private_lan_no_auth_rejects_wildcard_public_loopback_and_implicit_binds() {
        for address in [
            "0.0.0.0:8080",
            "127.0.0.1:8080",
            "8.8.8.8:8080",
            "[::]:8080",
            "[::1]:8080",
            "[2001:db8::69]:8080",
        ] {
            assert!(
                validate_startup_auth(
                    address.parse().expect("test address"),
                    true,
                    false,
                    false,
                    true,
                )
                .is_err(),
                "unexpectedly accepted {address}"
            );
        }
        assert!(
            validate_startup_auth(
                "192.168.1.69:8080".parse().expect("private bind"),
                false,
                false,
                false,
                true,
            )
            .is_err()
        );
        assert!(!is_private_lan_address(
            "100.64.0.1".parse().expect("shared address")
        ));
    }

    #[test]
    fn startup_auth_requires_an_opt_in_for_unauthenticated_non_loopback_binds() {
        assert!(
            validate_startup_auth(
                "192.168.1.69:8080".parse().expect("private bind"),
                true,
                false,
                false,
                false,
            )
            .is_err()
        );
        assert_eq!(
            validate_startup_auth(
                "127.0.0.1:8080".parse().expect("loopback bind"),
                false,
                false,
                true,
                false,
            ),
            Ok(AuthMode::LoopbackNoAuth)
        );
        assert_eq!(
            validate_startup_auth(
                "0.0.0.0:8080".parse().expect("wildcard bind"),
                true,
                false,
                true,
                false,
            ),
            Err("OPENSTREAM_ALLOW_NO_AUTH requires a loopback bind")
        );
    }

    #[test]
    fn local_no_auth_requires_no_admin_token_and_is_not_a_role_capability() {
        assert!(
            validate_startup_auth(
                "192.168.1.69:8080".parse().expect("private bind"),
                true,
                true,
                false,
                true,
            )
            .is_err()
        );

        let mut state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: true,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        let session = test_session();
        let empty = HeaderMap::new();
        assert!(admin_allowed(&state, &empty));
        assert!(!supplied_token_is_host(&empty, &session));

        state.admin_token = Some("admin-secret-012345".into());
        assert!(!admin_allowed(&state, &empty));
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

    #[test]
    fn inbound_rate_window_bounds_a_loud_socket_and_refills() {
        let start = Instant::now();
        let mut window = super::InboundRateWindow::new(start);

        // Everything inside the budget is allowed.
        for _ in 0..super::MAX_INBOUND_MESSAGES_PER_SECOND {
            assert!(window.allow(start));
        }
        // The next frame in the same second is refused.
        assert!(!window.allow(start));

        // A later second starts a fresh budget, so a well-behaved peer that
        // is merely bursty is never permanently penalised.
        let later = start + Duration::from_secs(1);
        assert!(window.allow(later));
    }

    #[tokio::test]
    async fn direct_not_ready_error_reaches_client_before_socket_closes() {
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
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
            ClientMessage::Text(text) if text.contains("establishment_not_ready")
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
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        state.sessions.lock().await.insert(
            "session-1".into(),
            Session {
                ownership: None,
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
            .send(ClientMessage::Text(r#"{"type":"path_candidate","generation":2,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"direct_udp","ip":"127.0.0.1","port":4001}"#.into()))
            .await
            .expect("stale socket can submit a frame");
        assert!(
            timeout(Duration::from_millis(100), host_receiver.recv())
                .await
                .is_err()
        );

        current_socket
            .send(ClientMessage::Text(r#"{"type":"path_candidate","generation":2,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"direct_udp","ip":"127.0.0.1","port":4001}"#.into()))
            .await
            .expect("current socket can submit a frame");
        assert!(matches!(
            timeout(Duration::from_millis(100), host_receiver.recv())
                .await
                .expect("current socket forwards")
                .expect("host receiver remains connected"),
            Message::Text(text) if text.contains("path_candidate")
        ));

        state
            .sessions
            .lock()
            .await
            .get_mut("session-1")
            .expect("test session")
            .host = None;
        stale_socket
            .send(ClientMessage::Text(r#"{"type":"path_candidate","generation":3,"token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"direct_udp","ip":"127.0.0.1","port":4002}"#.into()))
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

    /// Password verification is the most expensive thing an unauthenticated
    /// caller can ask this service to do, so the budget has to be real and
    /// has to recover on its own.
    #[test]
    fn auth_attempts_are_bounded_and_the_window_recovers() {
        let start = Instant::now();
        let mut window = RateWindow::default();
        for _ in 0..MAX_AUTH_ATTEMPTS_PER_MINUTE {
            assert!(window.allow(start, MAX_AUTH_ATTEMPTS_PER_MINUTE, AUTH_ATTEMPT_WINDOW));
        }
        assert!(
            !window.allow(start, MAX_AUTH_ATTEMPTS_PER_MINUTE, AUTH_ATTEMPT_WINDOW),
            "the budget must actually refuse once it is exhausted"
        );
        // Retained events are bounded by the limit, so a sustained flood
        // cannot grow this structure.
        assert_eq!(window.events.len(), MAX_AUTH_ATTEMPTS_PER_MINUTE);
        assert!(window.allow(
            start + AUTH_ATTEMPT_WINDOW,
            MAX_AUTH_ATTEMPTS_PER_MINUTE,
            AUTH_ATTEMPT_WINDOW
        ));
        assert_eq!(window.events.len(), 1);
    }

    /// Renewal must not be starvable by password-attempt spam.
    ///
    /// These are different budgets because they protect different things: one
    /// bounds expensive key derivation from strangers, the other keeps
    /// already-signed-in clients able to renew. Sharing them turns a nuisance
    /// into an outage.
    #[test]
    fn refresh_has_its_own_budget_and_outlives_an_exhausted_auth_budget() {
        // The ordering of the two budgets is asserted at compile time beside
        // the constants themselves; what this checks is that they are
        // genuinely independent windows.
        let start = Instant::now();
        let mut auth = RateWindow::default();
        let mut refresh = RateWindow::default();
        for _ in 0..MAX_AUTH_ATTEMPTS_PER_MINUTE {
            assert!(auth.allow(start, MAX_AUTH_ATTEMPTS_PER_MINUTE, AUTH_ATTEMPT_WINDOW));
        }
        assert!(!auth.allow(start, MAX_AUTH_ATTEMPTS_PER_MINUTE, AUTH_ATTEMPT_WINDOW));
        assert!(
            refresh.allow(start, MAX_REFRESH_ATTEMPTS_PER_MINUTE, AUTH_ATTEMPT_WINDOW),
            "an exhausted password budget must not block credential renewal"
        );
    }

    /// A source that blows past its own cap must not spend the shared budget on
    /// its refused requests, or it could throttle everyone else. This exercises
    /// the two windows together, the way the auth handler consumes them.
    #[test]
    fn per_source_rejections_do_not_consume_the_shared_authentication_budget() {
        let start = Instant::now();
        let mut attempts = RateWindow::default();
        let mut sources = SourceLimiter::default();
        let noisy: IpAddr = "203.0.113.10".parse().expect("address");
        let quiet: IpAddr = "203.0.113.11".parse().expect("address");

        // The noisy source floods far past its per-source cap.
        let mut noisy_allowed = 0;
        for _ in 0..MAX_AUTH_ATTEMPTS_PER_MINUTE + 10 {
            if consume_dual_budget(
                &mut attempts,
                &mut sources,
                noisy,
                start,
                MAX_AUTH_ATTEMPTS_PER_MINUTE,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW,
            ) {
                noisy_allowed += 1;
            }
        }
        assert_eq!(
            noisy_allowed, MAX_AUTH_ATTEMPTS_PER_SOURCE,
            "a source is capped at its own share"
        );
        // The shared window recorded only the allowed requests -- the refused
        // ones spent nothing -- so a well-behaved source still has room.
        assert_eq!(
            attempts.events.len(),
            MAX_AUTH_ATTEMPTS_PER_SOURCE,
            "refused per-source requests must not appear in the shared budget"
        );
        for _ in 0..MAX_AUTH_ATTEMPTS_PER_SOURCE {
            assert!(
                consume_dual_budget(
                    &mut attempts,
                    &mut sources,
                    quiet,
                    start,
                    MAX_AUTH_ATTEMPTS_PER_MINUTE,
                    MAX_AUTH_ATTEMPTS_PER_SOURCE,
                    AUTH_ATTEMPT_WINDOW,
                ),
                "a well-behaved source must not be throttled by the noisy one's refusals"
            );
        }
    }

    /// One noisy source must not spend everyone else's allowance.
    #[test]
    fn a_single_source_cannot_exhaust_the_shared_authentication_budget() {
        let start = Instant::now();
        let mut sources = SourceLimiter::default();
        let noisy: IpAddr = "203.0.113.10".parse().expect("address");
        let quiet: IpAddr = "203.0.113.11".parse().expect("address");

        for _ in 0..MAX_AUTH_ATTEMPTS_PER_SOURCE {
            assert!(sources.allow(
                noisy,
                start,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW
            ));
        }
        assert!(
            !sources.allow(
                noisy,
                start,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW
            ),
            "a source must be cut off at its own share"
        );
        assert!(
            sources.allow(
                quiet,
                start,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW
            ),
            "another source must be unaffected by the first one's spending"
        );
    }

    /// The tracking table is bounded, and eviction favours active sources.
    #[test]
    fn source_tracking_is_bounded_and_evicts_the_stalest_entry() {
        let start = Instant::now();
        let mut sources = SourceLimiter::default();
        let active: IpAddr = "198.51.100.1".parse().expect("address");
        assert!(sources.allow(
            active,
            start,
            MAX_AUTH_ATTEMPTS_PER_SOURCE,
            AUTH_ATTEMPT_WINDOW
        ));

        // Fill the table with distinct sources, keeping the first one in use
        // so it is never the stalest.
        for index in 0..MAX_TRACKED_AUTH_SOURCES + 64 {
            // Masked to a byte each way, so the conversion cannot truncate
            // anything the address needs.
            let octet = |shift: usize| {
                u8::try_from((index >> shift) & 0xff).expect("a masked byte fits in u8")
            };
            let filler = IpAddr::from([10, octet(16), octet(8), octet(0)]);
            let now = start + Duration::from_millis(index as u64 + 1);
            sources.allow(
                filler,
                now,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW,
            );
            sources.allow(
                active,
                now,
                MAX_AUTH_ATTEMPTS_PER_SOURCE,
                AUTH_ATTEMPT_WINDOW,
            );
        }
        assert!(
            sources.sources.len() <= MAX_TRACKED_AUTH_SOURCES,
            "unauthenticated requests must not grow this table without bound"
        );
        assert!(
            sources.sources.contains_key(&active),
            "churning through addresses must not evict a source that is still active"
        );
    }

    /// A forwarding header is believed only from a configured proxy.
    ///
    /// Believing it from anyone would hand every attacker an unlimited supply
    /// of identities, which is worse than having no per-source limit at all.
    #[test]
    fn forwarded_headers_are_believed_only_from_a_trusted_proxy() {
        let proxy: IpAddr = "192.0.2.7".parse().expect("address");
        let stranger: IpAddr = "192.0.2.8".parse().expect("address");
        let claimed: IpAddr = "198.51.100.42".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "10.0.0.1, 198.51.100.42".parse().expect("header"),
        );

        assert_eq!(
            request_source(stranger, &headers, &[proxy]),
            stranger,
            "an untrusted peer's forwarding header must be ignored"
        );
        assert_eq!(
            request_source(proxy, &headers, &[proxy]),
            claimed,
            "a trusted proxy's last hop is the source"
        );
        assert_eq!(
            request_source(proxy, &HeaderMap::new(), &[proxy]),
            proxy,
            "a trusted proxy with no header is itself the source"
        );
        assert_eq!(
            request_source(proxy, &headers, &[]),
            proxy,
            "with no configured proxies no header is ever believed"
        );
    }

    /// A chain of trusted proxies is walked past, not stopped at.
    ///
    /// `client -> Cloudflare -> nginx -> OpenStream`. Taking only the last
    /// entry attributes every request in the world to nginx, which puts the
    /// entire internet in one rate-limit bucket -- the limiter present but
    /// useless.
    #[test]
    fn a_chain_of_trusted_proxies_is_walked_through_to_the_client() {
        let edge: IpAddr = "192.0.2.7".parse().expect("address");
        let inner: IpAddr = "192.0.2.8".parse().expect("address");
        let client: IpAddr = "198.51.100.42".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, 192.0.2.7".parse().expect("header"),
        );
        assert_eq!(
            request_source(inner, &headers, &[edge, inner]),
            client,
            "the first non-proxy hop from the right is the client"
        );
    }

    /// Repeated header fields are one list, in order.
    ///
    /// A proxy may append its own field rather than extending the first one.
    /// Reading a single field silently drops every hop the others recorded,
    /// which is how the rightmost -- the only trustworthy -- end gets lost.
    #[test]
    fn repeated_forwarding_fields_are_read_as_one_list() {
        let edge: IpAddr = "192.0.2.7".parse().expect("address");
        let inner: IpAddr = "192.0.2.8".parse().expect("address");
        let client: IpAddr = "198.51.100.42".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.42".parse().expect("header"));
        headers.append("x-forwarded-for", "192.0.2.7".parse().expect("header"));
        assert_eq!(request_source(inner, &headers, &[edge, inner]), client);
    }

    /// A client cannot disown itself by poisoning the end of the list it owns.
    ///
    /// The entries on the left are whatever the client sent. If one unparseable
    /// entry there could discard the whole list, every attacker would send one
    /// and be attributed to the proxy instead -- landing everybody in a single
    /// shared bucket, which is the limiter failing open.
    #[test]
    fn client_supplied_junk_cannot_move_attribution_off_the_client() {
        let proxy: IpAddr = "192.0.2.7".parse().expect("address");
        let client: IpAddr = "198.51.100.42".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "not-an-address, <script>, 198.51.100.42"
                .parse()
                .expect("header"),
        );
        assert_eq!(
            request_source(proxy, &headers, &[proxy]),
            client,
            "the rightmost verifiable hop is still the attribution"
        );
    }

    /// Junk on the right stops the walk at the last hop that was verifiable.
    #[test]
    fn junk_nearer_the_proxy_stops_the_walk_conservatively() {
        let proxy: IpAddr = "192.0.2.7".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, not-an-address".parse().expect("header"),
        );
        assert_eq!(
            request_source(proxy, &headers, &[proxy]),
            proxy,
            "past an unreadable entry the list proves nothing"
        );
    }

    /// An all-proxy list attributes to the outermost proxy rather than
    /// falling back to the peer.
    #[test]
    fn a_list_of_only_proxies_attributes_to_the_outermost_one() {
        let edge: IpAddr = "192.0.2.7".parse().expect("address");
        let inner: IpAddr = "192.0.2.8".parse().expect("address");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.7, 192.0.2.8".parse().expect("header"),
        );
        assert_eq!(request_source(inner, &headers, &[edge, inner]), edge);
    }

    /// Registration is closed unless something explicitly opens it.
    ///
    /// An open endpoint is not only an account-creation problem: a 409 for a
    /// taken username enumerates every account on the service, which no
    /// amount of constant-time password comparison closes.
    #[tokio::test]
    async fn registration_is_closed_unless_bootstrapping_or_explicitly_opened() {
        let mut state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: false,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: Some("a-sufficiently-long-admin-token".to_string()),
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"relay-secret-value".to_vec(),
        };
        let anonymous = HeaderMap::new();

        // An empty store bootstraps its first account.
        assert_eq!(
            authorize_registration(&state, &anonymous).await,
            Some(RegistrationAuthorization::Bootstrap)
        );
        {
            let mut accounts = state.accounts.lock().await;
            accounts
                .register_derived(
                    "first-operator",
                    [7; 16],
                    [9; 32],
                    None,
                    true,
                    super::control_plane::now_ms(),
                )
                .expect("bootstrap account");
        }

        // Once an account exists, an anonymous caller is refused.
        assert_eq!(
            authorize_registration(&state, &anonymous).await,
            None,
            "registration must close after the first account exists"
        );

        // The administrator capability still gets through.
        let mut admin = HeaderMap::new();
        admin.insert(
            "authorization",
            "Bearer a-sufficiently-long-admin-token"
                .parse()
                .expect("authorization header"),
        );
        assert_eq!(
            authorize_registration(&state, &admin).await,
            Some(RegistrationAuthorization::Admin)
        );

        // And an operator can deliberately run an open endpoint.
        state.open_registration = true;
        assert_eq!(
            authorize_registration(&state, &anonymous).await,
            Some(RegistrationAuthorization::ExplicitlyOpen)
        );
    }

    /// Two anonymous registrations that both observed an empty store must not
    /// both succeed.
    ///
    /// This reproduces the interleaving deterministically rather than racing
    /// threads: both requests are authorized while the store is empty -- which
    /// is exactly what happens when the first request is still deriving its
    /// password -- and only then does either one insert. The second must be
    /// refused, because the basis it was authorized on no longer holds.
    #[tokio::test]
    async fn only_one_of_two_concurrent_bootstrap_registrations_succeeds() {
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: false,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: Some("a-sufficiently-long-admin-token".to_string()),
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"relay-secret-value".to_vec(),
        };
        let anonymous = HeaderMap::new();

        // Both requests reach authorization before either inserts.
        let first = authorize_registration(&state, &anonymous)
            .await
            .expect("first is authorized to bootstrap");
        let second = authorize_registration(&state, &anonymous)
            .await
            .expect("second is authorized while the store is still empty");
        assert_eq!(first, RegistrationAuthorization::Bootstrap);
        assert_eq!(second, RegistrationAuthorization::Bootstrap);

        let mut accounts = state.accounts.lock().await;
        accounts
            .register_derived(
                "operator-one",
                [1; 16],
                [1; 32],
                None,
                first.requires_empty_store(),
                super::control_plane::now_ms(),
            )
            .expect("the first bootstrap succeeds");
        let second_result = accounts.register_derived(
            "operator-two",
            [2; 16],
            [2; 32],
            None,
            second.requires_empty_store(),
            super::control_plane::now_ms(),
        );
        assert!(
            second_result.is_err(),
            "a second bootstrap registration must be refused once an account exists"
        );
        assert_eq!(
            accounts.account_count(),
            1,
            "exactly one account may be created by bootstrap"
        );
    }

    #[tokio::test]
    async fn expired_sessions_are_removed_and_their_sockets_are_closed() {
        let (sender, mut receiver) = mpsc::channel(2);
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        };
        state.sessions.lock().await.insert(
            "expired".into(),
            Session {
                ownership: None,
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

    fn owned_session(account: &str, requester: &str, target: &str) -> Session {
        let mut session = test_session();
        session.ownership = Some(SessionOwnership {
            account_id: account.into(),
            requester_device_id: requester.into(),
            target_device_id: target.into(),
            request_id: "req".into(),
        });
        session
    }

    #[test]
    fn sessions_owned_by_selects_by_account_then_device() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "a-req-d1".to_string(),
            owned_session("acct-a", "dev-1", "dev-2"),
        );
        sessions.insert(
            "a-tgt-d1".to_string(),
            owned_session("acct-a", "dev-3", "dev-1"),
        );
        sessions.insert(
            "b-other".to_string(),
            owned_session("acct-b", "dev-1", "dev-9"),
        );
        // A provisioning session has no ownership and must never be selected.
        sessions.insert("provisioning".to_string(), test_session());

        let mut all_a = sessions_owned_by(&sessions, "acct-a", None);
        all_a.sort();
        assert_eq!(all_a, vec!["a-req-d1".to_string(), "a-tgt-d1".to_string()]);

        // dev-1 matches whether it is the requester or the target device.
        let mut by_d1 = sessions_owned_by(&sessions, "acct-a", Some("dev-1"));
        by_d1.sort();
        assert_eq!(by_d1, vec!["a-req-d1".to_string(), "a-tgt-d1".to_string()]);

        assert_eq!(
            sessions_owned_by(&sessions, "acct-a", Some("dev-3")),
            vec!["a-tgt-d1".to_string()]
        );
        // A different account, and provisioning (unowned) sessions, never match.
        assert!(sessions_owned_by(&sessions, "acct-a", Some("dev-9")).is_empty());
        assert!(sessions_owned_by(&sessions, "acct-x", None).is_empty());
    }

    #[tokio::test]
    async fn revoking_a_device_tears_down_its_live_sessions_only() {
        let state = connect_test_state();
        let (doomed_tx, mut doomed_rx) = mpsc::channel(2);
        let (survivor_tx, mut survivor_rx) = mpsc::channel(2);
        {
            let mut sessions = state.sessions.lock().await;
            let mut doomed = owned_session("acct-a", "dev-1", "dev-2");
            doomed.host = Some(doomed_tx);
            sessions.insert("doomed".to_string(), doomed);
            // Same account but not involving dev-1: it must survive.
            let mut survivor = owned_session("acct-a", "dev-7", "dev-8");
            survivor.client = Some(survivor_tx);
            sessions.insert("survivor".to_string(), survivor);
        }

        let senders = revoke_owned_sessions(&state, "acct-a", Some("dev-1")).await;
        assert_eq!(
            senders.len(),
            1,
            "only the dev-1 session's sender comes back"
        );

        let remaining: Vec<String> = state.sessions.lock().await.keys().cloned().collect();
        assert_eq!(remaining, vec!["survivor".to_string()]);

        // The torn-down session's socket receives a close; the survivor's does not.
        senders[0]
            .try_send(Message::Close(None))
            .expect("close fits the bounded queue");
        assert!(matches!(doomed_rx.recv().await, Some(Message::Close(None))));
        assert!(survivor_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn relay_unregistration_is_idempotent_and_preserves_newer_registration() {
        let secret = b"test-relay-secret-0123456789".to_vec();
        let (host_sender, _) = mpsc::channel(1);
        let state = AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: secret.clone(),
        };
        state.sessions.lock().await.insert(
            "session-1".into(),
            Session {
                ownership: None,
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
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
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
            validate_signal_message(
                r#"{"type":"ice_credentials_v2","establishment_generation":1,"ufrag":"short","pwd":"long-password"}"#
            )
            .is_ok()
        );
        assert!(validate_signal_message(
            r#"{"type":"ice_candidate_v2","establishment_generation":1,"candidate":"candidate:1 1 udp 1 127.0.0.1 4000 typ host"}"#
        )
        .is_ok());
        assert!(
            validate_signal_message(
                r#"{"type":"ice_candidate_done_v2","establishment_generation":1,"count":2}"#
            )
            .is_ok()
        );
        assert!(
            validate_signal_message(&format!(
                r#"{{"type":"ice_key_v2","establishment_generation":1,"public_key":"{}","identity_public_key":"{}","signature":"{}"}}"#,
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(64),
            ))
            .is_ok()
        );
    }

    /// The pre-epoch ICE vocabulary is refused outright rather than treated
    /// as an older dialect.
    ///
    /// Those envelopes carry no establishment generation, so the service
    /// cannot tell a record from the current pair of sockets from one a
    /// reconnect left behind -- which is the ambiguity the epoch exists to
    /// remove. Accepting them "for compatibility" would reintroduce it for
    /// any peer that simply omitted the field.
    #[test]
    fn signaling_validator_rejects_the_pre_epoch_ice_vocabulary() {
        for message in [
            r#"{"type":"ice_credentials","ufrag":"short","pwd":"long-password"}"#,
            r#"{"type":"ice_candidate","candidate":"candidate:1 1 udp 1 127.0.0.1 4000 typ host"}"#,
            r#"{"type":"ice_candidate_done"}"#,
        ] {
            assert!(
                validate_signal_message(message).is_err(),
                "accepted pre-epoch envelope {message}"
            );
        }
        assert!(
            validate_signal_message(&format!(
                r#"{{"type":"key","public_key":"{}","identity_public_key":"{}","signature":"{}"}}"#,
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(64),
            ))
            .is_err(),
            "accepted the pre-epoch key envelope"
        );
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
        assert_peer_ready(&mut host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);
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
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);

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
        assert_peer_reset(&mut client_rx, 1);
        assert_peer_ready(&mut client_rx, 2);
        assert_peer_ready(&mut new_host_rx, 2);
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
        assert_peer_ready(&mut host_rx, 1);
        assert_peer_reset(&mut host_rx, 1);
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
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);
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
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);
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
        assert_peer_reset(&mut client_rx, 1);
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
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);
        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx).expect("replacement");
        // The surviving client sees the old epoch invalidated and the new one
        // published; the replacement socket sees its relay proof and the new
        // epoch. Drain all of it so the assertions below describe what the
        // stale cleanup did, not what admission had already queued.
        assert_peer_reset(&mut client_rx, 1);
        assert_peer_ready(&mut client_rx, 2);
        assert_relay_proof(new_host_rx.try_recv().expect("replacement proof"), 2);
        assert_peer_ready(&mut new_host_rx, 2);

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
    fn replacement_after_peer_ready_before_candidate_done_allows_only_next_epoch() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        assert_relay_proof(old_host_rx.try_recv().expect("host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("client proof"), 1);
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);

        // The old host has received peer_ready but has not completed its
        // candidate exchange yet. A replacement must invalidate that epoch
        // before any old candidate can be forwarded.
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::Forward(_)
        ));
        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx)
            .expect("replacement host");

        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::StaleSocket
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 2, 1),
            DirectRoute::DropStale
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 2, 2),
            DirectRoute::Forward(_)
        ));

        assert_relay_proof(new_host_rx.try_recv().expect("replacement proof"), 2);
        assert_peer_reset(&mut client_rx, 1);
        assert_peer_ready(&mut client_rx, 2);
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn replacement_after_candidate_done_before_key_exchange_rejects_old_key_epoch() {
        let mut session = test_session();
        let (host_tx, mut host_rx) = mpsc::channel(8);
        let (old_client_tx, mut old_client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &old_client_tx).expect("client");
        assert_relay_proof(host_rx.try_recv().expect("host proof"), 1);
        assert_relay_proof(old_client_rx.try_recv().expect("client proof"), 1);
        assert_peer_ready(&mut host_rx, 1);
        assert_peer_ready(&mut old_client_rx, 1);

        let candidate_done = Message::Text(
            r#"{"type":"direct_candidate_done","establishment_generation":1,"count":1}"#.into(),
        );
        let peer = match direct_message_route(&session, PrimaryRole::Host, 1, 1) {
            DirectRoute::Forward(peer) => peer,
            other => panic!("candidate exchange should target current client: {other:?}"),
        };
        peer.try_send(candidate_done)
            .expect("candidate done forwards");
        assert!(matches!(
            old_client_rx.try_recv(),
            Ok(Message::Text(text)) if text.contains("direct_candidate_done")
        ));

        // The client is replaced after candidate completion but before its
        // direct key. The old socket and its signed key must not participate
        // in the next epoch.
        let (new_client_tx, mut new_client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Client, &new_client_tx)
            .expect("replacement client");
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Client, 1, 1),
            DirectRoute::StaleSocket
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::DropStale
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 2),
            DirectRoute::Forward(_)
        ));

        assert_relay_proof(new_client_rx.try_recv().expect("replacement proof"), 2);
        assert_peer_reset(&mut host_rx, 1);
        assert_peer_ready(&mut host_rx, 2);
        assert_peer_ready(&mut new_client_rx, 2);
        assert!(host_rx.try_recv().is_err());
        assert!(new_client_rx.try_recv().is_err());
    }

    #[test]
    fn correctly_signed_old_socket_key_is_not_forwarded_after_generation_change() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        assert_relay_proof(old_host_rx.try_recv().expect("host proof"), 1);
        assert_relay_proof(client_rx.try_recv().expect("client proof"), 1);
        assert_peer_ready(&mut old_host_rx, 1);
        assert_peer_ready(&mut client_rx, 1);

        let signed_old_key = signed_direct_key_message("session-1", 1);
        let signed_old_key_text = message_text(signed_old_key);
        assert!(validate_signal_message(&signed_old_key_text).is_ok());

        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx)
            .expect("replacement host");
        assert_relay_proof(new_host_rx.try_recv().expect("replacement proof"), 2);
        assert_peer_reset(&mut client_rx, 1);
        assert_peer_ready(&mut client_rx, 2);

        // The signature is valid for session-1/host/epoch-1, but the socket
        // generation is no longer current. It must not reach the client.
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 1, 1),
            DirectRoute::StaleSocket
        ));
        assert!(matches!(
            direct_message_route(&session, PrimaryRole::Host, 2, 1),
            DirectRoute::DropStale
        ));
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn reconnect_converges_with_exactly_one_reset_and_one_next_ready() {
        let mut session = test_session();
        let (old_host_tx, mut old_host_rx) = mpsc::channel(8);
        let (client_tx, mut client_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &old_host_tx).expect("host");
        admit_primary_socket(&mut session, PrimaryRole::Client, &client_tx).expect("client");
        for receiver in [&mut old_host_rx, &mut client_rx] {
            let _ = receiver.try_recv(); // relay proof
            assert_peer_ready(receiver, 1);
        }

        let (new_host_tx, mut new_host_rx) = mpsc::channel(8);
        admit_primary_socket(&mut session, PrimaryRole::Host, &new_host_tx)
            .expect("reconnect host");
        assert_eq!(session.establishment_generation, 2);
        assert_eq!(
            session
                .ready_pair
                .expect("replacement epoch")
                .establishment_generation,
            2
        );
        assert_relay_proof(new_host_rx.try_recv().expect("new proof"), 2);

        assert_peer_reset(&mut client_rx, 1);
        assert_peer_ready(&mut client_rx, 2);
        assert!(client_rx.try_recv().is_err());

        // A stale cleanup of the old socket is a no-op and cannot publish a
        // second reset or recover another epoch.
        assert!(!cleanup_primary_socket(&mut session, PrimaryRole::Host, 1));
        assert!(client_rx.try_recv().is_err());
        assert_eq!(session.establishment_generation, 2);
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
                .all(|message| !super::is_establishment_message(message))
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
    // -----------------------------------------------------------------------
    // Secure Connect, end to end over the real router.
    // -----------------------------------------------------------------------

    /// The whole product surface in one state, with registration open so the
    /// test can create the two accounts' devices the way a client would.
    fn connect_test_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_creates: Arc::new(Mutex::new(CreationLimiter::default())),
            auth_attempts: Arc::new(Mutex::new(RateWindow::default())),
            refresh_attempts: Arc::new(Mutex::new(RateWindow::default())),
            auth_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            refresh_sources: Arc::new(Mutex::new(SourceLimiter::default())),
            trusted_proxies: Arc::new(Vec::new()),
            password_derivations: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PASSWORD_DERIVATIONS,
            )),
            open_registration: true,
            accounts: test_accounts(),
            connect: Arc::new(Mutex::new(super::connect::ConnectBroker::default())),
            admin_token: None,
            allow_no_auth: false,
            local_no_auth: false,
            relay_address: None,
            turn: None,
            relay_secret: b"test-relay-secret".to_vec(),
        }
    }

    fn connect_router(state: AppState) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/version", get(version_info))
            .route("/v1/auth/registration", get(registration_capability))
            .route("/v1/auth/register", post(register_account))
            .route("/v1/auth/login", post(login_account))
            .route(
                "/v1/devices",
                get(list_account_devices).post(enroll_account_device),
            )
            .route(
                "/v1/devices/{device_id}/trust",
                axum::routing::patch(set_account_device_trust),
            )
            .route(
                "/v1/presence",
                post(connect_presence).delete(connect_offline),
            )
            .route("/v1/connect", post(connect_request))
            .route("/v1/connect/pending", get(connect_pending))
            .route("/v1/connect/{request_id}", get(connect_observe))
            .route("/v1/connect/{request_id}/approve", post(connect_approve))
            .route("/v1/connect/{request_id}/deny", post(connect_deny))
            .route("/v1/session", post(create_session))
            // The signalling socket, so a test can present a broker-issued
            // credential to it and prove the connect flow and the relay are one
            // product rather than two subsystems that only work in isolation.
            .route("/v1/signal/{session_id}/{role}", get(signal_socket))
            .with_state(state)
    }

    /// Drive the real router, so routing and extractors are under test too.
    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let body = body.map_or_else(axum::body::Body::empty, |value| {
            axum::body::Body::from(value.to_string())
        });
        let mut request = request.body(body).expect("request");
        // The auth handlers attribute rate limiting to the peer address, so
        // they extract `ConnectInfo`. `oneshot` bypasses the connection layer
        // that normally supplies it, and a missing extension is a 500 rather
        // than a routing error -- which is exactly the kind of failure that
        // looks like a broken handler.
        request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
            "203.0.113.5:4000".parse().expect("peer address"),
        ));
        let response = app.clone().oneshot(request).await.expect("router responds");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body");
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    /// `/version` reports a build identity, not just that the process answers.
    ///
    /// `/healthz` alone cannot distinguish a good deploy from a stale or
    /// partial one; this is the endpoint an operator checks to prove which
    /// commit is actually serving traffic.
    #[tokio::test]
    async fn version_reports_a_non_empty_build_identity() {
        let app = connect_router(connect_test_state());
        let (status, body) = call(&app, "GET", "/version", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["name"].as_str(),
            Some("openstream-signal-server"),
            "unexpected package name in {body}"
        );
        assert!(
            body["version"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "version must be present: {body}"
        );
        assert!(
            body["git_sha"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "git_sha must be present even when it falls back to \"unknown\": {body}"
        );
    }

    /// An unclaimed deployment advertises that it will take a first account,
    /// and stops advertising it once one exists.
    ///
    /// This is what lets the login screen stop offering a "Create an account"
    /// button that cannot succeed. The transition is the whole point: the
    /// same server answers differently before and after bootstrap, so the
    /// shell has to ask rather than assume.
    #[tokio::test]
    async fn registration_is_advertised_only_while_it_would_succeed() {
        // Closed deployment: the shared helper opts registration open, which
        // is the *other* configuration and would never show the transition
        // this test exists to pin.
        let state = AppState {
            open_registration: false,
            ..connect_test_state()
        };
        let app = connect_router(state.clone());

        let (status, body) = call(&app, "GET", "/v1/auth/registration", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["open"],
            serde_json::json!(true),
            "an unclaimed deployment accepts the first account: {body}"
        );

        register_with_device(&app, "operator", "device-one", 0x51).await;

        let (status, body) = call(&app, "GET", "/v1/auth/registration", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["open"],
            serde_json::json!(false),
            "a claimed, closed deployment must not advertise open signup: {body}"
        );
    }

    /// The advertised answer matches what registration actually does.
    ///
    /// A capability endpoint that disagrees with the endpoint it describes is
    /// worse than none: the shell would hide a button that works, or offer one
    /// that does not. So this asserts the two agree rather than asserting a
    /// hardcoded expectation.
    #[tokio::test]
    async fn the_advertised_capability_matches_what_registration_does() {
        let state = AppState {
            open_registration: false,
            ..connect_test_state()
        };
        let app = connect_router(state.clone());
        register_with_device(&app, "operator", "device-one", 0x52).await;

        let (_, body) = call(&app, "GET", "/v1/auth/registration", None, None).await;
        let advertised = body["open"].as_bool().expect("open is a bool");

        let (status, _) = call(
            &app,
            "POST",
            "/v1/auth/register",
            None,
            Some(serde_json::json!({
                "username": "second",
                "password": "correct horse battery staple",
                "device": {
                    "device_id": "device-two",
                    "name": "device-two",
                    "platform": "test",
                    "public_key": hex::encode([0x53_u8; 32]),
                }
            })),
        )
        .await;
        let actually_open = status == StatusCode::CREATED;
        assert_eq!(
            advertised, actually_open,
            "the capability endpoint said open={advertised} but registration answered {status}"
        );
    }

    /// Register an account with one enrolled device and return its access
    /// token and device id.
    async fn register_with_device(
        app: &Router,
        username: &str,
        device_name: &str,
        key_byte: u8,
    ) -> (String, String) {
        let public_key = hex::encode([key_byte; 32]);
        let (status, body) = call(
            app,
            "POST",
            "/v1/auth/register",
            None,
            Some(serde_json::json!({
                "username": username,
                "password": "a-sufficiently-long-password",
                "device": {
                    "device_id": device_name,
                    "name": device_name,
                    "platform": "test",
                    "public_key": public_key,
                }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "register: {body}");
        let token = body["access_token"]
            .as_str()
            .expect("access token")
            .to_string();
        (token, device_name.to_string())
    }

    /// Enrol a second device on an existing account and trust it.
    async fn enroll_trusted_device(
        app: &Router,
        token: &str,
        device_id: &str,
        key_byte: u8,
    ) -> String {
        let public_key = hex::encode([key_byte; 32]);
        let (status, body) = call(
            app,
            "POST",
            "/v1/devices",
            Some(token),
            Some(serde_json::json!({
                "device_id": device_id,
                "name": device_id,
                "platform": "test",
                "public_key": public_key,
            })),
        )
        .await;
        // A device that signed in has already enrolled itself as pending, so
        // a conflict here means "already known", which is the state this
        // helper wants it in.
        assert!(
            status == StatusCode::OK || status == StatusCode::CONFLICT,
            "enroll: {status} {body}"
        );
        let (status, body) = call(
            app,
            "PATCH",
            &format!("/v1/devices/{device_id}/trust"),
            Some(token),
            Some(serde_json::json!({ "trust": "trusted" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "trust: {body}");
        device_id.to_string()
    }

    /// Sign a device in on an existing account, binding a token to it.
    async fn sign_in_as_device(
        app: &Router,
        username: &str,
        device_id: &str,
        key_byte: u8,
    ) -> String {
        let (status, body) = call(
            app,
            "POST",
            "/v1/auth/login",
            None,
            Some(serde_json::json!({
                "username": username,
                "password": "a-sufficiently-long-password",
                "device": {
                    "device_id": device_id,
                    "name": device_id,
                    "platform": "test",
                    "public_key": hex::encode([key_byte; 32]),
                }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "login as {device_id}: {body}");
        body["access_token"]
            .as_str()
            .expect("access token")
            .to_string()
    }

    /// credential the broker mints from an approval authenticates the
    /// signalling socket, and the socket then delivers its first frame.
    ///
    /// Every other test drives the two in isolation -- the connect flow over
    /// HTTP with `oneshot`, the socket with a hand-built session. This one runs
    /// the whole path against a single real served router: register, approve,
    /// then present the issued host credential to `/v1/signal` over a real
    /// WebSocket. If the token the broker mints did not match the token the
    /// socket checks, each half would pass its own test and they would fail
    /// only here.
    #[tokio::test]
    async fn a_broker_issued_credential_authenticates_the_signalling_socket() {
        let state = connect_test_state();
        let app = connect_router(state.clone());

        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x41).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x42).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x42).await;
        let (status, _) = call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Client asks, host approves -> the host credential (session, token, ws
        // path). This is the value the socket must accept.
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();
        let (status, grant) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve: {grant}");
        let ws_path = grant["websocket_path"]
            .as_str()
            .expect("websocket path")
            .to_string();
        let host_capability = grant["token"]
            .as_str()
            .expect("host capability")
            .to_string();

        // Serve the same router (so the same in-memory session) over TCP for
        // the WebSocket half.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        // Present the broker-issued credential to the signalling socket. A
        // token the socket does not recognise fails the handshake here.
        let mut request = format!("ws://{address}{ws_path}")
            .into_client_request()
            .expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {host_capability}")
                .parse()
                .expect("authorization header"),
        );
        let (mut socket, response) = connect_async(request)
            .await
            .expect("the broker-issued credential authenticates the signalling socket");
        assert_eq!(
            response.status().as_u16(),
            101,
            "the socket switches protocols for a credential it recognises",
        );

        // The host side receives a first frame on connect, proving the socket
        // is live for this session rather than merely accepting the upgrade.
        let first = timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("a first frame arrives before the timeout")
            .expect("the socket yields a frame")
            .expect("the frame is a valid websocket message");
        assert!(
            matches!(first, ClientMessage::Text(_) | ClientMessage::Binary(_)),
            "the signalling socket delivers its first frame to the host",
        );

        server.abort();
    }

    /// The signalling socket refuses a credential it never minted.
    ///
    /// The positive path proves a broker-issued token is accepted; this proves
    /// that acceptance is a check, not a formality. A real session exists, but a
    /// token the socket never issued for it does not open a live socket: either
    /// the handshake is refused, or the upgrade completes and the socket closes
    /// without ever delivering the session's first frame.
    #[tokio::test]
    async fn the_signalling_socket_refuses_a_credential_it_did_not_mint() {
        let state = connect_test_state();
        let app = connect_router(state.clone());

        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x43).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x44).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x44).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();
        let (_, grant) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        let ws_path = grant["websocket_path"]
            .as_str()
            .expect("websocket path")
            .to_string();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        let mut request = format!("ws://{address}{ws_path}")
            .into_client_request()
            .expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            "Bearer not-a-credential-this-socket-issued"
                .parse()
                .expect("authorization header"),
        );

        match connect_async(request).await {
            // The handshake itself was refused: an unambiguous rejection.
            Err(_) => {}
            // The upgrade completed; the socket must not then act as a live
            // session socket. It closes, errors, or yields nothing -- never a
            // usable first frame.
            Ok((mut socket, _)) => {
                match timeout(Duration::from_secs(2), socket.next()).await {
                    Ok(Some(Ok(ClientMessage::Text(text)))) => {
                        panic!("a credential the socket did not mint received a text frame: {text}")
                    }
                    Ok(Some(Ok(ClientMessage::Binary(bytes)))) => panic!(
                        "a credential the socket did not mint received a binary frame ({} bytes)",
                        bytes.len()
                    ),
                    // Close, transport error, end of stream, or timeout: all are
                    // a rejection, none is authentication.
                    _ => {}
                }
            }
        }

        server.abort();
    }

    /// A signalling socket that drops can reconnect with the same credential.
    ///
    /// A transport drop must not force the whole Connect flow to run again: the
    /// session and its role token outlive one socket, so a reconnecting peer
    /// presents the same credential and goes live again. This is the signalling
    /// half of reconnect resilience (signalling outage -> reconnect); the media
    /// path re-establishes separately.
    #[tokio::test]
    async fn a_signalling_socket_reconnects_with_the_same_credential_after_a_drop() {
        let state = connect_test_state();
        let app = connect_router(state.clone());

        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x45).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x46).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x46).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();
        let (_, grant) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        let ws_path = grant["websocket_path"]
            .as_str()
            .expect("websocket path")
            .to_string();
        let host_capability = grant["token"]
            .as_str()
            .expect("host capability")
            .to_string();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let ws_url = format!("ws://{address}{ws_path}");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });
        let bearer = format!("Bearer {host_capability}");

        // Connect, take the first frame, then drop the socket -- a signalling
        // outage from the peer's side.
        {
            let mut request = ws_url.clone().into_client_request().expect("request");
            request
                .headers_mut()
                .insert("authorization", bearer.parse().expect("header"));
            let (mut socket, response) = connect_async(request).await.expect("first connect");
            assert_eq!(response.status().as_u16(), 101);
            let _first = timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("a first frame arrives")
                .expect("socket yields a frame")
                .expect("valid frame");
            // The socket drops at the end of this scope.
        }

        // Let the server observe the drop before the reconnect.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Reconnect with the same credential: the session survived the drop.
        let mut request = ws_url.into_client_request().expect("request");
        request
            .headers_mut()
            .insert("authorization", bearer.parse().expect("header"));
        let (mut socket, response) = connect_async(request)
            .await
            .expect("the same credential reconnects the signalling socket after a drop");
        assert_eq!(
            response.status().as_u16(),
            101,
            "the reconnect switches protocols",
        );
        let first = timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("a first frame arrives on reconnect")
            .expect("socket yields a frame")
            .expect("valid frame");
        assert!(
            matches!(first, ClientMessage::Text(_) | ClientMessage::Binary(_)),
            "the reconnected socket is live",
        );

        server.abort();
    }

    /// Two broker-issued peers meet on the signalling plane and a candidate
    /// relays between them.
    ///
    /// The credential tests above each bring up a single socket. A session is
    /// only useful once both roles are live and can exchange establishment
    /// traffic, so this brings both up from one approval -- the host credential
    /// from `/approve`, the client credential from the observing `GET` -- lets
    /// the server pair them into one establishment epoch, and drives one real
    /// direct candidate from the client through to the host. It exercises the
    /// readiness handshake (`peer_ready`) and the post-ready relay together,
    /// end to end over real WebSockets, which no single-socket test can reach.
    #[tokio::test]
    async fn two_peers_relay_a_candidate_after_reaching_readiness() {
        let state = connect_test_state();
        let app = connect_router(state.clone());

        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x51).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x52).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x52).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;

        // Client asks; host approves -> the host credential. The client then
        // observes the approved request -> the client credential. Two roles,
        // one session, from a single approval.
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();
        let (status, host_grant) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve: {host_grant}");
        let (status, client_grant) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "observe: {client_grant}");

        let host_path = host_grant["websocket_path"]
            .as_str()
            .expect("host websocket path")
            .to_string();
        let host_capability = host_grant["token"]
            .as_str()
            .expect("host capability")
            .to_string();
        let client_path = client_grant["websocket_path"]
            .as_str()
            .expect("client websocket path")
            .to_string();
        let client_capability = client_grant["token"]
            .as_str()
            .expect("client capability")
            .to_string();

        // Serve the same router (hence the same in-memory session) over TCP so
        // both roles can open real WebSockets against it.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let host_url = format!("ws://{address}{host_path}");
        let client_url = format!("ws://{address}{client_path}");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        // Bring up the host socket first; it is live but not yet paired.
        let mut host_request = host_url.into_client_request().expect("host request");
        host_request.headers_mut().insert(
            "authorization",
            format!("Bearer {host_capability}")
                .parse()
                .expect("host authorization header"),
        );
        let (mut host_socket, _) = connect_async(host_request)
            .await
            .expect("the host credential authenticates its socket");

        // Bring up the client socket. With both roles present the server
        // publishes the ready epoch to each.
        let mut client_request = client_url.into_client_request().expect("client request");
        client_request.headers_mut().insert(
            "authorization",
            format!("Bearer {client_capability}")
                .parse()
                .expect("client authorization header"),
        );
        let (mut client_socket, _) = connect_async(client_request)
            .await
            .expect("the client credential authenticates its socket");

        // The client reads until its readiness announcement and takes the
        // establishment generation it must stamp on establishment traffic.
        let generation = loop {
            let frame = timeout(Duration::from_secs(2), client_socket.next())
                .await
                .expect("a client readiness frame arrives before the timeout")
                .expect("the client socket yields a frame")
                .expect("the client frame is valid");
            if let ClientMessage::Text(text) = frame {
                let value: serde_json::Value =
                    serde_json::from_str(text.as_str()).expect("a signalling frame is JSON");
                if value.get("type").and_then(serde_json::Value::as_str) == Some("peer_ready") {
                    break value["establishment_generation"]
                        .as_u64()
                        .expect("a readiness generation");
                }
            }
        };
        assert!(
            generation >= 1,
            "the readiness epoch is published to the client"
        );

        // The client emits one real direct candidate stamped with that epoch.
        let candidate = serde_json::json!({
            "type": "direct_candidate",
            "establishment_generation": generation,
            "kind": "host",
            "ip": "192.0.2.20",
            "port": 40002,
        })
        .to_string();
        client_socket
            .send(ClientMessage::Text(candidate))
            .await
            .expect("the client sends its candidate");

        // The host reads until the client's candidate arrives, relayed by the
        // server -- proof the two peers share one live signalling plane rather
        // than two isolated sockets.
        let relayed = loop {
            let frame = timeout(Duration::from_secs(2), host_socket.next())
                .await
                .expect("the relayed candidate arrives at the host before the timeout")
                .expect("the host socket yields a frame")
                .expect("the host frame is valid");
            if let ClientMessage::Text(text) = frame {
                let value: serde_json::Value =
                    serde_json::from_str(text.as_str()).expect("a signalling frame is JSON");
                if value.get("type").and_then(serde_json::Value::as_str) == Some("direct_candidate")
                {
                    break value;
                }
            }
        };
        assert_eq!(
            relayed["establishment_generation"].as_u64(),
            Some(generation),
            "the relayed candidate carries the same establishment epoch",
        );
        assert_eq!(
            relayed["ip"].as_str(),
            Some("192.0.2.20"),
            "the host receives the client's candidate unchanged",
        );
        assert_eq!(
            relayed["port"].as_u64(),
            Some(40002),
            "the candidate port survives the relay"
        );

        server.abort();
    }

    /// Permission classes negotiate through the broker: the requester asks, the
    /// target sees the request and grants a (possibly smaller) set, and both
    /// ends receive the granted set in their credential.
    ///
    /// The broker only carries the decision; nothing here enforces it. But a
    /// class that never reached the host to be granted, or never reached each
    /// end to be enforced, is a permission the product cannot honour -- so this
    /// round trip is the foundation enforcement sits on.
    #[tokio::test]
    async fn permissions_negotiate_through_the_connect_flow() {
        let state = connect_test_state();
        let app = connect_router(state.clone());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x31).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x32).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x32).await;
        let (status, _) = call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // The client asks for view + keyboard + mouse, and nothing else.
        let (status, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({
                "target_device_id": "device-host",
                "requested": { "view": true, "keyboard": true, "mouse": true },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "connect: {body}");
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        // The host sees exactly what was asked, including the classes left off.
        let (status, body) =
            call(&app, "GET", "/v1/connect/pending", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[0]["requested"]["view"], serde_json::json!(true));
        assert_eq!(body[0]["requested"]["keyboard"], serde_json::json!(true));
        assert_eq!(body[0]["requested"]["mouse"], serde_json::json!(true));
        assert_eq!(body[0]["requested"]["clipboard"], serde_json::json!(false));
        assert_eq!(body[0]["requested"]["microphone"], serde_json::json!(false));

        // The host grants a subset: view + keyboard, but not mouse.
        let (status, body) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            Some(serde_json::json!({ "granted": { "view": true, "keyboard": true } })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve: {body}");
        // The host's own credential carries the granted set.
        assert_eq!(body["permissions"]["view"], serde_json::json!(true));
        assert_eq!(body["permissions"]["keyboard"], serde_json::json!(true));
        assert_eq!(body["permissions"]["mouse"], serde_json::json!(false));

        // The client polls and receives the same granted set: both ends agree.
        let (status, body) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "observe: {body}");
        assert_eq!(body["role"], serde_json::json!("client"));
        assert_eq!(body["permissions"]["view"], serde_json::json!(true));
        assert_eq!(body["permissions"]["keyboard"], serde_json::json!(true));
        assert_eq!(body["permissions"]["mouse"], serde_json::json!(false));
    }

    /// The device listing carries live presence, which is what lets the owner's
    /// shell offer a connection at all.
    ///
    /// The broker already tracks and enforces presence, but until it was
    /// surfaced here the shell had no readable online status and marked every
    /// device offline -- so discovery could never happen and the connect
    /// button was never live. Presence must appear in `GET /v1/devices` for
    /// exactly the device that announced it, and only within the owner's own
    /// account.
    #[tokio::test]
    async fn presence_is_reported_in_the_device_listing() {
        let state = connect_test_state();
        let app = connect_router(state.clone());
        // The owner account, with its own (client) device.
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        // A host device on the same account, trusted by the owner.
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;

        let online_of = |body: &serde_json::Value, id: &str| -> bool {
            body.as_array()
                .expect("device array")
                .iter()
                .find(|device| device["device_id"] == serde_json::json!(id))
                .unwrap_or_else(|| panic!("device {id} present in listing: {body}"))["online"]
                .as_bool()
                .expect("online is a bool")
        };

        // Before any heartbeat, nothing is online.
        let (status, body) = call(&app, "GET", "/v1/devices", Some(&client_token), None).await;
        assert_eq!(status, StatusCode::OK, "list devices: {body}");
        assert!(
            !online_of(&body, "device-host"),
            "host offline before heartbeat"
        );
        assert!(!online_of(&body, "device-client"), "client never announces");

        // The host announces it is available.
        let (status, _) = call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "host announces presence");

        // Now the owner sees the host as online, and only the host: a device
        // that never announced stays offline.
        let (status, body) = call(&app, "GET", "/v1/devices", Some(&client_token), None).await;
        assert_eq!(status, StatusCode::OK, "list devices: {body}");
        assert!(
            online_of(&body, "device-host"),
            "the announced host is online"
        );
        assert!(
            !online_of(&body, "device-client"),
            "a device that never announced is not online"
        );
    }

    /// The product flow, end to end, and the boundary it exists to draw.
    ///
    /// Each end receives exactly one role capability and neither can obtain
    /// the other's. Before the broker there was no way to start a session
    /// except to hand one caller both, which is a developer workflow wearing
    /// a product's clothes: the person asking to use a machine received the
    /// capability that controls it.
    #[tokio::test]
    async fn connect_delivers_one_role_capability_to_each_end() {
        let state = connect_test_state();
        let app = connect_router(state.clone());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        // The host device signs in as itself; the owner then trusts it.
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;

        // The host announces it is available.
        let (status, _) = call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "host announces presence");

        // The client asks for it by name.
        let (status, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "connect request: {body}");
        assert_eq!(body["state"], "pending");
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        // The host sees the prompt.
        let (status, body) =
            call(&app, "GET", "/v1/connect/pending", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[0]["request_id"], serde_json::json!(request_id));
        assert_eq!(body[0]["requester_device_id"], "device-client");

        // Before approval the client learns only that it is waiting -- no
        // session, and certainly no capability.
        let (status, body) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "pending");
        assert!(body["token"].is_null(), "no capability before approval");

        // The host approves, and receives the host capability only.
        let (status, host_grant) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve: {host_grant}");
        assert_eq!(host_grant["role"], "host");
        let session_id = host_grant["session_id"].as_str().expect("session id");
        let host_capability = host_grant["token"].as_str().expect("host token");
        assert_eq!(
            host_grant.as_object().expect("object").keys().count(),
            7,
            "the approval response carries one capability plus the granted \
             permission set, and nothing that could be mistaken for a second \
             capability: {host_grant}"
        );

        // The client collects the client capability only.
        let (status, client_grant) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "observe: {client_grant}");
        assert_eq!(client_grant["role"], "client");
        assert_eq!(client_grant["session_id"], serde_json::json!(session_id));
        let client_capability = client_grant["token"].as_str().expect("client token");

        assert_ne!(
            host_capability, client_capability,
            "the two roles must not share one capability"
        );

        // And the session the pair now shares is attributed to them, so an
        // operator can answer "whose session is this" and revoke by account.
        let sessions = state.sessions.lock().await;
        let session = sessions.get(session_id).expect("the session exists");
        let ownership = session.ownership.as_ref().expect("an owned session");
        assert_eq!(ownership.requester_device_id, "device-client");
        assert_eq!(ownership.target_device_id, "device-host");
        assert_eq!(ownership.request_id, request_id);
        assert!(!ownership.account_id.is_empty());
        assert_eq!(session.host_token, host_capability);
        assert_eq!(session.client_token, client_capability);
    }

    /// Neither end can take the other's capability, and a retry of one's own
    /// is answered rather than refused.
    #[tokio::test]
    async fn a_role_capability_reaches_only_its_party_and_survives_a_retry() {
        let app = connect_router(connect_test_state());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        // The requester cannot approve its own request: that would be asking
        // permission and granting it in one step.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;

        // The host polling the requester's endpoint gets nothing: it is not
        // the requesting device, so the request is not addressed to it.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The client collects...
        let (status, first) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // ...and can collect again if it never received that answer. A
        // dropped connection must not leave a good session with one end
        // permanently unable to join it.
        let (status, again) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first, again, "a retry gets the same credential");
    }

    /// An approval whose response was lost can be repeated.
    ///
    /// The host has no separate collection route: approving *is* how it
    /// receives its credential. So a dropped response left a live session the
    /// host could never join -- the same unrecoverable failure that once-only
    /// collection produced, one layer up. This drives the exact sequence:
    /// approve, discard the answer, approve again with the identical request.
    #[tokio::test]
    async fn a_lost_approval_response_can_be_repeated_by_the_host() {
        let state = connect_test_state();
        let app = connect_router(state.clone());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        // The host approves and the response is lost on the way back.
        let (status, first) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve: {first}");
        let session_id = first["session_id"]
            .as_str()
            .expect("session id")
            .to_string();

        // The host repeats the identical request.
        let (status, again) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a retried approval must not be a conflict: {again}"
        );
        assert_eq!(
            first, again,
            "and must return the same session and host credential"
        );

        // Exactly one session exists: the retry did not mint a second.
        let sessions = state.sessions.lock().await;
        assert_eq!(
            sessions.len(),
            1,
            "a retry must not create a second session"
        );
        assert!(sessions.contains_key(&session_id));
        drop(sessions);

        // And the client can still collect its own side afterwards.
        let (status, client_grant) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(client_grant["role"], "client");
        assert_eq!(client_grant["session_id"], serde_json::json!(session_id));
        assert_ne!(
            client_grant["token"], first["token"],
            "the two roles still hold different capabilities"
        );
    }

    /// A retried approval does not spend a session-creation slot.
    ///
    /// The limit exists to bound how many sessions can be created. A retry
    /// creates none, so charging it would let a flaky network exhaust the
    /// budget for sessions that already exist.
    #[tokio::test]
    async fn a_retried_approval_does_not_consume_the_creation_budget() {
        let state = connect_test_state();
        let app = connect_router(state.clone());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/approve"),
            Some(&host_token),
            None,
        )
        .await;
        let spent_after_first = state.session_creates.lock().await.len();
        for _ in 0..5 {
            let (status, _) = call(
                &app,
                "POST",
                &format!("/v1/connect/{request_id}/approve"),
                Some(&host_token),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        assert_eq!(
            state.session_creates.lock().await.len(),
            spent_after_first,
            "retries must not be charged against session creation"
        );
    }

    /// An untrusted or unknown device is not connectable.
    #[tokio::test]
    async fn only_a_trusted_device_of_this_account_can_be_asked() {
        let app = connect_router(connect_test_state());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;

        // Enrolled but still pending: announcing presence is refused, so a
        // device the owner has not accepted never appears connectable.
        let (status, _) = call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // And asking for it is refused independently of presence.
        let (status, _) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "a-device-that-does-not-exist" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A refusal is reported as a refusal.
    #[tokio::test]
    async fn a_denied_request_is_visible_to_the_asker() {
        let app = connect_router(connect_test_state());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let host_token = sign_in_as_device(&app, "operator", "device-host", 0x22).await;
        enroll_trusted_device(&app, &client_token, "device-host", 0x22).await;
        call(&app, "POST", "/v1/presence", Some(&host_token), None).await;
        let (_, body) = call(
            &app,
            "POST",
            "/v1/connect",
            Some(&client_token),
            Some(serde_json::json!({ "target_device_id": "device-host" })),
        )
        .await;
        let request_id = body["request_id"].as_str().expect("request id").to_string();

        let (status, _) = call(
            &app,
            "POST",
            &format!("/v1/connect/{request_id}/deny"),
            Some(&host_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = call(
            &app,
            "GET",
            &format!("/v1/connect/{request_id}"),
            Some(&client_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["state"], "denied",
            "a refusal the asker never sees reads as the host being broken"
        );
    }

    /// The two-capability endpoint is no longer reachable by account holders.
    #[tokio::test]
    async fn session_provisioning_is_admin_only() {
        let app = connect_router(connect_test_state());
        let (client_token, _) = register_with_device(&app, "operator", "device-client", 0x11).await;
        let (status, _) = call(
            &app,
            "POST",
            "/v1/session",
            Some(&client_token),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an account holder must not be able to mint both role capabilities"
        );
    }
}
