//! The broker's protocol logic: turn a stream of [`ServiceRequest`]s into device
//! calls and [`BrokerEvent`]s.
//!
//! The core is [`BrokerSession`], which is entirely synchronous -- every request
//! is handled by [`BrokerSession::handle_request`] and every ready frame is
//! drained by [`BrokerSession::pump`], both returning the events to send. That
//! keeps the interesting logic (the handshake, the per-seat capability clamp,
//! the capture lifecycle) testable without timers or a socket. [`serve_connection`]
//! is the thin async wrapper that reads requests, calls the session, and writes
//! the events over the [`transport`](openstream_host_ipc::transport).
//!
//! The privileged boundary enforces the login-screen policy itself, not just the
//! service: at the greeter the broker grants keyboard and mouse (so the remote
//! user can type the OS password into the native login screen) but never
//! clipboard or gamepad, whatever the service asks for. A logout back to the
//! greeter contracts the grant the same way.

use std::io;
use std::time::Duration;

use openstream_host_ipc::grant::SessionGrant;
use openstream_host_ipc::lifecycle::Seat;
use openstream_host_ipc::peercred::PeerIdentity;
use openstream_host_ipc::protocol::{BrokerEvent, PROTOCOL_VERSION, ServiceRequest};
use openstream_host_ipc::token::{Capabilities, NO_GRANT, SessionToken};
use openstream_host_ipc::transport::{recv_request, send_event};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::device::{FrameSource, InputSink};

/// Stable reason codes carried in [`BrokerEvent::CaptureError`] and
/// [`BrokerEvent::Closed`].
pub mod code {
    /// `CaptureError`: the service spoke an unsupported protocol version.
    pub const PROTOCOL_VERSION: u16 = 10;
    /// `CaptureError`: the service sent a request before the handshake.
    pub const PROTOCOL_VIOLATION: u16 = 11;
    /// `CaptureError`: the request named a session grant the broker did not
    /// issue, or none at all. Distinct from a protocol violation: the message
    /// was well formed, the authority behind it was not.
    pub const UNAUTHORISED: u16 = 12;
    /// `Closed`: the service asked to close the capture.
    pub const CLOSED_ON_REQUEST: u16 = 0;
    /// `Closed`: the service is shutting the broker connection down.
    pub const CLOSED_ON_SHUTDOWN: u16 = 1;
}

/// The broker's standing policy: the absolute capability ceiling it will ever
/// grant, and how often the async wrapper drains ready frames.
#[derive(Debug, Clone, Copy)]
pub struct BrokerPolicy {
    /// The most any session may ever be granted, before the per-seat clamp
    /// narrows it further. Defaults to everything the broker models.
    pub ceiling: Capabilities,
    /// How often [`serve_connection`] polls the source for frames. Small, for
    /// low latency; the source itself paces real frame production.
    pub frame_poll: Duration,
}

/// What the broker needs in order to believe an approval happened.
///
/// Separate from [`BrokerPolicy`] because it is a different kind of fact: the
/// policy is what this machine's operator allows, and this is who is allowed
/// to say a particular session was approved. Both are read from the root
/// broker's own configuration, which the unprivileged service cannot write.
#[derive(Clone)]
pub struct GrantAuthority {
    /// The secret this machine shares with the control plane, pinned at
    /// enrolment. Empty means no authority is configured, and then nothing is
    /// authorised -- a broker that cannot check an approval has not been given
    /// one to trust.
    key: Vec<u8>,
    /// This machine's device id. A grant addressed to another device is
    /// refused, so an approval for one host in a fleet is not an approval for
    /// all of them.
    device_id: String,
}

impl GrantAuthority {
    /// An authority with a key and this machine's identity.
    #[must_use]
    pub fn new(key: Vec<u8>, device_id: String) -> Self {
        Self { key, device_id }
    }

    /// No authority: every grant is refused.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            key: Vec::new(),
            device_id: String::new(),
        }
    }

    /// Whether a key and identity are present at all.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        !self.key.is_empty() && !self.device_id.is_empty()
    }
}

impl std::fmt::Debug for GrantAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never reaches a log line.
        formatter
            .debug_struct("GrantAuthority")
            .field("device_id", &self.device_id)
            .field("configured", &self.is_configured())
            .finish_non_exhaustive()
    }
}

/// The nonces this broker has already honoured, so a captured grant cannot be
/// presented twice.
///
/// [`SessionGrant`] verifies one grant in isolation and cannot know it has seen
/// it before; that is the caller's job, and this is the caller. Entries are
/// dropped once their grant has expired, which bounds the set by how many
/// approvals can be issued inside one validity window rather than by how long
/// the broker has been running.
#[derive(Debug, Default)]
struct SeenNonces {
    entries: Vec<(u128, u64)>,
}

impl SeenNonces {
    /// Record `nonce` as used, or report that it already was.
    ///
    /// Expired entries are dropped on the way past, so a long-lived broker
    /// does not accumulate them.
    fn accept(&mut self, nonce: u128, expires_at_ms: u64, now_ms: u64) -> bool {
        self.entries.retain(|(_, expiry)| *expiry >= now_ms);
        if self.entries.iter().any(|(seen, _)| *seen == nonce) {
            return false;
        }
        self.entries.push((nonce, expires_at_ms));
        true
    }
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            // Nothing, on purpose. This is the root broker's standing answer to
            // a process that has not been configured to be trusted with
            // anything, and the machine service is network-facing: if its
            // configuration is missing or unreadable, the safe reading is that
            // the operator has not granted it capture or input, not that they
            // granted it everything. The previous default was
            // `Capabilities::all()`, which meant a service compromise reached
            // straight through to the devices.
            ceiling: Capabilities::none(),
            frame_poll: Duration::from_millis(1),
        }
    }
}

/// Where the broker's unguessable grant ids come from.
///
/// A trait rather than a direct call to the CSPRNG so the state machine stays
/// deterministic under test: production draws from the OS, tests hand it a
/// known value and can then check that a *different* value is refused.
pub trait TokenSource {
    /// A fresh, unguessable grant id.
    fn next_id(&mut self) -> u128;
}

/// The production source: platform entropy.
#[derive(Debug, Default)]
pub struct SystemEntropy;

impl TokenSource for SystemEntropy {
    fn next_id(&mut self) -> u128 {
        let mut bytes = [0u8; 16];
        // A grant id that is not random is not a capability. If the platform
        // cannot produce entropy the broker must not fall back to a counter or
        // a clock -- both are what the machine service used to construct
        // itself -- so this returns the one id that is never valid and the
        // grant is refused.
        match lowlat_crypto::fill(&mut bytes) {
            Ok(()) => u128::from_be_bytes(bytes),
            Err(_) => NO_GRANT,
        }
    }
}

/// Parse an operator-configured capability ceiling.
///
/// Comma-separated names: `capture,keyboard,mouse,gamepad,clipboard`, or
/// `all`, or `none`. An unrecognised name is refused rather than ignored --
/// silently dropping a misspelled capability would hand the operator a ceiling
/// they did not write, and the failure they would notice is the one where it is
/// *narrower* than intended, not wider.
///
/// This is read from the root broker's own environment, which is set by its
/// systemd unit. The machine service runs as a different, unprivileged user and
/// cannot write it -- which is the whole point: the ceiling has to come from
/// somewhere the network-facing process cannot reach.
pub fn parse_ceiling(spec: &str) -> Result<Capabilities, String> {
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("none") {
        return Ok(Capabilities::none());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(Capabilities::all());
    }
    let mut ceiling = Capabilities::none();
    for name in spec.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let capability = match name.to_ascii_lowercase().as_str() {
            "capture" => Capabilities::CAPTURE,
            "keyboard" => Capabilities::KEYBOARD,
            "mouse" => Capabilities::MOUSE,
            "gamepad" => Capabilities::GAMEPAD,
            "clipboard" => Capabilities::CLIPBOARD,
            other => return Err(format!("unknown capability {other:?}")),
        };
        ceiling = ceiling.with(capability);
    }
    Ok(ceiling)
}

/// Wall-clock milliseconds since the epoch, for grant expiry.
///
/// A grant's window is written by the control plane in absolute time, so this
/// has to be the wall clock and not a monotonic one. A machine whose clock is
/// badly wrong will refuse valid grants -- reported as expired or not-yet-valid
/// rather than silently accepted, which is the safe direction.
fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The capabilities a seat can ever expose, regardless of what was requested.
/// This is the privileged half of the login-screen policy: the greeter allows
/// exactly enough to log in and nothing that would leak across the trust
/// boundary of an unauthenticated screen.
fn seat_ceiling(seat: Seat) -> Capabilities {
    match seat {
        // Keyboard and mouse so the remote user can type the OS password into
        // the native greeter; never clipboard or gamepad on the login screen.
        Seat::Greeter => Capabilities::CAPTURE
            .with(Capabilities::KEYBOARD)
            .with(Capabilities::MOUSE),
        // Nothing to interact with between sessions.
        Seat::Empty => Capabilities::CAPTURE,
        // A logged-in user's own session: whatever policy and the request allow.
        Seat::User => Capabilities::all(),
    }
}

/// The capabilities actually granted: the request, narrowed to the broker's
/// ceiling and then to what the current seat may expose.
fn effective_grant(requested: Capabilities, ceiling: Capabilities, seat: Seat) -> Capabilities {
    requested.clamped_to(ceiling).clamped_to(seat_ceiling(seat))
}

/// The synchronous broker state machine for one service connection.
pub struct BrokerSession {
    policy: BrokerPolicy,
    handshaken: bool,
    done: bool,
    capturing: bool,
    /// The capabilities the service last requested, kept so a seat change can
    /// re-derive the grant without another request.
    requested: Capabilities,
    /// The capabilities currently granted (after the ceiling and seat clamp).
    granted: Capabilities,
    /// The seat currently being captured.
    seat: Seat,
    /// The grant this connection is operating under, once one has been issued.
    ///
    /// The broker mints it; the service presents it back. An id the broker did
    /// not mint is refused, which is what stops a compromised service from
    /// naming a session it was never approved for.
    grant: Option<SessionToken>,
    /// Where grant ids come from.
    tokens: Box<dyn TokenSource + Send>,
    /// Who may say a session was approved, and which machine this is.
    authority: GrantAuthority,
    /// Nonces already honoured, so a captured approval cannot be replayed.
    seen: SeenNonces,
    /// What the verified approval allowed. A ceiling that survives a seat
    /// switch, so logging in cannot widen a session past its approval.
    approved_capabilities: Capabilities,
    /// The approved session this connection is serving, once a grant has been
    /// verified. A token is bound to it, so a capability cannot outlive the
    /// approval that produced it.
    session_id: Option<String>,
    /// Supplies "now" for expiry checks. A field so a test can move the clock
    /// without sleeping, and so the production value is named in one place.
    now_ms: Box<dyn FnMut() -> u64 + Send>,
}

impl std::fmt::Debug for BrokerSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The grant id is deliberately not printed: it is a bearer capability,
        // and a debug line is a log line. Whether one exists is enough.
        formatter
            .debug_struct("BrokerSession")
            .field("policy", &self.policy)
            .field("handshaken", &self.handshaken)
            .field("done", &self.done)
            .field("capturing", &self.capturing)
            .field("requested", &self.requested)
            .field("granted", &self.granted)
            .field("seat", &self.seat)
            .field("granted_session", &self.grant.is_some())
            .field("authority", &self.authority)
            .field("approved_session", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl BrokerSession {
    /// A fresh session that has not yet completed the handshake.
    #[must_use]
    pub fn new(policy: BrokerPolicy) -> Self {
        Self::with_authority(policy, GrantAuthority::unconfigured())
    }

    /// A fresh session that will verify approvals against `authority`.
    #[must_use]
    pub fn with_authority(policy: BrokerPolicy, authority: GrantAuthority) -> Self {
        Self::with_parts(
            policy,
            authority,
            Box::new(SystemEntropy),
            Box::new(system_now_ms),
        )
    }

    /// A fresh session with every collaborator supplied.
    ///
    /// Production uses [`SystemEntropy`] and the system clock; a test supplies
    /// a known id, so it can check both that the issued capability is accepted
    /// and that any other id is not, and a movable clock, so expiry can be
    /// tested without sleeping.
    #[must_use]
    pub fn with_parts(
        policy: BrokerPolicy,
        authority: GrantAuthority,
        tokens: Box<dyn TokenSource + Send>,
        now_ms: Box<dyn FnMut() -> u64 + Send>,
    ) -> Self {
        Self {
            policy,
            handshaken: false,
            done: false,
            capturing: false,
            requested: Capabilities::none(),
            granted: Capabilities::none(),
            seat: Seat::Empty,
            grant: None,
            tokens,
            authority,
            seen: SeenNonces::default(),
            approved_capabilities: Capabilities::none(),
            session_id: None,
            now_ms,
        }
    }

    /// The approved session this connection is serving, if a grant has been
    /// verified.
    #[must_use]
    pub fn approved_session(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Verify an encoded approval, or say why it is refused.
    ///
    /// Everything fails closed. An unconfigured authority refuses every grant
    /// rather than waving them through, because a broker that cannot check an
    /// approval has not been given one to trust.
    ///
    /// The message returned is deliberately the same shape for every cause:
    /// the reason is logged here, where an operator can see it, and not handed
    /// back to a caller that might be the thing being refused.
    fn verify_approval(&mut self, encoded: &[u8]) -> Result<SessionGrant, String> {
        if !self.authority.is_configured() {
            eprintln!(
                "openstream-host-broker: refusing a session; no grant authority is configured"
            );
            return Err("no session approval could be verified".into());
        }
        let now = (self.now_ms)();
        let approved = SessionGrant::decode_and_verify(
            encoded,
            &self.authority.key,
            now,
            &self.authority.device_id,
        )
        .map_err(|error| {
            eprintln!("openstream-host-broker: refusing a session; {error}");
            "no session approval could be verified".to_string()
        })?;
        // Replay is not something a single grant can rule out: it is the same
        // bytes, correctly tagged, presented again. The broker is the only
        // party that can remember.
        if !self
            .seen
            .accept(approved.nonce, approved.expires_at_ms, now)
        {
            eprintln!(
                "openstream-host-broker: refusing a session; this approval has already been used"
            );
            return Err("no session approval could be verified".into());
        }
        Ok(approved)
    }

    /// Whether `token_id` is the grant this broker issued to this connection.
    ///
    /// Fails closed in both directions: before a grant exists nothing is
    /// authorised, and [`NO_GRANT`] never matches even if a caller managed to
    /// store it.
    fn authorised(&self, token_id: u128) -> bool {
        token_id != NO_GRANT && self.grant.is_some_and(|grant| grant.id() == token_id)
    }

    /// Whether the connection should be closed (shutdown, or a fatal protocol
    /// error). The async wrapper checks this after each request.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The capabilities currently granted to the session.
    #[must_use]
    pub fn granted(&self) -> Capabilities {
        self.granted
    }

    /// Handle one request, returning the events to send in response.
    pub fn handle_request<F, I>(
        &mut self,
        request: ServiceRequest,
        frames: &mut F,
        input: &mut I,
    ) -> Vec<BrokerEvent>
    where
        F: FrameSource,
        I: InputSink,
    {
        if !self.handshaken {
            return self.handle_handshake(request);
        }
        match request {
            // A second Hello after the handshake is a no-op, not a restart.
            ServiceRequest::Hello { .. } => Vec::new(),
            ServiceRequest::OpenCapture {
                token_id,
                grant: approval,
                requested,
                params,
            } => {
                // Either "issue me a capability" or "here is the one you
                // issued". Anything else is a service naming a capability it
                // was not given.
                if token_id != NO_GRANT && !self.authorised(token_id) {
                    return vec![BrokerEvent::CaptureError {
                        code: code::UNAUTHORISED,
                        message: "unknown session grant".into(),
                    }];
                }
                // The approval is checked on every OpenCapture, including one
                // that presents an already-issued capability: a re-open is a
                // fresh claim about what the peer may do, and a capability
                // whose approval has since expired must not keep working.
                let approved = match self.verify_approval(&approval) {
                    Ok(approved) => approved,
                    Err(message) => {
                        return vec![BrokerEvent::CaptureError {
                            code: code::UNAUTHORISED,
                            message,
                        }];
                    }
                };
                // One connection serves one approved session. A second
                // approval naming a different session on the same connection
                // would let a service collect capabilities across approvals.
                if let Some(existing) = &self.session_id
                    && existing != &approved.session_id
                {
                    return vec![BrokerEvent::CaptureError {
                        code: code::UNAUTHORISED,
                        message: "this connection is serving a different session".into(),
                    }];
                }
                self.session_id = Some(approved.session_id.clone());

                // Four ceilings, narrowest wins: what the operator allows on
                // this machine, what the seat can ever expose, what the
                // approval actually granted, and what the service asked for.
                let ceiling =
                    effective_grant(approved.capabilities, self.policy.ceiling, params.seat);
                let grant = match self.grant {
                    Some(existing) => existing,
                    None => {
                        let id = self.tokens.next_id();
                        if id == NO_GRANT {
                            return vec![BrokerEvent::CaptureError {
                                code: code::UNAUTHORISED,
                                message: "could not issue a session grant".into(),
                            }];
                        }
                        let issued = SessionToken::grant(id, requested, ceiling);
                        self.grant = Some(issued);
                        issued
                    }
                };
                self.requested = requested;
                self.approved_capabilities = approved.capabilities;
                self.seat = params.seat;
                self.granted = requested.clamped_to(ceiling);
                match frames.open(params) {
                    Ok(opened) => {
                        self.capturing = true;
                        vec![BrokerEvent::CaptureStarted {
                            token_id: grant.id(),
                            seat: params.seat,
                            kind: params.kind,
                            width: opened.width,
                            height: opened.height,
                            granted: self.granted,
                        }]
                    }
                    Err(failure) => {
                        self.capturing = false;
                        vec![BrokerEvent::CaptureError {
                            code: failure.code,
                            message: failure.message,
                        }]
                    }
                }
            }
            ServiceRequest::SwitchCapture {
                token_id,
                seat,
                kind,
            } => {
                if !self.authorised(token_id) {
                    return vec![BrokerEvent::CaptureError {
                        code: code::UNAUTHORISED,
                        message: "unknown session grant".into(),
                    }];
                }
                self.seat = seat;
                // Re-derive for the new seat: logging in can widen the grant,
                // logging out narrows it (dropping clipboard, say) at once.
                // The approval stays a ceiling across the switch -- a login
                // must not hand a session more than it was approved for.
                let ceiling =
                    effective_grant(self.approved_capabilities, self.policy.ceiling, seat);
                self.granted = self.requested.clamped_to(ceiling);
                match frames.switch(seat, kind) {
                    Ok(opened) => vec![BrokerEvent::CaptureStarted {
                        token_id,
                        seat,
                        kind,
                        width: opened.width,
                        height: opened.height,
                        granted: self.granted,
                    }],
                    Err(failure) => vec![BrokerEvent::CaptureError {
                        code: failure.code,
                        message: failure.message,
                    }],
                }
            }
            ServiceRequest::SetBitrate { kbps } => {
                frames.set_bitrate(kbps);
                Vec::new()
            }
            ServiceRequest::RequestKeyframe => {
                frames.request_keyframe();
                Vec::new()
            }
            ServiceRequest::CloseCapture => {
                frames.close();
                self.capturing = false;
                vec![BrokerEvent::Closed {
                    reason: code::CLOSED_ON_REQUEST,
                }]
            }
            ServiceRequest::Input { token_id, payload } => {
                // Injection is the request that actually moves the operator's
                // devices, so it is checked first and silently drops rather
                // than reporting: a caller probing ids should learn nothing
                // from the difference between a wrong id and an empty grant.
                if !self.authorised(token_id) {
                    return Vec::new();
                }
                // The sink re-checks each event against the grant; an empty
                // grant injects nothing.
                input.inject(&payload, self.granted);
                Vec::new()
            }
            ServiceRequest::Shutdown => {
                frames.close();
                self.capturing = false;
                self.done = true;
                Vec::new()
            }
        }
    }

    fn handle_handshake(&mut self, request: ServiceRequest) -> Vec<BrokerEvent> {
        match request {
            ServiceRequest::Hello { protocol } if protocol == PROTOCOL_VERSION => {
                self.handshaken = true;
                vec![BrokerEvent::Hello {
                    protocol: PROTOCOL_VERSION,
                    capabilities: self.policy.ceiling,
                }]
            }
            ServiceRequest::Hello { .. } => {
                self.done = true;
                vec![BrokerEvent::CaptureError {
                    code: code::PROTOCOL_VERSION,
                    message: "unsupported protocol version".to_string(),
                }]
            }
            _ => {
                self.done = true;
                vec![BrokerEvent::CaptureError {
                    code: code::PROTOCOL_VIOLATION,
                    message: "expected Hello before any other request".to_string(),
                }]
            }
        }
    }

    /// Drain every ready frame and rumble event from the devices while a capture
    /// is open, oldest first.
    pub fn pump<F, I>(&mut self, frames: &mut F, input: &mut I) -> Vec<BrokerEvent>
    where
        F: FrameSource,
        I: InputSink,
    {
        let mut events = Vec::new();
        if !self.capturing {
            return events;
        }
        while let Some(frame) = frames.next_frame() {
            events.push(BrokerEvent::Frame {
                sequence: frame.sequence,
                timestamp_us: frame.timestamp_us,
                keyframe: frame.keyframe,
                data: frame.data,
            });
        }
        while let Some(rumble) = input.take_rumble() {
            events.push(BrokerEvent::Rumble {
                device_id: rumble.device_id,
                strong: rumble.strong,
                weak: rumble.weak,
            });
        }
        events
    }
}

/// Serve one authenticated service connection to completion.
///
/// `peer` is the already-verified identity of the connected service (the caller
/// authorises it with [`peercred`](openstream_host_ipc::peercred) before calling
/// this); it is accepted here so the audit line and any per-peer policy have it.
/// The loop reads requests, runs them through a [`BrokerSession`], and writes the
/// resulting events, draining frames on the policy's poll tick in between.
///
/// # Errors
/// Returns an I/O error if the transport fails. A clean EOF (the service closed
/// the socket) returns `Ok(())`.
pub async fn serve_connection<R, W, F, I>(
    reader: &mut R,
    writer: &mut W,
    peer: PeerIdentity,
    policy: BrokerPolicy,
    authority: GrantAuthority,
    frames: &mut F,
    input: &mut I,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FrameSource,
    I: InputSink,
{
    let _ = peer;
    let mut session = BrokerSession::with_authority(policy, authority);
    let mut tick = tokio::time::interval(policy.frame_poll);
    loop {
        tokio::select! {
            request = recv_request(reader) => {
                let request = match request {
                    Ok(request) => request,
                    // A clean EOF is the service disconnecting, not an error.
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                };
                for event in session.handle_request(request, frames, input) {
                    send_event(writer, &event).await?;
                }
                if session.is_done() {
                    break;
                }
            }
            _ = tick.tick() => {
                for event in session.pump(frames, input) {
                    send_event(writer, &event).await?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::EncodedFrame;
    use crate::device::fakes::{FakeFrameSource, FakeInputSink};
    use openstream_host_ipc::lifecycle::CaptureKind;
    use openstream_host_ipc::protocol::CaptureParams;

    fn params(seat: Seat) -> CaptureParams {
        CaptureParams {
            seat,
            kind: CaptureKind::Scanout,
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 8_000,
        }
    }

    /// The id the test token source hands out, so a test can tell the grant
    /// the broker issued apart from one a caller invented.
    const TEST_GRANT: u128 = 0x5ec0_0de5_ec00_de5e_c00d_e5ec_00de;

    /// The enrolment secret the tests share with their pretend control plane.
    const TEST_KEY: &[u8] = b"the secret this machine shares with the control plane";
    const TEST_DEVICE: &str = "this-machine";
    /// A fixed "now" inside every test approval's window.
    const TEST_NOW_MS: u64 = 10_000;

    /// A token source with a known id.
    struct FixedToken(u128);

    impl TokenSource for FixedToken {
        fn next_id(&mut self) -> u128 {
            self.0
        }
    }

    fn authority() -> GrantAuthority {
        GrantAuthority::new(TEST_KEY.to_vec(), TEST_DEVICE.to_string())
    }

    /// An approval from the pretend control plane, for `capabilities`.
    fn approval(capabilities: Capabilities) -> SessionGrant {
        SessionGrant {
            session_id: "session-1".into(),
            requester_device_id: "the-peer".into(),
            target_device_id: TEST_DEVICE.into(),
            capabilities,
            issued_at_ms: 0,
            expires_at_ms: 60_000,
            nonce: 1,
        }
    }

    /// Encode an approval as the machine service would relay it.
    fn relayed(grant: &SessionGrant) -> Vec<u8> {
        grant.encode(TEST_KEY)
    }

    /// An approval valid around the real clock.
    ///
    /// `serve_connection` builds its own session and therefore uses the system
    /// clock, not the fixed one the unit tests inject, so an approval written
    /// in small absolute numbers is already decades expired there.
    fn approval_now(capabilities: Capabilities) -> SessionGrant {
        let now = system_now_ms();
        SessionGrant {
            issued_at_ms: now.saturating_sub(60_000),
            expires_at_ms: now.saturating_add(60_000),
            ..approval(capabilities)
        }
    }

    /// A policy that allows everything, so the seat and the approval are what
    /// the tests observe. The *default* policy allows nothing; that is covered
    /// on its own in `a_default_policy_grants_nothing`.
    fn permissive() -> BrokerPolicy {
        BrokerPolicy {
            ceiling: Capabilities::all(),
            ..BrokerPolicy::default()
        }
    }

    fn session_with(policy: BrokerPolicy, authority: GrantAuthority) -> BrokerSession {
        BrokerSession::with_parts(
            policy,
            authority,
            Box::new(FixedToken(TEST_GRANT)),
            Box::new(|| TEST_NOW_MS),
        )
    }

    /// Open a capture under `grant` and return the capability the broker
    /// issued, or the events if it refused.
    fn open(
        session: &mut BrokerSession,
        frames: &mut FakeFrameSource,
        input: &mut FakeInputSink,
        grant: &SessionGrant,
        requested: Capabilities,
        seat: Seat,
    ) -> Vec<BrokerEvent> {
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(grant),
                requested,
                params: params(seat),
            },
            frames,
            input,
        )
    }

    /// Open a capture and return the issued capability id, failing the test if
    /// the broker refused.
    fn open_and_take_grant(
        session: &mut BrokerSession,
        frames: &mut FakeFrameSource,
        input: &mut FakeInputSink,
        requested: Capabilities,
        seat: Seat,
    ) -> u128 {
        let events = open(
            session,
            frames,
            input,
            &approval(Capabilities::all()),
            requested,
            seat,
        );
        match events.as_slice() {
            [BrokerEvent::CaptureStarted { token_id, .. }] => *token_id,
            other => panic!("expected CaptureStarted, got {other:?}"),
        }
    }

    fn handshaken() -> (BrokerSession, FakeFrameSource, FakeInputSink) {
        let mut session = session_with(permissive(), authority());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events = session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(events.as_slice(), [BrokerEvent::Hello { .. }]));
        (session, frames, input)
    }

    #[test]
    fn a_request_before_the_handshake_is_a_fatal_violation() {
        let mut session = BrokerSession::new(BrokerPolicy::default());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events =
            session.handle_request(ServiceRequest::RequestKeyframe, &mut frames, &mut input);
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError {
                code: code::PROTOCOL_VIOLATION,
                ..
            }]
        ));
        assert!(session.is_done());
    }

    #[test]
    fn a_version_mismatch_is_refused() {
        let mut session = BrokerSession::new(BrokerPolicy::default());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events = session.handle_request(
            ServiceRequest::Hello { protocol: 999 },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError {
                code: code::PROTOCOL_VERSION,
                ..
            }]
        ));
        assert!(session.is_done());
    }

    #[test]
    fn the_greeter_never_grants_clipboard_even_when_requested() {
        let (mut session, mut frames, mut input) = handshaken();
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                // Ask for everything.
                requested: Capabilities::all(),
                params: params(Seat::Greeter),
            },
            &mut frames,
            &mut input,
        );
        let granted = match events.as_slice() {
            [BrokerEvent::CaptureStarted { granted, .. }] => *granted,
            other => panic!("expected CaptureStarted, got {other:?}"),
        };
        // Keyboard and mouse for password entry; capture to see the screen.
        assert!(granted.contains(Capabilities::CAPTURE));
        assert!(granted.contains(Capabilities::KEYBOARD));
        assert!(granted.contains(Capabilities::MOUSE));
        // But nothing sensitive on the login screen.
        assert!(!granted.contains(Capabilities::CLIPBOARD));
        assert!(!granted.contains(Capabilities::GAMEPAD));
    }

    /// The gap the broker-issued capability left: asking for a fresh one.
    ///
    /// `token_id: NO_GRANT` used to be answered with a valid capability
    /// bounded only by the machine's static ceiling, with nothing in the
    /// exchange saying anyone had approved the session. Now an approval is
    /// required, and one nobody can vouch for is refused.
    #[test]
    fn a_session_with_no_approval_is_refused() {
        let (mut session, mut frames, mut input) = handshaken();
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: Vec::new(),
                requested: Capabilities::CAPTURE
                    .with(Capabilities::KEYBOARD)
                    .with(Capabilities::MOUSE),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
        assert!(frames.opened.is_empty(), "capture must not have opened");
    }

    /// An approval the machine service tagged itself. This is the case the
    /// whole mechanism exists for: the service holds no key, so it cannot
    /// produce a tag this broker accepts.
    #[test]
    fn an_approval_signed_with_another_key_is_refused() {
        let (mut session, mut frames, mut input) = handshaken();
        let forged = approval(Capabilities::all()).encode(b"the service's own guess");
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: forged,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
        assert!(frames.opened.is_empty());
    }

    /// A broker with no key configured refuses everything, rather than
    /// treating "I cannot check" as "it must be fine".
    #[test]
    fn an_unconfigured_authority_refuses_every_approval() {
        let mut session = session_with(permissive(), GrantAuthority::unconfigured());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &approval(Capabilities::all()),
            Capabilities::all(),
            Seat::User,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
    }

    /// The approval is a ceiling. A service that asks for more than was
    /// approved gets what was approved, even where the machine's own policy
    /// and the seat would allow more.
    #[test]
    fn a_session_cannot_exceed_what_was_approved() {
        let (mut session, mut frames, mut input) = handshaken();
        let approved = approval(Capabilities::CAPTURE.with(Capabilities::MOUSE));
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &approved,
            Capabilities::all(),
            Seat::User,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureStarted { .. }]
        ));
        assert_eq!(
            session.granted(),
            Capabilities::CAPTURE.with(Capabilities::MOUSE),
            "the approval must bound the session, not the machine policy alone"
        );
        assert!(!session.granted().contains(Capabilities::KEYBOARD));
    }

    /// Logging in widens the seat ceiling. It must not widen the approval:
    /// a session approved for capture only must not gain the keyboard because
    /// somebody logged in.
    #[test]
    fn logging_in_does_not_widen_a_session_past_its_approval() {
        let (mut session, mut frames, mut input) = handshaken();
        let approved = approval(Capabilities::CAPTURE);
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &approved,
            Capabilities::all(),
            Seat::Greeter,
        );
        let token = match events.as_slice() {
            [BrokerEvent::CaptureStarted { token_id, .. }] => *token_id,
            other => panic!("expected CaptureStarted, got {other:?}"),
        };
        session.handle_request(
            ServiceRequest::SwitchCapture {
                token_id: token,
                seat: Seat::User,
                kind: CaptureKind::Scanout,
            },
            &mut frames,
            &mut input,
        );
        assert_eq!(
            session.granted(),
            Capabilities::CAPTURE,
            "a login must not hand a session more than it was approved for"
        );
    }

    /// The same approval presented twice is a replay. A single grant cannot
    /// detect it; the broker remembers.
    #[test]
    fn the_same_approval_cannot_be_used_twice() {
        let (mut session, mut frames, mut input) = handshaken();
        let approved = approval(Capabilities::all());
        let first = open(
            &mut session,
            &mut frames,
            &mut input,
            &approved,
            Capabilities::all(),
            Seat::User,
        );
        assert!(matches!(
            first.as_slice(),
            [BrokerEvent::CaptureStarted { .. }]
        ));

        let replayed = open(
            &mut session,
            &mut frames,
            &mut input,
            &approved,
            Capabilities::all(),
            Seat::User,
        );
        assert!(
            matches!(
                replayed.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {replayed:?}"
        );
    }

    /// An approval whose window has passed is refused, so a capability cannot
    /// outlive the approval that produced it.
    #[test]
    fn an_expired_approval_is_refused() {
        let mut session = BrokerSession::with_parts(
            permissive(),
            authority(),
            Box::new(FixedToken(TEST_GRANT)),
            // Past the 60_000 ms every test approval expires at.
            Box::new(|| 120_000),
        );
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &approval(Capabilities::all()),
            Capabilities::all(),
            Seat::User,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
    }

    /// An approval for a different machine is refused, so an approval for one
    /// host in a fleet is not an approval for all of them.
    #[test]
    fn an_approval_for_another_device_is_refused() {
        let (mut session, mut frames, mut input) = handshaken();
        let elsewhere = SessionGrant {
            target_device_id: "some-other-machine".into(),
            ..approval(Capabilities::all())
        };
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &elsewhere,
            Capabilities::all(),
            Seat::User,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
    }

    /// One connection serves one approved session. A second approval naming a
    /// different session would let a service accumulate capabilities across
    /// approvals on a connection it already holds.
    #[test]
    fn a_second_session_cannot_be_opened_on_the_same_connection() {
        let (mut session, mut frames, mut input) = handshaken();
        open(
            &mut session,
            &mut frames,
            &mut input,
            &approval(Capabilities::CAPTURE),
            Capabilities::all(),
            Seat::User,
        );
        assert_eq!(session.approved_session(), Some("session-1"));

        let other = SessionGrant {
            session_id: "session-2".into(),
            nonce: 2,
            capabilities: Capabilities::all(),
            ..approval(Capabilities::all())
        };
        let events = open(
            &mut session,
            &mut frames,
            &mut input,
            &other,
            Capabilities::all(),
            Seat::User,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
        assert_eq!(session.granted(), Capabilities::CAPTURE);
    }

    /// The nonce set is bounded by the validity window, not by uptime: an
    /// entry is dropped once the approval it names could no longer be used.
    #[test]
    fn expired_nonces_are_forgotten() {
        let mut seen = SeenNonces::default();
        assert!(seen.accept(1, 1_000, 0));
        assert!(!seen.accept(1, 1_000, 500), "still inside its window");
        // Past the expiry, the entry is dropped -- and the same nonce is then
        // accepted again, which is safe because a grant carrying it would fail
        // its own expiry check first.
        assert!(seen.accept(1, 1_000, 2_000));
        assert_eq!(seen.entries.len(), 1);
    }

    /// The finding this whole change exists for: a service that names a grant
    /// the broker never issued gets nothing.
    ///
    /// Before this, `token_id` was discarded and the capability set came
    /// straight from the request, so a compromised network-facing service
    /// could ask the root broker for capture and input and be given them.
    #[test]
    fn a_grant_the_broker_did_not_issue_is_refused() {
        let (mut session, mut frames, mut input) = handshaken();
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                // Any value the service picked for itself. The old
                // machine-service built one from the clock and its pid.
                token_id: 0x0123_4567_89ab_cdef,
                grant: relayed(&approval(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
        assert!(frames.opened.is_empty(), "capture must not have opened");
    }

    /// Injection is the request that moves real devices, so it is checked
    /// against the grant and not merely against the capability set.
    #[test]
    fn input_under_a_forged_grant_injects_nothing() {
        let (mut session, mut frames, mut input) = handshaken();
        let grant = open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::User,
        );

        session.handle_request(
            ServiceRequest::Input {
                token_id: grant ^ 1,
                payload: vec![1, 2, 3],
            },
            &mut frames,
            &mut input,
        );
        assert!(
            input.injected.is_empty(),
            "a forged grant must inject nothing"
        );

        // The real grant still works, so the check is discriminating and not
        // simply breaking injection.
        session.handle_request(
            ServiceRequest::Input {
                token_id: grant,
                payload: vec![1, 2, 3],
            },
            &mut frames,
            &mut input,
        );
        assert_eq!(input.injected.len(), 1);
    }

    /// Re-pointing the capture is a capability-bearing request too: without
    /// this a forged switch could move a session onto a seat it was never
    /// granted.
    #[test]
    fn switching_seats_under_a_forged_grant_is_refused() {
        let (mut session, mut frames, mut input) = handshaken();
        open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::Greeter,
        );
        let events = session.handle_request(
            ServiceRequest::SwitchCapture {
                token_id: NO_GRANT,
                seat: Seat::User,
                kind: CaptureKind::Scanout,
            },
            &mut frames,
            &mut input,
        );
        assert!(
            matches!(
                events.as_slice(),
                [BrokerEvent::CaptureError {
                    code: code::UNAUTHORISED,
                    ..
                }]
            ),
            "got {events:?}"
        );
        assert!(frames.switched.is_empty());
    }

    /// A broker that has not been told what the operator allows has not been
    /// told it may hand out the keyboard.
    #[test]
    fn a_default_policy_grants_nothing() {
        assert_eq!(BrokerPolicy::default().ceiling, Capabilities::none());

        let mut session = session_with(BrokerPolicy::default(), authority());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        let grant = open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::User,
        );
        assert_eq!(grant, TEST_GRANT);
        assert_eq!(
            session.granted(),
            Capabilities::none(),
            "an unconfigured broker must grant nothing, even to a User seat"
        );
    }

    /// The operator's ceiling is read from the root broker's environment, so a
    /// mistyped capability must be refused rather than silently dropped: a
    /// ceiling the operator did not write is the bug, in either direction.
    #[test]
    fn the_configured_ceiling_parses_names_and_refuses_unknown_ones() {
        assert_eq!(parse_ceiling(""), Ok(Capabilities::none()));
        assert_eq!(parse_ceiling("  none "), Ok(Capabilities::none()));
        assert_eq!(parse_ceiling("all"), Ok(Capabilities::all()));
        assert_eq!(
            parse_ceiling("capture, keyboard ,mouse"),
            Ok(Capabilities::CAPTURE
                .with(Capabilities::KEYBOARD)
                .with(Capabilities::MOUSE))
        );
        assert!(parse_ceiling("capture,keybaord").is_err());
        assert!(parse_ceiling("everything").is_err());
    }

    /// The service may ask for less than the ceiling, never more.
    #[test]
    fn a_request_can_only_narrow_the_operators_ceiling() {
        let policy = BrokerPolicy {
            ceiling: Capabilities::CAPTURE.with(Capabilities::KEYBOARD),
            ..BrokerPolicy::default()
        };
        let mut session = session_with(policy, authority());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::User,
        );
        assert_eq!(
            session.granted(),
            Capabilities::CAPTURE.with(Capabilities::KEYBOARD),
            "asking for everything must not exceed the operator's ceiling"
        );
    }

    #[test]
    fn a_user_session_grants_what_was_requested() {
        let (mut session, mut frames, mut input) = handshaken();
        let requested = Capabilities::CAPTURE
            .with(Capabilities::KEYBOARD)
            .with(Capabilities::CLIPBOARD);
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                requested,
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        let granted = match events.as_slice() {
            [BrokerEvent::CaptureStarted { granted, .. }] => *granted,
            other => panic!("expected CaptureStarted, got {other:?}"),
        };
        assert!(granted.contains(Capabilities::CLIPBOARD));
        assert_eq!(granted, requested);
        assert_eq!(frames.opened.len(), 1);
    }

    #[test]
    fn logging_out_to_the_greeter_contracts_the_grant() {
        let (mut session, mut frames, mut input) = handshaken();
        let grant = open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::User,
        );
        assert!(session.granted().contains(Capabilities::CLIPBOARD));

        // The user logs out: the seat switches back to the greeter.
        let events = session.handle_request(
            ServiceRequest::SwitchCapture {
                token_id: grant,
                seat: Seat::Greeter,
                kind: CaptureKind::Scanout,
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureStarted { .. }]
        ));
        assert!(
            !session.granted().contains(Capabilities::CLIPBOARD),
            "clipboard must be dropped when falling back to the greeter"
        );
        assert_eq!(frames.switched, vec![(Seat::Greeter, CaptureKind::Scanout)]);
    }

    #[test]
    fn input_is_injected_with_the_current_grant() {
        let (mut session, mut frames, mut input) = handshaken();
        let grant = open_and_take_grant(
            &mut session,
            &mut frames,
            &mut input,
            Capabilities::all(),
            Seat::Greeter,
        );
        session.handle_request(
            ServiceRequest::Input {
                token_id: grant,
                payload: vec![9, 9, 9],
            },
            &mut frames,
            &mut input,
        );
        assert_eq!(input.injected.len(), 1);
        let (payload, granted) = &input.injected[0];
        assert_eq!(payload, &vec![9, 9, 9]);
        // The grant handed to the sink is the greeter-clamped one.
        assert!(!granted.contains(Capabilities::CLIPBOARD));
        assert!(granted.contains(Capabilities::KEYBOARD));
    }

    #[test]
    fn pump_drains_frames_then_rumble_in_order() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        frames.queued.push_back(EncodedFrame {
            sequence: 0,
            timestamp_us: 0,
            keyframe: true,
            data: vec![1],
        });
        frames.queued.push_back(EncodedFrame {
            sequence: 1,
            timestamp_us: 16_000,
            keyframe: false,
            data: vec![2],
        });
        input.rumble.push_back(crate::device::RumbleOut {
            device_id: 0,
            strong: 100,
            weak: 5,
        });

        let events = session.pump(&mut frames, &mut input);
        assert!(matches!(
            events.as_slice(),
            [
                BrokerEvent::Frame {
                    sequence: 0,
                    keyframe: true,
                    ..
                },
                BrokerEvent::Frame {
                    sequence: 1,
                    keyframe: false,
                    ..
                },
                BrokerEvent::Rumble { device_id: 0, .. },
            ]
        ));
    }

    #[test]
    fn a_failed_open_reports_the_error_and_does_not_capture() {
        let (mut session, mut frames, mut input) = handshaken();
        frames.fail_open = Some(crate::device::CaptureFailure::new(2, "encoder unavailable"));
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError { code: 2, .. }]
        ));
        // With nothing capturing, a pump yields nothing.
        assert!(session.pump(&mut frames, &mut input).is_empty());
    }

    #[test]
    fn close_and_shutdown_stop_capture() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );

        let events = session.handle_request(ServiceRequest::CloseCapture, &mut frames, &mut input);
        assert!(matches!(events.as_slice(), [BrokerEvent::Closed { .. }]));
        assert_eq!(frames.closes, 1);
        assert!(session.pump(&mut frames, &mut input).is_empty());

        // Re-open, then shut the whole connection down.
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        session.handle_request(ServiceRequest::Shutdown, &mut frames, &mut input);
        assert!(session.is_done());
        assert_eq!(frames.closes, 2);
    }

    #[test]
    fn set_bitrate_and_keyframe_reach_the_source() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::SetBitrate { kbps: 3_500 },
            &mut frames,
            &mut input,
        );
        session.handle_request(ServiceRequest::RequestKeyframe, &mut frames, &mut input);
        assert_eq!(frames.bitrates, vec![3_500]);
        assert_eq!(frames.keyframes, 1);
    }

    #[tokio::test]
    async fn serve_connection_runs_a_handshake_and_streams_a_frame() {
        use openstream_host_ipc::transport::{recv_event, send_request};

        let (mut service, broker_stream) = tokio::io::duplex(64 * 1024);
        let mut frames = FakeFrameSource::default();
        frames.queued.push_back(EncodedFrame {
            sequence: 7,
            timestamp_us: 1_000,
            keyframe: true,
            data: vec![0, 0, 0, 1, 0x65],
        });
        let mut input = FakeInputSink::default();
        let peer = PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4242,
        };

        // Run the broker over its half of the pipe.
        let broker = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(broker_stream);
            let policy = BrokerPolicy {
                ceiling: Capabilities::all(),
                frame_poll: Duration::from_millis(1),
            };
            serve_connection(
                &mut reader,
                &mut writer,
                peer,
                policy,
                authority(),
                &mut frames,
                &mut input,
            )
            .await
            .unwrap();
        });

        // Drive it from the service side.
        send_request(
            &mut service,
            &ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::Hello { .. }
        ));

        send_request(
            &mut service,
            &ServiceRequest::OpenCapture {
                token_id: NO_GRANT,
                grant: relayed(&approval_now(Capabilities::all())),
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::CaptureStarted { .. }
        ));

        // The queued frame arrives on the next poll tick.
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::Frame {
                sequence: 7,
                keyframe: true,
                ..
            }
        ));

        // Shutting down ends the broker task cleanly.
        send_request(&mut service, &ServiceRequest::Shutdown)
            .await
            .unwrap();
        broker.await.unwrap();
    }
}
