//! The account control plane, for a process holding a device-bound token.
//!
//! `device_auth` obtains the token; this is what a machine can then do with
//! it. Presence, the Connect request queue, approval and the account's device
//! list, over the same small HTTP client the rest of this crate uses.
//!
//! **Why here rather than in the shell.** The desktop already speaks every one
//! of these endpoints, through a `reqwest` client inside `desktop/src-tauri`.
//! A Tauri application cannot be a dependency of a headless service, so a
//! second implementation was going to exist either way; putting it in the
//! crate below both means the second one is the shared one, and the shell can
//! delete its copy rather than the two drifting. The wire types here are
//! deliberately field-for-field the shell's.
//!
//! One error type for the whole family, rather than one per endpoint. A caller
//! driving a control loop handles "the request did not arrive", "it was
//! refused" and "the answer was not what it claims to be" the same way
//! whichever endpoint produced them.

use crate::enrolment::percent_encode_segment;
use crate::http::{self, HttpError};
use crate::{Pairing, Permissions, Role, RoleCredential};
use serde::{Deserialize, Serialize};

pub const PRESENCE_PATH: &str = "/v1/presence";
pub const CONNECT_PATH: &str = "/v1/connect";
pub const CONNECT_PENDING_PATH: &str = "/v1/connect/pending";
pub const DEVICES_PATH: &str = crate::enrolment::DEVICES_PATH;

/// Why a control-plane call did not produce what was asked for.
#[derive(Debug)]
pub enum ControlPlaneError {
    /// The request never reached the control plane, or its answer was unusable.
    Http(HttpError),
    /// The control plane answered with a status that is not success.
    ///
    /// `401` and `403` are the two a caller must tell apart: the first means
    /// the token is finished and a fresh one should be proved for, the second
    /// means this device is not permitted and proving again will not help.
    Rejected { status: u16, detail: String },
    /// The answer parsed but did not carry what the caller must have.
    Incomplete(&'static str),
    /// A credential for a role this caller cannot use.
    WrongRole(String),
}

impl ControlPlaneError {
    /// The token is spent or the device was revoked or removed: prove again.
    #[must_use]
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Rejected { status: 401, .. })
    }

    /// The control plane understood and refused. Proving again cannot change
    /// the answer, so a caller should wait rather than retry immediately.
    #[must_use]
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Rejected { status: 403, .. })
    }
}

impl std::fmt::Display for ControlPlaneError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Rejected { status, detail } => {
                write!(formatter, "the control plane refused ({status}): {detail}")
            }
            Self::Incomplete(detail) => write!(formatter, "the response {detail}"),
            Self::WrongRole(role) => {
                write!(formatter, "the credential is for the {role} role")
            }
        }
    }
}

impl std::error::Error for ControlPlaneError {}

impl From<HttpError> for ControlPlaneError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

/// Whether the owner has accepted a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrust {
    Pending,
    Trusted,
    Revoked,
}

/// One device on the account, as the control plane describes it.
///
/// A subset of what the service sends. Unknown fields are ignored rather than
/// refused, so a service that grows a field does not break a machine that has
/// not been updated.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicDevice {
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub platform: String,
    pub trust: DeviceTrust,
    /// Whether the service currently sees this device announcing presence.
    /// Advisory: the broker decides authoritatively when a session is asked
    /// for.
    #[serde(default)]
    pub online: bool,
}

/// A request this device is being asked to answer.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingConnectRequest {
    pub request_id: String,
    pub requester_device_id: String,
    pub expires_in_seconds: u64,
    /// What the requester asked for. Defaulted so a control plane predating
    /// permission negotiation parses, and an absent set is the empty one:
    /// a partial object can only narrow what is granted, never widen it.
    #[serde(default)]
    pub requested: Permissions,
}

/// One end of an approved session: a session and exactly one role token.
///
/// There is deliberately no shape here carrying both roles. The service will
/// not return both to one caller, and a type that could hold them would be the
/// first step towards asking it to.
#[derive(Clone, Deserialize, Serialize)]
pub struct ConnectCredential {
    pub session_id: String,
    pub role: String,
    pub token: String,
    pub websocket_path: String,
    #[serde(default)]
    pub relay_address: Option<String>,
    pub relay_ticket: String,
    /// What the host granted this session, or `None` from a control plane that
    /// predates permission negotiation. A present set is the runner's ceiling.
    #[serde(default)]
    pub permissions: Option<Permissions>,
    /// The control plane's signed statement that this session was approved,
    /// hex-encoded, for a host that runs behind a privileged broker.
    ///
    /// Carried, never inspected. This process cannot produce one and has no
    /// reason to read one: the broker verifies it against a key this process
    /// cannot read, which is exactly what makes it worth anything. `None` on
    /// the client's credential, which has no broker to present it to.
    #[serde(default)]
    pub session_grant: Option<String>,
}

/// Redacted by hand. `token` is a bearer credential for the session and
/// `session_grant` is a signed authorisation to drive a machine; neither
/// belongs in a log line, a panic message or a crash dump.
impl std::fmt::Debug for ConnectCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectCredential")
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .field("token", &"<redacted>")
            .field("websocket_path", &self.websocket_path)
            .field("relay_address", &self.relay_address)
            .field("relay_ticket", &"<redacted>")
            .field("permissions", &self.permissions)
            .field(
                "session_grant",
                &self.session_grant.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ConnectCredential {
    /// Turn a host approval into the pairing a session runner reads.
    ///
    /// Refuses any other role. A host that started a session from a client
    /// credential would fail later and less legibly, and the check costs one
    /// comparison.
    ///
    /// The shell has an identical conversion; this is the one to keep. A test
    /// that rebuilds the pairing by hand proves only that the test agrees with
    /// itself, which is the shape of the bug that once let negotiated
    /// permissions be parsed and thrown away, so the tests below assert on the
    /// fields that have been dropped before.
    pub fn into_host_pairing(self) -> Result<Pairing, ControlPlaneError> {
        if self.role != "host" {
            return Err(ControlPlaneError::WrongRole(self.role));
        }
        Ok(Pairing::from_role_credential(RoleCredential {
            session_id: self.session_id,
            role: Role::Host,
            token: self.token,
            websocket_path: self.websocket_path,
            // The service does not restate the session lifetime here; the
            // session's own expiry governs and the runner learns it from the
            // service.
            expires_in_seconds: 0,
            relay_address: self.relay_address,
            relay_ticket: Some(self.relay_ticket),
            turn: None,
            permissions: self.permissions,
            session_grant: self.session_grant,
        }))
    }
}

/// Tell the service this device is online and able to host.
///
/// A heartbeat, not a registration: presence lapses on its own, so a machine
/// that is switched off stops being offered rather than lingering in its
/// owner's list as connectable. The caller is responsible for repeating it
/// well inside the service's lifetime.
pub async fn announce_presence(origin: &str, access_token: &str) -> Result<(), ControlPlaneError> {
    let response = http::post_json(origin, PRESENCE_PATH, Some(access_token), b"").await?;
    expect_success(response)
}

/// Stop being offered as a host.
pub async fn withdraw_presence(origin: &str, access_token: &str) -> Result<(), ControlPlaneError> {
    let response = http::delete(origin, PRESENCE_PATH, Some(access_token)).await?;
    expect_success(response)
}

/// Requests this device is being asked to approve, oldest first.
pub async fn pending_connect_requests(
    origin: &str,
    access_token: &str,
) -> Result<Vec<PendingConnectRequest>, ControlPlaneError> {
    let response = http::get(origin, CONNECT_PENDING_PATH, Some(access_token)).await?;
    decode(response, "is not a list of pending requests")
}

/// Approve a request and receive this end's capability.
///
/// Safe to repeat. The service treats a second identical approval as the retry
/// it is and returns the same session, because approving is the only way a
/// host receives a credential and a lost response would otherwise strand it
/// outside its own session.
pub async fn approve_connect(
    origin: &str,
    access_token: &str,
    request_id: &str,
    granted: Permissions,
) -> Result<ConnectCredential, ControlPlaneError> {
    let body = serde_json::to_vec(&ApproveBody { granted })
        .map_err(|_| ControlPlaneError::Incomplete("could not be encoded"))?;
    let response = http::post_json(
        origin,
        &connect_action_path(request_id, "approve"),
        Some(access_token),
        &body,
    )
    .await?;
    decode(response, "is not a role credential")
}

/// Refuse a request.
pub async fn deny_connect(
    origin: &str,
    access_token: &str,
    request_id: &str,
) -> Result<(), ControlPlaneError> {
    let response = http::post_json(
        origin,
        &connect_action_path(request_id, "deny"),
        Some(access_token),
        b"",
    )
    .await?;
    expect_success(response)
}

/// The devices on this account.
///
/// A headless host needs this to decide whether the device asking for a
/// session is one its owner has accepted. The service checks that the *target*
/// is trusted; from this side that is the requester, and nobody else checks it.
pub async fn list_devices(
    origin: &str,
    access_token: &str,
) -> Result<Vec<PublicDevice>, ControlPlaneError> {
    let response = http::get(origin, DEVICES_PATH, Some(access_token)).await?;
    decode(response, "is not a device list")
}

#[derive(Serialize)]
struct ApproveBody {
    granted: Permissions,
}

/// `/v1/connect/{request_id}/{action}`, with the id encoded.
///
/// The id comes from the service rather than from a person, but it is still
/// data arriving over the network on its way into a URL, and the cost of
/// encoding it is nothing.
#[must_use]
fn connect_action_path(request_id: &str, action: &str) -> String {
    format!(
        "{CONNECT_PATH}/{}/{action}",
        percent_encode_segment(request_id)
    )
}

fn expect_success(response: http::Response) -> Result<(), ControlPlaneError> {
    if response.is_success() {
        return Ok(());
    }
    Err(ControlPlaneError::Rejected {
        status: response.status,
        detail: response.text(),
    })
}

fn decode<T: serde::de::DeserializeOwned>(
    response: http::Response,
    what: &'static str,
) -> Result<T, ControlPlaneError> {
    if !response.is_success() {
        return Err(ControlPlaneError::Rejected {
            status: response.status,
            detail: response.text(),
        });
    }
    serde_json::from_slice(&response.body).map_err(|_| ControlPlaneError::Incomplete(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what `connect_approve` sends, copied from the signal server's
    /// own test that pins the eight keys.
    fn host_credential_json() -> serde_json::Value {
        serde_json::json!({
            "session_id": "session-1",
            "role": "host",
            "token": "host-token",
            "websocket_path": "/v1/signal/session-1/host",
            "relay_address": "203.0.113.5:9000",
            "relay_ticket": "ticket-1",
            "permissions": { "view": true, "keyboard": true },
            "session_grant": "abcdef01"
        })
    }

    #[test]
    fn a_host_credential_parses_the_services_exact_shape() {
        let credential: ConnectCredential =
            serde_json::from_value(host_credential_json()).expect("parse");
        assert_eq!(credential.session_id, "session-1");
        assert_eq!(credential.role, "host");
        assert_eq!(credential.relay_ticket, "ticket-1");
        assert_eq!(
            credential.relay_address.as_deref(),
            Some("203.0.113.5:9000")
        );
        let permissions = credential.permissions.expect("a granted set");
        assert!(permissions.view && permissions.keyboard);
        assert!(
            !permissions.clipboard,
            "an absent class must read as denied, never as granted"
        );
        assert_eq!(credential.session_grant.as_deref(), Some("abcdef01"));
    }

    /// The grant and the negotiated set have both been dropped in a conversion
    /// like this before, and the session that followed ran unscoped or was
    /// refused by the broker with nothing to point at.
    #[test]
    fn a_host_credential_becomes_a_pairing_that_keeps_the_grant() {
        let credential: ConnectCredential =
            serde_json::from_value(host_credential_json()).expect("parse");
        let pairing = credential.into_host_pairing().expect("a host pairing");

        assert_eq!(pairing.session_id, "session-1");
        assert_eq!(
            pairing.session_grant.as_deref(),
            Some("abcdef01"),
            "the broker's approval must survive the conversion"
        );
        let permissions = pairing.permissions.expect("the negotiated set");
        assert!(permissions.view && permissions.keyboard);
        assert!(!permissions.clipboard);
        assert_eq!(
            pairing.token(Role::Host).expect("a host token"),
            "host-token",
            "the host's own token must be the one the runner uses"
        );
    }

    #[test]
    fn a_client_credential_is_refused_as_a_host_pairing() {
        let mut json = host_credential_json();
        json["role"] = serde_json::Value::String("client".into());
        let credential: ConnectCredential = serde_json::from_value(json).expect("parse");
        match credential.into_host_pairing() {
            Err(ControlPlaneError::WrongRole(role)) => assert_eq!(role, "client"),
            other => panic!("a client credential must not become a host pairing: {other:?}"),
        }
    }

    /// A control plane that predates permission negotiation, or a client
    /// credential, sends neither field.
    #[test]
    fn an_older_service_still_parses() {
        let credential: ConnectCredential = serde_json::from_value(serde_json::json!({
            "session_id": "session-2",
            "role": "host",
            "token": "t",
            "websocket_path": "/v1/signal/session-2/host",
            "relay_ticket": "ticket-2"
        }))
        .expect("parse");
        assert!(credential.permissions.is_none());
        assert!(credential.session_grant.is_none());
        assert!(credential.relay_address.is_none());
    }

    #[test]
    fn a_pending_request_without_a_requested_set_asks_for_nothing() {
        let request: PendingConnectRequest = serde_json::from_value(serde_json::json!({
            "request_id": "r1",
            "requester_device_id": "device-a",
            "expires_in_seconds": 120
        }))
        .expect("parse");
        assert!(
            request.requested.is_empty(),
            "an absent set must not read as everything granted"
        );
    }

    #[test]
    fn the_device_list_ignores_fields_it_does_not_know() {
        let devices: Vec<PublicDevice> = serde_json::from_value(serde_json::json!([{
            "device_id": "device-a",
            "name": "Studio",
            "platform": "linux",
            "trust": "trusted",
            "online": true,
            "enrolled_at_ms": 1,
            "last_seen_ms": 2,
            "public_key_fingerprint": "ff"
        }]))
        .expect("parse");
        assert_eq!(devices[0].trust, DeviceTrust::Trusted);
        assert!(devices[0].online);
    }

    #[test]
    fn device_trust_uses_the_services_spelling() {
        for (text, trust) in [
            ("pending", DeviceTrust::Pending),
            ("trusted", DeviceTrust::Trusted),
            ("revoked", DeviceTrust::Revoked),
        ] {
            let parsed: DeviceTrust =
                serde_json::from_value(serde_json::Value::String(text.into())).expect("parse");
            assert_eq!(parsed, trust);
            assert_eq!(serde_json::to_value(trust).expect("encode"), text);
        }
    }

    /// A bearer token in a log is a bearer token an attacker can read.
    #[test]
    fn a_credential_never_prints_its_token() {
        let credential: ConnectCredential =
            serde_json::from_value(host_credential_json()).expect("parse");
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("host-token"), "{rendered}");
        assert!(!rendered.contains("ticket-1"), "{rendered}");
        assert!(!rendered.contains("abcdef01"), "{rendered}");
        assert!(rendered.contains("session-1"), "{rendered}");
    }

    #[test]
    fn a_request_id_is_encoded_into_the_path() {
        assert_eq!(
            connect_action_path("r1", "approve"),
            "/v1/connect/r1/approve"
        );
        assert_eq!(
            connect_action_path("a/../b", "deny"),
            "/v1/connect/a%2F..%2Fb/deny",
            "a path separator in an id must not become one in the URL"
        );
    }

    #[test]
    fn the_two_statuses_a_control_loop_must_tell_apart() {
        let unauthorized = ControlPlaneError::Rejected {
            status: 401,
            detail: String::new(),
        };
        let forbidden = ControlPlaneError::Rejected {
            status: 403,
            detail: String::new(),
        };
        assert!(unauthorized.is_unauthorized() && !unauthorized.is_forbidden());
        assert!(forbidden.is_forbidden() && !forbidden.is_unauthorized());
    }
}
