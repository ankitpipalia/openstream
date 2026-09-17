//! Signing in as a machine, with no account password anywhere near it.
//!
//! A host that runs unattended cannot hold an account credential. The machine
//! service faces the network, and a password sitting in it is an account
//! compromise waiting for a bug in everything else. But it still needs a
//! device-bound access token: `/v1/presence` and every connect endpoint refuse
//! a principal with no device, which is how a machine ends up enrolled,
//! trusted, and unable to say it is online.
//!
//! What the machine does hold is the private half of the identity key it
//! enrolled with, in the operating system's own custody. Proving possession of
//! that is enough to say "I am this device", and that is all these endpoints
//! need to know.
//!
//! The private key never leaves the machine. What crosses the wire is a
//! signature over a transcript the control plane can rebuild, and which is
//! bound to one device, one moment and one nonce -- see
//! [`openstream_protocol::device_auth_transcript`].

use openstream_protocol::IdentityKey;

use crate::http::{self, HttpError};

/// Where a device proves itself.
///
/// Must match the signal server's route table -- `POST /v1/auth/device`. The
/// same unenforced-at-compile-time contract as [`crate::enrolment::DEVICES_PATH`],
/// with the same consequence for getting it wrong: a 404 that looks exactly
/// like a control plane too old to support device authentication.
/// [`the_device_auth_path_is_the_route_the_server_registers`] is what holds it.
pub const DEVICE_AUTH_PATH: &str = "/v1/auth/device";

/// Why a device could not authenticate.
#[derive(Debug)]
pub enum DeviceAuthError {
    /// The request never reached the control plane, or its answer was unusable.
    Http(HttpError),
    /// The control plane refused the proof.
    ///
    /// Deliberately one variant. The service answers every failure the same
    /// way -- an unknown device, a wrong key, a stale proof and a replayed
    /// nonce are indistinguishable from outside -- so inventing finer
    /// variants here would describe guesses rather than answers.
    Rejected { status: u16, detail: String },
    /// The identity key could not sign.
    Identity(openstream_protocol::IdentityError),
    /// The answer parsed but carried no token.
    Incomplete(&'static str),
    /// The local clock or random source failed.
    Local(&'static str),
}

impl std::fmt::Display for DeviceAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Rejected { status, detail } => write!(
                formatter,
                "the control plane refused this device's identity proof ({status}): {detail}"
            ),
            Self::Identity(error) => write!(formatter, "the device identity key: {error}"),
            Self::Incomplete(detail) => write!(formatter, "the response {detail}"),
            Self::Local(detail) => write!(formatter, "{detail}"),
        }
    }
}

impl std::error::Error for DeviceAuthError {}

impl From<HttpError> for DeviceAuthError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

/// A device's credential, and how long it lasts.
///
/// Not `Clone`, and no `Debug` that prints the token: it is a bearer credential
/// for a device that can host, and the one place it belongs is the
/// `Authorization` header of the next request.
pub struct DeviceSession {
    access_token: String,
    /// Seconds the control plane said the access token is good for.
    pub access_expires_in_seconds: u64,
}

impl DeviceSession {
    /// The bearer token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// When to re-authenticate, as a fraction of the lifetime.
    ///
    /// Early enough that a request is never made with a token about to expire,
    /// and not so early that a service spends its life authenticating. A floor
    /// because a control plane that hands out very short tokens would otherwise
    /// have this spinning.
    #[must_use]
    pub fn refresh_after(&self) -> std::time::Duration {
        let seconds = (self.access_expires_in_seconds / 2).max(30);
        std::time::Duration::from_secs(seconds)
    }
}

impl std::fmt::Debug for DeviceSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSession")
            .field("access_token", &"<redacted>")
            .field("access_expires_in_seconds", &self.access_expires_in_seconds)
            .finish()
    }
}

/// Build the proof body for a device.
///
/// Separate from the call so the wire shape is testable without a server, and
/// because the interesting property -- that the signature verifies against the
/// transcript the control plane rebuilds -- can then be checked directly.
pub fn proof_body(
    device_id: &str,
    identity: &IdentityKey,
    issued_at_ms: u64,
    nonce: [u8; 16],
) -> Result<Vec<u8>, DeviceAuthError> {
    let signature = identity
        .sign_device_auth(device_id, issued_at_ms, nonce)
        .map_err(DeviceAuthError::Identity)?;
    let body = serde_json::json!({
        "device_id": device_id,
        "issued_at_ms": issued_at_ms,
        "nonce": hex::encode(nonce),
        "signature": hex::encode(signature),
    });
    Ok(serde_json::to_vec(&body).unwrap_or_default())
}

/// Read the access token out of an authentication response.
pub fn parse_session(body: &[u8]) -> Result<DeviceSession, DeviceAuthError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| DeviceAuthError::Incomplete("is not JSON"))?;
    let access_token = value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or(DeviceAuthError::Incomplete("carries no access_token"))?
        .to_string();
    let access_expires_in_seconds = value
        .get("access_expires_in_seconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    Ok(DeviceSession {
        access_token,
        access_expires_in_seconds,
    })
}

/// Prove this machine is `device_id` and take a device-bound access token.
///
/// Call it again when [`DeviceSession::refresh_after`] has elapsed. There is no
/// refresh-token dance here on purpose: the machine can always mint a fresh
/// proof from a key it already holds, so storing a second long-lived secret
/// would add a thing to lose and nothing to gain.
pub async fn authenticate(
    origin: &str,
    device_id: &str,
    identity: &IdentityKey,
) -> Result<DeviceSession, DeviceAuthError> {
    let issued_at_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| DeviceAuthError::Local("the system clock is before the epoch"))?
            .as_millis(),
    )
    .map_err(|_| DeviceAuthError::Local("the system clock is implausibly far ahead"))?;
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| DeviceAuthError::Local("the system random source failed"))?;

    let body = proof_body(device_id, identity, issued_at_ms, nonce)?;
    // No bearer: this request is how the caller obtains one.
    let response = http::post_json(origin, DEVICE_AUTH_PATH, None, &body).await?;
    if !response.is_success() {
        return Err(DeviceAuthError::Rejected {
            status: response.status,
            detail: response.text().chars().take(500).collect(),
        });
    }
    parse_session(&response.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_auth_path_is_the_route_the_server_registers() {
        assert_eq!(DEVICE_AUTH_PATH, "/v1/auth/device");
    }

    #[test]
    fn the_proof_verifies_against_the_transcript_the_server_rebuilds() {
        // The contract that matters, and the one nothing else checks: the
        // server does not see this body, it sees four fields and rebuilds the
        // transcript from them. If the client signed anything else -- a
        // different field order, a different encoding, the raw bytes instead of
        // the transcript -- every device would fail to authenticate and the
        // only symptom would be a 401.
        let identity = IdentityKey::generate().expect("identity");
        let nonce = [0x5a_u8; 16];
        let body = proof_body("machine-one", &identity, 1_700_000_000_000, nonce).expect("body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");

        assert_eq!(parsed["device_id"], "machine-one");
        assert_eq!(parsed["issued_at_ms"], 1_700_000_000_000_u64);
        assert_eq!(parsed["nonce"], hex::encode(nonce));

        let signature_hex = parsed["signature"].as_str().expect("signature");
        let signature = <[u8; 64]>::try_from(
            hex::decode(signature_hex)
                .expect("the signature is hex")
                .as_slice(),
        )
        .expect("an Ed25519 signature is 64 bytes");
        assert!(
            IdentityKey::verify_device_auth(
                identity.public_key(),
                signature,
                "machine-one",
                1_700_000_000_000,
                nonce
            ),
            "the signed transcript is not the one the control plane rebuilds"
        );
    }

    #[test]
    fn the_private_key_never_appears_in_the_proof() {
        // The whole point of using an identity key rather than a shared secret.
        let identity = IdentityKey::generate().expect("identity");
        let body = proof_body("machine-one", &identity, 1, [0; 16]).expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains(&hex::encode(identity.pkcs8())),
            "the private key material is in the request body"
        );
    }

    #[test]
    fn a_session_carries_the_token_and_a_refresh_deadline() {
        let session = parse_session(
            br#"{"access_token":"abc","access_expires_in_seconds":900,"refresh_token":"x"}"#,
        )
        .expect("parse");
        assert_eq!(session.access_token(), "abc");
        // Half of 900s, comfortably before expiry.
        assert_eq!(session.refresh_after(), std::time::Duration::from_secs(450));
    }

    #[test]
    fn a_very_short_lifetime_does_not_turn_into_a_spin() {
        let session = parse_session(br#"{"access_token":"abc","access_expires_in_seconds":2}"#)
            .expect("parse");
        assert_eq!(session.refresh_after(), std::time::Duration::from_secs(30));

        // A response with no lifetime at all lands on the same floor rather
        // than re-authenticating without pause.
        let unknown = parse_session(br#"{"access_token":"abc"}"#).expect("parse");
        assert_eq!(unknown.refresh_after(), std::time::Duration::from_secs(30));
    }

    #[test]
    fn a_response_without_a_token_is_refused_rather_than_used() {
        assert!(parse_session(br#"{"refresh_token":"x"}"#).is_err());
        assert!(parse_session(br#"{"access_token":""}"#).is_err());
        assert!(parse_session(b"not json").is_err());
    }

    #[test]
    fn the_token_never_reaches_a_debug_line() {
        let session = parse_session(br#"{"access_token":"c0ffee","access_expires_in_seconds":60}"#)
            .expect("parse");
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("c0ffee"), "the token leaked: {rendered}");
    }
}
