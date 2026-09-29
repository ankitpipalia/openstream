//! Enrolling a machine with the control plane.
//!
//! This is the step that turns a machine into something the account owns: it
//! registers the device and receives, exactly once, the grant key the machine's
//! privileged broker uses to verify that a session was approved.
//!
//! The key is returned only on the enrolment that creates the device, and there
//! is deliberately no endpoint that reads it back -- a key retrievable with an
//! account credential would be obtainable by anything that had stolen one. So
//! the only correct thing to do with the value this returns is hand it straight
//! to the broker's provisioning path and forget it. [`Enrolment`] is built to
//! make that easy and the alternatives awkward: it does not implement `Clone`,
//! it redacts the key from its own `Debug`, and [`Enrolment::into_grant_key`]
//! consumes it.
//!
//! Enrolment is an *installation* step, not something the machine service does
//! on every start. Re-enrolling would mint a second device record for a machine
//! that already has one, and the account owner would see their fleet fill up
//! with duplicates of the same computer.

use crate::http::{self, HttpError};

/// Where enrolment is posted.
///
/// This must match the signal server's route table -- `POST /v1/devices` in
/// `signal-server/src/main.rs`. Nothing enforces that at compile time: the
/// crates share no types, and a wrong path is a 404 at runtime that looks
/// exactly like a control plane which does not support enrolment at all.
/// [`the_devices_path_is_the_route_the_server_registers`] is what holds it.
pub const DEVICES_PATH: &str = "/v1/devices";

/// Why enrolment did not produce a key.
#[derive(Debug)]
pub enum EnrolmentError {
    /// The request never reached the control plane, or its answer was unusable.
    Http(HttpError),
    /// The control plane answered with a status that is not success.
    Rejected { status: u16, detail: String },
    /// The answer parsed but did not carry what enrolment must produce.
    Incomplete(&'static str),
}

impl std::fmt::Display for EnrolmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Rejected { status, detail } => {
                write!(
                    formatter,
                    "the control plane refused enrolment ({status}): {detail}"
                )
            }
            Self::Incomplete(detail) => write!(formatter, "the enrolment response {detail}"),
        }
    }
}

impl std::error::Error for EnrolmentError {}

impl From<HttpError> for EnrolmentError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

/// What this machine tells the control plane about itself.
#[derive(Debug, Clone)]
pub struct MachineIdentity {
    /// The stable device id this machine will be known by.
    pub device_id: String,
    /// What the owner will see in their device list.
    pub name: String,
    /// `linux`, `windows`, `macos`.
    pub platform: String,
    /// The machine's public identity key, hex-encoded.
    pub public_key_hex: String,
}

/// A completed enrolment.
///
/// Deliberately not `Clone`: the grant key inside is a secret with exactly one
/// correct destination, and a type that copies itself invites a second copy to
/// end up somewhere it is not wanted.
pub struct Enrolment {
    /// The device id the control plane recorded.
    pub device_id: String,
    /// The account the device now belongs to.
    ///
    /// Needed to authenticate later: a device proof names the (account, device)
    /// pair it is good for, and this response is the only place the machine is
    /// told which account it joined.
    pub account_id: String,
    /// The grant key, hex-encoded. Present only on the enrolment that created
    /// the device; a machine that was already enrolled gets nothing here, and
    /// its key cannot be recovered -- it has to be un-enrolled and enrolled
    /// again.
    grant_key_hex: Option<String>,
}

impl Enrolment {
    /// Whether this enrolment carried a key to provision.
    #[must_use]
    pub fn has_grant_key(&self) -> bool {
        self.grant_key_hex.is_some()
    }

    /// Take the grant key, consuming the enrolment.
    ///
    /// Consuming rather than borrowing so there is one obvious place the secret
    /// goes and no way to keep reading it afterwards.
    #[must_use]
    pub fn into_grant_key(self) -> Option<String> {
        self.grant_key_hex
    }
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Enrolment")
            .field("device_id", &self.device_id)
            .field("account_id", &self.account_id)
            .field(
                "grant_key",
                &self.grant_key_hex.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Build the enrolment request body.
///
/// Separate from the call so the wire shape is testable without a server. It
/// has to match the control plane's `DeviceRegistrationRequest` field for
/// field; a rename on either side is a 422 at runtime and nothing at compile
/// time, which is exactly the sort of break a test should hold still.
#[must_use]
pub fn enrolment_body(identity: &MachineIdentity) -> Vec<u8> {
    let body = serde_json::json!({
        "device_id": identity.device_id,
        "name": identity.name,
        "platform": identity.platform,
        "public_key": identity.public_key_hex,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Read the device id and grant key out of an enrolment response.
///
/// Separate from the call for the same reason, and because the interesting
/// cases -- a device that already existed, so no key; a response missing the
/// device id -- are ones a live server will not produce on demand.
pub fn parse_enrolment(body: &[u8]) -> Result<Enrolment, EnrolmentError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| EnrolmentError::Incomplete("is not JSON"))?;
    let device_id = value
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(EnrolmentError::Incomplete("carries no device_id"))?
        .to_string();
    let account_id = value
        .get("account_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(EnrolmentError::Incomplete("carries no account_id"))?
        .to_string();
    let grant_key_hex = value
        .get("grant_key")
        .and_then(serde_json::Value::as_str)
        .filter(|key| !key.is_empty())
        .map(ToString::to_string);
    Ok(Enrolment {
        device_id,
        account_id,
        grant_key_hex,
    })
}

/// Enrol this machine and return its grant key.
///
/// `access_token` is the account holder's bearer token: enrolment is something
/// an owner does to their own machine, so it is authenticated as the owner and
/// not as the machine, which has no credential yet.
pub async fn enrol(
    origin: &str,
    access_token: &str,
    identity: &MachineIdentity,
) -> Result<Enrolment, EnrolmentError> {
    let body = enrolment_body(identity);
    let response = http::post_json(origin, DEVICES_PATH, Some(access_token), &body).await?;
    if !response.is_success() {
        return Err(EnrolmentError::Rejected {
            status: response.status,
            // Bounded: a hostile origin's error text should not become an
            // unbounded log line.
            detail: response.text().chars().take(500).collect(),
        });
    }
    parse_enrolment(&response.body)
}

/// Where a single device is addressed.
///
/// Built here rather than formatted at each call site so the one place that
/// has to match the server's route table is the one place [`DEVICES_PATH`]
/// already covers.
///
/// The id is percent-encoded, because it is not a path segment until it has
/// been. The control plane accepts any device id without control characters,
/// which leaves `/`, `?`, `#`, spaces and more -- and interpolating one of
/// those produces a different route, a query string, or a fragment. The id also
/// comes from `--device-id` on a command line, so `\r\n` in it would split the
/// request this client is building. Every one of those turns "remove the device
/// I just enrolled" into a request against something else.
#[must_use]
pub fn device_path(device_id: &str) -> String {
    format!("{DEVICES_PATH}/{}", percent_encode_segment(device_id))
}

/// Percent-encode one path segment.
///
/// Unreserved characters (RFC 3986: ALPHA / DIGIT / `-` / `.` / `_` / `~`) pass
/// through; everything else becomes `%XX`. Deliberately stricter than the
/// grammar allows -- sub-delims like `+` and `,` are legal in a segment but
/// encoding them costs nothing and removes a class of question. Hand-rolled
/// rather than pulling in a crate for fifteen lines.
#[must_use]
pub(crate) fn percent_encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Remove a device, destroying the grant key enrolment issued for it.
///
/// This exists because enrolment is not idempotent: the key is minted once,
/// and `POST /v1/devices` refuses an id it already holds. An installer that
/// received a key and then could not store it would otherwise leave a device
/// record that can never be provisioned and never be replaced.
///
/// So this is the undo. Call it when enrolment succeeded but storing the key
/// did not -- and only for a device this process just created, because for any
/// other device it is a device being deleted out from under whoever is using
/// it.
pub async fn remove(
    origin: &str,
    access_token: &str,
    device_id: &str,
) -> Result<(), EnrolmentError> {
    let response = http::delete(origin, &device_path(device_id), Some(access_token)).await?;
    if !response.is_success() {
        return Err(EnrolmentError::Rejected {
            status: response.status,
            detail: response.text().chars().take(500).collect(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> MachineIdentity {
        MachineIdentity {
            device_id: "device-abc".into(),
            name: "Studio".into(),
            platform: "linux".into(),
            public_key_hex: "aabb".into(),
        }
    }

    #[test]
    fn the_devices_path_is_the_route_the_server_registers() {
        // Pinned deliberately. An earlier version of this guessed
        // "/v1/account/devices" and enrolment failed with a 404 against the
        // live service -- indistinguishable, from here, from a deployment too
        // old to support enrolment.
        assert_eq!(DEVICES_PATH, "/v1/devices");
    }

    #[test]
    fn one_device_is_addressed_under_the_collection_that_created_it() {
        // `DELETE /v1/devices/{device_id}` in `signal-server/src/main.rs`. The
        // same no-compile-time-check problem as DEVICES_PATH, with a worse
        // failure: a 404 here is reported as "the device could not be removed"
        // during a rollback, which reads like the control plane refusing
        // rather than the client asking the wrong question.
        assert_eq!(device_path("device-abc"), "/v1/devices/device-abc");
    }

    #[test]
    fn a_device_id_is_encoded_before_it_becomes_a_path_segment() {
        // The control plane accepts any device id without control characters,
        // so every one of these is a real id someone can enrol -- and each one
        // interpolated raw addresses something other than the device.
        assert_eq!(
            device_path("a/b"),
            "/v1/devices/a%2Fb",
            "a slash silently becomes a different route"
        );
        assert_eq!(
            device_path("a?b"),
            "/v1/devices/a%3Fb",
            "a question mark turns the rest of the id into a query string"
        );
        assert_eq!(device_path("a#b"), "/v1/devices/a%23b");
        assert_eq!(device_path("my laptop"), "/v1/devices/my%20laptop");
        // The id reaches this from `--device-id` on a command line. A newline
        // in it would end the request line and let the rest be read as headers.
        assert_eq!(
            device_path("a\r\nX-Evil: 1"),
            "/v1/devices/a%0D%0AX-Evil%3A%201",
            "a device id must not be able to split the request"
        );
        // Unreserved characters are left alone, so the ordinary case stays
        // readable in a log.
        assert_eq!(
            device_path("Studio-01_a.b~c"),
            "/v1/devices/Studio-01_a.b~c"
        );
        // Non-ASCII is encoded per UTF-8 byte, which is what the server decodes.
        assert_eq!(device_path("caf\u{e9}"), "/v1/devices/caf%C3%A9");
    }

    #[test]
    fn the_request_body_matches_the_control_planes_field_names() {
        // These names are the contract. A rename on either side is a runtime
        // 422 and a compile-time nothing, so this test is the only thing
        // holding them together.
        let body: serde_json::Value =
            serde_json::from_slice(&enrolment_body(&identity())).expect("json");
        assert_eq!(body["device_id"], "device-abc");
        assert_eq!(body["name"], "Studio");
        assert_eq!(body["platform"], "linux");
        assert_eq!(body["public_key"], "aabb");
    }

    #[test]
    fn a_fresh_enrolment_yields_a_key() {
        let enrolment = parse_enrolment(
            br#"{"device_id":"device-abc","account_id":"acct-1","grant_key":"00ff"}"#,
        )
        .expect("parse");
        assert_eq!(enrolment.device_id, "device-abc");
        assert!(enrolment.has_grant_key());
        assert_eq!(enrolment.into_grant_key().as_deref(), Some("00ff"));
    }

    #[test]
    fn a_device_that_already_existed_yields_no_key() {
        // The control plane returns the key only on the enrolment that creates
        // the device. Treating a missing key as an error would make a
        // re-enrolment look like a transport failure; treating an empty one as
        // present would have the caller write an empty key file, which the
        // broker reports as unconfigured with no clue why.
        let enrolment =
            parse_enrolment(br#"{"device_id":"device-abc","account_id":"acct-1"}"#).expect("parse");
        assert!(!enrolment.has_grant_key());

        let empty =
            parse_enrolment(br#"{"device_id":"device-abc","account_id":"acct-1","grant_key":""}"#)
                .expect("parse");
        assert!(
            !empty.has_grant_key(),
            "an empty key is absent, not a key made of nothing"
        );
    }

    #[test]
    fn a_response_without_a_device_id_is_refused() {
        assert!(parse_enrolment(br#"{"grant_key":"00ff"}"#).is_err());
        assert!(parse_enrolment(b"not json").is_err());
    }

    #[test]
    fn the_key_never_reaches_a_debug_line() {
        // Enrolment output is the sort of thing that ends up in an installer
        // log. The key must not be in it.
        let enrolment = parse_enrolment(
            br#"{"device_id":"device-abc","account_id":"acct-1","grant_key":"c0ffee"}"#,
        )
        .expect("parse");
        let rendered = format!("{enrolment:?}");
        assert!(rendered.contains("device-abc"), "{rendered}");
        assert!(
            !rendered.contains("c0ffee"),
            "the grant key leaked into Debug: {rendered}"
        );
    }
}
