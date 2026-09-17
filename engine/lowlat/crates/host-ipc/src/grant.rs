//! Authorisation the network-facing service cannot manufacture.
//!
//! [`crate::token`] fixed who *issues* a capability: the broker mints it, and
//! refuses any id it did not hand out. That bounds a compromised machine
//! service to the operator's standing ceiling, and no further -- it can still
//! ask for a fresh grant and be given one, because nothing in that exchange
//! says anyone approved this session.
//!
//! A [`SessionGrant`] is that missing statement. The control plane issues one
//! when a Secure Connect request is approved, and it names what was approved:
//! which session, who asked, which machine, what permissions, and for how long.
//! The privileged broker verifies it against a key pinned at enrolment before
//! it opens a device.
//!
//! # Why the service cannot forge one
//!
//! The tag is an HMAC over the grant's fields, keyed by a secret the machine
//! shares with the control plane. That secret lives in a file readable only by
//! the broker's user. The machine service runs as a different, unprivileged
//! user: it relays a grant it was given and cannot compute a tag for one it
//! made up.
//!
//! This is deliberately a shared secret rather than a public-key signature.
//! The verifier here is the root broker, which is already the most trusted
//! process on the machine, so its ability to compute a tag it could also verify
//! costs nothing -- and it keeps the dependency graph to `hmac` and `sha2`,
//! which the workspace already carries. A signature would matter if an
//! untrusted party had to verify, which is not this boundary.
//!
//! # What this module does not do
//!
//! It verifies one grant in isolation. Replay is not a property of a single
//! grant: the caller must remember the nonces it has accepted within the
//! validity window and refuse a repeat. [`SessionGrant::nonce`] is there for
//! that, and [`SessionGrant::expires_at_ms`] bounds how long the caller has to
//! remember it for.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::token::Capabilities;
use crate::wire::{Reader, Writer};

/// The tag length: a full HMAC-SHA256.
pub const TAG_LEN: usize = 32;

/// The wire tag for an encoded grant, so a grant cannot be confused with any
/// other message body this crate encodes.
const GRANT_TAG: u8 = 0xA1;

/// The domain string mixed into every tag.
///
/// Without it, a secret reused for anything else that HMACs caller-supplied
/// bytes could have its output replayed here as a grant. It costs nothing and
/// removes a whole class of cross-protocol confusion.
const DOMAIN: &[u8] = b"openstream/session-grant/v1";

/// One approved session, as the control plane described it.
///
/// Every field is part of the tag. Changing any of them invalidates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGrant {
    /// The approved session this grant is for.
    pub session_id: String,
    /// The device that asked to connect.
    pub requester_device_id: String,
    /// The device being connected to. The broker refuses a grant addressed to
    /// a different machine, so one cannot be replayed across a fleet.
    pub target_device_id: String,
    /// What the approval allowed. A ceiling, not an instruction: the broker
    /// still clamps to its own policy and the seat.
    pub capabilities: Capabilities,
    /// When the control plane issued it, in milliseconds since the epoch.
    pub issued_at_ms: u64,
    /// When it stops being valid.
    pub expires_at_ms: u64,
    /// Unique per issuance, so the caller can refuse a replay.
    pub nonce: u128,
}

/// Why a grant was refused.
///
/// Each case names what failed. A caller should log which one and then treat
/// them identically: they all mean the session is not authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// The bytes were not a well-formed grant.
    Malformed,
    /// The tag did not match. The grant was altered, or was not issued by the
    /// holder of this machine's key.
    BadTag,
    /// `now` is past `expires_at_ms`.
    Expired,
    /// `now` is before `issued_at_ms`. A grant from the future is a clock
    /// disagreement or a fabrication; either way it is not usable.
    NotYetValid,
    /// `issued_at_ms` is after `expires_at_ms`, so the grant is valid for no
    /// instant at all.
    Inverted,
    /// The grant is addressed to a different machine.
    WrongDevice,
}

impl core::fmt::Display for GrantError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            Self::Malformed => "the grant was not well formed",
            Self::BadTag => "the grant's tag did not verify against this machine's key",
            Self::Expired => "the grant has expired",
            Self::NotYetValid => "the grant is not valid yet",
            Self::Inverted => "the grant expires before it was issued",
            Self::WrongDevice => "the grant is addressed to a different device",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for GrantError {}

impl SessionGrant {
    /// The bytes the tag is computed over: the domain string, then every
    /// field, each length-prefixed so two different grants cannot produce the
    /// same input.
    ///
    /// Length prefixing is the point. Concatenating `session_id` and
    /// `requester_device_id` without it would let `("ab", "c")` and
    /// `("a", "bc")` tag identically, and a grant for one session could be
    /// presented as a grant for another.
    fn signing_input(&self) -> Vec<u8> {
        let mut writer = Writer::tagged(GRANT_TAG);
        writer.bytes(DOMAIN);
        writer.bytes(self.session_id.as_bytes());
        writer.bytes(self.requester_device_id.as_bytes());
        writer.bytes(self.target_device_id.as_bytes());
        writer.u32(self.capabilities.bits());
        writer.u64(self.issued_at_ms);
        writer.u64(self.expires_at_ms);
        writer.u128(self.nonce);
        writer.finish()
    }

    /// Compute this grant's tag under `key`.
    ///
    /// The control plane calls this to issue; the broker calls it through
    /// [`verify`](Self::verify) to check. Exposed so the issuing side, when it
    /// exists, cannot drift from the verifying side by reimplementing it.
    #[must_use]
    pub fn tag(&self, key: &[u8]) -> [u8; TAG_LEN] {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
        mac.update(&self.signing_input());
        mac.finalize().into_bytes().into()
    }

    /// Encode the grant and its tag for transport.
    #[must_use]
    pub fn encode(&self, key: &[u8]) -> Vec<u8> {
        let mut writer = Writer::tagged(GRANT_TAG);
        writer.bytes(self.session_id.as_bytes());
        writer.bytes(self.requester_device_id.as_bytes());
        writer.bytes(self.target_device_id.as_bytes());
        writer.u32(self.capabilities.bits());
        writer.u64(self.issued_at_ms);
        writer.u64(self.expires_at_ms);
        writer.u128(self.nonce);
        writer.bytes(&self.tag(key));
        writer.finish()
    }

    /// Decode and verify in one step.
    ///
    /// Returns the grant only when the tag verifies against `key`, `now_ms`
    /// falls inside its validity window, and it is addressed to
    /// `this_device_id`. There is no way to obtain the contents of an
    /// unverified grant from this module, so a caller cannot accidentally act
    /// on fields it has not checked.
    ///
    /// The caller must still refuse a replayed [`nonce`](Self::nonce): this
    /// sees one grant and cannot know it has seen it before.
    pub fn decode_and_verify(
        bytes: &[u8],
        key: &[u8],
        now_ms: u64,
        this_device_id: &str,
    ) -> Result<Self, GrantError> {
        let mut reader = Reader::new(bytes);
        if reader.tag().map_err(|_| GrantError::Malformed)? != GRANT_TAG {
            return Err(GrantError::Malformed);
        }
        let grant = Self {
            session_id: read_string(&mut reader)?,
            requester_device_id: read_string(&mut reader)?,
            target_device_id: read_string(&mut reader)?,
            capabilities: Capabilities::from_bits_truncate(
                reader.u32().map_err(|_| GrantError::Malformed)?,
            ),
            issued_at_ms: reader.u64().map_err(|_| GrantError::Malformed)?,
            expires_at_ms: reader.u64().map_err(|_| GrantError::Malformed)?,
            nonce: reader.u128().map_err(|_| GrantError::Malformed)?,
        };
        let presented = reader.bytes().map_err(|_| GrantError::Malformed)?;
        reader.finish().map_err(|_| GrantError::Malformed)?;
        if presented.len() != TAG_LEN {
            return Err(GrantError::Malformed);
        }

        // The tag first, before any field is trusted enough to compare.
        let expected = grant.tag(key);
        if !constant_time_eq(presented, &expected) {
            return Err(GrantError::BadTag);
        }
        if grant.issued_at_ms > grant.expires_at_ms {
            return Err(GrantError::Inverted);
        }
        if now_ms < grant.issued_at_ms {
            return Err(GrantError::NotYetValid);
        }
        if now_ms > grant.expires_at_ms {
            return Err(GrantError::Expired);
        }
        if grant.target_device_id != this_device_id {
            return Err(GrantError::WrongDevice);
        }
        Ok(grant)
    }
}

fn read_string(reader: &mut Reader<'_>) -> Result<String, GrantError> {
    let bytes = reader.bytes().map_err(|_| GrantError::Malformed)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| GrantError::Malformed)
}

/// Compare two tags without leaking where they first differ.
///
/// A byte-at-a-time comparison that returns early tells an attacker, by how
/// long it took, how much of a guessed tag was right -- which turns forging one
/// from an infeasible search into a per-byte one.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"an enrolment secret shared with the control plane";
    const DEVICE: &str = "device-target";

    fn grant() -> SessionGrant {
        SessionGrant {
            session_id: "session-1".into(),
            requester_device_id: "device-requester".into(),
            target_device_id: DEVICE.into(),
            capabilities: Capabilities::CAPTURE.with(Capabilities::KEYBOARD),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
            nonce: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
        }
    }

    #[test]
    fn a_grant_round_trips_and_verifies() {
        let original = grant();
        let bytes = original.encode(KEY);
        let decoded = SessionGrant::decode_and_verify(&bytes, KEY, 30_000, DEVICE)
            .expect("the grant should verify");
        assert_eq!(decoded, original);
    }

    /// The whole point: a different key cannot produce an acceptable tag.
    #[test]
    fn another_key_cannot_produce_an_acceptable_grant() {
        let bytes = grant().encode(b"the machine service's own guess");
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, 30_000, DEVICE),
            Err(GrantError::BadTag)
        );
    }

    /// Every field is covered by the tag, so none of them can be edited in
    /// transit. Capabilities matter most -- that is the field a compromised
    /// relay would want to widen.
    #[test]
    fn no_field_can_be_altered_without_breaking_the_tag() {
        let base = grant();
        let mutations: Vec<(&str, SessionGrant)> = vec![
            (
                "session",
                SessionGrant {
                    session_id: "session-2".into(),
                    ..base.clone()
                },
            ),
            (
                "requester",
                SessionGrant {
                    requester_device_id: "someone-else".into(),
                    ..base.clone()
                },
            ),
            (
                "target",
                SessionGrant {
                    target_device_id: "another-machine".into(),
                    ..base.clone()
                },
            ),
            (
                "capabilities",
                SessionGrant {
                    capabilities: Capabilities::all(),
                    ..base.clone()
                },
            ),
            (
                "issued",
                SessionGrant {
                    issued_at_ms: 0,
                    ..base.clone()
                },
            ),
            (
                "expires",
                SessionGrant {
                    expires_at_ms: u64::MAX,
                    ..base.clone()
                },
            ),
            (
                "nonce",
                SessionGrant {
                    nonce: 0,
                    ..base.clone()
                },
            ),
        ];
        let authentic = base.tag(KEY);
        for (field, mutated) in mutations {
            assert_ne!(
                mutated.tag(KEY),
                authentic,
                "{field} is not covered by the tag"
            );
            // And the altered grant, presented with the authentic tag, is
            // refused rather than accepted with the attacker's fields.
            let mut writer = Writer::tagged(GRANT_TAG);
            writer.bytes(mutated.session_id.as_bytes());
            writer.bytes(mutated.requester_device_id.as_bytes());
            writer.bytes(mutated.target_device_id.as_bytes());
            writer.u32(mutated.capabilities.bits());
            writer.u64(mutated.issued_at_ms);
            writer.u64(mutated.expires_at_ms);
            writer.u128(mutated.nonce);
            writer.bytes(&authentic);
            let forged = writer.finish();
            assert_eq!(
                SessionGrant::decode_and_verify(&forged, KEY, 30_000, DEVICE),
                Err(GrantError::BadTag),
                "{field} was accepted with someone else's tag"
            );
        }
    }

    /// Fields are length-prefixed so a boundary cannot be moved. Without that,
    /// a grant for session "ab" from "c" would tag the same as one for session
    /// "a" from "bc".
    #[test]
    fn a_field_boundary_cannot_be_moved() {
        let left = SessionGrant {
            session_id: "ab".into(),
            requester_device_id: "c".into(),
            ..grant()
        };
        let right = SessionGrant {
            session_id: "a".into(),
            requester_device_id: "bc".into(),
            ..grant()
        };
        assert_ne!(left.tag(KEY), right.tag(KEY));
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let bytes = grant().encode(KEY);
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, 61_001, DEVICE),
            Err(GrantError::Expired)
        );
        // And is accepted on the last millisecond it is valid for, so the
        // boundary is not off by one in the direction that denies a live
        // session.
        assert!(SessionGrant::decode_and_verify(&bytes, KEY, 61_000, DEVICE).is_ok());
    }

    #[test]
    fn a_grant_from_the_future_is_refused() {
        let bytes = grant().encode(KEY);
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, 999, DEVICE),
            Err(GrantError::NotYetValid)
        );
        assert!(SessionGrant::decode_and_verify(&bytes, KEY, 1_000, DEVICE).is_ok());
    }

    /// A window that ends before it starts is valid at no instant, and must be
    /// named as such rather than reported as "expired" or "not yet valid"
    /// depending on which side of it the clock happens to be.
    #[test]
    fn a_grant_that_expires_before_it_was_issued_is_refused() {
        let inverted = SessionGrant {
            issued_at_ms: 5_000,
            expires_at_ms: 1_000,
            ..grant()
        };
        let bytes = inverted.encode(KEY);
        for now in [0, 3_000, 9_000] {
            assert_eq!(
                SessionGrant::decode_and_verify(&bytes, KEY, now, DEVICE),
                Err(GrantError::Inverted)
            );
        }
    }

    /// A grant issued for one machine must not open devices on another, or an
    /// approval for any host in a fleet is an approval for all of them.
    #[test]
    fn a_grant_for_another_device_is_refused() {
        let bytes = grant().encode(KEY);
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, 30_000, "some-other-machine"),
            Err(GrantError::WrongDevice)
        );
    }

    /// The tag is checked before the device and the clock, so a grant that
    /// fails several ways reports the tag. A caller that logged "expired" for
    /// an unsigned grant would send someone hunting a clock problem.
    #[test]
    fn a_bad_tag_is_reported_ahead_of_the_other_failures() {
        let bytes = grant().encode(b"wrong key");
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, u64::MAX, "another-machine"),
            Err(GrantError::BadTag)
        );
    }

    #[test]
    fn truncated_and_empty_input_is_malformed_not_a_panic() {
        let bytes = grant().encode(KEY);
        assert_eq!(
            SessionGrant::decode_and_verify(&[], KEY, 30_000, DEVICE),
            Err(GrantError::Malformed)
        );
        for cut in [1, 5, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(
                SessionGrant::decode_and_verify(&bytes[..cut], KEY, 30_000, DEVICE),
                Err(GrantError::Malformed),
                "a grant truncated to {cut} bytes should be malformed"
            );
        }
    }

    /// Trailing bytes are refused rather than ignored: a decoder that stops at
    /// the last field it wants lets an attacker append whatever it likes to a
    /// grant that verifies.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = grant().encode(KEY);
        bytes.push(0);
        assert_eq!(
            SessionGrant::decode_and_verify(&bytes, KEY, 30_000, DEVICE),
            Err(GrantError::Malformed)
        );
    }

    /// The domain separator is part of the tag, so a MAC computed over the same
    /// fields for another purpose cannot be presented as a grant.
    #[test]
    fn the_tag_is_domain_separated() {
        let base = grant();
        let mut without_domain = <Hmac<Sha256>>::new_from_slice(KEY).expect("key");
        let mut writer = Writer::tagged(GRANT_TAG);
        writer.bytes(base.session_id.as_bytes());
        writer.bytes(base.requester_device_id.as_bytes());
        writer.bytes(base.target_device_id.as_bytes());
        writer.u32(base.capabilities.bits());
        writer.u64(base.issued_at_ms);
        writer.u64(base.expires_at_ms);
        writer.u128(base.nonce);
        without_domain.update(&writer.finish());
        let undomained: [u8; TAG_LEN] = without_domain.finalize().into_bytes().into();
        assert_ne!(undomained, base.tag(KEY));
    }

    #[test]
    fn tags_of_different_lengths_are_not_equal() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }
}
