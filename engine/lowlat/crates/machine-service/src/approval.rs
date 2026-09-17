//! Where the session approval comes from, and where it must not come from.
//!
//! The control plane signs a grant when the owner approves a Secure Connect
//! request. The agent writes it into the pairing file it hands to this service,
//! and this service relays it to the broker without reading it: nothing here can
//! produce a grant or verify one, which is precisely what makes the broker's
//! check worth anything.
//!
//! This module is the seam where the grant is chosen. It is separate from the
//! Linux-only peer loop so it can be tested on any platform -- the rule it
//! encodes is a security rule, and a security rule that is only exercised on the
//! maintainer's least-available machine is one that rots.

/// Where a relayed approval came from, for the log line and for the tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalSource {
    /// The pairing file the agent wrote. The product path.
    Pairing,
    /// `OPENSTREAM_SESSION_APPROVAL`, the development override.
    Environment,
    /// Neither carried one. The broker will refuse the session, which is the
    /// intended posture rather than a fault.
    None,
}

/// Choose the approval to relay to the broker.
///
/// The pairing wins whenever it carries one. An environment variable must not
/// be able to substitute for a real approval on a machine that has one --
/// otherwise anything that can set this service's environment can choose which
/// approval the broker sees, and the grant stops being evidence that the owner
/// approved *this* session.
///
/// `None` from both is not an error. A broker with no approval refuses the
/// session, so the failure is closed either way, and reporting it here as a
/// hard error would stop the service before it could log why.
#[must_use]
pub fn select(pairing_grant: Option<&str>, environment_grant: Option<&str>) -> ApprovalSource {
    if pairing_grant.is_some_and(|grant| !grant.trim().is_empty()) {
        return ApprovalSource::Pairing;
    }
    if environment_grant.is_some_and(|grant| !grant.trim().is_empty()) {
        return ApprovalSource::Environment;
    }
    ApprovalSource::None
}

#[cfg(test)]
mod tests {
    use super::{ApprovalSource, select};

    #[test]
    fn the_pairing_grant_is_the_product_path() {
        assert_eq!(select(Some("ab01"), None), ApprovalSource::Pairing);
    }

    #[test]
    fn the_environment_cannot_override_a_real_approval() {
        // The point of the grant is that it names one approved session. If the
        // environment could displace the pairing's, then anything able to set
        // this service's environment -- a compromised unit file, an operator
        // debugging in a hurry -- would choose which approval the broker sees,
        // and the broker's check would be verifying a statement the attacker
        // picked.
        assert_eq!(
            select(Some("pairing"), Some("environment")),
            ApprovalSource::Pairing,
            "a pairing that carries a grant must win over the override"
        );
    }

    #[test]
    fn the_environment_is_used_only_when_the_pairing_carries_nothing() {
        assert_eq!(select(None, Some("ab01")), ApprovalSource::Environment);
        assert_eq!(select(Some(""), Some("ab01")), ApprovalSource::Environment);
        assert_eq!(
            select(Some("   "), Some("ab01")),
            ApprovalSource::Environment,
            "a whitespace-only grant is not a grant"
        );
    }

    #[test]
    fn no_approval_anywhere_is_reported_rather_than_invented() {
        assert_eq!(select(None, None), ApprovalSource::None);
        assert_eq!(select(Some(""), Some("")), ApprovalSource::None);
    }
}
