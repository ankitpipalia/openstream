//! Per-session capability grants.
//!
//! Being the trusted service user (proven by [`crate::peercred`]) lets a process
//! talk to the broker at all; it does not decide what that process may do.
//! Each session carries a [`SessionToken`]: an unguessable id the **broker**
//! mints from the OS CSPRNG, plus the capabilities it granted after clamping to
//! its own operator-configured ceiling and the seat.
//!
//! The direction matters. The service asks; the broker decides and issues. A
//! service cannot mint a token, and the broker refuses any id it did not hand
//! out, so a compromised network-facing service cannot name a session it was
//! never granted or drive a device the operator did not allow.
//!
//! # What this does not yet prove
//!
//! The grant is *broker-issued*, which bounds a compromised service to the
//! operator's configured ceiling. It is not yet bound to a specific Secure
//! Connect approval: that needs a signed, expiry-bound grant from the control
//! plane, carrying the session id and the approved permissions, which the
//! broker verifies against a key pinned at enrolment. Until that exists, the
//! ceiling is the operator's standing policy for the machine, not a statement
//! about who was approved.
//!
//! Pure and side-effect-free: the random token id is supplied by the caller
//! (the broker generates it from the OS CSPRNG), so issuance and clamping are
//! fully unit-tested.

/// The reserved grant id meaning "no grant".
///
/// A service sends this to ask the broker to issue one. It is never a valid
/// grant, so a caller that stores it, or a failed entropy draw that returns it,
/// authorises nothing.
pub const NO_GRANT: u128 = 0;

/// A set of device capabilities, as an opaque bitset. Constructed from the
/// named capabilities rather than raw bits so an unknown wire bit cannot smuggle
/// in a capability this version does not model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u32);

impl Capabilities {
    /// Read the framebuffer (capture). Every session that streams needs it.
    pub const CAPTURE: Self = Self(1 << 0);
    /// Inject keyboard events.
    pub const KEYBOARD: Self = Self(1 << 1);
    /// Inject pointer motion, buttons and wheel.
    pub const MOUSE: Self = Self(1 << 2);
    /// Inject gamepad button/axis events and receive rumble.
    pub const GAMEPAD: Self = Self(1 << 3);
    /// Apply clipboard changes into the captured session.
    pub const CLIPBOARD: Self = Self(1 << 4);

    /// The bits this version defines; any bit outside this is dropped on the
    /// way in so a newer peer cannot assert a capability this broker does not
    /// understand.
    const KNOWN: u32 = (1 << 5) - 1;

    /// The empty set.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Every capability this version defines. A convenient policy ceiling for a
    /// fully trusted, post-login session.
    #[must_use]
    pub const fn all() -> Self {
        Self(Self::KNOWN)
    }

    /// Build from raw wire bits, dropping any bit this version does not define.
    #[must_use]
    pub fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::KNOWN)
    }

    /// The raw bits, for the wire.
    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether every capability in `needle` is present.
    #[must_use]
    pub fn contains(self, needle: Self) -> bool {
        self.0 & needle.0 == needle.0
    }

    /// The union of two sets.
    #[must_use]
    pub fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The intersection: the capabilities present in both. Used to clamp a
    /// request down to a policy ceiling.
    #[must_use]
    pub fn clamped_to(self, ceiling: Self) -> Self {
        Self(self.0 & ceiling.0)
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One peer session's capability grant: an unguessable id plus the capabilities
/// the broker actually granted (already clamped to policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionToken {
    id: u128,
    capabilities: Capabilities,
}

impl SessionToken {
    /// Grant a token for `requested` capabilities, clamped to the broker's
    /// `ceiling`. The `id` is a fresh random value the broker draws from the OS
    /// CSPRNG; passing it in keeps this pure and testable. A pre-login session
    /// is typically granted a bare `CAPTURE` ceiling (look, do not touch); a
    /// fully approved post-login session may be granted input too.
    #[must_use]
    pub fn grant(id: u128, requested: Capabilities, ceiling: Capabilities) -> Self {
        Self {
            id,
            capabilities: requested.clamped_to(ceiling),
        }
    }

    /// The token id, carried on the wire so the broker can match a presented
    /// token to the grant it issued.
    #[must_use]
    pub fn id(self) -> u128 {
        self.id
    }

    /// The granted capabilities.
    #[must_use]
    pub fn capabilities(self) -> Capabilities {
        self.capabilities
    }

    /// Whether this token permits a specific capability. The broker calls this
    /// before injecting any input drawn from the peer.
    #[must_use]
    pub fn allows(self, capability: Capabilities) -> bool {
        self.capabilities.contains(capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_wire_bits_are_dropped() {
        // Every bit set on the wire, including undefined ones, truncates to
        // exactly the known set -- bit 31 and friends must not survive.
        let caps = Capabilities::from_bits_truncate(0xFFFF_FFFF);
        assert_eq!(caps, Capabilities::all());
        assert_eq!(
            caps.bits() & (1 << 31),
            0,
            "an undefined high bit must not survive truncation"
        );
        // And an undefined bit on its own truncates to nothing.
        assert!(Capabilities::from_bits_truncate(1 << 31).is_empty());
    }

    #[test]
    fn a_grant_is_clamped_to_the_policy_ceiling() {
        // The peer asked for keyboard+mouse+gamepad, but the pre-login ceiling
        // is capture-only: the grant must come back capture-only.
        let requested = Capabilities::KEYBOARD
            .with(Capabilities::MOUSE)
            .with(Capabilities::GAMEPAD)
            .with(Capabilities::CAPTURE);
        let ceiling = Capabilities::CAPTURE;
        let token = SessionToken::grant(0x1234_5678, requested, ceiling);
        assert!(token.allows(Capabilities::CAPTURE));
        assert!(!token.allows(Capabilities::KEYBOARD));
        assert!(!token.allows(Capabilities::MOUSE));
        assert_eq!(token.capabilities(), Capabilities::CAPTURE);
    }

    #[test]
    fn a_full_post_login_grant_keeps_input() {
        let requested = Capabilities::CAPTURE
            .with(Capabilities::KEYBOARD)
            .with(Capabilities::MOUSE);
        let token = SessionToken::grant(9, requested, Capabilities::all());
        assert!(token.allows(Capabilities::KEYBOARD));
        assert!(token.allows(Capabilities::MOUSE));
        assert!(!token.allows(Capabilities::GAMEPAD));
    }

    #[test]
    fn contains_requires_every_bit() {
        let both = Capabilities::KEYBOARD.with(Capabilities::MOUSE);
        assert!(both.contains(Capabilities::KEYBOARD));
        assert!(both.contains(Capabilities::MOUSE));
        assert!(both.contains(both));
        assert!(!Capabilities::KEYBOARD.contains(both));
    }

    #[test]
    fn the_id_round_trips() {
        let token = SessionToken::grant(u128::MAX, Capabilities::all(), Capabilities::all());
        assert_eq!(token.id(), u128::MAX);
    }

    #[test]
    fn an_empty_ceiling_grants_nothing() {
        let token = SessionToken::grant(1, Capabilities::all(), Capabilities::none());
        assert!(token.capabilities().is_empty());
        assert!(!token.allows(Capabilities::CAPTURE));
    }
}
