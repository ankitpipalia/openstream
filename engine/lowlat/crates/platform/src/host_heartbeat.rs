//! The frame-heartbeat contract between a host process and its supervisor.
//!
//! The host writes one short line to a file; the agent reads it and decides
//! whether the host is working. The two live in different processes and share
//! no other code, so the format is defined once here rather than twice by
//! convention.
//!
//! # Why the line carries a phase and not just a count
//!
//! A frame counter alone cannot answer the question the supervisor is asking.
//! A host that is up and waiting for someone to connect produces no frames,
//! and neither does a host whose capture has died -- the counter reads zero in
//! both cases. Treating the second as the general case means killing the
//! first, which is a persistent host being restarted for doing exactly what it
//! is supposed to do.
//!
//! The phase is the host saying which of those it is, so frame progress is
//! only ever required of a host that claims to be streaming.
//!
//! # Format
//!
//! ```text
//! streaming 8123
//! waiting-for-peer 0
//! ```
//!
//! A bare integer is accepted as a legacy heartbeat and read as `streaming`,
//! so an older host binary supervised by a newer agent keeps its previous
//! meaning instead of being misread as a phase it never reported.

/// What the host says it is currently doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostPhase {
    /// The process is up and has not yet reached the signaling server.
    #[default]
    Starting,
    /// Connected to signaling, waiting for a peer to arrive.
    ///
    /// This can last indefinitely and is not a fault. The establishment
    /// protocol deliberately allows a host to be started long before its
    /// client, so nothing here may be given a deadline.
    WaitingForPeer,
    /// A peer is present and the session is being established.
    Negotiating,
    /// Capture and encode are running. Only in this phase does a frame
    /// counter that stops advancing mean something is wrong.
    Streaming,
}

impl HostPhase {
    /// The token written to the heartbeat file.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::WaitingForPeer => "waiting-for-peer",
            Self::Negotiating => "negotiating",
            Self::Streaming => "streaming",
        }
    }

    /// Parse a token, or `None` if it is not one this agent understands.
    ///
    /// Unknown is deliberately not folded into a default: a host reporting a
    /// phase from a future version must not be silently read as `streaming`
    /// and held to a frame deadline it never agreed to.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "starting" => Some(Self::Starting),
            "waiting-for-peer" => Some(Self::WaitingForPeer),
            "negotiating" => Some(Self::Negotiating),
            "streaming" => Some(Self::Streaming),
            _ => None,
        }
    }

    /// Whether a stalled frame counter is a fault in this phase.
    #[must_use]
    pub const fn expects_frames(self) -> bool {
        matches!(self, Self::Streaming)
    }

    /// Compact form for an atomic, so the publisher thread can read the phase
    /// without a lock.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Starting => 0,
            Self::WaitingForPeer => 1,
            Self::Negotiating => 2,
            Self::Streaming => 3,
        }
    }

    /// Inverse of [`Self::as_u8`]. Anything else is [`Self::Starting`], which
    /// is the phase that promises least.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::WaitingForPeer,
            2 => Self::Negotiating,
            3 => Self::Streaming,
            _ => Self::Starting,
        }
    }
}

/// Render one heartbeat line, newline included.
#[must_use]
pub fn render(phase: HostPhase, frames: u64) -> String {
    format!("{} {frames}\n", phase.token())
}

/// Parse one heartbeat line.
///
/// `None` means the line is not a heartbeat this agent can act on. That is
/// different from a heartbeat reporting zero frames, and the caller must not
/// collapse the two: an unreadable line says nothing about the host, while
/// `waiting-for-peer 0` says something quite specific.
#[must_use]
pub fn parse(line: &str) -> Option<(HostPhase, u64)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    match line.split_once(char::is_whitespace) {
        Some((token, frames)) => {
            let phase = HostPhase::from_token(token)?;
            Some((phase, frames.trim().parse().ok()?))
        }
        // A bare count is the format this file used to have.
        None => line
            .parse()
            .ok()
            .map(|frames| (HostPhase::Streaming, frames)),
    }
}

#[cfg(test)]
mod tests {
    use super::{HostPhase, parse, render};

    #[test]
    fn every_phase_survives_a_round_trip() {
        for phase in [
            HostPhase::Starting,
            HostPhase::WaitingForPeer,
            HostPhase::Negotiating,
            HostPhase::Streaming,
        ] {
            let line = render(phase, 77);
            assert_eq!(parse(&line), Some((phase, 77)));
            assert_eq!(HostPhase::from_token(phase.token()), Some(phase));
            assert_eq!(HostPhase::from_u8(phase.as_u8()), phase);
        }
    }

    /// Only a streaming host owes anyone a frame.
    #[test]
    fn frames_are_expected_only_while_streaming() {
        assert!(HostPhase::Streaming.expects_frames());
        assert!(!HostPhase::Starting.expects_frames());
        assert!(!HostPhase::WaitingForPeer.expects_frames());
        assert!(!HostPhase::Negotiating.expects_frames());
    }

    /// An older host wrote a bare count and meant it was streaming.
    #[test]
    fn a_bare_count_is_read_as_the_legacy_streaming_heartbeat() {
        assert_eq!(parse("8123\n"), Some((HostPhase::Streaming, 8123)));
        assert_eq!(parse("0"), Some((HostPhase::Streaming, 0)));
    }

    /// Garbage is not a phase, and must not be read as one.
    #[test]
    fn unreadable_lines_are_rejected_rather_than_defaulted() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
        assert_eq!(parse("streaming"), None);
        assert_eq!(parse("streaming abc"), None);
        assert_eq!(parse("-1"), None);
        // A phase from a newer host must not be guessed at.
        assert_eq!(parse("encoder-stalled 5"), None);
    }
}
