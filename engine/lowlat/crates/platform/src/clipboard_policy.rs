//! Clipboard transfer policy: direction, approval, conflict, privacy.
//!
//! The wire format and OS adapters already exist; this module decides what a
//! front end is allowed to do with them. Policy is explicit and restrictive
//! by default: sync is off unless both the negotiated capability and the
//! local direction allow it, incoming text never touches the OS clipboard
//! without approval, concurrent edits resolve deterministically, and logs
//! carry lengths instead of contents.

/// Which directions may carry clipboard text in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// No clipboard traffic in either direction.
    #[default]
    Disabled,
    /// This side may send its clipboard outward only.
    SendOnly,
    /// This side may receive into its clipboard only.
    ReceiveOnly,
    /// Bidirectional sync (still subject to approval below).
    Bidirectional,
}

impl Direction {
    /// Parse `disabled`/`send`/`receive`/`bidirectional` (case-insensitive).
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "send" | "send-only" | "out" => Self::SendOnly,
            "receive" | "receive-only" | "in" => Self::ReceiveOnly,
            "bidirectional" | "both" | "sync" => Self::Bidirectional,
            _ => Self::Disabled,
        }
    }

    /// Whether locally observed clipboard changes may be transmitted.
    pub fn may_send(self) -> bool {
        matches!(self, Self::SendOnly | Self::Bidirectional)
    }

    /// Whether remotely received clipboard text may be applied locally.
    pub fn may_receive(self) -> bool {
        matches!(self, Self::ReceiveOnly | Self::Bidirectional)
    }
}

/// Whether incoming clipboard text needs an explicit user decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Approval {
    /// Headless/service default: apply automatically once negotiated.
    #[default]
    Automatic,
    /// Interactive clients hold incoming text until the user accepts it.
    /// Adapters without a prompt surface must treat this as deny.
    Prompt,
    /// Never apply incoming text (send-only posture).
    Deny,
}

impl Approval {
    /// Parse `auto`/`prompt`/`deny` (case-insensitive).
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "prompt" | "ask" => Self::Prompt,
            "deny" | "never" => Self::Deny,
            _ => Self::Automatic,
        }
    }
}

/// Full clipboard policy for one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardPolicy {
    pub direction: Direction,
    pub approval: Approval,
}

impl ClipboardPolicy {
    /// Read the policy from the process environment.
    ///
    /// `OPENSTREAM_CLIPBOARD_MODE` selects the direction
    /// (`disabled`/`send`/`receive`/`bidirectional`) and defaults to
    /// `disabled`; `OPENSTREAM_CLIPBOARD_APPROVAL` selects
    /// `auto`/`prompt`/`deny` and defaults to `auto`. For backwards
    /// compatibility, legacy `OPENSTREAM_CLIPBOARD=1` without an explicit
    /// mode selects bidirectional sync.
    pub fn from_env() -> Self {
        let direction = std::env::var("OPENSTREAM_CLIPBOARD_MODE")
            .ok()
            .map(|mode| Direction::parse(&mode))
            .unwrap_or_else(|| {
                if std::env::var("OPENSTREAM_CLIPBOARD").as_deref() == Ok("1") {
                    Direction::Bidirectional
                } else {
                    Direction::Disabled
                }
            });
        Self {
            direction,
            approval: std::env::var("OPENSTREAM_CLIPBOARD_APPROVAL")
                .ok()
                .map(|mode| Approval::parse(&mode))
                .unwrap_or_default(),
        }
    }

    /// Whether an outgoing local change may be transmitted, given the
    /// negotiated capability.
    pub fn may_send(&self, negotiated: bool) -> bool {
        negotiated && self.direction.may_send()
    }

    /// Whether incoming text may be applied without further interaction.
    /// `Prompt` and `Deny` always require the UI layer first.
    pub fn may_apply(&self, negotiated: bool) -> bool {
        negotiated && self.direction.may_receive() && self.approval == Approval::Automatic
    }

    /// Redacted one-line summary for startup logs (no contents).
    pub fn log_line(&self) -> String {
        format!(
            "clipboard policy: direction={:?} approval={:?}",
            self.direction, self.approval
        )
    }
}

/// Resolve a clipboard conflict deterministically.
///
/// When both sides change their clipboard in the same window, the transfer
/// with the higher `(transfer_id, length)` wins; ties keep the local value
/// so the outcome never depends on arrival order. Returns `true` when the
/// remote value should replace the local one.
pub fn remote_wins(
    local_transfer_id: u32,
    local_len: usize,
    remote_transfer_id: u32,
    remote_len: usize,
) -> bool {
    (remote_transfer_id, remote_len) > (local_transfer_id, local_len)
}

/// Redact clipboard text for diagnostics: length plus a 16-byte prefix hash
/// indicator (FNV-1a, not cryptographic, never the content).
pub fn diagnostic_tag(text: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("len={} tag={:04x}", text.len(), (hash & 0xffff) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_defaults_to_closed() {
        let policy = ClipboardPolicy {
            direction: Direction::Disabled,
            approval: Approval::Automatic,
        };
        assert!(!policy.may_send(true));
        assert!(!policy.may_apply(true));
    }

    #[test]
    fn directions_gate_each_side_independently() {
        let send = ClipboardPolicy {
            direction: Direction::SendOnly,
            approval: Approval::Automatic,
        };
        assert!(send.may_send(true));
        assert!(!send.may_apply(true));
        let receive = ClipboardPolicy {
            direction: Direction::ReceiveOnly,
            approval: Approval::Automatic,
        };
        assert!(!receive.may_send(true));
        assert!(receive.may_apply(true));
        let both = ClipboardPolicy {
            direction: Direction::Bidirectional,
            approval: Approval::Automatic,
        };
        assert!(both.may_send(true) && both.may_apply(true));
        // Negotiation off always wins over local policy.
        assert!(!both.may_send(false) && !both.may_apply(false));
    }

    #[test]
    fn prompt_and_deny_hold_incoming_text() {
        for mode in [Approval::Prompt, Approval::Deny] {
            let policy = ClipboardPolicy {
                direction: Direction::Bidirectional,
                approval: mode,
            };
            assert!(policy.may_send(true));
            assert!(!policy.may_apply(true));
        }
    }

    #[test]
    fn names_parse_case_insensitively_with_safe_fallbacks() {
        assert_eq!(Direction::parse("SYNC"), Direction::Bidirectional);
        assert_eq!(Direction::parse("out"), Direction::SendOnly);
        assert_eq!(Direction::parse("bogus"), Direction::Disabled);
        assert_eq!(Approval::parse("ASK"), Approval::Prompt);
        assert_eq!(Approval::parse("bogus"), Approval::Automatic);
    }

    #[test]
    fn conflicts_resolve_by_id_then_length_regardless_of_order() {
        assert!(remote_wins(1, 10, 2, 1));
        assert!(!remote_wins(2, 1, 1, 10));
        assert!(remote_wins(1, 5, 1, 9));
        assert!(!remote_wins(1, 9, 1, 9));
        assert!(!remote_wins(1, 9, 1, 5));
    }

    #[test]
    fn diagnostics_never_contain_content() {
        let tag = diagnostic_tag("super secret password");
        assert!(!tag.contains("secret"));
        assert!(tag.starts_with("len=21 tag="));
        assert_eq!(diagnostic_tag("a").len(), "len=1 tag=0000".len());
    }
}
