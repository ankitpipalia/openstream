//! Pure session-runtime policy shared by future native window backends.
//!
//! This module deliberately does not create a window or own a renderer.  It
//! defines the bounded lifecycle and input-safety seam that a winit/native
//! presenter can consume in a later change without changing the transport
//! protocol or introducing a new dependency here.

use std::collections::VecDeque;

/// Window presentation mode understood by a native session presenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum WindowMode {
    /// A resizable window at the negotiated stream size.
    #[default]
    Windowed,
    /// A borderless window that fills the available desktop area.
    Borderless,
    /// Native fullscreen requested from the window backend.
    Fullscreen,
}

impl WindowMode {
    /// Parse the persisted/user-facing value, falling back safely to windowed.
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "borderless" => Self::Borderless,
            "fullscreen" | "native-fullscreen" | "full" => Self::Fullscreen,
            _ => Self::Windowed,
        }
    }
}

/// Actions exposed by the session window's reserved hotkey set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyAction {
    Disconnect,
    ReleaseInput,
}

/// A parsed hotkey with only the modifiers needed by the session boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hotkey {
    pub(crate) action: HotkeyAction,
    pub(crate) ctrl: bool,
    pub(crate) alt: bool,
    pub(crate) shift: bool,
    pub(crate) key: &'static str,
}

/// Safety binding that can never be replaced by user hotkey configuration.
pub(crate) const RESERVED_RELEASE_INPUT: Hotkey = Hotkey {
    action: HotkeyAction::ReleaseInput,
    ctrl: true,
    alt: true,
    shift: false,
    key: "home",
};

/// Parsed hotkeys. The release-input binding is always present in this set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HotkeySet {
    hotkeys: Vec<Hotkey>,
}

impl HotkeySet {
    /// Parse `action=modifier+modifier+key` entries.
    ///
    /// Release-input entries supplied by the user are ignored: the reserved
    /// binding is inserted below so a malformed or over-eager customization
    /// cannot remove the last-resort input release action.
    pub(crate) fn parse(spec: &str) -> Self {
        let mut hotkeys = Vec::new();
        for entry in spec.split(',') {
            let Some((action_name, binding)) = entry.split_once('=') else {
                continue;
            };
            let Some(action) = parse_action(action_name) else {
                continue;
            };
            let Some(hotkey) = parse_hotkey(action, binding) else {
                continue;
            };
            if action != HotkeyAction::ReleaseInput && !hotkeys.contains(&hotkey) {
                hotkeys.push(hotkey);
            }
            if hotkeys.len() >= 8 {
                break;
            }
        }
        if !hotkeys
            .iter()
            .any(|hotkey| hotkey.action == HotkeyAction::ReleaseInput)
        {
            hotkeys.push(RESERVED_RELEASE_INPUT);
        }
        Self { hotkeys }
    }

    pub(crate) fn contains(&self, action: HotkeyAction) -> bool {
        self.hotkeys.iter().any(|hotkey| hotkey.action == action)
    }

    pub(crate) fn release_input(&self) -> Hotkey {
        self.hotkeys
            .iter()
            .find(|hotkey| hotkey.action == HotkeyAction::ReleaseInput)
            .copied()
            .unwrap_or(RESERVED_RELEASE_INPUT)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Hotkey> {
        self.hotkeys.iter()
    }
}

fn parse_action(value: &str) -> Option<HotkeyAction> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disconnect" | "quit" | "exit" => Some(HotkeyAction::Disconnect),
        "release" | "release-input" | "ungrab" => Some(HotkeyAction::ReleaseInput),
        _ => None,
    }
}

fn parse_hotkey(action: HotkeyAction, binding: &str) -> Option<Hotkey> {
    let mut ctrl = false;
    let mut alt = false;
    let mut shift = false;
    let mut key = None;
    for part in binding.split('+') {
        match part.trim().to_ascii_lowercase().as_str() {
            "ctrl" | "control" => ctrl = true,
            "alt" | "option" => alt = true,
            "shift" => shift = true,
            "" => {}
            value => key = parse_key(value),
        }
    }
    Some(Hotkey {
        action,
        ctrl,
        alt,
        shift,
        key: key?,
    })
}

fn parse_key(value: &str) -> Option<&'static str> {
    match value {
        "home" => Some("home"),
        "end" => Some("end"),
        "f1" => Some("f1"),
        "escape" | "esc" => Some("escape"),
        _ => None,
    }
}

/// Commands emitted to the future native window/session integration seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCommand {
    ReleaseInput,
    Stop,
}

/// Bounded lifecycle states for one desktop session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionError {
    InvalidTransition,
    QueueFull,
}

/// Small, synchronous session state machine for a native window runner.
///
/// Normal lifecycle commands are kept in a bounded queue. ReleaseInput has a
/// single reserved priority slot so focus-loss cleanup cannot be blocked by a
/// full normal queue; therefore `pending_len()` is bounded by
/// `queue_capacity + 1`.
#[derive(Debug)]
pub(crate) struct SessionRunner {
    state: SessionState,
    focused: bool,
    queue_capacity: usize,
    commands: VecDeque<SessionCommand>,
    release_pending: bool,
}

impl SessionRunner {
    pub(crate) fn new(queue_capacity: usize) -> Self {
        Self {
            state: SessionState::Idle,
            focused: true,
            queue_capacity: queue_capacity.max(1),
            commands: VecDeque::new(),
            release_pending: false,
        }
    }

    pub(crate) fn state(&self) -> SessionState {
        self.state
    }

    pub(crate) fn is_focused(&self) -> bool {
        self.focused
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.commands.len() + if self.release_pending { 1 } else { 0 }
    }

    pub(crate) fn start(&mut self) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Idle | SessionState::Stopped)
            || self.pending_len() != 0
        {
            return Err(SessionError::InvalidTransition);
        }
        self.state = SessionState::Starting;
        self.focused = true;
        Ok(())
    }

    pub(crate) fn mark_started(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Starting {
            return Err(SessionError::InvalidTransition);
        }
        self.state = SessionState::Running;
        Ok(())
    }

    pub(crate) fn request_stop(&mut self) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Starting | SessionState::Running) {
            return Err(SessionError::InvalidTransition);
        }
        self.enqueue(SessionCommand::Stop)?;
        self.state = SessionState::Stopping;
        Ok(())
    }

    pub(crate) fn mark_stopped(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Stopping {
            return Err(SessionError::InvalidTransition);
        }
        self.state = SessionState::Stopped;
        Ok(())
    }

    /// Update focus and reserve one ReleaseInput command on focus loss.
    ///
    /// Returns `true` only when this call added a new release command.
    pub(crate) fn set_focus(&mut self, focused: bool) -> bool {
        if self.focused == focused {
            return false;
        }
        self.focused = focused;
        if !focused && !matches!(self.state, SessionState::Idle | SessionState::Stopped) {
            let was_pending = self.release_pending;
            self.release_pending = true;
            return !was_pending;
        }
        false
    }

    pub(crate) fn enqueue(&mut self, command: SessionCommand) -> Result<(), SessionError> {
        if command == SessionCommand::ReleaseInput {
            self.release_pending = true;
            return Ok(());
        }
        if self.commands.len() >= self.queue_capacity {
            return Err(SessionError::QueueFull);
        }
        self.commands.push_back(command);
        Ok(())
    }

    pub(crate) fn pop_command(&mut self) -> Option<SessionCommand> {
        if self.release_pending {
            self.release_pending = false;
            Some(SessionCommand::ReleaseInput)
        } else {
            self.commands.pop_front()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_mode_parser_is_case_insensitive_and_safe() {
        assert_eq!(WindowMode::parse("windowed"), WindowMode::Windowed);
        assert_eq!(WindowMode::parse("BORDERLESS"), WindowMode::Borderless);
        assert_eq!(WindowMode::parse("fullscreen"), WindowMode::Fullscreen);
        assert_eq!(
            WindowMode::parse("native-fullscreen"),
            WindowMode::Fullscreen
        );
        assert_eq!(WindowMode::parse("unknown"), WindowMode::Windowed);
        assert_eq!(WindowMode::parse(""), WindowMode::Windowed);
    }

    #[test]
    fn release_input_hotkey_is_reserved_in_every_hotkey_set() {
        let hotkeys = HotkeySet::parse("disconnect=ctrl+alt+end");

        assert!(hotkeys.contains(HotkeyAction::Disconnect));
        assert_eq!(hotkeys.release_input(), RESERVED_RELEASE_INPUT);
        assert!(
            hotkeys
                .iter()
                .any(|hotkey| hotkey.action == HotkeyAction::ReleaseInput)
        );
    }

    #[test]
    fn user_hotkey_cannot_replace_reserved_release_input_binding() {
        let hotkeys = HotkeySet::parse("release=shift+f1");

        assert_eq!(hotkeys.release_input(), RESERVED_RELEASE_INPUT);
        assert!(
            !hotkeys.iter().any(|hotkey| {
                hotkey.action == HotkeyAction::ReleaseInput && hotkey.key == "f1"
            })
        );
    }

    #[test]
    fn focus_loss_enqueues_release_once() {
        let mut runner = SessionRunner::new(4);
        runner.start().unwrap();
        runner.mark_started().unwrap();

        assert!(runner.set_focus(false));
        assert!(!runner.set_focus(false));
        assert_eq!(runner.pending_len(), 1);
        assert_eq!(runner.pop_command(), Some(SessionCommand::ReleaseInput));
        assert_eq!(runner.pop_command(), None);
    }

    #[test]
    fn focus_regain_does_not_cancel_release() {
        let mut runner = SessionRunner::new(4);
        runner.start().unwrap();
        runner.mark_started().unwrap();

        runner.set_focus(false);
        runner.set_focus(true);

        assert_eq!(runner.pop_command(), Some(SessionCommand::ReleaseInput));
        assert!(runner.is_focused());
    }

    #[test]
    fn lifecycle_is_bounded_and_requires_observed_stops() {
        let mut runner = SessionRunner::new(1);
        assert_eq!(runner.state(), SessionState::Idle);

        runner.start().unwrap();
        assert_eq!(runner.state(), SessionState::Starting);
        runner.mark_started().unwrap();
        assert_eq!(runner.state(), SessionState::Running);
        runner.request_stop().unwrap();
        assert_eq!(runner.state(), SessionState::Stopping);
        assert_eq!(runner.request_stop(), Err(SessionError::InvalidTransition));
        assert_eq!(runner.mark_stopped(), Ok(()));
        assert_eq!(runner.state(), SessionState::Stopped);
        assert_eq!(runner.pop_command(), Some(SessionCommand::Stop));

        runner.start().unwrap();
        assert_eq!(runner.state(), SessionState::Starting);
        assert_eq!(runner.pending_len(), 0);
        assert_eq!(runner.start(), Err(SessionError::InvalidTransition));
        assert_eq!(runner.pending_len(), 0);
    }

    #[test]
    fn command_queue_never_exceeds_configured_capacity() {
        let mut runner = SessionRunner::new(2);

        assert_eq!(runner.enqueue(SessionCommand::Stop), Ok(()));
        assert_eq!(runner.enqueue(SessionCommand::Stop), Ok(()));
        assert_eq!(
            runner.enqueue(SessionCommand::Stop),
            Err(SessionError::QueueFull)
        );
        assert_eq!(runner.pending_len(), 2);
    }

    #[test]
    fn focus_loss_has_a_reserved_slot_when_normal_queue_is_full() {
        let mut runner = SessionRunner::new(1);
        runner.start().unwrap();
        runner.mark_started().unwrap();
        runner.enqueue(SessionCommand::Stop).unwrap();

        assert!(runner.set_focus(false));
        assert_eq!(runner.pending_len(), 2);
        assert_eq!(runner.pop_command(), Some(SessionCommand::ReleaseInput));
        assert_eq!(runner.pop_command(), Some(SessionCommand::Stop));
    }
}
