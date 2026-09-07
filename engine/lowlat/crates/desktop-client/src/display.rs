//! Desktop presentation policy: display mode, scaling, and hotkeys.
//!
//! minifb owns the actual window; this module keeps every user-facing knob
//! as a pure, tested value. Fullscreen here means a borderless window sized
//! to the stream (`FitScreen` scaling); exclusive-mode switching is left to
//! a future native renderer and is never claimed.

use minifb::{Key, Scale, ScaleMode, Window, WindowOptions};

/// How the desktop window presents the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum DisplayMode {
    /// Resizable window at the negotiated size.
    #[default]
    Windowed,
    /// Borderless window scaled to fill the screen.
    Borderless,
    /// Borderless window with `FitScreen` scaling (closest to fullscreen
    /// minifb can express without exclusive mode).
    Fullscreen,
}

impl DisplayMode {
    /// Parse `OPENSTREAM_DISPLAY_MODE` (`windowed`/`borderless`/`fullscreen`).
    pub(crate) fn from_env() -> Self {
        std::env::var("OPENSTREAM_DISPLAY_MODE")
            .ok()
            .map(|mode| Self::parse(&mode))
            .unwrap_or_default()
    }

    /// Parse one mode name (case-insensitive, safe fallback to windowed).
    pub(crate) fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "borderless" => Self::Borderless,
            "fullscreen" | "full" | "fit" => Self::Fullscreen,
            _ => Self::Windowed,
        }
    }

    /// Build the minifb window options for this mode.
    pub(crate) fn window_options(self) -> WindowOptions {
        let mut options = WindowOptions {
            resize: true,
            ..WindowOptions::default()
        };
        match self {
            Self::Windowed => {}
            Self::Borderless => {
                options.borderless = true;
                options.scale = Scale::FitScreen;
                options.scale_mode = ScaleMode::Stretch;
            }
            Self::Fullscreen => {
                options.borderless = true;
                options.scale = Scale::FitScreen;
                options.scale_mode = ScaleMode::AspectRatioStretch;
            }
        }
        options
    }
}

/// Actions a hotkey can trigger from the desktop window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyAction {
    /// End the session (same as closing the window).
    Disconnect,
    /// Release all held input without disconnecting.
    ReleaseInput,
}

/// One parsed hotkey: modifiers plus a final key name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hotkey {
    pub(crate) action: HotkeyAction,
    pub(crate) ctrl: bool,
    pub(crate) alt: bool,
    pub(crate) shift: bool,
    pub(crate) key: String,
}

impl Hotkey {
    /// Default safety set: Ctrl+Alt+End disconnects, Ctrl+Alt+Home releases.
    pub(crate) fn defaults() -> Vec<Self> {
        vec![
            Self {
                action: HotkeyAction::Disconnect,
                ctrl: true,
                alt: true,
                shift: false,
                key: "end".into(),
            },
            Self {
                action: HotkeyAction::ReleaseInput,
                ctrl: true,
                alt: true,
                shift: false,
                key: "home".into(),
            },
        ]
    }

    /// Parse `OPENSTREAM_HOTKEYS` (`disconnect=ctrl+alt+end,release=ctrl+alt+home`).
    /// Unknown actions and malformed entries are skipped; an empty result
    /// keeps the defaults so the window can always be exited by policy.
    pub(crate) fn from_env() -> Vec<Self> {
        let Ok(spec) = std::env::var("OPENSTREAM_HOTKEYS") else {
            return Self::defaults();
        };
        let parsed = Self::parse_spec(&spec);
        if parsed.is_empty() {
            Self::defaults()
        } else {
            parsed
        }
    }

    /// Parse one comma-separated hotkey spec. Pure and unit-tested.
    pub(crate) fn parse_spec(spec: &str) -> Vec<Self> {
        let mut hotkeys = Vec::new();
        for entry in spec.split(',') {
            let (action_name, keys) = match entry.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            let action = match action_name.trim().to_ascii_lowercase().as_str() {
                "disconnect" | "quit" | "exit" => HotkeyAction::Disconnect,
                "release" | "release-input" | "ungrab" => HotkeyAction::ReleaseInput,
                _ => continue,
            };
            let mut ctrl = false;
            let mut alt = false;
            let mut shift = false;
            let mut key = None;
            for part in keys.split('+') {
                match part.trim().to_ascii_lowercase().as_str() {
                    "ctrl" | "control" => ctrl = true,
                    "alt" | "option" => alt = true,
                    "shift" => shift = true,
                    "" => {}
                    other => key = Some(other.to_string()),
                }
            }
            let Some(key) = key else { continue };
            hotkeys.push(Self {
                action,
                ctrl,
                alt,
                shift,
                key,
            });
            if hotkeys.len() >= 8 {
                break;
            }
        }
        hotkeys
    }
}

/// Map a hotkey key name to minifb. Unknown names resolve to `None` so the
/// hotkey can never fire, which is the safe failure mode.
pub(crate) fn named_key(name: &str) -> Option<Key> {
    match name.trim().to_ascii_lowercase().as_str() {
        "a" => Some(Key::A),
        "b" => Some(Key::B),
        "c" => Some(Key::C),
        "d" => Some(Key::D),
        "e" => Some(Key::E),
        "f" => Some(Key::F),
        "g" => Some(Key::G),
        "h" => Some(Key::H),
        "i" => Some(Key::I),
        "j" => Some(Key::J),
        "k" => Some(Key::K),
        "l" => Some(Key::L),
        "m" => Some(Key::M),
        "n" => Some(Key::N),
        "o" => Some(Key::O),
        "p" => Some(Key::P),
        "q" => Some(Key::Q),
        "r" => Some(Key::R),
        "s" => Some(Key::S),
        "t" => Some(Key::T),
        "u" => Some(Key::U),
        "v" => Some(Key::V),
        "w" => Some(Key::W),
        "x" => Some(Key::X),
        "y" => Some(Key::Y),
        "z" => Some(Key::Z),
        "0" => Some(Key::Key0),
        "1" => Some(Key::Key1),
        "2" => Some(Key::Key2),
        "3" => Some(Key::Key3),
        "4" => Some(Key::Key4),
        "5" => Some(Key::Key5),
        "6" => Some(Key::Key6),
        "7" => Some(Key::Key7),
        "8" => Some(Key::Key8),
        "9" => Some(Key::Key9),
        "f1" => Some(Key::F1),
        "f2" => Some(Key::F2),
        "f3" => Some(Key::F3),
        "f4" => Some(Key::F4),
        "f5" => Some(Key::F5),
        "f6" => Some(Key::F6),
        "f7" => Some(Key::F7),
        "f8" => Some(Key::F8),
        "f9" => Some(Key::F9),
        "f10" => Some(Key::F10),
        "f11" => Some(Key::F11),
        "f12" => Some(Key::F12),
        "escape" | "esc" => Some(Key::Escape),
        "enter" | "return" => Some(Key::Enter),
        "tab" => Some(Key::Tab),
        "space" => Some(Key::Space),
        "backspace" => Some(Key::Backspace),
        "delete" | "del" => Some(Key::Delete),
        "insert" | "ins" => Some(Key::Insert),
        "home" => Some(Key::Home),
        "end" => Some(Key::End),
        "pageup" => Some(Key::PageUp),
        "pagedown" => Some(Key::PageDown),
        "up" => Some(Key::Up),
        "down" => Some(Key::Down),
        "left" => Some(Key::Left),
        "right" => Some(Key::Right),
        _ => None,
    }
}

fn modifiers_match(window: &Window, hotkey: &Hotkey) -> bool {
    let ctrl = window.is_key_down(Key::LeftCtrl) || window.is_key_down(Key::RightCtrl);
    let alt = window.is_key_down(Key::LeftAlt) || window.is_key_down(Key::RightAlt);
    let shift = window.is_key_down(Key::LeftShift) || window.is_key_down(Key::RightShift);
    ctrl == hotkey.ctrl && alt == hotkey.alt && shift == hotkey.shift
}

/// Poll the hotkey set once per frame. Returns the freshly pressed action at
/// most once per physical press: a held combo reports until released, then
/// re-arms. `last` tracks the previously reported action.
pub(crate) fn poll_hotkey(
    window: &Window,
    hotkeys: &[Hotkey],
    last: &mut Option<HotkeyAction>,
) -> Option<HotkeyAction> {
    let fired = hotkeys
        .iter()
        .filter(|hotkey| {
            named_key(&hotkey.key).is_some_and(|key| window.is_key_down(key))
                && modifiers_match(window, hotkey)
        })
        .map(|hotkey| hotkey.action)
        .next();
    let fresh = if fired != *last { fired } else { None };
    *last = fired;
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_map_to_sane_window_options() {
        let windowed = DisplayMode::Windowed.window_options();
        assert!(!windowed.borderless);
        let borderless = DisplayMode::Borderless.window_options();
        assert!(borderless.borderless);
        assert!(matches!(borderless.scale, Scale::FitScreen));
        let fullscreen = DisplayMode::Fullscreen.window_options();
        assert!(fullscreen.borderless);
        assert_eq!(fullscreen.scale_mode, ScaleMode::AspectRatioStretch);
    }

    #[test]
    fn unknown_modes_fall_back_to_windowed() {
        assert_eq!(DisplayMode::parse("BORDERLESS"), DisplayMode::Borderless);
        assert_eq!(DisplayMode::parse("full"), DisplayMode::Fullscreen);
        assert_eq!(DisplayMode::parse("bogus"), DisplayMode::Windowed);
        assert_eq!(DisplayMode::parse(""), DisplayMode::Windowed);
    }

    #[test]
    fn hotkey_spec_parses_actions_and_modifiers() {
        let hotkeys = Hotkey::parse_spec("disconnect=ctrl+alt+end,release=shift+f1");
        assert_eq!(hotkeys.len(), 2);
        assert_eq!(hotkeys[0].action, HotkeyAction::Disconnect);
        assert!(hotkeys[0].ctrl && hotkeys[0].alt && !hotkeys[0].shift);
        assert_eq!(hotkeys[0].key, "end");
        assert_eq!(hotkeys[1].action, HotkeyAction::ReleaseInput);
        assert!(hotkeys[1].shift);
    }

    #[test]
    fn malformed_hotkeys_fall_back_to_defaults() {
        assert!(Hotkey::parse_spec("").is_empty());
        assert!(Hotkey::parse_spec("bogus").is_empty());
        // Modifiers without a final key are unusable and skipped.
        assert!(Hotkey::parse_spec("disconnect=ctrl+alt").is_empty());
        assert_eq!(Hotkey::defaults().len(), 2);
    }

    #[test]
    fn known_key_names_resolve_and_unknown_names_do_not() {
        assert_eq!(named_key("end"), Some(Key::End));
        assert_eq!(named_key("HOME"), Some(Key::Home));
        assert_eq!(named_key("f12"), Some(Key::F12));
        assert_eq!(named_key("q"), Some(Key::Q));
        assert_eq!(named_key("bogus-key"), None);
    }
}
