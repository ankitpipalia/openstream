//! Raw input injection on Windows via `SendInput`.
//!
//! Status: implemented and CI-validated (the pure mapping and held-state logic
//! is unit-tested on every target; the `SendInput` FFI is compiled for the
//! Windows targets). Physical Windows runtime verification is pending the
//! hardware. Not a production default until then.
//!
//! A peer reports keys by USB HID usage code (layout belongs to the far side).
//! This maps each usage to its PS/2 Set 1 scan code and injects it with
//! `KEYEVENTF_SCANCODE`, so a game reading raw scan codes sees the same thing a
//! local keyboard would -- the reason Parsec injects scan codes rather than
//! virtual keys. Mouse buttons, relative and absolute motion, and the wheel map
//! to `MOUSEINPUT` flags.
//!
//! The [`Injector`] tracks what is held so it can guarantee a full release on
//! disconnect or focus loss ([`Injector::release_all`]): a remote key or button
//! must never stay stuck down on a machine nobody is driving.

use std::collections::BTreeSet;

/// A PS/2 Set 1 scan code plus whether it is an `E0`-extended key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scancode {
    /// The make code (the byte after any `E0` prefix).
    pub set1: u16,
    /// Whether the key is `E0`-extended (arrows, nav cluster, right-hand
    /// modifiers, keypad Enter/Divide, etc.).
    pub extended: bool,
}

impl Scancode {
    const fn plain(set1: u16) -> Self {
        Self {
            set1,
            extended: false,
        }
    }
    const fn ext(set1: u16) -> Self {
        Self {
            set1,
            extended: true,
        }
    }
}

/// Map a USB HID keyboard usage code (usage page 0x07) to its PS/2 Set 1 scan
/// code, or `None` for a usage this host does not inject (an unmapped or
/// reserved code is dropped rather than guessed).
pub fn hid_key_to_scancode(usage: u16) -> Option<Scancode> {
    use Scancode as S;
    let code = match usage {
        // Letters A-Z (0x04-0x1D).
        0x04 => S::plain(0x1E),
        0x05 => S::plain(0x30),
        0x06 => S::plain(0x2E),
        0x07 => S::plain(0x20),
        0x08 => S::plain(0x12),
        0x09 => S::plain(0x21),
        0x0A => S::plain(0x22),
        0x0B => S::plain(0x23),
        0x0C => S::plain(0x17),
        0x0D => S::plain(0x24),
        0x0E => S::plain(0x25),
        0x0F => S::plain(0x26),
        0x10 => S::plain(0x32),
        0x11 => S::plain(0x31),
        0x12 => S::plain(0x18),
        0x13 => S::plain(0x19),
        0x14 => S::plain(0x10),
        0x15 => S::plain(0x13),
        0x16 => S::plain(0x1F),
        0x17 => S::plain(0x14),
        0x18 => S::plain(0x16),
        0x19 => S::plain(0x2F),
        0x1A => S::plain(0x11),
        0x1B => S::plain(0x2D),
        0x1C => S::plain(0x15),
        0x1D => S::plain(0x2C),
        // Digits 1-0 (0x1E-0x27).
        0x1E => S::plain(0x02),
        0x1F => S::plain(0x03),
        0x20 => S::plain(0x04),
        0x21 => S::plain(0x05),
        0x22 => S::plain(0x06),
        0x23 => S::plain(0x07),
        0x24 => S::plain(0x08),
        0x25 => S::plain(0x09),
        0x26 => S::plain(0x0A),
        0x27 => S::plain(0x0B),
        // Enter, Esc, Backspace, Tab, Space.
        0x28 => S::plain(0x1C),
        0x29 => S::plain(0x01),
        0x2A => S::plain(0x0E),
        0x2B => S::plain(0x0F),
        0x2C => S::plain(0x39),
        // Punctuation.
        0x2D => S::plain(0x0C), // - _
        0x2E => S::plain(0x0D), // = +
        0x2F => S::plain(0x1A), // [ {
        0x30 => S::plain(0x1B), // ] }
        0x31 => S::plain(0x2B), // \ |
        0x32 => S::plain(0x2B), // non-US #/~
        0x33 => S::plain(0x27), // ; :
        0x34 => S::plain(0x28), // ' "
        0x35 => S::plain(0x29), // ` ~
        0x36 => S::plain(0x33), // , <
        0x37 => S::plain(0x34), // . >
        0x38 => S::plain(0x35), // / ?
        0x39 => S::plain(0x3A), // Caps Lock
        // Function keys F1-F12 (0x3A-0x45).
        0x3A => S::plain(0x3B),
        0x3B => S::plain(0x3C),
        0x3C => S::plain(0x3D),
        0x3D => S::plain(0x3E),
        0x3E => S::plain(0x3F),
        0x3F => S::plain(0x40),
        0x40 => S::plain(0x41),
        0x41 => S::plain(0x42),
        0x42 => S::plain(0x43),
        0x43 => S::plain(0x44),
        0x44 => S::plain(0x57),
        0x45 => S::plain(0x58),
        // PrintScreen, ScrollLock (Pause is a special sequence: dropped).
        0x46 => S::ext(0x37),
        0x47 => S::plain(0x46),
        // Insert/Home/PageUp/Delete/End/PageDown (extended nav cluster).
        0x49 => S::ext(0x52),
        0x4A => S::ext(0x47),
        0x4B => S::ext(0x49),
        0x4C => S::ext(0x53),
        0x4D => S::ext(0x4F),
        0x4E => S::ext(0x51),
        // Arrows (extended).
        0x4F => S::ext(0x4D), // Right
        0x50 => S::ext(0x4B), // Left
        0x51 => S::ext(0x50), // Down
        0x52 => S::ext(0x48), // Up
        // Keypad.
        0x53 => S::plain(0x45), // Num Lock
        0x54 => S::ext(0x35),   // KP /
        0x55 => S::plain(0x37), // KP *
        0x56 => S::plain(0x4A), // KP -
        0x57 => S::plain(0x4E), // KP +
        0x58 => S::ext(0x1C),   // KP Enter
        0x59 => S::plain(0x4F), // KP 1
        0x5A => S::plain(0x50), // KP 2
        0x5B => S::plain(0x51), // KP 3
        0x5C => S::plain(0x4B), // KP 4
        0x5D => S::plain(0x4C), // KP 5
        0x5E => S::plain(0x4D), // KP 6
        0x5F => S::plain(0x47), // KP 7
        0x60 => S::plain(0x48), // KP 8
        0x61 => S::plain(0x49), // KP 9
        0x62 => S::plain(0x52), // KP 0
        0x63 => S::plain(0x53), // KP .
        0x64 => S::plain(0x56), // non-US \ |
        0x65 => S::ext(0x5D),   // Application (menu)
        // Modifiers (0xE0-0xE7).
        0xE0 => S::plain(0x1D), // Left Ctrl
        0xE1 => S::plain(0x2A), // Left Shift
        0xE2 => S::plain(0x38), // Left Alt
        0xE3 => S::ext(0x5B),   // Left GUI
        0xE4 => S::ext(0x1D),   // Right Ctrl
        0xE5 => S::plain(0x36), // Right Shift
        0xE6 => S::ext(0x38),   // Right Alt
        0xE7 => S::ext(0x5C),   // Right GUI
        _ => return None,
    };
    Some(code)
}

/// A pointer button the peer can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PointerButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

/// Map a peer button number (1-5, the protocol's numbering) to a
/// [`PointerButton`], or `None` for an unknown button.
pub fn button_from_peer(number: u32) -> Option<PointerButton> {
    match number {
        1 => Some(PointerButton::Left),
        2 => Some(PointerButton::Middle),
        3 => Some(PointerButton::Right),
        4 => Some(PointerButton::X1),
        5 => Some(PointerButton::X2),
        _ => None,
    }
}

/// Normalise a pixel coordinate within a `width` x `height` output to the
/// 0..=65535 range `SendInput` absolute motion uses. The far edge maps to 65535
/// and out-of-range inputs are clamped, so a coordinate can never land off the
/// virtual desktop.
pub fn normalize_absolute(x: i32, y: i32, width: u32, height: u32) -> (i32, i32) {
    let map = |value: i32, extent: u32| -> i32 {
        if extent <= 1 {
            return 0;
        }
        let max = i64::from(extent - 1);
        let clamped = i64::from(value).clamp(0, max);
        // 65535 * clamped / (extent - 1), in i64 to avoid overflow; the result is
        // in 0..=65535 so the conversion never fails.
        let scaled = clamped * 65535 / max;
        i32::try_from(scaled).unwrap_or(65535)
    };
    (map(x, width), map(y, height))
}

/// One low-level injection action. The [`Injector`] state machine produces
/// these and the Windows layer turns each into a `SendInput` event, so the
/// stateful part (what is held, what a release must undo) is testable without
/// any OS call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectAction {
    Key {
        scancode: Scancode,
        down: bool,
    },
    Button {
        button: PointerButton,
        down: bool,
    },
    MoveRelative {
        dx: i32,
        dy: i32,
    },
    /// Absolute move, coordinates already normalised to 0..=65535.
    MoveAbsolute {
        x: i32,
        y: i32,
    },
    /// Wheel notches (positive up / right), one axis.
    Wheel {
        delta: i32,
        horizontal: bool,
    },
}

/// Tracks held keys and buttons so every press can be guaranteed a release.
#[derive(Debug, Default)]
pub struct Injector {
    held_keys: BTreeSet<u16>,
    held_buttons: BTreeSet<PointerButton>,
}

impl Injector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A key event by HID usage. An unmapped usage yields nothing; a release for
    /// a key that was never held is dropped (a reconnecting peer sends stray
    /// releases). Returns the action to inject, if any.
    pub fn key(&mut self, usage: u16, down: bool) -> Option<InjectAction> {
        let scancode = hid_key_to_scancode(usage)?;
        if down {
            self.held_keys.insert(usage);
        } else if !self.held_keys.remove(&usage) {
            return None;
        }
        Some(InjectAction::Key { scancode, down })
    }

    /// A pointer button event. A release for a button that was never held is
    /// dropped.
    pub fn button(&mut self, button: PointerButton, down: bool) -> Option<InjectAction> {
        if down {
            self.held_buttons.insert(button);
        } else if !self.held_buttons.remove(&button) {
            return None;
        }
        Some(InjectAction::Button { button, down })
    }

    /// Release everything currently held, in a deterministic order, and forget
    /// it. Call on disconnect, focus loss or permission revocation so nothing
    /// stays stuck down.
    pub fn release_all(&mut self) -> Vec<InjectAction> {
        let mut actions = Vec::new();
        for &usage in &self.held_keys {
            if let Some(scancode) = hid_key_to_scancode(usage) {
                actions.push(InjectAction::Key {
                    scancode,
                    down: false,
                });
            }
        }
        for &button in &self.held_buttons {
            actions.push(InjectAction::Button {
                button,
                down: false,
            });
        }
        self.held_keys.clear();
        self.held_buttons.clear();
        actions
    }

    /// Whether anything is currently held.
    #[must_use]
    pub fn holds_anything(&self) -> bool {
        !self.held_keys.is_empty() || !self.held_buttons.is_empty()
    }
}

#[cfg(target_os = "windows")]
pub use sender::{SendInputError, send_actions};

#[cfg(target_os = "windows")]
mod sender {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
        MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
        MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY,
    };

    // The `mouseData` values that select the first/second X button, per
    // MOUSEINPUT; small literals rather than a constant from another module.
    const XBUTTON1: i32 = 0x0001;
    const XBUTTON2: i32 = 0x0002;

    use super::{InjectAction, PointerButton};

    /// The `SendInput` call rejected or short-wrote the batch.
    #[derive(Debug)]
    pub struct SendInputError {
        pub sent: u32,
        pub expected: usize,
    }

    impl std::fmt::Display for SendInputError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "SendInput injected {} of {} events",
                self.sent, self.expected
            )
        }
    }

    impl std::error::Error for SendInputError {}

    /// Inject a batch of actions with one `SendInput` call so the OS keeps them
    /// contiguous. Returns an error if fewer than all events were accepted
    /// (a locked desktop or UIPI block).
    pub fn send_actions(actions: &[InjectAction]) -> Result<(), SendInputError> {
        if actions.is_empty() {
            return Ok(());
        }
        let inputs: Vec<INPUT> = actions.iter().map(|action| build_input(*action)).collect();
        // SAFETY: FFI. `inputs` is a valid slice of `INPUT`, and `cbsize` is the
        // element size as SendInput requires.
        let sent = unsafe {
            SendInput(
                &inputs,
                i32::try_from(std::mem::size_of::<INPUT>()).unwrap_or(0),
            )
        };
        if sent as usize == inputs.len() {
            Ok(())
        } else {
            Err(SendInputError {
                sent,
                expected: inputs.len(),
            })
        }
    }

    fn build_input(action: InjectAction) -> INPUT {
        match action {
            InjectAction::Key { scancode, down } => {
                let mut flags = KEYEVENTF_SCANCODE;
                if scancode.extended {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                if !down {
                    flags |= KEYEVENTF_KEYUP;
                }
                keyboard_input(scancode.set1, flags)
            }
            InjectAction::Button { button, down } => {
                let (flags, data) = button_event(button, down);
                mouse_input(0, 0, data, flags)
            }
            InjectAction::MoveRelative { dx, dy } => mouse_input(dx, dy, 0, MOUSEEVENTF_MOVE),
            InjectAction::MoveAbsolute { x, y } => mouse_input(
                x,
                y,
                0,
                MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            ),
            InjectAction::Wheel { delta, horizontal } => {
                let flags = if horizontal {
                    MOUSEEVENTF_HWHEEL
                } else {
                    MOUSEEVENTF_WHEEL
                };
                mouse_input(0, 0, delta, flags)
            }
        }
    }

    fn keyboard_input(scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn mouse_input(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
        // `mouseData` is a bitfield Windows reinterprets per flag (a signed wheel
        // delta, or the X-button selector); the reinterpret is intentional.
        #[allow(clippy::cast_sign_loss)]
        let mouse_data = data as u32;
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: mouse_data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn button_event(button: PointerButton, down: bool) -> (MOUSE_EVENT_FLAGS, i32) {
        match button {
            PointerButton::Left if down => (MOUSEEVENTF_LEFTDOWN, 0),
            PointerButton::Left => (MOUSEEVENTF_LEFTUP, 0),
            PointerButton::Right if down => (MOUSEEVENTF_RIGHTDOWN, 0),
            PointerButton::Right => (MOUSEEVENTF_RIGHTUP, 0),
            PointerButton::Middle if down => (MOUSEEVENTF_MIDDLEDOWN, 0),
            PointerButton::Middle => (MOUSEEVENTF_MIDDLEUP, 0),
            PointerButton::X1 if down => (MOUSEEVENTF_XDOWN, XBUTTON1),
            PointerButton::X1 => (MOUSEEVENTF_XUP, XBUTTON1),
            PointerButton::X2 if down => (MOUSEEVENTF_XDOWN, XBUTTON2),
            PointerButton::X2 => (MOUSEEVENTF_XUP, XBUTTON2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancode_table_maps_known_keys() {
        assert_eq!(hid_key_to_scancode(0x04), Some(Scancode::plain(0x1E))); // A
        assert_eq!(hid_key_to_scancode(0x28), Some(Scancode::plain(0x1C))); // Enter
        assert_eq!(hid_key_to_scancode(0x2C), Some(Scancode::plain(0x39))); // Space
        assert_eq!(hid_key_to_scancode(0xE0), Some(Scancode::plain(0x1D))); // Left Ctrl
        assert_eq!(hid_key_to_scancode(0xE4), Some(Scancode::ext(0x1D))); // Right Ctrl (extended)
        assert_eq!(hid_key_to_scancode(0x4F), Some(Scancode::ext(0x4D))); // Right arrow (extended)
        assert_eq!(hid_key_to_scancode(0x3A), Some(Scancode::plain(0x3B))); // F1
        // Unmapped / reserved usages are dropped.
        assert_eq!(hid_key_to_scancode(0x00), None);
        assert_eq!(hid_key_to_scancode(0xFFFF), None);
    }

    #[test]
    fn a_key_press_and_release_round_trips_through_held_state() {
        let mut injector = Injector::new();
        assert_eq!(
            injector.key(0x04, true),
            Some(InjectAction::Key {
                scancode: Scancode::plain(0x1E),
                down: true
            })
        );
        assert!(injector.holds_anything());
        assert_eq!(
            injector.key(0x04, false),
            Some(InjectAction::Key {
                scancode: Scancode::plain(0x1E),
                down: false
            })
        );
        assert!(!injector.holds_anything());
    }

    #[test]
    fn a_release_for_an_unheld_key_is_dropped() {
        let mut injector = Injector::new();
        assert_eq!(injector.key(0x04, false), None);
        // An unmapped usage yields nothing even on press.
        assert_eq!(injector.key(0x01, true), None);
    }

    #[test]
    fn release_all_releases_every_held_key_and_button() {
        let mut injector = Injector::new();
        injector.key(0x04, true); // A
        injector.key(0xE1, true); // Left Shift
        injector.button(PointerButton::Left, true);

        let released = injector.release_all();
        // Two key ups and one button up.
        assert_eq!(released.len(), 3);
        assert!(released.contains(&InjectAction::Key {
            scancode: Scancode::plain(0x1E),
            down: false
        }));
        assert!(released.contains(&InjectAction::Key {
            scancode: Scancode::plain(0x2A),
            down: false
        }));
        assert!(released.contains(&InjectAction::Button {
            button: PointerButton::Left,
            down: false
        }));
        assert!(!injector.holds_anything());
        // A second release-all does nothing.
        assert!(injector.release_all().is_empty());
    }

    #[test]
    fn absolute_coordinates_normalise_to_the_send_input_range() {
        assert_eq!(normalize_absolute(0, 0, 1920, 1080), (0, 0));
        assert_eq!(normalize_absolute(1919, 1079, 1920, 1080), (65535, 65535));
        // Out-of-range clamps to the edges.
        assert_eq!(normalize_absolute(-5, 5000, 1920, 1080), (0, 65535));
        // Degenerate extents do not divide by zero.
        assert_eq!(normalize_absolute(10, 10, 1, 1), (0, 0));
    }

    #[test]
    fn peer_button_numbers_map_to_buttons() {
        assert_eq!(button_from_peer(1), Some(PointerButton::Left));
        assert_eq!(button_from_peer(3), Some(PointerButton::Right));
        assert_eq!(button_from_peer(5), Some(PointerButton::X2));
        assert_eq!(button_from_peer(9), None);
    }
}
