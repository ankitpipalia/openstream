//! Host-side translation of the project-owned `OI` input envelope.
//!
//! The network and media path is shared across operating systems, but input
//! injection must use the local security boundary. Linux uses the existing
//! kernel `uinput` implementation; Windows uses `SendInput`; macOS uses
//! CoreGraphics HID events. Input is opt-in through `OPENSTREAM_ENABLE_INPUT`
//! and a malformed or unsupported event is rejected before it reaches an OS
//! API.

use std::env;

use openstream_media::input::{InputEvent, RumbleEvent};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use openstream_media::input::{FLAG_RELATIVE, InputKind};

pub(crate) enum HostInput {
    Disabled,
    #[cfg(target_os = "linux")]
    Linux(LinuxInput),
    #[cfg(target_os = "windows")]
    Windows(WindowsInput),
    #[cfg(target_os = "macos")]
    Mac(MacInput),
}

impl HostInput {
    pub(crate) fn from_environment(
        width: u16,
        height: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if env::var("OPENSTREAM_ENABLE_INPUT").as_deref() != Ok("1") {
            return Ok(Self::Disabled);
        }

        #[cfg(target_os = "linux")]
        {
            let extents = lowlat_inject::event::Extents::alone(u32::from(width), u32::from(height));
            let injector = lowlat_inject::event::Injector::new(extents);
            let devices = lowlat_inject::uinput::Devices::create("openstream")
                .map_err(|error| error.to_string())?;
            return Ok(Self::Linux(LinuxInput { injector, devices }));
        }

        #[cfg(target_os = "windows")]
        {
            return Ok(Self::Windows(WindowsInput::new(width, height)));
        }

        #[cfg(target_os = "macos")]
        {
            return Ok(Self::Mac(MacInput::new(width, height)?));
        }

        #[allow(unreachable_code)]
        Err("host input is unsupported on this target".into())
    }

    pub(crate) fn apply(&mut self, payload: &[u8]) -> Result<(), String> {
        if matches!(self, Self::Disabled) {
            return Ok(());
        }
        let event = InputEvent::decode(payload).map_err(|error| error.to_string())?;
        match self {
            Self::Disabled => Ok(()),
            #[cfg(target_os = "linux")]
            Self::Linux(input) => input.apply(event),
            #[cfg(target_os = "windows")]
            Self::Windows(input) => input.apply(event),
            #[cfg(target_os = "macos")]
            Self::Mac(input) => input.apply(event),
        }
    }

    pub(crate) fn tick(&mut self) {
        #[cfg(target_os = "linux")]
        if let Self::Linux(input) = self {
            input.devices.tick();
        }
    }

    pub(crate) fn rumble(&mut self) -> Option<RumbleEvent> {
        #[cfg(target_os = "linux")]
        if let Self::Linux(input) = self {
            return input.devices.rumble().map(|rumble| RumbleEvent {
                device_id: rumble.pad,
                strong: rumble.large,
                weak: rumble.small,
            });
        }
        None
    }
}

impl Drop for HostInput {
    fn drop(&mut self) {
        let result: Result<(), String> = match self {
            Self::Disabled => Ok(()),
            #[cfg(target_os = "linux")]
            Self::Linux(input) => {
                input.release_all();
                Ok(())
            }
            #[cfg(target_os = "windows")]
            Self::Windows(input) => input.release_all(),
            #[cfg(target_os = "macos")]
            Self::Mac(input) => input.release_all(),
        };
        if let Err(error) = result {
            eprintln!("OpenStream could not release host input state: {error}");
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxInput {
    injector: lowlat_inject::event::Injector,
    devices: lowlat_inject::uinput::Devices,
}

#[cfg(target_os = "linux")]
impl LinuxInput {
    fn apply(&mut self, event: InputEvent) -> Result<(), String> {
        let fields = event.lowlat_fields();
        if fields.opcode == lowlat_core::control::op::RELEASE {
            self.injector.release_all(&mut self.devices);
            return Ok(());
        }
        let control = lowlat_core::control::Control {
            a0: fields.a0,
            a1: fields.a1,
            a2: fields.a2,
            opcode: fields.opcode,
            body: &[],
        };
        self.injector.on_control(&control, &mut self.devices);
        Ok(())
    }

    fn release_all(&mut self) {
        self.injector.release_all(&mut self.devices);
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{FLAG_RELATIVE, InputEvent, InputKind};
    use std::mem::size_of;

    const INPUT_MOUSE: u32 = 0;
    const INPUT_KEYBOARD: u32 = 1;
    const MOUSEEVENTF_MOVE: u32 = 0x0001;
    const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
    const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
    const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
    const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
    const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
    const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
    const MOUSEEVENTF_XDOWN: u32 = 0x0080;
    const MOUSEEVENTF_XUP: u32 = 0x0100;
    const MOUSEEVENTF_WHEEL: u32 = 0x0800;
    const MOUSEEVENTF_HWHEEL: u32 = 0x1000;
    const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;
    const MOUSEEVENTF_VIRTUALDESK: u32 = 0x4000;
    const KEYEVENTF_KEYUP: u32 = 0x0002;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MouseInput {
        dx: i32,
        dy: i32,
        mouse_data: u32,
        flags: u32,
        time: u32,
        extra_info: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KeyboardInput {
        virtual_key: u16,
        scan_code: u16,
        flags: u32,
        time: u32,
        extra_info: usize,
    }

    #[repr(C)]
    union InputUnion {
        mouse: MouseInput,
        keyboard: KeyboardInput,
    }

    #[repr(C)]
    struct Input {
        kind: u32,
        data: InputUnion,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendInput(count: u32, inputs: *const Input, size: i32) -> u32;
    }

    pub(crate) struct WindowsInput {
        width: u32,
        height: u32,
        active_keys: Vec<u16>,
        active_buttons: [bool; 5],
    }

    impl WindowsInput {
        pub(super) fn new(width: u16, height: u16) -> Self {
            Self {
                width: u32::from(width).max(1),
                height: u32::from(height).max(1),
                active_keys: Vec::with_capacity(64),
                active_buttons: [false; 5],
            }
        }

        pub(super) fn apply(&mut self, event: InputEvent) -> Result<(), String> {
            match event.kind {
                InputKind::Keyboard => self.keyboard(event.code, event.value != 0),
                InputKind::PointerMotion => self.motion(event),
                InputKind::PointerButton => self.button(event.code, event.value != 0),
                InputKind::Wheel => self.wheel(event.value, event.value2),
                InputKind::Release => self.release_all(),
                InputKind::GamepadButton | InputKind::GamepadAxis | InputKind::GamepadUnplug => {
                    Ok(())
                }
                // Pen rides the absolute pointer path; pressure/tilt have no
                // SendInput/CoreGraphics equivalent here. Proximity is inert.
                InputKind::PenMotion => self.motion(event),
                InputKind::PenButton => self.button(event.code, event.value != 0),
                InputKind::PenProximity => Ok(()),
            }
        }

        fn keyboard(&mut self, usage: u32, pressed: bool) -> Result<(), String> {
            let Some(virtual_key) = virtual_key(usage) else {
                return Ok(());
            };
            let flags = if pressed { 0 } else { KEYEVENTF_KEYUP };
            let input = Input {
                kind: INPUT_KEYBOARD,
                data: InputUnion {
                    keyboard: KeyboardInput {
                        virtual_key,
                        scan_code: 0,
                        flags,
                        time: 0,
                        extra_info: 0,
                    },
                },
            };
            send(&input)?;
            if pressed {
                if !self.active_keys.contains(&virtual_key) {
                    self.active_keys.push(virtual_key);
                }
            } else {
                self.active_keys.retain(|key| *key != virtual_key);
            }
            Ok(())
        }

        fn motion(&self, event: InputEvent) -> Result<(), String> {
            let (dx, dy, flags) = if event.flags & FLAG_RELATIVE != 0 {
                (event.value, event.value2, MOUSEEVENTF_MOVE)
            } else {
                (
                    scale(event.value, self.width),
                    scale(event.value2, self.height),
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )
            };
            let input = Input {
                kind: INPUT_MOUSE,
                data: InputUnion {
                    mouse: MouseInput {
                        dx,
                        dy,
                        mouse_data: 0,
                        flags,
                        time: 0,
                        extra_info: 0,
                    },
                },
            };
            send(&input)
        }

        fn button(&mut self, button: u32, pressed: bool) -> Result<(), String> {
            let Some(index) = button
                .checked_sub(1)
                .and_then(|value| usize::try_from(value).ok())
            else {
                return Ok(());
            };
            let Some(state) = self.active_buttons.get_mut(index) else {
                return Ok(());
            };
            let Some((flags, data)) = mouse_button(button, pressed) else {
                return Ok(());
            };
            let input = Input {
                kind: INPUT_MOUSE,
                data: InputUnion {
                    mouse: MouseInput {
                        dx: 0,
                        dy: 0,
                        mouse_data: data,
                        flags,
                        time: 0,
                        extra_info: 0,
                    },
                },
            };
            send(&input)?;
            *state = pressed;
            Ok(())
        }

        fn wheel(&self, horizontal: i32, vertical: i32) -> Result<(), String> {
            if vertical != 0 {
                let input = mouse_wheel(vertical, MOUSEEVENTF_WHEEL);
                send(&input)?;
            }
            if horizontal != 0 {
                let input = mouse_wheel(horizontal, MOUSEEVENTF_HWHEEL);
                send(&input)?;
            }
            Ok(())
        }

        pub(super) fn release_all(&mut self) -> Result<(), String> {
            let keys = self.active_keys.clone();
            for key in keys {
                let input = Input {
                    kind: INPUT_KEYBOARD,
                    data: InputUnion {
                        keyboard: KeyboardInput {
                            virtual_key: key,
                            scan_code: 0,
                            flags: KEYEVENTF_KEYUP,
                            time: 0,
                            extra_info: 0,
                        },
                    },
                };
                send(&input)?;
            }
            self.active_keys.clear();
            for index in 0..self.active_buttons.len() {
                if self.active_buttons[index] {
                    let button = u32::try_from(index + 1).unwrap_or(1);
                    self.button(button, false)?;
                }
            }
            Ok(())
        }
    }

    fn send(input: &Input) -> Result<(), String> {
        #[allow(clippy::cast_possible_truncation)]
        let size = size_of::<Input>() as i32;
        let sent = unsafe { SendInput(1, std::ptr::from_ref(input), size) };
        if sent == 1 {
            Ok(())
        } else {
            Err("Windows SendInput rejected the event".to_string())
        }
    }

    fn mouse_wheel(value: i32, flags: u32) -> Input {
        Input {
            kind: INPUT_MOUSE,
            data: InputUnion {
                mouse: MouseInput {
                    dx: 0,
                    dy: 0,
                    mouse_data: u32::from_ne_bytes(value.saturating_mul(120).to_ne_bytes()),
                    flags,
                    time: 0,
                    extra_info: 0,
                },
            },
        }
    }

    fn mouse_button(button: u32, pressed: bool) -> Option<(u32, u32)> {
        match button {
            1 => Some((
                if pressed {
                    MOUSEEVENTF_LEFTDOWN
                } else {
                    MOUSEEVENTF_LEFTUP
                },
                0,
            )),
            2 => Some((
                if pressed {
                    MOUSEEVENTF_MIDDLEDOWN
                } else {
                    MOUSEEVENTF_MIDDLEUP
                },
                0,
            )),
            3 => Some((
                if pressed {
                    MOUSEEVENTF_RIGHTDOWN
                } else {
                    MOUSEEVENTF_RIGHTUP
                },
                0,
            )),
            4 | 5 => Some((
                if pressed {
                    MOUSEEVENTF_XDOWN
                } else {
                    MOUSEEVENTF_XUP
                },
                if button == 4 { 1 } else { 2 },
            )),
            _ => None,
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn scale(value: i32, extent: u32) -> i32 {
        let max = i64::from(extent.saturating_sub(1).max(1));
        let value = i64::from(value).clamp(0, max);
        ((value * 65_535) / max) as i32
    }

    /// Map common USB HID usages to Windows virtual-key codes. Modifier keys
    /// are sent as ordinary key events; clients emit them explicitly.
    fn virtual_key(usage: u32) -> Option<u16> {
        let key = match usage {
            0x04..=0x1d => u8::try_from(usage - 0x04).ok()?.saturating_add(b'A'),
            0x1e..=0x26 => u8::try_from(usage - 0x1e).ok()?.saturating_add(b'1'),
            0x27 => b'0',
            0x28 => 0x0d,
            0x29 => 0x1b,
            0x2a => 0x08,
            0x2b => 0x09,
            0x2c => 0x20,
            0x2d => 0xbd,
            0x2e => 0xbb,
            0x2f => 0xdb,
            0x30 => 0xdd,
            0x31 => 0xdc,
            0x33 => 0xba,
            0x34 => 0xde,
            0x35 => 0xc0,
            0x36 => 0xbc,
            0x37 => 0xbe,
            0x38 => 0xbf,
            0x39 => 0x14,
            0x3a..=0x45 => u8::try_from(usage - 0x3a).ok()?.saturating_add(0x70),
            0x49 => 0x2d,
            0x4a => 0x24,
            0x4b => 0x21,
            0x4c => 0x2e,
            0x4d => 0x23,
            0x4e => 0x22,
            0x4f => 0x27,
            0x50 => 0x25,
            0x51 => 0x28,
            0x52 => 0x26,
            0x53 => 0x90,
            0x54 => 0x6f,
            0x55 => 0x6a,
            0x56 => 0x6d,
            0x57 => 0x6b,
            0x58 => 0x0d,
            0x59..=0x61 => u8::try_from(usage - 0x59).ok()?.saturating_add(0x60),
            0x62 => 0x60,
            0x63 => 0x6e,
            0x65 => 0x5d,
            0xe0 => 0xa2,
            0xe1 => 0xa0,
            0xe2 => 0xa4,
            0xe3 => 0x5b,
            0xe4 => 0xa3,
            0xe5 => 0xa1,
            0xe6 => 0xa5,
            0xe7 => 0x5c,
            _ => return None,
        };
        Some(u16::from(key))
    }
}

#[cfg(target_os = "windows")]
use windows::WindowsInput;

#[cfg(target_os = "macos")]
mod macos {
    use super::{FLAG_RELATIVE, InputEvent, InputKind};
    use std::ffi::c_void;

    type EventRef = *mut c_void;
    type SourceRef = *mut c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: f64,
        y: f64,
    }

    const HID_EVENT_TAP: u32 = 0;
    const HID_STATE: u32 = 1;
    const MOUSE_MOVED: u32 = 5;
    const LEFT_DOWN: u32 = 1;
    const LEFT_UP: u32 = 2;
    const RIGHT_DOWN: u32 = 3;
    const RIGHT_UP: u32 = 4;
    const OTHER_DOWN: u32 = 25;
    const OTHER_UP: u32 = 26;
    const MOUSE_LEFT: u32 = 0;
    const MOUSE_RIGHT: u32 = 1;
    const MOUSE_CENTER: u32 = 2;
    const SCROLL_LINE: u32 = 1;
    const SCROLL_AXIS_2: u32 = 12;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceCreate(state: u32) -> SourceRef;
        fn CGEventCreate(source: SourceRef) -> EventRef;
        fn CGEventGetLocation(event: EventRef) -> Point;
        fn CGEventCreateKeyboardEvent(source: SourceRef, keycode: u16, keydown: bool) -> EventRef;
        fn CGEventCreateMouseEvent(
            source: SourceRef,
            event_type: u32,
            point: Point,
            button: u32,
        ) -> EventRef;
        fn CGEventCreateScrollWheelEvent(
            source: SourceRef,
            units: u32,
            wheel_count: u32,
            wheel_one: i32,
        ) -> EventRef;
        fn CGEventSetIntegerValueField(event: EventRef, field: u32, value: i64);
        fn CGEventPost(tap: u32, event: EventRef);
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: *const c_void);
    }

    pub(crate) struct MacInput {
        source: SourceRef,
        width: f64,
        height: f64,
        active_keys: Vec<u16>,
        active_buttons: [bool; 5],
    }

    impl MacInput {
        pub(super) fn new(width: u16, height: u16) -> Result<Self, Box<dyn std::error::Error>> {
            let source = unsafe { CGEventSourceCreate(HID_STATE) };
            if source.is_null() {
                return Err("CoreGraphics could not create an event source".into());
            }
            Ok(Self {
                source,
                width: f64::from(width.max(1)),
                height: f64::from(height.max(1)),
                active_keys: Vec::with_capacity(64),
                active_buttons: [false; 5],
            })
        }

        pub(super) fn apply(&mut self, event: InputEvent) -> Result<(), String> {
            match event.kind {
                InputKind::Keyboard => self.keyboard(event.code, event.value != 0),
                InputKind::PointerMotion => self.motion(event),
                InputKind::PointerButton => self.button(event.code, event.value != 0),
                InputKind::Wheel => self.wheel(event.value, event.value2),
                InputKind::Release => self.release_all(),
                InputKind::GamepadButton | InputKind::GamepadAxis | InputKind::GamepadUnplug => {
                    Ok(())
                }
                // Pen rides the absolute pointer path; pressure/tilt have no
                // SendInput/CoreGraphics equivalent here. Proximity is inert.
                InputKind::PenMotion => self.motion(event),
                InputKind::PenButton => self.button(event.code, event.value != 0),
                InputKind::PenProximity => Ok(()),
            }
        }

        fn keyboard(&mut self, usage: u32, pressed: bool) -> Result<(), String> {
            let Some(keycode) = keycode(usage) else {
                return Ok(());
            };
            let event = unsafe { CGEventCreateKeyboardEvent(self.source, keycode, pressed) };
            post(event)?;
            if pressed {
                if !self.active_keys.contains(&keycode) {
                    self.active_keys.push(keycode);
                }
            } else {
                self.active_keys.retain(|key| *key != keycode);
            }
            Ok(())
        }

        fn motion(&self, input: InputEvent) -> Result<(), String> {
            let mut point = current_point()?;
            if input.flags & FLAG_RELATIVE != 0 {
                point.x += f64::from(input.value);
                point.y += f64::from(input.value2);
            } else {
                point.x = f64::from(input.value).clamp(0.0, self.width - 1.0);
                point.y = f64::from(input.value2).clamp(0.0, self.height - 1.0);
            }
            let event =
                unsafe { CGEventCreateMouseEvent(self.source, MOUSE_MOVED, point, MOUSE_LEFT) };
            post(event)
        }

        fn button(&mut self, button: u32, pressed: bool) -> Result<(), String> {
            let Some(index) = button
                .checked_sub(1)
                .and_then(|value| usize::try_from(value).ok())
            else {
                return Ok(());
            };
            let Some(state) = self.active_buttons.get_mut(index) else {
                return Ok(());
            };
            let Some((event_type, mouse_button)) = mouse_button(button, pressed) else {
                return Ok(());
            };
            let event = unsafe {
                CGEventCreateMouseEvent(self.source, event_type, current_point()?, mouse_button)
            };
            post(event)?;
            *state = pressed;
            Ok(())
        }

        fn wheel(&self, horizontal: i32, vertical: i32) -> Result<(), String> {
            if vertical == 0 && horizontal == 0 {
                return Ok(());
            }
            let event =
                unsafe { CGEventCreateScrollWheelEvent(self.source, SCROLL_LINE, 1, vertical) };
            if event.is_null() {
                return Err("CoreGraphics could not create a scroll event".into());
            }
            if horizontal != 0 {
                unsafe { CGEventSetIntegerValueField(event, SCROLL_AXIS_2, i64::from(horizontal)) };
            }
            unsafe {
                CGEventPost(HID_EVENT_TAP, event);
                CFRelease(event.cast());
            }
            Ok(())
        }

        pub(super) fn release_all(&mut self) -> Result<(), String> {
            let keys = self.active_keys.clone();
            for keycode in keys {
                let event = unsafe { CGEventCreateKeyboardEvent(self.source, keycode, false) };
                post(event)?;
            }
            self.active_keys.clear();
            for index in 0..self.active_buttons.len() {
                if self.active_buttons[index] {
                    self.button(u32::try_from(index + 1).unwrap_or(1), false)?;
                }
            }
            Ok(())
        }
    }

    impl Drop for MacInput {
        fn drop(&mut self) {
            unsafe { CFRelease(self.source.cast()) };
        }
    }

    fn post(event: EventRef) -> Result<(), String> {
        if event.is_null() {
            return Err("CoreGraphics could not create an input event".into());
        }
        unsafe {
            CGEventPost(HID_EVENT_TAP, event);
            CFRelease(event.cast());
        }
        Ok(())
    }

    fn current_point() -> Result<Point, String> {
        let event = unsafe { CGEventCreate(std::ptr::null_mut()) };
        if event.is_null() {
            return Err("CoreGraphics could not read the pointer position".into());
        }
        let point = unsafe { CGEventGetLocation(event) };
        unsafe { CFRelease(event.cast()) };
        Ok(point)
    }

    fn mouse_button(button: u32, pressed: bool) -> Option<(u32, u32)> {
        match button {
            1 => Some((if pressed { LEFT_DOWN } else { LEFT_UP }, MOUSE_LEFT)),
            2 => Some((if pressed { OTHER_DOWN } else { OTHER_UP }, MOUSE_CENTER)),
            3 => Some((if pressed { RIGHT_DOWN } else { RIGHT_UP }, MOUSE_RIGHT)),
            _ => None,
        }
    }

    /// Map common USB HID usages to the ANSI macOS virtual-key table.
    fn keycode(usage: u32) -> Option<u16> {
        let keycode = match usage {
            0x04 => 0x00,
            0x05 => 0x0b,
            0x06 => 0x08,
            0x07 => 0x02,
            0x08 => 0x0e,
            0x09 => 0x03,
            0x0a => 0x05,
            0x0b => 0x04,
            0x0c => 0x22,
            0x0d => 0x26,
            0x0e => 0x28,
            0x0f => 0x25,
            0x10 => 0x2e,
            0x11 => 0x2d,
            0x12 => 0x1f,
            0x13 => 0x23,
            0x14 => 0x0c,
            0x15 => 0x0f,
            0x16 => 0x01,
            0x17 => 0x11,
            0x18 => 0x20,
            0x19 => 0x09,
            0x1a => 0x0d,
            0x1b => 0x07,
            0x1c => 0x10,
            0x1d => 0x06,
            0x1e => 0x12,
            0x1f => 0x13,
            0x20 => 0x14,
            0x21 => 0x15,
            0x22 => 0x17,
            0x23 => 0x16,
            0x24 => 0x1a,
            0x25 => 0x1c,
            0x26 => 0x19,
            0x27 => 0x1d,
            0x28 => 0x24,
            0x29 => 0x35,
            0x2a => 0x33,
            0x2b => 0x30,
            0x2c => 0x31,
            0x2d => 0x1b,
            0x2e => 0x18,
            0x2f => 0x21,
            0x30 => 0x1e,
            0x31 => 0x2a,
            0x33 => 0x29,
            0x34 => 0x27,
            0x35 => 0x32,
            0x36 => 0x2b,
            0x37 => 0x2f,
            0x38 => 0x2c,
            0x39 => 0x39,
            0x3a => 0x7a,
            0x3b => 0x78,
            0x3c => 0x63,
            0x3d => 0x76,
            0x3e => 0x60,
            0x3f => 0x61,
            0x40 => 0x62,
            0x41 => 0x64,
            0x42 => 0x65,
            0x43 => 0x6d,
            0x44 => 0x67,
            0x45 => 0x6f,
            0x49 => 0x72,
            0x4a => 0x73,
            0x4b => 0x74,
            0x4c => 0x75,
            0x4d => 0x77,
            0x4e => 0x79,
            0x4f => 0x7c,
            0x50 => 0x7b,
            0x51 => 0x7d,
            0x52 => 0x7e,
            0x53 => 0x47,
            0x54 => 0x4b,
            0x55 => 0x43,
            0x56 => 0x4e,
            0x57 => 0x45,
            0x58 => 0x24,
            0xe0 => 0x3b,
            0xe1 => 0x38,
            0xe2 => 0x3a,
            0xe3 => 0x37,
            0xe4 => 0x3e,
            0xe5 => 0x3c,
            0xe6 => 0x3d,
            0xe7 => 0x36,
            _ => return None,
        };
        Some(keycode)
    }
}

#[cfg(target_os = "macos")]
use macos::MacInput;

#[cfg(test)]
mod tests {
    use openstream_media::input::InputEvent;

    #[test]
    fn malformed_input_is_rejected_before_platform_translation() {
        let bytes = InputEvent::release(0).encode();
        assert!(InputEvent::decode(&bytes[..31]).is_err());
    }
}
