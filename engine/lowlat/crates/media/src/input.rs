//! Versioned cross-platform input events.
//!
//! This is the application-owned input seam. Platform clients encode HID
//! usages, pointer coordinates, and gamepad values here; a host translates
//! the event into its local input API. The fixed 32-byte form is small enough
//! for the reliable control channel and has no platform-specific ABI.

/// Relative-pointer bit for [`InputKind::PointerMotion`].
pub const FLAG_RELATIVE: u16 = 0x0001;
/// Eraser-end bit for [`InputKind::PenMotion`]: the inverted end is down.
pub const FLAG_PEN_ERASER: u16 = 0x0002;
/// Maximum pen pressure carried by [`InputKind::PenMotion::code`].
pub const PEN_PRESSURE_MAX: u32 = 8191;
const MAGIC: [u8; 2] = *b"OI";
const VERSION: u8 = 1;
const EVENT_LEN: usize = 32;
const RUMBLE_MAGIC: [u8; 2] = *b"OR";
const RUMBLE_VERSION: u8 = 1;
/// Fixed-size host-to-client force-feedback message.
pub const RUMBLE_LEN: usize = 12;

/// Input event kinds supported by the initial client bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InputKind {
    Keyboard = 1,
    PointerMotion = 2,
    PointerButton = 3,
    Wheel = 4,
    GamepadButton = 5,
    GamepadAxis = 6,
    Release = 7,
    GamepadUnplug = 8,
    /// Absolute pen/stylus position. `value`/`value2` are output coordinates,
    /// `code` is pressure 0..=8191, `device_id` is the tablet, and
    /// `FLAG_PEN_ERASER` marks the inverted end. Tilt is not carried in v1.
    PenMotion = 9,
    /// Pen barrel/tip button. `code` is the button index, `value` is pressed.
    PenButton = 10,
    /// Pen in/out of hover range. `value` is non-zero while in range.
    PenProximity = 11,
}

impl TryFrom<u8> for InputKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Keyboard),
            2 => Ok(Self::PointerMotion),
            3 => Ok(Self::PointerButton),
            4 => Ok(Self::Wheel),
            5 => Ok(Self::GamepadButton),
            6 => Ok(Self::GamepadAxis),
            7 => Ok(Self::Release),
            8 => Ok(Self::GamepadUnplug),
            9 => Ok(Self::PenMotion),
            10 => Ok(Self::PenButton),
            11 => Ok(Self::PenProximity),
            _ => Err(Error::UnknownKind(value)),
        }
    }
}

/// One platform-independent input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub kind: InputKind,
    /// Modifier bits for keyboards or pad identifier for gamepads.
    pub flags: u16,
    pub device_id: u32,
    /// HID usage, mouse button number, or gamepad axis/button number.
    pub code: u32,
    /// Press state, horizontal coordinate/delta, wheel amount, or axis value.
    pub value: i32,
    /// Vertical coordinate/delta or vertical wheel amount.
    pub value2: i32,
    /// Client monotonic timestamp, in microseconds, for diagnostics/order.
    pub timestamp_us: u64,
}

/// The legacy lowlat control fields a host adapter can consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowlatFields {
    pub opcode: u8,
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
}

impl InputEvent {
    /// Encode the bounded wire representation.
    pub fn encode(self) -> [u8; EVENT_LEN] {
        let mut out = [0_u8; EVENT_LEN];
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = VERSION;
        out[3] = self.kind as u8;
        out[4..6].copy_from_slice(&self.flags.to_be_bytes());
        out[6..10].copy_from_slice(&self.device_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.code.to_be_bytes());
        out[14..18].copy_from_slice(&self.value.to_be_bytes());
        out[18..22].copy_from_slice(&self.value2.to_be_bytes());
        out[22..30].copy_from_slice(&self.timestamp_us.to_be_bytes());
        // 30..32 is reserved and remains zero for forward compatibility.
        out
    }

    /// Decode one event after the outer authenticated transport.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != EVENT_LEN {
            return Err(Error::BadLength);
        }
        if bytes[..2] != MAGIC {
            return Err(Error::BadMagic);
        }
        if bytes[2] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[2]));
        }
        if bytes[30..32] != [0, 0] {
            return Err(Error::ReservedBits);
        }
        Ok(Self {
            kind: InputKind::try_from(bytes[3])?,
            flags: u16::from_be_bytes(bytes[4..6].try_into().expect("input header is checked")),
            device_id: u32::from_be_bytes(
                bytes[6..10].try_into().expect("input header is checked"),
            ),
            code: u32::from_be_bytes(bytes[10..14].try_into().expect("input header is checked")),
            value: i32::from_be_bytes(bytes[14..18].try_into().expect("input header is checked")),
            value2: i32::from_be_bytes(bytes[18..22].try_into().expect("input header is checked")),
            timestamp_us: u64::from_be_bytes(
                bytes[22..30].try_into().expect("input header is checked"),
            ),
        })
    }

    /// Construct a keyboard usage event.
    pub const fn keyboard(usage: u32, modifiers: u16, pressed: bool, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::Keyboard,
            flags: modifiers,
            device_id: 0,
            code: usage,
            value: pressed as i32,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct a relative or absolute pointer motion event.
    pub const fn pointer_motion(relative: bool, x: i32, y: i32, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::PointerMotion,
            flags: if relative { FLAG_RELATIVE } else { 0 },
            device_id: 0,
            code: 0,
            value: x,
            value2: y,
            timestamp_us,
        }
    }

    /// Construct a mouse button event; buttons are numbered from one.
    pub const fn pointer_button(button: u32, pressed: bool, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::PointerButton,
            flags: 0,
            device_id: 0,
            code: button,
            value: pressed as i32,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct a horizontal/vertical wheel event.
    pub const fn wheel(x: i32, y: i32, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::Wheel,
            flags: 0,
            device_id: 0,
            code: 0,
            value: x,
            value2: y,
            timestamp_us,
        }
    }

    /// Construct a gamepad button event.
    pub const fn gamepad_button(pad: u32, button: u32, pressed: bool, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::GamepadButton,
            flags: 0,
            device_id: pad,
            code: button,
            value: pressed as i32,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct a gamepad axis event. Values use signed 16-bit stick units.
    pub const fn gamepad_axis(pad: u32, axis: u32, value: i32, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::GamepadAxis,
            flags: 0,
            device_id: pad,
            code: axis,
            value,
            value2: 0,
            timestamp_us,
        }
    }

    /// Tell the host that a previously announced gamepad disappeared.
    pub const fn gamepad_unplug(pad: u32, timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::GamepadUnplug,
            flags: 0,
            device_id: pad,
            code: 0,
            value: 0,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct an absolute pen position event. Pressure above
    /// [`PEN_PRESSURE_MAX`] is clamped; set `eraser` for the inverted end.
    pub const fn pen_motion(
        tablet: u32,
        x: i32,
        y: i32,
        pressure: u32,
        eraser: bool,
        timestamp_us: u64,
    ) -> Self {
        Self {
            kind: InputKind::PenMotion,
            flags: if eraser { FLAG_PEN_ERASER } else { 0 },
            device_id: tablet,
            code: if pressure > PEN_PRESSURE_MAX {
                PEN_PRESSURE_MAX
            } else {
                pressure
            },
            value: x,
            value2: y,
            timestamp_us,
        }
    }

    /// Construct a pen button event (`button` 0 is tip).
    pub const fn pen_button(tablet: u32, button: u32, pressed: bool, timestamp_us: u64) -> Self {
        let pressed = pressed as i32;
        Self {
            kind: InputKind::PenButton,
            flags: 0,
            device_id: tablet,
            code: button,
            value: pressed,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct a pen hover-range event.
    pub const fn pen_proximity(tablet: u32, in_range: bool, timestamp_us: u64) -> Self {
        let in_range = in_range as i32;
        Self {
            kind: InputKind::PenProximity,
            flags: 0,
            device_id: tablet,
            code: 0,
            value: in_range,
            value2: 0,
            timestamp_us,
        }
    }

    /// Construct a focus-loss release event.
    pub const fn release(timestamp_us: u64) -> Self {
        Self {
            kind: InputKind::Release,
            flags: 0,
            device_id: 0,
            code: 0,
            value: 0,
            value2: 0,
            timestamp_us,
        }
    }

    /// Translate the project-owned event into the imported lowlat field
    /// layout without depending on Linux or the lowlat crate.
    #[must_use]
    pub fn lowlat_fields(self) -> LowlatFields {
        let (opcode, a0, a1, a2) = match self.kind {
            InputKind::Keyboard => (
                0,
                self.code,
                u32::from(self.flags),
                u32::from(self.value != 0),
            ),
            InputKind::PointerMotion => (
                3,
                u32::from(self.flags & FLAG_RELATIVE != 0),
                u32::from_ne_bytes(self.value.to_ne_bytes()),
                u32::from_ne_bytes(self.value2.to_ne_bytes()),
            ),
            InputKind::PointerButton => (1, self.code, u32::from(self.value != 0), 0),
            InputKind::Wheel => (
                2,
                u32::from_ne_bytes(self.value.to_ne_bytes()),
                u32::from_ne_bytes(self.value2.to_ne_bytes()),
                0,
            ),
            InputKind::GamepadButton => (4, self.code, u32::from(self.value != 0), self.device_id),
            InputKind::GamepadAxis => {
                let clamped = self.value.clamp(i32::from(i16::MIN), i32::from(i16::MAX));
                let value = i16::try_from(clamped).unwrap_or_default();
                let encoded = u16::from_ne_bytes(value.to_ne_bytes());
                (5, self.code, u32::from(encoded), self.device_id)
            }
            InputKind::Release => (24, 0, 0, 0),
            InputKind::GamepadUnplug => (6, 0, 0, self.device_id),
            // Pen travels as absolute pointer motion through the existing
            // virtual mouse/tablet path: coordinates survive, pressure and
            // tilt do not (the injector has no PEN_TOUCH handler yet).
            InputKind::PenMotion => (
                3,
                0,
                u32::from_ne_bytes(self.value.to_ne_bytes()),
                u32::from_ne_bytes(self.value2.to_ne_bytes()),
            ),
            InputKind::PenButton => (1, self.code, u32::from(self.value != 0), 0),
            // Hover range carries no host action by itself (motion follows
            // while in range; nothing is held while out). It maps to the
            // inert user-data opcode so the translation stays total without
            // ever releasing unrelated input.
            InputKind::PenProximity => (17, 0, 0, 0),
        };
        LowlatFields { opcode, a0, a1, a2 }
    }
}

/// One host-to-client force-feedback update.
///
/// The values are eight-bit motor magnitudes, matching the smallest common
/// representation across Linux uinput, Windows gamepad APIs, macOS HID
/// devices, and mobile haptics. A zero update stops both motors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RumbleEvent {
    pub device_id: u32,
    pub strong: u8,
    pub weak: u8,
}

impl RumbleEvent {
    /// Encode a bounded force-feedback update.
    pub fn encode(self) -> [u8; RUMBLE_LEN] {
        let mut out = [0_u8; RUMBLE_LEN];
        out[0..2].copy_from_slice(&RUMBLE_MAGIC);
        out[2] = RUMBLE_VERSION;
        out[4..8].copy_from_slice(&self.device_id.to_be_bytes());
        out[8] = self.strong;
        out[9] = self.weak;
        out
    }

    /// Decode one force-feedback update after outer authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self, RumbleError> {
        if bytes.len() != RUMBLE_LEN {
            return Err(RumbleError::BadLength);
        }
        if bytes[..2] != RUMBLE_MAGIC {
            return Err(RumbleError::BadMagic);
        }
        if bytes[2] != RUMBLE_VERSION {
            return Err(RumbleError::UnsupportedVersion(bytes[2]));
        }
        if bytes[3] != 0 || bytes[10..12] != [0, 0] {
            return Err(RumbleError::ReservedBits);
        }
        Ok(Self {
            device_id: u32::from_be_bytes(bytes[4..8].try_into().expect("rumble header checked")),
            strong: bytes[8],
            weak: bytes[9],
        })
    }
}

/// Force-feedback framing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RumbleError {
    BadLength,
    BadMagic,
    UnsupportedVersion(u8),
    ReservedBits,
}

impl std::fmt::Display for RumbleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => f.write_str("rumble event length is not 12 bytes"),
            Self::BadMagic => f.write_str("rumble event magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported rumble event version {version}")
            }
            Self::ReservedBits => f.write_str("rumble event reserved bits are not zero"),
        }
    }
}

impl std::error::Error for RumbleError {}

/// Input framing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadLength,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    ReservedBits,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => f.write_str("input event length is not 32 bytes"),
            Self::BadMagic => f.write_str("input event magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported input event version {version}")
            }
            Self::UnknownKind(kind) => write!(f, "unknown input event kind {kind}"),
            Self::ReservedBits => f.write_str("input event reserved bits are not zero"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{FLAG_RELATIVE, InputEvent, InputKind, RumbleEvent};

    #[test]
    fn all_event_fields_round_trip_in_the_fixed_envelope() {
        let event = InputEvent {
            kind: InputKind::PointerMotion,
            flags: FLAG_RELATIVE,
            device_id: 7,
            code: 9,
            value: -120,
            value2: 240,
            timestamp_us: 123_456,
        };
        assert_eq!(InputEvent::decode(&event.encode()), Ok(event));
    }

    #[test]
    fn malformed_events_are_rejected_before_use() {
        let mut bytes = InputEvent::release(0).encode();
        bytes[0] = 0;
        assert_eq!(InputEvent::decode(&bytes), Err(super::Error::BadMagic));
        bytes = InputEvent::release(0).encode();
        bytes[30] = 1;
        assert_eq!(InputEvent::decode(&bytes), Err(super::Error::ReservedBits));
        assert_eq!(
            InputEvent::decode(&bytes[..31]),
            Err(super::Error::BadLength)
        );
    }

    #[test]
    fn project_events_translate_to_the_legacy_host_fields() {
        assert_eq!(
            InputEvent::keyboard(4, 0x2000, true, 0).lowlat_fields(),
            super::LowlatFields {
                opcode: 0,
                a0: 4,
                a1: 0x2000,
                a2: 1,
            }
        );
        assert_eq!(
            InputEvent::pointer_motion(true, -4, 7, 0).lowlat_fields(),
            super::LowlatFields {
                opcode: 3,
                a0: 1,
                a1: u32::MAX - 3,
                a2: 7,
            }
        );
        assert_eq!(
            InputEvent::gamepad_axis(9, 2, 100_000, 0).lowlat_fields(),
            super::LowlatFields {
                opcode: 5,
                a0: 2,
                a1: 32_767,
                a2: 9,
            }
        );
        assert_eq!(
            InputEvent::release(0).lowlat_fields(),
            super::LowlatFields {
                opcode: 24,
                a0: 0,
                a1: 0,
                a2: 0,
            }
        );
        assert_eq!(
            InputEvent::gamepad_unplug(3, 0).lowlat_fields(),
            super::LowlatFields {
                opcode: 6,
                a0: 0,
                a1: 0,
                a2: 3,
            }
        );
    }

    #[test]
    fn gamepad_unplug_round_trips_through_the_wire_envelope() {
        let event = InputEvent::gamepad_unplug(42, 987_654);
        assert_eq!(InputEvent::decode(&event.encode()), Ok(event));
    }

    #[test]
    fn pen_events_round_trip_and_translate_to_pointer_motion() {
        let motion = InputEvent::pen_motion(3, 1000, -2000, 9000, true, 7);
        assert_eq!(motion.code, super::PEN_PRESSURE_MAX);
        assert_eq!(motion.flags, super::FLAG_PEN_ERASER);
        assert_eq!(InputEvent::decode(&motion.encode()), Ok(motion));
        assert_eq!(
            motion.lowlat_fields(),
            super::LowlatFields {
                opcode: 3,
                a0: 0,
                a1: u32::from_ne_bytes(1000_i32.to_ne_bytes()),
                a2: u32::from_ne_bytes((-2000_i32).to_ne_bytes()),
            }
        );
        let button = InputEvent::pen_button(3, 0, true, 8);
        assert_eq!(InputEvent::decode(&button.encode()), Ok(button));
        assert_eq!(
            button.lowlat_fields(),
            super::LowlatFields {
                opcode: 1,
                a0: 0,
                a1: 1,
                a2: 0,
            }
        );
        let proximity = InputEvent::pen_proximity(3, false, 9);
        assert_eq!(InputEvent::decode(&proximity.encode()), Ok(proximity));
        // Hover range never releases unrelated held input.
        assert_eq!(proximity.lowlat_fields().opcode, 17);
    }

    #[test]
    fn rumble_round_trips_through_the_host_to_client_envelope() {
        let event = RumbleEvent {
            device_id: 42,
            strong: 211,
            weak: 37,
        };
        assert_eq!(RumbleEvent::decode(&event.encode()), Ok(event));
    }

    #[test]
    fn malformed_rumble_is_rejected_before_use() {
        let mut bytes = RumbleEvent {
            device_id: 1,
            strong: 2,
            weak: 3,
        }
        .encode();
        bytes[10] = 1;
        assert_eq!(
            RumbleEvent::decode(&bytes),
            Err(super::RumbleError::ReservedBits)
        );
        assert_eq!(
            RumbleEvent::decode(&bytes[..11]),
            Err(super::RumbleError::BadLength)
        );
    }
}
