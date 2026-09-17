//! The Linux input [`InputSink`], backed by `lowlat-inject`'s `uinput` devices.
//!
//! It decodes the `openstream-media` input payloads the service forwards and
//! injects the events the session's granted capabilities permit, below the
//! display server so it works at the greeter too. The capability check is done
//! here, at the privileged boundary: even though the service already clamped the
//! grant, the broker re-derives keyboard/mouse/gamepad permission from the grant
//! it was given and refuses anything outside it, so a bug or compromise upstream
//! cannot drive a device the grant does not cover. If `/dev/uinput` is not
//! available the sink degrades to a no-op and capture still runs.

#![cfg(target_os = "linux")]

use std::time::Instant;

use lowlat_core::control::{self, Control, op};
use lowlat_inject::event::{Extents, Injector, Permissions};
use lowlat_inject::uinput::Devices;
use openstream_host_ipc::token::Capabilities;
use openstream_media::input::{InputCapability, InputEvent, InputKind, InputLease, MotionGate};

use crate::device::{InputSink, RumbleOut};

/// How long after the last input the sink releases any held keys/buttons, so a
/// peer that vanished mid-press does not strand them down. Milliseconds.
const LEASE_MS: u64 = 2_000;

/// A native input sink over virtual `uinput` devices.
pub struct NativeInputSink {
    /// The devices and permission-aware translator, or `None` when `uinput` is
    /// unavailable (the sink then drops every event).
    devices: Option<(Injector, Devices)>,
    motion: MotionGate,
    lease: InputLease,
    started: Instant,
    /// The last permission triple pushed to the injector, so it is only
    /// reconfigured when the grant actually changes.
    last_grants: Option<(bool, bool, bool)>,
}

impl std::fmt::Debug for NativeInputSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeInputSink")
            .field("uinput_available", &self.devices.is_some())
            .field("last_grants", &self.last_grants)
            .finish_non_exhaustive()
    }
}

impl Default for NativeInputSink {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeInputSink {
    /// Create the sink, opening `uinput` devices if permitted. Never fails: if
    /// the devices cannot be created the sink is a no-op and capture continues.
    #[must_use]
    pub fn new() -> Self {
        // The absolute-pointer extents default to a common desktop size; the
        // machine service negotiates capture near this, and relative motion is
        // unaffected. Tracking the exact capture geometry is a follow-up.
        let devices = match Devices::create("openstream") {
            Ok(devices) => Some((Injector::new(Extents::alone(1920, 1080)), devices)),
            Err(error) => {
                eprintln!("openstream-host-broker: input disabled ({error:?})");
                None
            }
        };
        Self {
            devices,
            motion: MotionGate::default(),
            lease: InputLease::new(LEASE_MS.saturating_mul(1_000)),
            started: Instant::now(),
            last_grants: None,
        }
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

/// Map a capability grant to the keyboard/mouse/gamepad permission triple the
/// injector understands.
fn grants(granted: Capabilities) -> (bool, bool, bool) {
    (
        granted.contains(Capabilities::KEYBOARD),
        granted.contains(Capabilities::MOUSE),
        granted.contains(Capabilities::GAMEPAD),
    )
}

/// Whether the grant permits this event, by adapter family. Release is always
/// allowed so a host can let go of what it is already holding; tablet is not
/// modelled as a grant yet, so pen events are refused.
fn event_allowed(event: InputEvent, keyboard: bool, mouse: bool, gamepad: bool) -> bool {
    match event.kind.capability() {
        InputCapability::BasicInput => match event.kind {
            InputKind::Keyboard => keyboard,
            InputKind::PointerMotion | InputKind::PointerButton | InputKind::Wheel => mouse,
            InputKind::Release => true,
            _ => false,
        },
        InputCapability::Gamepad => gamepad,
        InputCapability::Tablet => false,
    }
}

impl InputSink for NativeInputSink {
    fn inject(&mut self, payload: &[u8], granted: Capabilities) {
        let (keyboard, mouse, gamepad) = grants(granted);
        let now_us = self.now_us();
        let Some((injector, devices)) = self.devices.as_mut() else {
            return;
        };

        // Reconfigure the injector only when the grant changed (e.g. across a
        // greeter<->user switch), so the enabled devices track the grant.
        if self.last_grants != Some((keyboard, mouse, gamepad)) {
            injector.set_permissions(
                Permissions::from_keyboard_pointer_grants(keyboard, mouse, gamepad),
                devices,
            );
            self.last_grants = Some((keyboard, mouse, gamepad));
        }

        if let Ok(event) = InputEvent::decode(payload) {
            // Drop stale out-of-order motion, then enforce the grant, then act.
            if !self.motion.admit(event) {
                return;
            }
            if !event_allowed(event, keyboard, mouse, gamepad) {
                return;
            }
            if matches!(event.kind, InputKind::Release) {
                self.lease.disarm();
            } else {
                self.lease.renew(now_us);
            }
            let fields = event.lowlat_fields();
            if fields.opcode == op::RELEASE {
                injector.release_all(devices);
                return;
            }
            let control = Control {
                a0: fields.a0,
                a1: fields.a1,
                a2: fields.a2,
                opcode: fields.opcode,
                body: &[],
            };
            let mut encoded = [0_u8; control::CONTROL_HEADER_LEN];
            if control::encode_header(&mut encoded, &control).is_ok()
                && let Ok(parsed) = control::parse(&encoded)
            {
                injector.on_control(&parsed, devices);
            }
            return;
        }

        // Older clients send the raw lowlat control payload directly.
        if let Ok(control) = control::parse(payload) {
            if control.opcode == op::RELEASE {
                self.lease.disarm();
            } else {
                self.lease.renew(now_us);
            }
            injector.on_control(&control, devices);
        }
    }

    fn take_rumble(&mut self) -> Option<RumbleOut> {
        let now_us = self.now_us();
        let (injector, devices) = self.devices.as_mut()?;
        // A peer that went silent mid-press must not strand held keys/buttons.
        if self.lease.poll_expiry(now_us).is_some() {
            injector.release_all(devices);
        }
        devices.tick();
        devices.rumble().map(|rumble| RumbleOut {
            device_id: u8::try_from(rumble.pad).unwrap_or(0),
            strong: u16::from(rumble.large),
            weak: u16::from(rumble.small),
        })
    }
}
