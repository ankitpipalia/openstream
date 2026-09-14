//! Raw pointer capture for immersive sessions.
//!
//! The portable immersive path differences successive window positions, and
//! those positions are clamped to the window. Once the local pointer reaches
//! an edge the differences go to zero, so a remote turn stops even though the
//! physical mouse is still moving -- the exact case pointer capture exists to
//! serve.
//!
//! On macOS the platform will report device motion directly and decouple the
//! visible cursor from it, which removes the edge entirely. Everywhere else
//! this is a no-op and the caller keeps its existing behaviour; nothing here
//! changes the wire event, only where the delta comes from.

/// A pointer capture that follows window focus. Dropping it restores the
/// cursor.
///
/// Capture is deliberately tied to focus rather than to process lifetime. It
/// hides the cursor and detaches it from the device system-wide, so holding
/// it while the user is working in another window would take their pointer
/// away with nothing on screen to explain it.
#[derive(Debug)]
pub(crate) struct RawPointer {
    /// Whether the session wants raw input at all.
    wanted: bool,
    /// Whether the platform capture is held right now.
    active: bool,
    /// Whether a capture was ever obtainable; false means the platform does
    /// not support it and the caller should stay on its fallback.
    supported: bool,
}

impl RawPointer {
    /// Try to take raw pointer input. Returns a capture that reports itself
    /// inactive when the platform cannot provide one, so callers can fall
    /// back without branching on the target.
    pub(crate) fn capture() -> Self {
        let active = platform::capture();
        Self {
            wanted: true,
            active,
            supported: active,
        }
    }

    /// A capture that was never taken. Used when immersive mode is off, so
    /// the field is always present and never optional at the use site.
    pub(crate) fn inactive() -> Self {
        Self {
            wanted: false,
            active: false,
            supported: false,
        }
    }

    /// Track window focus: hold the capture only while the window is active.
    /// Releasing on focus loss is what stops a background client from
    /// keeping the pointer hidden.
    pub(crate) fn follow_focus(&mut self, focused: bool) {
        if !self.wanted || !self.supported {
            return;
        }
        match (self.active, focused) {
            (false, true) => self.active = platform::capture(),
            (true, false) => {
                platform::release();
                self.active = false;
            }
            _ => {}
        }
    }

    /// Whether raw deltas are actually being delivered.
    pub(crate) fn is_active(&self) -> bool {
        self.active
    }

    /// Device motion since the previous call, or `None` when no capture is
    /// held. A held capture with no movement reports `Some((0, 0))`, which
    /// the caller drops; that is deliberately distinct from "no capture".
    pub(crate) fn delta(&self) -> Option<(i32, i32)> {
        if !self.active {
            return None;
        }
        Some(platform::delta())
    }
}

impl Drop for RawPointer {
    fn drop(&mut self) {
        if self.active {
            platform::release();
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    // CoreGraphics event services. These are plain C entry points in the
    // ApplicationServices umbrella framework, so no Objective-C runtime
    // binding is needed to reach them.
    type CgError = i32;
    type CgDirectDisplayId = u32;

    const CG_ERROR_SUCCESS: CgError = 0;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGAssociateMouseAndMouseCursorPosition(connected: u32) -> CgError;
        fn CGGetLastMouseDelta(delta_x: *mut i32, delta_y: *mut i32);
        fn CGDisplayHideCursor(display: CgDirectDisplayId) -> CgError;
        fn CGDisplayShowCursor(display: CgDirectDisplayId) -> CgError;
        fn CGMainDisplayID() -> CgDirectDisplayId;
    }

    pub(super) fn capture() -> bool {
        // Disassociating is what makes the delta unbounded: the cursor stops
        // tracking the device, so it can no longer reach a screen edge and
        // stop producing motion.
        let disassociated = unsafe { CGAssociateMouseAndMouseCursorPosition(0) };
        if disassociated != CG_ERROR_SUCCESS {
            return false;
        }
        // Hiding is cosmetic and must not decide whether capture succeeded:
        // a visible local cursor over the stream is untidy, not broken.
        unsafe {
            CGDisplayHideCursor(CGMainDisplayID());
        }
        // Clear whatever motion accumulated before capture, so the first
        // reported delta is movement the user made while captured.
        let mut x = 0;
        let mut y = 0;
        unsafe { CGGetLastMouseDelta(&raw mut x, &raw mut y) };
        true
    }

    pub(super) fn delta() -> (i32, i32) {
        let mut x = 0;
        let mut y = 0;
        unsafe { CGGetLastMouseDelta(&raw mut x, &raw mut y) };
        (x, y)
    }

    pub(super) fn release() {
        unsafe {
            CGAssociateMouseAndMouseCursorPosition(1);
            CGDisplayShowCursor(CGMainDisplayID());
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub(super) fn capture() -> bool {
        false
    }

    pub(super) fn delta() -> (i32, i32) {
        (0, 0)
    }

    pub(super) fn release() {}
}

#[cfg(test)]
mod tests {
    use super::RawPointer;

    #[test]
    fn a_capture_that_is_not_active_reports_no_delta() {
        let pointer = RawPointer::inactive();
        assert_eq!(pointer.delta(), None);
        assert!(!pointer.is_active());
    }

    #[test]
    fn focus_changes_do_not_revive_a_capture_the_platform_never_gave() {
        // The fallback path must stay selected: claiming a capture on focus
        // would silently stop sending the deltas the caller does produce.
        let mut pointer = RawPointer::inactive();
        pointer.follow_focus(true);
        assert!(!pointer.is_active());
        pointer.follow_focus(false);
        assert!(!pointer.is_active());
    }

    #[test]
    fn losing_focus_releases_a_held_capture() {
        let mut pointer = RawPointer {
            wanted: true,
            active: true,
            supported: true,
        };
        pointer.follow_focus(false);
        assert!(!pointer.is_active(), "focus loss must hand the cursor back");
        assert_eq!(pointer.delta(), None);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn platforms_without_support_never_claim_a_capture() {
        let pointer = RawPointer::capture();
        assert!(!pointer.is_active());
        assert_eq!(pointer.delta(), None);
    }
}
