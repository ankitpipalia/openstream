//! Fullscreen presentation for window modes that ask for it.
//!
//! `WindowOptions::borderless` is honoured by minifb on Wayland, X11 and
//! Windows, and silently dropped on macOS: its macOS backend never reads the
//! flag. So a client started in a fullscreen or borderless mode came up as an
//! ordinary titled window there, with no error to say why.
//!
//! macOS has a better answer than borderless anyway. Asking the window to
//! enter the system's own fullscreen gives a real fullscreen space with the
//! menu bar and Dock out of the way, which is what the mode was asking for.
//! Everywhere else this is a no-op, because the flag already works.

/// Put the window into the platform's fullscreen presentation.
///
/// Returns whether the request was made. A `false` here is not an error: it
/// means this platform already handles the mode through window options.
pub(crate) fn enter(window_handle: *mut std::ffi::c_void) -> bool {
    platform::enter(window_handle)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{CString, c_void};

    #[link(name = "objc")]
    unsafe extern "C" {
        fn sel_registerName(name: *const std::ffi::c_char) -> *const c_void;
        fn objc_msgSend();
    }

    /// `objc_msgSend` has no single C prototype: every call site casts it to
    /// the signature of the method being sent. This is the one shape used
    /// here, a selector taking a single object argument.
    type SendOneArgument = unsafe extern "C" fn(*mut c_void, *const c_void, *mut c_void);

    pub(super) fn enter(window_handle: *mut c_void) -> bool {
        if window_handle.is_null() {
            return false;
        }
        let Ok(selector_name) = CString::new("toggleFullScreen:") else {
            return false;
        };
        // SAFETY: the handle is the NSWindow minifb reports for this window,
        // the selector is a valid null-terminated name, and the cast matches
        // `- (void)toggleFullScreen:(id)sender`. minifb creates and owns the
        // window on this thread, which is the main thread, as AppKit
        // requires for window state changes.
        unsafe {
            let selector = sel_registerName(selector_name.as_ptr());
            if selector.is_null() {
                return false;
            }
            let send: SendOneArgument = std::mem::transmute(objc_msgSend as *const ());
            send(window_handle, selector, std::ptr::null_mut());
        }
        true
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::ffi::c_void;

    pub(super) fn enter(_window_handle: *mut c_void) -> bool {
        // Wayland, X11 and Windows all honour WindowOptions::borderless, so
        // the mode is already applied by the time the window exists.
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_null_window_is_refused_rather_than_sent_a_message() {
        assert!(!super::enter(std::ptr::null_mut()));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn platforms_that_honour_the_window_option_report_no_action() {
        let mut placeholder = 0_u8;
        let handle = (&raw mut placeholder).cast();
        assert!(!super::enter(handle));
    }
}
