//! Process-wide Media Foundation startup, shared by the decoder and encoder.

#![cfg(target_os = "windows")]

use std::sync::Once;
use std::sync::atomic::{AtomicI32, Ordering};

use windows::Win32::Media::MediaFoundation::{MF_VERSION, MFSTARTUP_NOSOCKET, MFStartup};

/// Start Media Foundation once for the process and cache the result.
///
/// `MFStartup` is reference counted, but this library only ever needs it
/// running; starting it once and never shutting it down avoids racing a
/// shutdown against a codec on another thread. The resulting `HRESULT` is
/// cached so a second decoder or encoder observes the same outcome.
pub(crate) fn ensure_media_foundation_started() -> windows::core::Result<()> {
    static START: Once = Once::new();
    static CODE: AtomicI32 = AtomicI32::new(0);
    START.call_once(|| {
        // SAFETY: FFI. `MFStartup` takes a version and flags and returns an
        // `HRESULT`; no pointers are involved.
        let code = match unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) } {
            Ok(()) => 0,
            Err(error) => error.code().0,
        };
        CODE.store(code, Ordering::SeqCst);
    });
    windows::core::HRESULT(CODE.load(Ordering::SeqCst)).ok()
}
