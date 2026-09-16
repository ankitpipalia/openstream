//! Process-wide Media Foundation startup, shared by the decoder and encoder.

#![cfg(target_os = "windows")]

use std::sync::Once;
use std::sync::atomic::{AtomicI32, Ordering};

use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::Media::MediaFoundation::{MF_VERSION, MFSTARTUP_NOSOCKET, MFStartup};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};

/// Prepare the calling thread for Media Foundation work: join the COM
/// multithreaded apartment (the MFTs are in-process COM servers) and make sure
/// Media Foundation is started. Call it on any thread that creates a decoder
/// or encoder. A thread already initialised into a different apartment keeps
/// it; that is not an error for MFT creation, so it is not reported as one.
pub fn prepare_media_thread() -> windows::core::Result<()> {
    // SAFETY: FFI. No reserved pointer; the apartment flag is a documented
    // value. The call returns an `HRESULT` and touches nothing else.
    let code = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if code.is_err() && code != RPC_E_CHANGED_MODE {
        return Err(code.into());
    }
    ensure_media_foundation_started()
}

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
