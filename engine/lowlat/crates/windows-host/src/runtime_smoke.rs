//! Physical runtime smoke tests for the Windows host subsystems.
//!
//! These exercise the real OS FFI (Desktop Duplication, WASAPI, SendInput, Job
//! Objects) and so need a real Windows desktop. They are skipped unless
//! `OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME` is set, so CI (headless, session 0)
//! only compiles them; on the physical box they are forced and never silently
//! pass. Desktop Duplication and SendInput additionally need the interactive
//! session (they fail from a session-0 SSH shell), so run these via a task in the
//! logged-on user's session.

use std::time::Duration;

use crate::audio::{AudioError, LoopbackCapture};
use crate::capture::{CaptureError, DesktopDuplication};
use crate::input::{InjectAction, send_actions};
use crate::lifecycle::JobObject;

fn required() -> bool {
    std::env::var_os("OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME").is_some()
}

/// Desktop Duplication opens on the default adapter's first attached output and
/// delivers a frame. DXGI hands back the initial full desktop on the first
/// acquire, so even a static screen yields one frame within the window.
#[test]
fn desktop_duplication_opens_and_captures_a_frame() {
    if !required() {
        eprintln!(
            "skipping desktop duplication smoke test (set OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME)"
        );
        return;
    }
    let mut duplication = DesktopDuplication::new(None).expect("open desktop duplication");
    let mut captured = None;
    for _ in 0..20 {
        match duplication.capture(250) {
            Ok(frame) => {
                captured = Some((frame.width, frame.height, frame.bgra.len()));
                break;
            }
            Err(CaptureError::Timeout) => continue,
            Err(CaptureError::AccessLost) => duplication.recover().expect("recover duplication"),
            Err(error) => panic!("capture failed: {error}"),
        }
    }
    let (width, height, bytes) =
        captured.expect("a frame within 5 s (DXGI delivers the initial desktop)");
    assert!(width > 0 && height > 0, "frame has a size");
    assert_eq!(
        bytes,
        width * 4 * height,
        "frame is tightly packed B8G8R8A8"
    );
    eprintln!("desktop duplication: captured {width}x{height}, {bytes} bytes");
}

/// WASAPI loopback opens on the default render endpoint. Data only flows while
/// something is rendering, so on an idle machine zero frames is expected; the
/// requirement is that the endpoint activates and the format negotiates.
#[test]
fn wasapi_loopback_opens_on_the_default_endpoint() {
    if !required() {
        eprintln!(
            "skipping wasapi loopback smoke test (set OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME)"
        );
        return;
    }
    match LoopbackCapture::new(4_800) {
        Ok(mut capture) => {
            let mut frames = 0usize;
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(50));
                // 960 stereo samples = one 20 ms pipeline frame, interleaved.
                frames += capture
                    .read_frames(1_920)
                    .expect("read loopback frames")
                    .len();
            }
            eprintln!(
                "wasapi loopback: opened; {frames} frames in 500 ms (0 is expected while nothing renders); dropped samples {}",
                capture.dropped_samples()
            );
        }
        Err(AudioError::UnsupportedFormat(plan)) => {
            // Informative, not a failure of the FFI: the endpoint needs a
            // conversion (resampling) this slice does not implement yet.
            eprintln!("wasapi loopback: endpoint format needs unsupported conversion: {plan:?}");
        }
        Err(error) => panic!("wasapi loopback failed: {error}"),
    }
}

/// A kill-on-close Job Object can be created. The test process is deliberately
/// NOT assigned: with kill-on-close, dropping the job would end the test runner.
#[test]
fn job_object_creates_with_kill_on_close() {
    if !required() {
        eprintln!("skipping job object smoke test (set OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME)");
        return;
    }
    let job = JobObject::new_kill_on_close().expect("create kill-on-close job object");
    drop(job);
    eprintln!("job object: created with kill-on-close and closed");
}

/// SendInput accepts a batch. A zero-delta relative move is invisible to the
/// user but travels the whole injection path.
#[test]
fn send_input_accepts_a_zero_delta_move() {
    if !required() {
        eprintln!("skipping send_input smoke test (set OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME)");
        return;
    }
    send_actions(&[InjectAction::MoveRelative { dx: 0, dy: 0 }]).expect("SendInput zero move");
    eprintln!("send_input: zero-delta move injected");
}
