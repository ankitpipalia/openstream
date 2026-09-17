//! Screen capture via CoreGraphics `CGDisplayCreateImage`.
//!
//! Everything here is `unsafe` FFI to CoreGraphics / CoreFoundation. Ownership
//! follows CoreFoundation's Create rule: the image and the copied data are
//! owned and released with `CFRelease`; the byte pointer into the copied data
//! is borrowed and read before that release.

#![cfg(target_os = "macos")]

use std::ffi::c_void;

/// The tightly packed BGRA bytes are copied out and returned to the caller so
/// the CoreGraphics objects can be released immediately.
pub fn pack_bgra_rows(src: &[u8], width: usize, height: usize, src_stride: usize) -> Vec<u8> {
    let row_bytes = width * 4;
    let mut out = vec![0u8; row_bytes * height];
    for row in 0..height {
        let from = row * src_stride;
        let to = row * row_bytes;
        // The last source row may be shorter than a full stride; copy only what
        // the image actually provides for this row.
        let take = row_bytes.min(src.len().saturating_sub(from));
        if take == 0 {
            break;
        }
        out[to..to + take].copy_from_slice(&src[from..from + take]);
    }
    out
}

/// One captured frame: tightly packed 32-bit BGRA, `width * height * 4` bytes.
#[derive(Clone)]
pub struct CapturedFrame {
    pub width: usize,
    pub height: usize,
    pub bgra: Vec<u8>,
}

impl std::fmt::Debug for CapturedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.bgra.len())
            .finish()
    }
}

/// Why a capture failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// The OS returned no image. The overwhelmingly common cause is a missing
    /// Screen Recording permission (TCC); it is also what a display with no
    /// framebuffer returns. Not a black frame -- the absence is reported.
    Unavailable,
    /// The image had no data provider or empty data.
    NoData,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Unavailable => f.write_str(
                "the display produced no image (grant Screen Recording permission, or no display is attached)",
            ),
            CaptureError::NoData => f.write_str("the captured image had no pixel data"),
        }
    }
}

impl std::error::Error for CaptureError {}

type CgDirectDisplayId = u32;
type CgImageRef = *mut c_void;
type CgDataProviderRef = *mut c_void;
type CfDataRef = *const c_void;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGMainDisplayID() -> CgDirectDisplayId;
    fn CGDisplayCreateImage(display: CgDirectDisplayId) -> CgImageRef;
    fn CGImageGetWidth(image: CgImageRef) -> usize;
    fn CGImageGetHeight(image: CgImageRef) -> usize;
    fn CGImageGetBytesPerRow(image: CgImageRef) -> usize;
    fn CGImageGetDataProvider(image: CgImageRef) -> CgDataProviderRef;
    fn CGDataProviderCopyData(provider: CgDataProviderRef) -> CfDataRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataGetBytePtr(data: CfDataRef) -> *const u8;
    fn CFDataGetLength(data: CfDataRef) -> isize;
    fn CFRelease(cf: *const c_void);
}

/// A screen-capture source bound to one display.
#[derive(Debug)]
pub struct ScreenCapture {
    display: CgDirectDisplayId,
}

impl ScreenCapture {
    /// Capture the main display.
    pub fn main() -> Self {
        // SAFETY: FFI. Returns the main display id; no pointers involved.
        Self {
            display: unsafe { CGMainDisplayID() },
        }
    }

    /// Bind to a specific display id (from CoreGraphics display enumeration).
    pub fn for_display(display: u32) -> Self {
        Self { display }
    }

    /// Capture one frame as tightly packed BGRA. Polling: each call snapshots
    /// the display as it is now.
    pub fn capture(&mut self) -> Result<CapturedFrame, CaptureError> {
        // SAFETY: FFI. CGDisplayCreateImage returns an owned image (or null);
        // the data provider and its copied data are read then released. The
        // byte pointer is valid until the CFData is released, which is after
        // the copy below.
        unsafe {
            let image = CGDisplayCreateImage(self.display);
            if image.is_null() {
                return Err(CaptureError::Unavailable);
            }
            let width = CGImageGetWidth(image);
            let height = CGImageGetHeight(image);
            let stride = CGImageGetBytesPerRow(image);
            let provider = CGImageGetDataProvider(image);
            if provider.is_null() || width == 0 || height == 0 {
                CFRelease(image.cast());
                return Err(CaptureError::NoData);
            }
            let data = CGDataProviderCopyData(provider);
            if data.is_null() {
                CFRelease(image.cast());
                return Err(CaptureError::NoData);
            }
            let pointer = CFDataGetBytePtr(data);
            let length = usize::try_from(CFDataGetLength(data)).unwrap_or(0);
            if pointer.is_null() || length == 0 {
                CFRelease(data.cast());
                CFRelease(image.cast());
                return Err(CaptureError::NoData);
            }
            let src = std::slice::from_raw_parts(pointer, length);
            let bgra = pack_bgra_rows(src, width, height, stride);
            CFRelease(data.cast());
            CFRelease(image.cast());
            Ok(CapturedFrame {
                width,
                height,
                bgra,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_rows_dropping_stride_padding() {
        // 2x2 image, stride 12 (4 bytes padding per row beyond the 8 used).
        let width = 2;
        let height = 2;
        let stride = 12;
        let mut src = vec![0u8; stride * height];
        // Row 0: B0 G0 R0 A0 B1 G1 R1 A1 | pad pad pad pad
        for (i, byte) in src.iter_mut().take(8).enumerate() {
            *byte = u8::try_from(i + 1).unwrap();
        }
        // Row 1 begins at `stride`.
        for i in 0..8usize {
            src[stride + i] = u8::try_from(100 + i).unwrap();
        }
        let packed = pack_bgra_rows(&src, width, height, stride);
        assert_eq!(packed.len(), width * height * 4);
        assert_eq!(&packed[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&packed[8..16], &[100, 101, 102, 103, 104, 105, 106, 107]);
    }

    /// Physical capture smoke test: it needs a real display and the Screen
    /// Recording permission, so it is skipped unless forced. On a headless CI
    /// runner CGDisplayCreateImage returns no image, which the code reports as
    /// `Unavailable` rather than panicking -- so this only asserts the outcome
    /// when the runtime is explicitly required.
    #[test]
    fn captures_the_main_display_when_permitted() {
        if std::env::var_os("OPENSTREAM_REQUIRE_MACOS_CAPTURE").is_none() {
            eprintln!(
                "skipping macOS capture smoke test (set OPENSTREAM_REQUIRE_MACOS_CAPTURE and grant Screen Recording)"
            );
            return;
        }
        let mut capture = ScreenCapture::main();
        let frame = capture.capture().expect("capture the main display");
        assert!(frame.width > 0 && frame.height > 0);
        assert_eq!(frame.bgra.len(), frame.width * frame.height * 4);
        eprintln!(
            "macOS capture: {}x{}, {} bytes",
            frame.width,
            frame.height,
            frame.bgra.len()
        );
    }
}
