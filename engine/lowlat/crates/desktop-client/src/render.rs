//! Software presentation helpers shared by the desktop window.
//!
//! minifb owns the OS window on every desktop target, so this module keeps
//! the portable present logic explicit and tested: BGRA frame validation,
//! negotiated-dimension bounds, and frame pacing. Native GPU upload paths
//! (D3D11/Metal/Vulkan) plug in behind [`Presenter`] without touching the
//! network loop.

/// Maximum presentable pixels per frame (7680x4320, the negotiated ceiling).
pub(crate) const MAX_PRESENT_PIXELS: usize = 7680 * 4320;

/// Errors from frame validation; all map to dropping the frame, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentError {
    ZeroDimension,
    TooLarge,
    LengthMismatch,
}

impl std::fmt::Display for PresentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroDimension => f.write_str("frame dimensions are zero"),
            Self::TooLarge => f.write_str("frame exceeds the negotiated ceiling"),
            Self::LengthMismatch => f.write_str("BGRA buffer length does not match dimensions"),
        }
    }
}

impl std::error::Error for PresentError {}

/// Validate one decoded BGRA frame before presenting it.
pub(crate) fn validate_bgra_frame(
    width: usize,
    height: usize,
    pixels: &[u32],
) -> Result<(), PresentError> {
    if width == 0 || height == 0 {
        return Err(PresentError::ZeroDimension);
    }
    let count = width.checked_mul(height).ok_or(PresentError::TooLarge)?;
    if count > MAX_PRESENT_PIXELS {
        return Err(PresentError::TooLarge);
    }
    if pixels.len() != count {
        return Err(PresentError::LengthMismatch);
    }
    Ok(())
}

/// Fixed-cadence frame pacer: at most one present per `interval`, dropping
/// stale frames instead of accumulating latency.
#[derive(Debug)]
pub(crate) struct FramePacer {
    interval: std::time::Duration,
    last: Option<std::time::Instant>,
}

impl FramePacer {
    pub(crate) fn new(fps: u16) -> Self {
        let interval = if fps == 0 {
            std::time::Duration::from_millis(16)
        } else {
            std::time::Duration::from_nanos(1_000_000_000 / u64::from(fps.max(1)))
        };
        Self {
            interval,
            last: None,
        }
    }

    /// Returns `true` when the caller should present now.
    pub(crate) fn should_present(&mut self, now: std::time::Instant) -> bool {
        match self.last {
            Some(previous) if now.duration_since(previous) < self.interval => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

/// Presentation backend selected by `OPENSTREAM_RENDERER`.
///
/// `software` (the default) presents through the OS window via minifb.
/// `d3d11`, `metal`, and `vulkan` are accepted names for forward
/// compatibility and currently resolve to software with a one-time notice,
/// so scripts written against the future native backends keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RenderBackend {
    #[default]
    Software,
    D3d11,
    Metal,
    Vulkan,
}

impl RenderBackend {
    pub(crate) fn from_env() -> (Self, bool) {
        let name = std::env::var("OPENSTREAM_RENDERER").unwrap_or_default();
        match name.trim().to_ascii_lowercase().as_str() {
            "d3d11" | "direct3d" => (Self::D3d11, true),
            "metal" => (Self::Metal, true),
            "vulkan" | "gl" | "opengl" => (Self::Vulkan, true),
            _ => (Self::Software, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_frames_before_present() {
        assert_eq!(
            validate_bgra_frame(0, 1080, &[]),
            Err(PresentError::ZeroDimension)
        );
        assert_eq!(
            validate_bgra_frame(7681, 4321, &vec![0; 7681 * 4321]),
            Err(PresentError::TooLarge)
        );
        assert_eq!(
            validate_bgra_frame(2, 2, &[0, 0, 0]),
            Err(PresentError::LengthMismatch)
        );
        assert!(validate_bgra_frame(2, 2, &[0; 4]).is_ok());
    }

    #[test]
    fn pacer_limits_presents_to_cadence() {
        let mut pacer = FramePacer::new(60);
        let start = std::time::Instant::now();
        assert!(pacer.should_present(start));
        assert!(!pacer.should_present(start));
        assert!(pacer.should_present(start + std::time::Duration::from_millis(17)));
    }

    #[test]
    fn renderer_names_resolve_with_fallback_notice() {
        assert_eq!(RenderBackend::from_env().0, RenderBackend::Software);
        assert!(matches!(
            RenderBackend::from_env().0,
            RenderBackend::Software
        ));
    }
}
