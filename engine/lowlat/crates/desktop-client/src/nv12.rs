//! NV12 -> BGRA colour conversion.
//!
//! The vendor-neutral hardware decoders that OpenStream will use on Windows
//! (Media Foundation / D3D11) and Linux (VAAPI), and VideoToolbox in its
//! GPU-surface mode, all deliver frames as NV12 (a full-resolution Y plane
//! followed by an interleaved, half-resolution U/V plane) rather than the BGRA
//! the presenter consumes today. This module converts NV12 to the exact BGRA
//! `u32` packing the presenter expects, so those decoders share one CPU
//! fallback path. It is pure and platform-agnostic, so it is testable on any
//! machine while the Windows and Linux decoders that feed it are built out.
//!
//! The maths is the BT.601 "limited range" (studio-swing) YCbCr->RGB the H.264
//! decoders emit by default. A future step negotiates the colour space and
//! selects BT.709 for HD content; this covers the common path and is a clean
//! seam for that.

// Used by the Media Foundation decoder (Windows) once it lands; kept
// platform-agnostic and unit-tested here in the meantime.
#![allow(dead_code)]

/// Clamp an integer to a `u8`.
// Clamped to [0, 255] first, so the sign loss the lint warns about cannot occur.
#[allow(clippy::cast_sign_loss)]
fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

/// Convert one NV12 frame to BGRA, one pixel per `u32` as
/// `B | G<<8 | R<<16 | A<<24` -- the packing [`crate::render`] and the ffmpeg
/// path both use, so the result is a drop-in decoded frame.
///
/// `y` is the luma plane (`y_stride` bytes per row); `uv` is the interleaved
/// chroma plane (`uv_stride` bytes per row, one U and one V per 2x2 luma
/// block). Strides may exceed `width` (decoders align rows), so they are
/// honored explicitly rather than assumed equal to the width.
pub(crate) fn nv12_to_bgra(
    y: &[u8],
    y_stride: usize,
    uv: &[u8],
    uv_stride: usize,
    width: usize,
    height: usize,
) -> Vec<u32> {
    let mut pixels = Vec::with_capacity(width * height);
    for row in 0..height {
        let y_row = row * y_stride;
        let uv_row = (row / 2) * uv_stride;
        for col in 0..width {
            let luma = i32::from(y[y_row + col]);
            let chroma = (col / 2) * 2;
            let u = i32::from(uv[uv_row + chroma]);
            let v = i32::from(uv[uv_row + chroma + 1]);

            // BT.601 limited range.
            let c = luma - 16;
            let d = u - 128;
            let e = v - 128;
            let r = clamp_u8((298 * c + 409 * e + 128) >> 8);
            let g = clamp_u8((298 * c - 100 * d - 208 * e + 128) >> 8);
            let b = clamp_u8((298 * c + 516 * d + 128) >> 8);

            pixels
                .push(u32::from(b) | (u32::from(g) << 8) | (u32::from(r) << 16) | (0xFF_u32 << 24));
        }
    }
    pixels
}

/// Split a contiguous NV12 buffer into its Y and interleaved UV planes.
///
/// Hardware decoders hand back one buffer holding the full-resolution Y plane
/// (`stride` bytes per row, `height` rows) immediately followed by the
/// half-height interleaved UV plane (same `stride`). `stride` may exceed the
/// image width because the decoder aligns rows. Returns `None` if the buffer is
/// shorter than the two planes require, so a truncated frame is rejected rather
/// than read out of bounds.
pub(crate) fn nv12_contiguous_planes(
    buffer: &[u8],
    stride: usize,
    height: usize,
) -> Option<(&[u8], &[u8])> {
    let y_len = stride.checked_mul(height)?;
    let uv_len = stride.checked_mul(height / 2)?;
    let total = y_len.checked_add(uv_len)?;
    if buffer.len() < total {
        return None;
    }
    Some((&buffer[..y_len], &buffer[y_len..total]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BT.601 limited-range forward transform, matching the inverse above, so
    /// the test builds NV12 the way a decoder would and the round trip is exact
    /// up to rounding.
    // Clamped to [0, 255] before the cast, so the truncation and sign loss the
    // lint warns about cannot occur.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn round_to_u8(value: f64) -> u8 {
        value.round().clamp(0.0, 255.0) as u8
    }

    fn rgb_to_yuv601(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
        let (r, g, b) = (f64::from(r), f64::from(g), f64::from(b));
        let y = 16.0 + (65.481 * r + 128.553 * g + 24.966 * b) / 255.0;
        let u = 128.0 + (-37.797 * r - 74.203 * g + 112.0 * b) / 255.0;
        let v = 128.0 + (112.0 * r - 93.786 * g - 18.214 * b) / 255.0;
        (round_to_u8(y), round_to_u8(u), round_to_u8(v))
    }

    fn solid_nv12(width: usize, height: usize, y: u8, u: u8, v: u8) -> (Vec<u8>, Vec<u8>) {
        let luma = vec![y; width * height];
        let mut chroma = Vec::with_capacity(width * height / 2);
        for _ in 0..(width / 2) * (height / 2) {
            chroma.push(u);
            chroma.push(v);
        }
        (luma, chroma)
    }

    fn channels(pixel: u32) -> (u8, u8, u8) {
        (
            (pixel & 0xff) as u8,         // B
            ((pixel >> 8) & 0xff) as u8,  // G
            ((pixel >> 16) & 0xff) as u8, // R
        )
    }

    #[test]
    fn a_solid_primary_round_trips_within_tolerance() {
        for (name, r, g, b) in [
            ("red", 255, 0, 0),
            ("green", 0, 255, 0),
            ("blue", 0, 0, 255),
            ("white", 255, 255, 255),
            ("mid-gray", 128, 128, 128),
        ] {
            let (y, u, v) = rgb_to_yuv601(r, g, b);
            let (luma, chroma) = solid_nv12(8, 8, y, u, v);
            let out = nv12_to_bgra(&luma, 8, &chroma, 8, 8, 8);
            assert_eq!(out.len(), 64);
            let (ob, og, or) = channels(out[8 * 4 + 4]); // a central pixel
            // 4:2:0 chroma + integer BT.601 round trip: allow a small tolerance.
            let close = |a: u8, b: u8| (i32::from(a) - i32::from(b)).abs() <= 6;
            assert!(
                close(or, r) && close(og, g) && close(ob, b),
                "{name}: expected ~({r},{g},{b}), got ({or},{og},{ob})"
            );
            // Alpha is opaque.
            assert_eq!((out[0] >> 24) & 0xff, 0xff);
        }
    }

    #[test]
    fn respects_row_strides_larger_than_width() {
        // 4x2 image in planes padded to stride 6; the padding must be ignored.
        let (y, u, v) = rgb_to_yuv601(0, 0, 255);
        let width = 4;
        let height = 2;
        let y_stride = 6;
        let uv_stride = 6;
        let mut luma = vec![0u8; y_stride * height];
        for row in 0..height {
            for col in 0..width {
                luma[row * y_stride + col] = y;
            }
        }
        let mut chroma = vec![0u8; uv_stride * (height / 2)];
        for block in 0..(width / 2) {
            chroma[block * 2] = u;
            chroma[block * 2 + 1] = v;
        }
        let out = nv12_to_bgra(&luma, y_stride, &chroma, uv_stride, width, height);
        assert_eq!(out.len(), width * height);
        let (b, g, r) = channels(out[0]);
        assert!(
            b > 200 && r < 60 && g < 60,
            "expected blue, got ({b},{g},{r})"
        );
    }

    #[test]
    fn contiguous_planes_split_at_the_stride_padded_y_plane() {
        // stride 8, width 4, height 2: Y is 8*2=16 bytes, UV is 8*1=8 bytes.
        let mut buffer = vec![0u8; 16 + 8];
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        let (y, uv) = nv12_contiguous_planes(&buffer, 8, 2).expect("planes fit");
        assert_eq!(y.len(), 16);
        assert_eq!(uv.len(), 8);
        assert_eq!(y[0], 0);
        assert_eq!(uv[0], 16, "UV plane starts right after the Y plane");
    }

    #[test]
    fn contiguous_planes_reject_a_truncated_buffer() {
        // One byte short of the 24 the planes need.
        let buffer = vec![0u8; 23];
        assert!(nv12_contiguous_planes(&buffer, 8, 2).is_none());
    }
}
