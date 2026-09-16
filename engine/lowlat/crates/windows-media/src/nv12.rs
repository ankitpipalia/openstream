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

/// Convert a BGRA frame (one pixel per `u32`, `B | G<<8 | R<<16 | A<<24`) to a
/// contiguous NV12 buffer: a full-resolution Y plane (`width * height` bytes)
/// followed by an interleaved, half-resolution U/V plane (`width * height / 2`
/// bytes). This is the inverse of [`nv12_to_bgra`] and the input the Windows
/// Media Foundation encoder (and future VAAPI encoder) expects; Windows Desktop
/// Duplication and most capture paths hand back BGRA.
///
/// `width` and `height` must be even (4:2:0 subsampling). Each chroma sample
/// averages its 2x2 block of source pixels, which is more faithful than point
/// sampling. BT.601 limited range, matching the decode side so an encode ->
/// decode round trip is stable.
pub(crate) fn bgra_to_nv12(pixels: &[u32], width: usize, height: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height + width * height / 2];
    let (y_plane, uv_plane) = out.split_at_mut(width * height);
    fill_nv12_band(y_plane, uv_plane, width, 0, &|index| {
        unpack_bgr(pixels[index])
    });
    out
}

/// [`bgra_to_nv12`] for a tightly packed BGRA byte frame (4 bytes per pixel in
/// memory order B, G, R, A -- what Desktop Duplication's `B8G8R8A8` readback
/// produces), converting `threads` horizontal bands in parallel.
///
/// A 2560x1440 frame is 3.7 million pixels, and converting it on one core
/// costs a good part of a 60 Hz frame budget; each band is an independent run
/// of whole 2x2 chroma blocks, so bands split cleanly across threads.
/// `threads` is clamped to the number of chroma block rows; `1` converts
/// inline on the caller's thread. Panics if the buffer is shorter than the
/// frame or a dimension is odd: either is a programming error, not a runtime
/// condition.
pub fn bgra_bytes_to_nv12(bgra: &[u8], width: usize, height: usize, threads: usize) -> Vec<u8> {
    assert!(
        width % 2 == 0 && height % 2 == 0,
        "NV12 needs even dimensions"
    );
    assert!(
        bgra.len() >= width * height * 4,
        "BGRA buffer is shorter than the frame"
    );
    let bgr_at = |index: usize| {
        let pixel = &bgra[index * 4..index * 4 + 3];
        (
            i32::from(pixel[0]),
            i32::from(pixel[1]),
            i32::from(pixel[2]),
        )
    };
    let mut out = vec![0u8; width * height + width * height / 2];
    let (y_plane, uv_plane) = out.split_at_mut(width * height);
    let threads = threads.clamp(1, (height / 2).max(1));
    if threads == 1 {
        fill_nv12_band(y_plane, uv_plane, width, 0, &bgr_at);
        return out;
    }
    // Rows per band, rounded up to even so every band owns whole chroma
    // blocks; the last band is whatever remains (also even, as `height` is).
    let band_rows = height.div_ceil(threads).next_multiple_of(2);
    std::thread::scope(|scope| {
        let y_bands = y_plane.chunks_mut(band_rows * width);
        let uv_bands = uv_plane.chunks_mut(band_rows / 2 * width);
        for (band, (y_out, uv_out)) in y_bands.zip(uv_bands).enumerate() {
            let bgr_at = &bgr_at;
            scope.spawn(move || {
                fill_nv12_band(y_out, uv_out, width, band * band_rows, bgr_at);
            });
        }
    });
    out
}

/// Fill one band of an NV12 frame. `y_out` holds the band's luma rows and
/// `uv_out` its interleaved chroma rows; `first_row` (even) is where the band
/// starts in the whole frame, and `bgr_at(row * width + col)` supplies a
/// source pixel's `(B, G, R)`.
fn fill_nv12_band(
    y_out: &mut [u8],
    uv_out: &mut [u8],
    width: usize,
    first_row: usize,
    bgr_at: &(impl Fn(usize) -> (i32, i32, i32) + Sync),
) {
    let rows = y_out.len() / width;
    for local_row in 0..rows {
        let row = first_row + local_row;
        for col in 0..width {
            let (b, g, r) = bgr_at(row * width + col);
            // BT.601 limited-range luma: coefficients are the float transform in
            // the tests scaled by 256 (for the >>8 fixed point), so white maps to
            // Y=235 not 255. Sum 220.
            let y = (66 * r + 129 * g + 25 * b + 128) >> 8;
            y_out[local_row * width + col] = clamp_u8(16 + y);
        }
    }

    // One U/V pair per 2x2 block, averaging the block's chroma.
    let uv_width = width / 2;
    for local_block_row in 0..rows / 2 {
        let block_row = first_row / 2 + local_block_row;
        for block_col in 0..uv_width {
            let mut r_sum = 0i32;
            let mut g_sum = 0i32;
            let mut b_sum = 0i32;
            for dy in 0..2 {
                for dx in 0..2 {
                    let (b, g, r) = bgr_at((block_row * 2 + dy) * width + (block_col * 2 + dx));
                    r_sum += r;
                    g_sum += g;
                    b_sum += b;
                }
            }
            let (r, g, b) = (r_sum / 4, g_sum / 4, b_sum / 4);
            // BT.601 limited-range chroma, coefficients scaled by 256 to match
            // the luma above and the decode-side inverse.
            let u = 128 + ((-38 * r - 74 * g + 112 * b + 128) >> 8);
            let v = 128 + ((112 * r - 94 * g - 18 * b + 128) >> 8);
            let uv_index = local_block_row * width + block_col * 2;
            uv_out[uv_index] = clamp_u8(u);
            uv_out[uv_index + 1] = clamp_u8(v);
        }
    }
}

/// Unpack a BGRA `u32` into its `(B, G, R)` channels as `i32`.
fn unpack_bgr(pixel: u32) -> (i32, i32, i32) {
    (
        (pixel & 0xff) as i32,
        ((pixel >> 8) & 0xff) as i32,
        ((pixel >> 16) & 0xff) as i32,
    )
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

    /// A gradient exercising all channels, as packed `u32`s and as bytes.
    fn gradient(width: usize, height: usize) -> (Vec<u32>, Vec<u8>) {
        let mut pixels = Vec::with_capacity(width * height);
        let mut bytes = Vec::with_capacity(width * height * 4);
        for row in 0..height {
            for col in 0..width {
                let b = u8::try_from((col * 255) / width.max(1)).unwrap();
                let g = u8::try_from((row * 255) / height.max(1)).unwrap();
                let r = u8::try_from((row * 37 + col * 91) % 256).unwrap();
                pixels.push(
                    u32::from(b) | (u32::from(g) << 8) | (u32::from(r) << 16) | (0xFF_u32 << 24),
                );
                bytes.extend_from_slice(&[b, g, r, 0xFF]);
            }
        }
        (pixels, bytes)
    }

    #[test]
    fn byte_frames_convert_exactly_like_packed_pixels_on_any_thread_count() {
        let (width, height) = (16, 12);
        let (pixels, bytes) = gradient(width, height);
        let expected = bgra_to_nv12(&pixels, width, height);
        // 1 = inline; 3 = even bands; 5 = rounded-up bands with a short last
        // band; 64 = more threads than chroma rows, clamped.
        for threads in [1, 3, 5, 64] {
            assert_eq!(
                bgra_bytes_to_nv12(&bytes, width, height, threads),
                expected,
                "threads={threads}"
            );
        }
    }

    #[test]
    fn a_solid_bgra_byte_frame_lands_on_its_bt601_values() {
        let (y, u, v) = rgb_to_yuv601(0, 0, 255); // blue
        let bytes: Vec<u8> = [255u8, 0, 0, 255].repeat(8 * 8); // B, G, R, A
        let out = bgra_bytes_to_nv12(&bytes, 8, 8, 2);
        assert_eq!(out.len(), 8 * 8 + 8 * 8 / 2);
        let close = |a: u8, b: u8| (i32::from(a) - i32::from(b)).abs() <= 2;
        assert!(close(out[0], y), "Y {} vs {y}", out[0]);
        assert!(close(out[64], u), "U {} vs {u}", out[64]);
        assert!(close(out[65], v), "V {} vs {v}", out[65]);
    }

    #[test]
    fn contiguous_planes_reject_a_truncated_buffer() {
        // One byte short of the 24 the planes need.
        let buffer = vec![0u8; 23];
        assert!(nv12_contiguous_planes(&buffer, 8, 2).is_none());
    }

    #[test]
    fn bgra_round_trips_through_nv12() {
        // A solid colour survives BGRA -> NV12 -> BGRA within 4:2:0 + integer
        // BT.601 tolerance, proving the encoder-side forward transform matches
        // the decoder-side inverse.
        let colors: [(u8, u8, u8); 5] = [
            (200, 30, 40),
            (20, 180, 60),
            (30, 40, 210),
            (128, 128, 128),
            (240, 240, 240),
        ];
        for (r, g, b) in colors {
            let (w, h) = (8, 8);
            let px = u32::from(b) | (u32::from(g) << 8) | (u32::from(r) << 16) | (0xFF_u32 << 24);
            let frame = vec![px; w * h];

            let nv12 = bgra_to_nv12(&frame, w, h);
            assert_eq!(nv12.len(), w * h + w * h / 2);
            let (y, uv) = nv12_contiguous_planes(&nv12, w, h).expect("planes fit");
            let back = nv12_to_bgra(y, w, uv, w, w, h);

            let (bb, gg, rr) = channels(back[w * 4 + 4]);
            let close = |actual: u8, want: u8| (i32::from(actual) - i32::from(want)).abs() <= 6;
            assert!(
                close(rr, r) && close(gg, g) && close(bb, b),
                "({r},{g},{b}) -> nv12 -> ({rr},{gg},{bb})"
            );
        }
    }

    #[test]
    fn bgra_to_nv12_limited_range_white_is_235() {
        // White clamps to the studio-swing luma ceiling, not 255 -- the check
        // that the forward transform is limited range, not full range.
        let white = (0xFF_u32) | (0xFF_u32 << 8) | (0xFF_u32 << 16) | (0xFF_u32 << 24);
        let nv12 = bgra_to_nv12(&[white; 16], 4, 4);
        assert_eq!(nv12[0], 235, "limited-range white luma");
    }
}
