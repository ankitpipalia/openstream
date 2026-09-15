//! In-process H.264 decode via Apple VideoToolbox (macOS).
//!
//! This replaces the external `ffmpeg` child the client spawns to decode. It is
//! milestone 1 of the native-decode work: it decodes in-process — no subprocess,
//! no BGRA pipe — but still hands back a CPU `Vec<u32>` BGRA frame in the exact
//! packing the existing presenter consumes, so it is a drop-in for the ffmpeg
//! reader with no downstream changes. Milestone 2 keeps the decoded surface on
//! the GPU (NV12 `CVPixelBuffer` → `CVMetalTextureCache` → wgpu) to remove the
//! CPU pixel readback; the honest target is "a GPU-resident path with no CPU
//! pixel readback", and this milestone deliberately does not claim it yet.
//!
//! The decoder takes one Annex-B access unit at a time (exactly what the
//! reassembler produces as `EncodedFrame::payload`), extracts SPS/PPS from
//! keyframes to build the format description, converts the access unit to the
//! length-prefixed (AVCC) form VideoToolbox ingests, and decodes it
//! synchronously. Frames come back BGRA because the host encoder emits no
//! B-frames (`-bf 0` in every hardware profile), so decode order is display
//! order; the presentation timestamp is carried through regardless.
//!
//! Everything here is `unsafe` FFI to the VideoToolbox/CoreMedia/CoreVideo
//! frameworks. Ownership follows CoreFoundation's Create rule: anything a
//! `...Create...` call returns is owned and released with `CFRelease`; the image
//! buffer handed to the output callback is borrowed and copied there, never
//! retained.

// Wired into the decode loop (DecodeAccel dispatch) in a follow-up commit; this
// milestone lands the decoder and its on-hardware test in isolation so the FFI
// is proven before the hot path changes.
#![allow(dead_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFRelease;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use std::ffi::c_void;
use std::fmt;
use std::os::raw::{c_int, c_long};

// ---------------------------------------------------------------------------
// Opaque CoreFoundation-style handle types. Each is a distinct pointer alias so
// the compiler stops a block buffer being passed where a sample buffer is
// wanted; they are all released with `CFRelease`.
// ---------------------------------------------------------------------------
type OSStatus = i32;
type CmFormatDescriptionRef = *mut c_void;
type CmBlockBufferRef = *mut c_void;
type CmSampleBufferRef = *mut c_void;
type VtDecompressionSessionRef = *mut c_void;
type CvImageBufferRef = *mut c_void;
type CfAllocatorRef = *const c_void;

/// `CMTime`. Microsecond timescale throughout, so `value` is a µs count.
#[repr(C)]
#[derive(Clone, Copy)]
struct CmTime {
    value: i64,
    timescale: i32,
    flags: u32,
    epoch: i64,
}

const K_CM_TIME_FLAGS_VALID: u32 = 1;

impl CmTime {
    fn micros(us: u64) -> Self {
        CmTime {
            value: us as i64,
            timescale: 1_000_000,
            flags: K_CM_TIME_FLAGS_VALID,
            epoch: 0,
        }
    }

    fn invalid() -> Self {
        CmTime {
            value: 0,
            timescale: 0,
            flags: 0,
            epoch: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmSampleTimingInfo {
    duration: CmTime,
    presentation_time_stamp: CmTime,
    decode_time_stamp: CmTime,
}

type VtDecompressionOutputCallback = extern "C" fn(
    decompression_output_ref_con: *mut c_void,
    source_frame_ref_con: *mut c_void,
    status: OSStatus,
    info_flags: u32,
    image_buffer: CvImageBufferRef,
    presentation_time_stamp: CmTime,
    presentation_duration: CmTime,
);

#[repr(C)]
struct VtDecompressionOutputCallbackRecord {
    callback: VtDecompressionOutputCallback,
    ref_con: *mut c_void,
}

// `kCMBlockBufferAssureMemoryNowFlag` — allocate the backing store immediately
// so the subsequent copy has somewhere to land.
const K_CM_BLOCK_BUFFER_ASSURE_MEMORY_NOW_FLAG: u32 = 1;
// `kCVPixelBufferLock_ReadOnly` — the callback only reads the decoded pixels.
const K_CV_PIXEL_BUFFER_LOCK_READ_ONLY: u64 = 1;
// `kCVPixelFormatType_32BGRA` == 'BGRA'. Same byte order (B,G,R,A) the ffmpeg
// `-pix_fmt bgra` path produced, so the `u32` packing below is identical.
const K_CV_PIXEL_FORMAT_TYPE_32BGRA: i32 = 0x4247_5241;

#[link(name = "CoreMedia", kind = "framework")]
unsafe extern "C" {
    fn CMVideoFormatDescriptionCreateFromH264ParameterSets(
        allocator: CfAllocatorRef,
        parameter_set_count: usize,
        parameter_set_pointers: *const *const u8,
        parameter_set_sizes: *const usize,
        nal_unit_header_length: c_int,
        format_description_out: *mut CmFormatDescriptionRef,
    ) -> OSStatus;

    fn CMBlockBufferCreateWithMemoryBlock(
        structure_allocator: CfAllocatorRef,
        memory_block: *mut c_void,
        block_length: usize,
        block_allocator: CfAllocatorRef,
        custom_block_source: *const c_void,
        offset_to_data: usize,
        data_length: usize,
        flags: u32,
        block_buffer_out: *mut CmBlockBufferRef,
    ) -> OSStatus;

    fn CMBlockBufferReplaceDataBytes(
        source_bytes: *const c_void,
        destination_buffer: CmBlockBufferRef,
        offset_into_destination: usize,
        data_length: usize,
    ) -> OSStatus;

    fn CMSampleBufferCreateReady(
        allocator: CfAllocatorRef,
        data_buffer: CmBlockBufferRef,
        format_description: CmFormatDescriptionRef,
        num_samples: c_long,
        num_sample_timing_entries: c_long,
        sample_timing_array: *const CmSampleTimingInfo,
        num_sample_size_entries: c_long,
        sample_size_array: *const usize,
        sample_buffer_out: *mut CmSampleBufferRef,
    ) -> OSStatus;
}

#[link(name = "VideoToolbox", kind = "framework")]
unsafe extern "C" {
    fn VTDecompressionSessionCreate(
        allocator: CfAllocatorRef,
        video_format_description: CmFormatDescriptionRef,
        video_decoder_specification: CFDictionaryRef,
        destination_image_buffer_attributes: CFDictionaryRef,
        output_callback: *const VtDecompressionOutputCallbackRecord,
        decompression_session_out: *mut VtDecompressionSessionRef,
    ) -> OSStatus;

    fn VTDecompressionSessionDecodeFrame(
        session: VtDecompressionSessionRef,
        sample_buffer: CmSampleBufferRef,
        decode_flags: u32,
        source_frame_ref_con: *mut c_void,
        info_flags_out: *mut u32,
    ) -> OSStatus;

    fn VTDecompressionSessionWaitForAsynchronousFrames(
        session: VtDecompressionSessionRef,
    ) -> OSStatus;

    fn VTDecompressionSessionInvalidate(session: VtDecompressionSessionRef);
}

#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVPixelBufferLockBaseAddress(pixel_buffer: CvImageBufferRef, flags: u64) -> i32;
    fn CVPixelBufferUnlockBaseAddress(pixel_buffer: CvImageBufferRef, flags: u64) -> i32;
    fn CVPixelBufferGetBaseAddress(pixel_buffer: CvImageBufferRef) -> *mut c_void;
    fn CVPixelBufferGetWidth(pixel_buffer: CvImageBufferRef) -> usize;
    fn CVPixelBufferGetHeight(pixel_buffer: CvImageBufferRef) -> usize;
    fn CVPixelBufferGetBytesPerRow(pixel_buffer: CvImageBufferRef) -> usize;

    static kCVPixelBufferPixelFormatTypeKey: CFStringRef;
    static kCVPixelBufferIOSurfacePropertiesKey: CFStringRef;
}

/// One decoded picture: BGRA packed the way the presenter expects, plus its
/// presentation timestamp. Plain data — `Send` — so it rides the existing
/// latest-frame mailbox unchanged.
#[derive(Debug, Clone)]
pub(crate) struct VtFrame {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) presentation_time_us: u64,
    /// BGRA, one pixel per `u32` as `B | G<<8 | R<<16 | A<<24`.
    pub(crate) pixels: Vec<u32>,
}

/// Why a decode could not proceed. Failures are recoverable at the call site by
/// falling back to the ffmpeg path.
#[derive(Debug)]
pub(crate) enum VtError {
    /// A keyframe has not been seen yet, so there is no format description to
    /// decode against.
    NotConfigured,
    /// `CMVideoFormatDescriptionCreateFromH264ParameterSets` failed.
    FormatDescription(OSStatus),
    /// A session could not be created for the current format.
    SessionCreate(OSStatus),
    /// Building the sample buffer for an access unit failed.
    SampleBuffer(OSStatus),
    /// `VTDecompressionSessionDecodeFrame` reported an error.
    Decode(OSStatus),
}

impl fmt::Display for VtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtError::NotConfigured => {
                write!(f, "no keyframe decoded yet; VideoToolbox is not configured")
            }
            VtError::FormatDescription(s) => {
                write!(f, "CMVideoFormatDescription create failed (OSStatus {s})")
            }
            VtError::SessionCreate(s) => {
                write!(f, "VTDecompressionSession create failed (OSStatus {s})")
            }
            VtError::SampleBuffer(s) => write!(f, "CMSampleBuffer create failed (OSStatus {s})"),
            VtError::Decode(s) => {
                write!(f, "VTDecompressionSessionDecodeFrame failed (OSStatus {s})")
            }
        }
    }
}

impl std::error::Error for VtError {}

/// The output callback drains decoded pictures into this sink. It lives boxed at
/// a stable address for the session's lifetime, and the decode call reads and
/// clears it after `WaitForAsynchronousFrames`.
struct DecodeSink {
    frames: Vec<VtFrame>,
}

/// The VideoToolbox output callback. Copies the decoded BGRA image into a
/// `VtFrame`. Runs on a VideoToolbox thread, but the decode call waits for it
/// before reading the sink, so there is no concurrent access.
extern "C" fn output_callback(
    ref_con: *mut c_void,
    _source_frame_ref_con: *mut c_void,
    status: OSStatus,
    _info_flags: u32,
    image_buffer: CvImageBufferRef,
    presentation_time_stamp: CmTime,
    _presentation_duration: CmTime,
) {
    if ref_con.is_null() || status != 0 || image_buffer.is_null() {
        return;
    }
    // SAFETY: `ref_con` is the `Box<DecodeSink>` pointer this decoder passed to
    // `VTDecompressionSessionCreate` and keeps alive for the session's life; the
    // decode call has no other reference live while the callback runs.
    let sink = unsafe { &mut *(ref_con as *mut DecodeSink) };

    let presentation_time_us = if presentation_time_stamp.flags & K_CM_TIME_FLAGS_VALID != 0
        && presentation_time_stamp.timescale > 0
    {
        // Timescale is microseconds (we set it), so value is already µs.
        u64::try_from(presentation_time_stamp.value).unwrap_or(0)
    } else {
        0
    };

    // SAFETY: image_buffer is a valid CVPixelBuffer for the duration of the
    // callback; we lock read-only, read within the reported geometry, unlock.
    unsafe {
        if CVPixelBufferLockBaseAddress(image_buffer, K_CV_PIXEL_BUFFER_LOCK_READ_ONLY) != 0 {
            return;
        }
        let width = CVPixelBufferGetWidth(image_buffer);
        let height = CVPixelBufferGetHeight(image_buffer);
        let stride = CVPixelBufferGetBytesPerRow(image_buffer);
        let base = CVPixelBufferGetBaseAddress(image_buffer) as *const u8;
        if !base.is_null() && width > 0 && height > 0 && stride >= width * 4 {
            let mut pixels = Vec::with_capacity(width * height);
            for row in 0..height {
                let row_ptr = base.add(row * stride);
                for col in 0..width {
                    let p = row_ptr.add(col * 4);
                    // BGRA in memory -> B | G<<8 | R<<16 | A<<24, matching the
                    // ffmpeg path's packing exactly.
                    let value = u32::from(*p)
                        | (u32::from(*p.add(1)) << 8)
                        | (u32::from(*p.add(2)) << 16)
                        | (u32::from(*p.add(3)) << 24);
                    pixels.push(value);
                }
            }
            sink.frames.push(VtFrame {
                width,
                height,
                presentation_time_us,
                pixels,
            });
        }
        CVPixelBufferUnlockBaseAddress(image_buffer, K_CV_PIXEL_BUFFER_LOCK_READ_ONLY);
    }
}

/// In-process H.264 decoder. One access unit per `decode` call.
pub(crate) struct VideoToolboxH264Decoder {
    session: VtDecompressionSessionRef,
    format: CmFormatDescriptionRef,
    // Kept so the parameter-set pointers handed to CoreMedia stayed valid, and
    // so a format change can be detected without rebuilding needlessly.
    sps: Vec<u8>,
    pps: Vec<u8>,
    // Boxed so its address is stable for the callback record; freed in Drop.
    sink: *mut DecodeSink,
}

impl fmt::Debug for VideoToolboxH264Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoToolboxH264Decoder")
            .field("configured", &(!self.format.is_null()))
            .field("sps_len", &self.sps.len())
            .field("pps_len", &self.pps.len())
            .finish()
    }
}

impl VideoToolboxH264Decoder {
    /// Create an unconfigured decoder. The session is built lazily once the
    /// first keyframe supplies SPS/PPS.
    pub(crate) fn new() -> Self {
        let sink = Box::into_raw(Box::new(DecodeSink { frames: Vec::new() }));
        VideoToolboxH264Decoder {
            session: std::ptr::null_mut(),
            format: std::ptr::null_mut(),
            sps: Vec::new(),
            pps: Vec::new(),
            sink,
        }
    }

    /// Decode one Annex-B access unit, returning the pictures it produced (zero
    /// or more). `NotConfigured` means no keyframe has been seen yet.
    pub(crate) fn decode(
        &mut self,
        access_unit: &[u8],
        presentation_time_us: u64,
        keyframe: bool,
    ) -> Result<Vec<VtFrame>, VtError> {
        let nals = split_nal_units(access_unit);

        // Refresh the format description if this access unit carries parameter
        // sets (keyframes do) and they changed.
        let mut new_sps: Option<Vec<u8>> = None;
        let mut new_pps: Option<Vec<u8>> = None;
        for nal in &nals {
            match nal.first().map(|b| b & 0x1f) {
                Some(7) => new_sps = Some(nal.to_vec()),
                Some(8) => new_pps = Some(nal.to_vec()),
                _ => {}
            }
        }
        if let (Some(sps), Some(pps)) = (new_sps, new_pps)
            && (sps != self.sps || pps != self.pps || self.format.is_null())
        {
            self.configure(&sps, &pps)?;
        }

        if self.format.is_null() {
            // No parameter sets yet — cannot decode until a keyframe arrives.
            let _ = keyframe;
            return Err(VtError::NotConfigured);
        }

        // Build the AVCC (length-prefixed) payload from the VCL/SEI NALs. SPS,
        // PPS and AUD are excluded: parameter sets live in the format
        // description, and the access-unit delimiter is not decoded.
        let mut avcc: Vec<u8> = Vec::with_capacity(access_unit.len());
        for nal in &nals {
            match nal.first().map(|b| b & 0x1f) {
                Some(7) | Some(8) | Some(9) => continue,
                _ => {}
            }
            // A single NAL cannot exceed u32 in any reassembled frame; the
            // saturating fallback avoids a panic without a plausible loss.
            let len = u32::try_from(nal.len()).unwrap_or(u32::MAX);
            avcc.extend_from_slice(&len.to_be_bytes());
            avcc.extend_from_slice(nal);
        }
        if avcc.is_empty() {
            // Parameter-set-only access unit (e.g. a config refresh): nothing to
            // decode, no error.
            return Ok(Vec::new());
        }

        self.ensure_session()?;
        let sample = self.build_sample_buffer(&avcc, presentation_time_us)?;

        // SAFETY: sink is our live boxed pointer; the decode + wait completes the
        // callback before we read it, so the &mut here is exclusive.
        let sink = unsafe { &mut *self.sink };
        sink.frames.clear();

        // SAFETY: session and sample are valid; a synchronous decode (no async
        // flag) plus WaitForAsynchronousFrames guarantees the callback has run.
        let status = unsafe {
            let mut info_flags: u32 = 0;
            let status = VTDecompressionSessionDecodeFrame(
                self.session,
                sample,
                0,
                std::ptr::null_mut(),
                &mut info_flags,
            );
            if status == 0 {
                VTDecompressionSessionWaitForAsynchronousFrames(self.session);
            }
            CFRelease(sample as *const c_void);
            status
        };
        if status != 0 {
            return Err(VtError::Decode(status));
        }

        // SAFETY: same exclusivity argument; the callback has finished.
        let sink = unsafe { &mut *self.sink };
        Ok(std::mem::take(&mut sink.frames))
    }

    fn configure(&mut self, sps: &[u8], pps: &[u8]) -> Result<(), VtError> {
        let pointers: [*const u8; 2] = [sps.as_ptr(), pps.as_ptr()];
        let sizes: [usize; 2] = [sps.len(), pps.len()];
        let mut format: CmFormatDescriptionRef = std::ptr::null_mut();
        // SAFETY: pointers/sizes describe the two parameter-set slices, valid for
        // the call; CoreMedia copies them into the format description.
        let status = unsafe {
            CMVideoFormatDescriptionCreateFromH264ParameterSets(
                std::ptr::null(),
                2,
                pointers.as_ptr(),
                sizes.as_ptr(),
                4,
                &mut format,
            )
        };
        if status != 0 {
            return Err(VtError::FormatDescription(status));
        }

        // A format change invalidates the old session; it is rebuilt lazily.
        self.teardown_session();
        if !self.format.is_null() {
            // SAFETY: owned by us under the Create rule.
            unsafe { CFRelease(self.format as *const c_void) };
        }
        self.format = format;
        self.sps = sps.to_vec();
        self.pps = pps.to_vec();
        Ok(())
    }

    fn ensure_session(&mut self) -> Result<(), VtError> {
        if !self.session.is_null() {
            return Ok(());
        }
        let attrs = bgra_buffer_attributes();
        let record = VtDecompressionOutputCallbackRecord {
            callback: output_callback,
            ref_con: self.sink as *mut c_void,
        };
        let mut session: VtDecompressionSessionRef = std::ptr::null_mut();
        // SAFETY: format is a valid, owned format description; attrs is a valid
        // dictionary living for the call; record points to a stable callback +
        // sink. On success we own the session.
        let status = unsafe {
            VTDecompressionSessionCreate(
                std::ptr::null(),
                self.format,
                std::ptr::null(),
                attrs.as_concrete_TypeRef(),
                &record,
                &mut session,
            )
        };
        if status != 0 {
            return Err(VtError::SessionCreate(status));
        }
        self.session = session;
        Ok(())
    }

    fn build_sample_buffer(
        &self,
        avcc: &[u8],
        presentation_time_us: u64,
    ) -> Result<CmSampleBufferRef, VtError> {
        let mut block: CmBlockBufferRef = std::ptr::null_mut();
        // SAFETY: allocate a block buffer of the payload length, then fill it.
        let status = unsafe {
            CMBlockBufferCreateWithMemoryBlock(
                std::ptr::null(),
                std::ptr::null_mut(),
                avcc.len(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                avcc.len(),
                K_CM_BLOCK_BUFFER_ASSURE_MEMORY_NOW_FLAG,
                &mut block,
            )
        };
        if status != 0 {
            return Err(VtError::SampleBuffer(status));
        }
        // SAFETY: block is a valid buffer sized for avcc; copy the payload in.
        let status = unsafe {
            CMBlockBufferReplaceDataBytes(avcc.as_ptr() as *const c_void, block, 0, avcc.len())
        };
        if status != 0 {
            unsafe { CFRelease(block as *const c_void) };
            return Err(VtError::SampleBuffer(status));
        }

        let timing = CmSampleTimingInfo {
            duration: CmTime::invalid(),
            presentation_time_stamp: CmTime::micros(presentation_time_us),
            decode_time_stamp: CmTime::invalid(),
        };
        let sizes: [usize; 1] = [avcc.len()];
        let mut sample: CmSampleBufferRef = std::ptr::null_mut();
        // SAFETY: block and format are valid; timing/sizes arrays hold one entry
        // as declared. On success we own the sample buffer.
        let status = unsafe {
            CMSampleBufferCreateReady(
                std::ptr::null(),
                block,
                self.format,
                1,
                1,
                &timing,
                1,
                sizes.as_ptr(),
                &mut sample,
            )
        };
        // The sample buffer retains the block buffer, so release our reference.
        unsafe { CFRelease(block as *const c_void) };
        if status != 0 {
            return Err(VtError::SampleBuffer(status));
        }
        Ok(sample)
    }

    fn teardown_session(&mut self) {
        if !self.session.is_null() {
            // SAFETY: session is valid and owned; invalidate stops callbacks,
            // then release drops our reference.
            unsafe {
                VTDecompressionSessionInvalidate(self.session);
                CFRelease(self.session as *const c_void);
            }
            self.session = std::ptr::null_mut();
        }
    }
}

impl Drop for VideoToolboxH264Decoder {
    fn drop(&mut self) {
        self.teardown_session();
        if !self.format.is_null() {
            // SAFETY: owned format description.
            unsafe { CFRelease(self.format as *const c_void) };
            self.format = std::ptr::null_mut();
        }
        if !self.sink.is_null() {
            // SAFETY: sink was created with Box::into_raw and no longer aliased
            // now the session (its only other referent) is torn down.
            unsafe { drop(Box::from_raw(self.sink)) };
            self.sink = std::ptr::null_mut();
        }
    }
}

/// Destination attributes requesting BGRA, IOSurface-backed pixel buffers.
fn bgra_buffer_attributes() -> CFDictionary<CFType, CFType> {
    let format = CFNumber::from(K_CV_PIXEL_FORMAT_TYPE_32BGRA);
    // SAFETY: the keys are framework string constants, valid for the process.
    let format_key = unsafe { CFString::wrap_under_get_rule(kCVPixelBufferPixelFormatTypeKey) };
    let io_key = unsafe { CFString::wrap_under_get_rule(kCVPixelBufferIOSurfacePropertiesKey) };
    let empty: CFDictionary<CFType, CFType> = CFDictionary::from_CFType_pairs(&[]);
    CFDictionary::from_CFType_pairs(&[
        (format_key.as_CFType(), format.as_CFType()),
        (io_key.as_CFType(), empty.as_CFType()),
    ])
}

/// Split an Annex-B buffer into NAL units (payload only, start codes and any
/// trailing zero padding stripped). Handles 3- and 4-byte start codes.
fn split_nal_units(data: &[u8]) -> Vec<&[u8]> {
    // Offsets just past each `00 00 01` start-code triple.
    let mut starts: Vec<usize> = Vec::new();
    let mut p = 0usize;
    while p + 3 <= data.len() {
        if data[p] == 0 && data[p + 1] == 0 && data[p + 2] == 1 {
            starts.push(p + 3);
            p += 3;
        } else {
            p += 1;
        }
    }
    let mut units = Vec::with_capacity(starts.len());
    for (k, &s) in starts.iter().enumerate() {
        let mut end = if k + 1 < starts.len() {
            starts[k + 1] - 3
        } else {
            data.len()
        };
        // Trim the extra leading zero of a 4-byte start code and any trailing
        // zero padding before the next unit.
        while end > s && data[end - 1] == 0 {
            end -= 1;
        }
        if end > s {
            units.push(&data[s..end]);
        }
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn nal_splitter_handles_three_and_four_byte_start_codes() {
        // 4-byte start, NAL {0x67, 0x01}; 3-byte start, NAL {0x68, 0x02}.
        let stream = [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x01, 0x00, 0x00, 0x01, 0x68, 0x02,
        ];
        let nals = split_nal_units(&stream);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], &[0x67, 0x01]);
        assert_eq!(nals[1], &[0x68, 0x02]);
    }

    #[test]
    fn nal_splitter_trims_trailing_zero_padding() {
        // NAL {0x41, 0x9a} followed by two cabac_zero_words before the next code.
        let stream = [
            0x00, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00,
        ];
        let nals = split_nal_units(&stream);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], &[0x41, 0x9a]);
        assert_eq!(nals[1], &[0x41]);
    }

    fn ffmpeg() -> String {
        std::env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string())
    }

    /// Split an Annex-B elementary stream into access units on AUD (type 9)
    /// boundaries. Only used by the fixture test, which generates the stream
    /// with `aud=1`.
    fn access_units_by_aud(stream: &[u8]) -> Vec<Vec<u8>> {
        // Byte offsets where an AUD start code begins.
        let mut aud_offsets: Vec<usize> = Vec::new();
        let mut p = 0usize;
        while p + 4 <= stream.len() {
            if stream[p] == 0 && stream[p + 1] == 0 && stream[p + 2] == 1 {
                if stream[p + 3] & 0x1f == 9 {
                    // Include a preceding zero (4-byte start code) if present.
                    let start = if p > 0 && stream[p - 1] == 0 {
                        p - 1
                    } else {
                        p
                    };
                    aud_offsets.push(start);
                }
                p += 3;
            } else {
                p += 1;
            }
        }
        let mut units = Vec::new();
        for (k, &start) in aud_offsets.iter().enumerate() {
            let end = aud_offsets.get(k + 1).copied().unwrap_or(stream.len());
            units.push(stream[start..end].to_vec());
        }
        units
    }

    /// Decode a small H.264 clip end-to-end through VideoToolbox on this
    /// machine. Skips when ffmpeg is unavailable to generate the fixture.
    #[test]
    fn decodes_a_real_h264_clip_on_this_machine() {
        let generate = Command::new(ffmpeg())
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x240:rate=10",
                "-frames:v",
                "8",
                "-c:v",
                "libx264",
                "-bf",
                "0",
                "-g",
                "8",
                "-keyint_min",
                "8",
                "-pix_fmt",
                "yuv420p",
                "-x264-params",
                "aud=1",
                "-f",
                "h264",
                "-",
            ])
            .output();
        let Ok(output) = generate else {
            eprintln!("ffmpeg not available; skipping VideoToolbox decode test");
            return;
        };
        if !output.status.success() || output.stdout.is_empty() {
            eprintln!(
                "ffmpeg could not produce a fixture ({}); skipping",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let access_units = access_units_by_aud(&output.stdout);
        assert!(
            access_units.len() >= 2,
            "expected several access units, got {}",
            access_units.len()
        );

        let mut decoder = VideoToolboxH264Decoder::new();
        let mut decoded = Vec::new();
        for (index, au) in access_units.iter().enumerate() {
            let keyframe = index == 0;
            match decoder.decode(au, index as u64 * 100_000, keyframe) {
                Ok(frames) => decoded.extend(frames),
                Err(VtError::NotConfigured) => {} // before the first keyframe
                Err(error) => panic!("decode failed on AU {index}: {error}"),
            }
        }

        assert!(
            !decoded.is_empty(),
            "VideoToolbox produced no frames from {} access units",
            access_units.len()
        );
        for frame in &decoded {
            assert_eq!(frame.width, 320, "decoded width");
            assert_eq!(frame.height, 240, "decoded height");
            assert_eq!(
                frame.pixels.len(),
                320 * 240,
                "pixel count matches geometry"
            );
        }
    }
}
