//! In-process H.264 encode via a VideoToolbox `VTCompressionSession`.
//!
//! Everything here is `unsafe` FFI to the VideoToolbox / CoreMedia / CoreVideo
//! frameworks. Ownership follows CoreFoundation's Create rule: anything a
//! `...Create...` call returns is owned and released with `CFRelease`; the
//! sample buffer handed to the output callback is borrowed and copied there,
//! never retained.
//!
//! The session is driven in real-time mode with frame reordering off (no
//! B-frames), so decode order is display order and the client can present as
//! frames arrive. Output is an Annex-B access unit per frame; on a keyframe the
//! SPS/PPS are read from the sample's format description and prepended, so a
//! decoder can start from any keyframe -- the same contract the Windows encoder
//! honours.

#![cfg(target_os = "macos")]

use std::collections::VecDeque;
use std::ffi::c_void;
use std::os::raw::{c_int, c_long};
use std::sync::Mutex;

use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

type OSStatus = i32;
type CvReturn = i32;
type VtCompressionSessionRef = *mut c_void;
type CmSampleBufferRef = *mut c_void;
type CmBlockBufferRef = *mut c_void;
type CmFormatDescriptionRef = *mut c_void;
type CvImageBufferRef = *mut c_void;
type CfAllocatorRef = *const c_void;
type CfArrayRef = *const c_void;

/// `CMTime`, microsecond timescale throughout, so `value` is a microsecond count.
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
    fn micros(us: i64) -> Self {
        CmTime {
            value: us,
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

// `kCMVideoCodecType_H264` == 'avc1'.
const K_CM_VIDEO_CODEC_TYPE_H264: u32 = 0x6176_6331;
// `kCVPixelFormatType_32BGRA` == 'BGRA'. The byte order (B, G, R, A) matches the
// capture buffers and the client's decoder, so no channel swap is needed.
const K_CV_PIXEL_FORMAT_TYPE_32BGRA: u32 = 0x4247_5241;
// `kCVPixelBufferLock_ReadOnly` -- the copy into the pixel buffer writes, but the
// encode only reads; the flag is 0 for the writable lock we take.
const K_CV_PIXEL_BUFFER_LOCK_WRITE: u64 = 0;

type VtCompressionOutputCallback = extern "C" fn(
    output_callback_ref_con: *mut c_void,
    source_frame_ref_con: *mut c_void,
    status: OSStatus,
    info_flags: u32,
    sample_buffer: CmSampleBufferRef,
);

#[link(name = "VideoToolbox", kind = "framework")]
unsafe extern "C" {
    fn VTCompressionSessionCreate(
        allocator: CfAllocatorRef,
        width: i32,
        height: i32,
        codec_type: u32,
        encoder_specification: CFDictionaryRef,
        source_image_buffer_attributes: CFDictionaryRef,
        compressed_data_allocator: CfAllocatorRef,
        output_callback: VtCompressionOutputCallback,
        output_callback_ref_con: *mut c_void,
        compression_session_out: *mut VtCompressionSessionRef,
    ) -> OSStatus;

    fn VTCompressionSessionPrepareToEncodeFrames(session: VtCompressionSessionRef) -> OSStatus;

    fn VTCompressionSessionEncodeFrame(
        session: VtCompressionSessionRef,
        image_buffer: CvImageBufferRef,
        presentation_time_stamp: CmTime,
        duration: CmTime,
        frame_properties: CFDictionaryRef,
        source_frame_ref_con: *mut c_void,
        info_flags_out: *mut u32,
    ) -> OSStatus;

    fn VTCompressionSessionCompleteFrames(
        session: VtCompressionSessionRef,
        complete_until_presentation_time_stamp: CmTime,
    ) -> OSStatus;

    fn VTCompressionSessionInvalidate(session: VtCompressionSessionRef);

    fn VTSessionSetProperty(
        session: VtCompressionSessionRef,
        property_key: CFStringRef,
        property_value: CFTypeRef,
    ) -> OSStatus;

    static kVTCompressionPropertyKey_RealTime: CFStringRef;
    static kVTCompressionPropertyKey_ProfileLevel: CFStringRef;
    static kVTCompressionPropertyKey_AverageBitRate: CFStringRef;
    static kVTCompressionPropertyKey_ExpectedFrameRate: CFStringRef;
    static kVTCompressionPropertyKey_MaxKeyFrameInterval: CFStringRef;
    static kVTCompressionPropertyKey_AllowFrameReordering: CFStringRef;
    static kVTProfileLevel_H264_Main_AutoLevel: CFStringRef;
    static kVTEncodeFrameOptionKey_ForceKeyFrame: CFStringRef;
}

#[link(name = "CoreMedia", kind = "framework")]
unsafe extern "C" {
    fn CMSampleBufferGetDataBuffer(sbuf: CmSampleBufferRef) -> CmBlockBufferRef;

    fn CMSampleBufferGetFormatDescription(sbuf: CmSampleBufferRef) -> CmFormatDescriptionRef;

    fn CMSampleBufferGetSampleAttachmentsArray(
        sbuf: CmSampleBufferRef,
        create_if_necessary: u8,
    ) -> CfArrayRef;

    fn CMBlockBufferGetDataLength(bbuf: CmBlockBufferRef) -> usize;

    fn CMBlockBufferCopyDataBytes(
        source_buffer: CmBlockBufferRef,
        offset_to_data: usize,
        data_length: usize,
        destination: *mut c_void,
    ) -> OSStatus;

    fn CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
        video_desc: CmFormatDescriptionRef,
        parameter_set_index: usize,
        parameter_set_pointer_out: *mut *const u8,
        parameter_set_size_out: *mut usize,
        parameter_set_count_out: *mut usize,
        nal_unit_header_length_out: *mut c_int,
    ) -> OSStatus;

    static kCMSampleAttachmentKey_NotSync: CFStringRef;
}

#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVPixelBufferCreate(
        allocator: CfAllocatorRef,
        width: usize,
        height: usize,
        pixel_format_type: u32,
        pixel_buffer_attributes: CFDictionaryRef,
        pixel_buffer_out: *mut CvImageBufferRef,
    ) -> CvReturn;

    fn CVPixelBufferLockBaseAddress(pixel_buffer: CvImageBufferRef, flags: u64) -> CvReturn;
    fn CVPixelBufferUnlockBaseAddress(pixel_buffer: CvImageBufferRef, flags: u64) -> CvReturn;
    fn CVPixelBufferGetBaseAddress(pixel_buffer: CvImageBufferRef) -> *mut c_void;
    fn CVPixelBufferGetBytesPerRow(pixel_buffer: CvImageBufferRef) -> usize;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFArrayGetCount(array: CfArrayRef) -> c_long;
    fn CFArrayGetValueAtIndex(array: CfArrayRef, index: c_long) -> *const c_void;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> u8;
}

/// One encoded H.264 access unit and whether it starts a keyframe.
#[derive(Debug, Clone)]
pub struct EncodedAccessUnit {
    pub data: Vec<u8>,
    pub keyframe: bool,
}

/// Why a VideoToolbox encode failed.
#[derive(Debug)]
pub enum VtEncError {
    /// A framework call returned a failure `OSStatus` / `CVReturn`.
    Status(&'static str, OSStatus),
    /// The input frame was not the `width * height * 4` bytes a BGRA frame needs.
    FrameSize { expected: usize, got: usize },
}

impl std::fmt::Display for VtEncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VtEncError::Status(call, status) => {
                write!(f, "videotoolbox {call} failed with status {status}")
            }
            VtEncError::FrameSize { expected, got } => {
                write!(f, "expected a {expected}-byte BGRA frame, got {got}")
            }
        }
    }
}

impl std::error::Error for VtEncError {}

/// What the output callback and the host loop share: encoded units, waiting to
/// be drained, and the latest SPS/PPS as an Annex-B sequence header.
#[derive(Default)]
struct Shared {
    ready: Mutex<VecDeque<EncodedAccessUnit>>,
    sequence_header: Mutex<Option<Vec<u8>>>,
}

/// The in-process VideoToolbox H.264 encoder.
pub struct VideoToolboxH264Encoder {
    session: VtCompressionSessionRef,
    width: usize,
    height: usize,
    // Boxed so its address is stable for the whole session: the compression
    // callback receives this as its ref-con and reads it on a VideoToolbox
    // thread. The session is invalidated in `Drop` before the box is freed, so
    // no callback can run after it goes away.
    shared: Box<Shared>,
    force_keyframe: bool,
}

// SAFETY: the session and shared state are protected for cross-thread use --
// the callback only touches `Shared`, whose fields are mutexes, and the session
// handle is used from the owning thread while the callback pushes results.
unsafe impl Send for VideoToolboxH264Encoder {}

impl std::fmt::Debug for VideoToolboxH264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VideoToolboxH264Encoder")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl VideoToolboxH264Encoder {
    /// Create an encoder for `width` x `height` at `fps` frames per second and
    /// the given average `bitrate` (bits per second), accepting BGRA input.
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self, VtEncError> {
        let shared = Box::new(Shared::default());
        let ref_con = std::ptr::from_ref(shared.as_ref()) as *mut c_void;

        let mut session: VtCompressionSessionRef = std::ptr::null_mut();
        // SAFETY: FFI. A null encoder/source spec lets VideoToolbox pick the
        // hardware encoder; the callback and its ref-con outlive the session
        // (invalidated before the box drops).
        let status = unsafe {
            VTCompressionSessionCreate(
                std::ptr::null(),
                i32::try_from(width).unwrap_or(i32::MAX),
                i32::try_from(height).unwrap_or(i32::MAX),
                K_CM_VIDEO_CODEC_TYPE_H264,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                compression_output,
                ref_con,
                &mut session,
            )
        };
        if status != 0 || session.is_null() {
            return Err(VtEncError::Status("VTCompressionSessionCreate", status));
        }

        let encoder = Self {
            session,
            width: width as usize,
            height: height as usize,
            shared,
            force_keyframe: false,
        };
        encoder.configure(fps, bitrate)?;
        // SAFETY: preparing a live session is documented and side-effect free
        // beyond warming the encoder.
        let status = unsafe { VTCompressionSessionPrepareToEncodeFrames(encoder.session) };
        if status != 0 {
            return Err(VtEncError::Status(
                "VTCompressionSessionPrepareToEncodeFrames",
                status,
            ));
        }
        Ok(encoder)
    }

    fn configure(&self, fps: u32, bitrate: u32) -> Result<(), VtEncError> {
        // Real-time, low-latency: no frame reordering (no B-frames), a bounded
        // keyframe interval, and the target bitrate and frame rate the session
        // paces to.
        self.set_bool(unsafe { kVTCompressionPropertyKey_RealTime }, true)?;
        self.set_bool(
            unsafe { kVTCompressionPropertyKey_AllowFrameReordering },
            false,
        )?;
        // SAFETY: setting a CFString property value on a live session.
        let status = unsafe {
            VTSessionSetProperty(
                self.session,
                kVTCompressionPropertyKey_ProfileLevel,
                kVTProfileLevel_H264_Main_AutoLevel.cast(),
            )
        };
        if status != 0 {
            return Err(VtEncError::Status("set ProfileLevel", status));
        }
        self.set_number(
            unsafe { kVTCompressionPropertyKey_AverageBitRate },
            i64::from(bitrate),
        )?;
        self.set_number(
            unsafe { kVTCompressionPropertyKey_ExpectedFrameRate },
            i64::from(fps.max(1)),
        )?;
        // A keyframe at least every two seconds, so a late joiner or a client
        // that lost the reference chain recovers without a manual request.
        self.set_number(
            unsafe { kVTCompressionPropertyKey_MaxKeyFrameInterval },
            i64::from(fps.max(1)) * 2,
        )?;
        Ok(())
    }

    fn set_bool(&self, key: CFStringRef, value: bool) -> Result<(), VtEncError> {
        let value = CFBoolean::from(value);
        // SAFETY: the key is a framework constant and the value outlives the call.
        let status =
            unsafe { VTSessionSetProperty(self.session, key, value.as_CFTypeRef().cast()) };
        if status != 0 {
            return Err(VtEncError::Status("set bool property", status));
        }
        Ok(())
    }

    fn set_number(&self, key: CFStringRef, value: i64) -> Result<(), VtEncError> {
        let value = CFNumber::from(value);
        // SAFETY: the key is a framework constant and the value outlives the call.
        let status =
            unsafe { VTSessionSetProperty(self.session, key, value.as_CFTypeRef().cast()) };
        if status != 0 {
            return Err(VtEncError::Status("set number property", status));
        }
        Ok(())
    }

    /// The SPS/PPS parameter sets as an Annex-B byte sequence, or `None` before
    /// the first keyframe has been produced.
    pub fn sequence_header(&self) -> Option<Vec<u8>> {
        self.shared.sequence_header.lock().ok()?.clone()
    }

    /// Make the next encoded frame a keyframe.
    pub fn force_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    /// Change the running encoder's average bitrate (bits per second).
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<(), VtEncError> {
        self.set_number(
            unsafe { kVTCompressionPropertyKey_AverageBitRate },
            i64::from(bitrate),
        )
    }

    /// Encode one BGRA frame (`width * height * 4` bytes, `B, G, R, A` per
    /// pixel), returning any access units the encoder emitted.
    pub fn encode(
        &mut self,
        bgra: &[u8],
        presentation_time_us: i64,
    ) -> Result<Vec<EncodedAccessUnit>, VtEncError> {
        let expected = self.width * self.height * 4;
        if bgra.len() < expected {
            return Err(VtEncError::FrameSize {
                expected,
                got: bgra.len(),
            });
        }
        let pixel_buffer = self.make_pixel_buffer(bgra)?;
        let force = std::mem::take(&mut self.force_keyframe);
        let frame_properties = force.then(force_keyframe_dictionary);
        let frame_properties_ref = frame_properties
            .as_ref()
            .map_or(std::ptr::null(), |dict| dict.as_concrete_TypeRef());

        // SAFETY: the pixel buffer and the optional property dictionary outlive
        // the call; a null duration is documented as "unknown".
        let status = unsafe {
            VTCompressionSessionEncodeFrame(
                self.session,
                pixel_buffer,
                CmTime::micros(presentation_time_us),
                CmTime::invalid(),
                frame_properties_ref,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // SAFETY: created by CVPixelBufferCreate; released once, here.
        unsafe { CFRelease(pixel_buffer.cast()) };
        if status != 0 {
            return Err(VtEncError::Status(
                "VTCompressionSessionEncodeFrame",
                status,
            ));
        }
        Ok(self.drain_ready())
    }

    /// Force every pending frame out and return them. Call at end of stream.
    pub fn flush(&mut self) -> Result<Vec<EncodedAccessUnit>, VtEncError> {
        // SAFETY: completing all frames on a live session is documented.
        let status = unsafe { VTCompressionSessionCompleteFrames(self.session, CmTime::invalid()) };
        if status != 0 {
            return Err(VtEncError::Status(
                "VTCompressionSessionCompleteFrames",
                status,
            ));
        }
        Ok(self.drain_ready())
    }

    fn drain_ready(&self) -> Vec<EncodedAccessUnit> {
        self.shared
            .ready
            .lock()
            .map(|mut queue| queue.drain(..).collect())
            .unwrap_or_default()
    }

    /// Copy a BGRA frame into a fresh CoreVideo pixel buffer, honouring the
    /// buffer's own row stride (which the encoder may pad).
    fn make_pixel_buffer(&self, bgra: &[u8]) -> Result<CvImageBufferRef, VtEncError> {
        let mut pixel_buffer: CvImageBufferRef = std::ptr::null_mut();
        // SAFETY: FFI. A null attributes dictionary is documented; the output
        // pointer is written on success.
        let status = unsafe {
            CVPixelBufferCreate(
                std::ptr::null(),
                self.width,
                self.height,
                K_CV_PIXEL_FORMAT_TYPE_32BGRA,
                std::ptr::null(),
                &mut pixel_buffer,
            )
        };
        if status != 0 || pixel_buffer.is_null() {
            return Err(VtEncError::Status("CVPixelBufferCreate", status));
        }
        // SAFETY: the buffer is locked for the copy and unlocked after; the base
        // address and stride are the locked buffer's own.
        unsafe {
            CVPixelBufferLockBaseAddress(pixel_buffer, K_CV_PIXEL_BUFFER_LOCK_WRITE);
            let base = CVPixelBufferGetBaseAddress(pixel_buffer).cast::<u8>();
            let dst_stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
            let src_stride = self.width * 4;
            if base.is_null() {
                CVPixelBufferUnlockBaseAddress(pixel_buffer, K_CV_PIXEL_BUFFER_LOCK_WRITE);
                CFRelease(pixel_buffer.cast());
                return Err(VtEncError::Status("CVPixelBufferGetBaseAddress", -1));
            }
            for row in 0..self.height {
                let src = bgra.as_ptr().add(row * src_stride);
                let dst = base.add(row * dst_stride);
                std::ptr::copy_nonoverlapping(src, dst, src_stride);
            }
            CVPixelBufferUnlockBaseAddress(pixel_buffer, K_CV_PIXEL_BUFFER_LOCK_WRITE);
        }
        Ok(pixel_buffer)
    }
}

impl Drop for VideoToolboxH264Encoder {
    fn drop(&mut self) {
        // SAFETY: invalidate stops any further callbacks (so nothing touches
        // `shared` after this), then the session handle is released once.
        unsafe {
            VTCompressionSessionInvalidate(self.session);
            CFRelease(self.session.cast());
        }
    }
}

/// The compression callback: turn one encoded sample into an Annex-B access
/// unit and push it to the shared queue. Runs on a VideoToolbox thread.
extern "C" fn compression_output(
    output_callback_ref_con: *mut c_void,
    _source_frame_ref_con: *mut c_void,
    status: OSStatus,
    _info_flags: u32,
    sample_buffer: CmSampleBufferRef,
) {
    if status != 0 || sample_buffer.is_null() || output_callback_ref_con.is_null() {
        return;
    }
    // SAFETY: the ref-con is the encoder's boxed `Shared`, alive until the
    // session is invalidated, which happens before the box is freed.
    let shared = unsafe { &*(output_callback_ref_con as *const Shared) };

    let keyframe = sample_is_keyframe(sample_buffer);
    let Some(mut annexb) = sample_to_annexb(sample_buffer) else {
        return;
    };

    if keyframe {
        if let Some(header) = format_sequence_header(sample_buffer) {
            if let Ok(mut slot) = shared.sequence_header.lock() {
                *slot = Some(header.clone());
            }
            let mut unit = header;
            unit.append(&mut annexb);
            annexb = unit;
        }
    }

    if let Ok(mut queue) = shared.ready.lock() {
        queue.push_back(EncodedAccessUnit {
            data: annexb,
            keyframe,
        });
    }
}

/// Whether a sample is a sync sample (keyframe): keyframe unless its attachments
/// mark it `NotSync = true`.
fn sample_is_keyframe(sample_buffer: CmSampleBufferRef) -> bool {
    // SAFETY: reading the attachments array of a live sample buffer.
    unsafe {
        let attachments = CMSampleBufferGetSampleAttachmentsArray(sample_buffer, 0);
        if attachments.is_null() || CFArrayGetCount(attachments) == 0 {
            return true;
        }
        let dict = CFArrayGetValueAtIndex(attachments, 0);
        if dict.is_null() {
            return true;
        }
        let not_sync = CFDictionaryGetValue(dict.cast(), kCMSampleAttachmentKey_NotSync.cast());
        if not_sync.is_null() {
            return true;
        }
        CFBooleanGetValue(not_sync.cast()) == 0
    }
}

/// Convert a sample's length-prefixed (AVCC) H.264 data into Annex-B start-code
/// form.
fn sample_to_annexb(sample_buffer: CmSampleBufferRef) -> Option<Vec<u8>> {
    // SAFETY: FFI. The block buffer is the sample's own; its length is queried
    // and the exact bytes are copied out.
    unsafe {
        let block = CMSampleBufferGetDataBuffer(sample_buffer);
        if block.is_null() {
            return None;
        }
        let length = CMBlockBufferGetDataLength(block);
        if length == 0 {
            return None;
        }
        let mut avcc = vec![0u8; length];
        let status = CMBlockBufferCopyDataBytes(block, 0, length, avcc.as_mut_ptr().cast());
        if status != 0 {
            return None;
        }
        avcc_to_annexb(&avcc)
    }
}

/// Rewrite 4-byte-length-prefixed NAL units as 4-byte start codes.
fn avcc_to_annexb(avcc: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(avcc.len());
    let mut offset = 0usize;
    while offset + 4 <= avcc.len() {
        let length = u32::from_be_bytes([
            avcc[offset],
            avcc[offset + 1],
            avcc[offset + 2],
            avcc[offset + 3],
        ]) as usize;
        offset += 4;
        if length == 0 || offset + length > avcc.len() {
            return None;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&avcc[offset..offset + length]);
        offset += length;
    }
    (offset == avcc.len()).then_some(out)
}

/// Build the Annex-B SPS/PPS sequence header from a sample's H.264 format
/// description.
fn format_sequence_header(sample_buffer: CmSampleBufferRef) -> Option<Vec<u8>> {
    // SAFETY: FFI. The format description is the sample's own; each parameter
    // set pointer is valid for the copy that immediately follows.
    unsafe {
        let format = CMSampleBufferGetFormatDescription(sample_buffer);
        if format.is_null() {
            return None;
        }
        let mut header = Vec::new();
        for index in 0..2usize {
            let mut pointer: *const u8 = std::ptr::null();
            let mut size: usize = 0;
            let mut count: usize = 0;
            let status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                format,
                index,
                &mut pointer,
                &mut size,
                &mut count,
                std::ptr::null_mut(),
            );
            if status != 0 || pointer.is_null() || size == 0 {
                return None;
            }
            header.extend_from_slice(&[0, 0, 0, 1]);
            header.extend_from_slice(std::slice::from_raw_parts(pointer, size));
        }
        Some(header)
    }
}

/// A frame-properties dictionary that forces this frame to be a keyframe.
fn force_keyframe_dictionary() -> CFDictionary<CFString, CFBoolean> {
    let key = unsafe { CFString::wrap_under_get_rule(kVTEncodeFrameOptionKey_ForceKeyFrame) };
    CFDictionary::from_CFType_pairs(&[(key, CFBoolean::true_value())])
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: u32 = 320;
    const HEIGHT: u32 = 240;

    /// A BGRA frame with a moving vertical band, so successive frames differ and
    /// the encoder produces real inter frames rather than repeating one picture.
    fn frame(seed: u8) -> Vec<u8> {
        let mut pixels = vec![0u8; (WIDTH * HEIGHT * 4) as usize];
        let band = usize::from(seed) % WIDTH as usize;
        for row in 0..HEIGHT as usize {
            for col in 0..WIDTH as usize {
                let at = (row * WIDTH as usize + col) * 4;
                let lit = col == band;
                pixels[at] = if lit { 0xFF } else { 0x20 }; // B
                pixels[at + 1] = u8::try_from((row * 255) / HEIGHT as usize).unwrap_or(0); // G
                pixels[at + 2] = seed; // R
                pixels[at + 3] = 0xFF; // A
            }
        }
        pixels
    }

    fn has_nal(stream: &[u8], types: &[u8]) -> bool {
        let mut i = 0;
        while i + 4 < stream.len() {
            if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 0 && stream[i + 3] == 1 {
                let nal_type = stream[i + 4] & 0x1f;
                if types.contains(&nal_type) {
                    return true;
                }
                i += 4;
            } else {
                i += 1;
            }
        }
        false
    }

    #[test]
    fn annexb_conversion_rewrites_length_prefixes_as_start_codes() {
        // Two NALs: [len=2][0x67,0x01] then [len=1][0x68].
        let avcc = [0, 0, 0, 2, 0x67, 0x01, 0, 0, 0, 1, 0x68];
        let annexb = avcc_to_annexb(&avcc).expect("valid AVCC");
        assert_eq!(annexb, vec![0, 0, 0, 1, 0x67, 0x01, 0, 0, 0, 1, 0x68]);
    }

    #[test]
    fn avcc_conversion_rejects_a_truncated_length() {
        assert!(avcc_to_annexb(&[0, 0, 0, 9, 0x67]).is_none());
    }

    #[test]
    fn encodes_bgra_frames_to_an_h264_stream_with_parameter_sets() {
        let mut encoder = match VideoToolboxH264Encoder::new(WIDTH, HEIGHT, 30, 4_000_000) {
            Ok(encoder) => encoder,
            Err(error) => {
                if std::env::var_os("OPENSTREAM_REQUIRE_VT_TEST").is_some() {
                    panic!("VideoToolbox encoder required but unavailable: {error}");
                }
                eprintln!("skipping VideoToolbox encode test: unavailable ({error})");
                return;
            }
        };
        let mut stream = Vec::new();
        let mut keyframes = 0usize;
        for n in 0..30u8 {
            let pts = i64::from(n) * 33_333;
            for unit in encoder.encode(&frame(n), pts).expect("encode") {
                if unit.keyframe {
                    keyframes += 1;
                }
                stream.extend_from_slice(&unit.data);
            }
        }
        for unit in encoder.flush().expect("flush") {
            if unit.keyframe {
                keyframes += 1;
            }
            stream.extend_from_slice(&unit.data);
        }

        assert!(!stream.is_empty(), "the encoder produced no output");
        assert!(keyframes >= 1, "no keyframe was produced");
        // Coded slices (NAL type 1 or 5) and an SPS (type 7) prepended to the
        // keyframe, so a decoder can start.
        assert!(
            has_nal(&stream, &[1, 5]),
            "no coded slice NAL in the stream"
        );
        assert!(has_nal(&stream, &[7]), "no SPS in the stream");
        assert!(
            encoder.sequence_header().is_some(),
            "no sequence header after a keyframe"
        );
    }
}
