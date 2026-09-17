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

use core_foundation::array::CFArray;
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
/// A `CVPixelBufferRef`. Public because [`VideoToolboxH264Encoder::encode_surface`]
/// takes one: a caller with a capture surface has to be able to name the type.
pub type CvImageBufferRef = *mut c_void;
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

    fn VTSessionCopyProperty(
        session: VtCompressionSessionRef,
        property_key: CFStringRef,
        allocator: CfAllocatorRef,
        property_value_out: *mut CFTypeRef,
    ) -> OSStatus;

    static kVTCompressionPropertyKey_RealTime: CFStringRef;
    static kVTCompressionPropertyKey_ProfileLevel: CFStringRef;
    static kVTCompressionPropertyKey_AverageBitRate: CFStringRef;
    static kVTCompressionPropertyKey_ExpectedFrameRate: CFStringRef;
    static kVTCompressionPropertyKey_MaxKeyFrameInterval: CFStringRef;
    static kVTCompressionPropertyKey_AllowFrameReordering: CFStringRef;
    /// How many frames the encoder may hold before emitting one. Optional:
    /// a codec that does not support it returns a non-zero status.
    static kVTCompressionPropertyKey_MaxFrameDelayCount: CFStringRef;
    /// How many frames the session is currently holding. Read-only.
    static kVTCompressionPropertyKey_NumberOfPendingFrames: CFStringRef;
    /// Hint that latency matters more than compression efficiency. Apple
    /// recommends it for ultra-low-latency work.
    static kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality: CFStringRef;
    /// A hard ceiling on bytes emitted per window, as a two-element array of
    /// [bytes, seconds]. Distinct from AverageBitRate, which is a target the
    /// encoder may overshoot.
    static kVTCompressionPropertyKey_DataRateLimits: CFStringRef;
    /// Encoder-specification key enabling Apple's low-latency rate control,
    /// which Apple documents for cloud gaming and conferencing.
    static kVTVideoEncoderSpecification_EnableLowLatencyRateControl: CFStringRef;
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

/// The hard per-second byte ceiling for a given bitrate.
///
/// The nominal rate plus a ninth. A ceiling set exactly at the target leaves
/// the rate controller nothing for the frames that genuinely need more, and it
/// responds by dropping quality across the board; a ninth is enough for a
/// keyframe to exceed a delta frame without being enough for a burst to queue
/// anywhere that matters.
///
/// One function so session setup and bitrate adaptation cannot drift apart --
/// a ceiling computed one way at startup and another way on adaptation is a bug
/// that only shows up after the first rate change.
#[must_use]
fn burst_ceiling_bytes(bitrate: u32) -> i64 {
    i64::from(bitrate) / 8 * 10 / 9
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
    /// The frame-delay ceiling this session accepted, or `None` if the encoder
    /// refused every rung of the ladder. Diagnostic: the caller reports it so a
    /// measurement can be read against the setting that produced it.
    max_frame_delay: Option<i64>,
    /// Whether Apple's low-latency rate control was enabled at session
    /// creation.
    low_latency_rate_control: bool,
    /// Whether the encoder accepted the speed-over-quality hint.
    prioritise_speed: bool,
    /// The per-second byte ceiling the session accepted, if any.
    data_rate_limit: Option<i64>,
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

        // Ask for Apple's low-latency rate control. Unlike the compression
        // properties below this is an *encoder specification*: it selects how
        // the encoder is built, so it cannot be turned on afterwards. Apple
        // documents it for conferencing and cloud gaming -- it caps the
        // rate controller's lookahead rather than only asking for real-time
        // pacing.
        //
        // It is not available for every codec on every machine, and the
        // documented failure is that session creation itself fails. So try it,
        // and on any failure build the session the way this encoder always did.
        // A session that exists without it beats no session.
        let (session, low_latency_rate_control) =
            match Self::create_session(width, height, ref_con, true) {
                Ok(session) => (session, true),
                Err(_) => (Self::create_session(width, height, ref_con, false)?, false),
            };

        let mut encoder = Self {
            session,
            width: width as usize,
            height: height as usize,
            shared,
            force_keyframe: false,
            max_frame_delay: None,
            low_latency_rate_control,
            prioritise_speed: false,
            data_rate_limit: None,
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

    /// Build the compression session, optionally requesting low-latency rate
    /// control through the encoder specification.
    fn create_session(
        width: u32,
        height: u32,
        ref_con: *mut c_void,
        low_latency: bool,
    ) -> Result<VtCompressionSessionRef, VtEncError> {
        // Held for the duration of the call: VideoToolbox copies what it needs
        // out of the specification dictionary.
        let spec = low_latency.then(|| {
            CFDictionary::from_CFType_pairs(&[(
                // SAFETY: a framework constant, valid for the process lifetime.
                unsafe {
                    CFString::wrap_under_get_rule(
                        kVTVideoEncoderSpecification_EnableLowLatencyRateControl,
                    )
                }
                .as_CFType(),
                CFBoolean::true_value().as_CFType(),
            )])
        });
        let spec_ref: CFDictionaryRef = spec
            .as_ref()
            .map_or(std::ptr::null(), TCFType::as_concrete_TypeRef);

        let mut session: VtCompressionSessionRef = std::ptr::null_mut();
        // SAFETY: FFI. A null source spec lets VideoToolbox pick the pixel
        // format; the callback and its ref-con outlive the session (it is
        // invalidated before the box drops).
        let status = unsafe {
            VTCompressionSessionCreate(
                std::ptr::null(),
                i32::try_from(width).unwrap_or(i32::MAX),
                i32::try_from(height).unwrap_or(i32::MAX),
                K_CM_VIDEO_CODEC_TYPE_H264,
                spec_ref,
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
        Ok(session)
    }

    fn configure(&mut self, fps: u32, bitrate: u32) -> Result<(), VtEncError> {
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

        // Bound how many frames the encoder may hold before it emits one.
        //
        // VideoToolbox's documented default is an *unlimited* compression
        // window. That permits buffering; it is not evidence that this encoder
        // is buffering, which is what [`pending_frames`] is for. The ladder is
        // here because the property is optional: a codec that does not
        // implement it, or implements it read-only, refuses the value, and an
        // encoder that refuses 0 may still accept 1. Take the tightest rung
        // that sticks and record it, so a later measurement can be read against
        // the setting that produced it.
        //
        // Never fatal. An encoder that refuses the whole ladder encodes
        // correctly; it just keeps the default window.
        for candidate in [0_i64, 1, 2] {
            if self
                .try_set_number(
                    unsafe { kVTCompressionPropertyKey_MaxFrameDelayCount },
                    candidate,
                )
                .is_ok()
            {
                self.max_frame_delay = Some(candidate);
                break;
            }
        }

        // Cap the burst, not just the average.
        //
        // AverageBitRate is a target the rate controller converges on over
        // time; it says nothing about any one second. A keyframe or a scene
        // change can emit several times the average in a single window, and on
        // a link provisioned for the average that excess does not vanish -- it
        // queues, somewhere between here and the client, and arrives as
        // latency. DataRateLimits is the hard ceiling that stops it.
        //
        // The window is one second and the ceiling is the nominal bitrate plus
        // a ninth. The headroom exists because a limit set exactly at the
        // target leaves the rate controller nothing to work with on the frames
        // that genuinely need more, and it responds by dropping quality across
        // the board. A ninth is enough for a keyframe to be bigger than a delta
        // frame without being enough for a burst to matter.
        //
        // The value is an array of [bytes, seconds], in that order -- not a
        // bits-per-second number, and not [seconds, bytes]. Getting it backwards
        // yields a limit of a few bytes per several-billion-second window, which
        // the encoder accepts and then honours, so the mistake shows up as an
        // unaccountably terrible picture rather than as an error.
        let bytes_per_window = burst_ceiling_bytes(bitrate);
        self.data_rate_limit = self
            .try_set_data_rate_limit(bytes_per_window, 1.0)
            .is_ok()
            .then_some(bytes_per_window);

        // Ask the encoder to spend less time searching for a smaller frame.
        // Optional in the same way: absent on older systems and on codecs that
        // do not implement it.
        self.prioritise_speed = self
            .try_set_bool(
                unsafe { kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality },
                true,
            )
            .is_ok();

        Ok(())
    }

    /// Read a numeric session property, or `None` if it is unavailable.
    ///
    /// Used for read-only diagnostics, where "the encoder did not answer" is a
    /// fact about this machine and not a failure worth ending a session over.
    fn number_property(&self, key: CFStringRef) -> Option<i64> {
        let mut value: CFTypeRef = std::ptr::null();
        // SAFETY: the key is a framework constant; on success we own the value
        // under the Copy rule and release it below.
        let status =
            unsafe { VTSessionCopyProperty(self.session, key, std::ptr::null(), &mut value) };
        if status != 0 || value.is_null() {
            return None;
        }
        // SAFETY: the property is documented as a CFNumber.
        let number = unsafe { CFNumber::wrap_under_create_rule(value.cast()) };
        number.to_i64()
    }

    /// How many frames VideoToolbox is currently holding.
    ///
    /// This is the measurement that decides whether any of the queue-limiting
    /// properties are worth setting. Apple documents the default compression
    /// window as unlimited, which *permits* buffering -- it is not evidence
    /// that this encoder, on this machine, with these settings, is actually
    /// holding frames. Measure before constraining.
    ///
    /// `None` when the session does not report it.
    #[must_use]
    pub fn pending_frames(&self) -> Option<i64> {
        self.number_property(unsafe { kVTCompressionPropertyKey_NumberOfPendingFrames })
    }

    /// The frame-delay ceiling the session accepted, if any.
    ///
    /// `None` means the encoder refused every value tried, which is a
    /// supported outcome rather than an error: the property is optional and a
    /// codec that does not implement it still encodes correctly.
    #[must_use]
    pub fn max_frame_delay(&self) -> Option<i64> {
        self.max_frame_delay
    }

    /// Whether the session was created with Apple's low-latency rate control.
    #[must_use]
    pub fn low_latency_rate_control(&self) -> bool {
        self.low_latency_rate_control
    }

    /// Whether the encoder accepted the speed-over-quality hint.
    #[must_use]
    pub fn prioritises_speed(&self) -> bool {
        self.prioritise_speed
    }

    /// The per-second byte ceiling in force, or `None` if the encoder refused
    /// one. Optional in the same way as the other rate properties.
    #[must_use]
    pub fn data_rate_limit(&self) -> Option<i64> {
        self.data_rate_limit
    }

    /// Set the hard byte ceiling over a window, returning the raw status.
    ///
    /// The property takes a CFArray of exactly two numbers, byte count first
    /// and window length in seconds second.
    fn try_set_data_rate_limit(&self, bytes: i64, seconds: f64) -> Result<(), OSStatus> {
        let limits = CFArray::from_CFTypes(&[
            CFNumber::from(bytes).as_CFType(),
            CFNumber::from(seconds).as_CFType(),
        ]);
        // SAFETY: the key is a framework constant and the array outlives the call.
        let status = unsafe {
            VTSessionSetProperty(
                self.session,
                kVTCompressionPropertyKey_DataRateLimits,
                limits.as_CFTypeRef().cast(),
            )
        };
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Set a boolean property, returning the raw status instead of failing the
    /// session. For optional properties only.
    fn try_set_bool(&self, key: CFStringRef, value: bool) -> Result<(), OSStatus> {
        let value = CFBoolean::from(value);
        // SAFETY: the key is a framework constant and the value outlives the call.
        let status =
            unsafe { VTSessionSetProperty(self.session, key, value.as_CFTypeRef().cast()) };
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Set a numeric property, returning the raw status instead of failing the
    /// session. For optional properties only.
    fn try_set_number(&self, key: CFStringRef, value: i64) -> Result<(), OSStatus> {
        let value = CFNumber::from(value);
        // SAFETY: the key is a framework constant and the value outlives the call.
        let status =
            unsafe { VTSessionSetProperty(self.session, key, value.as_CFTypeRef().cast()) };
        if status == 0 { Ok(()) } else { Err(status) }
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
    ///
    /// Moves the hard burst ceiling with it. Leaving `DataRateLimits` at the
    /// value it was configured with breaks adaptation in both directions: after
    /// an increase the old, lower ceiling clamps the encoder below the bitrate
    /// it was just told to use, and the picture degrades for no visible reason;
    /// after a decrease the old, higher ceiling permits exactly the bursts the
    /// ceiling exists to prevent, on a link that has just been found too slow
    /// for them.
    ///
    /// The order is chosen so the two are never inconsistent in the direction
    /// that hurts:
    ///
    ///   * raising the bitrate raises the ceiling **first**, so the average is
    ///     never set above a ceiling that would clamp it;
    ///   * lowering it lowers the average **first**, so the ceiling is never
    ///     tightened around an average still set high.
    ///
    /// The ceiling is only touched if one was accepted at session creation. An
    /// encoder that refused it keeps refusing it, and a failure to move it is
    /// not made fatal for the same reason it was not fatal then -- but the
    /// recorded value is cleared rather than left describing a limit that is no
    /// longer in force.
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<(), VtEncError> {
        let average = unsafe { kVTCompressionPropertyKey_AverageBitRate };
        let target = i64::from(bitrate);
        let ceiling = burst_ceiling_bytes(bitrate);
        let raising = self
            .data_rate_limit
            .is_some_and(|current| ceiling > current);

        if self.data_rate_limit.is_some() && raising {
            self.move_burst_ceiling(ceiling);
        }
        self.set_number(average, target)?;
        if self.data_rate_limit.is_some() && !raising {
            self.move_burst_ceiling(ceiling);
        }
        Ok(())
    }

    /// Set the burst ceiling and record what is actually in force.
    ///
    /// On failure the recorded value is cleared: reporting the old number would
    /// describe a limit the session is no longer honouring, which is worse than
    /// reporting none.
    fn move_burst_ceiling(&mut self, bytes_per_window: i64) {
        self.data_rate_limit = self
            .try_set_data_rate_limit(bytes_per_window, 1.0)
            .is_ok()
            .then_some(bytes_per_window);
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
        let result = self.submit(pixel_buffer, presentation_time_us);
        // SAFETY: created by CVPixelBufferCreate just above; released once,
        // here, whether or not the submit succeeded.
        unsafe { CFRelease(pixel_buffer.cast()) };
        result
    }

    /// Encode a frame the caller already holds as a `CVPixelBuffer`, without
    /// copying its pixels.
    ///
    /// This is the path a capture source that hands back IOSurface-backed
    /// buffers -- ScreenCaptureKit, or a GPU decoder -- should take.
    /// [`encode`](Self::encode) has to allocate a pixel buffer and copy several
    /// megabytes into it row by row before VideoToolbox sees anything; here the
    /// buffer the capture produced goes straight to the hardware.
    ///
    /// # Safety
    ///
    /// `pixel_buffer` must be a valid `CVPixelBufferRef` that stays alive for
    /// the duration of the call. Ownership is *not* taken: the caller releases
    /// it as before. Its pixel format and dimensions must match what the
    /// session was created with; VideoToolbox rejects a mismatch with a status
    /// rather than misreading memory, so a wrong buffer is an error, not
    /// undefined behaviour -- but a dangling one is.
    pub unsafe fn encode_surface(
        &mut self,
        pixel_buffer: CvImageBufferRef,
        presentation_time_us: i64,
    ) -> Result<Vec<EncodedAccessUnit>, VtEncError> {
        if pixel_buffer.is_null() {
            return Err(VtEncError::Status("encode_surface: null pixel buffer", -1));
        }
        self.submit(pixel_buffer, presentation_time_us)
    }

    /// Hand one pixel buffer to the session. Shared by both entry points so a
    /// keyframe forced before either one is honoured identically, and so the
    /// two paths cannot drift on timestamps or property handling.
    ///
    /// Does not release `pixel_buffer`: whoever created it decides that.
    fn submit(
        &mut self,
        pixel_buffer: CvImageBufferRef,
        presentation_time_us: i64,
    ) -> Result<Vec<EncodedAccessUnit>, VtEncError> {
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
        if status != 0 {
            return Err(VtEncError::Status(
                "VTCompressionSessionEncodeFrame",
                status,
            ));
        }
        Ok(self.drain_ready())
    }

    /// Take whatever the encoder has finished, without submitting anything.
    ///
    /// The compression callback runs on a VideoToolbox thread, so output can
    /// become available at any time -- not only while a submit is in progress.
    /// A caller that only drains as a side effect of submitting will not see a
    /// finished frame until the *next* one arrives, which on a still screen can
    /// be a long time. This is how such a caller looks.
    pub fn take_ready(&mut self) -> Vec<EncodedAccessUnit> {
        self.drain_ready()
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

    /// Split an Annex-B stream into NALs, dropping SEI (type 6).
    ///
    /// Only 4-byte start codes appear here: the encoder's AVCC-to-Annex-B
    /// conversion writes those exclusively.
    fn without_sei(stream: &[u8]) -> Vec<Vec<u8>> {
        let mut starts = Vec::new();
        let mut index = 0;
        while index + 4 <= stream.len() {
            if stream[index..index + 4] == [0, 0, 0, 1] {
                starts.push(index + 4);
                index += 4;
            } else {
                index += 1;
            }
        }
        let mut nals = Vec::new();
        for (position, &start) in starts.iter().enumerate() {
            let end = starts
                .get(position + 1)
                .map_or(stream.len(), |next| next - 4);
            if start < end && stream[start] & 0x1f != 6 {
                nals.push(stream[start..end].to_vec());
            }
        }
        nals
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

    /// A caller-owned surface must encode to exactly what the copying path
    /// produces, and must still be the caller's to release afterwards.
    ///
    /// Byte equality is the strong form of the claim on purpose: the host is
    /// about to stop copying capture buffers and hand VideoToolbox the
    /// IOSurface it was given, and "the stream looks similar" would not rule
    /// out a subtly different picture reaching the wire. Two fresh sessions
    /// with identical settings, fed identical frames, differ only in how the
    /// pixels arrived.
    ///
    /// The release at the end is part of the test: `encode_surface` documents
    /// that it does not take ownership, and if it did release the buffer this
    /// would be a double free.
    #[test]
    fn encoding_from_a_caller_owned_surface_matches_the_copying_path() {
        let make = || VideoToolboxH264Encoder::new(WIDTH, HEIGHT, 30, 4_000_000);
        let (mut copying, mut from_surface) = match (make(), make()) {
            (Ok(first), Ok(second)) => (first, second),
            (first, second) => {
                let error = first.err().or(second.err()).expect("one of them failed");
                if std::env::var_os("OPENSTREAM_REQUIRE_VT_TEST").is_some() {
                    panic!("VideoToolbox encoder required but unavailable: {error}");
                }
                eprintln!("skipping VideoToolbox surface-encode test: unavailable ({error})");
                return;
            }
        };

        let mut copied_stream = Vec::new();
        let mut surface_stream = Vec::new();
        for n in 0..10u8 {
            let pts = i64::from(n) * 33_333;
            let pixels = frame(n);

            for unit in copying.encode(&pixels, pts).expect("encode by copy") {
                copied_stream.extend_from_slice(&unit.data);
            }

            let buffer = from_surface
                .make_pixel_buffer(&pixels)
                .expect("build a pixel buffer");
            // SAFETY: `buffer` was just created, is the session's format and
            // size, and is alive across the call.
            let units = unsafe { from_surface.encode_surface(buffer, pts) };
            let units = units.expect("encode from surface");
            for unit in units {
                surface_stream.extend_from_slice(&unit.data);
            }
            // SAFETY: we still own it -- `encode_surface` takes no ownership.
            unsafe { CFRelease(buffer.cast()) };
        }
        for unit in copying.flush().expect("flush") {
            copied_stream.extend_from_slice(&unit.data);
        }
        for unit in from_surface.flush().expect("flush") {
            surface_stream.extend_from_slice(&unit.data);
        }

        assert!(
            !surface_stream.is_empty(),
            "the surface path produced no output"
        );
        // SEI NALs are excluded: VideoToolbox stamps each session's SEI with
        // per-session identifiers, so two sessions never agree on them, and
        // they carry no picture. Everything that does -- the parameter sets
        // and every coded slice -- must match byte for byte.
        assert_eq!(
            without_sei(&surface_stream),
            without_sei(&copied_stream),
            "the surface path must encode the same picture as the copying path"
        );
    }

    /// A null surface is rejected, not dereferenced. The capture source is
    /// about to hand these in from an Objective-C callback, where a missing
    /// image buffer is an ordinary runtime outcome rather than a bug.
    #[test]
    fn the_burst_ceiling_is_the_nominal_rate_plus_a_ninth() {
        // [bytes, seconds], so bits/8, and 10/9 is the headroom. 10 Mbps ->
        // 1388888 bytes/s, an 11.11 Mbps ceiling.
        assert_eq!(super::burst_ceiling_bytes(10_000_000), 1_388_888);
        assert_eq!(super::burst_ceiling_bytes(0), 0);
    }

    #[test]
    fn adapting_the_bitrate_moves_the_burst_ceiling_with_it() {
        // The bug this pins: `set_bitrate` used to move only AverageBitRate.
        // After an increase the old lower ceiling clamped the encoder below the
        // rate it had just been given; after a decrease the old higher ceiling
        // allowed exactly the bursts the ceiling exists to stop.
        let Ok(mut encoder) = VideoToolboxH264Encoder::new(640, 480, 30, 4_000_000) else {
            eprintln!("no VideoToolbox encoder available; skipping");
            return;
        };
        let Some(initial) = encoder.data_rate_limit() else {
            eprintln!("this encoder refused DataRateLimits; nothing to adapt");
            return;
        };
        assert_eq!(initial, super::burst_ceiling_bytes(4_000_000));

        encoder.set_bitrate(8_000_000).expect("raise the bitrate");
        assert_eq!(
            encoder.data_rate_limit(),
            Some(super::burst_ceiling_bytes(8_000_000)),
            "raising the bitrate must raise the ceiling, or the encoder stays clamped"
        );

        encoder.set_bitrate(2_000_000).expect("lower the bitrate");
        assert_eq!(
            encoder.data_rate_limit(),
            Some(super::burst_ceiling_bytes(2_000_000)),
            "lowering the bitrate must lower the ceiling, or bursts stay permitted"
        );
    }

    #[test]
    fn a_null_surface_is_an_error_not_a_crash() {
        let Ok(mut encoder) = VideoToolboxH264Encoder::new(WIDTH, HEIGHT, 30, 4_000_000) else {
            eprintln!("skipping: VideoToolbox encoder unavailable");
            return;
        };
        // SAFETY: null is the case under test; the function must check it
        // before any dereference.
        let result = unsafe { encoder.encode_surface(std::ptr::null_mut(), 0) };
        assert!(result.is_err(), "a null surface must not be submitted");
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
