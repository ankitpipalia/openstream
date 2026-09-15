//! In-process H.264 decode on Windows via the Media Foundation decoder MFT.
//!
//! This is the Windows counterpart to the macOS VideoToolbox path
//! ([`crate::vt_decoder`]): it decodes H.264 access units in-process, with no
//! external ffmpeg subprocess, so the client matches Parsec's model of a native
//! decoder linked into the app. It uses the OS "H.264 Video Decoder" MFT
//! (`CLSID_CMSH264DecoderMFT`), which is vendor-neutral -- it runs on NVIDIA,
//! AMD and Intel GPUs through the OS, and falls back to the OS software decoder
//! where no hardware decoder is present -- so it is preferred over any single
//! vendor SDK (NVDEC/AMF/QSV).
//!
//! The MFT emits NV12; [`crate::nv12`] converts that to the BGRA the presenter
//! consumes. The buffer geometry and colour conversion live in that pure,
//! cross-platform-tested module; this file is the COM/MFT plumbing that feeds
//! it and is therefore compiled and exercised only on Windows.
//!
//! Verification: the test at the bottom decodes a committed H.264 fixture and
//! checks the frame count, dimensions and centre colour. It runs on the Windows
//! CI job against the OS decoder MFT (the software decoder is always present, so
//! CI needs no GPU). That proves functional correctness through the real MFT;
//! confirming a *hardware* decoder is selected on a specific GPU is a separate
//! on-hardware check, not something this test claims.

#![cfg(target_os = "windows")]

use std::mem::ManuallyDrop;
use std::sync::Once;
use std::sync::atomic::{AtomicI32, Ordering};

use windows::Win32::Media::MediaFoundation::{
    CLSID_MSH264DecoderMFT, IMFMediaType, IMFSample, IMFTransform, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_SIZE,
    MF_MT_MAJOR_TYPE, MF_MT_MINIMUM_DISPLAY_APERTURE, MF_MT_SUBTYPE, MF_VERSION, MFCreateMediaType,
    MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFSTARTUP_NOSOCKET, MFStartup,
    MFT_MESSAGE_COMMAND_DRAIN, MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER, MFVideoArea, MFVideoFormat_H264,
    MFVideoFormat_NV12,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::GUID;

use crate::nv12::{nv12_contiguous_planes, nv12_to_bgra};

/// A decoded picture: BGRA pixels (one per `u32`, `B | G<<8 | R<<16 | A<<24`)
/// ready for the presenter, plus its dimensions.
pub(crate) struct MfFrame {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) pixels: Vec<u32>,
}

/// Why a Media Foundation decode failed.
#[derive(Debug)]
pub(crate) enum MfError {
    /// A Media Foundation / COM call returned a failure `HRESULT`.
    Windows(windows::core::Error),
    /// The MFT advertised no NV12 output type (only NV12 is handled today).
    UnsupportedOutputFormat,
    /// The decoded buffer was smaller than its declared geometry, so it could
    /// not be read safely.
    ShortBuffer,
}

impl std::fmt::Display for MfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfError::Windows(error) => write!(f, "media foundation error: {error}"),
            MfError::UnsupportedOutputFormat => {
                write!(f, "media foundation advertised no NV12 output format")
            }
            MfError::ShortBuffer => write!(f, "media foundation output buffer was too short"),
        }
    }
}

impl std::error::Error for MfError {}

impl From<windows::core::Error> for MfError {
    fn from(error: windows::core::Error) -> Self {
        MfError::Windows(error)
    }
}

/// Start Media Foundation once for the process.
///
/// `MFStartup` is reference counted, but this program only ever needs it
/// running; starting it once and never shutting it down avoids racing a
/// shutdown against a decoder on another thread. The resulting `HRESULT` is
/// cached so a second decoder observes the same outcome.
fn ensure_media_foundation_started() -> Result<(), MfError> {
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
    windows::core::HRESULT(CODE.load(Ordering::SeqCst))
        .ok()
        .map_err(MfError::from)
}

/// Unpack a `width << 32 | height` attribute (Media Foundation's `MF_MT_FRAME_SIZE`
/// layout).
fn attribute_size(media_type: &IMFMediaType, key: &GUID) -> Result<(u32, u32), MfError> {
    // SAFETY: `key` is a valid attribute GUID and `media_type` is a live COM
    // object; `GetUINT64` writes only its return value.
    let packed = unsafe { media_type.GetUINT64(key) }?;
    // Both halves are 32 bits wide, so the conversions never fail.
    let width = u32::try_from(packed >> 32).unwrap_or(u32::MAX);
    let height = u32::try_from(packed & 0xffff_ffff).unwrap_or(u32::MAX);
    Ok((width, height))
}

/// The in-process Media Foundation H.264 decoder.
pub(crate) struct MediaFoundationH264Decoder {
    transform: IMFTransform,
    /// Visible picture width (the display aperture), the width of an emitted
    /// frame.
    width: usize,
    /// Visible picture height (the display aperture).
    height: usize,
    /// Coded frame height, aligned up to a macroblock multiple (e.g. 120 -> 128).
    /// The decoder's NV12 buffer is this tall, so the plane split uses it while
    /// the visible `height` bounds the converted output.
    coded_height: usize,
    /// Luma row stride of the decoder's NV12 buffer (>= coded width).
    stride: usize,
    output_configured: bool,
}

impl MediaFoundationH264Decoder {
    /// Create a decoder ready to accept Annex-B H.264 access units.
    ///
    /// The output type is negotiated lazily: the MFT cannot describe its output
    /// until it has parsed the stream's parameter sets, so [`Self::decode`]
    /// configures NV12 output on the first stream-change signal.
    pub(crate) fn new() -> Result<Self, MfError> {
        ensure_media_foundation_started()?;

        // SAFETY: FFI to Media Foundation. `CoCreateInstance` yields a live
        // `IMFTransform`; the type object and messages below are used per the
        // MFT contract (set the input type, then stream in the encoded samples).
        let transform: IMFTransform =
            unsafe { CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)? };

        // Low-latency mode: the decoder must not reorder or hold frames waiting
        // for a full GOP, which is exactly the queueing the latency work removed
        // elsewhere. Best-effort: not every decoder exposes the attribute.
        // SAFETY: `GetAttributes` returns the MFT's attribute store; setting a
        // documented UINT32 attribute on it is safe.
        unsafe {
            if let Ok(attributes) = transform.GetAttributes() {
                let _ = attributes.SetUINT32(&MF_LOW_LATENCY, 1);
            }
        }

        // Input type: H.264 video, major type and subtype only. The decoder
        // learns the dimensions from the bitstream.
        // SAFETY: freshly created media type; GUID keys/values are valid.
        unsafe {
            let input_type = MFCreateMediaType()?;
            input_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            transform.SetInputType(0, &input_type, 0)?;
        }

        let mut decoder = Self {
            transform,
            width: 0,
            height: 0,
            coded_height: 0,
            stride: 0,
            output_configured: false,
        };

        // The decoder MFT requires an output type before it will accept input --
        // otherwise ProcessInput fails with MF_E_TRANSFORM_TYPE_NOT_SET. Select
        // NV12 now; the real frame size is not known until the decoder parses the
        // stream's parameter sets, so it arrives with the first stream-change
        // signal and reconfigures the geometry then.
        decoder.configure_nv12_output()?;

        // Begin streaming.
        // SAFETY: standard MFT lifecycle messages on a live transform.
        unsafe {
            decoder
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            decoder
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(decoder)
    }

    /// Decode one Annex-B access unit, returning every picture it produced.
    ///
    /// `presentation_time_us` stamps the input sample so the decoder can order
    /// output; the client assigns its own sequence numbers downstream.
    pub(crate) fn decode(
        &mut self,
        access_unit: &[u8],
        presentation_time_us: i64,
    ) -> Result<Vec<MfFrame>, MfError> {
        self.submit(access_unit, presentation_time_us)?;
        self.drain()
    }

    /// Signal end of stream and pull every remaining picture. Call once after
    /// the last access unit so frames the decoder still holds are emitted.
    pub(crate) fn flush(&mut self) -> Result<Vec<MfFrame>, MfError> {
        // SAFETY: draining an MFT is a documented message on a live transform.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0)?;
        }
        self.drain()
    }

    /// Copy the access unit into an `IMFSample` and hand it to the decoder.
    fn submit(&mut self, access_unit: &[u8], presentation_time_us: i64) -> Result<(), MfError> {
        let length = u32::try_from(access_unit.len()).map_err(|_| MfError::ShortBuffer)?;
        // SAFETY: FFI. The buffer is created at `length` bytes, locked, filled
        // with exactly `length` bytes, unlocked, and its current length set to
        // match before it is attached to the sample.
        unsafe {
            let buffer = MFCreateMemoryBuffer(length)?;
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut max_length: u32 = 0;
            buffer.Lock(&mut data, Some(&mut max_length as *mut u32), None)?;
            std::ptr::copy_nonoverlapping(access_unit.as_ptr(), data, access_unit.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(length)?;

            let sample: IMFSample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            // Media Foundation times are in 100 ns units.
            sample.SetSampleTime(presentation_time_us * 10)?;
            self.transform.ProcessInput(0, &sample, 0)?;
        }
        Ok(())
    }

    /// Pull every picture the decoder can currently emit.
    fn drain(&mut self) -> Result<Vec<MfFrame>, MfError> {
        let mut frames = Vec::new();
        loop {
            match self.process_output() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => return Ok(frames),
                Err(MfError::Windows(error)) if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => {
                    return Ok(frames);
                }
                Err(MfError::Windows(error)) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    self.configure_nv12_output()?;
                    // Retry: the picture is still pending after the format is set.
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// One `ProcessOutput` call. `Ok(None)` never occurs today (need-more-input
    /// and stream-change arrive as `Err` for [`Self::drain`] to interpret), but
    /// the shape leaves room for MFTs that report an empty output without error.
    fn process_output(&mut self) -> Result<Option<MfFrame>, MfError> {
        // SAFETY: FFI. `GetOutputStreamInfo` fills the info struct; we allocate
        // an output sample of at least the reported size and pass exactly one
        // output-data-buffer as ProcessOutput requires. The buffer may be a
        // 1-byte placeholder before the output format is known: ProcessOutput
        // reports the stream change before it needs to write pixels.
        unsafe {
            let info = self.transform.GetOutputStreamInfo(0)?;
            let size = info.cbSize.max(1);

            let out_sample = MFCreateSample()?;
            let out_buffer = MFCreateMemoryBuffer(size)?;
            out_sample.AddBuffer(&out_buffer)?;

            let mut output = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: ManuallyDrop::new(Some(out_sample.clone())),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(None),
            }];
            let mut status: u32 = 0;
            let result = self.transform.ProcessOutput(0, &mut output, &mut status);
            // We hold `out_sample` independently of the array, so release the
            // array's references before interpreting the result.
            ManuallyDrop::drop(&mut output[0].pSample);
            ManuallyDrop::drop(&mut output[0].pEvents);
            result?;

            let frame = self.read_nv12_frame(&out_sample)?;
            Ok(Some(frame))
        }
    }

    /// Copy an NV12 output sample into a BGRA [`MfFrame`].
    fn read_nv12_frame(&self, sample: &IMFSample) -> Result<MfFrame, MfError> {
        // SAFETY: FFI. The contiguous buffer is locked for the copy and unlocked
        // immediately after; `nv12_contiguous_planes` bounds-checks the slice.
        unsafe {
            let buffer = sample.ConvertToContiguousBuffer()?;
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut current_length: u32 = 0;
            buffer.Lock(&mut data, None, Some(&mut current_length as *mut u32))?;
            let bytes = std::slice::from_raw_parts(data, current_length as usize);

            let converted = (|| {
                // The buffer is the coded size (stride x coded_height); split on
                // that so the UV plane is located correctly, then convert only the
                // visible width x height (a top-left crop to the display aperture).
                let (y, uv) = nv12_contiguous_planes(bytes, self.stride, self.coded_height)
                    .ok_or(MfError::ShortBuffer)?;
                let pixels = nv12_to_bgra(y, self.stride, uv, self.stride, self.width, self.height);
                Ok(MfFrame {
                    width: self.width,
                    height: self.height,
                    pixels,
                })
            })();

            buffer.Unlock()?;
            converted
        }
    }

    /// After a stream-change signal, select the NV12 output type and record the
    /// negotiated frame size and row stride.
    fn configure_nv12_output(&mut self) -> Result<(), MfError> {
        // SAFETY: FFI. We enumerate the MFT's advertised output types, pick the
        // NV12 one, set it, then read back the geometry from that type.
        unsafe {
            let mut index = 0u32;
            loop {
                let candidate: IMFMediaType = match self.transform.GetOutputAvailableType(0, index)
                {
                    Ok(candidate) => candidate,
                    Err(_) => return Err(MfError::UnsupportedOutputFormat),
                };
                let subtype = candidate.GetGUID(&MF_MT_SUBTYPE)?;
                if subtype == MFVideoFormat_NV12 {
                    self.transform.SetOutputType(0, &candidate, 0)?;
                    // The frame size is absent until the decoder has parsed the
                    // stream (the initial call from `new` runs before any input),
                    // so treat it as optional here: the geometry is filled in by
                    // the stream-change call once the real size is known.
                    if let Ok((coded_width, coded_height)) =
                        attribute_size(&candidate, &MF_MT_FRAME_SIZE)
                    {
                        let coded_width = coded_width as usize;
                        let coded_height = coded_height as usize;
                        self.coded_height = coded_height;
                        self.stride = self.negotiated_stride(&candidate, coded_width);
                        // The decoder reports the coded size, aligned up to a
                        // macroblock multiple; the visible picture is the display
                        // aperture. Crop to it so a 160x120 stream is emitted as
                        // 160x120 and not the 160x128 the decoder buffers.
                        let (visible_width, visible_height) =
                            display_aperture(&candidate).unwrap_or((coded_width, coded_height));
                        self.width = visible_width;
                        self.height = visible_height;
                    }
                    self.output_configured = true;
                    return Ok(());
                }
                index += 1;
            }
        }
    }

    /// The luma row stride: the decoder's declared default stride when present,
    /// otherwise `default` (an unpadded NV12 buffer, i.e. the coded width).
    fn negotiated_stride(&self, media_type: &IMFMediaType, default: usize) -> usize {
        // SAFETY: reading an optional documented attribute from a live type.
        match unsafe { media_type.GetUINT32(&MF_MT_DEFAULT_STRIDE) } {
            Ok(stride) => (stride as i32).unsigned_abs() as usize,
            Err(_) => default,
        }
    }
}

/// Read the visible picture size from a media type's minimum display aperture,
/// or `None` if the attribute is absent. The decoder reports the coded (aligned)
/// size in `MF_MT_FRAME_SIZE`; this is the region the stream actually displays.
fn display_aperture(media_type: &IMFMediaType) -> Option<(usize, usize)> {
    let mut area = MFVideoArea::default();
    // SAFETY: `MFVideoArea` is a 16-byte `repr(C)` struct of integer fields, so
    // reading the aperture blob over its bytes is sound; `GetBlob` writes at most
    // the buffer length.
    let ok = unsafe {
        let bytes = std::slice::from_raw_parts_mut(
            std::ptr::from_mut(&mut area).cast::<u8>(),
            std::mem::size_of::<MFVideoArea>(),
        );
        media_type
            .GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, bytes, None)
            .is_ok()
    };
    if !ok {
        return None;
    }
    let width = usize::try_from(area.Area.cx).ok()?;
    let height = usize::try_from(area.Area.cy).ok()?;
    if width == 0 || height == 0 {
        None
    } else {
        Some((width, height))
    }
}

impl Drop for MediaFoundationH264Decoder {
    fn drop(&mut self) {
        // SAFETY: standard MFT teardown on a live transform; errors on shutdown
        // are not actionable.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A committed H.264 clip: 6 frames of a solid colour (source 0x1040C0),
    /// 160x120, baseline profile, generated with ffmpeg. Committed as bytes so
    /// the Windows CI runner needs no ffmpeg to exercise the real decoder MFT.
    const FIXTURE: &[u8] = include_bytes!("fixtures/color_160x120.h264");

    /// Split an Annex-B elementary stream into access units. A new access unit
    /// begins at the first VCL slice (NAL types 1-5) after a previous slice, or
    /// at a parameter-set / SEI / delimiter NAL (6-9) that follows a slice, so
    /// each returned chunk is one coded picture with its leading headers.
    fn access_units(stream: &[u8]) -> Vec<Vec<u8>> {
        // (offset of the 00 00 01 start code, nal_type)
        let mut nals: Vec<(usize, u8)> = Vec::new();
        let mut i = 0usize;
        while i + 3 <= stream.len() {
            if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 1 {
                let nal_type = stream.get(i + 3).map(|byte| byte & 0x1f).unwrap_or(0);
                nals.push((i, nal_type));
                i += 3;
            } else {
                i += 1;
            }
        }
        if nals.is_empty() {
            return vec![stream.to_vec()];
        }

        // The nal indices at which each access unit starts.
        let mut au_starts = vec![0usize];
        let mut seen_vcl = (1..=5).contains(&nals[0].1);
        for (index, &(_, nal_type)) in nals.iter().enumerate().skip(1) {
            let is_vcl = (1..=5).contains(&nal_type);
            let starts_au = if is_vcl {
                seen_vcl
            } else {
                seen_vcl && matches!(nal_type, 6 | 7 | 8 | 9)
            };
            if starts_au {
                au_starts.push(index);
                seen_vcl = is_vcl;
            } else {
                seen_vcl = seen_vcl || is_vcl;
            }
        }

        let mut units = Vec::new();
        for slot in 0..au_starts.len() {
            let start = nals[au_starts[slot]].0;
            let end = au_starts
                .get(slot + 1)
                .map(|&next| nals[next].0)
                .unwrap_or(stream.len());
            units.push(stream[start..end].to_vec());
        }
        units
    }

    #[test]
    fn splits_the_fixture_into_six_access_units() {
        // A structural check that does not need Media Foundation, so it runs
        // even if the decoder MFT is unavailable.
        assert_eq!(access_units(FIXTURE).len(), 6);
    }

    #[test]
    fn decodes_the_committed_fixture_to_bgra_frames() {
        // The OS H.264 decoder MFT is absent on some headless Windows Server
        // SKUs (the "Media Foundation" feature is not installed). Where it is
        // missing, skip rather than fail -- unless OPENSTREAM_REQUIRE_MF_TEST is
        // set, which forces the test so a configured machine (the physical
        // Windows box, or a runner with the feature) proves real decoding and
        // never silently passes. This mirrors the macOS OPENSTREAM_REQUIRE_VT_TEST
        // gate.
        let mut decoder = match MediaFoundationH264Decoder::new() {
            Ok(decoder) => decoder,
            Err(error) => {
                if std::env::var_os("OPENSTREAM_REQUIRE_MF_TEST").is_some() {
                    panic!("Media Foundation decoder required but unavailable: {error}");
                }
                eprintln!("skipping Media Foundation decode test: decoder unavailable ({error})");
                return;
            }
        };

        let mut frames = Vec::new();
        for (index, unit) in access_units(FIXTURE).into_iter().enumerate() {
            let pts = index as i64 * 200_000;
            frames.extend(decoder.decode(&unit, pts).expect("decode the fixture"));
        }
        frames.extend(decoder.flush().expect("flush the decoder"));

        assert!(!frames.is_empty(), "the decoder produced no frames");
        let frame = frames.last().unwrap();
        assert_eq!(frame.width, 160);
        assert_eq!(frame.height, 120);
        assert_eq!(frame.pixels.len(), 160 * 120);

        // Centre pixel: the source colour 0x1040C0 (R=16 G=64 B=192). Allow a
        // wide tolerance for the MFT's colour matrix and 4:2:0 subsampling.
        let centre = frame.pixels[(120 / 2) * 160 + 80];
        let (b, g, r) = (centre & 0xff, (centre >> 8) & 0xff, (centre >> 16) & 0xff);
        assert!(
            b > 140 && r < 90 && g < 120,
            "expected a blue-dominant centre, got B={b} G={g} R={r}"
        );
        assert_eq!((centre >> 24) & 0xff, 0xff, "alpha is opaque");
    }
}
