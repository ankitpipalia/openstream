//! In-process H.264 encode on Windows via the Media Foundation encoder MFT.
//!
//! The host counterpart to the decoder: it turns NV12 frames into an H.264
//! elementary stream in-process, using the OS `H.264 Video Encoder` MFT
//! (`CLSID_MSH264EncoderMFT`), which is vendor-neutral (it drives NVIDIA/AMD/
//! Intel hardware encoders through the OS, with an OS software fallback), so it
//! is preferred over any single vendor SDK (NVENC/AMF/QSV).
//!
//! Unlike the decoder, an encoder MFT wants the OUTPUT type (the compressed
//! format: codec, bitrate, size, frame rate, profile) set before the input
//! type (the raw NV12 format). Output is a compressed H.264 access unit per
//! frame; the parameter sets (SPS/PPS) are available through
//! [`MediaFoundationH264Encoder::sequence_header`].

#![cfg(target_os = "windows")]

use std::mem::ManuallyDrop;

use windows::Win32::Media::MediaFoundation::{
    CLSID_MSH264EncoderMFT, CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncCommonRealTime, CODECAPI_AVEncMPVDefaultBPictureCount,
    CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode, ICodecAPI, IMFSample,
    IMFTransform, MF_E_TRANSFORM_NEED_MORE_INPUT, MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE,
    MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_MPEG_SEQUENCE_HEADER,
    MF_MT_MPEG2_PROFILE, MF_MT_SUBTYPE, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFT_MESSAGE_COMMAND_DRAIN, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFVideoFormat_H264, MFVideoFormat_NV12, MFVideoInterlace_Progressive,
    eAVEncCommonRateControlMode_CBR, eAVEncH264VProfile_Main,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Variant::VARIANT;
use windows::core::Interface;

use crate::mf_startup::ensure_media_foundation_started;

/// One encoded H.264 access unit and whether it starts a keyframe.
#[derive(Debug)]
pub struct EncodedAccessUnit {
    pub data: Vec<u8>,
    pub keyframe: bool,
}

/// Why a Media Foundation encode failed.
#[derive(Debug)]
pub enum MfEncError {
    /// A Media Foundation / COM call returned a failure `HRESULT`.
    Windows(windows::core::Error),
    /// The frame did not match the configured size.
    FrameTooLarge,
    /// The encoder exposes no `ICodecAPI`, so live changes are unavailable.
    NoCodecApi,
}

impl std::fmt::Display for MfEncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfEncError::Windows(error) => write!(f, "media foundation encode error: {error}"),
            MfEncError::FrameTooLarge => write!(f, "input frame exceeded the configured size"),
            MfEncError::NoCodecApi => write!(f, "the encoder exposes no ICodecAPI"),
        }
    }
}

impl std::error::Error for MfEncError {}

impl From<windows::core::Error> for MfEncError {
    fn from(error: windows::core::Error) -> Self {
        MfEncError::Windows(error)
    }
}

/// Pack two 32-bit halves the way Media Foundation stores size/ratio attributes.
fn pack_ratio(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// Ask the encoder for real-time, low-delay behaviour: low-latency mode, no
/// B-frames (they hold frames back for reordering), real-time priority and
/// constant bitrate. Returns whether low-latency mode itself was accepted; the
/// other properties are refinements and their refusal is not an error.
fn configure_low_latency(api: &ICodecAPI) -> bool {
    // SAFETY: FFI. Each call passes a documented property GUID and a VARIANT of
    // the type the property is documented to take (VT_BOOL / VT_UI4).
    unsafe {
        let low_latency = api
            .SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true))
            .is_ok();
        let _ = api.SetValue(&CODECAPI_AVEncCommonRealTime, &VARIANT::from(1_u32));
        let _ = api.SetValue(
            &CODECAPI_AVEncMPVDefaultBPictureCount,
            &VARIANT::from(0_u32),
        );
        let _ = api.SetValue(
            &CODECAPI_AVEncCommonRateControlMode,
            &VARIANT::from(u32::try_from(eAVEncCommonRateControlMode_CBR.0).unwrap_or(0)),
        );
        low_latency
    }
}

/// The in-process Media Foundation H.264 encoder.
#[derive(Debug)]
pub struct MediaFoundationH264Encoder {
    transform: IMFTransform,
    /// The encoder's codec property interface, for live changes (forced
    /// keyframes, bitrate). `None` if the MFT does not expose one.
    codec_api: Option<ICodecAPI>,
    output_provides_samples: bool,
    low_latency: bool,
}

impl MediaFoundationH264Encoder {
    /// Create an encoder for `width` x `height` at `fps` frames per second and
    /// the given average `bitrate` (bits per second), accepting NV12 input.
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self, MfEncError> {
        ensure_media_foundation_started().map_err(MfEncError::from)?;

        // SAFETY: FFI. CoCreateInstance yields a live IMFTransform; the encoder
        // requires the output type set before the input type.
        let transform: IMFTransform =
            unsafe { CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)? };

        // Real-time properties go through ICodecAPI and belong before the
        // output type. Best effort: the OS encoder supports them, a vendor
        // MFT may not, and the stream is valid without them (with more
        // buffering), so only the outcome is recorded.
        let codec_api: Option<ICodecAPI> = transform.cast().ok();
        let low_latency = codec_api.as_ref().is_some_and(configure_low_latency);

        // SAFETY: fresh media types; documented GUID keys/values.
        unsafe {
            let output = MFCreateMediaType()?;
            output.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            output.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
            output.SetUINT32(&MF_MT_INTERLACE_MODE, progressive_interlace_mode())?;
            output.SetUINT64(&MF_MT_FRAME_SIZE, pack_ratio(width, height))?;
            output.SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(fps, 1))?;
            output.SetUINT32(&MF_MT_MPEG2_PROFILE, main_profile())?;
            transform.SetOutputType(0, &output, 0)?;

            let input = MFCreateMediaType()?;
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            input.SetUINT32(&MF_MT_INTERLACE_MODE, progressive_interlace_mode())?;
            input.SetUINT64(&MF_MT_FRAME_SIZE, pack_ratio(width, height))?;
            input.SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(fps, 1))?;
            transform.SetInputType(0, &input, 0)?;
        }

        // SAFETY: reading the output stream info from a live transform.
        let info = unsafe { transform.GetOutputStreamInfo(0)? };
        let output_provides_samples = (info.dwFlags & provides_samples_flag()) != 0;

        // SAFETY: standard MFT lifecycle messages on a live transform.
        unsafe {
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(Self {
            transform,
            codec_api,
            output_provides_samples,
            low_latency,
        })
    }

    /// Whether the encoder accepted low-latency mode at creation.
    pub fn low_latency_configured(&self) -> bool {
        self.low_latency
    }

    /// Make the next encoded frame a keyframe, so a client that lost the
    /// reference chain (or just joined) can resume without a new encoder.
    pub fn force_keyframe(&mut self) -> Result<(), MfEncError> {
        self.set_property(&CODECAPI_AVEncVideoForceKeyFrame, VARIANT::from(1_u32))
    }

    /// Change the running encoder's average bitrate (bits per second).
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<(), MfEncError> {
        self.set_property(&CODECAPI_AVEncCommonMeanBitRate, VARIANT::from(bitrate))
    }

    fn set_property(
        &self,
        property: &windows::core::GUID,
        value: VARIANT,
    ) -> Result<(), MfEncError> {
        let api = self.codec_api.as_ref().ok_or(MfEncError::NoCodecApi)?;
        // SAFETY: FFI. A documented codec property GUID and a VARIANT of the
        // type that property is documented to take; both outlive the call.
        unsafe { api.SetValue(property, &value)? }
        Ok(())
    }

    /// The SPS/PPS parameter sets for the stream, as an Annex-B byte sequence,
    /// or `None` if the encoder has not published them yet. Prepend these to the
    /// encoded access units to make a stream a decoder can start from.
    pub fn sequence_header(&self) -> Option<Vec<u8>> {
        // SAFETY: reading a blob attribute from the current output type.
        unsafe {
            let output_type = self.transform.GetOutputCurrentType(0).ok()?;
            let size = output_type.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER).ok()?;
            if size == 0 {
                return None;
            }
            let mut header = vec![0u8; size as usize];
            output_type
                .GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut header, None)
                .ok()?;
            Some(header)
        }
    }

    /// Encode one NV12 frame (`width * height` Y bytes followed by
    /// `width * height / 2` interleaved UV bytes), returning any access units the
    /// encoder emitted.
    pub fn encode(
        &mut self,
        nv12: &[u8],
        presentation_time_us: i64,
    ) -> Result<Vec<EncodedAccessUnit>, MfEncError> {
        let length = u32::try_from(nv12.len()).map_err(|_| MfEncError::FrameTooLarge)?;
        // SAFETY: FFI. Buffer sized to the frame, filled, length set, attached.
        unsafe {
            let buffer = MFCreateMemoryBuffer(length)?;
            let mut data: *mut u8 = std::ptr::null_mut();
            buffer.Lock(&mut data, None, None)?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), data, nv12.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(length)?;

            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(presentation_time_us * 10)?;
            sample.SetSampleDuration(0)?;
            self.transform.ProcessInput(0, &sample, 0)?;
        }
        self.drain()
    }

    /// Signal end of stream and pull every remaining access unit.
    pub fn flush(&mut self) -> Result<Vec<EncodedAccessUnit>, MfEncError> {
        // SAFETY: draining an MFT is a documented message on a live transform.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0)?;
        }
        self.drain()
    }

    fn drain(&mut self) -> Result<Vec<EncodedAccessUnit>, MfEncError> {
        let mut units = Vec::new();
        loop {
            match self.process_output() {
                Ok(Some(unit)) => units.push(unit),
                Ok(None) => return Ok(units),
                Err(MfEncError::Windows(error))
                    if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT =>
                {
                    return Ok(units);
                }
                Err(other) => return Err(other),
            }
        }
    }

    fn process_output(&mut self) -> Result<Option<EncodedAccessUnit>, MfEncError> {
        // SAFETY: FFI. Allocate an output sample unless the MFT provides its own,
        // then pass exactly one output-data-buffer to ProcessOutput.
        unsafe {
            let info = self.transform.GetOutputStreamInfo(0)?;
            let allocated = if self.output_provides_samples {
                None
            } else {
                let sample = MFCreateSample()?;
                let buffer = MFCreateMemoryBuffer(info.cbSize.max(1))?;
                sample.AddBuffer(&buffer)?;
                Some(sample)
            };

            let mut output = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: ManuallyDrop::new(allocated.clone()),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(None),
            }];
            let mut status: u32 = 0;
            let result = self.transform.ProcessOutput(0, &mut output, &mut status);
            // When the MFT provides samples it writes pSample; take it back before
            // releasing the array's references.
            let produced = ManuallyDrop::take(&mut output[0].pSample);
            ManuallyDrop::drop(&mut output[0].pEvents);
            result?;

            let Some(sample) = allocated.or(produced) else {
                return Ok(None);
            };
            let unit = read_access_unit(&sample)?;
            Ok(Some(unit))
        }
    }
}

/// Copy an encoded sample's bytes into an [`EncodedAccessUnit`], marking it a
/// keyframe if it carries an IDR (NAL type 5) or SPS (type 7).
fn read_access_unit(sample: &IMFSample) -> Result<EncodedAccessUnit, MfEncError> {
    // SAFETY: contiguous buffer locked for the copy and unlocked after.
    unsafe {
        let buffer = sample.ConvertToContiguousBuffer()?;
        let mut data: *mut u8 = std::ptr::null_mut();
        let mut length: u32 = 0;
        buffer.Lock(&mut data, None, Some(&mut length as *mut u32))?;
        let bytes = std::slice::from_raw_parts(data, length as usize).to_vec();
        buffer.Unlock()?;
        let keyframe = annexb_has_nal(&bytes, &[5, 7]);
        Ok(EncodedAccessUnit {
            data: bytes,
            keyframe,
        })
    }
}

/// Whether an Annex-B byte sequence contains a NAL of any of the given types.
fn annexb_has_nal(stream: &[u8], types: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 3 < stream.len() {
        if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 1 {
            let nal_type = stream[i + 3] & 0x1f;
            if types.contains(&nal_type) {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// `MFVideoInterlace_Progressive` as the `u32` the interlace-mode attribute takes.
fn progressive_interlace_mode() -> u32 {
    u32::try_from(MFVideoInterlace_Progressive.0).unwrap_or(2)
}

/// The H.264 Main profile as the `u32` the profile attribute takes.
fn main_profile() -> u32 {
    u32::try_from(eAVEncH264VProfile_Main.0).unwrap_or(77)
}

/// The provides-samples output-stream flag as a `u32` for the bitwise test.
fn provides_samples_flag() -> u32 {
    u32::try_from(MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0).unwrap_or(0x100)
}

impl Drop for MediaFoundationH264Encoder {
    fn drop(&mut self) {
        // SAFETY: standard MFT teardown on a live transform.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mf_decoder::MediaFoundationH264Decoder;
    use crate::nv12::bgra_to_nv12;

    const WIDTH: usize = 160;
    const HEIGHT: usize = 120;

    /// A solid-colour NV12 frame at the test resolution, built from BGRA so the
    /// colour conversion is exercised too.
    fn solid_nv12(b: u8, g: u8, r: u8) -> Vec<u8> {
        let px = u32::from(b) | (u32::from(g) << 8) | (u32::from(r) << 16) | (0xFF_u32 << 24);
        let frame = vec![px; WIDTH * HEIGHT];
        bgra_to_nv12(&frame, WIDTH, HEIGHT)
    }

    fn make_encoder() -> Option<MediaFoundationH264Encoder> {
        let (w, h) = (
            u32::try_from(WIDTH).unwrap(),
            u32::try_from(HEIGHT).unwrap(),
        );
        match MediaFoundationH264Encoder::new(w, h, 30, 4_000_000) {
            Ok(encoder) => Some(encoder),
            Err(error) => {
                if std::env::var_os("OPENSTREAM_REQUIRE_MF_TEST").is_some() {
                    panic!("Media Foundation encoder required but unavailable: {error}");
                }
                eprintln!("skipping Media Foundation encode test: encoder unavailable ({error})");
                None
            }
        }
    }

    #[test]
    fn encoder_produces_h264_pictures() {
        let Some(mut encoder) = make_encoder() else {
            return;
        };
        let nv12 = solid_nv12(0xC0, 0x40, 0x10); // blue-dominant
        let mut stream = Vec::new();
        for frame in 0..20 {
            for unit in encoder.encode(&nv12, frame * 33_333).expect("encode") {
                stream.extend_from_slice(&unit.data);
            }
        }
        for unit in encoder.flush().expect("flush") {
            stream.extend_from_slice(&unit.data);
        }

        assert!(!stream.is_empty(), "the encoder produced no output");
        // The encoder must have emitted coded pictures (a slice NAL, type 1 or 5).
        assert!(
            annexb_has_nal(&stream, &[1, 5]),
            "no slice NAL in the encoded stream"
        );
        // And the parameter sets must be available for a decoder to start.
        let header = encoder.sequence_header();
        let has_sps = annexb_has_nal(&stream, &[7])
            || header
                .as_deref()
                .map(|h| annexb_has_nal(h, &[7]))
                .unwrap_or(false);
        assert!(has_sps, "no SPS in the stream or its sequence header");
    }

    #[test]
    fn encode_decode_round_trips_a_solid_colour() {
        let Some(mut encoder) = make_encoder() else {
            return;
        };
        let nv12 = solid_nv12(0xC0, 0x40, 0x10); // blue-dominant, like the decoder fixture

        let mut units: Vec<EncodedAccessUnit> = Vec::new();
        for frame in 0..20 {
            units.extend(encoder.encode(&nv12, frame * 33_333).expect("encode"));
        }
        units.extend(encoder.flush().expect("flush"));
        assert!(!units.is_empty(), "no encoded access units");

        let mut decoder = match MediaFoundationH264Decoder::new() {
            Ok(decoder) => decoder,
            Err(error) => {
                if std::env::var_os("OPENSTREAM_REQUIRE_MF_TEST").is_some() {
                    panic!("decoder required but unavailable: {error}");
                }
                eprintln!("skipping round trip: decoder unavailable ({error})");
                return;
            }
        };

        // Seed the decoder with the parameter sets, then feed every access unit.
        let mut frames = Vec::new();
        if let Some(header) = encoder.sequence_header() {
            frames.extend(decoder.decode(&header, 0).expect("decode header"));
        }
        for (index, unit) in units.iter().enumerate() {
            let pts = index as i64 * 33_333;
            frames.extend(decoder.decode(&unit.data, pts).expect("decode"));
        }
        frames.extend(decoder.flush().expect("decoder flush"));

        assert!(!frames.is_empty(), "the round trip produced no frames");
        let frame = frames.last().unwrap();
        assert_eq!(frame.width, WIDTH);
        assert_eq!(frame.height, HEIGHT);
        // A solid blue survives encode -> decode within a wide tolerance for the
        // lossy codec and 4:2:0.
        let centre = frame.pixels[(HEIGHT / 2) * WIDTH + WIDTH / 2];
        let (b, g, r) = (centre & 0xff, (centre >> 8) & 0xff, (centre >> 16) & 0xff);
        assert!(
            b > 120 && r < 110 && g < 130,
            "expected a blue-dominant centre after the round trip, got B={b} G={g} R={r}"
        );
    }
}
