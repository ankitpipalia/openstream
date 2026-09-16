//! In-process H.264 decode on Windows via the Media Foundation decoder MFT.
//!
//! This is the Windows counterpart to the macOS VideoToolbox decode path: it
//! decodes H.264 access units in-process, with no external ffmpeg subprocess,
//! so the client matches Parsec's model of a native decoder linked into the
//! app. It uses the OS "H.264 Video Decoder" MFT (`CLSID_MSH264DecoderMFT`),
//! which is vendor-neutral -- it runs on NVIDIA, AMD and Intel GPUs through the
//! OS, and falls back to the OS software decoder where no hardware decoder is
//! present -- so it is preferred over any single vendor SDK (NVDEC/AMF/QSV).
//!
//! The MFT emits NV12; the crate's `nv12` module converts that to the BGRA the
//! presenter consumes. The buffer geometry and colour conversion live in that
//! pure, cross-platform-tested module; this file is the COM/MFT plumbing that
//! feeds it and is therefore compiled and exercised only on Windows.
//!
//! Verification: the test at the bottom decodes a committed H.264 fixture and
//! checks the frame count, dimensions and centre colour. It runs on the Windows
//! CI job against the OS decoder MFT (the software decoder is always present, so
//! CI needs no GPU). That proves functional correctness through the real MFT;
//! confirming a *hardware* decoder is selected on a specific GPU is a separate
//! on-hardware check, not something this test claims.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::mem::ManuallyDrop;

use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
    D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
    D3D11_USAGE_STAGING, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
    ID3D11Texture2D,
};
use windows::Win32::Media::MediaFoundation::{
    CLSID_MSH264DecoderMFT, IMFDXGIBuffer, IMFDXGIDeviceManager, IMFMediaType, IMFSample,
    IMFTransform, MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY,
    MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_SIZE, MF_MT_MAJOR_TYPE, MF_MT_MINIMUM_DISPLAY_APERTURE,
    MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MFCreateDXGIDeviceManager, MFCreateMediaType,
    MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFT_MESSAGE_COMMAND_DRAIN,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFVideoArea, MFVideoFormat_H264, MFVideoFormat_NV12,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::{GUID, Interface};

use crate::mf_startup::ensure_media_foundation_started;
use crate::nv12::{nv12_contiguous_planes, nv12_to_bgra};

/// A decoded picture: BGRA pixels (one per `u32`, `B | G<<8 | R<<16 | A<<24`)
/// ready for the presenter, plus its dimensions.
#[derive(Debug)]
pub struct MfFrame {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
}

/// Why a Media Foundation decode failed.
#[derive(Debug)]
pub enum MfError {
    /// A Media Foundation / COM call returned a failure `HRESULT`.
    Windows(windows::core::Error),
    /// The MFT advertised no NV12 output type (only NV12 is handled today).
    UnsupportedOutputFormat,
    /// The decoded buffer was smaller than its declared geometry, so it could
    /// not be read safely.
    ShortBuffer,
    /// The hardware path was requested but the decoder MFT does not report
    /// `MF_SA_D3D11_AWARE`, so it cannot take a D3D11 device manager.
    NotD3d11Aware,
    /// No hardware D3D11 device with video support could be created (no GPU,
    /// or a driver without DXVA), so there is nothing to decode on.
    NoD3d11Device,
}

impl std::fmt::Display for MfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfError::Windows(error) => write!(f, "media foundation error: {error}"),
            MfError::UnsupportedOutputFormat => {
                write!(f, "media foundation advertised no NV12 output format")
            }
            MfError::ShortBuffer => write!(f, "media foundation output buffer was too short"),
            MfError::NotD3d11Aware => {
                write!(f, "media foundation decoder is not D3D11-aware")
            }
            MfError::NoD3d11Device => {
                write!(f, "no hardware D3D11 device with video support")
            }
        }
    }
}

impl std::error::Error for MfError {}

impl From<windows::core::Error> for MfError {
    fn from(error: windows::core::Error) -> Self {
        MfError::Windows(error)
    }
}

/// The provides-samples output-stream flag as a `u32` for the bitwise test.
fn provides_samples_flag() -> u32 {
    u32::try_from(MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0).unwrap_or(0x100)
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

/// The D3D11 device the hardware path decodes on, shared with the decoder MFT
/// through a DXGI device manager, plus the CPU-readable staging texture used to
/// read decoded frames back.
#[derive(Debug)]
struct D3d11Context {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    manager: IMFDXGIDeviceManager,
    staging: Option<ID3D11Texture2D>,
}

impl D3d11Context {
    /// Create a hardware D3D11 device with video (DXVA) support and wrap it in a
    /// DXGI device manager the decoder MFT can use.
    fn new() -> Result<Self, MfError> {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        // SAFETY: FFI. A null adapter selects the default hardware adapter; the
        // out-params receive owned interfaces on success.
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )?;
        }
        let device = device.ok_or(MfError::NoD3d11Device)?;
        let context = context.ok_or(MfError::NoD3d11Device)?;

        // Media Foundation shares the device across its worker threads, so it
        // must be multithread-protected before it is handed over.
        // SAFETY: the device is live; the cast fails cleanly if unsupported.
        unsafe {
            let multithread: ID3D11Multithread = device.cast()?;
            // Returns the previous protection state, which is not needed.
            let _ = multithread.SetMultithreadProtected(true);
        }

        let mut token = 0u32;
        let mut manager: Option<IMFDXGIDeviceManager> = None;
        // SAFETY: FFI. The manager is created then bound to the device with the
        // reset token the creation returned.
        unsafe {
            MFCreateDXGIDeviceManager(&mut token, &mut manager)?;
        }
        let manager = manager.ok_or(MfError::NoD3d11Device)?;
        // SAFETY: binding a live device to a live manager.
        unsafe {
            manager.ResetDevice(&device, token)?;
        }

        Ok(Self {
            device,
            context,
            manager,
            staging: None,
        })
    }

    /// The CPU-readable staging texture matching `desc` (created once and reused;
    /// cleared on a stream change so a new size gets a new one).
    fn staging_for(&mut self, desc: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D, MfError> {
        if let Some(staging) = &self.staging {
            return Ok(staging.clone());
        }
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width: desc.Width,
            Height: desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: desc.Format,
            SampleDesc: desc.SampleDesc,
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging: Option<ID3D11Texture2D> = None;
        // SAFETY: FFI. `staging_desc` is a valid staging description; the
        // out-param receives an owned texture.
        unsafe {
            self.device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))?;
        }
        let staging = staging.ok_or(MfError::NoD3d11Device)?;
        self.staging = Some(staging.clone());
        Ok(staging)
    }
}

/// The in-process Media Foundation H.264 decoder.
#[derive(Debug)]
pub struct MediaFoundationH264Decoder {
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
    /// Present when decoding on the GPU (the D3D11/DXVA path); `None` for the
    /// software decoder.
    d3d: Option<D3d11Context>,
}

impl MediaFoundationH264Decoder {
    /// Create a decoder ready to accept Annex-B H.264 access units, decoding in
    /// software (the OS decoder MFT with no D3D device manager).
    ///
    /// The output type is negotiated lazily: the MFT cannot describe its output
    /// until it has parsed the stream's parameter sets, so [`Self::decode`]
    /// configures NV12 output on the first stream-change signal.
    pub fn new() -> Result<Self, MfError> {
        Self::build(None)
    }

    /// Create a decoder that decodes on the GPU through DXVA.
    ///
    /// A hardware D3D11 device with video support is handed to the D3D11-aware
    /// decoder MFT through a DXGI device manager, so the OS routes the decode to
    /// the GPU's fixed-function decoder -- NVIDIA, AMD and Intel alike, with no
    /// vendor SDK. Output then arrives as D3D11 textures; this reads them back
    /// through a staging texture for the CPU BGRA path (a later step hands the
    /// texture straight to the presenter). Fails with [`MfError::NoD3d11Device`]
    /// on a machine without a suitable GPU and [`MfError::NotD3d11Aware`] if the
    /// MFT cannot take a device manager, so a caller can fall back to [`Self::new`].
    pub fn new_d3d11() -> Result<Self, MfError> {
        let d3d = D3d11Context::new()?;
        Self::build(Some(d3d))
    }

    /// Whether this decoder runs on the GPU through a D3D11 device manager.
    #[must_use]
    pub fn is_hardware(&self) -> bool {
        self.d3d.is_some()
    }

    fn build(d3d: Option<D3d11Context>) -> Result<Self, MfError> {
        ensure_media_foundation_started().map_err(MfError::from)?;

        // SAFETY: FFI to Media Foundation. `CoCreateInstance` yields a live
        // `IMFTransform`; the type object and messages below are used per the
        // MFT contract (set the input type, then stream in the encoded samples).
        let transform: IMFTransform =
            unsafe { CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)? };

        // The hardware path: the MFT must advertise D3D11 awareness, and is told
        // about the device manager before any media type is set.
        if let Some(d3d) = &d3d {
            // SAFETY: reading a documented attribute and sending the documented
            // message with the manager's IUnknown pointer, which stays alive in
            // `d3d` for the decoder's lifetime.
            unsafe {
                let attributes = transform.GetAttributes()?;
                if attributes.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) == 0 {
                    return Err(MfError::NotD3d11Aware);
                }
                transform
                    .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, d3d.manager.as_raw() as usize)?;
            }
        }

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
            d3d,
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
    pub fn decode(
        &mut self,
        access_unit: &[u8],
        presentation_time_us: i64,
    ) -> Result<Vec<MfFrame>, MfError> {
        self.submit(access_unit, presentation_time_us)?;
        self.drain()
    }

    /// Signal end of stream and pull every remaining picture. Call once after
    /// the last access unit so frames the decoder still holds are emitted.
    pub fn flush(&mut self) -> Result<Vec<MfFrame>, MfError> {
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
        // SAFETY: FFI. `GetOutputStreamInfo` reports whether the MFT allocates
        // its own output (a D3D11-aware decoder hands back GPU textures) or
        // expects a caller buffer (the software decoder); we supply one only in
        // the latter case and pass exactly one output-data-buffer as
        // ProcessOutput requires. A caller buffer may be a 1-byte placeholder
        // before the output format is known: the stream change is reported
        // before any pixels are written.
        unsafe {
            let info = self.transform.GetOutputStreamInfo(0)?;
            let provides = (info.dwFlags & provides_samples_flag()) != 0;
            let allocated = if provides {
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
            // Take back whatever sample the array holds -- the MFT's own when it
            // provides samples -- and release the array's event reference before
            // interpreting the result.
            let produced = ManuallyDrop::take(&mut output[0].pSample);
            ManuallyDrop::drop(&mut output[0].pEvents);
            result?;

            let Some(sample) = allocated.or(produced) else {
                return Ok(None);
            };
            let frame = self.read_nv12_frame(&sample)?;
            Ok(Some(frame))
        }
    }

    /// Copy an NV12 output sample into a BGRA [`MfFrame`].
    fn read_nv12_frame(&mut self, sample: &IMFSample) -> Result<MfFrame, MfError> {
        // A D3D11-aware decoder's sample wraps a GPU texture, read back through
        // a staging texture; otherwise the buffer is ordinary CPU memory.
        // SAFETY: querying the first buffer's interfaces on a live sample.
        let dxgi = unsafe {
            sample
                .GetBufferByIndex(0)
                .ok()
                .and_then(|buffer| buffer.cast::<IMFDXGIBuffer>().ok())
        };
        if let Some(dxgi) = dxgi {
            return self.read_texture_frame(&dxgi);
        }

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

    /// Read back a decoded D3D11 texture (the hardware path's output) through a
    /// CPU-readable staging copy and convert its visible region to BGRA.
    fn read_texture_frame(&mut self, dxgi: &IMFDXGIBuffer) -> Result<MfFrame, MfError> {
        let (width, height, coded_height) = (self.width, self.height, self.coded_height);
        let d3d = self.d3d.as_mut().ok_or(MfError::NotD3d11Aware)?;
        // SAFETY: FFI. The buffer's resource is a live texture owned by the
        // sample for this call; the staging copy is mapped for the read and
        // unmapped before returning; `nv12_contiguous_planes` bounds-checks.
        unsafe {
            let mut raw: *mut c_void = std::ptr::null_mut();
            dxgi.GetResource(&ID3D11Texture2D::IID, &mut raw)?;
            let texture = ID3D11Texture2D::from_raw(raw);
            let subresource = dxgi.GetSubresourceIndex()?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            texture.GetDesc(&mut desc);

            let staging = d3d.staging_for(&desc)?;
            d3d.context
                .CopySubresourceRegion(&staging, 0, 0, 0, 0, &texture, subresource, None);

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            d3d.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
            let stride = mapped.RowPitch as usize;
            // An NV12 staging texture maps as the Y rows followed directly by the
            // interleaved UV rows, both at RowPitch: exactly the contiguous layout
            // the plane split expects.
            let total = stride * (coded_height + coded_height / 2);
            let bytes = std::slice::from_raw_parts(mapped.pData.cast::<u8>(), total);
            let converted = nv12_contiguous_planes(bytes, stride, coded_height)
                .map(|(y, uv)| nv12_to_bgra(y, stride, uv, stride, width, height))
                .ok_or(MfError::ShortBuffer);
            d3d.context.Unmap(&staging, 0);

            let pixels = converted?;
            Ok(MfFrame {
                width,
                height,
                pixels,
            })
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
                    // A new output geometry needs a new staging texture.
                    if let Some(d3d) = self.d3d.as_mut() {
                        d3d.staging = None;
                    }
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
                seen_vcl && matches!(nal_type, 6..=9)
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

    /// The same fixture through the GPU (DXVA) path. Needs a hardware D3D11
    /// device with video support, so it skips on a headless runner unless
    /// OPENSTREAM_REQUIRE_MF_TEST forces it -- which is how the physical box
    /// proves hardware decode rather than the software MFT.
    #[test]
    fn decodes_the_committed_fixture_on_the_d3d11_hardware_path() {
        let mut decoder = match MediaFoundationH264Decoder::new_d3d11() {
            Ok(decoder) => decoder,
            Err(error) => {
                if std::env::var_os("OPENSTREAM_REQUIRE_MF_TEST").is_some() {
                    panic!("D3D11 hardware decoder required but unavailable: {error}");
                }
                eprintln!("skipping D3D11 hardware decode test: unavailable ({error})");
                return;
            }
        };
        assert!(
            decoder.is_hardware(),
            "the D3D11 constructor yields a hardware decoder"
        );

        let mut frames = Vec::new();
        for (index, unit) in access_units(FIXTURE).into_iter().enumerate() {
            let pts = index as i64 * 200_000;
            frames.extend(decoder.decode(&unit, pts).expect("hardware decode"));
        }
        frames.extend(decoder.flush().expect("hardware flush"));

        assert!(
            !frames.is_empty(),
            "the hardware decoder produced no frames"
        );
        let frame = frames.last().unwrap();
        assert_eq!(frame.width, 160);
        assert_eq!(frame.height, 120);
        assert_eq!(frame.pixels.len(), 160 * 120);
        let centre = frame.pixels[(120 / 2) * 160 + 80];
        let (b, g, r) = (centre & 0xff, (centre >> 8) & 0xff, (centre >> 16) & 0xff);
        assert!(
            b > 140 && r < 90 && g < 120,
            "expected a blue-dominant centre from the GPU path, got B={b} G={g} R={r}"
        );
        eprintln!(
            "d3d11 hardware decode: {} frames, centre B={b} G={g} R={r}",
            frames.len()
        );
    }
}
