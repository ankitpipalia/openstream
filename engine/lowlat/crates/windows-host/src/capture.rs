//! Desktop capture on Windows via the Desktop Duplication API (DXGI 1.2).
//!
//! Status: implemented and CI-validated (compiles for the Windows targets and
//! its pure logic is unit-tested); physical Windows runtime verification is
//! pending the hardware. Not a production default until then.
//!
//! Desktop Duplication is the vendor-neutral OS capture path -- it works across
//! NVIDIA/AMD/Intel and needs no per-vendor SDK. It hands back the desktop as a
//! GPU texture; this module copies it to a CPU-readable staging texture and
//! emits tightly packed B8G8R8A8, which the codec crate's NV12 conversion then
//! feeds to the hardware encoder.
//!
//! The session recovers from the two states the API reports as errors: a frame
//! timeout (no screen change within the deadline -- normal and common) and
//! access loss (a mode switch, a desktop switch, or another duplication taking
//! over -- recovered by rebuilding the duplication).

// The pure helpers (output selection, row packing) are always compiled and
// tested; the DXGI/D3D11 session is Windows-only.

/// A description of one display output, enough to choose between them without
/// any platform types, so the choice is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputInfo {
    /// Whether the output is attached to the desktop (a detached output cannot
    /// be duplicated).
    pub attached: bool,
    pub width: u32,
    pub height: u32,
}

/// Choose which output to duplicate: the `requested` index when it names an
/// attached output, otherwise the first attached output. `None` when nothing is
/// attached (there is nothing to capture).
pub fn choose_output(outputs: &[OutputInfo], requested: Option<usize>) -> Option<usize> {
    if let Some(index) = requested
        && outputs.get(index).is_some_and(|output| output.attached)
    {
        return Some(index);
    }
    outputs.iter().position(|output| output.attached)
}

/// Copy `width * 4` bytes from each of `height` rows out of a source whose rows
/// are `src_stride` bytes apart (the GPU staging texture's row pitch, which is
/// aligned and usually wider than the image), producing a tightly packed
/// B8G8R8A8 buffer. Returns `None` if the source is shorter than the geometry
/// requires, so a short map is rejected rather than read out of bounds.
pub fn pack_bgra_rows(
    src: &[u8],
    src_stride: usize,
    width: usize,
    height: usize,
) -> Option<Vec<u8>> {
    let row_bytes = width.checked_mul(4)?;
    if src_stride < row_bytes {
        return None;
    }
    let needed = src_stride
        .checked_mul(height.saturating_sub(1))?
        .checked_add(row_bytes)?;
    if height > 0 && src.len() < needed {
        return None;
    }
    let mut out = Vec::with_capacity(row_bytes.checked_mul(height)?);
    for row in 0..height {
        let start = row * src_stride;
        out.extend_from_slice(&src[start..start + row_bytes]);
    }
    Some(out)
}

#[cfg(target_os = "windows")]
pub use session::{CaptureError, CapturedFrame, DesktopDuplication};

#[cfg(target_os = "windows")]
mod session {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    use windows::Win32::Graphics::Direct3D11::{
        D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
        D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
    use windows::Win32::Graphics::Dxgi::{
        DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, IDXGIAdapter,
        IDXGIDevice, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
    };
    use windows::core::Interface;

    use super::{OutputInfo, choose_output, pack_bgra_rows};

    /// A captured desktop frame: tightly packed B8G8R8A8 plus its dimensions and
    /// the duplication's presentation timestamp (QPC units).
    #[derive(Debug)]
    pub struct CapturedFrame {
        pub width: usize,
        pub height: usize,
        pub bgra: Vec<u8>,
        pub present_time_qpc: i64,
    }

    /// Why a capture attempt did not yield a frame.
    #[derive(Debug)]
    pub enum CaptureError {
        /// A DXGI/D3D11 call failed.
        Windows(windows::core::Error),
        /// No new frame arrived before the deadline (the screen did not change).
        /// Not fatal: try again.
        Timeout,
        /// The duplication became invalid (mode/desktop switch, or another
        /// client took over). The caller should rebuild via [`DesktopDuplication::recover`].
        AccessLost,
        /// No attached output to duplicate.
        NoOutput,
        /// The mapped staging texture was shorter than its geometry.
        ShortMap,
    }

    impl std::fmt::Display for CaptureError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                CaptureError::Windows(error) => write!(f, "desktop duplication error: {error}"),
                CaptureError::Timeout => write!(f, "no new frame before the deadline"),
                CaptureError::AccessLost => write!(f, "duplication access lost; rebuild required"),
                CaptureError::NoOutput => write!(f, "no attached output to capture"),
                CaptureError::ShortMap => write!(f, "mapped staging texture was too short"),
            }
        }
    }

    impl std::error::Error for CaptureError {}

    impl From<windows::core::Error> for CaptureError {
        fn from(error: windows::core::Error) -> Self {
            CaptureError::Windows(error)
        }
    }

    /// A Desktop Duplication capture session bound to one output.
    #[derive(Debug)]
    pub struct DesktopDuplication {
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        output: IDXGIOutput1,
        duplication: IDXGIOutputDuplication,
        width: u32,
        height: u32,
        staging: Option<ID3D11Texture2D>,
        holding_frame: bool,
    }

    impl DesktopDuplication {
        /// Open a duplication of `output_index` (or the first attached output)
        /// on the default adapter.
        pub fn new(output_index: Option<usize>) -> Result<Self, CaptureError> {
            let (device, context) = create_device()?;
            // SAFETY: FFI. The device casts to its DXGI device, whose adapter
            // enumerates the outputs; each call returns an owned interface.
            let (output, width, height) = unsafe { select_output(&device, output_index)? };
            let duplication = unsafe { duplicate(&output, &device)? };
            Ok(Self {
                device,
                context,
                output,
                duplication,
                width,
                height,
                staging: None,
                holding_frame: false,
            })
        }

        /// Rebuild the duplication after access loss, keeping the same device and
        /// output. Cheap relative to `new` (no device recreation).
        pub fn recover(&mut self) -> Result<(), CaptureError> {
            self.release_if_holding();
            // SAFETY: FFI on the live output/device.
            self.duplication = unsafe { duplicate(&self.output, &self.device)? };
            self.staging = None;
            Ok(())
        }

        /// Capture the next frame, waiting up to `timeout_ms`. `Timeout` means the
        /// screen did not change; `AccessLost` means the caller should
        /// [`Self::recover`] and retry.
        pub fn capture(&mut self, timeout_ms: u32) -> Result<CapturedFrame, CaptureError> {
            self.release_if_holding();
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;
            // SAFETY: FFI. AcquireNextFrame fills `info` and `resource`; its
            // error codes distinguish timeout and access loss.
            let acquired = unsafe {
                self.duplication
                    .AcquireNextFrame(timeout_ms, &mut info, &mut resource)
            };
            if let Err(error) = acquired {
                return Err(match error.code() {
                    code if code == DXGI_ERROR_WAIT_TIMEOUT => CaptureError::Timeout,
                    code if code == DXGI_ERROR_ACCESS_LOST => CaptureError::AccessLost,
                    _ => CaptureError::Windows(error),
                });
            }
            self.holding_frame = true;
            let resource = resource.ok_or(CaptureError::Timeout)?;
            // SAFETY: the acquired resource is a desktop texture; the copy and map
            // stay within the staging texture's mapped bytes.
            let frame = unsafe { self.read_frame(&resource, info.LastPresentTime) };
            self.release_if_holding();
            frame
        }

        /// Copy the desktop texture into the CPU-readable staging texture and pack
        /// its rows into a `CapturedFrame`.
        unsafe fn read_frame(
            &mut self,
            resource: &IDXGIResource,
            present_time_qpc: i64,
        ) -> Result<CapturedFrame, CaptureError> {
            let desktop: ID3D11Texture2D = resource.cast()?;
            let staging = self.ensure_staging()?;
            // SAFETY: both textures are the same size/format B8G8R8A8.
            unsafe { self.context.CopyResource(&staging, &desktop) };

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            // SAFETY: staging is CPU-readable; Map yields a pointer valid until
            // Unmap, which runs before this function returns.
            unsafe {
                self.context
                    .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
            }
            let stride = mapped.RowPitch as usize;
            let width = self.width as usize;
            let height = self.height as usize;
            // SAFETY: the mapped region is at least stride*height bytes.
            let bytes = unsafe {
                std::slice::from_raw_parts(mapped.pData.cast::<u8>(), stride.max(1) * height)
            };
            let packed = pack_bgra_rows(bytes, stride, width, height);
            // SAFETY: pairs with the Map above.
            unsafe { self.context.Unmap(&staging, 0) };

            let bgra = packed.ok_or(CaptureError::ShortMap)?;
            Ok(CapturedFrame {
                width,
                height,
                bgra,
                present_time_qpc,
            })
        }

        /// Create (once) the CPU-readable staging texture matching the output.
        fn ensure_staging(&mut self) -> Result<ID3D11Texture2D, CaptureError> {
            if let Some(staging) = &self.staging {
                return Ok(staging.clone());
            }
            let desc = D3D11_TEXTURE2D_DESC {
                Width: self.width,
                Height: self.height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            // SAFETY: FFI. `desc` is a valid staging description; the out-param
            // receives an owned texture.
            unsafe {
                self.device
                    .CreateTexture2D(&desc, None, Some(&mut staging))?;
            }
            let staging = staging.ok_or(CaptureError::Timeout)?;
            self.staging = Some(staging.clone());
            Ok(staging)
        }

        fn release_if_holding(&mut self) {
            if self.holding_frame {
                // SAFETY: releasing a frame we hold; errors are not actionable.
                let _ = unsafe { self.duplication.ReleaseFrame() };
                self.holding_frame = false;
            }
        }
    }

    impl Drop for DesktopDuplication {
        fn drop(&mut self) {
            self.release_if_holding();
        }
    }

    /// Create a hardware D3D11 device (falling back to WARP software rendering),
    /// with BGRA support for Desktop Duplication.
    fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
        for driver in [D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP] {
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            // SAFETY: FFI. Null adapter selects the default for the driver type;
            // the out-params receive owned interfaces on success.
            let result = unsafe {
                D3D11CreateDevice(
                    None,
                    driver,
                    HMODULE::default(),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
            };
            if result.is_ok()
                && let (Some(device), Some(context)) = (device, context)
            {
                return Ok((device, context));
            }
        }
        Err(CaptureError::NoOutput)
    }

    /// Enumerate the default adapter's outputs, choose one, and return it with
    /// its pixel size.
    unsafe fn select_output(
        device: &ID3D11Device,
        requested: Option<usize>,
    ) -> Result<(IDXGIOutput1, u32, u32), CaptureError> {
        let dxgi_device: IDXGIDevice = device.cast()?;
        // SAFETY: the DXGI device's adapter is a live interface.
        let adapter: IDXGIAdapter = unsafe { dxgi_device.GetAdapter()? };

        let mut infos = Vec::new();
        let mut raw = Vec::new();
        let mut index = 0u32;
        loop {
            // SAFETY: EnumOutputs returns an owned output or a not-found error
            // that ends the enumeration.
            let output = match unsafe { adapter.EnumOutputs(index) } {
                Ok(output) => output,
                Err(_) => break,
            };
            // GetDesc is on the base IDXGIOutput and returns the description.
            // SAFETY: describing a live output.
            let desc = unsafe { output.GetDesc()? };
            let output1: IDXGIOutput1 = output.cast()?;
            let rect = desc.DesktopCoordinates;
            infos.push(OutputInfo {
                attached: desc.AttachedToDesktop.as_bool(),
                width: (rect.right - rect.left).unsigned_abs(),
                height: (rect.bottom - rect.top).unsigned_abs(),
            });
            raw.push(output1);
            index += 1;
        }

        let chosen = choose_output(&infos, requested).ok_or(CaptureError::NoOutput)?;
        let info = infos[chosen];
        let output1 = raw.swap_remove(chosen);
        Ok((output1, info.width, info.height))
    }

    /// Duplicate one output for this device.
    unsafe fn duplicate(
        output: &IDXGIOutput1,
        device: &ID3D11Device,
    ) -> Result<IDXGIOutputDuplication, CaptureError> {
        // SAFETY: FFI on a live output and device.
        Ok(unsafe { output.DuplicateOutput(device)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attached(w: u32, h: u32) -> OutputInfo {
        OutputInfo {
            attached: true,
            width: w,
            height: h,
        }
    }

    fn detached() -> OutputInfo {
        OutputInfo {
            attached: false,
            width: 0,
            height: 0,
        }
    }

    #[test]
    fn choose_output_prefers_a_valid_request() {
        let outputs = [attached(1920, 1080), attached(2560, 1440)];
        assert_eq!(choose_output(&outputs, Some(1)), Some(1));
    }

    #[test]
    fn choose_output_falls_back_to_first_attached() {
        let outputs = [detached(), attached(1920, 1080)];
        // A request for a detached output falls back to the first attached one.
        assert_eq!(choose_output(&outputs, Some(0)), Some(1));
        // No request: the first attached output.
        assert_eq!(choose_output(&outputs, None), Some(1));
    }

    #[test]
    fn choose_output_none_when_nothing_attached() {
        assert_eq!(choose_output(&[detached(), detached()], None), None);
        assert_eq!(choose_output(&[], None), None);
    }

    #[test]
    fn pack_bgra_rows_strips_row_padding() {
        // 2x2 image, stride padded to 12 bytes (8 used + 4 pad).
        let width = 2;
        let height = 2;
        let stride = 12;
        let mut src = vec![0u8; stride * height];
        // Row 0: pixels 1,2 ; Row 1: pixels 3,4 (first byte marks each pixel).
        src[0] = 1;
        src[4] = 2;
        src[stride] = 3;
        src[stride + 4] = 4;
        let out = pack_bgra_rows(&src, stride, width, height).expect("packs");
        assert_eq!(out.len(), width * 4 * height);
        assert_eq!(out[0], 1);
        assert_eq!(out[4], 2);
        assert_eq!(out[8], 3);
        assert_eq!(out[12], 4);
    }

    #[test]
    fn pack_bgra_rows_rejects_short_source_and_narrow_stride() {
        // Source one byte short of the last row.
        let short = vec![0u8; 12 * 2 - 5];
        assert!(pack_bgra_rows(&short, 12, 2, 2).is_none());
        // Stride narrower than a row of pixels.
        assert!(pack_bgra_rows(&[0u8; 100], 4, 2, 2).is_none());
    }
}
