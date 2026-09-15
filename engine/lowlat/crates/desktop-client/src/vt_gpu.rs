//! Zero-copy import of a decoded `CVPixelBuffer` into a `wgpu` texture (macOS).
//!
//! This is milestone 2 of the native-decode work: keep the decoded surface on
//! the GPU. VideoToolbox can decode into an IOSurface-backed `CVPixelBuffer`;
//! `CVMetalTextureCache` turns that surface into an `MTLTexture` with no CPU
//! pixel copy; and `wgpu` re-exports its Metal HAL, so that `MTLTexture` wraps
//! into a `wgpu::Texture` the presenter can sample directly. The import path
//! never reads the pixels back to the CPU -- the honest target from the Parsec
//! analysis, "a GPU-resident path with no CPU pixel readback".
//!
//! This module lands the import mechanism in isolation with an on-hardware
//! readback test (the readback is verification only, not part of the import).
//! Threading a GPU-backed frame through the mailbox to the presenter -- which
//! means sharing the presenter's `wgpu::Device` with the decode worker -- is the
//! integration step that follows.

#![allow(dead_code)]

use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use metal::foreign_types::{ForeignType, ForeignTypeRef};
use std::ffi::c_void;
use std::fmt;

type CvReturn = i32;
type CvImageBufferRef = *mut c_void;
type CvMetalTextureCacheRef = *mut c_void;
type CvMetalTextureRef = *mut c_void;
type CfAllocatorRef = *const c_void;

// `kCVPixelFormatType_32BGRA` == 'BGRA'.
const K_CV_PIXEL_FORMAT_TYPE_32BGRA: u32 = 0x4247_5241;
// `MTLPixelFormatBGRA8Unorm`.
const MTL_PIXEL_FORMAT_BGRA8UNORM: usize = 80;
// `kCVPixelBufferLock_ReadOnly`, for the test fixture's CPU fill.
const K_CV_PIXEL_BUFFER_LOCK_READ_ONLY: u64 = 1;

#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVMetalTextureCacheCreate(
        allocator: CfAllocatorRef,
        cache_attributes: CFDictionaryRef,
        metal_device: *mut c_void,
        texture_attributes: CFDictionaryRef,
        cache_out: *mut CvMetalTextureCacheRef,
    ) -> CvReturn;

    fn CVMetalTextureCacheCreateTextureFromImage(
        allocator: CfAllocatorRef,
        texture_cache: CvMetalTextureCacheRef,
        source_image: CvImageBufferRef,
        texture_attributes: CFDictionaryRef,
        pixel_format: usize,
        width: usize,
        height: usize,
        plane_index: usize,
        texture_out: *mut CvMetalTextureRef,
    ) -> CvReturn;

    fn CVMetalTextureGetTexture(image: CvMetalTextureRef) -> *mut c_void;
    fn CVMetalTextureCacheFlush(cache: CvMetalTextureCacheRef, options: u64);

    fn CVPixelBufferGetWidth(pixel_buffer: CvImageBufferRef) -> usize;
    fn CVPixelBufferGetHeight(pixel_buffer: CvImageBufferRef) -> usize;

    static kCVPixelBufferMetalCompatibilityKey: CFStringRef;
    static kCVPixelBufferIOSurfacePropertiesKey: CFStringRef;
}

/// Why a GPU import failed. Recoverable at the call site by falling back to the
/// CPU decode path.
#[derive(Debug)]
pub(crate) enum GpuImportError {
    /// The wgpu device is not a Metal device.
    NotMetalDevice,
    /// `CVMetalTextureCacheCreate` failed.
    CacheCreate(CvReturn),
    /// `CVMetalTextureCacheCreateTextureFromImage` failed.
    TextureFromImage(CvReturn),
    /// The Metal texture behind the CoreVideo texture was null.
    NoTexture,
}

impl fmt::Display for GpuImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpuImportError::NotMetalDevice => write!(f, "wgpu device is not Metal-backed"),
            GpuImportError::CacheCreate(r) => write!(f, "CVMetalTextureCacheCreate failed ({r})"),
            GpuImportError::TextureFromImage(r) => {
                write!(f, "CVMetalTextureCacheCreateTextureFromImage failed ({r})")
            }
            GpuImportError::NoTexture => write!(f, "CVMetalTextureGetTexture returned null"),
        }
    }
}

impl std::error::Error for GpuImportError {}

/// Retrieve the raw `MTLDevice` pointer backing a wgpu device.
fn metal_device_ptr(device: &wgpu::Device) -> Result<*mut c_void, GpuImportError> {
    // SAFETY: as_hal hands out the Metal HAL device only when this wgpu device
    // is Metal-backed; the raw device pointer is a stable object address.
    // `as_hal` is `Option<R>` (None off Metal); the closure is `Option<_>` too
    // (None if the HAL device is absent), so flatten both.
    let pointer = unsafe {
        device.as_hal::<wgpu::hal::api::Metal, _, _>(|hal_device| {
            hal_device.map(|hal| hal.raw_device().lock().as_ptr() as *mut c_void)
        })
    }
    .flatten();
    pointer.ok_or(GpuImportError::NotMetalDevice)
}

/// Imports IOSurface-backed `CVPixelBuffer`s into `wgpu` textures through a
/// shared `CVMetalTextureCache`.
pub(crate) struct MetalTextureImporter {
    cache: CvMetalTextureCacheRef,
}

// The cache is a CoreFoundation object with thread-safe retain/release; the
// importer owns one reference for its lifetime.
unsafe impl Send for MetalTextureImporter {}

impl MetalTextureImporter {
    /// Create an importer bound to `device`'s Metal device.
    pub(crate) fn new(device: &wgpu::Device) -> Result<Self, GpuImportError> {
        let metal_device = metal_device_ptr(device)?;
        let mut cache: CvMetalTextureCacheRef = std::ptr::null_mut();
        // SAFETY: metal_device is a valid MTLDevice pointer; null attributes
        // select the defaults; on success we own the cache.
        let ret = unsafe {
            CVMetalTextureCacheCreate(
                std::ptr::null(),
                std::ptr::null(),
                metal_device,
                std::ptr::null(),
                &mut cache,
            )
        };
        if ret != 0 || cache.is_null() {
            return Err(GpuImportError::CacheCreate(ret));
        }
        Ok(Self { cache })
    }

    /// Import a BGRA `CVPixelBuffer` into a `wgpu::Texture` with no CPU pixel
    /// copy. The returned texture is `COPY_SRC | TEXTURE_BINDING`.
    ///
    /// The pixel buffer must stay alive (its IOSurface backs the texture) until
    /// the returned texture is no longer used.
    pub(crate) fn import(
        &self,
        device: &wgpu::Device,
        pixel_buffer: CvImageBufferRef,
    ) -> Result<wgpu::Texture, GpuImportError> {
        // SAFETY: pixel_buffer is a valid CVPixelBuffer.
        let width = unsafe { CVPixelBufferGetWidth(pixel_buffer) };
        let height = unsafe { CVPixelBufferGetHeight(pixel_buffer) };
        // Frame dimensions fit u32; the fallback avoids a panic on an absurd one.
        let width_u32 = u32::try_from(width).unwrap_or(u32::MAX);
        let height_u32 = u32::try_from(height).unwrap_or(u32::MAX);

        let mut cv_texture: CvMetalTextureRef = std::ptr::null_mut();
        // SAFETY: cache and pixel_buffer are valid; on success we own cv_texture.
        let ret = unsafe {
            CVMetalTextureCacheCreateTextureFromImage(
                std::ptr::null(),
                self.cache,
                pixel_buffer,
                std::ptr::null(),
                MTL_PIXEL_FORMAT_BGRA8UNORM,
                width,
                height,
                0,
                &mut cv_texture,
            )
        };
        if ret != 0 || cv_texture.is_null() {
            return Err(GpuImportError::TextureFromImage(ret));
        }

        // SAFETY: cv_texture is valid; its MTLTexture is borrowed (+0), so take
        // an owned reference (+1) before releasing the CoreVideo wrapper. The
        // texture stays valid on our retain plus the pixel buffer's IOSurface.
        let metal_texture = unsafe {
            let raw = CVMetalTextureGetTexture(cv_texture);
            if raw.is_null() {
                CFRelease(cv_texture as CFTypeRef);
                return Err(GpuImportError::NoTexture);
            }
            let owned = metal::TextureRef::from_ptr(raw.cast()).to_owned();
            CFRelease(cv_texture as CFTypeRef);
            owned
        };

        // Wrap the MTLTexture as a wgpu-hal Metal texture, then adopt it as a
        // wgpu texture. SAFETY: the texture was created from this device's Metal
        // device and matches the descriptor below.
        let hal_texture = unsafe {
            wgpu::hal::metal::Device::texture_from_raw(
                metal_texture,
                wgpu::TextureFormat::Bgra8Unorm,
                metal::MTLTextureType::D2,
                1,
                1,
                wgpu::hal::CopyExtent {
                    width: width_u32,
                    height: height_u32,
                    depth: 1,
                },
            )
        };
        let descriptor = wgpu::TextureDescriptor {
            label: Some("videotoolbox-imported"),
            size: wgpu::Extent3d {
                width: width_u32,
                height: height_u32,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Bgra8Unorm,
            usage: wgpu::TextureUsages::COPY_SRC | wgpu::TextureUsages::TEXTURE_BINDING,
            view_formats: &[],
        };
        // SAFETY: hal_texture came from this device's Metal HAL and matches the
        // descriptor.
        let texture = unsafe {
            device.create_texture_from_hal::<wgpu::hal::api::Metal>(hal_texture, &descriptor)
        };
        Ok(texture)
    }
}

impl Drop for MetalTextureImporter {
    fn drop(&mut self) {
        if !self.cache.is_null() {
            // SAFETY: cache is owned. Flush releasable textures, then release it.
            unsafe {
                CVMetalTextureCacheFlush(self.cache, 0);
                CFRelease(self.cache as CFTypeRef);
            }
            self.cache = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use std::ffi::c_void;

    type CvPixelBufferRef = *mut c_void;

    #[link(name = "CoreVideo", kind = "framework")]
    unsafe extern "C" {
        fn CVPixelBufferCreate(
            allocator: CfAllocatorRef,
            width: usize,
            height: usize,
            pixel_format_type: u32,
            pixel_buffer_attributes: CFDictionaryRef,
            pixel_buffer_out: *mut CvPixelBufferRef,
        ) -> CvReturn;
        fn CVPixelBufferLockBaseAddress(pixel_buffer: CvPixelBufferRef, flags: u64) -> CvReturn;
        fn CVPixelBufferUnlockBaseAddress(pixel_buffer: CvPixelBufferRef, flags: u64) -> CvReturn;
        fn CVPixelBufferGetBaseAddress(pixel_buffer: CvPixelBufferRef) -> *mut c_void;
        fn CVPixelBufferGetBytesPerRow(pixel_buffer: CvPixelBufferRef) -> usize;
    }

    /// Attributes marking a pixel buffer Metal- and IOSurface-compatible.
    fn metal_compatible_attributes() -> CFDictionary<CFType, CFType> {
        // SAFETY: framework string constants.
        let metal_key =
            unsafe { CFString::wrap_under_get_rule(kCVPixelBufferMetalCompatibilityKey) };
        let io_key = unsafe { CFString::wrap_under_get_rule(kCVPixelBufferIOSurfacePropertiesKey) };
        let empty: CFDictionary<CFType, CFType> = CFDictionary::from_CFType_pairs(&[]);
        CFDictionary::from_CFType_pairs(&[
            (metal_key.as_CFType(), CFBoolean::true_value().as_CFType()),
            (io_key.as_CFType(), empty.as_CFType()),
        ])
    }

    /// Create an IOSurface-backed BGRA pixel buffer filled with one colour.
    fn make_solid_bgra(
        width: usize,
        height: usize,
        b: u8,
        g: u8,
        r: u8,
        a: u8,
    ) -> CvPixelBufferRef {
        let attributes = metal_compatible_attributes();
        let mut pixel_buffer: CvPixelBufferRef = std::ptr::null_mut();
        // SAFETY: valid attributes; on success we own the pixel buffer.
        let ret = unsafe {
            CVPixelBufferCreate(
                std::ptr::null(),
                width,
                height,
                K_CV_PIXEL_FORMAT_TYPE_32BGRA,
                attributes.as_concrete_TypeRef(),
                &mut pixel_buffer,
            )
        };
        assert_eq!(ret, 0, "CVPixelBufferCreate failed");
        assert!(!pixel_buffer.is_null());
        // SAFETY: lock for writing, fill within the reported geometry, unlock.
        unsafe {
            assert_eq!(CVPixelBufferLockBaseAddress(pixel_buffer, 0), 0);
            let base = CVPixelBufferGetBaseAddress(pixel_buffer).cast::<u8>();
            let stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
            for row in 0..height {
                let row_ptr = base.add(row * stride);
                for col in 0..width {
                    let p = row_ptr.add(col * 4);
                    *p = b;
                    *p.add(1) = g;
                    *p.add(2) = r;
                    *p.add(3) = a;
                }
            }
            CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
        }
        pixel_buffer
    }

    /// Copy an imported texture back to the CPU and return its BGRA bytes. This
    /// is verification only -- the import itself never touches pixels on the CPU.
    fn read_back_bgra(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        texture: &wgpu::Texture,
        width: usize,
        height: usize,
    ) -> Vec<u8> {
        let bytes_per_row = width * 4; // width 64 -> 256, already 256-aligned
        assert_eq!(
            bytes_per_row % 256,
            0,
            "test width must keep rows 256-aligned"
        );
        let size = (bytes_per_row * height) as u64;
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder =
            device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        encoder.copy_texture_to_buffer(
            wgpu::ImageCopyTexture {
                texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            wgpu::ImageCopyBuffer {
                buffer: &buffer,
                layout: wgpu::ImageDataLayout {
                    offset: 0,
                    bytes_per_row: Some(u32::try_from(bytes_per_row).unwrap()),
                    rows_per_image: Some(u32::try_from(height).unwrap()),
                },
            },
            wgpu::Extent3d {
                width: u32::try_from(width).unwrap(),
                height: u32::try_from(height).unwrap(),
                depth_or_array_layers: 1,
            },
        );
        queue.submit(Some(encoder.finish()));

        let slice = buffer.slice(..);
        slice.map_async(wgpu::MapMode::Read, |_| {});
        device.poll(wgpu::Maintain::Wait);
        let data = slice.get_mapped_range().to_vec();
        buffer.unmap();
        data
    }

    /// Import a known-colour IOSurface pixel buffer into wgpu and read it back:
    /// proves the GPU import produces correct pixels, on this machine's Metal
    /// device, with no CPU copy on the import path.
    #[test]
    fn imports_a_cvpixelbuffer_into_wgpu() {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::METAL,
            ..Default::default()
        });
        let Some(adapter) =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
        else {
            eprintln!("no Metal adapter; skipping GPU import test");
            return;
        };
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))
                .expect("request device");

        let importer = MetalTextureImporter::new(&device).expect("create importer");
        // Blue-dominant: B=200, G=10, R=20.
        let pixel_buffer = make_solid_bgra(64, 48, 200, 10, 20, 255);
        let texture = importer
            .import(&device, pixel_buffer)
            .expect("import pixel buffer");

        let bytes = read_back_bgra(&device, &queue, &texture, 64, 48);
        let (b, g, r) = (bytes[0], bytes[1], bytes[2]);
        assert!(
            b > 150 && g < 80 && r < 80,
            "imported centre pixel should be blue (B={b} G={g} R={r})"
        );

        // SAFETY: we own the pixel buffer from CVPixelBufferCreate.
        unsafe { CFRelease(pixel_buffer as CFTypeRef) };
    }

    /// End to end: decode real H.264 into an IOSurface pixel buffer (no CPU
    /// copy), import it into a wgpu texture, and read the colour back. This is
    /// the real decode->GPU path, not a synthetic buffer.
    #[test]
    fn decodes_h264_into_a_wgpu_texture() {
        use crate::test_fixtures::{access_units_by_aud, generate_h264};
        use crate::vt_decoder::VideoToolboxH264Decoder;

        let Some(stream) = generate_h264("color=c=0x0000FF:size=64x48:rate=5", 3, 3) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);

        // Decode into retained IOSurface pixel buffers.
        let mut decoder = VideoToolboxH264Decoder::new_gpu();
        let mut gpu_frames = Vec::new();
        for (index, au) in access_units.iter().enumerate() {
            if let Ok(frames) = decoder.decode_gpu(au, index as u64 * 100_000, index == 0) {
                gpu_frames.extend(frames);
            }
        }
        let Some(frame) = gpu_frames.first() else {
            panic!("GPU decode produced no frames");
        };
        assert_eq!(frame.width, 64);
        assert_eq!(frame.height, 48);

        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::METAL,
            ..Default::default()
        });
        let Some(adapter) =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
        else {
            eprintln!("no Metal adapter; skipping");
            return;
        };
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))
                .expect("request device");

        let importer = MetalTextureImporter::new(&device).expect("create importer");
        let texture = importer
            .import(&device, frame.pixel_buffer.as_ptr())
            .expect("import decoded frame");

        let bytes = read_back_bgra(&device, &queue, &texture, 64, 48);
        // Centre pixel, BGRA.
        let offset = ((48 / 2) * 64 + 32) * 4;
        let (b, g, r) = (bytes[offset], bytes[offset + 1], bytes[offset + 2]);
        assert!(
            b > 140 && g < 100 && r < 100,
            "decoded->GPU centre should be blue (B={b} G={g} R={r})"
        );
        // The retained pixel buffer keeps the texture valid; drop after use.
        drop(gpu_frames);
    }

    // A no-swizzle sampling shader. The imported texture is Bgra8Unorm, which
    // wgpu already samples as logical RGBA, so -- unlike the CPU presenter's
    // shader, which swizzles because it uploads BGRA bytes into an RGBA texture
    // -- this must NOT swizzle. Getting that right is the crux of present_texture.
    const RENDER_SHADER: &str = r#"
struct VOut { @builtin(position) position: vec4<f32>, @location(0) uv: vec2<f32> };
@vertex
fn vs_main(@builtin(vertex_index) index: u32) -> VOut {
    var positions = array<vec2<f32>, 3>(vec2<f32>(-1.0, -1.0), vec2<f32>(3.0, -1.0), vec2<f32>(-1.0, 3.0));
    var uvs = array<vec2<f32>, 3>(vec2<f32>(0.0, 0.0), vec2<f32>(2.0, 0.0), vec2<f32>(0.0, 2.0));
    var o: VOut;
    o.position = vec4<f32>(positions[index], 0.0, 1.0);
    o.uv = uvs[index];
    return o;
}
@group(0) @binding(0) var frame_texture: texture_2d<f32>;
@group(0) @binding(1) var frame_sampler: sampler;
@fragment
fn fs_main(in: VOut) -> @location(0) vec4<f32> {
    return textureSample(frame_texture, frame_sampler, in.uv);
}
"#;

    /// Render `source` through the no-swizzle pipeline to an offscreen
    /// Rgba8Unorm target and read it back (bytes R,G,B,A). No CPU pixel copy
    /// touches the source; only the final verification reads back.
    fn render_texture_offscreen(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        source: &wgpu::Texture,
        width: usize,
        height: usize,
    ) -> Vec<u8> {
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("m2 render test"),
            source: wgpu::ShaderSource::Wgsl(std::borrow::Cow::Borrowed(RENDER_SHADER)),
        });
        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: None,
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor::default());
        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: None,
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        let target_format = wgpu::TextureFormat::Rgba8Unorm;
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: None,
            layout: Some(&layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs_main",
                compilation_options: Default::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: target_format,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview: None,
        });
        let target = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("m2 render target"),
            size: wgpu::Extent3d {
                width: u32::try_from(width).unwrap(),
                height: u32::try_from(height).unwrap(),
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: target_format,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        let source_view = source.create_view(&wgpu::TextureViewDescriptor::default());
        let target_view = target.create_view(&wgpu::TextureViewDescriptor::default());
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None,
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&source_view),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::Sampler(&sampler),
                },
            ],
        });
        let mut encoder =
            device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: None,
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &target_view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.draw(0..3, 0..1);
        }
        queue.submit(Some(encoder.finish()));
        read_back_bgra(device, queue, &target, width, height)
    }

    /// The render half of M2: decode -> import -> GPU shader render -> read a
    /// correct colour back. Proves the imported Bgra8Unorm texture renders
    /// through a sampling pipeline without a swizzle -- the format handling the
    /// live present_texture path will use once the decode worker shares the
    /// presenter's wgpu device.
    #[test]
    fn renders_a_decoded_frame_through_a_shader() {
        use crate::test_fixtures::{access_units_by_aud, generate_h264};
        use crate::vt_decoder::VideoToolboxH264Decoder;

        let Some(stream) = generate_h264("color=c=0x0000FF:size=64x48:rate=5", 3, 3) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);
        let mut decoder = VideoToolboxH264Decoder::new_gpu();
        let mut gpu_frames = Vec::new();
        for (index, au) in access_units.iter().enumerate() {
            if let Ok(frames) = decoder.decode_gpu(au, index as u64 * 100_000, index == 0) {
                gpu_frames.extend(frames);
            }
        }
        let Some(frame) = gpu_frames.first() else {
            panic!("GPU decode produced no frames");
        };

        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::METAL,
            ..Default::default()
        });
        let Some(adapter) =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
        else {
            eprintln!("no Metal adapter; skipping");
            return;
        };
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))
                .expect("request device");
        let importer = MetalTextureImporter::new(&device).expect("create importer");
        let texture = importer
            .import(&device, frame.pixel_buffer.as_ptr())
            .expect("import decoded frame");

        let bytes = render_texture_offscreen(&device, &queue, &texture, 64, 48);
        // Rgba8Unorm target: bytes are R,G,B,A.
        let offset = ((48 / 2) * 64 + 32) * 4;
        let (r, g, b) = (bytes[offset], bytes[offset + 1], bytes[offset + 2]);
        assert!(
            b > 140 && r < 100 && g < 100,
            "rendered pixel should be blue (R={r} G={g} B={b})"
        );
        drop(gpu_frames);
    }
}
