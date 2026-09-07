//! Desktop presentation helpers shared by the window.
//!
//! The transport and decoder hand the UI a bounded BGRA frame. The default
//! software path presents it through minifb, while the optional native path
//! uploads the same frame to one GPU texture and draws a full-screen triangle
//! through wgpu. The native path deliberately owns no network state, so a
//! surface/driver failure can fall back to the software presenter without
//! tearing down the session.

use std::borrow::Cow;

use minifb::Window;

/// Maximum presentable pixels per frame (7680x4320, the negotiated ceiling).
pub(crate) const MAX_PRESENT_PIXELS: usize = 7680 * 4320;

/// Errors from frame validation; all map to dropping the frame, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentError {
    ZeroDimension,
    TooLarge,
    LengthMismatch,
}

impl std::fmt::Display for PresentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroDimension => f.write_str("frame dimensions are zero"),
            Self::TooLarge => f.write_str("frame exceeds the negotiated ceiling"),
            Self::LengthMismatch => f.write_str("BGRA buffer length does not match dimensions"),
        }
    }
}

impl std::error::Error for PresentError {}

/// Validate one decoded BGRA frame before presenting it.
pub(crate) fn validate_bgra_frame(
    width: usize,
    height: usize,
    pixels: &[u32],
) -> Result<(), PresentError> {
    if width == 0 || height == 0 {
        return Err(PresentError::ZeroDimension);
    }
    let count = width.checked_mul(height).ok_or(PresentError::TooLarge)?;
    if count > MAX_PRESENT_PIXELS {
        return Err(PresentError::TooLarge);
    }
    if pixels.len() != count {
        return Err(PresentError::LengthMismatch);
    }
    Ok(())
}

/// Fixed-cadence frame pacer: at most one present per `interval`, dropping
/// stale frames instead of accumulating latency.
#[derive(Debug)]
pub(crate) struct FramePacer {
    interval: std::time::Duration,
    last: Option<std::time::Instant>,
}

impl FramePacer {
    pub(crate) fn new(fps: u16) -> Self {
        let interval = if fps == 0 {
            std::time::Duration::from_millis(16)
        } else {
            std::time::Duration::from_nanos(1_000_000_000 / u64::from(fps.max(1)))
        };
        Self {
            interval,
            last: None,
        }
    }

    /// Returns `true` when the caller should present now.
    pub(crate) fn should_present(&mut self, now: std::time::Instant) -> bool {
        match self.last {
            Some(previous) if now.duration_since(previous) < self.interval => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

/// Presentation backend selected by `OPENSTREAM_RENDERER`.
///
/// `software` (the default) presents through the OS window via minifb. The
/// native names choose one wgpu backend. The `d3d11` spelling is retained for
/// configuration compatibility, but wgpu uses the platform's Direct3D 12
/// backend; it is reported accurately in the startup log rather than being
/// presented as a D3D11 implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RenderBackend {
    #[default]
    Software,
    D3d11,
    Metal,
    Vulkan,
    OpenGl,
}

impl RenderBackend {
    pub(crate) fn from_env() -> Self {
        let name = std::env::var("OPENSTREAM_RENDERER").unwrap_or_default();
        Self::parse(&name)
    }

    pub(crate) fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "d3d11" | "d3d12" | "direct3d" => Self::D3d11,
            "metal" => Self::Metal,
            "vulkan" => Self::Vulkan,
            "gl" | "opengl" | "gles" => Self::OpenGl,
            _ => Self::Software,
        }
    }

    fn wgpu_backends(self) -> wgpu::Backends {
        match self {
            Self::Software => wgpu::Backends::empty(),
            // wgpu does not expose a D3D11 backend. Keep the old environment
            // spelling, but use the native Direct3D 12 backend it provides.
            Self::D3d11 => wgpu::Backends::DX12,
            Self::Metal => wgpu::Backends::METAL,
            Self::Vulkan => wgpu::Backends::VULKAN,
            Self::OpenGl => wgpu::Backends::GL,
        }
    }

    pub(crate) fn is_native(self) -> bool {
        !matches!(self, Self::Software)
    }
}

/// Native GPU presenter for the minifb-owned window.
///
/// The lifetime ties the wgpu surface to the minifb window that supplies its
/// raw handles. The presenter stores one decoded frame texture and replaces
/// it only when the negotiated video dimensions change; the surface itself is
/// reconfigured only when the OS window is resized.
#[derive(Debug)]
pub(crate) struct GpuPresenter {
    instance: wgpu::Instance,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    sampler: wgpu::Sampler,
    pipeline: wgpu::RenderPipeline,
    texture: Option<wgpu::Texture>,
    bind_group: Option<wgpu::BindGroup>,
    frame_size: Option<(u32, u32)>,
    max_texture_dimension_2d: u32,
}

impl GpuPresenter {
    /// Try to initialize a native presenter. Driver and surface errors are
    /// returned to the caller, which can retain the software path.
    pub(crate) fn new(window: &Window, backend: RenderBackend) -> Result<Self, String> {
        if !backend.is_native() {
            return Err("software rendering was requested".to_string());
        }
        let requested_backends = backend.wgpu_backends();
        if !wgpu::Instance::enabled_backend_features().intersects(requested_backends) {
            return Err(format!(
                "{backend:?} is not compiled for this operating system"
            ));
        }
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: requested_backends,
            ..Default::default()
        });
        // The presenter is created after `window` and dropped before it in
        // `main`, so the native handles remain valid for the entire surface
        // lifetime. The raw-handle API is needed here to avoid holding a Rust
        // borrow of `Window` while the event loop mutates it.
        let target = unsafe { wgpu::SurfaceTargetUnsafe::from_window(window) }
            .map_err(|error| format!("could not get {backend:?} window handles: {error}"))?;
        let surface = unsafe { instance.create_surface_unsafe(target) }
            .map_err(|error| format!("could not create {backend:?} surface: {error}"))?;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: Some(&surface),
        }))
        .ok_or_else(|| format!("no adapter for {backend:?}"))?;
        let info = adapter.get_info();
        let adapter_limits = adapter.limits();
        let max_texture_dimension_2d = adapter_limits.max_texture_dimension_2d;
        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("openstream desktop presenter"),
                required_features: wgpu::Features::empty(),
                // Use the adapter's limits rather than downlevel defaults so
                // 2560/4K frames are not artificially capped at 2048 pixels.
                required_limits: adapter_limits,
            },
            None,
        ))
        .map_err(|error| format!("could not open {backend:?} adapter: {error}"))?;
        let (window_width, window_height) = window.get_size();
        let width = u32::try_from(window_width.max(1))
            .map_err(|_| "window width exceeds the GPU surface limit".to_string())?;
        let height = u32::try_from(window_height.max(1))
            .map_err(|_| "window height exceeds the GPU surface limit".to_string())?;
        let mut config = surface
            .get_default_config(&adapter, width, height)
            .ok_or_else(|| format!("{backend:?} surface has no compatible formats"))?;
        config.desired_maximum_frame_latency = 1;
        surface.configure(&device, &config);

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("openstream frame texture layout"),
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
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("openstream frame sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("openstream frame shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(FRAME_SHADER)),
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("openstream frame pipeline layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("openstream frame pipeline"),
            layout: Some(&pipeline_layout),
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
                    format: config.format,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview: None,
        });
        eprintln!(
            "OpenStream native renderer: {backend:?} via {:?} ({})",
            info.backend, info.name
        );
        Ok(Self {
            instance,
            surface,
            device,
            queue,
            config,
            sampler,
            pipeline,
            texture: None,
            bind_group: None,
            frame_size: None,
            max_texture_dimension_2d,
        })
    }

    /// Upload and present one validated BGRA frame. Transient swapchain
    /// changes are recovered in place; only an out-of-memory condition is
    /// returned as a hard presenter failure.
    pub(crate) fn present(
        &mut self,
        window: &Window,
        width: usize,
        height: usize,
        pixels: &[u32],
    ) -> Result<(), String> {
        validate_bgra_frame(width, height, pixels)
            .map_err(|error| format!("native presenter refused frame: {error}"))?;
        let (window_width, window_height) = window.get_size();
        let surface_width = u32::try_from(window_width.max(1))
            .map_err(|_| "window width exceeds the GPU surface limit".to_string())?;
        let surface_height = u32::try_from(window_height.max(1))
            .map_err(|_| "window height exceeds the GPU surface limit".to_string())?;
        if self.config.width != surface_width || self.config.height != surface_height {
            self.config.width = surface_width;
            self.config.height = surface_height;
            self.surface.configure(&self.device, &self.config);
        }

        let frame_width =
            u32::try_from(width).map_err(|_| "frame width is too large".to_string())?;
        let frame_height =
            u32::try_from(height).map_err(|_| "frame height is too large".to_string())?;
        if frame_width > self.max_texture_dimension_2d
            || frame_height > self.max_texture_dimension_2d
        {
            return Err(format!(
                "frame {frame_width}x{frame_height} exceeds GPU texture limit {}",
                self.max_texture_dimension_2d
            ));
        }
        if self.frame_size != Some((frame_width, frame_height)) {
            let texture = self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("openstream decoded BGRA frame"),
                size: wgpu::Extent3d {
                    width: frame_width,
                    height: frame_height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                // The CPU decoder stores bytes in BGRA order. Upload as RGBA
                // and swizzle in the fragment shader, which is portable on
                // every wgpu surface instead of depending on BGRA texture
                // binding support.
                format: wgpu::TextureFormat::Rgba8UnormSrgb,
                usage: wgpu::TextureUsages::COPY_DST | wgpu::TextureUsages::TEXTURE_BINDING,
                view_formats: &[],
            });
            let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
            let pipeline_layout = self.pipeline.get_bind_group_layout(0);
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("openstream frame bind group"),
                layout: &pipeline_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: wgpu::BindingResource::TextureView(&view),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: wgpu::BindingResource::Sampler(&self.sampler),
                    },
                ],
            });
            self.texture = Some(texture);
            self.bind_group = Some(bind_group);
            self.frame_size = Some((frame_width, frame_height));
        }
        let Some(texture) = self.texture.as_ref() else {
            return Err("native frame texture was not created".to_string());
        };
        self.queue.write_texture(
            texture.as_image_copy(),
            bytemuck::cast_slice(pixels),
            wgpu::ImageDataLayout {
                offset: 0,
                bytes_per_row: Some(frame_width.saturating_mul(4)),
                rows_per_image: Some(frame_height),
            },
            wgpu::Extent3d {
                width: frame_width,
                height: frame_height,
                depth_or_array_layers: 1,
            },
        );

        let output = match self.surface.get_current_texture() {
            Ok(output) => output,
            Err(wgpu::SurfaceError::Lost | wgpu::SurfaceError::Outdated) => {
                self.surface.configure(&self.device, &self.config);
                return Ok(());
            }
            Err(wgpu::SurfaceError::Timeout) => return Ok(()),
            Err(wgpu::SurfaceError::OutOfMemory) => {
                return Err("native renderer ran out of GPU memory".to_string());
            }
        };
        let view = output
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("openstream frame encoder"),
            });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("openstream frame pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
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
            pass.set_pipeline(&self.pipeline);
            let Some(bind_group) = self.bind_group.as_ref() else {
                return Err("native frame bind group was not created".to_string());
            };
            pass.set_bind_group(0, bind_group, &[]);
            pass.draw(0..3, 0..1);
        }
        self.queue.submit(Some(encoder.finish()));
        output.present();
        self.instance.poll_all(false);
        Ok(())
    }
}

const FRAME_SHADER: &str = r#"
struct VertexOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) index: u32) -> VertexOutput {
    var positions = array<vec2<f32>, 3>(
        vec2<f32>(-1.0, -1.0),
        vec2<f32>( 3.0, -1.0),
        vec2<f32>(-1.0,  3.0),
    );
    var uvs = array<vec2<f32>, 3>(
        vec2<f32>(0.0, 1.0),
        vec2<f32>(2.0, 1.0),
        vec2<f32>(0.0, -1.0),
    );
    var output: VertexOutput;
    output.position = vec4<f32>(positions[index], 0.0, 1.0);
    output.uv = uvs[index];
    return output;
}

@group(0) @binding(0)
var frame_texture: texture_2d<f32>;
@group(0) @binding(1)
var frame_sampler: sampler;

@fragment
fn fs_main(input: VertexOutput) -> @location(0) vec4<f32> {
    return textureSample(frame_texture, frame_sampler, input.uv).bgra;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_frames_before_present() {
        assert_eq!(
            validate_bgra_frame(0, 1080, &[]),
            Err(PresentError::ZeroDimension)
        );
        assert_eq!(
            validate_bgra_frame(7681, 4321, &vec![0; 7681 * 4321]),
            Err(PresentError::TooLarge)
        );
        assert_eq!(
            validate_bgra_frame(2, 2, &[0, 0, 0]),
            Err(PresentError::LengthMismatch)
        );
        assert!(validate_bgra_frame(2, 2, &[0; 4]).is_ok());
    }

    #[test]
    fn pacer_limits_presents_to_cadence() {
        let mut pacer = FramePacer::new(60);
        let start = std::time::Instant::now();
        assert!(pacer.should_present(start));
        assert!(!pacer.should_present(start));
        assert!(pacer.should_present(start + std::time::Duration::from_millis(17)));
    }

    #[test]
    fn renderer_names_select_the_expected_backend() {
        assert_eq!(RenderBackend::parse(""), RenderBackend::Software);
        assert_eq!(RenderBackend::parse("d3d11"), RenderBackend::D3d11);
        assert_eq!(RenderBackend::parse("metal"), RenderBackend::Metal);
        assert_eq!(RenderBackend::parse("vulkan"), RenderBackend::Vulkan);
        assert_eq!(RenderBackend::parse("OPENGL"), RenderBackend::OpenGl);
        assert!(!RenderBackend::Software.is_native());
        assert!(RenderBackend::Vulkan.is_native());
    }
}
