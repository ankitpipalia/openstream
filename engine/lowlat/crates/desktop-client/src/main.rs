//! Small cross-platform desktop client.
//!
//! The network/media core is shared with mobile and the headless test client.
//! This binary adds the desktop presentation path: FFmpeg decodes negotiated
//! Annex-B H.264/H.265 access units to BGRA and presents them in a native
//! window. The default minifb software path and the optional wgpu
//! Metal/Vulkan/OpenGL/Direct3D path share the same bounded UI and network
//! queues without changing signaling or the OpenStream wire format.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use gilrs::ff::{BaseEffect, BaseEffectType, Effect, EffectBuilder, Repeat, Replay, Ticks};
use gilrs::{Axis, Button, EventType, GamepadId, Gilrs};
use minifb::{Key, MouseButton, MouseMode, Window};
use openstream_client_core::{
    Capabilities, ConnectionPath, FlushOutcome, PeerSession, ReliableControl, Role, VideoCodec,
    load_pairing_from_environment, parse_stun_servers,
};
use openstream_media::clipboard::{
    Assembler as ClipboardAssembler, CompletedClipboard, fragment_text,
};
use openstream_media::displays::Display as RemoteDisplay;
use openstream_media::frame_age::{
    DecodedFrame, DecodedFrameSeq, FrameAgeRecord, FrameOffer, FrameSurface,
};
use openstream_media::input::{FLAG_RELATIVE, InputEvent, InputKind, RumbleEvent};
use openstream_media::latency::{
    Client as ClientClock, ClientObservability, ClientRecorder, ClientStage, Liveness, Milestone,
    ReportOnDrop, RunContext, Stamp, TraceEnd,
};
use openstream_media::latest_frame::{LatestFramePublisher, LatestFrameReader, latest_frame};
use openstream_media::metrics::ReconnectSupervisor;
use openstream_media::probe::{InteractionProbe, detect as probe_detect};
use openstream_media::{
    Assembler, AudioEvent, AudioFrame, Fragment, FragmentOutcome, FrameAck, JitterBuffer,
    KEYFRAME_REQUEST, metrics::MetricsReporter,
};
use openstream_platform::clipboard as platform_clipboard;
use openstream_platform::clipboard_policy::ClipboardPolicy;
use openstream_protocol::Kind;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

mod display;
mod fullscreen;
mod mic;
mod raw_pointer;
mod render;
// In-process VideoToolbox H.264 decode (macOS). Live: `decode_dispatch`
// selects it for a session and `native_decode_worker` below drives it.
#[cfg(target_os = "macos")]
mod vt_decoder;
// Zero-copy import of a decoded CVPixelBuffer into a wgpu texture (macOS).
// Live under `OPENSTREAM_ZERO_COPY=1`: `native_decode_worker` publishes
// surfaces and the window imports and presents them (see `present_gpu_frame`).
#[cfg(target_os = "macos")]
mod vt_gpu;
// In-process Media Foundation H.264 decode (Windows) lives in the shared
// openstream-windows-media codec crate; the worker below drives it.
// Decoder-backend selection and the native decode -> DecodedFrame path. The
// runtime network loop selects through here (see `select_decoder` below); the
// loopback harness drives the native decoder directly.
mod decode_dispatch;
// Shared ffmpeg-fixture test helpers, used only by the macOS decode tests.
#[cfg(all(test, target_os = "macos"))]
mod test_fixtures;
// Pure lifecycle/input-safety seam; a future winit presenter can consume it
// without making this minifb path or the dependency graph change in this slice.
#[allow(dead_code)]
mod session;

const DEFAULT_WIDTH: usize = 1280;
const DEFAULT_HEIGHT: usize = 720;
/// A slow window must not let decoded frames or status messages accumulate
/// without bound. New frames are dropped when the UI is behind; the next
/// frame is still a complete decoded image.
/// Channel for unreliable input.
///
/// Separate from the reliable control channel so a host can tell the two
/// apart without inspecting the payload, and so congestion on one does not
/// reorder the other.
const INPUT_CHANNEL: u8 = 1;

const UI_QUEUE_CAPACITY: usize = 8;
/// Input is sampled at the UI rate and must remain bounded if the network
/// worker is stalled. The queue is intentionally larger than the UI queue so
/// short scheduling pauses do not drop normal keyboard transitions.
const INPUT_QUEUE_CAPACITY: usize = 1024;
/// Lifecycle and state transitions need a separate bounded lane so a burst of
/// normal input cannot prevent a release or stop command from reaching the
/// worker. The lane is still bounded: repeated lifecycle notifications must
/// not become an unbounded memory escape hatch.
const CRITICAL_INPUT_QUEUE_CAPACITY: usize = 16;
/// Status/topology messages are small and infrequent, but must not disappear
/// behind a burst of decoded frames.
const CRITICAL_UI_QUEUE_CAPACITY: usize = 32;

#[derive(Debug)]
enum UiMessage {
    Ready {
        width: usize,
        height: usize,
        fps: u16,
        path: ConnectionPath,
        audio: bool,
        input: bool,
    },
    /// A decoded picture on its way to the presenter. It carries its own
    /// sequence number and stamps so the window can account for the time it
    /// spent in this queue and for the frames that never arrived; a bare
    /// buffer leaves both unknowable at the consuming end.
    Frame(Box<DecodedFrame>),
    Error(String),
    Metrics(String),
    Rumble {
        device_id: u32,
        strong: u8,
        weak: u8,
    },
    Displays(Vec<RemoteDisplay>),
    /// The session dropped and the worker is waiting out its backoff before
    /// trying again. The window must stop sampling and forwarding input
    /// for the duration: nothing is draining the input queue while the
    /// worker sleeps, so anything typed here would otherwise sit in the
    /// queue and be delivered to whatever session connects next.
    Reconnecting {
        attempt: u32,
        delay_ms: u64,
    },
    End,
}

/// Non-blocking bounded sender used by the network worker. Blocking the
/// transport on a stalled desktop window would turn a rendering problem into
/// a connection-wide deadlock; stale frames/metrics may be dropped, while
/// lifecycle and topology messages use the separate priority lane.
#[derive(Clone, Debug)]
struct UiSender {
    normal: SyncSender<UiMessage>,
    critical: SyncSender<UiMessage>,
    /// Frames do not queue.
    ///
    /// They used to share the normal lane, where a full queue dropped the
    /// frame being offered and kept up to eight stale ones -- so under load
    /// the window was shown exactly the pictures that mattered least, and the
    /// backlog's length was added to the latency of everything behind it.
    /// A capacity-one mailbox shows the newest picture instead, and costs
    /// frame rate rather than frame age when the presenter falls behind.
    frames: LatestFramePublisher<Box<DecodedFrame>>,
}

impl UiSender {
    fn send(&self, message: UiMessage) -> Result<(), ()> {
        let critical = matches!(
            &message,
            UiMessage::Ready { .. }
                | UiMessage::Error(_)
                | UiMessage::Displays(_)
                | UiMessage::Reconnecting { .. }
                | UiMessage::End
        );
        let sender = if critical {
            &self.critical
        } else {
            &self.normal
        };
        sender.try_send(message).map_err(|_| ())
    }

    /// Offer a decoded frame to the window, saying which of the two failure
    /// modes occurred.
    ///
    /// `send` collapses both into `Err(())`, which is adequate for a metrics
    /// line and wrong for a frame: "the window replaced a picture it had not
    /// drawn yet" and "the window is gone" call for different responses and
    /// belong in different counters.
    ///
    /// `ReplacedOlder` is not a loss. The frame being offered is the one the
    /// viewer will see; what was displaced is a picture that was already out
    /// of date. It is counted because a stream producing them constantly is
    /// saying the presenter cannot keep up with the decoder.
    fn send_frame(&self, frame: DecodedFrame) -> FrameOffer {
        self.frames.publish(Box::new(frame))
    }
}

/// The UI side of the two bounded lanes. Critical messages are checked first
/// so a terminal error/end notification is visible even when several stale
/// frames were already queued.
#[derive(Debug)]
struct UiReceiver {
    normal: Receiver<UiMessage>,
    critical: Receiver<UiMessage>,
    frames: LatestFrameReader<Box<DecodedFrame>>,
}

impl UiReceiver {
    /// Critical, then the newest frame, then everything else.
    ///
    /// Frames come before the normal lane so a backlog of metrics lines
    /// cannot delay the picture; critical comes before both so a terminal
    /// error or end notice is never stuck behind rendering.
    fn try_recv(&self) -> Result<UiMessage, TryRecvError> {
        if let Ok(message) = self.critical.try_recv() {
            return Ok(message);
        }
        if let Some(frame) = self.frames.take() {
            return Ok(UiMessage::Frame(frame));
        }
        self.normal.try_recv()
    }
}

#[derive(Debug, Clone, Copy)]
enum UiInput {
    Event(InputEvent),
    Release,
    SelectDisplay(u32),
    Stop,
}

/// Two bounded input lanes. Normal events preserve FIFO order; release/stop
/// and monitor-selection commands have a small priority lane so cleanup and
/// explicit state changes are not lost when normal input is backpressured.
#[derive(Clone, Debug)]
struct InputSender {
    normal: SyncSender<UiInput>,
    critical: SyncSender<UiInput>,
    relative_motion: Arc<Mutex<Option<InputEvent>>>,
}

impl InputSender {
    fn try_send(&self, input: UiInput) -> Result<(), ()> {
        if let UiInput::Event(event) = input
            && event.kind == InputKind::PointerMotion
            && event.flags & FLAG_RELATIVE != 0
        {
            let mut pending = self.relative_motion.lock().map_err(|_| ())?;
            if let Some(previous) = *pending {
                *pending = Some(InputEvent::pointer_motion(
                    true,
                    previous.value.saturating_add(event.value),
                    previous.value2.saturating_add(event.value2),
                    event.timestamp_us,
                ));
            } else {
                *pending = Some(event);
            }
            return Ok(());
        }
        let critical = matches!(
            &input,
            UiInput::Release | UiInput::SelectDisplay(_) | UiInput::Stop
        );
        let sender = if critical {
            &self.critical
        } else {
            &self.normal
        };
        sender.try_send(input).map_err(|_| ())
    }
}

#[derive(Debug)]
struct InputReceiver {
    normal: Receiver<UiInput>,
    critical: Receiver<UiInput>,
    relative_motion: Arc<Mutex<Option<InputEvent>>>,
    deferred_critical: Option<UiInput>,
}

impl InputReceiver {
    /// Release and stop are safety barriers: they must not sit behind a full
    /// normal queue containing stale key/button transitions. A display
    /// selection is deferred until already-queued input has drained so it
    /// cannot reorder a user's click with a monitor change.
    fn try_recv(&mut self) -> Result<UiInput, TryRecvError> {
        if let Some(input) = self.deferred_critical.take() {
            return Ok(input);
        }
        match self.critical.try_recv() {
            Ok(input @ (UiInput::Release | UiInput::Stop)) => {
                self.discard_normal();
                Ok(input)
            }
            Ok(input @ UiInput::SelectDisplay(_)) => match self.normal.try_recv() {
                Ok(normal) => {
                    self.deferred_critical = Some(input);
                    Ok(normal)
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(input),
            },
            // `InputSender::try_send` routes ordinary events to the normal
            // lane, so this is unreachable today. It is still delivered
            // rather than dropped: the one thing this queue must never do is
            // lose a key or button transition, and a silent discard here
            // would leave a key held on the host with no matching release.
            Ok(input @ UiInput::Event(_)) => Ok(input),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => match self.normal.try_recv() {
                Ok(input) => Ok(input),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => self
                    .relative_motion
                    .lock()
                    .ok()
                    .and_then(|mut pending| pending.take())
                    .map(|event| Ok(UiInput::Event(event)))
                    .unwrap_or(Err(TryRecvError::Empty)),
            },
        }
    }

    fn discard_normal(&mut self) {
        while self.normal.try_recv().is_ok() {}
        if let Ok(mut pending) = self.relative_motion.lock() {
            *pending = None;
        }
    }
}

fn input_channels(normal_capacity: usize) -> (InputSender, InputReceiver) {
    let (normal_tx, normal_rx) = mpsc::sync_channel(normal_capacity);
    let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_INPUT_QUEUE_CAPACITY);
    let relative_motion = Arc::new(Mutex::new(None));
    (
        InputSender {
            normal: normal_tx,
            critical: critical_tx,
            relative_motion: Arc::clone(&relative_motion),
        },
        InputReceiver {
            normal: normal_rx,
            critical: critical_rx,
            relative_motion,
            deferred_critical: None,
        },
    )
}

/// Whether decoded pictures may travel to the window as GPU surfaces instead
/// of pixel buffers.
///
/// Process-wide because the decision is: there is one window and one
/// presenter, and the decode worker that has to honour it sits several call
/// layers below `main`. It is set once at startup and cleared if the GPU path
/// later proves unusable. A decode worker reads it when it starts, so
/// clearing it takes effect at the next reconnect rather than mid-stream --
/// the decoder's mode is fixed when its session is created, and swapping it
/// mid-stream would stall until the next keyframe.
static ZERO_COPY_PRESENT: AtomicBool = AtomicBool::new(false);

/// Zero-copy presentation needs both halves: the user asking for it, and a
/// native presenter to import the surface into.
///
/// With the software presenter there is nothing to import into, and a frame
/// that carries a surface has no pixels -- the readback it would have paid
/// for is exactly what this path removes -- so enabling it without a native
/// presenter would present black. The presenter's availability is only known
/// after it has actually been created, which is why this is a function of the
/// built presenter and not of the requested backend.
const fn zero_copy_available(opted_in: bool, native_presenter: bool) -> bool {
    opted_in && native_presenter
}

/// Record that a frame reached the presenter.
///
/// Shared by the CPU and zero-copy present paths so both credit exactly the
/// same milestones: if only one of them recorded, say, `present_called`, the
/// two paths could not be compared, and comparing them is the whole point of
/// the zero-copy work. Called only after a presenter accepted the frame.
fn record_frame_presented(
    telemetry: &SharedTelemetry,
    seq: DecodedFrameSeq,
    decoded_at: Stamp<ClientClock>,
    marker: Option<u16>,
    present_started: Stamp<ClientClock>,
    presented_at: Stamp<ClientClock>,
) {
    with_telemetry(telemetry, |client| {
        client.frames.present_called(present_started, presented_at);
        client
            .frames
            .present_submitted_seq(seq, decoded_at, presented_at);
        client.marker_present_submitted(marker, presented_at);
        client.liveness.advance(
            Milestone::FramePresented,
            seq_as_frame_id(seq),
            presented_at,
        );
    });
}

/// Present one GPU-resident frame: import its pixel buffer into a texture on
/// the presenter's own device, then draw that texture.
///
/// The importer is built lazily and kept across frames because its
/// `CVMetalTextureCache` is what makes repeat imports cheap; it must come
/// from `presenter.device()`, since a texture imported on any other device is
/// one this presenter cannot bind.
#[cfg(target_os = "macos")]
fn present_gpu_frame(
    presenter: &mut render::GpuPresenter,
    importer: &mut Option<vt_gpu::MetalTextureImporter>,
    window: &Window,
    surface: &vt_decoder::SendPixelBuffer,
) -> Result<(), String> {
    if importer.is_none() {
        *importer = Some(
            vt_gpu::MetalTextureImporter::new(presenter.device())
                .map_err(|error| format!("Metal texture importer unavailable: {error}"))?,
        );
    }
    let texture = importer
        .as_ref()
        .ok_or_else(|| "Metal texture importer missing".to_string())?
        .import(presenter.device(), surface.as_ptr())
        .map_err(|error| format!("could not import the decoded surface: {error}"))?;
    presenter.present_texture(window, &texture)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (ui_normal_tx, ui_normal_rx) = mpsc::sync_channel(UI_QUEUE_CAPACITY);
    let (ui_critical_tx, ui_critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
    let (frame_publisher, frame_reader) = latest_frame();
    let ui_tx = UiSender {
        normal: ui_normal_tx,
        critical: ui_critical_tx,
        frames: frame_publisher,
    };
    let ui_rx = UiReceiver {
        normal: ui_normal_rx,
        critical: ui_critical_rx,
        frames: frame_reader,
    };
    let (input_tx, input_rx) = input_channels(INPUT_QUEUE_CAPACITY);
    let display_mode = display::DisplayMode::from_env();
    let mut window = Window::new(
        "OpenStream",
        DEFAULT_WIDTH,
        DEFAULT_HEIGHT,
        display_mode.window_options(),
    )?;
    let keyboard_connected = Arc::new(AtomicBool::new(false));
    window.set_input_callback(Box::new(KeyboardEvents {
        input_tx: input_tx.clone(),
        connected: Arc::clone(&keyboard_connected),
    }));
    if display_mode.wants_whole_screen() && fullscreen::enter(window.get_window_handle()) {
        // Said out loud because the mode is otherwise indistinguishable from
        // a window that simply failed to resize.
        println!("OpenStream run window=fullscreen requested from the platform");
    }
    let render_backend = render::RenderBackend::from_env();
    let mut native_presenter = if render_backend.is_native() {
        match render::GpuPresenter::new(&window, render_backend) {
            Ok(presenter) => Some(presenter),
            Err(error) => {
                eprintln!(
                    "OpenStream native renderer {render_backend:?} unavailable: {error}; using software present"
                );
                None
            }
        }
    } else {
        None
    };
    // Latched before the network thread starts, because the decode worker it
    // spawns reads this to decide whether to decode into GPU surfaces, and a
    // surface is only useful if the presenter above actually exists.
    ZERO_COPY_PRESENT.store(
        zero_copy_available(
            decode_dispatch::prefer_zero_copy_from_env(),
            native_presenter.is_some(),
        ),
        Ordering::Relaxed,
    );
    if ZERO_COPY_PRESENT.load(Ordering::Relaxed) {
        eprintln!(
            "OpenStream zero-copy present enabled: decoded surfaces go to the GPU without a CPU readback"
        );
    } else if decode_dispatch::prefer_zero_copy_from_env() {
        eprintln!(
            "OpenStream zero-copy present requested but no native presenter is available; using CPU frames"
        );
    }
    // This opt-in path exercises native adapter creation, texture upload, and
    // one present without requiring a signaling service or pairing secret.
    // It is intentionally not part of normal startup or the production
    // session state machine.
    if env::var("OPENSTREAM_RENDERER_SMOKE").as_deref() == Ok("1") {
        let pixels = [0xff00_00ff, 0xff00_ff00, 0xffff_0000, 0xffff_ffff];
        if let Some(presenter) = native_presenter.as_mut() {
            presenter
                .present(&window, 2, 2, &pixels)
                .map_err(|error| format!("native renderer smoke failed: {error}"))?;
        } else {
            window.update_with_buffer(&pixels, 2, 2)?;
        }
        window.update();
        eprintln!("OpenStream renderer smoke passed");
        return Ok(());
    }
    // Always on. A frame the window never sees leaves no span sample -- it
    // has no end stamp -- so a client discarding half its decoder output
    // shows a perfectly healthy decode-to-present distribution. These
    // counters are the only record that the discards happened, and a record
    // that has to be switched on is one that will be missing when it
    // matters.
    let telemetry: SharedTelemetry = Arc::new(Mutex::new(ClientTelemetry::new(
        probe_origin_from_environment(),
    )));
    let worker = thread::Builder::new()
        .name("openstream-network".to_string())
        .spawn({
            let telemetry = Arc::clone(&telemetry);
            move || run_worker(ui_tx, input_rx, telemetry)
        })?;
    window.set_target_fps(120);
    let hotkeys = display::Hotkey::from_env();
    let mut last_hotkey: Option<display::HotkeyAction> = None;
    let mut buffer = vec![0_u32; DEFAULT_WIDTH * DEFAULT_HEIGHT];
    let mut buffer_width = DEFAULT_WIDTH;
    let mut buffer_height = DEFAULT_HEIGHT;
    // Built on the first GPU-resident frame from the presenter's own device,
    // then reused: the texture cache inside it is what keeps repeat imports
    // cheap.
    #[cfg(target_os = "macos")]
    let mut texture_importer: Option<vt_gpu::MetalTextureImporter> = None;
    let immersive_requested = env::var("OPENSTREAM_IMMERSIVE").as_deref() == Ok("1");
    let mut input_state = InputState {
        last_mouse: None,
        last_window_mouse: None,
        button_state: [false; 3],
        gamepads: None,
        gamepad_ids: HashMap::new(),
        rumble_effects: HashMap::new(),
        immersive: immersive_requested,
        raw_pointer: if immersive_requested {
            raw_pointer::RawPointer::capture()
        } else {
            // Not immersive: leave the cursor associated with the device.
            raw_pointer::RawPointer::inactive()
        },
    };
    if immersive_requested {
        // Which path is running decides whether a turn can continue past the
        // window edge, so it is worth saying out loud rather than leaving the
        // operator to infer it from behaviour.
        println!(
            "OpenStream run pointer={}",
            if input_state.raw_pointer.is_active() {
                "raw device capture"
            } else {
                "relative from window position (stops at the window edge)"
            }
        );
    }
    // Optional pixel-level diagnostic; off unless the operator asks for it.
    let mut frame_dump = FrameDump::from_env();
    let mut connected = false;
    let mut base_title = String::from("OpenStream");
    let mut displays = Vec::<RemoteDisplay>::new();
    let mut selected_display = None;
    let mut pacer = render::FramePacer::new(60);
    input_state.gamepads = match Gilrs::new() {
        Ok(gamepads) => Some(gamepads),
        Err(error) => {
            eprintln!("OpenStream gamepad input unavailable: {error}");
            None
        }
    };

    // Set when the network worker has returned for good, which is the only
    // thing that drops its `UiSender`. Reconnects happen inside the worker, so
    // this is a terminal end of session, not a gap between two of them.
    let mut worker_finished = false;
    while window.is_open() && !window.is_key_down(Key::Escape) && !worker_finished {
        loop {
            match ui_rx.try_recv() {
                Ok(UiMessage::Ready {
                    width,
                    height,
                    fps,
                    path,
                    audio,
                    input,
                }) => {
                    connected = true;
                    // Only now may key transitions reach the host.
                    keyboard_connected.store(true, Ordering::Relaxed);
                    base_title = format!(
                        "{width}x{height} @ {fps}fps -- {path:?} -- audio={audio} input={input}"
                    );
                    window.set_title(&format!("OpenStream -- {base_title}"));
                }
                Ok(UiMessage::Frame(frame)) => {
                    let consumed_at = Stamp::<ClientClock>::now();
                    let seq = frame.seq();
                    let decoded_at = frame.decoded_at();
                    let width = frame.width();
                    let height = frame.height();
                    let marker = with_telemetry(&telemetry, |client| {
                        client.frames.ui_queue_consumed(&frame, consumed_at);
                        // Read before the pixels move, so the frame that
                        // gets credited is the frame that was shown.
                        client.marker_in(&frame)
                    })
                    .flatten();
                    // A frame decoded straight into a GPU surface never had
                    // its pixels read back -- that readback is precisely what
                    // this path removes -- so it cannot fall back to the CPU
                    // branch below: `pixels` is empty. It presents from the
                    // surface or it does not present at all.
                    #[cfg(target_os = "macos")]
                    if let Some(surface) = frame
                        .surface()
                        .and_then(FrameSurface::downcast_ref::<vt_decoder::SendPixelBuffer>)
                    {
                        // Same boundary as the CPU path: the stamp goes
                        // immediately before the presenter call, so the import
                        // and the draw are both inside the measured span.
                        let present_started = Stamp::<ClientClock>::now();
                        let presented = match native_presenter.as_mut() {
                            Some(presenter) => present_gpu_frame(
                                presenter,
                                &mut texture_importer,
                                &window,
                                surface,
                            ),
                            None => Err("no native presenter for a GPU-resident frame".to_string()),
                        };
                        if let Err(error) = presented {
                            // Drop the frame rather than present black, and
                            // turn the session back to CPU decoding. The
                            // decode worker reads this when it starts, so the
                            // next reconnect carries pixels again; until then
                            // the remaining surface frames are dropped, and
                            // they stay counted as consumed-but-not-submitted.
                            ZERO_COPY_PRESENT.store(false, Ordering::Relaxed);
                            texture_importer = None;
                            eprintln!(
                                "OpenStream zero-copy present failed: {error}; reverting to CPU frames"
                            );
                            continue;
                        }
                        let presented_at = Stamp::<ClientClock>::now();
                        record_frame_presented(
                            &telemetry,
                            seq,
                            decoded_at,
                            marker,
                            present_started,
                            presented_at,
                        );
                        continue;
                    }
                    // Malformed decoder output is dropped, never presented.
                    // It stays counted as consumed-and-replaced rather than
                    // vanishing: a decoder emitting garbage should show up
                    // as frames that never reached the presenter.
                    if render::validate_bgra_frame(width, height, frame.pixels()).is_err() {
                        continue;
                    }
                    buffer_width = width;
                    buffer_height = height;
                    buffer = frame.into_pixels();
                    if let Some(dump) = frame_dump.as_mut() {
                        dump.offer(width, height, &buffer);
                    }

                    // Everything below this stamp is the presenter's own
                    // time: texture upload, surface acquisition, or a
                    // software blit. Recording `present_submit` before the
                    // call excluded all of it, and counted a frame as
                    // submitted even when the call then failed.
                    let present_started = Stamp::<ClientClock>::now();
                    if let Some(presenter) = native_presenter.as_mut() {
                        if let Err(error) = presenter.present(&window, width, height, &buffer) {
                            eprintln!(
                                "OpenStream native renderer stopped: {error}; using software present"
                            );
                            native_presenter = None;
                            if let Err(error) = window.update_with_buffer(&buffer, width, height) {
                                let _ = input_tx.try_send(UiInput::Stop);
                                return Err(error.into());
                            }
                        }
                    } else if let Err(error) = window.update_with_buffer(&buffer, width, height) {
                        let _ = input_tx.try_send(UiInput::Stop);
                        return Err(error.into());
                    }
                    // Reached only when a presenter accepted the frame:
                    // both failure paths above return. Still not photon
                    // time -- the compositor's queueing, the swap and the
                    // panel are outside this process.
                    let presented_at = Stamp::<ClientClock>::now();
                    record_frame_presented(
                        &telemetry,
                        seq,
                        decoded_at,
                        marker,
                        present_started,
                        presented_at,
                    );
                }
                Ok(UiMessage::Error(error)) => {
                    connected = false;
                    // A decoder, transport, or protocol error can arrive
                    // while a key/button is held. Release before changing
                    // local state so the host never has to infer cleanup from
                    // a later reconnect or process exit.
                    let _ = input_tx.try_send(UiInput::Release);
                    input_state.last_mouse = None;
                    input_state.last_window_mouse = None;
                    input_state.button_state = [false; 3];
                    window.set_title(&format!("OpenStream -- error: {error}"));
                }
                Ok(UiMessage::Rumble {
                    device_id,
                    strong,
                    weak,
                }) => {
                    play_rumble(
                        &mut input_state.gamepads,
                        &input_state.gamepad_ids,
                        &mut input_state.rumble_effects,
                        device_id,
                        strong,
                        weak,
                    );
                }
                Ok(UiMessage::Displays(topology)) => {
                    selected_display = selected_display_index(&topology);
                    displays = topology;
                    let monitor = selected_display
                        .and_then(|index| displays.get(index))
                        .map_or_else(
                            || "monitor=?".to_string(),
                            |display| format!("monitor={}", display.id),
                        );
                    window.set_title(&format!("OpenStream -- {base_title} -- {monitor}"));
                }
                Ok(UiMessage::Reconnecting { attempt, delay_ms }) => {
                    // Everything the operator does during the backoff is
                    // discarded rather than queued: a key pressed now is
                    // not a key pressed in the session that comes back.
                    connected = false;
                    let _ = input_tx.try_send(UiInput::Release);
                    input_state.last_mouse = None;
                    input_state.last_window_mouse = None;
                    input_state.button_state = [false; 3];
                    let seconds = delay_ms as f64 / 1000.0;
                    window.set_title(&format!(
                        "OpenStream -- reconnecting in {seconds:.0}s (attempt {attempt})"
                    ));
                }
                Ok(UiMessage::End) => {
                    connected = false;
                    let _ = input_tx.try_send(UiInput::Release);
                    input_state.last_mouse = None;
                    input_state.last_window_mouse = None;
                    input_state.button_state = [false; 3];
                    window.set_title("OpenStream -- disconnected");
                }
                Ok(UiMessage::Metrics(line)) => {
                    if connected {
                        window.set_title(&format!("OpenStream -- {base_title} -- {line}"));
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    connected = false;
                    let _ = input_tx.try_send(UiInput::Release);
                    input_state.last_mouse = None;
                    input_state.last_window_mouse = None;
                    input_state.button_state = [false; 3];
                    // The worker is gone and will not come back: it owns the
                    // reconnect loop, so there is nothing left to wait for.
                    // Leaving the window up here left a dead picture on screen
                    // and a process that only a kill could end -- which is also
                    // what the shell that launched it would be waiting on.
                    // Critical messages and the newest frame are both drained
                    // ahead of this lane, so nothing is dropped by leaving now.
                    worker_finished = true;
                    break;
                }
            }
        }

        // Keep the last decoded frame visible while the network worker waits
        // for the next access unit. The buffer is bounded by the negotiated
        // dimensions, and a malformed size is ignored rather than panicking.
        // Re-presents are paced so an idle stream does not spin the GPU.
        if buffer.len() == buffer_width.saturating_mul(buffer_height)
            && pacer.should_present(std::time::Instant::now())
            && native_presenter.is_none()
        {
            window.update_with_buffer(&buffer, buffer_width, buffer_height)?;
        }
        // Capture is held only while the session is live and the window has
        // focus. Keying it on both is what stops a window left open after a
        // disconnect from keeping the pointer hidden, and it must run outside
        // the connected branch below, which stops being entered at exactly
        // the moment the capture needs releasing.
        let focused = window.is_active();
        input_state.raw_pointer.follow_focus(connected && focused);
        if !connected {
            keyboard_connected.store(false, Ordering::Relaxed);
        }
        if connected {
            forward_input(
                &window,
                focused,
                &input_tx,
                (buffer_width, buffer_height),
                // A GPU present stretches to the surface; only the software
                // path can letterbox, and only in a mode that asks it to.
                native_presenter.is_none() && display_mode.preserves_aspect_ratio(),
                &mut input_state,
            );
        }
        // Window hotkeys (default Ctrl+Alt+End to disconnect, Ctrl+Alt+Home
        // to release input, and Ctrl+Alt+PageUp/PageDown to select a monitor)
        // fire once per press; fullscreen itself is a startup-only mode via
        // OPENSTREAM_DISPLAY_MODE.
        match display::poll_hotkey(&window, &hotkeys, &mut last_hotkey) {
            Some(display::HotkeyAction::Disconnect) => break,
            Some(display::HotkeyAction::ReleaseInput) => {
                let _ = input_tx.try_send(UiInput::Release);
            }
            Some(
                action @ (display::HotkeyAction::NextDisplay
                | display::HotkeyAction::PreviousDisplay),
            ) => {
                let forward = matches!(action, display::HotkeyAction::NextDisplay);
                if let Some((index, id)) = cycled_display(&displays, selected_display, forward)
                    && input_tx.try_send(UiInput::SelectDisplay(id)).is_ok()
                {
                    selected_display = Some(index);
                    window.set_title(&format!(
                        "OpenStream -- {base_title} -- monitor={id} (pending)"
                    ));
                }
            }
            None => {}
        }
        window.update();
    }
    let _ = input_tx.try_send(UiInput::Release);
    let _ = input_tx.try_send(UiInput::Stop);
    for effect in input_state.rumble_effects.values() {
        let _ = effect.stop();
    }
    let _ = worker.join();
    Ok(())
}

/// Pick the next or previous announced output with wrap-around. Selection is
/// deliberately computed from the topology received from the host; no local
/// numeric assumption can target an output the host did not publish.
fn cycled_display(
    displays: &[RemoteDisplay],
    selected: Option<usize>,
    forward: bool,
) -> Option<(usize, u32)> {
    if displays.is_empty() {
        return None;
    }
    let current = selected.unwrap_or(0).min(displays.len() - 1);
    let index = if forward {
        (current + 1) % displays.len()
    } else if current == 0 {
        displays.len() - 1
    } else {
        current - 1
    };
    Some((index, displays[index].id))
}

fn selected_display_index(displays: &[RemoteDisplay]) -> Option<usize> {
    displays
        .iter()
        .position(|display| display.selected())
        .or_else(|| displays.iter().position(|display| display.primary()))
        .or_else(|| (!displays.is_empty()).then_some(0))
}

#[allow(clippy::cast_possible_truncation)]
/// Where the streamed picture actually sits inside the window, in window
/// pixels.
///
/// The window and the picture are not the same rectangle whenever the
/// presentation preserves the stream's aspect ratio: the picture is centred
/// and the remaining area is background. Renderer and pointer have to agree
/// on this rectangle or the cursor is wrong by the size of the bars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PresentedRect {
    x: usize,
    y: usize,
    width: usize,
    height: usize,
}

/// Diagnostic capture of decoded frames, enabled by `OPENSTREAM_DUMP_FRAMES`.
///
/// Presenting is the last point where this process still owns the picture as
/// pixels. Counters can report a frame as presented while the window shows
/// nothing, so "the screen is blank" cannot be settled from telemetry alone.
/// Writing the pixels here separates "the decoder produced a picture" from
/// "the window displayed it", which is the split that tells a capture or
/// encode fault apart from a presentation fault.
///
/// Frames are written as binary PPM: no image encoder is needed and every
/// common image tool reads it.
#[derive(Debug)]
struct FrameDump {
    directory: PathBuf,
    every: u64,
    limit: u64,
    seen: u64,
    written: u64,
}

impl FrameDump {
    /// `OPENSTREAM_DUMP_FRAMES` names the destination directory and turns the
    /// capture on. `OPENSTREAM_DUMP_FRAME_EVERY` keeps one frame in N
    /// (default 30) and `OPENSTREAM_DUMP_FRAME_LIMIT` caps how many are
    /// written (default 8), so a long session cannot fill the disk.
    fn from_env() -> Option<Self> {
        let directory = PathBuf::from(env::var("OPENSTREAM_DUMP_FRAMES").ok()?);
        if let Err(error) = std::fs::create_dir_all(&directory) {
            eprintln!(
                "OpenStream frame dump disabled: {} is not usable: {error}",
                directory.display()
            );
            return None;
        }
        Some(Self {
            directory,
            every: env_u64("OPENSTREAM_DUMP_FRAME_EVERY", 30).max(1),
            limit: env_u64("OPENSTREAM_DUMP_FRAME_LIMIT", 8),
            seen: 0,
            written: 0,
        })
    }

    /// Offer one frame that passed validation and is about to be presented.
    /// Sampling and the write both happen on the UI thread, which is why the
    /// default cadence is coarse: this is a diagnostic, not a recorder.
    fn offer(&mut self, width: usize, height: usize, pixels: &[u32]) {
        let index = self.seen;
        self.seen += 1;
        if self.written >= self.limit || index % self.every != 0 {
            return;
        }
        let path = self.directory.join(format!("frame-{index:06}.ppm"));
        match Self::write_ppm(&path, width, height, pixels) {
            Ok(()) => {
                self.written += 1;
                println!(
                    "OpenStream dumped frame {index} ({width}x{height}) to {}",
                    path.display()
                );
            }
            Err(error) => {
                // One failed write means the destination is not usable.
                // Stop rather than repeat the same error every frame.
                eprintln!("OpenStream frame dump stopped: {error}");
                self.limit = 0;
            }
        }
    }

    fn write_ppm(
        path: &std::path::Path,
        width: usize,
        height: usize,
        pixels: &[u32],
    ) -> io::Result<()> {
        let mut out = Vec::with_capacity(32 + pixels.len() * 3);
        out.extend_from_slice(format!("P6\n{width} {height}\n255\n").as_bytes());
        for pixel in pixels {
            // The decoder packs BGRA bytes into a little-endian word, so the
            // native byte order is already blue, green, red, alpha.
            let [blue, green, red, _alpha] = pixel.to_le_bytes();
            out.push(red);
            out.push(green);
            out.push(blue);
        }
        std::fs::write(path, out)
    }
}

/// Read a non-negative integer from the environment, falling back when the
/// variable is absent or does not parse.
fn env_u64(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

/// Compute the rectangle the picture occupies.
///
/// A stretching presentation fills the window. An aspect-preserving one
/// scales until one axis is full and centres the result, which is what
/// minifb's `ScaleMode::AspectRatioStretch` does and what an
/// aspect-correct GPU present would do.
fn presented_rect(
    window: (usize, usize),
    stream: (usize, usize),
    preserve_aspect: bool,
) -> PresentedRect {
    let (window_width, window_height) = window;
    let (stream_width, stream_height) = stream;
    if !preserve_aspect
        || window_width == 0
        || window_height == 0
        || stream_width == 0
        || stream_height == 0
    {
        return PresentedRect {
            x: 0,
            y: 0,
            width: window_width,
            height: window_height,
        };
    }

    // Scale by whichever axis runs out first, in integers so the rectangle
    // lands on real pixels.
    let by_width = window_width * stream_height;
    let by_height = window_height * stream_width;
    let (width, height) = if by_width <= by_height {
        // Width-limited: bars above and below.
        (window_width, (window_width * stream_height) / stream_width)
    } else {
        // Height-limited: bars left and right.
        (
            (window_height * stream_width) / stream_height,
            window_height,
        )
    };
    let width = width.min(window_width);
    let height = height.min(window_height);
    PresentedRect {
        x: (window_width - width) / 2,
        y: (window_height - height) / 2,
        width,
        height,
    }
}

/// Map a pointer position in window pixels onto the streamed image.
///
/// The host places absolute coordinates by scaling them out of the streamed
/// image's own pixel space and into wherever that image sits on its desktop,
/// so the client has to answer in that space -- not the window's, which is
/// whatever size the operator dragged it to, and not counting any
/// letterbox bars, which are not part of the picture at all.
fn stream_pointer_position(
    presented: PresentedRect,
    stream: (usize, usize),
    pointer: (f32, f32),
) -> (i32, i32) {
    let map = |value: f32, origin: usize, extent: usize, stream: usize| -> i32 {
        if extent == 0 || stream == 0 {
            return 0;
        }
        // A pointer over a bar is outside the picture; clamp it to the
        // nearest edge rather than reporting a position the picture does
        // not have.
        let within = f64::from(value) - origin as f64;
        let ratio = (within / extent as f64).clamp(0.0, 1.0);
        let scaled = ratio * stream as f64;
        // The last pixel is a valid position; one past it is not.
        let limit = (stream - 1) as f64;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "clamped to [0, stream - 1], and a frame dimension fits an i32"
        )]
        {
            scaled.clamp(0.0, limit).round() as i32
        }
    };
    (
        map(pointer.0, presented.x, presented.width, stream.0),
        map(pointer.1, presented.y, presented.height, stream.1),
    )
}

/// Everything `forward_input` carries between calls.
struct InputState {
    /// Last position sent, in streamed-image pixels, so an unmoved pointer
    /// is not resent every frame.
    last_mouse: Option<(i32, i32)>,
    /// Last window-space sample used by the compatibility immersive path.
    /// minifb does not expose a raw `DeviceEvent`; when immersive mode is
    /// requested we still send relative deltas and coalesce them at the
    /// bounded input boundary. The native winit runner can replace this with
    /// true device motion without changing the wire event.
    last_window_mouse: Option<(f32, f32)>,
    button_state: [bool; 3],
    gamepads: Option<Gilrs>,
    gamepad_ids: HashMap<u32, GamepadId>,
    rumble_effects: HashMap<u32, Effect>,
    immersive: bool,
    /// Held only in immersive mode, and only where the platform supports it.
    /// When it is active the window-position path above is not used at all.
    raw_pointer: raw_pointer::RawPointer,
}

fn forward_input(
    window: &Window,
    focused: bool,
    input_tx: &InputSender,
    stream: (usize, usize),
    preserve_aspect: bool,
    state: &mut InputState,
) {
    if !focused {
        // Drop the reference sample. Keeping it would turn the gap between
        // leaving the window and returning to it into one large relative
        // jump the user never made.
        state.last_window_mouse = None;
    }

    // Strictly increasing, because the host orders pointer motion by this
    // and equal stamps would leave it breaking ties.
    let timestamp = monotonic_input_stamp();
    // A held capture reports device motion whether or not the cursor is over
    // the window -- it is deliberately not over the window, since capture
    // decouples the two. Reading it must not be gated on a window-relative
    // position, or the deltas the capture exists to deliver would be dropped
    // exactly when they start arriving.
    if let Some((dx, dy)) = state.raw_pointer.delta() {
        if dx != 0 || dy != 0 {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_motion(
                true, dx, dy, timestamp,
            )));
        }
    } else if let Some((x, y)) = window.get_mouse_pos(MouseMode::Clamp) {
        if state.immersive {
            // Compatibility relative path: window positions are clamped, so
            // this stops producing motion at an edge. It is what runs where
            // the platform cannot capture the device.
            if let Some((last_x, last_y)) = state.last_window_mouse {
                #[allow(clippy::cast_possible_truncation)]
                let dx = (x - last_x).round() as i32;
                #[allow(clippy::cast_possible_truncation)]
                let dy = (y - last_y).round() as i32;
                if dx != 0 || dy != 0 {
                    let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_motion(
                        true, dx, dy, timestamp,
                    )));
                }
            }
            state.last_window_mouse = Some((x, y));
        } else {
            let presented = presented_rect(window.get_size(), stream, preserve_aspect);
            let current = stream_pointer_position(presented, stream, (x, y));
            if state.last_mouse != Some(current) {
                let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_motion(
                    false, current.0, current.1, timestamp,
                )));
            }
            state.last_mouse = Some(current);
        }
    }

    for (index, button) in [MouseButton::Left, MouseButton::Middle, MouseButton::Right]
        .into_iter()
        .enumerate()
    {
        let pressed = window.get_mouse_down(button);
        if pressed != state.button_state[index] {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_button(
                u32::try_from(index + 1).unwrap_or(1),
                pressed,
                timestamp,
            )));
            state.button_state[index] = pressed;
        }
    }

    if let Some((x, y)) = window.get_scroll_wheel() {
        #[allow(clippy::cast_possible_truncation)]
        let x = x.round() as i32;
        #[allow(clippy::cast_possible_truncation)]
        let y = y.round() as i32;
        if x != 0 || y != 0 {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::wheel(x, y, timestamp)));
        }
    }

    poll_gamepads(
        &mut state.gamepads,
        input_tx,
        timestamp,
        &mut state.gamepad_ids,
        &mut state.rumble_effects,
    );
}

fn poll_gamepads(
    gamepads: &mut Option<Gilrs>,
    input_tx: &InputSender,
    timestamp: u64,
    gamepad_ids: &mut HashMap<u32, GamepadId>,
    rumble_effects: &mut HashMap<u32, Effect>,
) {
    let Some(gamepads) = gamepads.as_mut() else {
        return;
    };
    while let Some(event) = gamepads.next_event() {
        let Ok(device_id) = u32::try_from(usize::from(event.id)) else {
            continue;
        };
        gamepad_ids.insert(device_id, event.id);
        match event.event {
            EventType::ButtonPressed(button, _) => {
                if let Some(index) = gamepad_button_index(button) {
                    let _ = input_tx.try_send(UiInput::Event(InputEvent::gamepad_button(
                        device_id, index, true, timestamp,
                    )));
                }
            }
            EventType::ButtonReleased(button, _) => {
                if let Some(index) = gamepad_button_index(button) {
                    let _ = input_tx.try_send(UiInput::Event(InputEvent::gamepad_button(
                        device_id, index, false, timestamp,
                    )));
                }
            }
            EventType::ButtonChanged(button, value, _) => {
                let axis = match button {
                    Button::LeftTrigger2 => Some(4),
                    Button::RightTrigger2 => Some(5),
                    _ => None,
                };
                if let Some(axis) = axis {
                    let _ = input_tx.try_send(UiInput::Event(InputEvent::gamepad_axis(
                        device_id,
                        axis,
                        axis_value(value),
                        timestamp,
                    )));
                }
            }
            EventType::AxisChanged(axis, value, _) => {
                if let Some(axis) = gamepad_axis_index(axis) {
                    let _ = input_tx.try_send(UiInput::Event(InputEvent::gamepad_axis(
                        device_id,
                        axis,
                        axis_value(value),
                        timestamp,
                    )));
                }
            }
            EventType::Disconnected => {
                if let Some(effect) = rumble_effects.remove(&device_id) {
                    let _ = effect.stop();
                }
                gamepad_ids.remove(&device_id);
                let _ = input_tx.try_send(UiInput::Event(InputEvent::gamepad_unplug(
                    device_id, timestamp,
                )));
            }
            EventType::ButtonRepeated(_, _)
            | EventType::Connected
            | EventType::Dropped
            | EventType::ForceFeedbackEffectCompleted => {}
            _ => {}
        }
    }
}

/// Apply one short host rumble update to the corresponding local controller.
///
/// The remote device identifier is the identifier the desktop client emitted
/// in its input envelope. It is mapped to the local Gilrs identifier when the
/// first controller event arrives; unknown or disconnected devices are
/// ignored instead of vibrating an unrelated controller.
fn play_rumble(
    gamepads: &mut Option<Gilrs>,
    gamepad_ids: &HashMap<u32, GamepadId>,
    rumble_effects: &mut HashMap<u32, Effect>,
    device_id: u32,
    strong: u8,
    weak: u8,
) {
    if let Some(previous) = rumble_effects.remove(&device_id) {
        let _ = previous.stop();
    }
    if strong == 0 && weak == 0 {
        return;
    }
    let Some(gilrs) = gamepads.as_mut() else {
        return;
    };
    let Some(&local_id) = gamepad_ids.get(&device_id) else {
        return;
    };
    let supported = gilrs
        .connected_gamepad(local_id)
        .is_some_and(|gamepad| gamepad.is_ff_supported());
    if !supported {
        return;
    }

    let duration = Ticks::from_ms(120);
    let scheduling = Replay {
        play_for: duration,
        ..Default::default()
    };
    let mut builder = EffectBuilder::new();
    if strong != 0 {
        builder.add_effect(BaseEffect {
            kind: BaseEffectType::Strong {
                magnitude: u16::from(strong) * 257,
            },
            scheduling,
            envelope: Default::default(),
        });
    }
    if weak != 0 {
        builder.add_effect(BaseEffect {
            kind: BaseEffectType::Weak {
                magnitude: u16::from(weak) * 257,
            },
            scheduling,
            envelope: Default::default(),
        });
    }
    builder.repeat(Repeat::For(duration)).gamepads(&[local_id]);
    if let Ok(effect) = builder.finish(gilrs) {
        let _ = effect.play();
        rumble_effects.insert(device_id, effect);
    }
}

fn gamepad_button_index(button: Button) -> Option<u32> {
    match button {
        Button::South => Some(0),
        Button::East => Some(1),
        Button::North => Some(2),
        Button::West => Some(3),
        Button::Select => Some(4),
        Button::Mode => Some(5),
        Button::Start => Some(6),
        Button::LeftThumb => Some(7),
        Button::RightThumb => Some(8),
        Button::LeftTrigger => Some(9),
        Button::RightTrigger => Some(10),
        Button::DPadUp => Some(11),
        Button::DPadDown => Some(12),
        Button::DPadLeft => Some(13),
        Button::DPadRight => Some(14),
        Button::C | Button::Z | Button::LeftTrigger2 | Button::RightTrigger2 | Button::Unknown => {
            None
        }
    }
}

fn gamepad_axis_index(axis: Axis) -> Option<u32> {
    match axis {
        Axis::LeftStickX => Some(0),
        Axis::LeftStickY => Some(1),
        Axis::RightStickX => Some(2),
        Axis::RightStickY => Some(3),
        Axis::LeftZ => Some(4),
        Axis::RightZ => Some(5),
        Axis::DPadX | Axis::DPadY | Axis::Unknown => None,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn axis_value(value: f32) -> i32 {
    (value.clamp(-1.0, 1.0) * 32_767.0).round() as i32
}

/// Map minifb's platform-neutral key enum to USB HID keyboard usages.
///
/// HID usages are stable across Windows, Linux, and macOS, so the host never
/// needs to know which desktop window backend generated the event. Unknown
/// keys are intentionally omitted instead of sending a platform-specific
/// scan-code guess.
/// Event-driven keyboard forwarding.
///
/// The frame loop samples key state once per presented frame. A press and its
/// release that both land between two samples collapse into no observed
/// change, so keystrokes shorter than a frame interval were dropped outright
/// -- at 45 fps that is any press under about 22 ms, which ordinary fast
/// typing produces. Measured on the acceptance rig: holding each key 200 ms
/// delivered 13 of 13, and holding 30 ms delivered 3.
///
/// minifb reports every transition here as the platform delivers it, so
/// delivery no longer depends on when the frame loop next looks.
struct KeyboardEvents {
    input_tx: InputSender,
    /// Nothing is forwarded before the session is up, so keys pressed while
    /// the window is still connecting are not replayed into the host.
    connected: Arc<AtomicBool>,
}

impl fmt::Debug for KeyboardEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyboardEvents").finish_non_exhaustive()
    }
}

impl minifb::InputCallback for KeyboardEvents {
    /// Text input is not forwarded: the host is sent HID usages and applies
    /// its own layout, so a translated character here would arrive twice.
    fn add_char(&mut self, _uni_char: u32) {}

    fn set_key_state(&mut self, key: Key, state: bool) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }
        let Some(usage) = usage_for_key(key) else {
            return;
        };
        let _ = self.input_tx.try_send(UiInput::Event(InputEvent::keyboard(
            usage,
            0,
            state,
            monotonic_input_stamp(),
        )));
    }
}

/// HID usage for a window key, or `None` for keys this client does not map.
fn usage_for_key(key: Key) -> Option<u32> {
    keyboard_usages()
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, usage)| *usage)
}

fn keyboard_usages() -> &'static [(Key, u32)] {
    &[
        (Key::Key0, 0x27),
        (Key::Key1, 0x1e),
        (Key::Key2, 0x1f),
        (Key::Key3, 0x20),
        (Key::Key4, 0x21),
        (Key::Key5, 0x22),
        (Key::Key6, 0x23),
        (Key::Key7, 0x24),
        (Key::Key8, 0x25),
        (Key::Key9, 0x26),
        (Key::A, 0x04),
        (Key::B, 0x05),
        (Key::C, 0x06),
        (Key::D, 0x07),
        (Key::E, 0x08),
        (Key::F, 0x09),
        (Key::G, 0x0a),
        (Key::H, 0x0b),
        (Key::I, 0x0c),
        (Key::J, 0x0d),
        (Key::K, 0x0e),
        (Key::L, 0x0f),
        (Key::M, 0x10),
        (Key::N, 0x11),
        (Key::O, 0x12),
        (Key::P, 0x13),
        (Key::Q, 0x14),
        (Key::R, 0x15),
        (Key::S, 0x16),
        (Key::T, 0x17),
        (Key::U, 0x18),
        (Key::V, 0x19),
        (Key::W, 0x1a),
        (Key::X, 0x1b),
        (Key::Y, 0x1c),
        (Key::Z, 0x1d),
        (Key::F1, 0x3a),
        (Key::F2, 0x3b),
        (Key::F3, 0x3c),
        (Key::F4, 0x3d),
        (Key::F5, 0x3e),
        (Key::F6, 0x3f),
        (Key::F7, 0x40),
        (Key::F8, 0x41),
        (Key::F9, 0x42),
        (Key::F10, 0x43),
        (Key::F11, 0x44),
        (Key::F12, 0x45),
        (Key::F13, 0x68),
        (Key::F14, 0x69),
        (Key::F15, 0x6a),
        (Key::Down, 0x51),
        (Key::Left, 0x50),
        (Key::Right, 0x4f),
        (Key::Up, 0x52),
        (Key::Apostrophe, 0x34),
        (Key::Backquote, 0x35),
        (Key::Backslash, 0x31),
        (Key::Comma, 0x36),
        (Key::Equal, 0x2e),
        (Key::LeftBracket, 0x2f),
        (Key::Minus, 0x2d),
        (Key::Period, 0x37),
        (Key::RightBracket, 0x30),
        (Key::Semicolon, 0x33),
        (Key::Slash, 0x38),
        (Key::Backspace, 0x2a),
        (Key::Delete, 0x4c),
        (Key::End, 0x4d),
        (Key::Enter, 0x28),
        (Key::Escape, 0x29),
        (Key::Home, 0x4a),
        (Key::Insert, 0x49),
        (Key::Menu, 0x65),
        (Key::PageDown, 0x4e),
        (Key::PageUp, 0x4b),
        (Key::Pause, 0x48),
        (Key::Space, 0x2c),
        (Key::Tab, 0x2b),
        (Key::NumLock, 0x53),
        (Key::CapsLock, 0x39),
        (Key::ScrollLock, 0x47),
        (Key::LeftShift, 0xe1),
        (Key::RightShift, 0xe5),
        (Key::LeftCtrl, 0xe0),
        (Key::RightCtrl, 0xe4),
        (Key::NumPad0, 0x62),
        (Key::NumPad1, 0x59),
        (Key::NumPad2, 0x5a),
        (Key::NumPad3, 0x5b),
        (Key::NumPad4, 0x5c),
        (Key::NumPad5, 0x5d),
        (Key::NumPad6, 0x5e),
        (Key::NumPad7, 0x5f),
        (Key::NumPad8, 0x60),
        (Key::NumPad9, 0x61),
        (Key::NumPadDot, 0x63),
        (Key::NumPadSlash, 0x54),
        (Key::NumPadAsterisk, 0x55),
        (Key::NumPadMinus, 0x56),
        (Key::NumPadPlus, 0x57),
        (Key::NumPadEnter, 0x58),
        (Key::LeftAlt, 0xe2),
        (Key::RightAlt, 0xe6),
        (Key::LeftSuper, 0xe3),
        (Key::RightSuper, 0xe7),
    ]
}

fn run_worker(ui_tx: UiSender, input_rx: InputReceiver, telemetry: SharedTelemetry) {
    let _ = write_session_status("starting", None, None);
    let result = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(network_loop(ui_tx.clone(), input_rx, telemetry)),
        Err(error) => Err(error.to_string().into()),
    };
    if let Err(error) = result {
        let _ = ui_tx.send(UiMessage::Error(error.to_string()));
    }
    let _ = write_session_status("stopped", None, None);
    let _ = ui_tx.send(UiMessage::End);
}

/// Secret-free lifecycle status consumed by the desktop product shell.
///
/// The session runner is intentionally a separate process from Tauri. The
/// shell therefore needs one small, private observation channel to know
/// whether the process is still negotiating or has reached an authenticated
/// session. This file contains only a state label, the non-secret session id,
/// and a path generation; it never contains pairing tokens, keys, or media.
fn write_session_status(
    state: &str,
    session_id: Option<&str>,
    generation: Option<u64>,
) -> io::Result<()> {
    let Some(path) = env::var_os("OPENSTREAM_SESSION_STATUS_FILE").map(PathBuf::from) else {
        return Ok(());
    };
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.to_string_lossy().len() > 4096
        || state.is_empty()
        || state.len() > 32
        || state.chars().any(char::is_control)
        || session_id.is_some_and(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session status path or value is invalid",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "session status has no parent")
    })?;
    validate_session_status_path(&path, parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("session-status"),
        std::process::id()
    ));
    let json = serde_json::json!({
        "state": state,
        "session_id": session_id,
        "generation": generation,
    });
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        serde_json::to_writer(&mut file, &json)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        replace_session_status(&temporary, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// The status file is a control-plane observation, not a writable IPC
/// endpoint. Keep it inside the private runtime directory and reject a
/// symlink/reparse point before the atomic replace. The supervisor repeats
/// these checks while reading, so a malformed or replaced file fails closed.
fn validate_session_status_path(
    path: &std::path::Path,
    parent: &std::path::Path,
) -> io::Result<()> {
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "session status parent is not a private directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "session status parent is a reparse point",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if parent_metadata.uid() != unsafe { libc::geteuid() }
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "session status parent is not private",
            ));
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "session status destination is not a regular file",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "session status destination is a reparse point",
                ));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "session status destination is not private",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn replace_session_status(
    temporary: &std::path::Path,
    destination: &std::path::Path,
) -> io::Result<()> {
    std::fs::rename(temporary, destination)
}

#[cfg(not(unix))]
fn replace_session_status(
    temporary: &std::path::Path,
    destination: &std::path::Path,
) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
        };
        let temporary_wide = windows_wide_path(temporary)?;
        let destination_wide = windows_wide_path(destination)?;
        let replaced = unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                temporary_wide.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if replaced != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(2 | 3)) {
            return Err(error);
        }
        let created = unsafe {
            MoveFileExW(
                temporary_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if created != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(temporary, destination)
    }
}

#[cfg(windows)]
fn windows_wide_path(path: &std::path::Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Default reconnect budget. Bounded so an unreachable host eventually
/// surfaces an error instead of retrying forever behind a blank window.
const DEFAULT_RECONNECT_ATTEMPTS: u32 = 5;

/// How long a negotiated session must survive before its predecessor's
/// failures are forgiven.
///
/// Resetting the moment a session negotiates would be wrong in the other
/// direction: a peer that accepts the handshake and drops immediately would
/// refresh the budget on every attempt and retry at the floor delay
/// forever. A session that negotiated and then stayed up this long has
/// demonstrably made progress.
const HEALTHY_SESSION: Duration = Duration::from_secs(30);

/// An error that retrying cannot fix.
///
/// A missing pairing file, an unparseable environment variable, an absent
/// FFmpeg binary, or a negotiated frame too large to decode will fail
/// identically on every attempt. Retrying them costs the operator the whole
/// 1 + 2 + 4 + 8 + 16 second schedule before the real problem is printed.
#[derive(Debug)]
struct TerminalError(Box<dyn std::error::Error + Send + Sync>);

impl TerminalError {
    fn new(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }
}

impl fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for TerminalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Whether an error from `network_session` is worth another attempt.
fn is_retryable(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    !error.is::<TerminalError>()
}

/// How far a session got before it ended. `network_session` records the
/// moment it finished negotiating, which is the earliest point at which the
/// peer has proved it can complete an authenticated exchange.
#[derive(Default)]
struct SessionProgress {
    negotiated_at: Option<Instant>,
}

impl SessionProgress {
    fn negotiated(&mut self) {
        self.negotiated_at = Some(Instant::now());
    }

    fn was_healthy(&self) -> bool {
        self.negotiated_at
            .is_some_and(|at| at.elapsed() >= HEALTHY_SESSION)
    }
}

/// Discard input queued while no session was draining it, and report
/// whether the operator asked to stop in the meantime.
///
/// Without this, keystrokes and clicks made during a backoff wait sit in
/// the bounded queue and are delivered in full to whichever session
/// connects next -- a key pressed and released before the drop arrives as
/// a press in a session the operator never typed into, and a held button
/// arrives with no matching release. Only the explicit stop survives.
fn discard_stale_input(input_rx: &mut InputReceiver) -> bool {
    let mut stop_requested = false;
    while let Ok(input) = input_rx.try_recv() {
        if matches!(input, UiInput::Stop) {
            stop_requested = true;
        }
    }
    stop_requested
}

/// Supervise the session. A transport error used to end the process, because
/// the backoff schedule in `openstream-media` had no caller. Retry a bounded
/// number of times instead, and reset the budget after a session that actually
/// negotiated and stayed up, so a long-lived connection does not inherit old
/// failures.
async fn network_loop(
    ui_tx: UiSender,
    mut input_rx: InputReceiver,
    telemetry: SharedTelemetry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let max_attempts = match env::var("OPENSTREAM_RECONNECT_ATTEMPTS") {
        Ok(value) if value.eq_ignore_ascii_case("unlimited") => None,
        Ok(value) => Some(value.parse::<u32>().map_err(|error| {
            format!("OPENSTREAM_RECONNECT_ATTEMPTS must be a number or 'unlimited': {error}")
        })?),
        Err(_) => Some(DEFAULT_RECONNECT_ATTEMPTS),
    };
    let mut supervisor = ReconnectSupervisor::new(max_attempts);
    loop {
        let mut progress = SessionProgress::default();
        let outcome = network_session(&ui_tx, &mut input_rx, &mut progress, &telemetry).await;
        // Frames the window had taken but not yet submitted are gone with
        // the session, and are counted as never shown rather than left
        // pending across the reconnect.
        //
        // The counters themselves run for the life of the process, not per
        // session: a run that reconnected four times is one measurement of
        // this client, and resetting would hide the losses that happened
        // around each drop -- which is where they cluster.
        with_telemetry(&telemetry, |client| {
            client.session_ended();
            for line in client.report(Stamp::now()) {
                eprintln!("OpenStream telemetry {line}");
            }
        });
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                if !is_retryable(error.as_ref()) {
                    return Err(error);
                }
                // A session that negotiated and then ran is evidence the
                // configuration works; only consecutive failures count
                // against the budget.
                if progress.was_healthy() {
                    supervisor.reset();
                }
                let Some(delay) = supervisor.next_delay() else {
                    return Err(error);
                };
                let attempt = supervisor.attempts();
                eprintln!(
                    "OpenStream session ended ({error}); reconnecting in {:.0}s (attempt {attempt})",
                    delay.as_secs_f64(),
                );
                // Tell the window before sleeping. Nothing drains the input
                // queue while this task is parked, so the window has to stop
                // filling it.
                let _ = ui_tx.send(UiMessage::Reconnecting {
                    attempt,
                    delay_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                });
                tokio::time::sleep(delay).await;
                // Drop anything that was queued before the window saw the
                // message above, so the new session starts from a clean
                // input state.
                if discard_stale_input(&mut input_rx) {
                    return Ok(());
                }
            }
        }
    }
}

async fn network_session(
    ui_tx: &UiSender,
    input_rx: &mut InputReceiver,
    progress: &mut SessionProgress,
    telemetry: &SharedTelemetry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let origin = env::var("OPENSTREAM_SIGNAL_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    // Configuration faults are terminal: none of these produce a different
    // answer on a second attempt, so waiting out the backoff schedule only
    // delays showing the operator what is actually wrong.
    let pairing = load_pairing_from_environment().map_err(TerminalError::new)?;
    let _ = write_session_status("negotiating", Some(&pairing.session_id), None);
    let bind = env::var("OPENSTREAM_UDP_BIND")
        .unwrap_or_else(|_| "0.0.0.0:0".to_string())
        .parse::<SocketAddr>()
        .map_err(TerminalError::new)?;
    let stun_servers = match env::var("OPENSTREAM_STUN_SERVERS") {
        Ok(spec) => parse_stun_servers(&spec).map_err(TerminalError::new)?,
        Err(_) => Vec::new(),
    };
    let mut session =
        PeerSession::establish_configured(&origin, &pairing, Role::Client, bind, &stun_servers)
            .await?;
    let _ = write_session_status(
        "connected",
        Some(&pairing.session_id),
        Some(session.path_generation()),
    );
    let path = session.connection_path();
    let clipboard_policy = ClipboardPolicy::from_env();
    eprintln!("{}", clipboard_policy.log_line());
    let mut client_capabilities = Capabilities::client_default();
    client_capabilities.clipboard = (clipboard_policy.direction.may_send()
        || clipboard_policy.direction.may_receive())
        && platform_clipboard::available();
    // 10-bit and 4:4:4 decode through the FFmpeg BGRA path; advertise them
    // only when the operator opts in so default sessions stay 8-bit 4:2:0.
    client_capabilities.video_10_bit = env::var("OPENSTREAM_ALLOW_10BIT").as_deref() == Ok("1");
    client_capabilities.video_444 = env::var("OPENSTREAM_ALLOW_444").as_deref() == Ok("1");
    // The window exposes a bounded monitor picker (Ctrl+Alt+PageUp/PageDown)
    // once the host publishes its topology.
    client_capabilities.multi_monitor = true;
    // Microphone passthrough needs a configured capture device; the host
    // still applies its own take-microphone policy before unmuting.
    client_capabilities.microphone = mic::mic_configured();
    let negotiated = session
        .negotiate_client_with_capabilities(client_capabilities)
        .await?;
    let width = usize::from(negotiated.width.max(1));
    let height = usize::from(negotiated.height.max(1));
    let frame_bytes = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| TerminalError::new("negotiated frame dimensions overflow"))?;
    const MAX_DECODE_FRAME_BYTES: usize = 64 * 1024 * 1024;
    if frame_bytes > MAX_DECODE_FRAME_BYTES {
        return Err(TerminalError::new(format!(
            "negotiated decoded frame is too large ({frame_bytes} bytes; limit {MAX_DECODE_FRAME_BYTES})"
        ))
        .into());
    }
    // The peer completed an authenticated negotiation, which is the earliest
    // point at which this attempt counts as progress.
    progress.negotiated();
    let _ = ui_tx.send(UiMessage::Ready {
        width,
        height,
        fps: negotiated.fps,
        path,
        audio: negotiated.audio.is_some(),
        input: negotiated.input,
    });

    let format = match negotiated.video {
        VideoCodec::H264 => "h264",
        VideoCodec::H265 => "hevc",
    };
    // In-process native decode is opt-in for H.264 (`OPENSTREAM_DECODER=native`):
    // VideoToolbox on macOS, Media Foundation on Windows. Every other value, and
    // every other codec, uses the ffmpeg subprocess, which stays the default and
    // the universal fallback.
    let codec = if format == "h264" {
        decode_dispatch::DecodeCodec::H264
    } else {
        decode_dispatch::DecodeCodec::H265
    };
    let backend = decode_dispatch::select_decoder(
        codec,
        decode_dispatch::prefer_native_from_env(),
        &decode_dispatch::available_decoders(),
    );
    // A mailbox, not a queue (see the consumer below): the decoder outruns the
    // network loop whenever it is busy, and replace-oldest keeps only the
    // freshest picture. `Notify` supplies the wake `select!` needs.
    let (frame_tx, frame_rx) = latest_frame::<DecodedFrame>();
    let decoded_ready = Arc::new(tokio::sync::Notify::new());
    let mut session_decoder = build_session_decoder(
        backend,
        format,
        width,
        height,
        frame_bytes,
        frame_tx.clone(),
        Arc::clone(&decoded_ready),
        Arc::clone(telemetry),
    )?;

    let mut audio_player = spawn_audio_player()?;
    let mut audio_stdin = audio_player.as_mut().and_then(|child| child.stdin.take());
    let mut audio_decoder = opus_rs::OpusDecoder::new(48_000, lowlat_audio::CHANNELS)
        .map_err(|error| format!("could not create Opus decoder: {error}"))?;
    let mut audio_jitter = JitterBuffer::new(3);
    let mut audio_pcm = vec![0_f32; lowlat_audio::FRAME * lowlat_audio::CHANNELS];
    let mut last_audio_toc = None;

    let mut assembler = Assembler::default();
    // Timing stops at decoder submission: FFmpeg does not return the frame
    // id it was given, so nothing after that can be attributed to a host
    // frame. The stages past it report `not-observable`, and what actually
    // happens there is measured by decoded sequence number in `frame_age`.
    let observability = ClientObservability::ExternalDecoder;
    // Emitted with the stage table rather than supplied by hand afterwards.
    // The host half is left explicitly unstated: this side is told the
    // negotiated codec and size and nothing about how they were produced.
    for line in (RunContext {
        codec: format!("{:?}", negotiated.video),
        width: negotiated.width,
        height: negotiated.height,
        fps: negotiated.fps,
        path: format!("{:?}", session.connection_path()),
        profile: format!("{format}-low-delay"),
        decoder: Some(decoder_report(backend, format)),
        // The presenter is chosen in `main` and the window is not this
        // task's to inspect, so the backend it settled on is named there
        // and not guessed here.
        configured_presenter: Some(format!("{:?}", render::RenderBackend::from_env())),
        // minifb's software path does not expose whether the compositor
        // synchronised the update, and saying "off" would be a guess.
        vsync: Some("not-reported-by-presenter".to_string()),
        client_observability: Some(observability),
        ..RunContext::default()
    })
    .report()
    {
        eprintln!("OpenStream run {line}");
    }
    let mut stages = ReportOnDrop::new(
        ClientRecorder::for_decoder(observability),
        observability.unobserved_note(),
    );
    let mut metrics = MetricsReporter::default();
    let mut metrics_tick = tokio::time::interval(Duration::from_secs(2));
    // Reported once per transition, not once per tick: a stalled pipeline
    // should say so, not fill the log while it stays stalled.
    let mut last_stall: Option<Milestone> = None;
    with_telemetry(telemetry, |client| client.session_started(Stamp::now()));
    let probe_enabled = with_telemetry(telemetry, |client| client.probe.is_some()).unwrap_or(false);
    let mut probe_tick = tokio::time::interval(PROBE_INTERVAL);
    let mut clipboard_assembler = ClipboardAssembler::default();
    let mut clipboard_transfer_id = 1_u32;
    let mut clipboard_value = if clipboard_policy.may_send(negotiated.clipboard) {
        platform_clipboard::read_text().ok()
    } else {
        None
    };
    let mut reliable_control = ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
    // Microphone passthrough: capture only when negotiated AND configured.
    // The host still applies its own policy before taking the microphone.
    let mut mic_capture = if negotiated.microphone && mic::mic_configured() {
        match mic::spawn_mic_capture() {
            Ok(mut child) => {
                let stdout = child.stdout.take();
                eprintln!("OpenStream microphone capture started");
                stdout.map(|stdout| (child, stdout))
            }
            Err(error) => {
                eprintln!("OpenStream microphone capture unavailable: {error}");
                None
            }
        }
    } else {
        None
    };
    let mut mic_encoder = mic::MicEncoder::new().ok();
    let mut mic_buffer = vec![0_u8; mic::MIC_CHUNK_BYTES];
    // Coalesce keyframe requests: a burst of detected gaps on a fresh or lossy
    // path (before the first keyframe lands) collapses into a single pending
    // request, re-sent at most once per interval, so it can never flood the
    // bounded reliable-control window and tear the session down.
    let mut keyframe_pacer =
        openstream_client_core::KeyframeRequestPacer::new(KEYFRAME_REQUEST_INTERVAL);
    let mut control_tick = tokio::time::interval(Duration::from_millis(100));
    let mut clipboard_tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        let outbound_backpressured = matches!(
            session.flush_outbound_recoverably().await?,
            FlushOutcome::Backpressured
        );
        while let Ok(input) = input_rx.try_recv() {
            match input {
                UiInput::Event(event) => {
                    // Pointer motion goes on the unreliable path; everything
                    // else stays reliable and ordered.
                    //
                    // A retransmitted position is a position the pointer has
                    // already left, so retrying one is worse than dropping
                    // it: it arrives late, moves the pointer backwards, and
                    // the head-of-line wait it caused delayed every input
                    // behind it. A key release is the opposite -- losing one
                    // strands the key down on the remote desktop -- so those
                    // keep their acknowledgements.
                    if event.kind == InputKind::PointerMotion {
                        session
                            .send(Kind::Input, INPUT_CHANNEL, 0, &event.encode())
                            .await?;
                    } else {
                        reliable_control.send(&mut session, &event.encode()).await?;
                    }
                }
                UiInput::Release => {
                    reliable_control
                        .send(&mut session, &InputEvent::release(monotonic_us()).encode())
                        .await?;
                }
                UiInput::SelectDisplay(id) => {
                    reliable_control
                        .send(&mut session, &openstream_media::displays::encode_select(id))
                        .await?;
                }
                UiInput::Stop => {
                    let _ = reliable_control.send(&mut session, b"openstream/end").await;
                    // Returning drops `session_decoder`: the ffmpeg child dies via
                    // kill_on_drop, and the native worker's channel closes so its
                    // thread exits.
                    if let Some(mut player) = audio_player {
                        let _ = player.kill().await;
                    }
                    return Ok(());
                }
            }
        }
        let outbound_wake = if outbound_backpressured {
            None
        } else {
            session.next_outbound_wake()
        };
        tokio::select! {
            packet = session.recv() => {
                let packet = packet?;
                if packet.kind == Kind::Control {
                    if let Some(deliveries) = reliable_control.receive(&mut session, &packet).await? {
                        for payload in deliveries {
                            if payload == b"openstream/end" {
                                return Ok(());
                            }
                            if payload.starts_with(b"MD") {
                                match openstream_media::displays::decode_list(&payload) {
                                    Ok(topology) => {
                                        let _ = ui_tx.send(UiMessage::Displays(topology));
                                    }
                                    Err(error) => eprintln!(
                                        "OpenStream dropped malformed display topology: {error}"
                                    ),
                                }
                                continue;
                            }
                            if let Ok(rumble) = RumbleEvent::decode(&payload) {
                                let _ = ui_tx.send(UiMessage::Rumble {
                                    device_id: rumble.device_id,
                                    strong: rumble.strong,
                                    weak: rumble.weak,
                                });
                            } else if apply_clipboard_chunk(
                                &payload,
                                clipboard_policy.may_apply(negotiated.clipboard),
                                &mut clipboard_assembler,
                                &mut clipboard_value,
                            ) {
                                // Clipboard data is handled only when both
                                // peers negotiated it and local policy enabled it.
                            }
                        }
                        continue;
                    }
                    if packet.payload == b"openstream/end" {
                        return Ok(());
                    }
                    if packet.payload.starts_with(b"MD") {
                        match openstream_media::displays::decode_list(&packet.payload) {
                            Ok(topology) => {
                                let _ = ui_tx.send(UiMessage::Displays(topology));
                            }
                            Err(error) => eprintln!(
                                "OpenStream dropped malformed display topology: {error}"
                            ),
                        }
                        continue;
                    }
                    if let Ok(rumble) = RumbleEvent::decode(&packet.payload) {
                        let _ = ui_tx.send(UiMessage::Rumble {
                            device_id: rumble.device_id,
                            strong: rumble.strong,
                            weak: rumble.weak,
                        });
                    } else if apply_clipboard_chunk(
                        &packet.payload,
                        clipboard_policy.may_apply(negotiated.clipboard),
                        &mut clipboard_assembler,
                        &mut clipboard_value,
                    ) {
                        // Clipboard data is handled only when both peers
                        // negotiated it and local policy enabled it.
                    }
                }
                if packet.kind == Kind::Audio {
                    let Ok(audio) = AudioFrame::decode(&packet.payload) else {
                        let _ = ui_tx.send(UiMessage::Error(
                            "malformed audio packet dropped".to_string(),
                        ));
                        continue;
                    };
                    audio_jitter.push(audio);
                    while let Some(event) = audio_jitter.poll() {
                        let payload = match event {
                            AudioEvent::Frame(frame) => frame.payload,
                            AudioEvent::Missing(_) => {
                                let Some(toc) = last_audio_toc else {
                                    continue;
                                };
                                vec![toc]
                            }
                        };
                        let samples = match audio_decoder
                            .decode(&payload, lowlat_audio::FRAME, &mut audio_pcm)
                        {
                            Ok(samples) => samples,
                            Err(error) => {
                                let _ = ui_tx.send(UiMessage::Error(format!(
                                    "Opus packet dropped: {error}"
                                )));
                                continue;
                            }
                        };
                        if let Some(toc) = payload.first().copied() {
                            last_audio_toc = Some(toc);
                        }
                        if let Some(stdin) = audio_stdin.as_mut() {
                            let mut pcm16 = Vec::with_capacity(
                                samples * lowlat_audio::CHANNELS * 2,
                            );
                            for sample in audio_pcm
                                .iter()
                                .take(samples * lowlat_audio::CHANNELS)
                            {
                                #[allow(clippy::cast_possible_truncation)]
                                let sample = (sample.clamp(-1.0, 1.0) * 32767.0) as i16;
                                pcm16.extend_from_slice(&sample.to_le_bytes());
                            }
                            if stdin.write_all(&pcm16).await.is_err() {
                                audio_stdin = None;
                                let _ = ui_tx.send(UiMessage::Error(
                                    "audio player exited".to_string(),
                                ));
                            }
                        }
                    }
                    continue;
                }
                if packet.kind != Kind::Video {
                    continue;
                }
                let mut ready_frames = Vec::new();
                let fragment = match Fragment::decode(&packet.payload) {
                    Ok(fragment) => fragment,
                    Err(error) => {
                        let _ = ui_tx.send(UiMessage::Error(format!(
                            "video fragment dropped: {error}"
                        )));
                        continue;
                    }
                };
                let fragment_at = Stamp::<ClientClock>::now();
                let frame_id = fragment.frame_id;
                // Telemetry follows the assembler's lifecycle rather than
                // reconstructing it. Every branch below comes from what the
                // assembler says it did with this fragment, because the two
                // used to diverge in both directions: a retransmission of an
                // already-assembled frame opened a timeline that could never
                // finish, and a frame that completed while an older one was
                // missing never got its completion stamp at all.
                let outcome = match assembler.push(fragment) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // The fragment was rejected and any partial frame
                        // discarded with it. Close the timeline rather than
                        // leaving it open to be retired later as a stall
                        // that never happened.
                        stages.abandon_frame(frame_id, TraceEnd::Superseded);
                        let _ = ui_tx.send(UiMessage::Error(format!(
                            "video frame dropped: {error}"
                        )));
                        continue;
                    }
                };
                match outcome.fragment {
                    // The assembler ignored it, so nothing began or
                    // advanced. Opening a timeline here is what produced
                    // ghost traces for frames that had already finished.
                    FragmentOutcome::Duplicate => {}
                    FragmentOutcome::AcceptedIncomplete | FragmentOutcome::Completed => {
                        // "First" means the first fragment seen for this
                        // frame, not index zero. `begin` is a no-op for a
                        // frame already being timed, so a later fragment
                        // cannot restart the timeline.
                        stages.begin(frame_id, fragment_at);
                    }
                }
                with_telemetry(telemetry, |client| {
                    client
                        .liveness
                        .advance(Milestone::PacketReceived, frame_id, fragment_at);
                });
                if let Some(completed) = outcome.completed {
                    // The frame whose last missing fragment this was -- not
                    // necessarily the frame released below, which is
                    // whichever one became next in presentation order. The
                    // gap between the two is the reorder wait, and keying
                    // this stamp off the released frame is what hid it.
                    stages.mark(completed, ClientStage::LastFragmentReceived, fragment_at);
                }
                for dropped in &outcome.dropped {
                    // Evicted to stay bounded, or completed too late to
                    // decode in order. Nothing more will arrive for it.
                    stages.abandon_frame(*dropped, TraceEnd::Superseded);
                }
                // The release stamp is taken here, as each frame leaves the
                // reorder buffer, and carried with it. Stamping inside the
                // loop below instead put two unrelated awaits inside the
                // span: the reliable keyframe request, and -- for every
                // frame after the first -- the previous frame's decoder
                // write and ACK. That is what the 290ms tail in the
                // `LastFragmentReceived -> Reassembled` measurement was
                // actually timing.
                if let Some(frame) = outcome.ready {
                    ready_frames.push((frame, Stamp::<ClientClock>::now()));
                }
                while let Some(frame) = assembler.pop_ready() {
                    ready_frames.push((frame, Stamp::<ClientClock>::now()));
                }
                if assembler.take_keyframe_request() {
                    keyframe_pacer.note_gap();
                }
                // Draining the assembler's flag above coalesces any number of
                // detected gaps into a single pending request; the pacer emits
                // it at most once per interval, and `send_if_available` can never
                // grow the reliable-control window past its bound, so a keyframe
                // request can never kill the session. The request is retried
                // until an actual keyframe clears the pacer below.
                if keyframe_pacer.due(Instant::now())
                    && reliable_control
                        .send_if_available(&mut session, KEYFRAME_REQUEST)
                        .await?
                        .is_some()
                {
                    keyframe_pacer.note_sent(Instant::now());
                }
                for (frame, released_at) in ready_frames {
                    stages.mark(frame.frame_id, ClientStage::Reassembled, released_at);
                    if frame.keyframe {
                        keyframe_pacer.keyframe_received();
                    }
                    if !keyframe_pacer.is_waiting() {
                        session_decoder
                            .feed(&frame.payload, frame.presentation_time_us, frame.keyframe)
                            .await?;
                        stages.mark(frame.frame_id, ClientStage::DecoderSubmitted, Stamp::now());
                        // The last stage this client can attribute to a
                        // host frame id: FFmpeg does not hand the id back
                        // with the picture. What happens after this is
                        // measured by decoded sequence number instead --
                        // see `openstream_media::frame_age`.
                        stages.finish(frame.frame_id);
                        metrics.frame_received(frame.frame_id);
                        let ack = FrameAck {
                            frame_id: frame.frame_id,
                            lost_frames: assembler.take_frame_gap(),
                        };
                        let ack = ack.encode();
                        let _ = reliable_control
                            .send_if_available(&mut session, &ack)
                            .await?;
                    } else {
                        // Complete, correctly released, and then dropped
                        // because the decoder is waiting to recover. Retired
                        // under its own reason rather than `Superseded`:
                        // nothing pushed this frame out, the client chose
                        // not to decode it, and reading that as contention
                        // sends someone hunting a queueing problem that is
                        // not there.
                        stages.abandon_frame(frame.frame_id, TraceEnd::RecoverySkipped);
                    }
                }
            }
            () = decoded_ready.notified() => {
                // A loop rather than a single take: a permit can coalesce
                // with a publication that happened while this arm was not
                // being polled, and leaving a frame in the mailbox would
                // delay it until the next wake.
                while let Some(mut frame) = frame_rx.take() {
                    let taken_at = Stamp::<ClientClock>::now();
                    with_telemetry(telemetry, |client| {
                        client.frames.decoder_queue_consumed(&frame, taken_at);
                    });
                    frame.entering_ui_queue(taken_at);
                    let offer = ui_tx.send_frame(frame);
                    with_telemetry(telemetry, |client| {
                        client.frames.ui_queue_offer(offer);
                    });
                }
            }
            _ = control_tick.tick() => {
                reliable_control.retry(&mut session).await?;
                session.flush_outbound_recoverably().await?;
                session.maintain_liveness().await?;
                // Mirror the host's peer-liveness watch. A returned error is
                // retryable (it is not a TerminalError), so the reconnect
                // supervisor re-establishes and re-requests a keyframe rather
                // than the picture sitting frozen indefinitely.
                let peer_silence = session.last_peer_activity_age();
                if peer_liveness_expired(peer_silence, PEER_LIVENESS_TIMEOUT) {
                    return Err(format!(
                        "no host traffic for {peer_silence:?}; reconnecting"
                    )
                    .into());
                }
            }
            _ = wait_for_outbound_wake(outbound_wake) => {
                session.flush_outbound_recoverably().await?;
            }
            _ = probe_tick.tick(), if probe_enabled && negotiated.input => {
                // Stamp first, then send a real key event. The helper
                // advances its counter when the injected event reaches it,
                // so the span covers the client's input path, the network,
                // host injection and the application's own response -- the
                // part a benchmark message carrying the id would have
                // skipped while still being labelled `interaction_*`.
                //
                // Nothing happens until the marker has been read once: the
                // next id is one past whatever the helper is currently
                // showing, which is how this stays synchronised without a
                // channel of its own.
                let action = with_telemetry(telemetry, |client| {
                    client.next_probe_action(Stamp::now())
                });
                match action {
                    Some(ProbeAction::Press) => {
                        let press =
                            InputEvent::keyboard(PROBE_KEY_USAGE, 0, true, monotonic_us());
                        reliable_control.send(&mut session, &press.encode()).await?;
                    }
                    Some(ProbeAction::Release) => {
                        let release =
                            InputEvent::keyboard(PROBE_KEY_USAGE, 0, false, monotonic_us());
                        reliable_control.send(&mut session, &release.encode()).await?;
                    }
                    Some(ProbeAction::Idle) | None => {}
                }
            }
            _ = metrics_tick.tick() => {
                // A stall is observed here or it is not observed at all.
                // Nothing else retires a timeline as stalled, so before
                // this watch existed a zero stall count meant only "no code
                // ever said the word", not "the pipeline kept moving".
                let stalled = with_telemetry(telemetry, |client| {
                    client.liveness.stalled_at(STALL_DEADLINE, Stamp::now())
                })
                .flatten();
                match stalled {
                    Some(milestone) if last_stall != Some(milestone) => {
                        eprintln!(
                            "OpenStream pipeline stalled at {milestone:?}: nothing new in {}s",
                            STALL_DEADLINE.as_secs_f64()
                        );
                        stages.abandon(milestone.stall_reason());
                        last_stall = Some(milestone);
                    }
                    Some(_) => {}
                    None => last_stall = None,
                }
                let mut line = metrics.snapshot().overlay_line();
                with_telemetry(telemetry, |client| {
                    line.push_str(" -- ");
                    line.push_str(&client.frames.overlay_fragment());
                });
                let _ = ui_tx.send(UiMessage::Metrics(line));
            }
            _ = clipboard_tick.tick(), if clipboard_policy.may_send(negotiated.clipboard) => {
                if let Ok(current) = platform_clipboard::read_text()
                    && clipboard_value.as_deref() != Some(current.as_str())
                {
                    for payload in fragment_text(clipboard_transfer_id, &current)? {
                        reliable_control.send(&mut session, &payload).await?;
                    }
                    clipboard_transfer_id = clipboard_transfer_id.wrapping_add(1);
                    clipboard_value = Some(current);
                }
            }
            result = async {
                match mic_capture.as_mut() {
                    Some((_, stdout)) => {
                        use tokio::io::AsyncReadExt;
                        stdout.read_exact(&mut mic_buffer).await
                    }
                    None => std::future::pending::<io::Result<usize>>().await,
                }
            } => {
                // A short read means the capture device ended: stop mic
                // cleanly rather than looping on errors.
                let ended = result.is_err();
                if !ended && let Some(encoder) = mic_encoder.as_mut() {
                    match encoder.encode_chunk(&mic_buffer) {
                        Ok(message) => {
                            reliable_control.send(&mut session, &message).await?;
                        }
                        Err(error) => {
                            eprintln!("OpenStream microphone frame dropped: {error}");
                        }
                    }
                }
                if ended {
                    mic_capture = None;
                }
            }
        }
    }
}

async fn wait_for_outbound_wake(wake: Option<Duration>) {
    match wake {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}

fn apply_clipboard_chunk(
    payload: &[u8],
    enabled: bool,
    assembler: &mut ClipboardAssembler,
    current: &mut Option<String>,
) -> bool {
    if !payload.starts_with(b"CB") {
        return false;
    }
    if !enabled {
        return true;
    }
    let completed = match assembler.push(payload) {
        Ok(completed) => completed,
        Err(error) => {
            eprintln!("OpenStream dropped malformed clipboard chunk: {error}");
            return true;
        }
    };
    match completed {
        Some(CompletedClipboard::Text(text)) => match platform_clipboard::write_text(&text) {
            Ok(()) => *current = Some(text),
            Err(error) => eprintln!("OpenStream could not apply clipboard text: {error}"),
        },
        Some(CompletedClipboard::Clear) => match platform_clipboard::clear() {
            Ok(()) => *current = Some(String::new()),
            Err(error) => eprintln!("OpenStream could not clear the clipboard: {error}"),
        },
        None => {}
    }
    true
}

fn spawn_audio_player() -> Result<Option<Child>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(executable) = env::var("OPENSTREAM_AUDIO_PLAYER").ok() else {
        return Ok(None);
    };
    let child = Command::new(executable)
        .args([
            "-hide_banner",
            "-loglevel",
            "warning",
            "-f",
            "s16le",
            "-ar",
            "48000",
            "-ac",
            "2",
            "-i",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("could not start audio player: {error}"))?;
    Ok(Some(child))
}

/// Arguments for the decoder child.
///
/// The low-delay flags are not tuning; without them the decoder is the
/// largest single source of latency in the client.
///
/// libavcodec's H.264 decoder defaults to frame-level threading with one
/// thread per core, and frame threading holds output back so the workers
/// can run ahead. `-thread_type slice` keeps the parallelism that can be
/// had within a frame and drops the part that costs frames.
///
/// The rest stop the demuxer buffering ahead of the decoder: `nobuffer` and
/// `low_delay` disable the reordering and read-ahead that exist for files,
/// and the tiny probe/analyse limits stop FFmpeg reading a long stretch of
/// stream before it will emit anything at all.
///
/// Together these measured 553 ms on a ten-core client at 30 fps
/// (1000 ms -> 447 ms glass-to-glass). How that total divides between frame
/// threading and the demuxer flags has not been measured separately, so no
/// single figure here is attributed to one of them.
/// Which decode path FFmpeg is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DecodeAccel {
    /// libavcodec on the CPU. The default, and the fallback everywhere.
    #[default]
    Software,
    /// Apple's VideoToolbox. FFmpeg decodes on the media engine and hands
    /// back CPU frames, so the rest of the pipeline is unchanged.
    VideoToolbox,
}

impl DecodeAccel {
    /// Read `OPENSTREAM_DECODER`. Unknown names, and VideoToolbox asked for
    /// off macOS, fall back to software rather than failing to start: a
    /// decoder that runs is worth more than one that is exactly as asked.
    fn from_env() -> Self {
        let requested = std::env::var("OPENSTREAM_DECODER").unwrap_or_default();
        match requested.trim().to_ascii_lowercase().as_str() {
            "videotoolbox" | "vt" if cfg!(target_os = "macos") => Self::VideoToolbox,
            "videotoolbox" | "vt" => {
                eprintln!(
                    "OpenStream decoder videotoolbox is macOS only; using the software decoder"
                );
                Self::Software
            }
            "" | "software" | "cpu" => Self::Software,
            // The in-process decoder is selected by `decode_dispatch`; when
            // it is chosen no ffmpeg runs, so there is no acceleration to
            // pick here and nothing to warn about.
            "native" | "videotoolbox-native" => Self::Software,
            other => {
                eprintln!(
                    "OpenStream decoder {other} is not recognised; using the software decoder"
                );
                Self::Software
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::VideoToolbox => "videotoolbox",
        }
    }
}

fn decoder_args(format: &str, width: usize, height: usize) -> Vec<String> {
    decoder_args_with(DecodeAccel::from_env(), format, width, height)
}

/// The decoder line of the run context: the in-process backend by name, or
/// the ffmpeg command and acceleration the subprocess is asked for. It names
/// what `select_decoder` chose, not what the environment asked for.
fn decoder_report(backend: decode_dispatch::DecodeBackend, format: &str) -> String {
    match backend {
        #[cfg(target_os = "macos")]
        decode_dispatch::DecodeBackend::VideoToolboxNative => {
            format!("videotoolbox in-process {format} (no ffmpeg subprocess)")
        }
        #[cfg(target_os = "windows")]
        decode_dispatch::DecodeBackend::MediaFoundationNative => {
            format!("media-foundation in-process {format} (no ffmpeg subprocess)")
        }
        decode_dispatch::DecodeBackend::Ffmpeg => format!(
            "{} {format} {}",
            env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".into()),
            DecodeAccel::from_env().name()
        ),
    }
}

fn decoder_args_with(accel: DecodeAccel, format: &str, width: usize, height: usize) -> Vec<String> {
    let mut arguments: Vec<String> = vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-fflags".into(),
        "nobuffer".into(),
        "-flags".into(),
        "low_delay".into(),
        "-thread_type".into(),
        "slice".into(),
        "-probesize".into(),
        "32".into(),
        "-analyzeduration".into(),
        "0".into(),
    ];
    if accel == DecodeAccel::VideoToolbox {
        // No -hwaccel_output_format: FFmpeg downloads to CPU frames on its
        // own, which is what the scale filter and the BGRA sink below need.
        // Asking for hardware frames here would force a hwdownload filter
        // into the chain for no gain.
        arguments.push("-hwaccel".into());
        arguments.push("videotoolbox".into());
    }
    arguments.extend([
        "-f".into(),
        format.into(),
        "-i".into(),
        "pipe:0".into(),
        "-an".into(),
        "-sn".into(),
        "-dn".into(),
        "-f".into(),
        "rawvideo".into(),
        "-vf".into(),
        format!("scale={width}:{height}:flags=fast_bilinear"),
        "-pix_fmt".into(),
        "bgra".into(),
        "-fps_mode".into(),
        "passthrough".into(),
        "pipe:1".into(),
    ]);
    arguments
}

/// Hand one decoded frame to the window, dropping it if the window is
/// behind. Returns false once the window is gone.
///
/// This must never await. The task that calls it is the only thing draining
/// the decoder's stdout, and the loop that drains the receiving end is the
/// same loop that writes access units to the decoder's stdin. Blocking on a
/// full channel therefore deadlocks the whole session: the decoder's output
/// pipe fills, the decoder stops reading its input, the network loop blocks
/// in `write_all`, and so never reaches the receiver to make room here. The
/// window shows nothing at all while packets pile up unread in the socket.
///
/// A late frame is worth less than a live one, so a frame the window has not
/// kept up with is dropped -- exactly as `UiSender` already drops stale
/// frames and metrics.
///
/// The outcome is returned as a [`FrameOffer`] rather than a `bool`. Under
/// the `bool` a delivered frame and a discarded one were the same value, so
/// a client dropping half its decoder output looked identical to one
/// dropping none: the discarded frames left no span sample either, having no
/// end stamp, so nothing anywhere recorded them.
fn offer_decoded_frame(
    sender: &LatestFramePublisher<DecodedFrame>,
    frame: DecodedFrame,
) -> FrameOffer {
    sender.publish(frame)
}

/// The decoder backing a session: the ffmpeg subprocess (default and universal
/// fallback) or the in-process native decoder fed over a channel.
enum SessionDecoder {
    Ffmpeg {
        stdin: tokio::process::ChildStdin,
        // Held so the subprocess is killed on drop at session end.
        _child: Child,
    },
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Native {
        au_tx: std::sync::mpsc::Sender<NativeAccessUnit>,
    },
}

impl SessionDecoder {
    /// Submit one reassembled access unit to the decoder.
    // On platforms with no in-process decoder the native arm is compiled out, so
    // the match has a single arm and these two fields go unused; both are fine
    // and intentional.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "windows")),
        allow(clippy::match_single_binding)
    )]
    async fn feed(
        &mut self,
        payload: &[u8],
        presentation_time_us: u64,
        keyframe: bool,
    ) -> std::io::Result<()> {
        // Consumed only by the native arm; reference them so they are not unused
        // where that arm is compiled out.
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (presentation_time_us, keyframe);
        match self {
            SessionDecoder::Ffmpeg { stdin, .. } => stdin.write_all(payload).await,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            SessionDecoder::Native { au_tx } => au_tx
                .send(NativeAccessUnit {
                    payload: payload.to_vec(),
                    presentation_time_us,
                    keyframe,
                })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "native decoder thread stopped",
                    )
                }),
        }
    }
}

/// One access unit handed to a native decoder thread (VideoToolbox on macOS,
/// Media Foundation on Windows).
#[cfg(any(target_os = "macos", target_os = "windows"))]
struct NativeAccessUnit {
    payload: Vec<u8>,
    presentation_time_us: u64,
    keyframe: bool,
}

/// Build the session decoder for `backend`: spawn the ffmpeg subprocess plus its
/// stdout reader, or the native decoder thread. Both feed the same mailbox
/// through [`publish_decoded_picture`], so everything downstream is identical.
// On platforms with no in-process decoder the native arm is compiled out,
// leaving a single-arm match.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(clippy::match_single_binding)
)]
fn build_session_decoder(
    backend: decode_dispatch::DecodeBackend,
    format: &str,
    width: usize,
    height: usize,
    frame_bytes: usize,
    frame_tx: LatestFramePublisher<DecodedFrame>,
    decoded_ready: Arc<tokio::sync::Notify>,
    telemetry: SharedTelemetry,
) -> Result<SessionDecoder, TerminalError> {
    match backend {
        #[cfg(target_os = "macos")]
        decode_dispatch::DecodeBackend::VideoToolboxNative => {
            let (au_tx, au_rx) = std::sync::mpsc::channel::<NativeAccessUnit>();
            // Read here rather than on the decoder thread: the mode is fixed
            // when the VideoToolbox session is created, and reading it on the
            // thread would make the decision depend on when that thread
            // happened to be scheduled.
            let zero_copy = ZERO_COPY_PRESENT.load(Ordering::Relaxed);
            std::thread::Builder::new()
                .name("openstream-vt-decode".into())
                .spawn(move || {
                    native_decode_worker(au_rx, frame_tx, decoded_ready, telemetry, zero_copy);
                })
                .map_err(|error| {
                    TerminalError::new(format!("could not start native decoder thread: {error}"))
                })?;
            Ok(SessionDecoder::Native { au_tx })
        }
        #[cfg(target_os = "windows")]
        decode_dispatch::DecodeBackend::MediaFoundationNative => {
            let (au_tx, au_rx) = std::sync::mpsc::channel::<NativeAccessUnit>();
            std::thread::Builder::new()
                .name("openstream-mf-decode".into())
                .spawn(move || {
                    windows_native_decode_worker(au_rx, frame_tx, decoded_ready, telemetry)
                })
                .map_err(|error| {
                    TerminalError::new(format!(
                        "could not start Media Foundation decoder thread: {error}"
                    ))
                })?;
            Ok(SessionDecoder::Native { au_tx })
        }
        decode_dispatch::DecodeBackend::Ffmpeg => {
            let mut decoder =
                Command::new(env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".into()))
                    .args(decoder_args(format, width, height))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|error| {
                        TerminalError::new(format!("could not start FFmpeg decoder: {error}"))
                    })?;
            let stdin = decoder
                .stdin
                .take()
                .ok_or_else(|| TerminalError::new("FFmpeg decoder stdin was not piped"))?;
            let mut decoder_stdout = decoder
                .stdout
                .take()
                .ok_or_else(|| TerminalError::new("FFmpeg decoder stdout was not piped"))?;
            tokio::spawn(async move {
                loop {
                    let mut raw = vec![0_u8; frame_bytes];
                    if tokio::io::AsyncReadExt::read_exact(&mut decoder_stdout, &mut raw)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    // Stamped before the pixel conversion (see frame_age): the
                    // loop below walks every pixel, and clocking after it would
                    // leave that CPU work outside every span.
                    let raw_ready_at = Stamp::<ClientClock>::now();
                    let mut pixels = Vec::with_capacity(width * height);
                    for pixel in raw.chunks_exact(4) {
                        let value = u32::from(pixel[0])
                            | (u32::from(pixel[1]) << 8)
                            | (u32::from(pixel[2]) << 16)
                            | (u32::from(pixel[3]) << 24);
                        pixels.push(value);
                    }
                    let ready_at = Stamp::<ClientClock>::now();
                    if !publish_decoded_picture(
                        pixels,
                        width,
                        height,
                        raw_ready_at,
                        ready_at,
                        None,
                        &telemetry,
                        &frame_tx,
                        &decoded_ready,
                    ) {
                        break;
                    }
                }
            });
            Ok(SessionDecoder::Ffmpeg {
                stdin,
                _child: decoder,
            })
        }
    }
}

/// One picture out of the native decoder, in whichever form it was decoded
/// into: CPU pixels, or a GPU surface with `pixels` left empty.
///
/// The two modes are normalised here so the worker below has one publish
/// path, one set of stamps and one error handler regardless of which it is
/// running -- the alternative was two near-identical loops that would drift.
#[cfg(target_os = "macos")]
struct NativePicture {
    pixels: Vec<u32>,
    width: usize,
    height: usize,
    surface: Option<FrameSurface>,
}

/// The native decoder thread: decode each access unit in-process with
/// VideoToolbox and publish the pictures to the same mailbox the ffmpeg reader
/// uses. A decode error is recoverable -- the network loop keeps requesting
/// keyframes, and the next one re-seeds the decoder.
///
/// With `zero_copy` the decoder is created in GPU mode and each picture is
/// published as a retained `CVPixelBuffer` with no pixels: the per-pixel
/// readback never happens, and the window imports the surface directly. It is
/// a parameter rather than a read of [`ZERO_COPY_PRESENT`] because a
/// decoder's mode is fixed when its VideoToolbox session is created, so the
/// caller decides once, before the thread starts.
#[cfg(target_os = "macos")]
fn native_decode_worker(
    au_rx: std::sync::mpsc::Receiver<NativeAccessUnit>,
    frame_tx: LatestFramePublisher<DecodedFrame>,
    decoded_ready: Arc<tokio::sync::Notify>,
    telemetry: SharedTelemetry,
    zero_copy: bool,
) {
    let mut decoder = if zero_copy {
        vt_decoder::VideoToolboxH264Decoder::new_gpu()
    } else {
        vt_decoder::VideoToolboxH264Decoder::new()
    };
    eprintln!(
        "OpenStream in-process decoder: VideoToolbox H.264 on this thread ({}); no ffmpeg subprocess",
        if zero_copy {
            "GPU surfaces, no CPU readback"
        } else {
            "CPU pixel buffers"
        }
    );
    // VideoToolbox only says whether it is on the media engine once a session
    // exists, so the acceleration state is reported with the first pictures.
    let mut acceleration_reported = false;
    while let Ok(au) = au_rx.recv() {
        let raw_ready_at = Stamp::<ClientClock>::now();
        let decoded = if zero_copy {
            decoder
                .decode_gpu(&au.payload, au.presentation_time_us, au.keyframe)
                .map(|frames| {
                    frames
                        .into_iter()
                        .map(|frame| NativePicture {
                            pixels: Vec::new(),
                            width: frame.width,
                            height: frame.height,
                            surface: Some(FrameSurface::new(frame.pixel_buffer)),
                        })
                        .collect::<Vec<_>>()
                })
        } else {
            decoder
                .decode(&au.payload, au.presentation_time_us, au.keyframe)
                .map(|frames| {
                    frames
                        .into_iter()
                        .map(|frame| NativePicture {
                            pixels: frame.pixels,
                            width: frame.width,
                            height: frame.height,
                            surface: None,
                        })
                        .collect::<Vec<_>>()
                })
        };
        match decoded {
            Ok(pictures) => {
                if !acceleration_reported && !pictures.is_empty() {
                    acceleration_reported = true;
                    eprintln!(
                        "OpenStream VideoToolbox decoder: {}",
                        match decoder.hardware_accelerated() {
                            Some(true) => "hardware accelerated",
                            Some(false) => "software (VideoToolbox reports no hardware decoder)",
                            None => "acceleration not reported by the session",
                        }
                    );
                }
                for picture in pictures {
                    let ready_at = Stamp::<ClientClock>::now();
                    if !publish_decoded_picture(
                        picture.pixels,
                        picture.width,
                        picture.height,
                        raw_ready_at,
                        ready_at,
                        picture.surface,
                        &telemetry,
                        &frame_tx,
                        &decoded_ready,
                    ) {
                        return;
                    }
                }
            }
            Err(vt_decoder::VtError::NotConfigured) => {
                // Waiting for the first keyframe; nothing to publish yet.
            }
            Err(error) => {
                eprintln!("native VideoToolbox decode error: {error}");
            }
        }
    }
}

/// The native decoder thread on Windows: decode each access unit in-process with
/// the Media Foundation H.264 MFT and publish the pictures to the same mailbox
/// the ffmpeg reader uses. A decode error is recoverable -- the network loop
/// keeps requesting keyframes, and the next one re-seeds the decoder.
#[cfg(target_os = "windows")]
fn windows_native_decode_worker(
    au_rx: std::sync::mpsc::Receiver<NativeAccessUnit>,
    frame_tx: LatestFramePublisher<DecodedFrame>,
    decoded_ready: Arc<tokio::sync::Notify>,
    telemetry: SharedTelemetry,
) {
    let mut decoder = match openstream_windows_media::MediaFoundationH264Decoder::new() {
        Ok(decoder) => decoder,
        Err(error) => {
            eprintln!("could not create the Media Foundation decoder: {error}");
            return;
        }
    };
    eprintln!(
        "OpenStream in-process decoder: Media Foundation H.264 on this thread ({}); no ffmpeg subprocess",
        if decoder.is_hardware() {
            "D3D11/DXVA hardware"
        } else {
            "software MFT"
        }
    );
    while let Ok(au) = au_rx.recv() {
        // The MFT keys ordering off the sample time, not a keyframe flag.
        let _ = au.keyframe;
        let raw_ready_at = Stamp::<ClientClock>::now();
        let pts = i64::try_from(au.presentation_time_us).unwrap_or(0);
        match decoder.decode(&au.payload, pts) {
            Ok(pictures) => {
                for picture in pictures {
                    let ready_at = Stamp::<ClientClock>::now();
                    if !publish_decoded_picture(
                        picture.pixels,
                        picture.width,
                        picture.height,
                        raw_ready_at,
                        ready_at,
                        None,
                        &telemetry,
                        &frame_tx,
                        &decoded_ready,
                    ) {
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!("native Media Foundation decode error: {error}");
            }
        }
    }
    // The stream ended (the session dropped the sender): drain any pictures the
    // decoder still holds so the last frames are not lost at teardown.
    if let Ok(pictures) = decoder.flush() {
        for picture in pictures {
            let now = Stamp::<ClientClock>::now();
            if !publish_decoded_picture(
                picture.pixels,
                picture.width,
                picture.height,
                now,
                now,
                None,
                &telemetry,
                &frame_tx,
                &decoded_ready,
            ) {
                break;
            }
        }
    }
}

/// Assign the client sequence number, stamp, wrap, and publish a decoded picture
/// to the mailbox. Shared by the ffmpeg reader and the native decoder so both
/// record identical telemetry and freshness. Returns `false` when the session
/// should stop (telemetry gone, or the mailbox reports stop).
#[allow(clippy::too_many_arguments)]
fn publish_decoded_picture(
    pixels: Vec<u32>,
    width: usize,
    height: usize,
    raw_ready_at: Stamp<ClientClock>,
    ready_at: Stamp<ClientClock>,
    surface: Option<FrameSurface>,
    telemetry: &SharedTelemetry,
    frame_tx: &LatestFramePublisher<DecodedFrame>,
    decoded_ready: &tokio::sync::Notify,
) -> bool {
    // The sequence number is assigned here, by the client, not the host's frame
    // id: the decoder may emit a different number of pictures than the host
    // encoded, so a host id carried through would be a false correlation.
    let Some(seq) = with_telemetry(telemetry, |client| {
        client.frames.pixels_unpacked(raw_ready_at, ready_at);
        client.frames.frame_decoded()
    }) else {
        return false;
    };
    with_telemetry(telemetry, |client| {
        client
            .liveness
            .advance(Milestone::FrameDecoded, seq_as_frame_id(seq), ready_at);
    });
    let frame = DecodedFrame::new(seq, raw_ready_at, ready_at, width, height, pixels);
    let frame = match surface {
        Some(surface) => frame.with_surface(surface),
        None => frame,
    };
    with_telemetry(telemetry, |client| {
        client.marker_decoded(&frame, Stamp::now());
    });
    // Never block: a late frame is worth less than a live one, so a frame the UI
    // has not kept up with is dropped, exactly as the UI queue already drops
    // stale frames.
    let offer = offer_decoded_frame(frame_tx, frame);
    with_telemetry(telemetry, |client| {
        client.frames.decoder_queue_offer(offer);
    });
    if offer.should_stop() {
        return false;
    }
    // After publishing, so the woken loop always finds the frame. `notify_one`
    // stores a permit when nobody is waiting, so a wake raced against the
    // consumer's next poll is not lost.
    decoded_ready.notify_one();
    true
}

/// The opt-in interaction probe's client-side state.
///
/// The probe id is not carried over any side channel: the host helper simply
/// counts the input events it receives, so the client learns where the
/// counter is by reading the marker, and the next id is one past whatever it
/// last saw. That self-synchronises after a reconnect or a dropped event,
/// and it means the measured span includes host injection and the helper's
/// own response to an ordinary event -- which is the part a benchmark
/// message would have skipped.
#[derive(Debug)]
struct ProbeState {
    origin: (usize, usize),
    probe: InteractionProbe,
    last_seen: Option<u16>,
    /// The id most recently sent, so the same one is never sent twice.
    ///
    /// `next_probe_id` is derived from the marker, which does not move until
    /// the helper receives an event. Re-sending on the next tick pushed a
    /// second outstanding entry with the same id, and when the helper
    /// finally advanced, the match landed on the *oldest* of them -- turning
    /// a lost keystroke into a ten-second interaction latency in the first
    /// rig run.
    last_sent: Option<u16>,
    /// Whether the probe key is currently held down on the host.
    ///
    /// The press and the release go out on consecutive ticks rather than
    /// back to back. The helper detects a keypress as a down transition
    /// between two polls of its event loop; a press and release delivered
    /// within one poll interval collapse into no transition at all, and the
    /// first rig run lost three quarters of its keystrokes that way.
    key_down: bool,
    /// When [`Self::last_sent`] went out, so a probe whose keystroke never
    /// arrived can be given up on instead of stalling the benchmark.
    last_sent_at: Option<Stamp<ClientClock>>,
    /// Probes given up on because their marker never came back in time.
    /// Reported rather than silently retried: a benchmark that quietly
    /// stops measuring looks exactly like one that is measuring fine.
    timeouts: u64,
    /// Why this session's interaction measurement stopped being trustworthy,
    /// if it did. `Some` means no further probes are sent.
    invalidated: Option<&'static str>,
}

/// The client's always-on frame accounting and its opt-in interaction probe.
///
/// One lock rather than two because they are updated at the same three
/// points, and the points are on three different threads: the task reading
/// the decoder's stdout, the session loop, and the window. The critical
/// sections are integer increments, an array index, and -- only when the
/// probe is enabled -- a fixed 42-cell read of the frame, so the lock is
/// never held across an await or a present.
#[derive(Debug)]
struct ClientTelemetry {
    frames: FrameAgeRecord,
    /// Forward-progress watch, so "no stalls" is an observation rather than
    /// an absence of evidence.
    ///
    /// `StageRecorder::stalls()` only counts timelines something explicitly
    /// retired as stalled, so without this nothing ever would, and a report
    /// printing zero would be stating that nothing classified a stall -- not
    /// that the pipeline kept moving. It also gives the per-boundary rates
    /// needed to say *where* a stream slowed down.
    liveness: Liveness<ClientClock>,
    probe: Option<ProbeState>,
}

impl ClientTelemetry {
    fn new(probe_origin: Option<(usize, usize)>) -> Self {
        Self {
            frames: FrameAgeRecord::new(),
            liveness: Liveness::new(Stamp::now()),
            probe: probe_origin.map(|origin| ProbeState {
                origin,
                probe: InteractionProbe::new(),
                last_seen: None,
                last_sent: None,
                key_down: false,
                last_sent_at: None,
                timeouts: 0,
                invalidated: None,
            }),
        }
    }

    /// Look for the helper's marker in a decoded picture.
    ///
    /// Reads at the agreed origin rather than searching: scanning a 1080p
    /// frame on every decoded picture would cost more than the span being
    /// measured. A frame with no intact marker is the normal case between
    /// probes and costs 42 cell samples to rule out.
    fn marker_decoded(&mut self, frame: &DecodedFrame, at: Stamp<ClientClock>) -> Option<u16> {
        let state = self.probe.as_mut()?;
        let marker = probe_detect(frame.pixels(), frame.width(), frame.height(), state.origin)?;
        state.last_seen = Some(marker);
        state.probe.marker_decoded(marker, at);
        Some(marker)
    }

    /// The marker in a frame, if the probe is enabled and one is there.
    ///
    /// Read separately from crediting it so the pixels can be handed to the
    /// presenter first: the frame is credited only once a presenter has
    /// accepted it, and by then the buffer has moved.
    fn marker_in(&self, frame: &DecodedFrame) -> Option<u16> {
        let state = self.probe.as_ref()?;
        probe_detect(frame.pixels(), frame.width(), frame.height(), state.origin)
    }

    fn marker_present_submitted(&mut self, marker: Option<u16>, at: Stamp<ClientClock>) {
        if let (Some(state), Some(marker)) = (self.probe.as_mut(), marker) {
            state.probe.marker_present_submitted(marker, at);
        }
    }

    /// The id the helper will show once it has received one more event.
    ///
    /// `None` until the client has read the marker at least once, and `None`
    /// again while that id is still outstanding: the marker does not move
    /// until the helper receives an event, so a tick that fires before the
    /// last one came back would otherwise send the same id a second time.
    fn next_probe_id(&self) -> Option<u16> {
        let state = self.probe.as_ref()?;
        let next = state.last_seen?.wrapping_add(1);
        if state.last_sent == Some(next) {
            return None;
        }
        Some(next)
    }

    /// Decide what to put on the wire this tick.
    ///
    /// The probe key is pressed on one tick and released on the next, never
    /// both in one. The helper sees a keypress as a down transition between
    /// two polls of its event loop, so a press and release delivered inside
    /// one poll interval collapse into nothing -- which is what cost the
    /// first rig run three quarters of its probes.
    fn next_probe_action(&mut self, at: Stamp<ClientClock>) -> ProbeAction {
        self.expire_stale_probe(at);
        // Once invalid, the only thing left to do is let go of the key.
        if self
            .probe
            .as_ref()
            .is_some_and(|state| state.invalidated.is_some())
        {
            return match self.probe.as_mut() {
                Some(state) if state.key_down => {
                    state.key_down = false;
                    ProbeAction::Release
                }
                _ => ProbeAction::Idle,
            };
        }
        let Some(next) = self.next_probe_id() else {
            // Still holding the key, or nothing new to send. Releasing takes
            // priority: the key must not stay down across a stall.
            return match self.probe.as_mut() {
                Some(state) if state.key_down => {
                    state.key_down = false;
                    ProbeAction::Release
                }
                _ => ProbeAction::Idle,
            };
        };
        let Some(state) = self.probe.as_mut() else {
            return ProbeAction::Idle;
        };
        if state.key_down {
            state.key_down = false;
            return ProbeAction::Release;
        }
        state.probe.sent(next, at);
        state.last_sent = Some(next);
        state.last_sent_at = Some(at);
        state.key_down = true;
        ProbeAction::Press
    }

    /// Give up on a probe whose keystroke never reached the helper.
    ///
    /// Without this the benchmark stops silently: the marker never moves,
    /// so `next_probe_id` keeps returning the id already outstanding,
    /// "never resend the same id" suppresses every tick, and the client
    /// waits forever while printing nothing. Abandoning the probe first
    /// means the retry cannot be matched against the stale stamp, so the
    /// re-send measures the new attempt rather than the lost one.
    fn expire_stale_probe(&mut self, at: Stamp<ClientClock>) {
        let Some(state) = self.probe.as_mut() else {
            return;
        };
        if state.invalidated.is_some() {
            return;
        }
        let (Some(sent_id), Some(sent_at)) = (state.last_sent, state.last_sent_at) else {
            return;
        };
        if at
            .since(sent_at)
            .is_none_or(|waited| waited < PROBE_TIMEOUT)
        {
            return;
        }
        state.probe.abandon(sent_id);
        state.timeouts = state.timeouts.saturating_add(1);
        state.last_sent = None;
        state.last_sent_at = None;
        state.invalidated =
            Some("a probe timed out; a delayed input event cannot be told from a lost one");
        eprintln!(
            "OpenStream interaction probe {sent_id} timed out after {}s; \
             interaction measurement for this session is now invalid and \
             probing has stopped",
            PROBE_TIMEOUT.as_secs_f64()
        );
    }

    /// Start a session's liveness watch. Rates describe one session, so a
    /// reconnect does not dilute them with the downtime before it.
    fn session_started(&mut self, at: Stamp<ClientClock>) {
        self.liveness = Liveness::new(at);
    }

    /// End a session's probing. Nothing measured in one session may be
    /// matched against a marker from the next.
    fn session_ended(&mut self) {
        self.frames.session_ended();
        let Some(state) = self.probe.as_mut() else {
            return;
        };
        // An outstanding probe would otherwise be matched by a marker from
        // the session that reconnects, and report a span covering the
        // downtime as if it were interaction latency.
        state.probe.abandon_all();
        state.last_seen = None;
        state.last_sent = None;
        state.last_sent_at = None;
        // A new session is a new measurement: nothing in flight from the old
        // one can reach the new helper's marker state.
        state.invalidated = None;
        // The host's virtual keyboard state does not survive the session
        // either, so the next one starts with nothing held.
        state.key_down = false;
    }

    fn report(&self, now: Stamp<ClientClock>) -> Vec<String> {
        let mut lines = self.liveness.report(now);
        lines.extend(self.frames.report());
        if let Some(state) = self.probe.as_ref() {
            lines.extend(state.probe.report());
            lines.push(format!(
                "probe timeouts={} outstanding_at_end={}",
                state.timeouts,
                state.probe.outstanding()
            ));
            if let Some(reason) = state.invalidated {
                // A reader who quotes the interaction numbers without this
                // line is quoting a measurement that stopped partway
                // through the run.
                lines.push(format!("probe INVALID: {reason}"));
                lines.push(
                    "probe the interaction spans above cover only what was \
                     measured before that point"
                        .to_string(),
                );
            }
        }
        lines
    }
}

/// Shared across the three threads a frame passes through.
type SharedTelemetry = Arc<Mutex<ClientTelemetry>>;

/// Run `edit` against the shared telemetry, returning `None` if a panic
/// elsewhere poisoned the lock. Losing a counter is not a reason to take the
/// session down, so the caller decides whether a missing answer matters.
fn with_telemetry<R>(
    telemetry: &SharedTelemetry,
    edit: impl FnOnce(&mut ClientTelemetry) -> R,
) -> Option<R> {
    telemetry.lock().ok().map(|mut guard| edit(&mut guard))
}

/// Where the host helper draws its marker, when the interaction probe is
/// enabled. Off unless set: it is a benchmark facility and requires
/// `openstream-probe-helper` to be running on the host desktop.
fn probe_origin_from_environment() -> Option<(usize, usize)> {
    let spec = env::var("OPENSTREAM_PROBE_ORIGIN").ok()?;
    let (x, y) = spec.split_once(',')?;
    let origin = (x.trim().parse().ok()?, y.trim().parse().ok()?);
    eprintln!("OpenStream interaction probe reading marker at {origin:?}");
    Some(origin)
}

/// What the probe puts on the wire on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeAction {
    /// Press the probe key, having just stamped a new probe.
    Press,
    /// Release the key pressed on the previous tick.
    Release,
    /// Nothing to do: the marker has not been read yet, or the last probe
    /// is still outstanding.
    Idle,
}

/// How often to send the probe's input event.
///
/// A press goes out on one tick and its release on the next, so a full
/// probe takes two of these. Slow enough that the measurement does not
/// become the load -- each probe costs one key event and one redraw on the
/// host -- and fast enough to gather a few hundred samples in a few minutes.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// Minimum spacing between keyframe requests while one is outstanding. A few
/// round trips: long enough that a burst of gaps coalesces into one request,
/// short enough that a genuinely lost keyframe is re-requested promptly.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

/// The key the probe presses. A modifier, so an ordinary application that
/// happens to be focused instead of the helper receives something inert
/// rather than typed text or a shortcut.
const PROBE_KEY_USAGE: u32 = 0x0000_00E1;

/// A decoded sequence number as a liveness frame id.
///
/// `Liveness` keys on `u32` because it is shared with the host, whose frame
/// ids are 32-bit. Truncating is safe for the question it answers -- whether
/// the id *changed* since the last observation -- and two sequence numbers
/// 2^32 apart cannot be adjacent.
fn seq_as_frame_id(seq: DecodedFrameSeq) -> u32 {
    u32::try_from(seq.get() & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

/// How long a downstream milestone may go without advancing before the
/// pipeline is called stalled.
///
/// Well beyond any frame interval worth streaming, so ordinary jitter and a
/// keyframe wait cannot trip it, and short enough that a session which has
/// stopped moving says so within a metrics tick of noticing.
const STALL_DEADLINE: Duration = Duration::from_secs(2);

/// How long to wait for a probe's marker before giving up on it.
///
/// Generous against any plausible interaction latency and short enough
/// that a benchmark which has stopped measuring says so rather than
/// sitting quietly. A timeout is reported, never silently retried.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the client tolerates total silence from the host before it tears
/// the session down and reconnects. It matches the host's own peer-liveness
/// window: authenticated traffic in either direction refreshes the clock, and
/// the host sends a keepalive frame roughly every second even on a static
/// desktop, so this trips only on a genuinely dead transport -- not on a
/// decode stall (which [`STALL_DEADLINE`] reports separately). Without it a
/// client whose link drops mid-session waits forever at "pipeline stalled"
/// instead of reconnecting.
const PEER_LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether the host has been silent long enough to declare the session dead.
/// Pure so the boundary is unit-tested; the live check reads the age from the
/// session each control tick.
fn peer_liveness_expired(peer_silence: Duration, timeout: Duration) -> bool {
    peer_silence >= timeout
}

/// A process-local monotonic microsecond reading.
///
/// Monotonic but not *strictly* increasing: two calls in the same microsecond
/// return the same value. Use [`monotonic_input_stamp`] for anything the host
/// will order by.
fn monotonic_us() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

/// A strictly increasing stamp for input the host orders by.
///
/// Pointer motion travels on an unreliable, unordered path, and the host
/// decides which of two positions is newer by comparing stamps. Two positions
/// produced inside the same microsecond would compare equal, and the host
/// would then have to break the tie by some rule of its own -- which it does,
/// but a tie that never occurs is better than one resolved arbitrarily.
///
/// So a reading that has not advanced is bumped past the last one issued. The
/// stamp can therefore run slightly ahead of the clock under a burst, which
/// costs nothing: it is an ordering key, not a measurement.
fn monotonic_input_stamp() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = monotonic_us();
    // Relaxed is enough: this only has to be a distinct increasing value per
    // call, and the compare-exchange loop provides that on its own.
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let stamp = now.max(last.saturating_add(1));
        match LAST.compare_exchange_weak(last, stamp, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return stamp,
            Err(observed) => last = observed,
        }
    }
}

impl From<io::Error> for UiMessage {
    fn from(error: io::Error) -> Self {
        Self::Error(error.to_string())
    }
}

#[cfg(test)]
mod frame_dump_tests {
    use super::FrameDump;

    fn dump(directory: &std::path::Path, every: u64, limit: u64) -> FrameDump {
        FrameDump {
            directory: directory.to_path_buf(),
            every,
            limit,
            seen: 0,
            written: 0,
        }
    }

    #[test]
    fn ppm_carries_the_pixels_in_red_green_blue_order() {
        let directory =
            std::env::temp_dir().join(format!("openstream-dump-order-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let path = directory.join("one.ppm");
        // A single pixel packed the way the decoder packs BGRA: blue in the
        // low byte, red in bits 16-23.
        FrameDump::write_ppm(&path, 1, 1, &[0x00_11_22_33]).expect("write");
        let written = std::fs::read(&path).expect("read back");
        assert_eq!(&written[..11], b"P6\n1 1\n255\n");
        assert_eq!(&written[11..], &[0x11, 0x22, 0x33]);
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn sampling_keeps_one_frame_in_every_n_and_stops_at_the_limit() {
        let directory =
            std::env::temp_dir().join(format!("openstream-dump-cadence-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let mut dump = dump(&directory, 3, 2);
        for _ in 0..12 {
            dump.offer(1, 1, &[0]);
        }
        // Frames 0 and 3 are written; the limit stops 6 and 9 rather than
        // letting a long session fill the disk.
        assert_eq!(dump.written, 2);
        assert_eq!(dump.seen, 12);
        assert!(directory.join("frame-000000.ppm").exists());
        assert!(directory.join("frame-000003.ppm").exists());
        assert!(!directory.join("frame-000006.ppm").exists());
        std::fs::remove_dir_all(&directory).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRITICAL_UI_QUEUE_CAPACITY, ClientClock, ClientTelemetry, Duration, HEALTHY_SESSION,
        InputReceiver, InputSender, PEER_LIVENESS_TIMEOUT, PROBE_TIMEOUT, PresentedRect,
        ProbeAction, SessionProgress, TerminalError, UiInput, UiMessage, UiReceiver, UiSender,
        axis_value, cycled_display, decoder_args, discard_stale_input, gamepad_axis_index,
        gamepad_button_index, is_retryable, keyboard_usages, offer_decoded_frame,
        peer_liveness_expired, presented_rect, selected_display_index, stream_pointer_position,
        zero_copy_available,
    };
    use gilrs::{Axis, Button};
    use minifb::Key;
    use openstream_media::displays::{Display, PRIMARY_FLAG, SELECTED_FLAG};
    use openstream_media::frame_age::{DecodedFrame, DecodedFrameSeq, FrameAgeRecord, FrameOffer};
    use openstream_media::latency::Stamp;
    use openstream_media::latest_frame::latest_frame;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A surface frame carries no pixels, so handing one to the software
    /// presenter would show black. Both halves are required, and asking for
    /// zero-copy is never enough on its own.
    #[test]
    fn zero_copy_needs_both_the_opt_in_and_a_native_presenter() {
        assert!(zero_copy_available(true, true));
        assert!(!zero_copy_available(true, false));
        assert!(!zero_copy_available(false, true));
        assert!(!zero_copy_available(false, false));
    }

    #[test]
    fn peer_liveness_trips_only_at_or_past_the_timeout() {
        // Fresh and merely-slow sessions survive; true silence trips. The
        // host keepalive (~1 Hz) keeps a healthy client well under this even
        // on a static desktop, so the boundary is what matters.
        assert!(!peer_liveness_expired(
            Duration::from_secs(0),
            PEER_LIVENESS_TIMEOUT
        ));
        assert!(!peer_liveness_expired(
            PEER_LIVENESS_TIMEOUT - Duration::from_millis(1),
            PEER_LIVENESS_TIMEOUT
        ));
        assert!(peer_liveness_expired(
            PEER_LIVENESS_TIMEOUT,
            PEER_LIVENESS_TIMEOUT
        ));
        assert!(peer_liveness_expired(
            PEER_LIVENESS_TIMEOUT + Duration::from_secs(45),
            PEER_LIVENESS_TIMEOUT
        ));
    }

    #[test]
    fn gamepad_layout_is_stable_across_platform_backends() {
        assert_eq!(gamepad_button_index(Button::South), Some(0));
        assert_eq!(gamepad_button_index(Button::East), Some(1));
        assert_eq!(gamepad_button_index(Button::North), Some(2));
        assert_eq!(gamepad_button_index(Button::West), Some(3));
        assert_eq!(gamepad_button_index(Button::DPadRight), Some(14));
        assert_eq!(gamepad_button_index(Button::Unknown), None);
        assert_eq!(gamepad_axis_index(Axis::LeftStickX), Some(0));
        assert_eq!(gamepad_axis_index(Axis::RightZ), Some(5));
        assert_eq!(gamepad_axis_index(Axis::Unknown), None);
    }

    #[test]
    fn gamepad_axes_are_clamped_to_signed_16_bit_units() {
        assert_eq!(axis_value(-2.0), -32_767);
        assert_eq!(axis_value(-0.5), -16_384);
        assert_eq!(axis_value(0.0), 0);
        assert_eq!(axis_value(0.5), 16_384);
        assert_eq!(axis_value(2.0), 32_767);
    }

    #[test]
    fn keyboard_map_uses_usb_hid_usages() {
        assert!(keyboard_usages().contains(&(Key::A, 0x04)));
        assert!(keyboard_usages().contains(&(Key::Enter, 0x28)));
        assert!(keyboard_usages().contains(&(Key::LeftCtrl, 0xe0)));
        assert!(!keyboard_usages().iter().any(|(_, usage)| *usage == 0));
    }

    #[test]
    fn monitor_selection_prefers_the_host_selected_output() {
        let displays = vec![
            Display {
                id: 10,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                flags: PRIMARY_FLAG,
            },
            Display {
                id: 20,
                x: 1920,
                y: 0,
                width: 1280,
                height: 1024,
                flags: SELECTED_FLAG,
            },
        ];
        assert_eq!(selected_display_index(&displays), Some(1));
        assert_eq!(cycled_display(&displays, Some(1), true), Some((0, 10)));
        assert_eq!(cycled_display(&displays, Some(0), false), Some((1, 20)));
        assert_eq!(cycled_display(&[], None, true), None);
    }

    #[test]
    fn critical_input_survives_a_full_normal_queue() {
        // A one-slot normal lane, so the second ordinary event is
        // guaranteed to hit backpressure and the critical lane still has to
        // get through.
        let (sender, mut receiver) = super::input_channels(1);
        let event = UiInput::Event(openstream_media::input::InputEvent::release(1));
        assert!(sender.try_send(event).is_ok());
        assert!(
            sender
                .try_send(UiInput::Event(
                    openstream_media::input::InputEvent::release(2)
                ))
                .is_err()
        );
        assert!(sender.try_send(UiInput::Release).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(UiInput::Release)));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn critical_ui_state_survives_a_full_frame_queue() {
        let (normal_tx, normal_rx) = mpsc::sync_channel(1);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let (frame_tx, frame_rx) = latest_frame();
        let sender = UiSender {
            normal: normal_tx,
            critical: critical_tx,
            frames: frame_tx,
        };
        let receiver = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
            frames: frame_rx,
        };
        assert!(sender.send_frame(test_frame(0)).delivered());
        assert!(sender.send(UiMessage::End).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(UiMessage::End)));
    }

    /// The window closes on `Disconnected`, so that outcome must only appear
    /// once there is genuinely nothing left to show.
    ///
    /// The worker's `UiSender` drops only when the worker has returned for
    /// good -- it owns the reconnect loop -- and the window treats that as the
    /// end of the run. Before it can, every message already handed over has to
    /// come out: a terminal error on the critical lane and the last decoded
    /// picture both outrank the lane that reports the disconnect.
    #[test]
    fn a_dropped_worker_reports_disconnected_only_after_its_last_message() {
        let (normal_tx, normal_rx) = mpsc::sync_channel(4);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let (frame_tx, frame_rx) = latest_frame();
        let sender = UiSender {
            normal: normal_tx,
            critical: critical_tx,
            frames: frame_tx,
        };
        let receiver = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
            frames: frame_rx,
        };

        assert!(sender.send_frame(test_frame(0)).delivered());
        assert!(sender.send(UiMessage::End).is_ok());
        drop(sender);

        assert!(matches!(receiver.try_recv(), Ok(UiMessage::End)));
        assert!(matches!(receiver.try_recv(), Ok(UiMessage::Frame(_))));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    fn input_channels() -> (InputSender, InputReceiver) {
        super::input_channels(64)
    }

    fn key_event(down: bool) -> UiInput {
        UiInput::Event(openstream_media::input::InputEvent::keyboard(
            0x1a, 0, down, 1,
        ))
    }

    /// Input typed while the worker is waiting out a reconnect backoff must
    /// never reach the session that comes back.
    ///
    /// Nothing drains the queue while the worker sleeps, and the session
    /// loop drains it in full the moment it starts, so without this a key
    /// pressed and released during the wait is delivered to a session the
    /// operator never typed into -- and a button still held when the
    /// connection dropped arrives with no matching release.
    #[test]
    fn input_queued_during_a_reconnect_is_discarded_before_the_next_session() {
        let (sender, mut receiver) = input_channels();
        assert!(sender.try_send(key_event(true)).is_ok());
        assert!(sender.try_send(key_event(false)).is_ok());
        assert!(sender.try_send(UiInput::SelectDisplay(2)).is_ok());

        assert!(!discard_stale_input(&mut receiver), "no stop was requested");
        assert!(
            receiver.try_recv().is_err(),
            "the next session must start from an empty input queue"
        );
    }

    /// An explicit stop is the one thing the discard must not swallow:
    /// closing the window during a backoff wait has to end the worker
    /// rather than start another attempt.
    #[test]
    fn a_stop_requested_during_a_reconnect_survives_the_discard() {
        let (sender, mut receiver) = input_channels();
        assert!(sender.try_send(key_event(true)).is_ok());
        assert!(sender.try_send(UiInput::Stop).is_ok());

        assert!(discard_stale_input(&mut receiver));
        assert!(receiver.try_recv().is_err());
    }

    /// The reconnect notice shares the priority lane with the other
    /// lifecycle messages: the window has to see it even behind a backlog
    /// of stale frames, because it is what stops input being sampled.
    #[test]
    fn a_reconnect_notice_survives_a_full_frame_queue() {
        let (normal_tx, normal_rx) = mpsc::sync_channel(1);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let (frame_tx, frame_rx) = latest_frame();
        let sender = UiSender {
            normal: normal_tx,
            critical: critical_tx,
            frames: frame_tx,
        };
        let receiver = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
            frames: frame_rx,
        };
        assert!(sender.send_frame(test_frame(0)).delivered());
        assert!(
            sender
                .send(UiMessage::Reconnecting {
                    attempt: 1,
                    delay_ms: 1_000,
                })
                .is_ok()
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(UiMessage::Reconnecting { attempt: 1, .. })
        ));
    }

    /// A configuration fault fails identically on every attempt, so it must
    /// not consume the retry budget or make the operator wait out the whole
    /// backoff schedule before seeing what is wrong.
    #[test]
    fn a_configuration_fault_is_not_retried() {
        let terminal: Box<dyn std::error::Error + Send + Sync> =
            TerminalError::new("missing pairing file").into();
        assert!(!is_retryable(terminal.as_ref()));
        assert!(terminal.to_string().contains("missing pairing file"));

        let transport: Box<dyn std::error::Error + Send + Sync> = "connection reset".into();
        assert!(is_retryable(transport.as_ref()));
    }

    /// Only a session that negotiated *and* then stayed up forgives earlier
    /// failures. A peer that accepts the handshake and drops immediately
    /// would otherwise refresh the budget on every attempt and retry at the
    /// floor delay forever.
    #[test]
    fn only_a_session_that_stayed_up_forgives_earlier_failures() {
        let never = SessionProgress::default();
        assert!(!never.was_healthy());

        let mut just_negotiated = SessionProgress::default();
        just_negotiated.negotiated();
        assert!(!just_negotiated.was_healthy());

        let long_lived = SessionProgress {
            negotiated_at: Instant::now().checked_sub(HEALTHY_SESSION),
        };
        assert!(long_lived.was_healthy());
    }

    /// Handing a decoded frame to a window that is behind must return
    /// immediately, never park the caller.
    ///
    /// The task that calls this is the only drain for the decoder's stdout,
    /// and the loop that empties this channel is the same loop that feeds
    /// the decoder's stdin. If a full channel parks the caller, the
    /// decoder's output pipe fills, the decoder stops reading its input,
    /// the network loop blocks writing an access unit, and nothing ever
    /// drains the channel again -- a deadlock whose symptom is a window
    /// that stays blank while the socket backs up.
    #[tokio::test]
    async fn a_frame_the_window_cannot_keep_up_with_replaces_the_stale_one() {
        let (sender, receiver) = latest_frame::<DecodedFrame>();
        assert_eq!(
            offer_decoded_frame(&sender, test_frame(0)),
            FrameOffer::Enqueued
        );

        // The slot is occupied. This must still return, and promptly, and it
        // must keep the *newer* picture.
        let replaced = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            offer_decoded_frame(&sender, test_frame(1))
        })
        .await
        .expect("offering a frame must not park the decoder reader");
        assert_eq!(replaced, FrameOffer::ReplacedOlder);
        assert!(replaced.delivered(), "the newer frame is the one shown");
        assert!(!replaced.should_stop());

        assert_eq!(
            offer_decoded_frame(&sender, test_frame(2)),
            FrameOffer::ReplacedOlder
        );
        assert_eq!(
            receiver.take().map(|frame| frame.seq()),
            Some(seq(2)),
            "the consumer sees the newest picture, not the oldest queued one"
        );
        assert!(receiver.take().is_none(), "and nothing stale behind it");

        // A closed window ends the reader.
        drop(receiver);
        assert_eq!(
            offer_decoded_frame(&sender, test_frame(3)),
            FrameOffer::Closed
        );
        assert!(offer_decoded_frame(&sender, test_frame(4)).should_stop());
    }

    /// The window's own queue drops the newest frame too, and says which of
    /// the two failures happened.
    ///
    /// `UiSender::send` folds "full" and "disconnected" into `Err(())`,
    /// which is fine for a metrics line and wrong for a frame: one means the
    /// window is behind and this picture is lost, the other means there is
    /// no window. `send_frame` distinguishes them so the counters can.
    #[test]
    fn the_window_mailbox_keeps_the_newest_frame_and_names_the_failure() {
        let (normal_tx, normal_rx) = mpsc::sync_channel(2);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let (frame_tx, frame_rx) = latest_frame();
        let sender = UiSender {
            normal: normal_tx,
            critical: critical_tx,
            frames: frame_tx,
        };
        let receiver = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
            frames: frame_rx,
        };

        assert_eq!(sender.send_frame(test_frame(0)), FrameOffer::Enqueued);
        // Occupied. The older picture is the one displaced, because it is
        // already out of date by the time a newer one exists.
        assert_eq!(sender.send_frame(test_frame(1)), FrameOffer::ReplacedOlder);
        assert_eq!(sender.send_frame(test_frame(2)), FrameOffer::ReplacedOlder);

        let shown = match receiver.try_recv() {
            Ok(UiMessage::Frame(frame)) => frame.seq(),
            other => panic!("expected a frame, got {other:?}"),
        };
        assert_eq!(
            shown,
            seq(2),
            "the window must be shown the newest picture, not a recording of \
             the recent past"
        );
        assert!(
            receiver.try_recv().is_err(),
            "no stale frames are queued behind it"
        );

        drop(receiver);
        assert_eq!(sender.send_frame(test_frame(3)), FrameOffer::Closed);
    }

    /// Filling both queues at once: every decoded picture is accounted for
    /// either as presented or as dropped, and the span histograms alone
    /// would have shown none of it.
    #[tokio::test]
    async fn frames_lost_in_either_queue_are_still_counted() {
        let mut record = FrameAgeRecord::new();
        let (decoder_tx, decoder_rx) = latest_frame::<DecodedFrame>();
        let (normal_tx, normal_rx) = mpsc::sync_channel(2);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let (ui_frame_tx, ui_frame_rx) = latest_frame();
        let ui_tx = UiSender {
            normal: normal_tx,
            critical: critical_tx,
            frames: ui_frame_tx,
        };
        let ui_rx = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
            frames: ui_frame_rx,
        };

        // Nothing drains either queue: decode ten pictures into a client
        // that has stopped consuming entirely.
        for _ in 0..10 {
            let seq = record.frame_decoded();
            let frame = DecodedFrame::new(seq, Stamp::now(), Stamp::now(), 1, 1, vec![0]);
            record.decoder_queue_offer(offer_decoded_frame(&decoder_tx, frame));
        }
        // Nothing is lost at the offer: a mailbox always accepts. What it
        // records instead is how far behind the consumer was, which is the
        // measurement that actually matters.
        assert_eq!(record.decoder_queue().enqueued, 1);
        assert_eq!(record.decoder_queue().replaced_older, 9);
        assert_eq!(record.decoder_queue().dropped_newest, 0);

        // Drain the mailbox into the window's, which holds one too.
        while let Some(mut frame) = decoder_rx.take() {
            let taken_at = Stamp::now();
            record.decoder_queue_consumed(&frame, taken_at);
            frame.entering_ui_queue(taken_at);
            record.ui_queue_offer(ui_tx.send_frame(frame));
        }
        assert_eq!(record.ui_queue().enqueued, 1);

        // The window consumes one and presents it, then the session ends.
        if let Ok(UiMessage::Frame(frame)) = ui_rx.try_recv() {
            let at = Stamp::now();
            record.ui_queue_consumed(&frame, at);
            record.present_submitted(&frame, at);
        } else {
            panic!("expected a queued frame");
        }
        record.session_ended();

        assert_eq!(record.decoded_frames(), 10);
        assert_eq!(record.new_frames_present_submitted(), 1);
        // Nine pictures were decoded and never seen. The one that made it is
        // the *newest*, which is the point of the change -- but it still has
        // a healthy-looking span, which is precisely why the counters have to
        // be published next to it.
        assert_eq!(record.frames_never_presented(), 9);
        assert_eq!(record.decoded_to_present_submit().count(), 1);
        assert_eq!(record.overlay_fragment(), "shown 1/10");
    }

    /// The probe is a benchmark facility and must be inert unless asked
    /// for: it presses a key on the host every half second.
    #[test]
    fn the_interaction_probe_is_off_unless_an_origin_is_configured() {
        let mut telemetry = ClientTelemetry::new(None);
        assert!(telemetry.probe.is_none());
        assert_eq!(telemetry.next_probe_id(), None);

        let frame = test_frame(0);
        assert_eq!(telemetry.marker_decoded(&frame, Stamp::now()), None);
        assert_eq!(telemetry.marker_in(&frame), None, "no probe, no detection");
        telemetry.marker_present_submitted(None, Stamp::now());

        let report = telemetry.report(Stamp::now()).join("\n");
        assert!(report.contains("decoded_frames="), "{report}");
        assert!(!report.contains("interaction_"), "{report}");
    }

    /// The next id is one past whatever the helper is currently showing.
    /// Until the marker has been read once there is no id to send, because
    /// the client does not know where the helper's counter is.
    #[test]
    fn the_next_probe_id_follows_the_marker_the_client_last_read() {
        let origin = (0, 0);
        let mut telemetry = ClientTelemetry::new(Some(origin));
        assert_eq!(
            telemetry.next_probe_id(),
            None,
            "nothing to send before the marker has been located"
        );

        let (width, height) = (256, 192);
        let mut pixels = vec![0_u32; width * height];
        openstream_media::probe::render(&mut pixels, width, height, origin, 41);
        let frame = DecodedFrame::new(seq(0), Stamp::now(), Stamp::now(), width, height, pixels);

        assert_eq!(telemetry.marker_decoded(&frame, Stamp::now()), Some(41));
        assert_eq!(telemetry.next_probe_id(), Some(42));

        let report = telemetry.report(Stamp::now()).join("\n");
        assert!(report.contains("interaction_to_decoded"), "{report}");
        // Named for what it measures. Nothing here has seen a photon.
        assert!(!report.contains("photon"), "{report}");
    }

    /// A press on one tick, its release on the next, and never the same id
    /// twice.
    ///
    /// The first rig run sent press and release back to back and re-sent the
    /// same id whenever the marker had not moved. The helper detects a
    /// keypress as a down transition between two polls of its event loop, so
    /// the pair collapsed into nothing three times out of four; and when a
    /// later keystroke did land, the match found the *oldest* outstanding
    /// entry carrying that id -- reporting a ten-second interaction latency
    /// that was really a lost keystroke and a stale stamp.
    #[test]
    fn a_probe_presses_on_one_tick_and_releases_on_the_next() {
        let origin = (0, 0);
        let mut telemetry = ClientTelemetry::new(Some(origin));
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Idle,
            "nothing to press before the marker has been read"
        );

        telemetry.marker_decoded(&marked_frame(origin, 5), Stamp::now());
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Press
        );
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Release,
            "the release is a separate tick, so the helper sees a transition"
        );
        // The marker has not moved, so there is nothing new to send: the
        // same id must not go out twice.
        assert_eq!(telemetry.next_probe_action(Stamp::now()), ProbeAction::Idle);
        assert_eq!(telemetry.next_probe_action(Stamp::now()), ProbeAction::Idle);

        // The helper received it and advanced. Now there is a new id.
        telemetry.marker_decoded(&marked_frame(origin, 6), Stamp::now());
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Press
        );

        let state = telemetry.probe.as_ref().expect("probe enabled");
        assert_eq!(state.probe.sent_count(), 2, "two probes, not four");
    }

    /// The key must not stay held when the stream stops advancing.
    #[test]
    fn a_held_probe_key_is_released_even_when_the_marker_stops_moving() {
        let origin = (0, 0);
        let mut telemetry = ClientTelemetry::new(Some(origin));
        telemetry.marker_decoded(&marked_frame(origin, 1), Stamp::now());
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Press
        );
        // The host never advances the marker again.
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Release
        );
        assert_eq!(telemetry.next_probe_action(Stamp::now()), ProbeAction::Idle);
        assert!(!telemetry.probe.as_ref().expect("probe enabled").key_down);
    }

    /// A probe outstanding when a session drops must not be matched by a
    /// marker from the session that reconnects.
    ///
    /// `ClientTelemetry` outlives the reconnect loop, so without an explicit
    /// reset the next session's first marker would complete a probe stamped
    /// before the disconnection -- reporting the downtime as interaction
    /// latency, in the same histogram as the real measurements.
    #[test]
    fn a_session_boundary_ends_every_outstanding_probe() {
        let origin = (0, 0);
        let mut telemetry = ClientTelemetry::new(Some(origin));
        telemetry.marker_decoded(&marked_frame(origin, 3), Stamp::now());
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Press
        );
        assert_eq!(
            telemetry.probe.as_ref().expect("probe").probe.outstanding(),
            1
        );

        telemetry.session_ended();

        let state = telemetry.probe.as_ref().expect("probe");
        assert_eq!(state.probe.outstanding(), 0, "nothing survives the drop");
        assert_eq!(state.probe.abandoned_count(), 1);
        assert_eq!(state.last_seen, None, "the marker must be read again");
        assert!(
            !state.key_down,
            "the host's key state did not survive either"
        );
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Idle,
            "no id to send until a marker is read in the new session"
        );

        // The next session's marker starts a fresh measurement, and cannot
        // complete the one abandoned above.
        telemetry.marker_decoded(&marked_frame(origin, 4), Stamp::now());
        assert_eq!(
            telemetry.next_probe_action(Stamp::now()),
            ProbeAction::Press
        );
        assert_eq!(
            telemetry
                .probe
                .as_ref()
                .expect("probe")
                .probe
                .to_decoded()
                .count(),
            0,
            "no span was manufactured across the reconnect"
        );
    }

    /// A probe timeout invalidates the session's interaction measurement
    /// rather than re-arming the same id.
    ///
    /// Re-arming looks safe and is not. The input event travels over the
    /// reliable control channel, which retransmits, so a benchmark timeout
    /// says nothing about whether that record is still in flight. If the
    /// delayed event lands after a new probe for the same id was stamped,
    /// the client credits an old keystroke against a new timestamp and
    /// reports an impossibly fast interaction. The client cannot tell that
    /// apart from a real one, so it stops measuring and says so.
    #[test]
    fn a_probe_timeout_invalidates_the_session_rather_than_re_arming() {
        let origin = (0, 0);
        let base = Instant::now();
        let at = |ms: u64| Stamp::<ClientClock>::from_instant(base + Duration::from_millis(ms));
        let mut telemetry = ClientTelemetry::new(Some(origin));

        telemetry.marker_decoded(&marked_frame(origin, 7), at(0));
        assert_eq!(telemetry.next_probe_action(at(0)), ProbeAction::Press);
        assert_eq!(telemetry.next_probe_action(at(250)), ProbeAction::Release);
        // The helper never received it, so the marker never moved.
        assert_eq!(telemetry.next_probe_action(at(500)), ProbeAction::Idle);
        assert_eq!(telemetry.next_probe_action(at(1_000)), ProbeAction::Idle);

        // Past the timeout the probe is given up on and nothing new goes
        // out: a delayed reliable input record may still be travelling, and
        // crediting it against a fresh stamp would manufacture a fast
        // sample rather than a slow one.
        let after = u64::try_from(PROBE_TIMEOUT.as_millis()).expect("small") + 100;
        assert_eq!(
            telemetry.next_probe_action(at(after)),
            ProbeAction::Idle,
            "the key was already released on the previous tick"
        );
        assert_eq!(
            telemetry.next_probe_action(at(after + 500)),
            ProbeAction::Idle
        );

        let state = telemetry.probe.as_ref().expect("probe");
        assert_eq!(state.timeouts, 1, "the loss is counted, not hidden");
        assert_eq!(state.probe.abandoned_count(), 1);
        assert_eq!(state.probe.outstanding(), 0, "nothing is left armed");
        assert!(state.invalidated.is_some());

        // Even a marker advancing afterwards must not restart measurement.
        telemetry.marker_decoded(&marked_frame(origin, 8), at(after + 600));
        assert_eq!(
            telemetry.next_probe_action(at(after + 700)),
            ProbeAction::Idle,
            "a late marker does not make the session measurable again"
        );

        let report = telemetry.report(Stamp::now()).join("\n");
        assert!(report.contains("timeouts=1"), "{report}");
        assert!(
            report.contains("probe INVALID:"),
            "a run that stopped measuring must say so: {report}"
        );
    }

    /// A reconnect is a fresh measurement: nothing in flight from the old
    /// session can reach the new helper's marker state.
    #[test]
    fn a_new_session_can_measure_again_after_an_invalidating_timeout() {
        let origin = (0, 0);
        let base = Instant::now();
        let at = |ms: u64| Stamp::<ClientClock>::from_instant(base + Duration::from_millis(ms));
        let mut telemetry = ClientTelemetry::new(Some(origin));

        telemetry.marker_decoded(&marked_frame(origin, 1), at(0));
        assert_eq!(telemetry.next_probe_action(at(0)), ProbeAction::Press);
        let after = u64::try_from(PROBE_TIMEOUT.as_millis()).expect("small") + 100;
        // The key was still held, so it is released before going idle: an
        // invalidated benchmark must not leave a key down on the host.
        assert_eq!(telemetry.next_probe_action(at(after)), ProbeAction::Release);
        assert_eq!(
            telemetry.next_probe_action(at(after + 10)),
            ProbeAction::Idle
        );
        assert!(
            telemetry
                .probe
                .as_ref()
                .expect("probe")
                .invalidated
                .is_some()
        );

        telemetry.session_ended();
        assert!(
            telemetry
                .probe
                .as_ref()
                .expect("probe")
                .invalidated
                .is_none()
        );

        telemetry.marker_decoded(&marked_frame(origin, 20), at(after + 500));
        assert_eq!(
            telemetry.next_probe_action(at(after + 600)),
            ProbeAction::Press
        );
    }

    fn marked_frame(origin: (usize, usize), probe_id: u16) -> DecodedFrame {
        let (width, height) = (256, 192);
        let mut pixels = vec![0_u32; width * height];
        openstream_media::probe::render(&mut pixels, width, height, origin, probe_id);
        DecodedFrame::new(seq(0), Stamp::now(), Stamp::now(), width, height, pixels)
    }

    /// A frame carrying no marker is the normal case between probes, and
    /// must not disturb the counter or be reported as a sighting.
    #[test]
    fn a_frame_without_a_marker_leaves_the_probe_alone() {
        let origin = (0, 0);
        let mut telemetry = ClientTelemetry::new(Some(origin));
        let (width, height) = (256, 192);
        let mut pixels = vec![0_u32; width * height];
        openstream_media::probe::render(&mut pixels, width, height, origin, 9);
        let marked = DecodedFrame::new(seq(0), Stamp::now(), Stamp::now(), width, height, pixels);
        assert_eq!(telemetry.marker_decoded(&marked, Stamp::now()), Some(9));

        let blank = DecodedFrame::new(
            seq(1),
            Stamp::now(),
            Stamp::now(),
            width,
            height,
            vec![0; width * height],
        );
        assert_eq!(telemetry.marker_decoded(&blank, Stamp::now()), None);
        assert_eq!(
            telemetry.next_probe_id(),
            Some(10),
            "an unmarked frame is not a new sighting"
        );
    }

    fn seq(index: u64) -> DecodedFrameSeq {
        (0..index).fold(DecodedFrameSeq::FIRST, |current, _| current.next())
    }

    fn test_frame(index: u64) -> DecodedFrame {
        DecodedFrame::new(seq(index), Stamp::now(), Stamp::now(), 1, 1, vec![0])
    }

    /// A stretching presentation puts the picture over the whole window.
    #[test]
    fn a_stretched_picture_fills_the_window() {
        let rect = presented_rect((1280, 720), (1920, 1080), false);
        assert_eq!(
            rect,
            PresentedRect {
                x: 0,
                y: 0,
                width: 1280,
                height: 720
            }
        );
    }

    /// A 16:9 stream in a 16:10 window is width-limited, so the bars are
    /// above and below.
    #[test]
    fn a_16_9_stream_in_a_16_10_window_is_letterboxed_vertically() {
        let rect = presented_rect((2560, 1600), (1920, 1080), true);
        assert_eq!(
            rect,
            PresentedRect {
                x: 0,
                y: 80,
                width: 2560,
                height: 1440
            },
            "2560x1440 of picture with an 80px bar above and below"
        );
    }

    /// A 16:9 stream in an ultrawide window is height-limited, so the bars
    /// are left and right.
    #[test]
    fn a_16_9_stream_in_an_ultrawide_window_is_pillarboxed() {
        let rect = presented_rect((3440, 1440), (1920, 1080), true);
        assert_eq!(
            rect,
            PresentedRect {
                x: (3440 - 2560) / 2,
                y: 0,
                width: 2560,
                height: 1440
            }
        );
    }

    /// The top of the picture is the top of the *picture*, not the window.
    ///
    /// Mapping against the whole window put a pointer at the first row of
    /// video at y=54 of 1080 instead of y=0 -- the height of the bar,
    /// expressed in stream pixels. That is the bug this mapping exists to
    /// avoid, and it returns for any window whose aspect ratio differs from
    /// the stream's.
    #[test]
    fn the_picture_edges_map_to_the_stream_edges_when_letterboxed() {
        let stream = (1920, 1080);
        let rect = presented_rect((2560, 1600), stream, true);

        // First and last row of actual picture.
        assert_eq!(stream_pointer_position(rect, stream, (0.0, 80.0)), (0, 0));
        assert_eq!(
            stream_pointer_position(rect, stream, (2560.0, 1520.0)),
            (1919, 1079)
        );
        // All four corners of the image.
        assert_eq!(stream_pointer_position(rect, stream, (0.0, 80.0)), (0, 0));
        assert_eq!(
            stream_pointer_position(rect, stream, (2560.0, 80.0)),
            (1919, 0)
        );
        assert_eq!(
            stream_pointer_position(rect, stream, (0.0, 1520.0)),
            (0, 1079)
        );
        // The centre of the picture is the centre of the stream.
        assert_eq!(
            stream_pointer_position(rect, stream, (1280.0, 800.0)),
            (960, 540)
        );
    }

    /// A pointer over a bar is outside the picture. It clamps to the nearest
    /// edge rather than reporting a position the picture does not have.
    #[test]
    fn a_pointer_over_a_letterbox_bar_clamps_to_the_picture() {
        let stream = (1920, 1080);
        let vertical = presented_rect((2560, 1600), stream, true);
        // Above the top bar and below the bottom one.
        assert_eq!(
            stream_pointer_position(vertical, stream, (500.0, 0.0)),
            (375, 0)
        );
        assert_eq!(
            stream_pointer_position(vertical, stream, (500.0, 1599.0)),
            (375, 1079)
        );

        let horizontal = presented_rect((3440, 1440), stream, true);
        // Left of the left bar and right of the right one.
        assert_eq!(
            stream_pointer_position(horizontal, stream, (0.0, 720.0)),
            (0, 540)
        );
        assert_eq!(
            stream_pointer_position(horizontal, stream, (3439.0, 720.0)),
            (1919, 540)
        );
    }

    /// The pointer must be reported where it is in the *streamed image*,
    /// not in the window.
    ///
    /// The host scales absolute coordinates out of the stream's pixel space
    /// and onto wherever that image sits on its desktop. The client sent
    /// relative deltas instead, so the remote cursor drifted away from the
    /// local one and never came back -- and any window size other than the
    /// stream size made the drift worse with every movement.
    #[test]
    fn a_pointer_is_reported_in_the_streamed_images_own_pixels() {
        let stream = (1920, 1080);

        let small = presented_rect((1280, 720), stream, false);
        // A window smaller than the stream: the centre is still the centre.
        assert_eq!(
            stream_pointer_position(small, stream, (640.0, 360.0)),
            (960, 540)
        );

        // Corners map to corners, and the far edge is the last pixel rather
        // than one past it.
        assert_eq!(stream_pointer_position(small, stream, (0.0, 0.0)), (0, 0));
        assert_eq!(
            stream_pointer_position(small, stream, (1280.0, 720.0)),
            (1919, 1079)
        );

        // A window larger than the stream scales the other way.
        let large = presented_rect((3840, 2160), stream, false);
        assert_eq!(
            stream_pointer_position(large, stream, (1920.0, 1080.0)),
            (960, 540)
        );

        // A window matching the stream is the identity.
        let exact = presented_rect(stream, stream, false);
        assert_eq!(
            stream_pointer_position(exact, stream, (123.0, 456.0)),
            (123, 456)
        );
    }

    /// Degenerate input must not panic or divide by zero.
    #[test]
    fn a_collapsed_window_reports_the_origin() {
        let collapsed = presented_rect((0, 0), (1920, 1080), false);
        assert_eq!(
            stream_pointer_position(collapsed, (1920, 1080), (10.0, 10.0)),
            (0, 0)
        );
        let no_stream = presented_rect((1280, 720), (0, 0), false);
        assert_eq!(
            stream_pointer_position(no_stream, (0, 0), (10.0, 10.0)),
            (0, 0)
        );
        // Some backends report a negative position while dragging out of
        // the window; it clamps rather than wrapping.
        let normal = presented_rect((1280, 720), (1920, 1080), false);
        assert_eq!(
            stream_pointer_position(normal, (1920, 1080), (-5.0, -5.0)),
            (0, 0)
        );
        // An aspect-preserving rect is never larger than the window.
        let rect = presented_rect((100, 100), (1920, 1080), true);
        assert!(rect.width <= 100 && rect.height <= 100);
    }

    /// The decoder must not be allowed to buffer frames ahead.
    ///
    /// Frame-level threading is libavcodec's default and holds output back
    /// so its workers can run ahead. These flags together recovered 553 ms
    /// of a measured 1,000 ms; how much of that is threading rather than
    /// the demuxer read-ahead was not measured separately.
    #[test]
    fn the_decoder_is_configured_for_low_delay() {
        let args = decoder_args("h264", 1920, 1080);
        let pair = |flag: &str, value: &str| {
            args.windows(2)
                .any(|window| window[0] == flag && window[1] == value)
        };
        assert!(
            pair("-thread_type", "slice"),
            "frame threading delays output by a frame per thread: {args:?}"
        );
        assert!(pair("-flags", "low_delay"), "{args:?}");
        assert!(pair("-fflags", "nobuffer"), "{args:?}");
        assert!(pair("-analyzeduration", "0"), "{args:?}");
        // The flags have to reach the demuxer, so they must come before -i.
        let input = args.iter().position(|arg| arg == "-i").expect("has input");
        let low_delay = args
            .iter()
            .position(|arg| arg == "low_delay")
            .expect("has low_delay");
        assert!(low_delay < input, "input options must precede -i: {args:?}");
    }

    #[test]
    fn videotoolbox_flags_reach_the_demuxer_and_ask_for_cpu_frames() {
        let args = super::decoder_args_with(super::DecodeAccel::VideoToolbox, "h264", 1920, 1080);
        let hwaccel = args
            .iter()
            .position(|arg| arg == "-hwaccel")
            .expect("hardware decode requested");
        assert_eq!(args[hwaccel + 1], "videotoolbox");
        let input = args.iter().position(|arg| arg == "-i").expect("has input");
        assert!(
            hwaccel < input,
            "input options must precede -i or FFmpeg ignores them: {args:?}"
        );
        // The pipeline scales and reads BGRA, which needs CPU frames. Asking
        // for hardware output would force a download filter for no gain.
        assert!(!args.iter().any(|arg| arg == "-hwaccel_output_format"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-pix_fmt" && w[1] == "bgra")
        );
    }

    #[test]
    fn the_software_decoder_asks_for_no_hardware() {
        let args = super::decoder_args_with(super::DecodeAccel::Software, "h264", 1920, 1080);
        assert!(!args.iter().any(|arg| arg == "-hwaccel"), "{args:?}");
    }

    #[test]
    fn the_low_delay_flags_survive_hardware_decode() {
        // The latency work these flags encode is not specific to the CPU
        // decoder, so selecting hardware must not quietly drop them.
        let args = super::decoder_args_with(super::DecodeAccel::VideoToolbox, "h264", 1920, 1080);
        for (flag, value) in [
            ("-flags", "low_delay"),
            ("-fflags", "nobuffer"),
            ("-analyzeduration", "0"),
        ] {
            assert!(
                args.windows(2).any(|w| w[0] == flag && w[1] == value),
                "{flag} {value} missing: {args:?}"
            );
        }
    }

    #[test]
    fn decoder_args_use_fps_mode_for_current_ffmpeg() {
        let args = decoder_args("h264", 1920, 1080);
        assert!(
            args.windows(2)
                .any(|window| { window[0] == "-fps_mode" && window[1] == "passthrough" })
        );
        assert!(!args.iter().any(|arg| arg == "-vsync"));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod native_wiring_tests {
    use super::*;
    use crate::test_fixtures::{access_units_by_aud, generate_h264};
    use std::sync::PoisonError;

    /// How long to wait for the first decoded picture.
    ///
    /// Generous on purpose. The first decode of a session pays for
    /// `VTDecompressionSessionCreate`, which is XPC-backed: on an unloaded
    /// machine it returns in milliseconds, and on a loaded one it has been
    /// measured here taking several seconds. A one-second budget passed for
    /// weeks and then failed every run once this machine was busy, which is
    /// the worst way for a test to be wrong -- it looks like the decoder
    /// broke. The wait is bounded so a genuine failure still fails, just not
    /// on a stopwatch tuned to an idle laptop.
    const FIRST_FRAME_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

    /// `ZERO_COPY_PRESENT` is process-wide, and these tests run in one process:
    /// a test that flips it would otherwise change the decoder mode under a
    /// test that is between storing the flag and building its decoder.
    static DECODER_MODE: Mutex<()> = Mutex::new(());

    /// Build a session decoder in a chosen mode, without letting the flag leak
    /// to another test.
    ///
    /// Synchronous on purpose: `build_session_decoder` reads the flag and
    /// hands the mode to its worker before it returns, so the whole critical
    /// section fits between one lock and one unlock with no await in it. The
    /// flag is restored before returning, whatever the result.
    fn build_decoder_in_mode(
        zero_copy: bool,
        frame_tx: LatestFramePublisher<DecodedFrame>,
        decoded_ready: Arc<tokio::sync::Notify>,
        telemetry: SharedTelemetry,
    ) -> Result<SessionDecoder, TerminalError> {
        let _mode = DECODER_MODE.lock().unwrap_or_else(PoisonError::into_inner);
        ZERO_COPY_PRESENT.store(zero_copy, Ordering::Relaxed);
        let decoder = build_session_decoder(
            decode_dispatch::DecodeBackend::VideoToolboxNative,
            "h264",
            160,
            120,
            160 * 120 * 4,
            frame_tx,
            decoded_ready,
            telemetry,
        );
        ZERO_COPY_PRESENT.store(false, Ordering::Relaxed);
        decoder
    }

    /// The wired native path end to end: build the native `SessionDecoder`, feed
    /// it real access units through `feed`, and confirm decoded frames reach the
    /// mailbox exactly as the ffmpeg reader would deliver them. Exercises
    /// `build_session_decoder`, the `SessionDecoder::Native` channel, the decoder
    /// thread, and `publish_decoded_picture` together.
    #[tokio::test]
    async fn native_session_decoder_publishes_to_the_mailbox() {
        let Some(stream) = generate_h264("testsrc2=size=160x120:rate=10", 6, 6) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);

        let telemetry: SharedTelemetry = Arc::new(Mutex::new(ClientTelemetry::new(None)));
        let (frame_tx, frame_rx) = latest_frame::<DecodedFrame>();
        let decoded_ready = Arc::new(tokio::sync::Notify::new());

        let mut decoder = build_decoder_in_mode(
            false,
            frame_tx,
            Arc::clone(&decoded_ready),
            Arc::clone(&telemetry),
        )
        .expect("build native session decoder");

        for (index, au) in access_units.iter().enumerate() {
            decoder
                .feed(au, index as u64 * 100_000, index == 0)
                .await
                .expect("feed access unit");
        }

        // The decoder runs on its own thread; wait for frames to land.
        let mut frames = 0;
        let deadline = std::time::Instant::now() + FIRST_FRAME_BUDGET;
        while std::time::Instant::now() < deadline {
            while let Some(frame) = frame_rx.take() {
                assert_eq!(frame.width(), 160);
                assert_eq!(frame.height(), 120);
                // The window chooses its path on this being absent, so the
                // default decode must not look like a zero-copy frame.
                assert!(
                    frame.surface().is_none(),
                    "the CPU decode path must not attach a GPU surface"
                );
                assert_eq!(frame.pixels().len(), 160 * 120);
                frames += 1;
            }
            // One is the whole claim, and one is all that can be relied on:
            // the mailbox keeps only the newest picture, so a decoder that
            // outruns this loop has most of its output replaced before it is
            // ever taken. Waiting for more would burn the budget above for
            // frames that are working exactly as designed.
            if frames >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            frames >= 1,
            "native SessionDecoder published no frames to the mailbox within {FIRST_FRAME_BUDGET:?}"
        );
    }

    /// The zero-copy path through the same wiring the session uses: with
    /// `ZERO_COPY_PRESENT` latched, `build_session_decoder` must produce a
    /// worker that decodes into GPU surfaces and publishes them to the real
    /// client mailbox with no pixels -- and the surface that comes back out of
    /// that mailbox must still import into a `wgpu::Texture`.
    ///
    /// This is the seam the window depends on. The offscreen tests in `vt_gpu`
    /// prove a `CVPixelBuffer` imports and renders correctly; what they cannot
    /// prove is that the surface survives `DecodedFrame`, `FrameSurface` and
    /// the latest-frame mailbox as something the presenter can still use.
    /// Presenting it on a live window surface needs a window and is not
    /// claimed here.
    #[tokio::test]
    async fn the_zero_copy_path_publishes_surfaces_that_still_import() {
        let Some(stream) = generate_h264("color=c=0x0000FF:size=160x120:rate=10", 6, 6) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);

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
        let (device, _queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))
                .expect("request device");
        let importer = vt_gpu::MetalTextureImporter::new(&device).expect("create importer");

        let telemetry: SharedTelemetry = Arc::new(Mutex::new(ClientTelemetry::new(None)));
        let (frame_tx, frame_rx) = latest_frame::<DecodedFrame>();
        let decoded_ready = Arc::new(tokio::sync::Notify::new());
        let mut decoder = build_decoder_in_mode(
            true,
            frame_tx,
            Arc::clone(&decoded_ready),
            Arc::clone(&telemetry),
        )
        .expect("build native session decoder");

        for (index, au) in access_units.iter().enumerate() {
            decoder
                .feed(au, index as u64 * 100_000, index == 0)
                .await
                .expect("feed access unit");
        }

        let mut imported = 0;
        let deadline = std::time::Instant::now() + FIRST_FRAME_BUDGET;
        while std::time::Instant::now() < deadline {
            while let Some(frame) = frame_rx.take() {
                let surface = frame
                    .surface()
                    .and_then(FrameSurface::downcast_ref::<vt_decoder::SendPixelBuffer>)
                    .expect("a zero-copy frame carries a CVPixelBuffer");
                // The point of the path: no per-pixel readback happened, so
                // there is nothing for the CPU present branch to show. A frame
                // carrying both would mean the copy was still being paid.
                assert!(
                    frame.pixels().is_empty(),
                    "a zero-copy frame must not also carry a CPU readback"
                );
                let texture = importer
                    .import(&device, surface.as_ptr())
                    .expect("the mailbox surface still imports");
                assert_eq!(texture.width(), 160);
                assert_eq!(texture.height(), 120);
                imported += 1;
            }
            // As above: the mailbox is a slot, not a queue.
            if imported >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            imported >= 1,
            "the zero-copy path published no importable surfaces within {FIRST_FRAME_BUDGET:?}"
        );
    }
}
