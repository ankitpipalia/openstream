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
use std::io;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::time::Duration;

use gilrs::ff::{BaseEffect, BaseEffectType, Effect, EffectBuilder, Repeat, Replay, Ticks};
use gilrs::{Axis, Button, EventType, GamepadId, Gilrs};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window};
use openstream_client_core::{
    Capabilities, ConnectionPath, FlushOutcome, Pairing, PeerSession, ReliableControl, Role,
    VideoCodec, parse_stun_servers,
};
use openstream_media::clipboard::{
    Assembler as ClipboardAssembler, CompletedClipboard, fragment_text,
};
use openstream_media::displays::Display as RemoteDisplay;
use openstream_media::input::{InputEvent, RumbleEvent};
use openstream_media::{
    Assembler, AudioEvent, AudioFrame, Fragment, FrameAck, JitterBuffer, KEYFRAME_REQUEST,
    metrics::MetricsReporter,
};
use openstream_platform::clipboard as platform_clipboard;
use openstream_platform::clipboard_policy::ClipboardPolicy;
use openstream_protocol::Kind;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc as async_mpsc;

mod display;
mod mic;
mod render;

const DEFAULT_WIDTH: usize = 1280;
const DEFAULT_HEIGHT: usize = 720;
/// A slow window must not let decoded frames or status messages accumulate
/// without bound. New frames are dropped when the UI is behind; the next
/// frame is still a complete decoded image.
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
    Frame {
        width: usize,
        height: usize,
        pixels: Vec<u32>,
    },
    Error(String),
    Metrics(String),
    Rumble {
        device_id: u32,
        strong: u8,
        weak: u8,
    },
    Displays(Vec<RemoteDisplay>),
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
}

impl UiSender {
    fn send(&self, message: UiMessage) -> Result<(), ()> {
        let critical = matches!(
            &message,
            UiMessage::Ready { .. } | UiMessage::Error(_) | UiMessage::Displays(_) | UiMessage::End
        );
        let sender = if critical {
            &self.critical
        } else {
            &self.normal
        };
        sender.try_send(message).map_err(|_| ())
    }
}

/// The UI side of the two bounded lanes. Critical messages are checked first
/// so a terminal error/end notification is visible even when several stale
/// frames were already queued.
#[derive(Debug)]
struct UiReceiver {
    normal: Receiver<UiMessage>,
    critical: Receiver<UiMessage>,
}

impl UiReceiver {
    fn try_recv(&self) -> Result<UiMessage, TryRecvError> {
        match self.critical.try_recv() {
            Ok(message) => Ok(message),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => self.normal.try_recv(),
        }
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
}

impl InputSender {
    fn try_send(&self, input: UiInput) -> Result<(), ()> {
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
}

impl InputReceiver {
    /// Normal events are drained before the critical lane so an explicit
    /// release cannot be reordered ahead of already-queued button presses.
    fn try_recv(&self) -> Result<UiInput, TryRecvError> {
        match self.normal.try_recv() {
            Ok(input) => Ok(input),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => self.critical.try_recv(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (ui_normal_tx, ui_normal_rx) = mpsc::sync_channel(UI_QUEUE_CAPACITY);
    let (ui_critical_tx, ui_critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
    let ui_tx = UiSender {
        normal: ui_normal_tx,
        critical: ui_critical_tx,
    };
    let ui_rx = UiReceiver {
        normal: ui_normal_rx,
        critical: ui_critical_rx,
    };
    let (input_normal_tx, input_normal_rx) = mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
    let (input_critical_tx, input_critical_rx) = mpsc::sync_channel(CRITICAL_INPUT_QUEUE_CAPACITY);
    let input_tx = InputSender {
        normal: input_normal_tx,
        critical: input_critical_tx,
    };
    let input_rx = InputReceiver {
        normal: input_normal_rx,
        critical: input_critical_rx,
    };
    let mut window = Window::new(
        "OpenStream",
        DEFAULT_WIDTH,
        DEFAULT_HEIGHT,
        display::DisplayMode::from_env().window_options(),
    )?;
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
    let worker = thread::Builder::new()
        .name("openstream-network".to_string())
        .spawn(move || run_worker(ui_tx, input_rx))?;
    window.set_target_fps(120);
    let hotkeys = display::Hotkey::from_env();
    let mut last_hotkey: Option<display::HotkeyAction> = None;
    let mut buffer = vec![0_u32; DEFAULT_WIDTH * DEFAULT_HEIGHT];
    let mut buffer_width = DEFAULT_WIDTH;
    let mut buffer_height = DEFAULT_HEIGHT;
    let mut last_mouse = None;
    let mut button_state = [false; 3];
    let mut gamepad_ids = HashMap::new();
    let mut rumble_effects = HashMap::new();
    let mut connected = false;
    let mut base_title = String::from("OpenStream");
    let mut displays = Vec::<RemoteDisplay>::new();
    let mut selected_display = None;
    let mut pacer = render::FramePacer::new(60);
    let mut gamepads = match Gilrs::new() {
        Ok(gamepads) => Some(gamepads),
        Err(error) => {
            eprintln!("OpenStream gamepad input unavailable: {error}");
            None
        }
    };

    while window.is_open() && !window.is_key_down(Key::Escape) {
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
                    base_title = format!(
                        "{width}x{height} @ {fps}fps -- {path:?} -- audio={audio} input={input}"
                    );
                    window.set_title(&format!("OpenStream -- {base_title}"));
                }
                Ok(UiMessage::Frame {
                    width,
                    height,
                    pixels,
                }) => {
                    // Malformed decoder output is dropped, never presented.
                    if render::validate_bgra_frame(width, height, &pixels).is_err() {
                        continue;
                    }
                    buffer_width = width;
                    buffer_height = height;
                    buffer = pixels;
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
                }
                Ok(UiMessage::Error(error)) => {
                    connected = false;
                    window.set_title(&format!("OpenStream -- error: {error}"));
                }
                Ok(UiMessage::Rumble {
                    device_id,
                    strong,
                    weak,
                }) => {
                    play_rumble(
                        &mut gamepads,
                        &gamepad_ids,
                        &mut rumble_effects,
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
                Ok(UiMessage::End) => {
                    connected = false;
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
        if connected {
            forward_input(
                &window,
                &input_tx,
                &mut last_mouse,
                &mut button_state,
                &mut gamepads,
                &mut gamepad_ids,
                &mut rumble_effects,
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
    for effect in rumble_effects.values() {
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
fn forward_input(
    window: &Window,
    input_tx: &InputSender,
    last_mouse: &mut Option<(i32, i32)>,
    button_state: &mut [bool; 3],
    gamepads: &mut Option<Gilrs>,
    gamepad_ids: &mut HashMap<u32, GamepadId>,
    rumble_effects: &mut HashMap<u32, Effect>,
) {
    let timestamp = monotonic_us();
    for &(key, usage) in keyboard_usages() {
        if window.is_key_pressed(key, KeyRepeat::No) {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::keyboard(
                usage, 0, true, timestamp,
            )));
        }
        if window.is_key_released(key) {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::keyboard(
                usage, 0, false, timestamp,
            )));
        }
    }

    if let Some((x, y)) = window.get_mouse_pos(MouseMode::Clamp) {
        let current = (x as i32, y as i32);
        if let Some(previous) = *last_mouse {
            let dx = current.0.saturating_sub(previous.0);
            let dy = current.1.saturating_sub(previous.1);
            if dx != 0 || dy != 0 {
                let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_motion(
                    true, dx, dy, timestamp,
                )));
            }
        }
        *last_mouse = Some(current);
    }

    for (index, button) in [MouseButton::Left, MouseButton::Middle, MouseButton::Right]
        .into_iter()
        .enumerate()
    {
        let pressed = window.get_mouse_down(button);
        if pressed != button_state[index] {
            let _ = input_tx.try_send(UiInput::Event(InputEvent::pointer_button(
                u32::try_from(index + 1).unwrap_or(1),
                pressed,
                timestamp,
            )));
            button_state[index] = pressed;
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

    poll_gamepads(gamepads, input_tx, timestamp, gamepad_ids, rumble_effects);
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

fn run_worker(ui_tx: UiSender, input_rx: InputReceiver) {
    let result = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(network_loop(ui_tx.clone(), input_rx)),
        Err(error) => Err(error.to_string().into()),
    };
    if let Err(error) = result {
        let _ = ui_tx.send(UiMessage::Error(error.to_string()));
    }
    let _ = ui_tx.send(UiMessage::End);
}

async fn network_loop(
    ui_tx: UiSender,
    input_rx: InputReceiver,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let origin = env::var("OPENSTREAM_SIGNAL_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let pairing: Pairing = serde_json::from_str(
        &env::var("OPENSTREAM_PAIRING_JSON")
            .map_err(|_| "OPENSTREAM_PAIRING_JSON must contain the create-session response")?,
    )?;
    let bind = env::var("OPENSTREAM_UDP_BIND")
        .unwrap_or_else(|_| "0.0.0.0:0".to_string())
        .parse::<SocketAddr>()?;
    let stun_servers = match env::var("OPENSTREAM_STUN_SERVERS") {
        Ok(spec) => parse_stun_servers(&spec)?,
        Err(_) => Vec::new(),
    };
    let mut session =
        PeerSession::establish_configured(&origin, &pairing, Role::Client, bind, &stun_servers)
            .await?;
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
        .ok_or("negotiated frame dimensions overflow")?;
    const MAX_DECODE_FRAME_BYTES: usize = 64 * 1024 * 1024;
    if frame_bytes > MAX_DECODE_FRAME_BYTES {
        return Err(format!(
            "negotiated decoded frame is too large ({frame_bytes} bytes; limit {MAX_DECODE_FRAME_BYTES})"
        )
        .into());
    }
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
    let mut decoder =
        Command::new(env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".into()))
            .args(decoder_args(format, width, height))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("could not start FFmpeg decoder: {error}"))?;
    let mut decoder_stdin = decoder
        .stdin
        .take()
        .ok_or("FFmpeg decoder stdin was not piped")?;
    let mut decoder_stdout = decoder
        .stdout
        .take()
        .ok_or("FFmpeg decoder stdout was not piped")?;

    let mut audio_player = spawn_audio_player()?;
    let mut audio_stdin = audio_player.as_mut().and_then(|child| child.stdin.take());
    let mut audio_decoder = opus_rs::OpusDecoder::new(48_000, lowlat_audio::CHANNELS)
        .map_err(|error| format!("could not create Opus decoder: {error}"))?;
    let mut audio_jitter = JitterBuffer::new(3);
    let mut audio_pcm = vec![0_f32; lowlat_audio::FRAME * lowlat_audio::CHANNELS];
    let mut last_audio_toc = None;

    let (frame_tx, mut frame_rx) = async_mpsc::channel(2);
    tokio::spawn(async move {
        loop {
            let mut raw = vec![0_u8; frame_bytes];
            if tokio::io::AsyncReadExt::read_exact(&mut decoder_stdout, &mut raw)
                .await
                .is_err()
            {
                break;
            }
            let mut pixels = Vec::with_capacity(width * height);
            for pixel in raw.chunks_exact(4) {
                let value = u32::from(pixel[0])
                    | (u32::from(pixel[1]) << 8)
                    | (u32::from(pixel[2]) << 16)
                    | (u32::from(pixel[3]) << 24);
                pixels.push(value);
            }
            if frame_tx.send(pixels).await.is_err() {
                break;
            }
        }
    });

    let mut assembler = Assembler::default();
    let mut metrics = MetricsReporter::default();
    let mut metrics_tick = tokio::time::interval(Duration::from_secs(2));
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
    let mut waiting_for_keyframe = false;
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
                    reliable_control.send(&mut session, &event.encode()).await?;
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
                    let _ = decoder.kill().await;
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
                match assembler.push(fragment) {
                    Ok(Some(frame)) => ready_frames.push(frame),
                    Ok(None) => {}
                    Err(error) => {
                        let _ = ui_tx.send(UiMessage::Error(format!(
                            "video frame dropped: {error}"
                        )));
                        continue;
                    }
                }
                while let Some(frame) = assembler.pop_ready() {
                    ready_frames.push(frame);
                }
                if assembler.take_keyframe_request() {
                    waiting_for_keyframe = true;
                    reliable_control.send(&mut session, KEYFRAME_REQUEST).await?;
                }
                for frame in ready_frames {
                    if frame.keyframe {
                        waiting_for_keyframe = false;
                    }
                    if !waiting_for_keyframe {
                        decoder_stdin.write_all(&frame.payload).await?;
                        metrics.frame_received(frame.frame_id);
                        let ack = FrameAck {
                            frame_id: frame.frame_id,
                            lost_frames: assembler.take_frame_gap(),
                        };
                        let ack = ack.encode();
                        let _ = reliable_control
                            .send_if_available(&mut session, &ack)
                            .await?;
                    }
                }
            }
            Some(pixels) = frame_rx.recv() => {
                let _ = ui_tx.send(UiMessage::Frame { width, height, pixels });
            }
            _ = control_tick.tick() => {
                reliable_control.retry(&mut session).await?;
                session.flush_outbound_recoverably().await?;
                session.maintain_liveness().await?;
            }
            _ = wait_for_outbound_wake(outbound_wake) => {
                session.flush_outbound_recoverably().await?;
            }
            _ = metrics_tick.tick() => {
                let _ = ui_tx.send(UiMessage::Metrics(metrics.snapshot().overlay_line()));
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

fn decoder_args(format: &str, width: usize, height: usize) -> Vec<String> {
    vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
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
    ]
}

fn monotonic_us() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
    // This function is only an input timestamp; it is not used for crypto or
    // ordering, so a process-local monotonic approximation is sufficient.
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

impl From<io::Error> for UiMessage {
    fn from(error: io::Error) -> Self {
        Self::Error(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRITICAL_INPUT_QUEUE_CAPACITY, CRITICAL_UI_QUEUE_CAPACITY, InputReceiver, InputSender,
        UiInput, UiMessage, UiReceiver, UiSender, axis_value, cycled_display, decoder_args,
        gamepad_axis_index, gamepad_button_index, keyboard_usages, selected_display_index,
    };
    use gilrs::{Axis, Button};
    use minifb::Key;
    use openstream_media::displays::{Display, PRIMARY_FLAG, SELECTED_FLAG};
    use std::sync::mpsc;

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
        let (normal_tx, normal_rx) = mpsc::sync_channel(1);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_INPUT_QUEUE_CAPACITY);
        let sender = InputSender {
            normal: normal_tx,
            critical: critical_tx,
        };
        let receiver = InputReceiver {
            normal: normal_rx,
            critical: critical_rx,
        };
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
        assert!(matches!(receiver.try_recv(), Ok(UiInput::Event(_))));
        assert!(matches!(receiver.try_recv(), Ok(UiInput::Release)));
    }

    #[test]
    fn critical_ui_state_survives_a_full_frame_queue() {
        let (normal_tx, normal_rx) = mpsc::sync_channel(1);
        let (critical_tx, critical_rx) = mpsc::sync_channel(CRITICAL_UI_QUEUE_CAPACITY);
        let sender = UiSender {
            normal: normal_tx,
            critical: critical_tx,
        };
        let receiver = UiReceiver {
            normal: normal_rx,
            critical: critical_rx,
        };
        assert!(
            sender
                .send(UiMessage::Frame {
                    width: 1,
                    height: 1,
                    pixels: vec![0],
                })
                .is_ok()
        );
        assert!(sender.send(UiMessage::End).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(UiMessage::End)));
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
