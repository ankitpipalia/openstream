//! Cross-platform FFmpeg process host adapter.
//!
//! This is intentionally an external-process backend: it gives the OpenStream
//! transport a real H.264 source on Linux, Windows, and macOS without making
//! the Rust workspace link against GPL FFmpeg libraries. Production builds
//! can replace it with native PipeWire/DRM, Desktop Duplication, and
//! ScreenCaptureKit backends behind the same packetizer.

use std::env;
use std::io;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use openstream_client_core::{
    Capabilities, FlushOutcome, Pairing, PeerSession, QueueOutcome, ReliableControl, Role,
    VideoCodec, parse_stun_servers,
};
use openstream_media::clipboard::{
    Assembler as ClipboardAssembler, CompletedClipboard, fragment_text,
};
use openstream_media::{
    AdaptiveBitrate, AudioFrame, BitrateDecision, KEYFRAME_REQUEST, MAX_FRAGMENT_BYTES,
    PeerTelemetryAdapter, fragment_frame,
};
use openstream_platform::clipboard as platform_clipboard;
use openstream_platform::clipboard_policy::ClipboardPolicy;
use openstream_protocol::Kind;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdout, Command};

mod input;
mod reconfigure;

const DEFAULT_SIGNAL_ORIGIN: &str = "http://127.0.0.1:8080";
const DEFAULT_UDP_BIND: &str = "0.0.0.0:0";
const DEFAULT_FFMPEG: &str = "ffmpeg";
const DEFAULT_HOST_SECONDS: u64 = 60;
const MAX_HOST_SECONDS: u64 = 24 * 60 * 60;
const MIN_KEYFRAME_SECONDS: f64 = 0.1;
const MAX_KEYFRAME_SECONDS: f64 = 60.0;
const MAX_FFMPEG_ARGS: usize = 64;
const MAX_FFMPEG_ARG_BYTES: usize = 4096;
const MAX_FFMPEG_ARGS_BYTES: usize = 16 * 1024;
/// A missing AUD must not allow an external encoder to grow this buffer
/// without bound. At 200 Mbps this is roughly 0.6 seconds of video, which is
/// enough to absorb normal pipe chunking while still failing closed on a
/// broken encoder or an unexpected elementary stream.
const MAX_PENDING_ACCESS_UNIT_BYTES: usize = 16 * 1024 * 1024;
/// A client may request a different monitor, but the host must not respawn an
/// external capture process for every packet a peer sends. This cooldown is
/// independent of adaptive bitrate restarts because monitor selection is a
/// user-visible control action.
const DISPLAY_SWITCH_MIN_INTERVAL: Duration = Duration::from_secs(1);

fn remember_adaptive_decision(
    pending: &mut Option<BitrateDecision>,
    decision: Option<BitrateDecision>,
) {
    if decision.is_some() {
        *pending = decision;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match run().await {
        Ok(()) => Ok(()),
        Err(error) if expected_peer_disconnect(&error.to_string()) => {
            eprintln!("OpenStream FFmpeg host ended after peer disconnect: {error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let origin =
        env::var("OPENSTREAM_SIGNAL_ORIGIN").unwrap_or_else(|_| DEFAULT_SIGNAL_ORIGIN.to_string());
    let pairing: Pairing = serde_json::from_str(
        &env::var("OPENSTREAM_PAIRING_JSON")
            .map_err(|_| "OPENSTREAM_PAIRING_JSON must contain the create-session response")?,
    )?;
    let bind = env::var("OPENSTREAM_UDP_BIND")
        .unwrap_or_else(|_| DEFAULT_UDP_BIND.to_string())
        .parse::<SocketAddr>()?;
    let stun_servers = match env::var("OPENSTREAM_STUN_SERVERS") {
        Ok(spec) => parse_stun_servers(&spec)?,
        Err(_) => Vec::new(),
    };
    let mut session =
        PeerSession::establish_configured(&origin, &pairing, Role::Host, bind, &stun_servers)
            .await?;
    eprintln!(
        "OpenStream selected data path: {:?}",
        session.connection_path()
    );
    let (requested_width, requested_height, requested_fps) = configured_limits();
    let host_displays = enumerate_host_displays(requested_width, requested_height);
    let mut display_index = selected_display(&host_displays)?;
    let capture_backend = env::var("OPENSTREAM_CAPTURE_BACKEND").unwrap_or_else(|_| {
        match env::consts::OS {
            "linux" => "x11grab",
            "macos" => "avfoundation",
            "windows" => "gdigrab",
            _ => "unsupported",
        }
        .to_string()
    });
    // Runtime monitor switching is only honest when this adapter controls the
    // X11 origin. A custom input or custom argument list may describe a
    // PipeWire/window/device source that cannot be selected by an xrandr id.
    let display_selection_enabled = cfg!(target_os = "linux")
        && capture_backend == "x11grab"
        && env::var_os("OPENSTREAM_FFMPEG_INPUT").is_none()
        && env::var_os("OPENSTREAM_FFMPEG_ARGS").is_none()
        && host_displays.len() > 1;
    let host_policy = openstream_platform::policy::HostPolicy::from_env();
    eprintln!("{}", host_policy.log_line());
    let clipboard_policy = ClipboardPolicy::from_env();
    eprintln!("{}", clipboard_policy.log_line());
    let input_enabled = host_policy.input;
    let audio_requested = env::var("OPENSTREAM_AUDIO").as_deref() == Ok("1");
    let clipboard_requested = host_policy.clipboard;
    let mut host_capabilities =
        Capabilities::host_with_limits(requested_width, requested_height, requested_fps);
    host_capabilities.input = input_enabled;
    host_capabilities.rumble = host_policy.gamepad && cfg!(target_os = "linux");
    host_capabilities.clipboard = clipboard_requested && platform_clipboard::available();
    host_capabilities.microphone = host_policy.microphone;
    host_capabilities.multi_monitor = display_selection_enabled;
    // 10-bit and 4:4:4 are opt-in host profiles: the encoder emits them only
    // when both the host allows them here and the client negotiates them.
    host_capabilities.video_10_bit = env::var("OPENSTREAM_ALLOW_10BIT").as_deref() == Ok("1");
    host_capabilities.video_444 = env::var("OPENSTREAM_ALLOW_444").as_deref() == Ok("1");
    if !audio_requested {
        host_capabilities.audio_codecs.clear();
    }
    let negotiated = session
        .negotiate_host_with_capabilities(host_capabilities)
        .await?;
    let mut host_input = input::HostInput::from_environment(negotiated.width, negotiated.height)?;
    eprintln!(
        "OpenStream negotiated {:?} {}x{} at up to {} fps; audio={:?}; input={}",
        negotiated.video,
        negotiated.width,
        negotiated.height,
        negotiated.fps,
        negotiated.audio,
        negotiated.input
    );
    let mut reliable_control = ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
    // Guest-microphone intake: negotiated capability plus explicit policy.
    // Accepted frames decode into the verification sink when configured.
    let mut mic_sink = openstream_media::microphone::GuestMicSink::from_env(
        negotiated.microphone && host_policy.microphone,
    );
    if mic_sink.accepting() {
        eprintln!("OpenStream guest microphone intake enabled");
    }

    // Multi-monitor: enumerate outputs, select one for x11grab capture, and
    // advertise the topology when both peers support the live control.
    if let Some(selected) = host_displays.get(display_index) {
        eprintln!(
            "OpenStream capturing display {} ({}x{}+{}+{}{})",
            selected.id,
            selected.width,
            selected.height,
            selected.x,
            selected.y,
            if selected.primary() { ", primary" } else { "" },
        );
    }
    if negotiated.multi_monitor {
        match openstream_media::displays::encode_list(&topology_with_selected(
            &host_displays,
            display_index,
        )) {
            Ok(topology) => {
                if reliable_control
                    .send(&mut session, &topology)
                    .await
                    .is_err()
                {
                    eprintln!("OpenStream display topology announcement backpressured");
                }
            }
            Err(error) => eprintln!("OpenStream display topology omitted: {error}"),
        }
    }

    let (ffmpeg_child, mut profile) = spawn_ffmpeg(SpawnRequest {
        codec: negotiated.video,
        width: negotiated.width,
        height: negotiated.height,
        fps: negotiated.fps,
        ten_bit: negotiated.video_10_bit,
        four_four_four: negotiated.video_444,
        bitrate_override_mbps: None,
        capture_input: display_capture_input(&host_displays, display_index),
    })?;
    // Keep every external process under a drop guard. The streaming loop has
    // several fallible async operations (transport, encoder, clipboard), and
    // a plain `?` on any of them must not orphan an FFmpeg process.
    let mut ffmpeg = ChildGuard::new(ffmpeg_child);
    let mut stdout = ffmpeg.take_stdout().ok_or("FFmpeg stdout was not piped")?;
    // Congestion response for the external encoder. The adaptive controller
    // tracks assembly ACKs; because FFmpeg exposes no in-place rate control,
    // decisions are applied as bounded rolling restarts (see reconfigure).
    let min_mbps = env::var("OPENSTREAM_VIDEO_MIN_MBPS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(1.0)
        .min(profile.bitrate_mbps);
    let mut telemetry = PeerTelemetryAdapter::new(
        AdaptiveBitrate::new(profile.bitrate_mbps, min_mbps, profile.bitrate_mbps),
        session.path_generation(),
        0,
    );
    let restart_policy = reconfigure::RestartPolicy::from_env();
    let mut last_restart: Option<Instant> = None;
    // `AdaptiveBitrate::tick` emits one-shot decisions. Keep one pending when
    // a display switch takes precedence so the bounded restart policy can
    // apply it on a later control tick.
    let mut pending_adaptive_decision: Option<BitrateDecision> = None;
    let mut audio_process = if audio_requested {
        Some(ChildGuard::new(spawn_audio_ffmpeg()?))
    } else {
        None
    };
    let mut audio_stdout = audio_process.as_mut().and_then(ChildGuard::take_stdout);
    let mut audio_encoder = if audio_stdout.is_some() {
        Some(
            lowlat_audio::Encoder::new(128)
                .map_err(|error| format!("could not create Opus encoder: {error}"))?,
        )
    } else {
        None
    };
    let seconds = env::var("OPENSTREAM_HOST_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HOST_SECONDS)
        .min(MAX_HOST_SECONDS);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut buffer = vec![0_u8; MAX_FRAGMENT_BYTES * 8];
    let mut audio_read = vec![0_u8; lowlat_audio::FRAME_BYTES * 2];
    let mut audio_pcm = Vec::with_capacity(lowlat_audio::FRAME_BYTES * 2);
    let mut access_units = AccessUnitizer::for_codec(negotiated.video);
    let mut frame_id = 0_u32;
    let mut audio_sequence = 0_u32;
    let mut chunks = 0_u64;
    let mut clipboard_assembler = ClipboardAssembler::default();
    let mut clipboard_transfer_id = 1_u32;
    let mut clipboard_value = if clipboard_policy.may_send(negotiated.clipboard) {
        platform_clipboard::read_text().ok()
    } else {
        None
    };
    let mut keyframe_requested = false;
    let mut pending_display = None;
    let mut last_display_switch = None;
    let mut control_tick = tokio::time::interval(Duration::from_millis(100));
    let mut clipboard_tick = tokio::time::interval(Duration::from_millis(500));

    let mut peer_ended = false;
    'stream: while Instant::now() < deadline {
        let outbound_backpressured = matches!(
            session.flush_outbound_recoverably().await?,
            FlushOutcome::Backpressured
        );
        let outbound_wake = if outbound_backpressured {
            None
        } else {
            session.next_outbound_wake()
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::select! {
            result = tokio::time::timeout(remaining, session.recv()) => {
                let packet = match result {
                    Ok(result) => result?,
                    Err(_) => break 'stream,
                };
                if packet.kind == Kind::Input {
                    // Older/headless clients put the same authenticated OI
                    // envelope on the dedicated input kind. Keep accepting
                    // it here as well as on ReliableControl so every host
                    // adapter has one input policy regardless of which
                    // client generation produced the packet.
                    if let Err(error) = host_input.apply(&packet.payload) {
                        eprintln!("OpenStream host input event rejected: {error}");
                    }
                    continue;
                }
                if packet.kind == Kind::Control {
                    if let Some(deliveries) = reliable_control.receive(&mut session, &packet).await? {
                        for payload in deliveries {
                            if payload == KEYFRAME_REQUEST {
                                // FFmpeg is asked for a short intra refresh.
                                // Not every external encoder exposes this
                                // flag, so the adapter also reports the
                                // request rather than pretending it was
                                // applied when the process cannot honor it.
                                eprintln!("OpenStream client requested a keyframe refresh");
                                keyframe_requested = true;
                            } else if payload == b"openstream/end" {
                                peer_ended = true;
                                break 'stream;
                            } else if telemetry.accept_frame_ack_payload(
                                &payload,
                                started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                            ) {
                                // Frame assembly ACKs drive the adaptive
                                // controller; the rolling-restart policy
                                // decides whether the decision is worth an
                                // encoder respawn (see control_tick below).
                            } else if payload == b"openstream/frame-ack" {
                                // Compatibility marker for legacy clients;
                                // it carries no portable encoder evidence.
                            } else if apply_clipboard_chunk(
                                &payload,
                                clipboard_policy.may_apply(negotiated.clipboard),
                                &mut clipboard_assembler,
                                &mut clipboard_value,
                            ).map_err(|error| io::Error::other(error.to_string()))? {
                                // Clipboard data is handled only when the
                                // negotiated policy explicitly enables it.
                            } else if mic_sink.accept(&payload) {
                                // Guest microphone audio: validated, decoded,
                                // and counted above. Never input.
                            } else if queue_display_selection(
                                &payload,
                                &host_displays,
                                display_index,
                                &mut pending_display,
                                display_selection_enabled,
                            ) {
                                // A monitor change is applied by the bounded
                                // restart in the control tick below.
                            } else if let Err(error) = host_input.apply(&payload) {
                                eprintln!("OpenStream host input event rejected: {error}");
                            }
                        }
                    } else if packet.payload == KEYFRAME_REQUEST {
                        eprintln!("OpenStream client requested a keyframe refresh");
                        keyframe_requested = true;
                    } else if packet.payload == b"openstream/end" {
                        peer_ended = true;
                        break 'stream;
                    } else if telemetry.accept_frame_ack_payload(
                        &packet.payload,
                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    ) {
                        // External FFmpeg has no portable live bitrate
                        // actuator, so ACKs feed the adaptive controller and
                        // the rolling-restart policy applies significant
                        // decisions by respawning the encoder. ACKs are never
                        // input events.
                    } else if packet.payload == b"openstream/frame-ack" {
                        // Compatibility marker for legacy clients; no metrics.
                    } else if apply_clipboard_chunk(
                        &packet.payload,
                        clipboard_policy.may_apply(negotiated.clipboard),
                        &mut clipboard_assembler,
                        &mut clipboard_value,
                    ).map_err(|error| io::Error::other(error.to_string()))? {
                        // Clipboard data is handled only when the negotiated
                        // policy explicitly enables it.
                    } else if mic_sink.accept(&packet.payload) {
                        // Guest microphone audio: validated, decoded, and
                        // counted above. Never input.
                    } else if queue_display_selection(
                        &packet.payload,
                        &host_displays,
                        display_index,
                        &mut pending_display,
                        display_selection_enabled,
                    ) {
                        // A monitor change is applied by the bounded restart
                        // in the control tick below.
                    } else if packet.payload != b"openstream/end"
                        && let Err(error) = host_input.apply(&packet.payload)
                    {
                        eprintln!("OpenStream host input event rejected: {error}");
                    }
                }
            }
            result = stdout.read(&mut buffer) => {
                let length = result?;
                if length == 0 {
                    break;
                }
                for payload in access_units.push(&buffer[..length])? {
                    send_access_unit(
                        &mut session,
                        frame_id,
                        started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                        &payload,
                        negotiated.video,
                    )
                    .await?;
                    telemetry.frame_sent(
                        frame_id,
                        payload.len(),
                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    );
                    frame_id = frame_id.wrapping_add(1);
                    chunks += 1;
                }
            }
            result = read_optional(&mut audio_stdout, &mut audio_read) => {
                let length = result?;
                if length == 0 {
                    audio_stdout = None;
                    continue;
                }
                audio_pcm.extend_from_slice(&audio_read[..length]);
                while audio_pcm.len() >= lowlat_audio::FRAME_BYTES {
                    let frame: Vec<u8> = audio_pcm.drain(..lowlat_audio::FRAME_BYTES).collect();
                    let encoded = audio_encoder
                        .as_mut()
                        .ok_or("audio encoder disappeared")?
                        .encode(&frame)
                        .map_err(|error| format!("Opus encoding failed: {error}"))?;
                    let payload = AudioFrame {
                        sequence: audio_sequence,
                        presentation_time_us: started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                        payload: encoded.to_vec(),
                    }
                    .encode()?;
                    queue_stream_packet(&mut session, Kind::Audio, &payload)?;
                    audio_sequence = audio_sequence.wrapping_add(1);
                }
            }
            _ = control_tick.tick() => {
                host_input.tick();
                while let Some(rumble) = host_input.rumble() {
                    reliable_control.send(&mut session, &rumble.encode()).await?;
                }
                reliable_control.retry(&mut session).await?;
                session.flush_outbound_recoverably().await?;
                session.maintain_liveness().await?;
                let now = Instant::now();
                let now_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                telemetry.observe_path(&session.transport_snapshot(now), now_ms);
                let adaptive_decision = telemetry.tick(now_ms);
                remember_adaptive_decision(&mut pending_adaptive_decision, adaptive_decision);
                let display_target = pending_display.filter(|_| {
                    last_display_switch
                        .is_none_or(|previous| now.duration_since(previous) >= DISPLAY_SWITCH_MIN_INTERVAL)
                });
                if let Some(target) = display_target {
                    eprintln!(
                        "OpenStream switching FFmpeg capture from display {} to {}",
                        display_index, target
                    );
                    match spawn_ffmpeg(SpawnRequest {
                        codec: negotiated.video,
                        width: negotiated.width,
                        height: negotiated.height,
                        fps: negotiated.fps,
                        ten_bit: negotiated.video_10_bit,
                        four_four_four: negotiated.video_444,
                        bitrate_override_mbps: Some(profile.bitrate_mbps),
                        capture_input: display_capture_input(&host_displays, target),
                    }) {
                        Ok((child, next_profile)) => {
                            let mut replacement = ChildGuard::new(child);
                            let Some(replacement_stdout) = replacement.take_stdout() else {
                                replacement.terminate().await;
                                eprintln!("OpenStream display switch produced no FFmpeg stdout; keeping the current capture");
                                pending_display = None;
                                continue;
                            };
                            // Spawn the replacement before terminating the old
                            // process. A failed display/device open therefore
                            // leaves the existing stream alive.
                            ffmpeg.terminate().await;
                            ffmpeg = replacement;
                            profile = next_profile;
                            stdout = replacement_stdout;
                            access_units = AccessUnitizer::for_codec(negotiated.video);
                            display_index = target;
                            pending_display = None;
                            last_display_switch = Some(now);
                            last_restart = Some(now);
                            keyframe_requested = false;
                            if negotiated.multi_monitor {
                                let topology = openstream_media::displays::encode_list(
                                    &topology_with_selected(&host_displays, display_index),
                                )?;
                                reliable_control.send(&mut session, &topology).await?;
                            }
                        }
                        Err(error) => {
                            eprintln!("OpenStream could not switch to display {target}: {error}");
                            // The old capture remains active; require a fresh
                            // client request after the display topology changes.
                            pending_display = None;
                        }
                    }
                } else {
                let force_keyframe_restart = keyframe_requested
                    && last_restart
                        .is_none_or(|previous| now.duration_since(previous) >= restart_policy.min_interval);
                let adaptive_target = pending_adaptive_decision.as_ref().and_then(|decision| {
                    restart_policy.should_restart(
                        profile.bitrate_mbps,
                        decision.bitrate_mbps,
                        now,
                        last_restart,
                    )
                });
                let applied_adaptive_decision = !force_keyframe_restart && adaptive_target.is_some();
                let target = if force_keyframe_restart {
                    Some(profile.bitrate_mbps)
                } else {
                    adaptive_target
                };
                if let Some(target) = target {
                    let reason = if force_keyframe_restart {
                        "client keyframe request"
                    } else {
                        "adaptive bitrate change"
                    };
                    eprintln!(
                        "OpenStream restarting FFmpeg encoder at {target:.2} Mbps ({reason})",
                    );
                    match spawn_ffmpeg(SpawnRequest {
                        codec: negotiated.video,
                        width: negotiated.width,
                        height: negotiated.height,
                        fps: negotiated.fps,
                        ten_bit: negotiated.video_10_bit,
                        four_four_four: negotiated.video_444,
                        bitrate_override_mbps: Some(target),
                        capture_input: display_capture_input(&host_displays, display_index),
                    }) {
                        Ok((child, next)) => {
                            let mut replacement = ChildGuard::new(child);
                            let Some(replacement_stdout) = replacement.take_stdout() else {
                                replacement.terminate().await;
                                eprintln!(
                                    "OpenStream FFmpeg restart produced no stdout; keeping the current capture"
                                );
                                last_restart = Some(now);
                                continue;
                            };
                            // Start and validate the replacement before
                            // terminating the current encoder. A transient
                            // device/driver failure therefore causes a retry,
                            // not an avoidable black stream.
                            ffmpeg.terminate().await;
                            ffmpeg = replacement;
                            profile = next;
                            stdout = replacement_stdout;
                            access_units = AccessUnitizer::for_codec(negotiated.video);
                            last_restart = Some(now);
                            keyframe_requested = false;
                            if applied_adaptive_decision {
                                pending_adaptive_decision = None;
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "OpenStream could not restart FFmpeg; keeping the current capture: {error}"
                            );
                            // Rate-limit failed attempts just like successful
                            // ones. Otherwise a missing encoder/device turns
                            // the 100 ms control tick into a process-spawn
                            // loop.
                            last_restart = Some(now);
                        }
                    }
                }
                }
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
            _ = wait_for_outbound_wake(outbound_wake) => {
                session.flush_outbound_recoverably().await?;
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                break;
            }
        }
    }
    if !peer_ended && let Some(payload) = access_units.finish() {
        send_access_unit(
            &mut session,
            frame_id,
            started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
            &payload,
            negotiated.video,
        )
        .await?;
        chunks += 1;
    }
    if !peer_ended {
        let _ = reliable_control.send(&mut session, b"openstream/end").await;
    }
    ffmpeg.terminate().await;
    if let Some(mut audio_process) = audio_process {
        audio_process.terminate().await;
    }
    let _ = session.release_upnp().await;
    eprintln!("OpenStream FFmpeg host sent {chunks} encoded chunks");
    eprintln!("OpenStream transport stats: {:?}", session.stats());
    Ok(())
}

async fn read_optional(reader: &mut Option<ChildStdout>, buffer: &mut [u8]) -> io::Result<usize> {
    match reader {
        Some(reader) => reader.read(buffer).await,
        None => std::future::pending::<io::Result<usize>>().await,
    }
}

async fn wait_for_outbound_wake(wake: Option<Duration>) {
    match wake {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}

fn queue_stream_packet(
    session: &mut PeerSession,
    kind: Kind,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        session.queue(kind, 0, 0, payload)?,
        QueueOutcome::DroppedOldest
    ) {
        eprintln!("OpenStream dropped oldest queued {kind:?} packet");
    }
    Ok(())
}

/// Own an external encoder process and make early-return cleanup reliable.
/// `Child` only kills the process when explicitly asked, so a transport or
/// parsing error in the host loop would otherwise leave FFmpeg running.
struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    async fn terminate(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `start_kill` is non-blocking and safe from Drop. The normal path
        // awaits `terminate`, while error paths still request process exit.
        let _ = self.child.start_kill();
    }
}

fn apply_clipboard_chunk(
    payload: &[u8],
    enabled: bool,
    assembler: &mut ClipboardAssembler,
    current: &mut Option<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !payload.starts_with(b"CB") {
        return Ok(false);
    }
    if !enabled {
        return Ok(true);
    }
    let completed = match assembler.push(payload) {
        Ok(completed) => completed,
        Err(error) => {
            eprintln!("OpenStream dropped malformed clipboard chunk: {error}");
            return Ok(true);
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
    Ok(true)
}

fn configured_limits() -> (u16, u16, u16) {
    let parse = |name: &str, default: u16| {
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    };
    (
        parse("OPENSTREAM_WIDTH", 1920),
        parse("OPENSTREAM_HEIGHT", 1080),
        parse("OPENSTREAM_FPS", 60),
    )
}

/// Everything `spawn_ffmpeg` needs beyond process-global configuration.
struct SpawnRequest {
    codec: VideoCodec,
    width: u16,
    height: u16,
    fps: u16,
    ten_bit: bool,
    four_four_four: bool,
    bitrate_override_mbps: Option<f64>,
    capture_input: Option<String>,
}

const MAX_VIDEO_FILTER_BYTES: usize = 4096;

fn configured_video_filter(width: &str, height: &str) -> Result<String, String> {
    let filter = env::var("OPENSTREAM_VIDEO_FILTER")
        .unwrap_or_else(|_| format!("scale={width}:{height}:flags=fast_bilinear"));
    if filter.trim().is_empty() {
        return Err("OPENSTREAM_VIDEO_FILTER must not be empty".to_string());
    }
    if filter.len() > MAX_VIDEO_FILTER_BYTES {
        return Err(format!(
            "OPENSTREAM_VIDEO_FILTER exceeds {MAX_VIDEO_FILTER_BYTES} bytes"
        ));
    }
    Ok(filter)
}

fn spawn_ffmpeg(
    request: SpawnRequest,
) -> Result<(Child, EncodeProfile), Box<dyn std::error::Error>> {
    let SpawnRequest {
        codec,
        width: negotiated_width,
        height: negotiated_height,
        fps: negotiated_fps,
        ten_bit: negotiated_10_bit,
        four_four_four: negotiated_444,
        bitrate_override_mbps,
        capture_input,
    } = request;
    let executable = env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| DEFAULT_FFMPEG.into());
    let fps = negotiated_fps.to_string();
    let width = negotiated_width.to_string();
    let height = negotiated_height.to_string();
    let keyframe_seconds = keyframe_interval()?;
    // Explicit device input wins; otherwise the multi-monitor selection
    // supplies an x11grab origin for the chosen display.
    let input = env::var("OPENSTREAM_FFMPEG_INPUT").ok().or(capture_input);
    let profile = resolve_encode_profile(
        codec,
        negotiated_width,
        negotiated_height,
        negotiated_fps,
        negotiated_10_bit,
        negotiated_444,
        bitrate_override_mbps,
    )?;
    eprintln!(
        "OpenStream FFmpeg encoder: {} pix_fmt={} bitrate={:.2} Mbps",
        profile.encoder, profile.pix_fmt, profile.bitrate_mbps
    );
    let bitstream_filter = match codec {
        VideoCodec::H264 => "h264_metadata=aud=insert",
        VideoCodec::H265 => "hevc_metadata=aud=insert",
    };
    let video_filter = configured_video_filter(&width, &height)?;
    let output_format = match codec {
        VideoCodec::H264 => "h264",
        VideoCodec::H265 => "hevc",
    };
    let mut command = Command::new(executable);
    command.args(["-hide_banner", "-loglevel", "error"]);
    if let Ok(args) = env::var("OPENSTREAM_FFMPEG_ARGS") {
        command.args(validate_custom_ffmpeg_args(&split_command_line(&args)?)?);
    } else {
        let backend = env::var("OPENSTREAM_CAPTURE_BACKEND").unwrap_or_else(|_| {
            match env::consts::OS {
                "linux" => "x11grab",
                "macos" => "avfoundation",
                "windows" => "gdigrab",
                _ => "unsupported",
            }
            .to_string()
        });
        let arguments = capture_arguments(
            env::consts::OS,
            &backend,
            input.as_deref(),
            &width,
            &height,
            &fps,
        )?;
        command.args(arguments);
    }
    command.args([
        "-an",
        "-vf",
        &video_filter,
        "-force_key_frames",
        &format!("expr:gte(t,n_forced*{keyframe_seconds})"),
        "-bsf:v",
        bitstream_filter,
    ]);
    // Encoder, pixel format, size, and rate come from the negotiated profile
    // so hardware and 10-bit/4:4:4 paths share one argument source. Output
    // options must precede the `pipe:1` output URL.
    let profile_args = openstream_platform::hwaccel::ffmpeg_profile_args(
        &profile.encoder,
        negotiated_width,
        negotiated_height,
        negotiated_fps,
        profile.bitrate_mbps,
        &profile.pix_fmt,
    )
    .map_err(|error| format!("invalid encoder profile: {error}"))?;
    // The profile carries -s/-r/-pix_fmt/-c:v plus rate control; the video
    // filter above already handles scaling and the frame rate flag below
    // already pins -r, so drop the profile's own copies.
    let mut skip_next = false;
    for arg in &profile_args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-s" || arg == "-r" || arg == "-pix_fmt" {
            skip_next = true;
            continue;
        }
        command.arg(arg);
    }
    command.arg("-pix_fmt").arg(&profile.pix_fmt);
    command.args(["-r", &fps, "-f", output_format, "pipe:1"]);
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(Into::into);
    child.map(|child| (child, profile))
}

/// Encoder profile resolved from the environment and the negotiated caps.
#[derive(Debug, Clone, PartialEq)]
struct EncodeProfile {
    encoder: String,
    pix_fmt: String,
    bitrate_mbps: f64,
}

/// Resolve the encoder, pixel format, and bitrate for this session.
///
/// `OPENSTREAM_VIDEO_ENCODER` selects `libx264`/`libx265` (defaults per
/// codec), any `ffmpeg_profile_args` hardware profile, or `auto` for
/// NVENC-first hardware detection with a software fallback.
/// `OPENSTREAM_PIX_FMT` defaults to the richest negotiated format and is
/// rejected when it exceeds negotiation. `OPENSTREAM_VIDEO_MBPS` sets the
/// target bitrate.
fn resolve_encode_profile(
    codec: VideoCodec,
    width: u16,
    height: u16,
    fps: u16,
    negotiated_10_bit: bool,
    negotiated_444: bool,
    bitrate_override_mbps: Option<f64>,
) -> Result<EncodeProfile, String> {
    use openstream_platform::hwaccel::{EncoderCodec, HwReport, validate_pix_fmt};
    let requested = env::var("OPENSTREAM_VIDEO_ENCODER").unwrap_or_default();
    let encoder = if requested.trim().is_empty() || requested.trim() == "auto" {
        let wanted = match codec {
            VideoCodec::H264 => EncoderCodec::H264,
            VideoCodec::H265 => EncoderCodec::H265,
        };
        HwReport::probe()
            .preferred_encoder(wanted)
            .map(str::to_string)
            .unwrap_or_else(|| match codec {
                VideoCodec::H264 => "libx264".into(),
                VideoCodec::H265 => "libx265".into(),
            })
    } else if requested.trim() == "default" {
        match codec {
            VideoCodec::H264 => "libx264".into(),
            VideoCodec::H265 => "libx265".into(),
        }
    } else {
        requested.trim().to_string()
    };
    // Software defaults keep their historic ultrafast/zerolatency flags via
    // ffmpeg_profile_args; validate the name early for a clear error.
    openstream_platform::hwaccel::ffmpeg_profile_args(
        &encoder,
        width.max(1),
        height.max(1),
        fps.max(1),
        1.0,
        "yuv420p",
    )?;
    let pix_fmt = env::var("OPENSTREAM_PIX_FMT").unwrap_or_else(|_| {
        if negotiated_444 {
            "yuv444p".into()
        } else if negotiated_10_bit {
            "yuv420p10le".into()
        } else {
            "yuv420p".into()
        }
    });
    validate_pix_fmt(pix_fmt.trim(), negotiated_10_bit, negotiated_444)?;
    let bitrate_mbps = bitrate_override_mbps
        .filter(|value| {
            value.is_finite()
                && *value > 0.0
                && *value <= openstream_platform::hwaccel::MAX_VIDEO_BITRATE_MBPS
        })
        .or_else(|| {
            env::var("OPENSTREAM_VIDEO_MBPS")
                .ok()
                .and_then(|value| value.parse::<f64>().ok())
                .filter(|value| {
                    value.is_finite()
                        && *value > 0.0
                        && *value <= openstream_platform::hwaccel::MAX_VIDEO_BITRATE_MBPS
                })
        })
        .unwrap_or(10.0);
    Ok(EncodeProfile {
        encoder,
        pix_fmt: pix_fmt.trim().to_string(),
        bitrate_mbps,
    })
}

/// Enumerate host displays for the multi-monitor topology message.
///
/// On Linux the RandR monitor list is preferred; everywhere else (or when
/// `xrandr` is absent) a single synthetic display covers the configured
/// capture dimensions so selection logic stays uniform.
fn enumerate_host_displays(
    fallback_width: u16,
    fallback_height: u16,
) -> Vec<openstream_media::displays::Display> {
    use openstream_media::displays::{Display, parse_xrandr_listmonitors};
    if cfg!(target_os = "linux") {
        if let Ok(output) = std::process::Command::new("xrandr")
            .arg("--listmonitors")
            .stdin(std::process::Stdio::null())
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let displays = parse_xrandr_listmonitors(&text);
                if !displays.is_empty() {
                    return displays;
                }
            }
        }
    }
    vec![Display {
        id: 0,
        x: 0,
        y: 0,
        width: fallback_width.max(1),
        height: fallback_height.max(1),
        flags: 1,
    }]
}

/// Resolve the selected display index from `OPENSTREAM_DISPLAY` (default 0).
/// A configured but malformed/out-of-range value is an error: silently
/// clamping it to another monitor is an especially confusing hosting failure.
fn selected_display(displays: &[openstream_media::displays::Display]) -> Result<usize, String> {
    let requested = std::env::var("OPENSTREAM_DISPLAY").ok();
    resolve_display_index(requested.as_deref(), displays.len())
}

fn resolve_display_index(requested: Option<&str>, count: usize) -> Result<usize, String> {
    let index = match requested {
        None => 0,
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "OPENSTREAM_DISPLAY must be a non-negative display index".to_string())?,
    };
    if index >= count {
        return Err(format!(
            "OPENSTREAM_DISPLAY={index} is unavailable; the host reported {count} display(s)"
        ));
    }
    Ok(index)
}

/// Copy a topology while marking exactly one display as the active capture.
/// The primary bit belongs to the desktop layout; the selected bit belongs to
/// the current stream and lets a client preserve an explicitly configured
/// non-primary monitor instead of immediately forcing the primary one.
fn topology_with_selected(
    displays: &[openstream_media::displays::Display],
    selected: usize,
) -> Vec<openstream_media::displays::Display> {
    use openstream_media::displays::{PRIMARY_FLAG, SELECTED_FLAG};
    displays
        .iter()
        .enumerate()
        .map(|(index, display)| {
            let mut display = *display;
            display.flags &= PRIMARY_FLAG;
            if index == selected {
                display.flags |= SELECTED_FLAG;
            }
            display
        })
        .collect()
}

/// Consume an authenticated monitor-selection request and queue a validated
/// index for the control tick. `MS`-prefixed malformed messages are consumed
/// too, so they cannot fall through into the input parser.
fn queue_display_selection(
    payload: &[u8],
    displays: &[openstream_media::displays::Display],
    current: usize,
    pending: &mut Option<usize>,
    enabled: bool,
) -> bool {
    if !payload.starts_with(b"MS") {
        return false;
    }
    let selected = match openstream_media::displays::decode_select(payload) {
        Ok(selected) => selected,
        Err(error) => {
            eprintln!("OpenStream dropped malformed display selection: {error}");
            return true;
        }
    };
    if !enabled {
        eprintln!(
            "OpenStream ignored display selection because the capture backend is not switchable"
        );
        return true;
    }
    let Some(index) = displays.iter().position(|display| display.id == selected) else {
        eprintln!("OpenStream rejected unavailable display id {selected}");
        return true;
    };
    if index != current {
        *pending = Some(index);
    }
    true
}

/// x11grab input for the selected display (`:0.0+X+Y`), or `None` to keep
/// the default capture origin. Explicit `OPENSTREAM_FFMPEG_INPUT` always
/// wins and is handled by the caller passing it through `capture_input`.
fn display_capture_input(
    displays: &[openstream_media::displays::Display],
    index: usize,
) -> Option<String> {
    let display = displays.get(index)?;
    if display.x == 0 && display.y == 0 {
        return None;
    }
    Some(format!(":0.0+{}+{}", display.x, display.y))
}
///
/// This remains a pure function so the platform profile can be tested on any
/// host. `OPENSTREAM_FFMPEG_ARGS` is the escape hatch for a custom FFmpeg
/// input, while this function handles the safe, documented profiles:
/// `x11grab`, `pipewire`, `avfoundation`, and `gdigrab`.
fn capture_arguments(
    platform: &str,
    backend: &str,
    input: Option<&str>,
    width: &str,
    height: &str,
    fps: &str,
) -> Result<Vec<String>, String> {
    let mut arguments = Vec::new();
    match (platform, backend) {
        ("linux", "x11grab") => {
            let display = input.unwrap_or(":0.0");
            arguments.extend([
                "-f".to_string(),
                "x11grab".to_string(),
                "-framerate".to_string(),
                fps.to_string(),
                "-video_size".to_string(),
                format!("{width}x{height}"),
                "-i".to_string(),
                display.to_string(),
            ]);
        }
        ("linux", "pipewire") => {
            let node = input.ok_or(
                "OPENSTREAM_CAPTURE_BACKEND=pipewire requires OPENSTREAM_FFMPEG_INPUT to name a PipeWire node",
            )?;
            arguments.extend([
                "-f".to_string(),
                "pipewire".to_string(),
                "-framerate".to_string(),
                fps.to_string(),
                "-video_size".to_string(),
                format!("{width}x{height}"),
                "-i".to_string(),
                node.to_string(),
            ]);
        }
        ("macos", "avfoundation") => {
            let device = input.unwrap_or("1:none");
            arguments.extend([
                "-f".to_string(),
                "avfoundation".to_string(),
                "-framerate".to_string(),
                fps.to_string(),
                "-i".to_string(),
                device.to_string(),
            ]);
        }
        ("windows", "gdigrab") => {
            let device = input.unwrap_or("desktop");
            arguments.extend([
                "-f".to_string(),
                "gdigrab".to_string(),
                "-framerate".to_string(),
                fps.to_string(),
                "-i".to_string(),
                device.to_string(),
            ]);
        }
        ("linux" | "macos" | "windows", "custom") => {
            return Err(
                "OPENSTREAM_CAPTURE_BACKEND=custom requires OPENSTREAM_FFMPEG_ARGS".to_string(),
            );
        }
        ("linux" | "macos" | "windows", other) => {
            return Err(format!(
                "capture backend {other:?} is not supported on {platform}; use x11grab/pipewire, avfoundation, gdigrab, or custom"
            ));
        }
        _ => return Err("FFmpeg host is supported on Linux, Windows, and macOS".to_string()),
    }
    Ok(arguments)
}

fn spawn_audio_ffmpeg() -> Result<Child, Box<dyn std::error::Error>> {
    let executable = env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| DEFAULT_FFMPEG.into());
    let args = env::var("OPENSTREAM_AUDIO_FFMPEG_ARGS").or_else(|_| {
        if env::var("OPENSTREAM_AUDIO_TEST").as_deref() == Ok("1") {
            Ok("-f lavfi -i sine=frequency=440:sample_rate=48000".to_string())
        } else {
            Err(std::env::VarError::NotPresent)
        }
    })?;
    let mut command = Command::new(executable);
    command.args(["-hide_banner", "-loglevel", "error"]);
    // Audio must share the live wall clock with video. Without `-re`, lavfi
    // and many file/device inputs can drain faster than real time and fill a
    // network queue with minutes of samples during a one-second session.
    command.arg("-re");
    command.args(validate_custom_ffmpeg_args(&split_command_line(&args)?)?);
    command.args(["-vn", "-ar", "48000", "-ac", "2", "-f", "s16le", "pipe:1"]);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(Into::into)
}

async fn send_access_unit(
    session: &mut PeerSession,
    frame_id: u32,
    presentation_time_us: u64,
    payload: &[u8],
    codec: VideoCodec,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyframe = contains_idr(payload, codec);
    for fragment in fragment_frame(frame_id, presentation_time_us, keyframe, payload)? {
        queue_stream_packet(session, Kind::Video, &fragment)?;
    }
    Ok(())
}

#[derive(Debug)]
struct AccessUnitizer {
    bytes: Vec<u8>,
    codec: VideoCodec,
}

impl AccessUnitizer {
    fn for_codec(codec: VideoCodec) -> Self {
        Self {
            bytes: Vec::new(),
            codec,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if bytes.len() > MAX_PENDING_ACCESS_UNIT_BYTES
            || self.bytes.len().saturating_add(bytes.len()) > MAX_PENDING_ACCESS_UNIT_BYTES
        {
            self.bytes.clear();
            return Err(format!(
                "FFmpeg access-unit buffer exceeded {} bytes",
                MAX_PENDING_ACCESS_UNIT_BYTES
            ));
        }
        self.bytes.extend_from_slice(bytes);
        let boundaries = aud_boundaries(&self.bytes, self.codec);
        if boundaries.len() < 2 {
            return Ok(Vec::new());
        }
        let mut output = Vec::with_capacity(boundaries.len() - 1);
        let mut start = 0;
        for &boundary in boundaries.iter().skip(1) {
            if boundary > start {
                output.push(self.bytes[start..boundary].to_vec());
            }
            start = boundary;
        }
        self.bytes.drain(..start);
        Ok(output)
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        (!self.bytes.is_empty()).then(|| std::mem::take(&mut self.bytes))
    }
}

fn aud_boundaries(bytes: &[u8], codec: VideoCodec) -> Vec<usize> {
    let mut boundaries = Vec::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        let start_code = if bytes[index..].starts_with(&[0, 0, 1]) {
            3
        } else if bytes[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        let is_aud = bytes
            .get(index + start_code)
            .is_some_and(|byte| match codec {
                VideoCodec::H264 => byte & 0x1f == 9,
                VideoCodec::H265 => (byte >> 1) & 0x3f == 35,
            });
        if is_aud {
            boundaries.push(index);
        }
        index += start_code;
    }
    boundaries
}

fn keyframe_interval() -> Result<String, String> {
    let seconds = env::var("OPENSTREAM_KEYFRAME_SECONDS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(2.0);
    if !seconds.is_finite() || !(MIN_KEYFRAME_SECONDS..=MAX_KEYFRAME_SECONDS).contains(&seconds) {
        return Err(format!(
            "OPENSTREAM_KEYFRAME_SECONDS must be finite and between {MIN_KEYFRAME_SECONDS} and {MAX_KEYFRAME_SECONDS}"
        ));
    }
    Ok(format!("{seconds:.3}"))
}

fn contains_idr(bytes: &[u8], codec: VideoCodec) -> bool {
    let mut index = 0;
    while index + 4 < bytes.len() {
        let start_code = if bytes[index..].starts_with(&[0, 0, 1]) {
            3
        } else if bytes[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        let is_idr = bytes
            .get(index + start_code)
            .is_some_and(|byte| match codec {
                VideoCodec::H264 => byte & 0x1f == 5,
                VideoCodec::H265 => (byte >> 1) & 0x3f >= 19 && (byte >> 1) & 0x3f <= 21,
            });
        if is_idr {
            return true;
        }
        index += start_code;
    }
    false
}

fn expected_peer_disconnect(message: &str) -> bool {
    [
        "Connection refused",
        "connection refused",
        "Connection reset",
        "connection reset",
        "Broken pipe",
        "broken pipe",
        "connection closed",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

/// Split user-supplied FFmpeg arguments without invoking a shell.
///
/// Capture device names frequently contain spaces on Windows and macOS. A
/// plain `split_whitespace` silently changes such a name into multiple FFmpeg
/// arguments, while passing the complete string to a shell would introduce a
/// command-injection boundary. This small parser supports the quoting and
/// escaping needed by device arguments and rejects malformed input before the
/// process starts.
fn split_command_line(spec: &str) -> Result<Vec<String>, String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut token_started = false;

    for character in spec.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            token_started = true;
            continue;
        }
        match (quote, character) {
            (_, '\\') => {
                escaped = true;
                token_started = true;
            }
            (Some(delimiter), value) if value == delimiter => quote = None,
            (Some(_), value) => {
                current.push(value);
                token_started = true;
            }
            (None, '\'' | '"') => {
                quote = Some(character);
                token_started = true;
            }
            (None, value) if value.is_whitespace() => {
                if token_started {
                    arguments.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            (None, value) => {
                current.push(value);
                token_started = true;
            }
        }
    }
    if escaped {
        return Err("FFmpeg argument string ends with an escape".to_string());
    }
    if quote.is_some() {
        return Err("FFmpeg argument string has an unterminated quote".to_string());
    }
    if token_started {
        arguments.push(current);
    }
    Ok(arguments)
}

/// Validate the operator-supplied input portion before appending OpenStream's
/// output pipeline.  The command is launched without a shell, but an argument
/// that replaces `pipe:1` could still redirect encoded media to an arbitrary
/// file/device or make the process block forever.
fn validate_custom_ffmpeg_args(args: &[String]) -> Result<&[String], String> {
    if args.is_empty() {
        return Err("FFmpeg argument string must not be empty".to_string());
    }
    if args.len() > MAX_FFMPEG_ARGS {
        return Err(format!(
            "FFmpeg argument string contains more than {MAX_FFMPEG_ARGS} arguments"
        ));
    }
    let total_bytes: usize = args.iter().map(String::len).sum();
    if total_bytes > MAX_FFMPEG_ARGS_BYTES {
        return Err(format!(
            "FFmpeg argument string exceeds {MAX_FFMPEG_ARGS_BYTES} bytes"
        ));
    }
    if args
        .iter()
        .any(|argument| argument.len() > MAX_FFMPEG_ARG_BYTES)
    {
        return Err(format!(
            "an FFmpeg argument exceeds {MAX_FFMPEG_ARG_BYTES} bytes"
        ));
    }
    if args.iter().any(|argument| {
        matches!(argument.as_str(), "pipe:0" | "pipe:1")
            || argument.starts_with("file:")
            || argument.starts_with("tcp:")
            || argument.starts_with("udp:")
    }) {
        return Err(
            "custom FFmpeg arguments must describe input only; output URLs are not allowed"
                .to_string(),
        );
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use openstream_client_core::VideoCodec;
    use openstream_media::{BitrateDecision, BitrateReason};

    use super::{
        AccessUnitizer, MAX_FFMPEG_ARGS, MAX_VIDEO_FILTER_BYTES, capture_arguments,
        configured_video_filter, contains_idr, display_capture_input, enumerate_host_displays,
        queue_display_selection, remember_adaptive_decision, resolve_display_index,
        resolve_encode_profile, split_command_line, topology_with_selected,
        validate_custom_ffmpeg_args,
    };

    #[test]
    fn display_switch_does_not_drop_pending_adaptive_decision() {
        let decision = BitrateDecision {
            bitrate_mbps: 7.0,
            reason: BitrateReason::Loss,
            pending_frames: 8,
            oldest_frame_age_ms: 300,
            smoothed_ack_ms: Some(120.0),
        };
        let mut pending = None;

        remember_adaptive_decision(&mut pending, Some(decision));
        // A display-switch branch does not produce a new telemetry decision.
        remember_adaptive_decision(&mut pending, None);

        assert_eq!(pending, Some(decision));
    }

    #[test]
    fn detects_three_and_four_byte_idr_start_codes() {
        assert!(contains_idr(&[0, 0, 1, 0x65, 0xaa], VideoCodec::H264));
        assert!(contains_idr(&[0, 0, 0, 1, 0x65, 0xbb], VideoCodec::H264));
        assert!(!contains_idr(&[0, 0, 1, 0x41, 0xaa], VideoCodec::H264));
        assert!(contains_idr(&[0, 0, 1, 0x26, 0xaa], VideoCodec::H265));
    }

    #[test]
    fn groups_annex_b_bytes_at_aud_boundaries() {
        let mut unitizer = AccessUnitizer::for_codec(VideoCodec::H264);
        assert!(unitizer.push(&[0, 0, 1, 9, 0x10, 0, 0]).unwrap().is_empty());
        let units = unitizer
            .push(&[1, 9, 0x30, 0, 0, 1, 9, 0x40, 0, 0, 1, 0x41, 0xaa])
            .unwrap();
        assert_eq!(units, vec![vec![0, 0, 1, 9, 0x10], vec![0, 0, 1, 9, 0x30]]);
        assert_eq!(
            unitizer.finish(),
            Some(vec![0, 0, 1, 9, 0x40, 0, 0, 1, 0x41, 0xaa])
        );
    }

    #[test]
    fn preserves_quoted_capture_device_names_without_a_shell() {
        assert_eq!(
            split_command_line("-f avfoundation -i \"1:Built-in Audio\"").unwrap(),
            vec!["-f", "avfoundation", "-i", "1:Built-in Audio",]
        );
        assert_eq!(
            split_command_line(r#"-i 'Desktop Capture' -vf scale=1920:1080"#).unwrap(),
            vec!["-i", "Desktop Capture", "-vf", "scale=1920:1080"]
        );
    }

    #[test]
    fn rejects_malformed_argument_quoting() {
        assert!(split_command_line("-i \\").is_err());
        assert!(split_command_line("-i \"desktop").is_err());
    }

    #[test]
    fn rejects_custom_output_and_unbounded_argument_lists() {
        assert!(validate_custom_ffmpeg_args(&["-i".into(), "pipe:1".into()]).is_err());
        assert!(validate_custom_ffmpeg_args(&[]).is_err());
        let too_many = (0..=MAX_FFMPEG_ARGS)
            .map(|index| format!("arg{index}"))
            .collect::<Vec<_>>();
        assert!(validate_custom_ffmpeg_args(&too_many).is_err());
    }

    #[test]
    fn bounds_custom_video_filter() {
        with_env_many(&[("OPENSTREAM_VIDEO_FILTER", None)], || {
            assert!(
                configured_video_filter("1920", "1080")
                    .expect("default filter")
                    .starts_with("scale=1920:1080")
            );
        });
        let oversized = "x".repeat(MAX_VIDEO_FILTER_BYTES + 1);
        with_env_many(
            &[("OPENSTREAM_VIDEO_FILTER", Some(oversized.as_str()))],
            || assert!(configured_video_filter("1920", "1080").is_err()),
        );
    }

    #[test]
    fn builds_each_documented_desktop_capture_profile() {
        assert_eq!(
            capture_arguments("linux", "x11grab", None, "1920", "1080", "60").unwrap(),
            vec![
                "-f",
                "x11grab",
                "-framerate",
                "60",
                "-video_size",
                "1920x1080",
                "-i",
                ":0.0"
            ]
        );
        assert_eq!(
            capture_arguments(
                "linux",
                "pipewire",
                Some("screen-node"),
                "1280",
                "720",
                "30"
            )
            .unwrap(),
            vec![
                "-f",
                "pipewire",
                "-framerate",
                "30",
                "-video_size",
                "1280x720",
                "-i",
                "screen-node"
            ]
        );
        assert_eq!(
            capture_arguments(
                "macos",
                "avfoundation",
                Some("2:none"),
                "1920",
                "1080",
                "60"
            )
            .unwrap(),
            vec!["-f", "avfoundation", "-framerate", "60", "-i", "2:none"]
        );
        assert_eq!(
            capture_arguments(
                "windows",
                "gdigrab",
                Some("title=Game"),
                "1920",
                "1080",
                "60"
            )
            .unwrap(),
            vec!["-f", "gdigrab", "-framerate", "60", "-i", "title=Game"]
        );
    }

    #[test]
    fn rejects_invalid_or_incomplete_capture_profiles() {
        assert!(capture_arguments("linux", "pipewire", None, "1", "1", "1").is_err());
        assert!(capture_arguments("windows", "pipewire", None, "1", "1", "1").is_err());
        assert!(capture_arguments("linux", "custom", None, "1", "1", "1").is_err());
        assert!(capture_arguments("freebsd", "x11grab", None, "1", "1", "1").is_err());
    }

    fn with_env_many(vars: &[(&str, Option<&str>)], run: impl FnOnce()) {
        // Process environment is global: serialize every env-touching test
        // so parallel runners cannot observe each other's variables.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let saved: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect();
        unsafe {
            for (key, value) in vars {
                match value {
                    Some(text) => std::env::set_var(key, text),
                    None => std::env::remove_var(key),
                }
            }
        }
        run();
        unsafe {
            for (key, value) in saved {
                match value {
                    Some(previous) => std::env::set_var(key, previous),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn encode_profile_defaults_to_software_420() {
        with_env_many(
            &[
                ("OPENSTREAM_VIDEO_ENCODER", None),
                ("OPENSTREAM_PIX_FMT", None),
                ("OPENSTREAM_VIDEO_MBPS", None),
            ],
            || {
                let profile =
                    resolve_encode_profile(VideoCodec::H264, 1920, 1080, 60, false, false, None)
                        .expect("default profile");
                assert_eq!(profile.pix_fmt, "yuv420p");
                assert!((profile.bitrate_mbps - 10.0).abs() < f64::EPSILON);
                assert!(
                    profile.encoder == "libx264"
                        || profile.encoder.ends_with("nvenc")
                        || profile.encoder.ends_with("vaapi")
                );
            },
        );
    }

    #[test]
    fn encode_profile_rejects_444_without_negotiation() {
        with_env_many(
            &[
                ("OPENSTREAM_VIDEO_ENCODER", Some("libx264")),
                ("OPENSTREAM_PIX_FMT", Some("yuv444p")),
            ],
            || {
                assert!(
                    resolve_encode_profile(VideoCodec::H264, 1920, 1080, 60, false, false, None)
                        .is_err()
                );
                assert!(
                    resolve_encode_profile(VideoCodec::H264, 1920, 1080, 60, false, true, None)
                        .is_ok()
                );
            },
        );
    }

    #[test]
    fn encode_profile_honors_bitrate_override() {
        with_env_many(
            &[
                ("OPENSTREAM_VIDEO_ENCODER", Some("libx264")),
                ("OPENSTREAM_PIX_FMT", Some("yuv420p")),
                ("OPENSTREAM_VIDEO_MBPS", Some("8.0")),
            ],
            || {
                let live =
                    resolve_encode_profile(VideoCodec::H264, 1920, 1080, 60, false, false, None)
                        .expect("env profile");
                assert!((live.bitrate_mbps - 8.0).abs() < f64::EPSILON);
                let restarted = resolve_encode_profile(
                    VideoCodec::H264,
                    1920,
                    1080,
                    60,
                    false,
                    false,
                    Some(3.5),
                )
                .expect("restart profile");
                assert!((restarted.bitrate_mbps - 3.5).abs() < f64::EPSILON);
            },
        );
    }

    #[test]
    fn display_selection_names_x11grab_offsets() {
        use openstream_media::displays::Display;
        let displays = vec![
            Display {
                id: 0,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                flags: 1,
            },
            Display {
                id: 1,
                x: 1920,
                y: 0,
                width: 1280,
                height: 1024,
                flags: 0,
            },
        ];
        assert_eq!(display_capture_input(&displays, 0), None);
        assert_eq!(
            display_capture_input(&displays, 1),
            Some(":0.0+1920+0".to_string())
        );
        assert_eq!(display_capture_input(&displays, 9), None);
        assert_eq!(display_capture_input(&[], 0), None);
    }

    #[test]
    fn display_enumeration_always_yields_one_fallback() {
        let displays = enumerate_host_displays(1920, 1080);
        assert!(!displays.is_empty());
        assert!(displays.iter().any(|display| display.primary()));
    }

    #[test]
    fn display_selection_is_fail_closed_instead_of_clamped() {
        assert_eq!(resolve_display_index(None, 2), Ok(0));
        assert_eq!(resolve_display_index(Some("1"), 2), Ok(1));
        assert!(resolve_display_index(Some("bogus"), 2).is_err());
        assert!(resolve_display_index(Some("2"), 2).is_err());
        assert!(resolve_display_index(Some("0"), 0).is_err());
    }

    #[test]
    fn display_selection_queues_only_a_known_id() {
        use openstream_media::displays::{Display, SELECTED_FLAG};
        let displays = vec![
            Display {
                id: 10,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                flags: 1,
            },
            Display {
                id: 20,
                x: 1920,
                y: 0,
                width: 1280,
                height: 1024,
                flags: 0,
            },
        ];
        let mut pending = None;
        assert!(queue_display_selection(
            &openstream_media::displays::encode_select(20),
            &displays,
            0,
            &mut pending,
            true,
        ));
        assert_eq!(pending, Some(1));
        assert!(queue_display_selection(
            &openstream_media::displays::encode_select(99),
            &displays,
            0,
            &mut pending,
            true,
        ));
        assert_eq!(pending, Some(1));
        assert!(!queue_display_selection(
            b"input",
            &displays,
            0,
            &mut pending,
            true
        ));
        let topology = topology_with_selected(&displays, 1);
        assert!(!topology[0].selected());
        assert_eq!(topology[1].flags, SELECTED_FLAG);
    }
}
