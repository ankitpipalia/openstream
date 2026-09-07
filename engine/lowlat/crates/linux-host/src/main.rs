//! OpenStream Linux host adapter.
//!
//! This is the first real host-side integration: it consumes the existing
//! Linux display/encoder pipeline, establishes the project-owned session, and
//! packetizes its encoded access units into OpenStream encrypted UDP. It is a
//! headless host adapter, not a settings UI.

#[cfg(target_os = "linux")]
mod pipewire;
#[cfg(target_os = "linux")]
mod x11;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("openstream-linux-host requires a Linux target");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use lowlat::stream::{Backend, Codec, Config, Quality, Stream};
    use lowlat_inject::event::{Extents, Injector};
    use lowlat_inject::uinput::Devices;
    use openstream_client_core::{
        Capabilities, Pairing, PeerSession, ReliableControl, Role, VideoCodec, parse_stun_servers,
    };
    use openstream_media::clipboard::{Assembler as ClipboardAssembler, fragment_text};
    use openstream_media::input::RumbleEvent;
    use openstream_media::{
        AdaptiveBitrate, AudioFrame, FrameAck, KEYFRAME_REQUEST, fragment_frame,
    };
    use openstream_platform::clipboard as platform_clipboard;
    use openstream_platform::clipboard_policy::ClipboardPolicy;
    use openstream_protocol::Kind;

    let origin = env::var("OPENSTREAM_SIGNAL_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    // Diagnostics mode: report X11 screens and PipeWire source nodes as JSON
    // and exit before touching signaling. Used by setup scripts and the
    // multi-monitor acceptance path.
    if env::var("OPENSTREAM_LIST_DISPLAYS").as_deref() == Ok("1") {
        return list_displays();
    }
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
        PeerSession::establish_configured(&origin, &pairing, Role::Host, bind, &stun_servers)
            .await?;
    eprintln!(
        "OpenStream selected data path: {:?}",
        session.connection_path()
    );
    let host_policy = openstream_platform::policy::HostPolicy::from_env();
    eprintln!("{}", host_policy.log_line());
    let clipboard_policy = ClipboardPolicy::from_env();
    eprintln!("{}", clipboard_policy.log_line());
    let input_enabled = host_policy.input;
    let audio_requested = env::var("OPENSTREAM_AUDIO").as_deref() == Ok("1");
    let clipboard_requested = host_policy.clipboard;
    let mut host_capabilities = Capabilities::host_with_limits(1920, 1080, 60);
    host_capabilities.video_codecs = vec![VideoCodec::H264];
    host_capabilities.input = input_enabled;
    host_capabilities.rumble = host_policy.gamepad;
    host_capabilities.clipboard = clipboard_requested && platform_clipboard::available();
    host_capabilities.microphone = host_policy.microphone;
    if !audio_requested {
        host_capabilities.audio_codecs.clear();
    }
    let negotiated = session
        .negotiate_host_with_capabilities(host_capabilities)
        .await?;
    if negotiated.video != VideoCodec::H264 {
        return Err("the Linux lowlat adapter currently emits H.264 only".into());
    }
    let mut reliable_control = ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
    let seconds = env::var("OPENSTREAM_HOST_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(15)
        .min(24 * 60 * 60);
    let output = env::var("LOWLAT_OUTPUT").ok();
    let backend = match env::var("LOWLAT_BACKEND").as_deref() {
        Ok("vendor") => Some(Backend::Vendor),
        Ok("open") => Some(Backend::Open),
        _ => None,
    };
    let audio_enabled =
        audio_requested && negotiated.audio == Some(openstream_client_core::AudioCodec::Opus);
    let audio_device = env::var("OPENSTREAM_AUDIO_DEVICE").ok();
    let audio_mute_local = env::var("OPENSTREAM_AUDIO_MUTE_LOCAL").as_deref() == Ok("1");
    let audio_kbps = env::var("OPENSTREAM_AUDIO_KBPS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0 && *value <= 512)
        .unwrap_or(128);
    let configured_mbps = positive_mbps("OPENSTREAM_VIDEO_MBPS", 10.0);
    let min_mbps = positive_mbps("OPENSTREAM_VIDEO_MIN_MBPS", 1.0).min(configured_mbps);
    let adaptive_enabled = env::var("OPENSTREAM_ADAPTIVE_BITRATE").as_deref() != Ok("0");
    let mut adaptive =
        adaptive_enabled.then(|| AdaptiveBitrate::new(configured_mbps, min_mbps, configured_mbps));
    let stream = Stream::start(Config {
        audio: audio_enabled.then(|| lowlat_audio::Config {
            server: env::var("OPENSTREAM_AUDIO_SERVER").ok(),
            wanted: std::sync::Arc::new(lowlat_audio::Wanted::new(lowlat_audio::Live {
                device: audio_device,
                mute_local: audio_mute_local,
            })),
        }),
        convert: None,
        prefer_vulkan: false,
        audio_on: audio_enabled,
        // The native seat takes the guest microphone only when negotiated
        // and explicitly allowed by host policy.
        accept_microphone: negotiated.microphone && host_policy.microphone,
        audio_kbps,
        allow_raw_audio: false,
        output: output.clone(),
        display: true,
        width: u32::from(negotiated.width),
        height: u32::from(negotiated.height),
        fps: u32::from(negotiated.fps),
        cg_level: 1,
        full_fps: false,
        quality: Quality::default(),
        // The OpenStream Linux adapter currently advertises and packetizes
        // H.264 only. Do not let a process-level LOWLAT_CODEC override turn
        // this into an H.265 producer after capability negotiation promised
        // the client H.264 access units.
        codec: Codec::H264,
        backend,
        configured_mbps,
        min_mbps,
        rotation: lowlat_core::video::Rotation::None,
        detail_rows: 0,
    });
    let wake = lowlat_net::Wake::new()?;
    let seat = stream
        .seats()
        .take(wake.handle()?, wake.handle()?)
        .ok_or("no free lowlat seat")?;
    if audio_enabled {
        // OpenStream's initial audio profile is Opus. The lowlat seat owns
        // the capture queue and keeps the encoding choice per guest.
        seat.declare_audio(false);
    }

    let mut input = if input_enabled {
        Some((
            Injector::new(Extents::alone(
                u32::from(negotiated.width),
                u32::from(negotiated.height),
            )),
            Devices::create("openstream")?,
        ))
    } else {
        None
    };

    let started = Instant::now();
    let mut frame_id = 0_u32;
    let mut audio_sequence = 0_u32;
    let mut frames = 0_u64;
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    let mut clipboard_assembler = ClipboardAssembler::default();
    let mut clipboard_transfer_id = 1_u32;
    let mut clipboard_value = if clipboard_policy.may_send(negotiated.clipboard) {
        platform_clipboard::read_text().ok()
    } else {
        None
    };
    let mut clipboard_tick = tokio::time::interval(Duration::from_millis(500));
    while started.elapsed() < Duration::from_secs(seconds) {
        tokio::select! {
            packet = session.recv() => {
                let packet = packet?;
                if packet.kind == Kind::Control {
                    if let Some(deliveries) = reliable_control.receive(&mut session, &packet).await? {
                        for payload in deliveries {
                            if let Ok(ack) = FrameAck::decode(&payload) {
                                if let Some(adaptive) = adaptive.as_mut() {
                                    let _ = adaptive.frame_acknowledged_with_loss(
                                        ack.frame_id,
                                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                                        ack.lost_frames,
                                    );
                                }
                            } else if payload == KEYFRAME_REQUEST {
                                seat.request_refresh();
                            } else if payload == b"openstream/end" {
                                return Ok(());
                            } else if apply_clipboard_chunk(
                                &payload,
                                clipboard_policy.may_apply(negotiated.clipboard),
                                &mut clipboard_assembler,
                                &mut clipboard_value,
                            )? {
                                // Clipboard data is handled only after both
                                // peers explicitly negotiated the feature.
                            } else if payload != b"openstream/frame-ack"
                                && payload != b"openstream/end"
                                && let Some((injector, devices)) = input.as_mut()
                            {
                                apply_input_payload(&payload, injector, devices);
                            }
                        }
                        continue;
                    }
                    if packet.payload == KEYFRAME_REQUEST {
                        seat.request_refresh();
                        continue;
                    }
                    if let Ok(ack) = FrameAck::decode(&packet.payload) {
                        if let Some(adaptive) = adaptive.as_mut() {
                            let _ = adaptive.frame_acknowledged_with_loss(
                                ack.frame_id,
                                started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                                ack.lost_frames,
                            );
                        }
                        continue;
                    }
                    if packet.payload == b"openstream/end" {
                        return Ok(());
                    }
                    if apply_clipboard_chunk(
                        &packet.payload,
                        clipboard_policy.may_apply(negotiated.clipboard),
                        &mut clipboard_assembler,
                        &mut clipboard_value,
                    )? {
                        continue;
                    }
                }
                if packet.kind != Kind::Input {
                    continue;
                }
                let Some((injector, devices)) = input.as_mut() else {
                    continue;
                };
                match lowlat_core::control::parse(&packet.payload) {
                    Ok(control) => injector.on_control(&control, devices),
                    Err(error) => eprintln!("OpenStream dropped malformed input: {error}"),
                }
            }
            _ = tick.tick() => {
                if let Some((_, devices)) = input.as_mut() {
                    devices.tick();
                    while let Some(rumble) = devices.rumble() {
                        let payload = RumbleEvent {
                            device_id: rumble.pad,
                            strong: rumble.large,
                            weak: rumble.small,
                        }
                        .encode();
                        reliable_control.send(&mut session, &payload).await?;
                    }
                }
                reliable_control.retry(&mut session).await?;
                session.maintain_liveness().await?;
                if let Some(adaptive) = adaptive.as_mut()
                    && let Some(decision) = adaptive.tick(
                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    )
                {
                    let mut live = stream.video();
                    live.bitrate_mbps = decision.bitrate_mbps;
                    stream.set_video(live);
                    eprintln!(
                        "OpenStream adaptive bitrate: {:.2} Mbps ({:?}, pending={}, oldest={}ms, ack={:?}ms)",
                        decision.bitrate_mbps,
                        decision.reason,
                        decision.pending_frames,
                        decision.oldest_frame_age_ms,
                        decision.smoothed_ack_ms
                    );
                }
                if audio_enabled {
                    while let Some(audio) = seat.next_audio() {
                        let encoded = AudioFrame {
                            sequence: audio_sequence,
                            presentation_time_us: started
                                .elapsed()
                                .as_micros()
                                .try_into()
                                .unwrap_or(u64::MAX),
                            payload: audio.bytes().to_vec(),
                        }
                        .encode()?;
                        drop(audio);
                        session.send(Kind::Audio, 0, 0, &encoded).await?;
                        audio_sequence = audio_sequence.wrapping_add(1);
                    }
                }
                let Some(frame) = seat.next_frame() else {
                    continue;
                };
                let keyframe = frame.keyframe();
                let encoded = frame.bytes().to_vec();
                drop(frame);
                let timestamp = started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
                for fragment in fragment_frame(frame_id, timestamp, keyframe, &encoded)? {
                    session.send(Kind::Video, 0, 0, &fragment).await?;
                }
                if let Some(adaptive) = adaptive.as_mut() {
                    adaptive.frame_sent(
                        frame_id,
                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    );
                }
                frame_id = frame_id.wrapping_add(1);
                frames += 1;
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
        }
    }
    let _ = session.release_upnp().await;
    eprintln!("OpenStream Linux host sent {frames} encoded frames");
    eprintln!("OpenStream transport stats: {:?}", session.stats());
    Ok(())
}

#[cfg(target_os = "linux")]
fn list_displays() -> Result<(), Box<dyn std::error::Error>> {
    let x11_screens = match x11::Connection::open(None) {
        Ok(connection) => connection
            .screens
            .iter()
            .map(|screen| {
                serde_json::json!({
                    "index": screen.index,
                    "root": screen.root,
                    "width_px": screen.width_px,
                    "height_px": screen.height_px,
                    "width_mm": screen.width_mm,
                    "height_mm": screen.height_mm,
                    "root_depth": screen.root_depth,
                    "root_visual": screen.root_visual,
                })
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            eprintln!("OpenStream X11 enumeration unavailable: {error}");
            Vec::new()
        }
    };
    let pipewire_nodes = match pipewire::list_source_nodes() {
        Ok(nodes) => nodes
            .iter()
            .map(|node| {
                serde_json::json!({
                    "id": node.id,
                    "name": node.name,
                    "media_class": node.media_class,
                    "object_serial": node.object_serial,
                })
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            eprintln!("OpenStream PipeWire enumeration unavailable: {error}");
            Vec::new()
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "x11_screens": x11_screens,
            "pipewire_nodes": pipewire_nodes,
        })
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn positive_mbps(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| {
            value.is_finite()
                && *value > 0.0
                && *value <= openstream_platform::hwaccel::MAX_VIDEO_BITRATE_MBPS
        })
        .unwrap_or(default)
}

#[cfg(target_os = "linux")]
fn apply_clipboard_chunk(
    payload: &[u8],
    enabled: bool,
    assembler: &mut openstream_media::clipboard::Assembler,
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
        Some(openstream_media::clipboard::CompletedClipboard::Text(text)) => {
            match openstream_platform::clipboard::write_text(&text) {
                Ok(()) => *current = Some(text),
                Err(error) => eprintln!("OpenStream could not apply clipboard text: {error}"),
            }
        }
        Some(openstream_media::clipboard::CompletedClipboard::Clear) => {
            match openstream_platform::clipboard::clear() {
                Ok(()) => *current = Some(String::new()),
                Err(error) => eprintln!("OpenStream could not clear the clipboard: {error}"),
            }
        }
        None => {}
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn apply_input_payload(
    payload: &[u8],
    injector: &mut lowlat_inject::event::Injector,
    devices: &mut lowlat_inject::uinput::Devices,
) {
    if let Ok(event) = openstream_media::input::InputEvent::decode(payload) {
        let fields = event.lowlat_fields();
        if fields.opcode == lowlat_core::control::op::RELEASE {
            injector.release_all(devices);
            return;
        }
        let control = lowlat_core::control::Control {
            a0: fields.a0,
            a1: fields.a1,
            a2: fields.a2,
            opcode: fields.opcode,
            body: &[],
        };
        let mut encoded = [0_u8; lowlat_core::control::CONTROL_HEADER_LEN];
        if lowlat_core::control::encode_header(&mut encoded, &control).is_ok()
            && let Ok(control) = lowlat_core::control::parse(&encoded)
        {
            injector.on_control(&control, devices);
        }
        return;
    }

    // Keep accepting the imported lowlat control payload while older desktop
    // clients migrate to the project-owned OI envelope.
    if let Ok(control) = lowlat_core::control::parse(payload) {
        injector.on_control(&control, devices);
    }
}
