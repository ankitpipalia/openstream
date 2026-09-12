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

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("openstream-linux-host requires a Linux target");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::SocketAddr;

    use lowlat::display::Display as NativeDisplay;
    use lowlat::stream::{Backend, Codec, Config, Quality, Stream};
    use lowlat_inject::event::{Extents, Injector, Permissions};
    use lowlat_inject::uinput::Devices;
    use openstream_client_core::{
        Capabilities, PeerSession, ReliableControl, Role, VideoCodec,
        load_pairing_from_environment, parse_stun_servers,
    };
    use openstream_media::clipboard::{Assembler as ClipboardAssembler, fragment_text};
    use openstream_media::input::{InputLease, RumbleEvent};
    use openstream_media::microphone::GuestMicSink;
    use openstream_media::{
        AdaptiveBitrate, AudioFrame, FrameAck, KEYFRAME_REQUEST, fragment_frame,
    };
    use openstream_platform::clipboard as platform_clipboard;
    use openstream_platform::clipboard_policy::ClipboardPolicy;
    use openstream_platform::policy::{
        HostCapabilityProbes, HostDeviceCapabilities, RuntimeAvailability, UnavailableReason,
    };
    use openstream_protocol::Kind;

    let origin = env::var("OPENSTREAM_SIGNAL_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    // Diagnostics mode: report X11 screens and PipeWire source nodes as JSON
    // and exit before touching signaling. Used by setup scripts and the
    // multi-monitor acceptance path.
    if env::var("OPENSTREAM_LIST_DISPLAYS").as_deref() == Ok("1") {
        return list_displays();
    }
    if env::args().any(|argument| argument == "--preflight")
        || env::var("OPENSTREAM_LINUX_HOST_PREFLIGHT").as_deref() == Ok("1")
    {
        return preflight();
    }
    let pairing = load_pairing_from_environment()?;
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
    let input_probe = if host_policy.input {
        match Devices::probe() {
            Ok(()) => RuntimeAvailability::Available,
            Err(error) => RuntimeAvailability::Unavailable(match error {
                lowlat_inject::uinput::Error::NoModule => UnavailableReason::DeviceUnavailable,
                lowlat_inject::uinput::Error::NotPermitted => UnavailableReason::PermissionDenied,
                lowlat_inject::uinput::Error::Confined(_)
                | lowlat_inject::uinput::Error::Failed(_) => UnavailableReason::OsApiUnavailable,
            }),
        }
    } else {
        RuntimeAvailability::Unavailable(UnavailableReason::DisabledByPolicy)
    };
    let device_capabilities = HostDeviceCapabilities::discover(
        host_policy,
        HostCapabilityProbes {
            input: input_probe,
            clipboard: if platform_clipboard::available() {
                RuntimeAvailability::Available
            } else {
                RuntimeAvailability::Unavailable(UnavailableReason::DeviceUnavailable)
            },
            microphone: if GuestMicSink::decoder_available() {
                RuntimeAvailability::Available
            } else {
                RuntimeAvailability::Unavailable(UnavailableReason::OsApiUnavailable)
            },
        },
    );
    eprintln!("{}", device_capabilities.log_line());
    let input_enabled = device_capabilities.input.can_advertise();
    let gamepad_enabled = device_capabilities.gamepad.can_advertise();
    let microphone_enabled = device_capabilities.microphone.can_advertise();
    let audio_requested = env::var("OPENSTREAM_AUDIO").as_deref() == Ok("1");
    let clipboard_enabled = device_capabilities.clipboard.can_advertise();
    let native_outputs = NativeDisplay::outputs();
    let output = env::var("LOWLAT_OUTPUT").ok();
    if let Some(requested) = output.as_deref()
        && !native_outputs
            .iter()
            .any(|available| available.id == requested)
    {
        return Err(
            format!("LOWLAT_OUTPUT={requested} is not one of the currently lit outputs").into(),
        );
    }
    let mut selected_output = output.clone().or_else(NativeDisplay::preferred);
    let mut host_capabilities = Capabilities::host_with_limits(1920, 1080, 60);
    host_capabilities.video_codecs = vec![VideoCodec::H264];
    host_capabilities.input = input_enabled;
    host_capabilities.rumble = gamepad_enabled;
    host_capabilities.pen = device_capabilities.tablet.can_advertise();
    host_capabilities.clipboard = clipboard_enabled;
    host_capabilities.microphone = microphone_enabled;
    host_capabilities.multi_monitor = native_outputs.len() > 1;
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
    // The native Linux adapter must consume the same guest-microphone controls
    // as the external FFmpeg adapter. With no sink path this still validates
    // and counts decoded frames, which makes the negotiated capability honest
    // without silently injecting audio into an OS device.
    let mut mic_sink = GuestMicSink::from_env(negotiated.microphone && microphone_enabled);
    if mic_sink.accepting() {
        eprintln!("OpenStream native guest microphone intake enabled");
    }
    if negotiated.multi_monitor {
        let topology = openstream_media::displays::encode_list(&native_topology(
            &native_outputs,
            selected_output.as_deref(),
        ))?;
        reliable_control.send(&mut session, &topology).await?;
    }
    let seconds = env::var("OPENSTREAM_HOST_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(15)
        .min(24 * 60 * 60);
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
        accept_microphone: negotiated.microphone && microphone_enabled,
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
        let mut injector = Injector::new(Extents::alone(
            u32::from(negotiated.width),
            u32::from(negotiated.height),
        ));
        let mut devices = Devices::create("openstream")?;
        injector.set_permissions(
            Permissions::from_host_grants(input_enabled, gamepad_enabled),
            &mut devices,
        );
        Some((injector, devices))
    } else {
        None
    };
    // A client that disappears without sending a final release must not leave
    // a key or button held on the host. The lease is renewed by every valid
    // input event and is intentionally inactive until the first event.
    let mut input_lease = InputLease::new(input_lease_timeout_us());

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
                            } else if mic_sink.accept(&payload) {
                                // Guest microphone audio is decoded and
                                // optionally written to OPENSTREAM_MIC_SINK;
                                // it must never fall through to input.
                            } else if let Some(selection) =
                                decode_output_selection(&payload, &native_outputs)
                            {
                                match selection {
                                    Ok(output_id) => {
                                        stream.select_output(Some(output_id.clone()));
                                        selected_output = Some(output_id);
                                        if negotiated.multi_monitor {
                                            let topology =
                                                openstream_media::displays::encode_list(&native_topology(
                                                    &native_outputs,
                                                    selected_output.as_deref(),
                                                ))?;
                                            reliable_control
                                                .send(&mut session, &topology)
                                                .await?;
                                        }
                                    }
                                    Err(error) => eprintln!(
                                        "OpenStream rejected display selection: {error}"
                                    ),
                                }
                            } else if payload != b"openstream/frame-ack"
                                && payload != b"openstream/end"
                                && let Some((injector, devices)) = input.as_mut()
                            {
                                apply_input_payload(
                                    &payload,
                                    injector,
                                    devices,
                                    gamepad_enabled,
                                    &mut input_lease,
                                    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                                );
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
                    if mic_sink.accept(&packet.payload) {
                        continue;
                    }
                    if let Some(selection) =
                        decode_output_selection(&packet.payload, &native_outputs)
                    {
                        match selection {
                            Ok(output_id) => {
                                stream.select_output(Some(output_id.clone()));
                                selected_output = Some(output_id);
                                if negotiated.multi_monitor {
                                    let topology =
                                        openstream_media::displays::encode_list(&native_topology(
                                            &native_outputs,
                                            selected_output.as_deref(),
                                        ))?;
                                    reliable_control.send(&mut session, &topology).await?;
                                }
                            }
                            Err(error) => {
                                eprintln!("OpenStream rejected display selection: {error}")
                            }
                        }
                        continue;
                    }
                }
                if packet.kind != Kind::Input {
                    continue;
                }
                let Some((injector, devices)) = input.as_mut() else {
                    continue;
                };
                apply_input_payload(
                    &packet.payload,
                    injector,
                    devices,
                    gamepad_enabled,
                    &mut input_lease,
                    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                );
            }
            _ = tick.tick() => {
                if let Some((injector, devices)) = input.as_mut() {
                    if input_lease
                        .poll_expiry(started.elapsed().as_micros().try_into().unwrap_or(u64::MAX))
                        .is_some()
                    {
                        // `Devices::tick` is still called below so any
                        // pending force-feedback cleanup proceeds normally.
                        // The injector owns the exact set of held keys/buttons.
                        injector.release_all(devices);
                    }
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
/// Convert the native host's stable connector names into the compact topology
/// message shared with desktop clients. The wire id is a CRC32 of the full
/// `cardN:CONNECTOR` identity; the native stream still receives the original
/// string when a selection is applied.
fn native_topology(
    outputs: &[lowlat::display::Selectable],
    selected: Option<&str>,
) -> Vec<openstream_media::displays::Display> {
    use openstream_media::displays::{Display, PRIMARY_FLAG, SELECTED_FLAG};

    let mut topology = outputs
        .iter()
        .filter_map(|output| {
            if output.width == 0 || output.height == 0 {
                return None;
            }
            let width = u16::try_from(output.width).ok()?;
            let height = u16::try_from(output.height).ok()?;
            let (x, y, primary) = output.place.map_or((0, 0, false), |place| {
                (
                    i32::try_from(place.x).unwrap_or(i32::MAX),
                    i32::try_from(place.y).unwrap_or(i32::MAX),
                    place.x == 0 && place.y == 0,
                )
            });
            let mut flags = u16::from(primary) * PRIMARY_FLAG;
            if selected == Some(output.id.as_str()) {
                flags |= SELECTED_FLAG;
            }
            Some(Display {
                id: lowlat_core::crc32::of(output.id.as_bytes()),
                x,
                y,
                width,
                height,
                flags,
            })
        })
        .collect::<Vec<_>>();
    if !topology.iter().any(|display| display.primary())
        && let Some(first) = topology.first_mut()
    {
        first.flags |= PRIMARY_FLAG;
    }
    topology
}

#[cfg(target_os = "linux")]
/// Decode a selection only when the payload is an `MS` message. Returning an
/// error rather than `None` for malformed or unknown ids prevents it from
/// falling through into the native input parser.
fn decode_output_selection(
    payload: &[u8],
    outputs: &[lowlat::display::Selectable],
) -> Option<Result<String, String>> {
    if !payload.starts_with(b"MS") {
        return None;
    }
    let selected = match openstream_media::displays::decode_select(payload) {
        Ok(selected) => selected,
        Err(error) => return Some(Err(error.to_string())),
    };
    Some(
        outputs
            .iter()
            .find(|output| lowlat_core::crc32::of(output.id.as_bytes()) == selected)
            .map(|output| output.id.clone())
            .ok_or_else(|| format!("display id {selected} is not currently available")),
    )
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
/// Emit a bounded, secret-free Linux host readiness report and exit.
///
/// This deliberately reports facts instead of returning a single boolean:
/// no display, an inaccessible framebuffer, a missing render node, a missing
/// FFmpeg executable, and a missing PipeWire session require different fixes.
/// A successful preflight is not a substitute for a real ten-minute stream
/// acceptance run because encoder/driver compatibility is only fully proven
/// when a frame is submitted.
fn preflight() -> Result<(), Box<dyn std::error::Error>> {
    use lowlat::display::{Display, NativeDrmProbe, native_drm_probe};
    use openstream_platform::hwaccel::{EncoderCodec, HwReport};

    let outputs = Display::outputs();
    let capture = native_drm_probe();
    let capture_name = match capture {
        NativeDrmProbe::Ready => "yes",
        NativeDrmProbe::NothingLit => "nothing_lit",
        NativeDrmProbe::Unreachable => "not_reachable",
    };
    let output_json = outputs
        .iter()
        .map(|output| {
            let placement = output.place.map(|place| {
                serde_json::json!({
                    "x": place.x,
                    "y": place.y,
                    "width": place.width,
                    "height": place.height,
                    "desktop_width": place.desktop_width,
                    "desktop_height": place.desktop_height,
                })
            });
            serde_json::json!({
                "id": output.id,
                "connector": output.connector,
                "width": output.width,
                "height": output.height,
                "driver": Display::driver(Some(&output.id)),
                "placement": placement,
            })
        })
        .collect::<Vec<_>>();

    let x11 = match x11::Connection::open(None) {
        Ok(connection) => serde_json::json!({
            "available": true,
            "screens": connection.screens.iter().map(|screen| serde_json::json!({
                "index": screen.index,
                "width_px": screen.width_px,
                "height_px": screen.height_px,
                "root_depth": screen.root_depth,
            })).collect::<Vec<_>>(),
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "error": error.to_string(),
        }),
    };
    let pipewire = match pipewire::list_source_nodes() {
        Ok(nodes) => serde_json::json!({
            "available": true,
            "sources": nodes.iter().map(|node| serde_json::json!({
                "id": node.id,
                "name": node.name,
                "media_class": node.media_class,
                "object_serial": node.object_serial,
            })).collect::<Vec<_>>(),
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "error": error.to_string(),
        }),
    };

    let hardware = HwReport::probe();
    let ffmpeg = command_probe(
        &env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string()),
        &["-hide_banner", "-loglevel", "error", "-version"],
    );
    let report = serde_json::json!({
        "schema": 1,
        "platform": {
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "display_env_set": env::var_os("DISPLAY").is_some(),
            "wayland_display_env_set": env::var_os("WAYLAND_DISPLAY").is_some(),
        },
        "native_drm": {
            "capturable": capture_name,
            "outputs": output_json,
            "host_capture_gate": capture.is_ready(),
        },
        "x11": x11,
        "pipewire": pipewire,
        "ffmpeg": ffmpeg,
        "hardware": {
            "vaapi_render_node": hardware.vaapi_render_node(),
            "nvenc_library": hardware.nvenc_library,
            "nvenc_library_location": hardware.nvenc_library_location(),
            "nvidia_smi": hardware.nvidia_smi,
            "preferred_h264_encoder": hardware.preferred_encoder(EncoderCodec::H264),
            "preferred_h265_encoder": hardware.preferred_encoder(EncoderCodec::H265),
        },
        "input": {
            "uinput_present": std::fs::metadata("/dev/uinput").is_ok(),
            "enabled_by_policy": env::var("OPENSTREAM_ENABLE_INPUT").as_deref() == Ok("1"),
        },
        "audio": {
            "requested": env::var("OPENSTREAM_AUDIO").as_deref() == Ok("1"),
            "server_configured": env::var_os("OPENSTREAM_AUDIO_SERVER").is_some(),
            "device_configured": env::var_os("OPENSTREAM_AUDIO_DEVICE").is_some(),
        },
        "acceptance": {
            "preflight_is_not_live_stream_test": true,
            "encoder_submission": "not tested; run the native host with a real pairing",
            "recommended_command": "openstream-linux-host --preflight",
        },
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn command_probe(program: &str, args: &[&str]) -> serde_json::Value {
    use std::process::{Command, Stdio};
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return serde_json::json!({
                "program": program,
                "available": false,
                "error": error.to_string(),
            });
        }
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return serde_json::json!({
                    "program": program,
                    "available": status.success(),
                    "exit_code": status.code(),
                });
            }
            Ok(None) if started.elapsed() > Duration::from_secs(3) => {
                let _ = child.kill();
                let _ = child.wait();
                return serde_json::json!({
                    "program": program,
                    "available": false,
                    "timed_out": true,
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return serde_json::json!({
                    "program": program,
                    "available": false,
                    "error": error.to_string(),
                });
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{command_probe, decode_output_selection, input_event_allowed, native_topology};
    use lowlat::display::Selectable;
    use openstream_media::input::InputEvent;

    #[test]
    fn command_probe_reports_a_fixed_successful_command() {
        let report = command_probe("true", &[]);
        assert_eq!(
            report.get("available").and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            report.get("exit_code").and_then(|value| value.as_i64()),
            Some(0)
        );
    }

    #[test]
    fn command_probe_reports_missing_program_without_panicking() {
        let report = command_probe("openstream-command-that-does-not-exist", &[]);
        assert_eq!(
            report.get("available").and_then(|value| value.as_bool()),
            Some(false)
        );
        assert!(
            report
                .get("error")
                .and_then(|value| value.as_str())
                .is_some()
        );
    }

    #[test]
    fn native_topology_round_trips_stable_connector_selection() {
        let outputs = vec![
            Selectable {
                id: "card0:DP-1".to_string(),
                connector: "DP-1".to_string(),
                width: 1920,
                height: 1080,
                place: None,
            },
            Selectable {
                id: "card0:HDMI-A-1".to_string(),
                connector: "HDMI-A-1".to_string(),
                width: 1280,
                height: 1024,
                place: None,
            },
        ];
        let topology = native_topology(&outputs, Some("card0:HDMI-A-1"));
        assert_eq!(topology.len(), 2);
        assert!(topology[0].primary());
        assert!(topology[1].selected());
        let selected = openstream_media::displays::encode_select(topology[1].id);
        assert_eq!(
            decode_output_selection(&selected, &outputs),
            Some(Ok("card0:HDMI-A-1".to_string()))
        );
        let unknown = openstream_media::displays::encode_select(0xdead_beef);
        assert!(
            decode_output_selection(&unknown, &outputs)
                .expect("MS is consumed")
                .is_err()
        );
    }

    #[test]
    fn native_input_rejects_unimplemented_advanced_events() {
        assert!(input_event_allowed(
            InputEvent::keyboard(4, 0, true, 0),
            false
        ));
        assert!(!input_event_allowed(
            InputEvent::gamepad_button(0, 0, true, 0),
            false
        ));
        assert!(input_event_allowed(
            InputEvent::gamepad_button(0, 0, true, 0),
            true
        ));
        assert!(!input_event_allowed(
            InputEvent::pen_motion(0, 100, 100, 0, false, 0),
            true
        ));
    }
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
    gamepad_enabled: bool,
    input_lease: &mut openstream_media::input::InputLease,
    now_us: u64,
) {
    if let Ok(event) = openstream_media::input::InputEvent::decode(payload) {
        if !input_event_allowed(event, gamepad_enabled) {
            eprintln!("OpenStream rejected an input event without a local adapter");
            return;
        }
        if matches!(
            event.kind,
            openstream_media::input::InputKind::Release
        ) {
            input_lease.disarm();
        } else {
            input_lease.renew(now_us);
        }
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
        if control.opcode == lowlat_core::control::op::RELEASE {
            input_lease.disarm();
        } else {
            input_lease.renew(now_us);
        }
        injector.on_control(&control, devices);
    }
}

#[cfg(target_os = "linux")]
fn input_lease_timeout_us() -> u64 {
    const DEFAULT_MS: u64 = 2_000;
    const MIN_MS: u64 = 250;
    const MAX_MS: u64 = 60_000;
    let milliseconds = env::var("OPENSTREAM_INPUT_LEASE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(MIN_MS, MAX_MS))
        .unwrap_or(DEFAULT_MS);
    milliseconds.saturating_mul(1_000)
}

#[cfg(target_os = "linux")]
fn input_event_allowed(event: openstream_media::input::InputEvent, gamepad_enabled: bool) -> bool {
    match event.kind.capability() {
        openstream_media::input::InputCapability::BasicInput => true,
        openstream_media::input::InputCapability::Gamepad => gamepad_enabled,
        openstream_media::input::InputCapability::Tablet => false,
    }
}
