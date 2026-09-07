//! Headless OpenStream client adapter.
//!
//! It receives and reassembles H.264/H.265 access units into a file so the
//! transport and host adapters can be tested before a GPU renderer is linked.
//! The same `PeerSession` and media assembler are intended to sit beneath
//! desktop, Android, and iOS presentation layers.

use std::env;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use openstream_client_core::{
    Capabilities, Pairing, PeerSession, ReliableControl, Role, VideoCodec, parse_stun_servers,
};
use openstream_media::{
    Assembler, AudioEvent, AudioFrame, Fragment, FrameAck, JitterBuffer, KEYFRAME_REQUEST,
};
use openstream_protocol::Kind;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let mut client_capabilities = Capabilities::client_default();
    if matches!(
        env::var("OPENSTREAM_VIDEO_CODEC").as_deref(),
        Ok("h265" | "hevc")
    ) {
        client_capabilities.video_codecs = vec![VideoCodec::H265];
    }
    let negotiated = session
        .negotiate_client_with_capabilities(client_capabilities)
        .await?;
    eprintln!(
        "OpenStream path={:?}; negotiated {:?} {}x{} at up to {} fps; audio={:?}; input={}",
        session.connection_path(),
        negotiated.video,
        negotiated.width,
        negotiated.height,
        negotiated.fps,
        negotiated.audio,
        negotiated.input
    );
    let mut reliable_control = ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);

    if env::var("OPENSTREAM_TEST_INPUT").as_deref() == Ok("1") {
        let mut payload = vec![0_u8; lowlat_core::control::CONTROL_HEADER_LEN];
        let message = lowlat_core::control::Control {
            a0: 0,
            a1: 0,
            a2: 0,
            opcode: lowlat_core::control::op::RELEASE,
            body: &[],
        };
        lowlat_core::control::encode_header(&mut payload, &message)
            .map_err(|error| error.to_string())?;
        session.send(Kind::Input, 0, 0, &payload).await?;
        eprintln!("OpenStream client sent a release-state input test message");
    }

    let output = env::var("OPENSTREAM_OUTPUT")
        .unwrap_or_else(|_| format!("openstream-output.{}", codec_suffix(negotiated.video)));
    let mut file = tokio::fs::File::create(&output).await?;
    let mut player = spawn_player(negotiated.video)?;
    let mut player_stdin = player.as_mut().and_then(|child| child.stdin.take());
    let mut audio_output = match env::var("OPENSTREAM_AUDIO_OUTPUT") {
        Ok(path) => Some(tokio::fs::File::create(path).await?),
        Err(_) => None,
    };
    let mut audio_decoder = opus_rs::OpusDecoder::new(48_000, lowlat_audio::CHANNELS)
        .map_err(|error| format!("could not create Opus decoder: {error}"))?;
    let mut audio_jitter = JitterBuffer::new(3);
    let mut audio_pcm = vec![0_f32; lowlat_audio::FRAME * lowlat_audio::CHANNELS];
    let mut last_audio_toc = None;
    let mut assembler = Assembler::default();
    let seconds = env::var("OPENSTREAM_CLIENT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut frames = 0_u64;
    let mut waiting_for_keyframe = false;
    let mut control_tick = tokio::time::interval(Duration::from_millis(100));
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = tokio::select! {
            packet = tokio::time::timeout(remaining, session.recv()) => {
                match packet {
                    Ok(packet) => packet?,
                    Err(_) => break,
                }
            }
            _ = control_tick.tick() => {
                reliable_control.retry(&mut session).await?;
                continue;
            }
        };
        if packet.kind == Kind::Control {
            if let Some(deliveries) = reliable_control.receive(&mut session, &packet).await? {
                if deliveries
                    .iter()
                    .any(|payload| payload == b"openstream/end")
                {
                    break;
                }
                continue;
            }
            if packet.payload == b"openstream/end" {
                break;
            }
        }
        if packet.kind == Kind::Audio {
            let Ok(audio) = AudioFrame::decode(&packet.payload) else {
                eprintln!("OpenStream dropped malformed audio packet");
                continue;
            };
            audio_jitter.push(audio);
            while let Some(event) = audio_jitter.poll() {
                let (payload, sequence) = match event {
                    AudioEvent::Frame(frame) => (frame.payload, frame.sequence),
                    AudioEvent::Missing(sequence) => {
                        let Some(toc) = last_audio_toc else {
                            continue;
                        };
                        (vec![toc], sequence)
                    }
                };
                let samples =
                    match audio_decoder.decode(&payload, lowlat_audio::FRAME, &mut audio_pcm) {
                        Ok(samples) => samples,
                        Err(error) => {
                            eprintln!("OpenStream dropped Opus sequence {sequence}: {error}");
                            continue;
                        }
                    };
                if let Some(toc) = payload.first().copied() {
                    last_audio_toc = Some(toc);
                }
                if let Some(file) = audio_output.as_mut() {
                    let mut pcm16 = Vec::with_capacity(samples * lowlat_audio::CHANNELS * 2);
                    for sample in audio_pcm.iter().take(samples * lowlat_audio::CHANNELS) {
                        // The decoder output is clamped to the representable
                        // signed-16-bit range before this intentional format
                        // conversion.
                        #[allow(clippy::cast_possible_truncation)]
                        let sample = (sample.clamp(-1.0, 1.0) * 32767.0) as i16;
                        pcm16.extend_from_slice(&sample.to_le_bytes());
                    }
                    file.write_all(&pcm16).await?;
                }
            }
            continue;
        }
        if packet.kind != Kind::Video {
            continue;
        }
        let Ok(fragment) = Fragment::decode(&packet.payload) else {
            eprintln!("OpenStream dropped malformed video fragment");
            continue;
        };
        let mut ready_frames = Vec::new();
        match assembler.push(fragment) {
            Ok(Some(frame)) => ready_frames.push(frame),
            Ok(None) => {}
            Err(error) => {
                eprintln!("OpenStream dropped malformed video frame: {error}");
                continue;
            }
        }
        while let Some(frame) = assembler.pop_ready() {
            ready_frames.push(frame);
        }
        if assembler.take_keyframe_request() {
            waiting_for_keyframe = true;
            reliable_control
                .send(&mut session, KEYFRAME_REQUEST)
                .await?;
        }
        for frame in ready_frames {
            if frame.keyframe {
                waiting_for_keyframe = false;
            }
            if !waiting_for_keyframe {
                tokio::io::AsyncWriteExt::write_all(&mut file, &frame.payload).await?;
                if let Some(stdin) = player_stdin.as_mut()
                    && stdin.write_all(&frame.payload).await.is_err()
                {
                    player_stdin = None;
                    eprintln!("OpenStream player exited; continuing to write the access-unit file");
                }
                let ack = FrameAck {
                    frame_id: frame.frame_id,
                    lost_frames: assembler.take_frame_gap(),
                }
                .encode();
                let _ = reliable_control
                    .send_if_available(&mut session, &ack)
                    .await?;
                frames += 1;
            }
        }
    }
    // Let a time-bounded headless client close the host side cleanly. Without
    // this explicit control message the host can still be encoding when the
    // client process exits, turning a normal demo shutdown into a broken UDP
    // pipe/error in the host log.
    let _ = session.send(Kind::Control, 0, 0, b"openstream/end").await;
    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    if let Some(file) = audio_output.as_mut() {
        file.flush().await?;
    }
    if let Some(mut player) = player {
        let _ = player.kill().await;
    }
    let _ = session.release_upnp().await;
    eprintln!("OpenStream client wrote {frames} decoded access units to {output}");
    eprintln!("OpenStream transport stats: {:?}", session.stats());
    Ok(())
}

fn codec_suffix(codec: VideoCodec) -> &'static str {
    match codec {
        VideoCodec::H264 => "h264",
        VideoCodec::H265 => "h265",
    }
}

fn spawn_player(codec: VideoCodec) -> Result<Option<Child>, Box<dyn std::error::Error>> {
    let Some(executable) = env::var("OPENSTREAM_PLAYER").ok() else {
        return Ok(None);
    };
    let format = codec_suffix(codec);
    let child = Command::new(executable)
        .args([
            "-hide_banner",
            "-loglevel",
            "warning",
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-framedrop",
            "-f",
            format,
            "-i",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(Some(child))
}
