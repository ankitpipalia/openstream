//! The unprivileged machine-service binary.
//!
//! It establishes the peer session (signaling, ICE, transport), connects to the
//! privileged broker, negotiates capabilities, and then bridges the two: encoded
//! frames from the broker are fragmented onto the peer's video path, and the
//! peer's input and control travel back to the broker as requests. Nothing here
//! touches a device or runs as root; the broker does.

fn is_version_request() -> bool {
    std::env::args()
        .skip(1)
        .any(|argument| argument == "--version")
}

fn print_version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if is_version_request() {
        print_version();
        return;
    }
    eprintln!("openstream-machine-service runs only on Linux");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if is_version_request() {
        print_version();
        return Ok(());
    }
    linux::run().await
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use openstream_client_core::{
        Capabilities, PeerSession, ReliableControl, Role, VideoCodec,
        load_pairing_from_environment, parse_stun_servers,
    };
    use openstream_host_ipc::lifecycle::CaptureKind;
    use openstream_host_ipc::protocol::{BrokerEvent, CaptureParams, ServiceRequest};
    use openstream_host_ipc::token::Capabilities as BrokerCaps;
    use openstream_host_ipc::transport::{recv_event, send_request};
    use openstream_media::{AdaptiveBitrate, FrameAck, KEYFRAME_REQUEST, fragment_frame};
    use openstream_protocol::{Kind, Packet};

    use openstream_machine_service::broker_client;
    use openstream_machine_service::session::current_seat;

    /// After this long with no authenticated packet from the peer, end the
    /// session so the supervisor restarts a clean one. Well above the keepalive
    /// cadence so a healthy idle peer is never torn down.
    const PEER_LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);

    fn env_or(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_string())
    }

    fn configured_mbps() -> f64 {
        std::env::var("OPENSTREAM_VIDEO_MBPS")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0 && *value <= 200.0)
            .unwrap_or(10.0)
    }

    /// Convert a megabit-per-second rate to the protocol's kilobit-per-second
    /// integer, saturating rather than wrapping. The final cast is bounded by
    /// the clamp, so the truncation/sign lints do not apply.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn kbps_from_mbps(mbps: f64) -> u32 {
        let kbps = (mbps * 1000.0).round();
        if kbps <= 0.0 {
            0
        } else if kbps >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            kbps as u32
        }
    }

    /// A best-effort unique-enough token id for this session. The broker does not
    /// treat it as a secret in this version (it enforces the granted capability
    /// set, not token possession), so a monotonic value from the clock suffices.
    fn session_token_id() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|delta| delta.as_nanos())
            .unwrap_or(0);
        nanos ^ (u128::from(std::process::id()) << 96)
    }

    pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
        use std::net::SocketAddr;

        let origin = env_or("OPENSTREAM_SIGNAL_ORIGIN", "http://127.0.0.1:8080");
        let pairing = load_pairing_from_environment()?;
        let bind = env_or("OPENSTREAM_UDP_BIND", "0.0.0.0:0").parse::<SocketAddr>()?;
        let stun_servers = match std::env::var("OPENSTREAM_STUN_SERVERS") {
            Ok(spec) => parse_stun_servers(&spec)?,
            Err(_) => Vec::new(),
        };

        // The network side comes up first; if the broker is unreachable there is
        // nothing to stream, so connect it before negotiating with the peer.
        let broker_socket = PathBuf::from(env_or(
            "OPENSTREAM_BROKER_SOCKET",
            broker_client_default_socket(),
        ));
        let mut broker = broker_client::connect(&broker_socket).await?;
        eprintln!(
            "machine-service: broker connected, capabilities {:?}",
            broker.capabilities
        );

        let mut session =
            PeerSession::establish_configured(&origin, &pairing, Role::Host, bind, &stun_servers)
                .await?;
        eprintln!(
            "machine-service: peer data path {:?}",
            session.connection_path()
        );

        // Advertise only what the broker can actually serve. v1 is video plus
        // input; audio and clipboard are not bridged yet.
        let broker_can_input = broker.capabilities.contains(BrokerCaps::KEYBOARD)
            || broker.capabilities.contains(BrokerCaps::MOUSE);
        let mut host_capabilities = Capabilities::host_with_limits(1920, 1080, 60);
        host_capabilities.video_codecs = vec![VideoCodec::H264];
        host_capabilities.input = broker_can_input;
        host_capabilities.clipboard = false;
        host_capabilities.microphone = false;
        host_capabilities.rumble = broker.capabilities.contains(BrokerCaps::GAMEPAD);
        host_capabilities.audio_codecs.clear();

        let negotiated = session
            .negotiate_host_with_capabilities(host_capabilities)
            .await?;
        if negotiated.video != VideoCodec::H264 {
            return Err("the machine service currently emits H.264 only".into());
        }

        // Ask the broker to capture the seat as it stands now (greeter or user),
        // with the capabilities the peer negotiated. The broker clamps this to
        // its own policy and to the seat (the login screen never gets clipboard).
        let seat = current_seat();
        let mut requested = BrokerCaps::CAPTURE;
        if negotiated.input {
            requested = requested.with(BrokerCaps::KEYBOARD).with(BrokerCaps::MOUSE);
        }
        let mbps = configured_mbps();
        let bitrate_kbps = kbps_from_mbps(mbps);
        session
            .set_wire_pacing_rate((mbps * 1.5).max(30.0))
            .map_err(|error| format!("wire pacing rate: {error:?}"))?;

        send_request(
            &mut broker.writer,
            &ServiceRequest::OpenCapture {
                token_id: session_token_id(),
                requested,
                params: CaptureParams {
                    seat,
                    kind: CaptureKind::Scanout,
                    width: negotiated.width,
                    height: negotiated.height,
                    fps: u8::try_from(negotiated.fps.clamp(1, 240)).unwrap_or(60),
                    bitrate_kbps,
                },
            },
        )
        .await?;
        match recv_event(&mut broker.reader).await? {
            BrokerEvent::CaptureStarted {
                width,
                height,
                granted,
                ..
            } => {
                eprintln!("machine-service: capture started {width}x{height}, granted {granted:?}");
            }
            BrokerEvent::CaptureError { code, message } => {
                return Err(format!("broker refused capture ({code}): {message}").into());
            }
            other => return Err(format!("unexpected first broker event: {other:?}").into()),
        }

        let mut reliable_control =
            ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
        let mut adaptive = AdaptiveBitrate::new(mbps, (mbps / 4.0).max(1.0), mbps);
        let started = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(1));

        loop {
            tokio::select! {
                event = recv_event(&mut broker.reader) => {
                    match event {
                        Ok(event) => {
                            if forward_broker_event(event, &mut session, &mut adaptive, started).await? {
                                // A fatal broker error ended capture.
                                break;
                            }
                        }
                        Err(error) => {
                            eprintln!("machine-service: broker disconnected: {error}");
                            break;
                        }
                    }
                }
                packet = session.recv() => {
                    let packet = packet?;
                    if handle_peer_packet(
                        packet,
                        &mut session,
                        &mut broker.writer,
                        &mut reliable_control,
                        &mut adaptive,
                        started,
                    ).await? {
                        // The peer asked to end the session.
                        break;
                    }
                }
                _ = tick.tick() => {
                    reliable_control.retry(&mut session).await?;
                    session.maintain_liveness().await?;
                    if session.last_peer_activity_age() >= PEER_LIVENESS_TIMEOUT {
                        eprintln!("machine-service: peer silent past the liveness timeout; ending");
                        break;
                    }
                    if let Some(decision) = adaptive.tick(
                        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    ) {
                        let kbps = kbps_from_mbps(decision.bitrate_mbps);
                        send_request(&mut broker.writer, &ServiceRequest::SetBitrate { kbps }).await?;
                    }
                }
            }
        }

        let _ = send_request(&mut broker.writer, &ServiceRequest::Shutdown).await;
        let _ = session.release_upnp().await;
        eprintln!(
            "machine-service: session ended, stats {:?}",
            session.stats()
        );
        Ok(())
    }

    fn broker_client_default_socket() -> &'static str {
        "/run/openstream/broker.sock"
    }

    /// Forward one broker event to the peer. Returns `true` when a fatal capture
    /// error means the session should end.
    async fn forward_broker_event(
        event: BrokerEvent,
        session: &mut PeerSession,
        adaptive: &mut AdaptiveBitrate,
        started: Instant,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match event {
            BrokerEvent::Frame {
                sequence,
                timestamp_us,
                keyframe,
                data,
            } => {
                for fragment in fragment_frame(sequence, timestamp_us, keyframe, &data)? {
                    session.send(Kind::Video, 0, 0, &fragment).await?;
                }
                adaptive.frame_sent(
                    sequence,
                    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                );
                Ok(false)
            }
            BrokerEvent::CaptureStarted {
                seat,
                kind,
                width,
                height,
                granted,
            } => {
                // A re-point after a login/logout switch: geometry and grant may
                // have changed. Nothing to send the peer; just note it.
                eprintln!(
                    "machine-service: capture re-pointed {seat:?}/{kind:?} {width}x{height}, granted {granted:?}"
                );
                Ok(false)
            }
            BrokerEvent::Rumble { .. } => {
                // Rumble travels on the reliable control channel; wiring it is a
                // follow-up. Dropping it is harmless (no force-feedback felt).
                Ok(false)
            }
            BrokerEvent::CaptureError { code, message } => {
                eprintln!("machine-service: broker capture error ({code}): {message}");
                Ok(true)
            }
            BrokerEvent::Closed { reason } => {
                eprintln!("machine-service: broker closed capture (reason {reason})");
                Ok(false)
            }
            BrokerEvent::Hello { .. } => Ok(false),
        }
    }

    /// Handle one peer packet, issuing broker requests as needed. Returns `true`
    /// when the peer asked to end the session.
    async fn handle_peer_packet(
        packet: Packet,
        session: &mut PeerSession,
        broker_writer: &mut tokio::net::unix::OwnedWriteHalf,
        reliable_control: &mut ReliableControl,
        adaptive: &mut AdaptiveBitrate,
        started: Instant,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if packet.kind == Kind::Control {
            if let Some(deliveries) = reliable_control.receive(session, &packet).await? {
                for payload in deliveries {
                    if handle_control_payload(&payload, broker_writer, adaptive, started).await? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            return handle_control_payload(&packet.payload, broker_writer, adaptive, started).await;
        }
        if packet.kind == Kind::Input {
            send_request(
                broker_writer,
                &ServiceRequest::Input {
                    payload: packet.payload,
                },
            )
            .await?;
        }
        Ok(false)
    }

    /// Act on one decoded control payload. Returns `true` for an end request.
    async fn handle_control_payload(
        payload: &[u8],
        broker_writer: &mut tokio::net::unix::OwnedWriteHalf,
        adaptive: &mut AdaptiveBitrate,
        started: Instant,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if payload == b"openstream/end" {
            return Ok(true);
        }
        if payload == KEYFRAME_REQUEST {
            send_request(broker_writer, &ServiceRequest::RequestKeyframe).await?;
            return Ok(false);
        }
        if let Ok(ack) = FrameAck::decode(payload) {
            let _ = adaptive.frame_acknowledged_with_loss(
                ack.frame_id,
                started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                ack.lost_frames,
            );
            return Ok(false);
        }
        // Anything else is an input event; the broker validates it against the
        // session grant before it reaches a device.
        send_request(
            broker_writer,
            &ServiceRequest::Input {
                payload: payload.to_vec(),
            },
        )
        .await?;
        Ok(false)
    }
}
