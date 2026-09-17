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
    use openstream_host_ipc::lifecycle::{Action, Event, Lifecycle};
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

    /// The session approval to relay to the broker.
    ///
    /// `OPENSTREAM_SESSION_APPROVAL` carries it as hex until the control plane
    /// delivers one with the Secure Connect approval. Absent or malformed
    /// means no approval, and the broker then refuses the session -- there is
    /// deliberately no path here that produces a grant, because a service that
    /// could produce one would defeat the point of having it.
    fn load_approval() -> Vec<u8> {
        let Ok(hex) = std::env::var("OPENSTREAM_SESSION_APPROVAL") else {
            return Vec::new();
        };
        let hex = hex.trim();
        if hex.is_empty() || hex.len() % 2 != 0 {
            eprintln!("machine-service: OPENSTREAM_SESSION_APPROVAL is not valid hex; ignoring");
            return Vec::new();
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let Ok(text) = std::str::from_utf8(pair) else {
                return Vec::new();
            };
            let Ok(byte) = u8::from_str_radix(text, 16) else {
                eprintln!(
                    "machine-service: OPENSTREAM_SESSION_APPROVAL is not valid hex; ignoring"
                );
                return Vec::new();
            };
            bytes.push(byte);
        }
        bytes
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

        // The capabilities the peer negotiated; the broker clamps them to its
        // own policy and to the seat (the login screen never gets clipboard).
        let mut requested = BrokerCaps::CAPTURE;
        if negotiated.input {
            requested = requested.with(BrokerCaps::KEYBOARD).with(BrokerCaps::MOUSE);
        }
        let mbps = configured_mbps();
        let mut capture = CaptureContext {
            requested,
            // The approval this session was opened under. Read from the
            // environment for now; the control plane will deliver it with the
            // Secure Connect approval, and until then the broker refuses the
            // session, which is correct rather than convenient.
            approval: load_approval(),
            // Zero asks the broker to issue a capability. It is replaced by
            // the one the broker mints, on the first CaptureStarted.
            grant: openstream_host_ipc::token::NO_GRANT,
            width: negotiated.width,
            height: negotiated.height,
            fps: u8::try_from(negotiated.fps.clamp(1, 240)).unwrap_or(60),
            bitrate_kbps: kbps_from_mbps(mbps),
        };
        session
            .set_wire_pacing_rate((mbps * 1.5).max(30.0))
            .map_err(|error| format!("wire pacing rate: {error:?}"))?;

        // Drive capture through the lifecycle state machine, so logging in
        // (greeter -> user) or out re-points capture WITHOUT dropping the peer.
        // The peer stays approved across every seat change; only PeerLost ends
        // it. CaptureStarted/CaptureError come back through the loop below.
        let mut lifecycle = Lifecycle::new();
        let mut last_seat = current_seat();
        eprintln!("machine-service: initial seat {last_seat:?}");
        apply_actions(
            lifecycle.on(Event::SeatObserved(last_seat)),
            &mut broker.writer,
            &capture,
        )
        .await?;
        apply_actions(
            lifecycle.on(Event::PeerApproved),
            &mut broker.writer,
            &capture,
        )
        .await?;

        let mut reliable_control =
            ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
        let mut adaptive = AdaptiveBitrate::new(mbps, (mbps / 4.0).max(1.0), mbps);
        let started = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(1));
        // Watch the seat a few times a second; a login transition is not
        // latency-critical, and this keeps the logind read off the hot path.
        let mut seat_poll = tokio::time::interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                event = recv_event(&mut broker.reader) => {
                    match event {
                        Ok(event) => {
                            if forward_broker_event(event, &mut session, &mut adaptive, started, &mut capture).await? {
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
                        capture.grant,
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
                _ = seat_poll.tick() => {
                    // A login or logout changes the seat; feed it to the
                    // lifecycle, which re-points capture (SwitchCapture) and
                    // asks for a keyframe -- never dropping the approved peer.
                    let seat = current_seat();
                    if seat != last_seat {
                        eprintln!("machine-service: seat {last_seat:?} -> {seat:?}, re-pointing capture");
                        last_seat = seat;
                        apply_actions(
                            lifecycle.on(Event::SeatObserved(seat)),
                            &mut broker.writer,
                            &capture,
                        )
                        .await?;
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

    /// The fixed capture parameters negotiated with the peer, used to fill in an
    /// `OpenCapture` whenever the lifecycle asks to (re)start capture.
    #[derive(Debug, Clone, Copy)]
    struct CaptureContext {
        requested: BrokerCaps,
        width: u16,
        height: u16,
        fps: u8,
        bitrate_kbps: u32,
        /// The control plane's approval for this session, relayed verbatim.
        ///
        /// This service cannot produce one: the tag is keyed by a secret only
        /// the broker's user can read. It carries what it was given, and the
        /// broker decides. Empty until the control-plane issuance exists, and
        /// an empty approval is refused -- which is the intended posture, and
        /// is why the pre-login path is not packaged yet.
        approval: Vec<u8>,
        /// The capability id the broker issued, echoed back on every later
        /// request.
        ///
        /// This service does not and cannot mint one: it used to build an id
        /// from the clock and its own pid, which the broker then ignored, so
        /// nothing stopped a compromise of this process from asking the root
        /// broker for capture and input directly. `NO_GRANT` asks to be issued
        /// one; the broker refuses any other id it did not itself hand out.
        grant: u128,
    }

    /// Turn lifecycle actions into broker requests. `StartCapture` opens a new
    /// capture with the negotiated geometry; `SwitchCapture` re-points a live one
    /// without dropping the peer. This is the only place capture is opened or
    /// moved, so a login transition is always a switch, never a teardown.
    async fn apply_actions(
        actions: Vec<Action>,
        broker_writer: &mut tokio::net::unix::OwnedWriteHalf,
        capture: &CaptureContext,
    ) -> std::io::Result<()> {
        for action in actions {
            let request = match action {
                Action::StartCapture(seat, kind) => ServiceRequest::OpenCapture {
                    token_id: capture.grant,
                    grant: capture.approval.clone(),
                    requested: capture.requested,
                    params: CaptureParams {
                        seat,
                        kind,
                        width: capture.width,
                        height: capture.height,
                        fps: capture.fps,
                        bitrate_kbps: capture.bitrate_kbps,
                    },
                },
                Action::SwitchCapture(seat, kind) => ServiceRequest::SwitchCapture {
                    token_id: capture.grant,
                    seat,
                    kind,
                },
                Action::StopCapture => ServiceRequest::CloseCapture,
                Action::RequestKeyframe => ServiceRequest::RequestKeyframe,
            };
            send_request(broker_writer, &request).await?;
        }
        Ok(())
    }

    /// Forward one broker event to the peer. Returns `true` when a fatal capture
    /// error means the session should end.
    async fn forward_broker_event(
        event: BrokerEvent,
        session: &mut PeerSession,
        adaptive: &mut AdaptiveBitrate,
        started: Instant,
        capture: &mut CaptureContext,
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
                token_id,
                seat,
                kind,
                width,
                height,
                granted,
            } => {
                // The grant the broker issued. Recorded, not chosen: every
                // later request echoes this id back, and the broker refuses
                // any other.
                capture.grant = token_id;
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
        grant: u128,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if packet.kind == Kind::Control {
            if let Some(deliveries) = reliable_control.receive(session, &packet).await? {
                for payload in deliveries {
                    if handle_control_payload(&payload, broker_writer, adaptive, started, grant)
                        .await?
                    {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            return handle_control_payload(
                &packet.payload,
                broker_writer,
                adaptive,
                started,
                grant,
            )
            .await;
        }
        if packet.kind == Kind::Input {
            send_request(
                broker_writer,
                &ServiceRequest::Input {
                    token_id: grant,
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
        grant: u128,
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
                token_id: grant,
                payload: payload.to_vec(),
            },
        )
        .await?;
        Ok(false)
    }
}
