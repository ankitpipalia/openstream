//! The broker's protocol logic: turn a stream of [`ServiceRequest`]s into device
//! calls and [`BrokerEvent`]s.
//!
//! The core is [`BrokerSession`], which is entirely synchronous -- every request
//! is handled by [`BrokerSession::handle_request`] and every ready frame is
//! drained by [`BrokerSession::pump`], both returning the events to send. That
//! keeps the interesting logic (the handshake, the per-seat capability clamp,
//! the capture lifecycle) testable without timers or a socket. [`serve_connection`]
//! is the thin async wrapper that reads requests, calls the session, and writes
//! the events over the [`transport`](openstream_host_ipc::transport).
//!
//! The privileged boundary enforces the login-screen policy itself, not just the
//! service: at the greeter the broker grants keyboard and mouse (so the remote
//! user can type the OS password into the native login screen) but never
//! clipboard or gamepad, whatever the service asks for. A logout back to the
//! greeter contracts the grant the same way.

use std::io;
use std::time::Duration;

use openstream_host_ipc::lifecycle::Seat;
use openstream_host_ipc::peercred::PeerIdentity;
use openstream_host_ipc::protocol::{BrokerEvent, PROTOCOL_VERSION, ServiceRequest};
use openstream_host_ipc::token::Capabilities;
use openstream_host_ipc::transport::{recv_request, send_event};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::device::{FrameSource, InputSink};

/// Stable reason codes carried in [`BrokerEvent::CaptureError`] and
/// [`BrokerEvent::Closed`].
pub mod code {
    /// `CaptureError`: the service spoke an unsupported protocol version.
    pub const PROTOCOL_VERSION: u16 = 10;
    /// `CaptureError`: the service sent a request before the handshake.
    pub const PROTOCOL_VIOLATION: u16 = 11;
    /// `Closed`: the service asked to close the capture.
    pub const CLOSED_ON_REQUEST: u16 = 0;
    /// `Closed`: the service is shutting the broker connection down.
    pub const CLOSED_ON_SHUTDOWN: u16 = 1;
}

/// The broker's standing policy: the absolute capability ceiling it will ever
/// grant, and how often the async wrapper drains ready frames.
#[derive(Debug, Clone, Copy)]
pub struct BrokerPolicy {
    /// The most any session may ever be granted, before the per-seat clamp
    /// narrows it further. Defaults to everything the broker models.
    pub ceiling: Capabilities,
    /// How often [`serve_connection`] polls the source for frames. Small, for
    /// low latency; the source itself paces real frame production.
    pub frame_poll: Duration,
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            ceiling: Capabilities::all(),
            frame_poll: Duration::from_millis(1),
        }
    }
}

/// The capabilities a seat can ever expose, regardless of what was requested.
/// This is the privileged half of the login-screen policy: the greeter allows
/// exactly enough to log in and nothing that would leak across the trust
/// boundary of an unauthenticated screen.
fn seat_ceiling(seat: Seat) -> Capabilities {
    match seat {
        // Keyboard and mouse so the remote user can type the OS password into
        // the native greeter; never clipboard or gamepad on the login screen.
        Seat::Greeter => Capabilities::CAPTURE
            .with(Capabilities::KEYBOARD)
            .with(Capabilities::MOUSE),
        // Nothing to interact with between sessions.
        Seat::Empty => Capabilities::CAPTURE,
        // A logged-in user's own session: whatever policy and the request allow.
        Seat::User => Capabilities::all(),
    }
}

/// The capabilities actually granted: the request, narrowed to the broker's
/// ceiling and then to what the current seat may expose.
fn effective_grant(requested: Capabilities, ceiling: Capabilities, seat: Seat) -> Capabilities {
    requested.clamped_to(ceiling).clamped_to(seat_ceiling(seat))
}

/// The synchronous broker state machine for one service connection.
#[derive(Debug)]
pub struct BrokerSession {
    policy: BrokerPolicy,
    handshaken: bool,
    done: bool,
    capturing: bool,
    /// The capabilities the service last requested, kept so a seat change can
    /// re-derive the grant without another request.
    requested: Capabilities,
    /// The capabilities currently granted (after the ceiling and seat clamp).
    granted: Capabilities,
    /// The seat currently being captured.
    seat: Seat,
}

impl BrokerSession {
    /// A fresh session that has not yet completed the handshake.
    #[must_use]
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            handshaken: false,
            done: false,
            capturing: false,
            requested: Capabilities::none(),
            granted: Capabilities::none(),
            seat: Seat::Empty,
        }
    }

    /// Whether the connection should be closed (shutdown, or a fatal protocol
    /// error). The async wrapper checks this after each request.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The capabilities currently granted to the session.
    #[must_use]
    pub fn granted(&self) -> Capabilities {
        self.granted
    }

    /// Handle one request, returning the events to send in response.
    pub fn handle_request<F, I>(
        &mut self,
        request: ServiceRequest,
        frames: &mut F,
        input: &mut I,
    ) -> Vec<BrokerEvent>
    where
        F: FrameSource,
        I: InputSink,
    {
        if !self.handshaken {
            return self.handle_handshake(request);
        }
        match request {
            // A second Hello after the handshake is a no-op, not a restart.
            ServiceRequest::Hello { .. } => Vec::new(),
            ServiceRequest::OpenCapture {
                token_id: _,
                requested,
                params,
            } => {
                self.requested = requested;
                self.seat = params.seat;
                self.granted = effective_grant(requested, self.policy.ceiling, params.seat);
                match frames.open(params) {
                    Ok(opened) => {
                        self.capturing = true;
                        vec![BrokerEvent::CaptureStarted {
                            seat: params.seat,
                            kind: params.kind,
                            width: opened.width,
                            height: opened.height,
                            granted: self.granted,
                        }]
                    }
                    Err(failure) => {
                        self.capturing = false;
                        vec![BrokerEvent::CaptureError {
                            code: failure.code,
                            message: failure.message,
                        }]
                    }
                }
            }
            ServiceRequest::SwitchCapture { seat, kind } => {
                self.seat = seat;
                // Re-derive the grant for the new seat: logging in can widen it,
                // logging out narrows it (dropping clipboard, say) at once.
                self.granted = effective_grant(self.requested, self.policy.ceiling, seat);
                match frames.switch(seat, kind) {
                    Ok(opened) => vec![BrokerEvent::CaptureStarted {
                        seat,
                        kind,
                        width: opened.width,
                        height: opened.height,
                        granted: self.granted,
                    }],
                    Err(failure) => vec![BrokerEvent::CaptureError {
                        code: failure.code,
                        message: failure.message,
                    }],
                }
            }
            ServiceRequest::SetBitrate { kbps } => {
                frames.set_bitrate(kbps);
                Vec::new()
            }
            ServiceRequest::RequestKeyframe => {
                frames.request_keyframe();
                Vec::new()
            }
            ServiceRequest::CloseCapture => {
                frames.close();
                self.capturing = false;
                vec![BrokerEvent::Closed {
                    reason: code::CLOSED_ON_REQUEST,
                }]
            }
            ServiceRequest::Input { payload } => {
                // The sink re-checks each event against the grant; an empty
                // grant injects nothing.
                input.inject(&payload, self.granted);
                Vec::new()
            }
            ServiceRequest::Shutdown => {
                frames.close();
                self.capturing = false;
                self.done = true;
                Vec::new()
            }
        }
    }

    fn handle_handshake(&mut self, request: ServiceRequest) -> Vec<BrokerEvent> {
        match request {
            ServiceRequest::Hello { protocol } if protocol == PROTOCOL_VERSION => {
                self.handshaken = true;
                vec![BrokerEvent::Hello {
                    protocol: PROTOCOL_VERSION,
                    capabilities: self.policy.ceiling,
                }]
            }
            ServiceRequest::Hello { .. } => {
                self.done = true;
                vec![BrokerEvent::CaptureError {
                    code: code::PROTOCOL_VERSION,
                    message: "unsupported protocol version".to_string(),
                }]
            }
            _ => {
                self.done = true;
                vec![BrokerEvent::CaptureError {
                    code: code::PROTOCOL_VIOLATION,
                    message: "expected Hello before any other request".to_string(),
                }]
            }
        }
    }

    /// Drain every ready frame and rumble event from the devices while a capture
    /// is open, oldest first.
    pub fn pump<F, I>(&mut self, frames: &mut F, input: &mut I) -> Vec<BrokerEvent>
    where
        F: FrameSource,
        I: InputSink,
    {
        let mut events = Vec::new();
        if !self.capturing {
            return events;
        }
        while let Some(frame) = frames.next_frame() {
            events.push(BrokerEvent::Frame {
                sequence: frame.sequence,
                timestamp_us: frame.timestamp_us,
                keyframe: frame.keyframe,
                data: frame.data,
            });
        }
        while let Some(rumble) = input.take_rumble() {
            events.push(BrokerEvent::Rumble {
                device_id: rumble.device_id,
                strong: rumble.strong,
                weak: rumble.weak,
            });
        }
        events
    }
}

/// Serve one authenticated service connection to completion.
///
/// `peer` is the already-verified identity of the connected service (the caller
/// authorises it with [`peercred`](openstream_host_ipc::peercred) before calling
/// this); it is accepted here so the audit line and any per-peer policy have it.
/// The loop reads requests, runs them through a [`BrokerSession`], and writes the
/// resulting events, draining frames on the policy's poll tick in between.
///
/// # Errors
/// Returns an I/O error if the transport fails. A clean EOF (the service closed
/// the socket) returns `Ok(())`.
pub async fn serve_connection<R, W, F, I>(
    reader: &mut R,
    writer: &mut W,
    peer: PeerIdentity,
    policy: BrokerPolicy,
    frames: &mut F,
    input: &mut I,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FrameSource,
    I: InputSink,
{
    let _ = peer;
    let mut session = BrokerSession::new(policy);
    let mut tick = tokio::time::interval(policy.frame_poll);
    loop {
        tokio::select! {
            request = recv_request(reader) => {
                let request = match request {
                    Ok(request) => request,
                    // A clean EOF is the service disconnecting, not an error.
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                };
                for event in session.handle_request(request, frames, input) {
                    send_event(writer, &event).await?;
                }
                if session.is_done() {
                    break;
                }
            }
            _ = tick.tick() => {
                for event in session.pump(frames, input) {
                    send_event(writer, &event).await?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::EncodedFrame;
    use crate::device::fakes::{FakeFrameSource, FakeInputSink};
    use openstream_host_ipc::lifecycle::CaptureKind;
    use openstream_host_ipc::protocol::CaptureParams;

    fn params(seat: Seat) -> CaptureParams {
        CaptureParams {
            seat,
            kind: CaptureKind::Scanout,
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 8_000,
        }
    }

    fn handshaken() -> (BrokerSession, FakeFrameSource, FakeInputSink) {
        let mut session = BrokerSession::new(BrokerPolicy::default());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events = session.handle_request(
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(events.as_slice(), [BrokerEvent::Hello { .. }]));
        (session, frames, input)
    }

    #[test]
    fn a_request_before_the_handshake_is_a_fatal_violation() {
        let mut session = BrokerSession::new(BrokerPolicy::default());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events =
            session.handle_request(ServiceRequest::RequestKeyframe, &mut frames, &mut input);
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError {
                code: code::PROTOCOL_VIOLATION,
                ..
            }]
        ));
        assert!(session.is_done());
    }

    #[test]
    fn a_version_mismatch_is_refused() {
        let mut session = BrokerSession::new(BrokerPolicy::default());
        let mut frames = FakeFrameSource::default();
        let mut input = FakeInputSink::default();
        let events = session.handle_request(
            ServiceRequest::Hello { protocol: 999 },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError {
                code: code::PROTOCOL_VERSION,
                ..
            }]
        ));
        assert!(session.is_done());
    }

    #[test]
    fn the_greeter_never_grants_clipboard_even_when_requested() {
        let (mut session, mut frames, mut input) = handshaken();
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                // Ask for everything.
                requested: Capabilities::all(),
                params: params(Seat::Greeter),
            },
            &mut frames,
            &mut input,
        );
        let granted = match events.as_slice() {
            [BrokerEvent::CaptureStarted { granted, .. }] => *granted,
            other => panic!("expected CaptureStarted, got {other:?}"),
        };
        // Keyboard and mouse for password entry; capture to see the screen.
        assert!(granted.contains(Capabilities::CAPTURE));
        assert!(granted.contains(Capabilities::KEYBOARD));
        assert!(granted.contains(Capabilities::MOUSE));
        // But nothing sensitive on the login screen.
        assert!(!granted.contains(Capabilities::CLIPBOARD));
        assert!(!granted.contains(Capabilities::GAMEPAD));
    }

    #[test]
    fn a_user_session_grants_what_was_requested() {
        let (mut session, mut frames, mut input) = handshaken();
        let requested = Capabilities::CAPTURE
            .with(Capabilities::KEYBOARD)
            .with(Capabilities::CLIPBOARD);
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested,
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        let granted = match events.as_slice() {
            [BrokerEvent::CaptureStarted { granted, .. }] => *granted,
            other => panic!("expected CaptureStarted, got {other:?}"),
        };
        assert!(granted.contains(Capabilities::CLIPBOARD));
        assert_eq!(granted, requested);
        assert_eq!(frames.opened.len(), 1);
    }

    #[test]
    fn logging_out_to_the_greeter_contracts_the_grant() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(session.granted().contains(Capabilities::CLIPBOARD));

        // The user logs out: the seat switches back to the greeter.
        let events = session.handle_request(
            ServiceRequest::SwitchCapture {
                seat: Seat::Greeter,
                kind: CaptureKind::Scanout,
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureStarted { .. }]
        ));
        assert!(
            !session.granted().contains(Capabilities::CLIPBOARD),
            "clipboard must be dropped when falling back to the greeter"
        );
        assert_eq!(frames.switched, vec![(Seat::Greeter, CaptureKind::Scanout)]);
    }

    #[test]
    fn input_is_injected_with_the_current_grant() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::Greeter),
            },
            &mut frames,
            &mut input,
        );
        session.handle_request(
            ServiceRequest::Input {
                payload: vec![9, 9, 9],
            },
            &mut frames,
            &mut input,
        );
        assert_eq!(input.injected.len(), 1);
        let (payload, granted) = &input.injected[0];
        assert_eq!(payload, &vec![9, 9, 9]);
        // The grant handed to the sink is the greeter-clamped one.
        assert!(!granted.contains(Capabilities::CLIPBOARD));
        assert!(granted.contains(Capabilities::KEYBOARD));
    }

    #[test]
    fn pump_drains_frames_then_rumble_in_order() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        frames.queued.push_back(EncodedFrame {
            sequence: 0,
            timestamp_us: 0,
            keyframe: true,
            data: vec![1],
        });
        frames.queued.push_back(EncodedFrame {
            sequence: 1,
            timestamp_us: 16_000,
            keyframe: false,
            data: vec![2],
        });
        input.rumble.push_back(crate::device::RumbleOut {
            device_id: 0,
            strong: 100,
            weak: 5,
        });

        let events = session.pump(&mut frames, &mut input);
        assert!(matches!(
            events.as_slice(),
            [
                BrokerEvent::Frame {
                    sequence: 0,
                    keyframe: true,
                    ..
                },
                BrokerEvent::Frame {
                    sequence: 1,
                    keyframe: false,
                    ..
                },
                BrokerEvent::Rumble { device_id: 0, .. },
            ]
        ));
    }

    #[test]
    fn a_failed_open_reports_the_error_and_does_not_capture() {
        let (mut session, mut frames, mut input) = handshaken();
        frames.fail_open = Some(crate::device::CaptureFailure::new(2, "encoder unavailable"));
        let events = session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        assert!(matches!(
            events.as_slice(),
            [BrokerEvent::CaptureError { code: 2, .. }]
        ));
        // With nothing capturing, a pump yields nothing.
        assert!(session.pump(&mut frames, &mut input).is_empty());
    }

    #[test]
    fn close_and_shutdown_stop_capture() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );

        let events = session.handle_request(ServiceRequest::CloseCapture, &mut frames, &mut input);
        assert!(matches!(events.as_slice(), [BrokerEvent::Closed { .. }]));
        assert_eq!(frames.closes, 1);
        assert!(session.pump(&mut frames, &mut input).is_empty());

        // Re-open, then shut the whole connection down.
        session.handle_request(
            ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
            &mut frames,
            &mut input,
        );
        session.handle_request(ServiceRequest::Shutdown, &mut frames, &mut input);
        assert!(session.is_done());
        assert_eq!(frames.closes, 2);
    }

    #[test]
    fn set_bitrate_and_keyframe_reach_the_source() {
        let (mut session, mut frames, mut input) = handshaken();
        session.handle_request(
            ServiceRequest::SetBitrate { kbps: 3_500 },
            &mut frames,
            &mut input,
        );
        session.handle_request(ServiceRequest::RequestKeyframe, &mut frames, &mut input);
        assert_eq!(frames.bitrates, vec![3_500]);
        assert_eq!(frames.keyframes, 1);
    }

    #[tokio::test]
    async fn serve_connection_runs_a_handshake_and_streams_a_frame() {
        use openstream_host_ipc::transport::{recv_event, send_request};

        let (mut service, broker_stream) = tokio::io::duplex(64 * 1024);
        let mut frames = FakeFrameSource::default();
        frames.queued.push_back(EncodedFrame {
            sequence: 7,
            timestamp_us: 1_000,
            keyframe: true,
            data: vec![0, 0, 0, 1, 0x65],
        });
        let mut input = FakeInputSink::default();
        let peer = PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4242,
        };

        // Run the broker over its half of the pipe.
        let broker = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(broker_stream);
            let policy = BrokerPolicy {
                ceiling: Capabilities::all(),
                frame_poll: Duration::from_millis(1),
            };
            serve_connection(
                &mut reader,
                &mut writer,
                peer,
                policy,
                &mut frames,
                &mut input,
            )
            .await
            .unwrap();
        });

        // Drive it from the service side.
        send_request(
            &mut service,
            &ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::Hello { .. }
        ));

        send_request(
            &mut service,
            &ServiceRequest::OpenCapture {
                token_id: 1,
                requested: Capabilities::all(),
                params: params(Seat::User),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::CaptureStarted { .. }
        ));

        // The queued frame arrives on the next poll tick.
        assert!(matches!(
            recv_event(&mut service).await.unwrap(),
            BrokerEvent::Frame {
                sequence: 7,
                keyframe: true,
                ..
            }
        ));

        // Shutting down ends the broker task cleanly.
        send_request(&mut service, &ServiceRequest::Shutdown)
            .await
            .unwrap();
        broker.await.unwrap();
    }
}
