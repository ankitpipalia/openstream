//! The message set exchanged between the machine service and the broker.
//!
//! The socket carries length-prefixed frames; each frame body is one of these
//! messages, encoded by [`crate::wire`]. The service drives the broker with
//! [`ServiceRequest`] and the broker reports back with [`BrokerEvent`]. The
//! data path is deliberately **encoded bitstream**, not raw frames: the broker
//! captures the DRM scanout and hardware-encodes it inside its own address
//! space, then ships H.264 access units (tens of kilobytes) to the service.
//! That keeps the DMA-BUF and the GPU import wholly inside the privileged
//! process, so the boundary needs no file-descriptor passing -- only bytes --
//! and the unprivileged, network-facing service never touches the framebuffer.
//!
//! Input travels the other way as an already-encoded `openstream-media` input
//! payload: the broker re-validates it against the session's granted
//! [`crate::token::Capabilities`] before it reaches `/dev/uinput`, so an
//! over-reaching or malformed event is dropped at the privileged boundary
//! rather than trusted because the service forwarded it.

use crate::lifecycle::{CaptureKind, Seat};
use crate::token::Capabilities;
use crate::wire::{DecodeError, Reader, Writer};

/// The protocol version. Both sides announce it in their `Hello`; a mismatch is
/// a clean refusal rather than a misread message.
pub const PROTOCOL_VERSION: u16 = 2;

// Service -> broker tags occupy the low half, broker -> service the high half,
// so a message decoded against the wrong direction fails on the tag rather than
// being silently reinterpreted.
mod tag {
    pub(super) const HELLO: u8 = 0x01;
    pub(super) const OPEN_CAPTURE: u8 = 0x02;
    pub(super) const SWITCH_CAPTURE: u8 = 0x03;
    pub(super) const SET_BITRATE: u8 = 0x04;
    pub(super) const REQUEST_KEYFRAME: u8 = 0x05;
    pub(super) const CLOSE_CAPTURE: u8 = 0x06;
    pub(super) const INPUT: u8 = 0x07;
    pub(super) const SHUTDOWN: u8 = 0x08;

    pub(super) const EV_HELLO: u8 = 0x81;
    pub(super) const EV_CAPTURE_STARTED: u8 = 0x82;
    pub(super) const EV_FRAME: u8 = 0x83;
    pub(super) const EV_RUMBLE: u8 = 0x84;
    pub(super) const EV_CAPTURE_ERROR: u8 = 0x85;
    pub(super) const EV_CLOSED: u8 = 0x86;
}

fn seat_to_wire(seat: Seat) -> u8 {
    match seat {
        Seat::Empty => 0,
        Seat::Greeter => 1,
        Seat::User => 2,
    }
}

fn seat_from_wire(byte: u8) -> Result<Seat, DecodeError> {
    match byte {
        0 => Ok(Seat::Empty),
        1 => Ok(Seat::Greeter),
        2 => Ok(Seat::User),
        other => Err(DecodeError::BadTag(other)),
    }
}

fn kind_to_wire(kind: CaptureKind) -> u8 {
    match kind {
        CaptureKind::Scanout => 0,
        CaptureKind::PipeWire => 1,
    }
}

fn kind_from_wire(byte: u8) -> Result<CaptureKind, DecodeError> {
    match byte {
        0 => Ok(CaptureKind::Scanout),
        1 => Ok(CaptureKind::PipeWire),
        other => Err(DecodeError::BadTag(other)),
    }
}

/// The geometry and pacing the service negotiated with the peer and is asking
/// the broker to capture and encode at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureParams {
    /// Which seat to capture.
    pub seat: Seat,
    /// Scanout or a session-agent PipeWire stream.
    pub kind: CaptureKind,
    /// Encoded frame width in pixels.
    pub width: u16,
    /// Encoded frame height in pixels.
    pub height: u16,
    /// Target frame rate.
    pub fps: u8,
    /// Target encoder bitrate in kilobits per second.
    pub bitrate_kbps: u32,
}

/// A request from the unprivileged machine service to the privileged broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceRequest {
    /// Version handshake, sent first on a fresh connection.
    Hello {
        /// The service's [`PROTOCOL_VERSION`].
        protocol: u16,
    },
    /// Begin capturing and encoding for an approved peer session.
    ///
    /// `token_id` is zero to ask the broker to issue a grant, or the id of the
    /// grant it already issued on this connection. It is never a value the
    /// service invented: the broker rejects any id it did not mint itself.
    ///
    /// `requested` can only *narrow* what the broker's policy already allows.
    /// A service asking for more than its ceiling does not get more; the extra
    /// bits are dropped, as they always were, but the ceiling no longer
    /// defaults to everything.
    OpenCapture {
        /// Zero to be issued a grant, or the id of this connection's grant.
        token_id: u128,
        /// Capabilities the service is requesting, as a reduction only.
        requested: Capabilities,
        /// Geometry and pacing to encode at.
        params: CaptureParams,
    },
    /// Re-point the live capture (greeter <-> user, scanout <-> PipeWire)
    /// without ending the session, driven by the lifecycle state machine.
    SwitchCapture {
        /// The grant this capture belongs to.
        token_id: u128,
        /// The seat to capture now.
        seat: Seat,
        /// The source kind to capture with now.
        kind: CaptureKind,
    },
    /// Change the encoder's target bitrate (adaptive control).
    SetBitrate {
        /// New target bitrate in kilobits per second.
        kbps: u32,
    },
    /// Force the next frame to be a keyframe (IDR).
    RequestKeyframe,
    /// Stop capturing but keep the connection open for the next `OpenCapture`.
    CloseCapture,
    /// Inject an `openstream-media` input payload, subject to the session's
    /// granted capabilities. The bytes are opaque here; the broker decodes and
    /// validates them.
    Input {
        /// The grant authorising this injection.
        token_id: u128,
        /// The encoded input-event bytes.
        payload: Vec<u8>,
    },
    /// The service is shutting down; the broker should release devices.
    Shutdown,
}

impl ServiceRequest {
    /// Encode to a self-describing message body (tag included).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ServiceRequest::Hello { protocol } => {
                let mut writer = Writer::tagged(tag::HELLO);
                writer.u16(*protocol);
                writer.finish()
            }
            ServiceRequest::OpenCapture {
                token_id,
                requested,
                params,
            } => {
                let mut writer = Writer::tagged(tag::OPEN_CAPTURE);
                writer.u128(*token_id);
                writer.u32(requested.bits());
                writer.u8(seat_to_wire(params.seat));
                writer.u8(kind_to_wire(params.kind));
                writer.u16(params.width);
                writer.u16(params.height);
                writer.u8(params.fps);
                writer.u32(params.bitrate_kbps);
                writer.finish()
            }
            ServiceRequest::SwitchCapture {
                token_id,
                seat,
                kind,
            } => {
                let mut writer = Writer::tagged(tag::SWITCH_CAPTURE);
                writer.u128(*token_id);
                writer.u8(seat_to_wire(*seat));
                writer.u8(kind_to_wire(*kind));
                writer.finish()
            }
            ServiceRequest::SetBitrate { kbps } => {
                let mut writer = Writer::tagged(tag::SET_BITRATE);
                writer.u32(*kbps);
                writer.finish()
            }
            ServiceRequest::RequestKeyframe => Writer::tagged(tag::REQUEST_KEYFRAME).finish(),
            ServiceRequest::CloseCapture => Writer::tagged(tag::CLOSE_CAPTURE).finish(),
            ServiceRequest::Input { token_id, payload } => {
                let mut writer = Writer::tagged(tag::INPUT);
                writer.u128(*token_id);
                writer.bytes(payload);
                writer.finish()
            }
            ServiceRequest::Shutdown => Writer::tagged(tag::SHUTDOWN).finish(),
        }
    }

    /// Decode a message body produced by [`ServiceRequest::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let message = match reader.tag()? {
            tag::HELLO => ServiceRequest::Hello {
                protocol: reader.u16()?,
            },
            tag::OPEN_CAPTURE => {
                let token_id = reader.u128()?;
                let requested = Capabilities::from_bits_truncate(reader.u32()?);
                let seat = seat_from_wire(reader.u8()?)?;
                let kind = kind_from_wire(reader.u8()?)?;
                let width = reader.u16()?;
                let height = reader.u16()?;
                let fps = reader.u8()?;
                let bitrate_kbps = reader.u32()?;
                ServiceRequest::OpenCapture {
                    token_id,
                    requested,
                    params: CaptureParams {
                        seat,
                        kind,
                        width,
                        height,
                        fps,
                        bitrate_kbps,
                    },
                }
            }
            tag::SWITCH_CAPTURE => ServiceRequest::SwitchCapture {
                token_id: reader.u128()?,
                seat: seat_from_wire(reader.u8()?)?,
                kind: kind_from_wire(reader.u8()?)?,
            },
            tag::SET_BITRATE => ServiceRequest::SetBitrate {
                kbps: reader.u32()?,
            },
            tag::REQUEST_KEYFRAME => ServiceRequest::RequestKeyframe,
            tag::CLOSE_CAPTURE => ServiceRequest::CloseCapture,
            tag::INPUT => ServiceRequest::Input {
                token_id: reader.u128()?,
                payload: reader.bytes()?.to_vec(),
            },
            tag::SHUTDOWN => ServiceRequest::Shutdown,
            other => return Err(DecodeError::BadTag(other)),
        };
        reader.finish()?;
        Ok(message)
    }
}

/// A report from the broker back to the machine service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerEvent {
    /// Version handshake plus what the broker can actually do on this machine.
    Hello {
        /// The broker's [`PROTOCOL_VERSION`].
        protocol: u16,
        /// The capabilities the broker's policy will ever grant here.
        capabilities: Capabilities,
    },
    /// Capture has begun; carries the geometry actually in use and the
    /// capabilities the broker granted after clamping the request.
    CaptureStarted {
        /// The grant the broker issued for this session. The service presents
        /// this id on every later request; it cannot mint one of its own.
        token_id: u128,
        /// The seat now being captured.
        seat: Seat,
        /// The source kind now in use.
        kind: CaptureKind,
        /// Actual encoded width.
        width: u16,
        /// Actual encoded height.
        height: u16,
        /// Capabilities the broker granted the session.
        granted: Capabilities,
    },
    /// One encoded H.264 access unit.
    Frame {
        /// Monotonic frame sequence number.
        sequence: u32,
        /// Capture timestamp in microseconds since the stream began.
        timestamp_us: u64,
        /// Whether this access unit is a keyframe (IDR).
        keyframe: bool,
        /// The access-unit bytes (Annex-B).
        data: Vec<u8>,
    },
    /// Force-feedback from a captured gamepad, to forward to the peer.
    Rumble {
        /// Which pad.
        device_id: u8,
        /// Strong (low-frequency) motor magnitude.
        strong: u16,
        /// Weak (high-frequency) motor magnitude.
        weak: u16,
    },
    /// Capture or encode failed. `code` is a stable machine-readable reason;
    /// `message` is a short, secret-free human string.
    CaptureError {
        /// Stable reason code.
        code: u16,
        /// Short human-readable detail, no secrets.
        message: String,
    },
    /// Capture stopped in response to a `CloseCapture` or a lost source.
    Closed {
        /// Stable reason code.
        reason: u16,
    },
}

impl BrokerEvent {
    /// Encode to a self-describing message body (tag included).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            BrokerEvent::Hello {
                protocol,
                capabilities,
            } => {
                let mut writer = Writer::tagged(tag::EV_HELLO);
                writer.u16(*protocol);
                writer.u32(capabilities.bits());
                writer.finish()
            }
            BrokerEvent::CaptureStarted {
                token_id,
                seat,
                kind,
                width,
                height,
                granted,
            } => {
                let mut writer = Writer::tagged(tag::EV_CAPTURE_STARTED);
                writer.u128(*token_id);
                writer.u8(seat_to_wire(*seat));
                writer.u8(kind_to_wire(*kind));
                writer.u16(*width);
                writer.u16(*height);
                writer.u32(granted.bits());
                writer.finish()
            }
            BrokerEvent::Frame {
                sequence,
                timestamp_us,
                keyframe,
                data,
            } => {
                let mut writer = Writer::tagged(tag::EV_FRAME);
                writer.u32(*sequence);
                writer.u64(*timestamp_us);
                writer.bool(*keyframe);
                writer.bytes(data);
                writer.finish()
            }
            BrokerEvent::Rumble {
                device_id,
                strong,
                weak,
            } => {
                let mut writer = Writer::tagged(tag::EV_RUMBLE);
                writer.u8(*device_id);
                writer.u16(*strong);
                writer.u16(*weak);
                writer.finish()
            }
            BrokerEvent::CaptureError { code, message } => {
                let mut writer = Writer::tagged(tag::EV_CAPTURE_ERROR);
                writer.u16(*code);
                writer.bytes(message.as_bytes());
                writer.finish()
            }
            BrokerEvent::Closed { reason } => {
                let mut writer = Writer::tagged(tag::EV_CLOSED);
                writer.u16(*reason);
                writer.finish()
            }
        }
    }

    /// Decode a message body produced by [`BrokerEvent::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let message = match reader.tag()? {
            tag::EV_HELLO => BrokerEvent::Hello {
                protocol: reader.u16()?,
                capabilities: Capabilities::from_bits_truncate(reader.u32()?),
            },
            tag::EV_CAPTURE_STARTED => BrokerEvent::CaptureStarted {
                token_id: reader.u128()?,
                seat: seat_from_wire(reader.u8()?)?,
                kind: kind_from_wire(reader.u8()?)?,
                width: reader.u16()?,
                height: reader.u16()?,
                granted: Capabilities::from_bits_truncate(reader.u32()?),
            },
            tag::EV_FRAME => BrokerEvent::Frame {
                sequence: reader.u32()?,
                timestamp_us: reader.u64()?,
                keyframe: reader.bool()?,
                data: reader.bytes()?.to_vec(),
            },
            tag::EV_RUMBLE => BrokerEvent::Rumble {
                device_id: reader.u8()?,
                strong: reader.u16()?,
                weak: reader.u16()?,
            },
            tag::EV_CAPTURE_ERROR => {
                let code = reader.u16()?;
                let message = String::from_utf8_lossy(reader.bytes()?).into_owned();
                BrokerEvent::CaptureError { code, message }
            }
            tag::EV_CLOSED => BrokerEvent::Closed {
                reason: reader.u16()?,
            },
            other => return Err(DecodeError::BadTag(other)),
        };
        reader.finish()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_round_trip(message: ServiceRequest) {
        let encoded = message.encode();
        let decoded = ServiceRequest::decode(&encoded).expect("decode");
        assert_eq!(decoded, message);
    }

    fn broker_round_trip(message: BrokerEvent) {
        let encoded = message.encode();
        let decoded = BrokerEvent::decode(&encoded).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn every_service_request_round_trips() {
        service_round_trip(ServiceRequest::Hello {
            protocol: PROTOCOL_VERSION,
        });
        service_round_trip(ServiceRequest::OpenCapture {
            token_id: 0x0123_4567_89AB_CDEF_0011_2233_4455_6677,
            requested: Capabilities::CAPTURE.with(Capabilities::KEYBOARD),
            params: CaptureParams {
                seat: Seat::Greeter,
                kind: CaptureKind::Scanout,
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_kbps: 10_000,
            },
        });
        service_round_trip(ServiceRequest::SwitchCapture {
            token_id: 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
            seat: Seat::User,
            kind: CaptureKind::PipeWire,
        });
        service_round_trip(ServiceRequest::SetBitrate { kbps: 4_000 });
        service_round_trip(ServiceRequest::RequestKeyframe);
        service_round_trip(ServiceRequest::CloseCapture);
        service_round_trip(ServiceRequest::Input {
            token_id: u128::MAX,
            payload: vec![1, 2, 3, 4, 5],
        });
        service_round_trip(ServiceRequest::Shutdown);
    }

    #[test]
    fn every_broker_event_round_trips() {
        broker_round_trip(BrokerEvent::Hello {
            protocol: PROTOCOL_VERSION,
            capabilities: Capabilities::all(),
        });
        broker_round_trip(BrokerEvent::CaptureStarted {
            token_id: 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
            seat: Seat::User,
            kind: CaptureKind::Scanout,
            width: 2560,
            height: 1440,
            granted: Capabilities::CAPTURE,
        });
        broker_round_trip(BrokerEvent::Frame {
            sequence: 42,
            timestamp_us: 1_000_000,
            keyframe: true,
            data: vec![0, 0, 0, 1, 0x67, 0x42],
        });
        broker_round_trip(BrokerEvent::Rumble {
            device_id: 1,
            strong: 40_000,
            weak: 10_000,
        });
        broker_round_trip(BrokerEvent::CaptureError {
            code: 3,
            message: "encoder unavailable".to_string(),
        });
        broker_round_trip(BrokerEvent::Closed { reason: 0 });
    }

    #[test]
    fn a_service_tag_does_not_decode_as_a_broker_event() {
        // A Hello from the service (tag 0x01) must not be misread as an event.
        let encoded = ServiceRequest::Hello { protocol: 1 }.encode();
        assert!(matches!(
            BrokerEvent::decode(&encoded),
            Err(DecodeError::BadTag(0x01))
        ));
    }

    #[test]
    fn a_truncated_open_capture_is_rejected() {
        let mut encoded = ServiceRequest::OpenCapture {
            token_id: 7,
            requested: Capabilities::all(),
            params: CaptureParams {
                seat: Seat::Greeter,
                kind: CaptureKind::Scanout,
                width: 800,
                height: 600,
                fps: 30,
                bitrate_kbps: 2_000,
            },
        }
        .encode();
        encoded.truncate(encoded.len() - 3);
        assert_eq!(
            ServiceRequest::decode(&encoded),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn an_unknown_seat_byte_is_rejected() {
        // Tag OPEN_CAPTURE, token, caps, then an out-of-range seat byte (9).
        let mut writer = Writer::tagged(tag::OPEN_CAPTURE);
        writer.u128(1);
        writer.u32(0);
        writer.u8(9);
        writer.u8(0);
        writer.u16(0);
        writer.u16(0);
        writer.u8(0);
        writer.u32(0);
        let encoded = writer.finish();
        assert_eq!(
            ServiceRequest::decode(&encoded),
            Err(DecodeError::BadTag(9))
        );
    }

    #[test]
    fn trailing_bytes_after_a_message_are_rejected() {
        let mut encoded = ServiceRequest::RequestKeyframe.encode();
        encoded.push(0xFF);
        assert_eq!(
            ServiceRequest::decode(&encoded),
            Err(DecodeError::TrailingBytes)
        );
    }
}
