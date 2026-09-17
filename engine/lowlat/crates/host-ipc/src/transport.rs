//! Length-prefixed message transport over an async byte stream.
//!
//! The broker socket carries [`crate::protocol`] messages framed as a 4-byte
//! big-endian length followed by that many body bytes. This module is the
//! framing: it reads and writes one whole message at a time over any
//! `tokio` reader/writer, so it works over a `UnixStream` in production and an
//! in-memory pipe in tests. Every read is bounded by [`MAX_MESSAGE_LEN`] before
//! it allocates, so a hostile or corrupt length prefix cannot drive an
//! unbounded allocation, and each write is flushed immediately -- this is a
//! low-latency control-and-media path, not a throughput pipe, so nothing is
//! held back in a buffer.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{BrokerEvent, ServiceRequest};
use crate::wire::{DecodeError, MAX_FIELD_LEN};

/// The largest message body the transport will read. A `Frame` is the biggest
/// message: its header plus one byte string bounded by [`MAX_FIELD_LEN`], so a
/// little headroom over that field bound covers every message.
pub const MAX_MESSAGE_LEN: usize = MAX_FIELD_LEN + 256;

fn decode_error(error: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Write one length-prefixed message body and flush it.
///
/// # Errors
/// Returns an I/O error if the body is longer than `u32::MAX` or the write
/// fails.
pub async fn write_message<W>(writer: &mut W, body: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message body exceeds u32"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed message body, rejecting a length above
/// [`MAX_MESSAGE_LEN`] before allocating.
///
/// # Errors
/// Returns an I/O error on a short read, a closed stream, or an over-long
/// length prefix.
pub async fn read_message<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message length exceeds the transport bound",
        ));
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Send a [`ServiceRequest`] (service -> broker).
///
/// # Errors
/// Propagates any write error.
pub async fn send_request<W>(writer: &mut W, request: &ServiceRequest) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_message(writer, &request.encode()).await
}

/// Receive one [`ServiceRequest`] (broker side).
///
/// # Errors
/// Returns an I/O error on a transport failure or a malformed message.
pub async fn recv_request<R>(reader: &mut R) -> io::Result<ServiceRequest>
where
    R: AsyncRead + Unpin,
{
    let body = read_message(reader).await?;
    ServiceRequest::decode(&body).map_err(decode_error)
}

/// Send a [`BrokerEvent`] (broker -> service).
///
/// # Errors
/// Propagates any write error.
pub async fn send_event<W>(writer: &mut W, event: &BrokerEvent) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_message(writer, &event.encode()).await
}

/// Receive one [`BrokerEvent`] (service side).
///
/// # Errors
/// Returns an I/O error on a transport failure or a malformed message.
pub async fn recv_event<R>(reader: &mut R) -> io::Result<BrokerEvent>
where
    R: AsyncRead + Unpin,
{
    let body = read_message(reader).await?;
    BrokerEvent::decode(&body).map_err(decode_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{CaptureKind, Seat};
    use crate::protocol::{CaptureParams, PROTOCOL_VERSION};
    use crate::token::Capabilities;

    #[tokio::test]
    async fn a_service_request_round_trips_over_a_pipe() {
        let (mut client, mut broker) = tokio::io::duplex(64 * 1024);
        let sent = ServiceRequest::OpenCapture {
            token_id: 0xABCD,
            requested: Capabilities::CAPTURE.with(Capabilities::MOUSE),
            params: CaptureParams {
                seat: Seat::Greeter,
                kind: CaptureKind::Scanout,
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_kbps: 8_000,
            },
        };
        send_request(&mut client, &sent).await.unwrap();
        let got = recv_request(&mut broker).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn a_broker_event_round_trips_over_a_pipe() {
        let (mut broker, mut service) = tokio::io::duplex(64 * 1024);
        let sent = BrokerEvent::Frame {
            sequence: 5,
            timestamp_us: 250_000,
            keyframe: true,
            data: vec![0, 0, 0, 1, 0x65, 0x88, 0x84],
        };
        send_event(&mut broker, &sent).await.unwrap();
        let got = recv_event(&mut service).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn several_messages_stream_in_order() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let messages = [
            ServiceRequest::Hello {
                protocol: PROTOCOL_VERSION,
            },
            ServiceRequest::RequestKeyframe,
            ServiceRequest::SetBitrate { kbps: 3_000 },
            ServiceRequest::Shutdown,
        ];
        for message in &messages {
            send_request(&mut writer, message).await.unwrap();
        }
        for message in &messages {
            assert_eq!(&recv_request(&mut reader).await.unwrap(), message);
        }
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused_before_allocating() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        // Write a length prefix past the bound; the reader must reject it
        // without trying to allocate that much.
        let bogus = u32::try_from(MAX_MESSAGE_LEN + 1).unwrap();
        writer.write_all(&bogus.to_be_bytes()).await.unwrap();
        writer.flush().await.unwrap();
        let error = read_message(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_malformed_body_is_an_invalid_data_error() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        // A single unknown tag byte: valid framing, invalid message.
        write_message(&mut writer, &[0xEE]).await.unwrap();
        let error = recv_request(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
