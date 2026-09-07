//! Small RFC 5389 STUN Binding client used for server-reflexive candidates.
//!
//! This is deliberately only the binding transaction.  ICE nomination,
//! consent freshness, TURN allocation, and policy around which candidates a
//! peer may use belong above this module.  Keeping the parser here tiny also
//! makes it possible to fuzz independently of the encrypted media path.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

const MAGIC_COOKIE: u32 = 0x2112_a442;
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Errors returned by a STUN Binding transaction.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Timeout,
    InvalidMessage(&'static str),
    UnexpectedResponse,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "STUN I/O failed: {error}"),
            Self::Timeout => f.write_str("STUN Binding request timed out"),
            Self::InvalidMessage(reason) => write!(f, "invalid STUN message: {reason}"),
            Self::UnexpectedResponse => {
                f.write_str("STUN response did not contain a mapped address")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Send one Binding request on an already-bound socket and return its public
/// address as reported by the STUN server.
pub(crate) async fn binding(
    socket: &UdpSocket,
    server: SocketAddr,
    wait: Duration,
) -> Result<SocketAddr, Error> {
    let transaction = transaction_id()?;
    let request = request(transaction);
    socket.send_to(&request, server).await?;

    let deadline = Instant::now() + wait;
    let mut response = [0_u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        let received = timeout(remaining, socket.recv_from(&mut response))
            .await
            .map_err(|_| Error::Timeout)??;
        let (length, source) = received;
        if source != server {
            continue;
        }
        match parse_response(&response[..length], transaction) {
            Ok(Some(address)) => return Ok(address),
            Ok(None) => return Err(Error::UnexpectedResponse),
            Err(Error::InvalidMessage(_)) => continue,
            Err(error) => return Err(error),
        }
    }
}

fn transaction_id() -> Result<[u8; 12], Error> {
    let mut transaction = [0_u8; 12];
    getrandom::getrandom(&mut transaction)
        .map_err(|_| Error::InvalidMessage("OS random source unavailable"))?;
    Ok(transaction)
}

fn request(transaction: [u8; 12]) -> [u8; HEADER_LEN] {
    let mut packet = [0_u8; HEADER_LEN];
    packet[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    packet[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(&transaction);
    packet
}

fn parse_response(packet: &[u8], transaction: [u8; 12]) -> Result<Option<SocketAddr>, Error> {
    if packet.len() < HEADER_LEN {
        return Err(Error::InvalidMessage("header is truncated"));
    }
    let message_type = u16::from_be_bytes([packet[0], packet[1]]);
    let message_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if message_length % 4 != 0 || HEADER_LEN + message_length > packet.len() {
        return Err(Error::InvalidMessage("attribute length is invalid"));
    }
    if u32::from_be_bytes(packet[4..8].try_into().unwrap()) != MAGIC_COOKIE {
        return Err(Error::InvalidMessage("magic cookie is invalid"));
    }
    if packet[8..20] != transaction {
        return Err(Error::InvalidMessage("transaction ID is not ours"));
    }
    if message_type != BINDING_SUCCESS {
        return Err(Error::UnexpectedResponse);
    }

    let end = HEADER_LEN + message_length;
    let mut offset = HEADER_LEN;
    while offset + 4 <= end {
        let attribute_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let attribute_length =
            usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        let value_start = offset + 4;
        let value_end = value_start + attribute_length;
        if value_end > end {
            return Err(Error::InvalidMessage("attribute is truncated"));
        }
        let value = &packet[value_start..value_end];
        if attribute_type == XOR_MAPPED_ADDRESS {
            if let Some(address) = decode_address(value, true, transaction)? {
                return Ok(Some(address));
            }
        } else if attribute_type == MAPPED_ADDRESS {
            if let Some(address) = decode_address(value, false, transaction)? {
                return Ok(Some(address));
            }
        }
        offset = value_start + attribute_length.div_ceil(4) * 4;
    }
    Ok(None)
}

fn decode_address(
    value: &[u8],
    xor: bool,
    transaction: [u8; 12],
) -> Result<Option<SocketAddr>, Error> {
    if value.len() < 4 || value[0] != 0 {
        return Err(Error::InvalidMessage("address attribute is invalid"));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match family {
        0x01 if value.len() == 8 => {
            let mut address = u32::from_be_bytes(value[4..8].try_into().unwrap());
            if xor {
                address ^= MAGIC_COOKIE;
            }
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address)),
                port,
            )))
        }
        0x02 if value.len() == 20 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&value[4..20]);
            if xor {
                let mask = MAGIC_COOKIE.to_be_bytes();
                for (index, byte) in address.iter_mut().enumerate() {
                    *byte ^= if index < 4 {
                        mask[index]
                    } else {
                        transaction[index - 4]
                    };
                }
            }
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address)),
                port,
            )))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(transaction: [u8; 12], attribute_type: u16, value: &[u8]) -> Vec<u8> {
        let padded = value.len().div_ceil(4) * 4;
        let message_length = 4 + padded;
        let mut packet = vec![0_u8; HEADER_LEN + message_length];
        packet[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet[2..4].copy_from_slice(&u16::try_from(message_length).unwrap().to_be_bytes());
        packet[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet[8..20].copy_from_slice(&transaction);
        packet[20..22].copy_from_slice(&attribute_type.to_be_bytes());
        packet[22..24].copy_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        packet[24..24 + value.len()].copy_from_slice(value);
        packet
    }

    #[test]
    fn parses_xor_mapped_ipv4() {
        let transaction = [0x10; 12];
        let address = u32::from(Ipv4Addr::new(203, 0, 113, 9)) ^ MAGIC_COOKIE;
        let port = 44_321_u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let value = [
            0,
            1,
            port.to_be_bytes()[0],
            port.to_be_bytes()[1],
            address.to_be_bytes()[0],
            address.to_be_bytes()[1],
            address.to_be_bytes()[2],
            address.to_be_bytes()[3],
        ];
        let packet = response(transaction, XOR_MAPPED_ADDRESS, &value);
        assert_eq!(
            parse_response(&packet, transaction).unwrap(),
            Some("203.0.113.9:44321".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn binding_uses_the_same_bound_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request_packet = [0_u8; 64];
            let (length, source) = server.recv_from(&mut request_packet).await.unwrap();
            let transaction: [u8; 12] = request_packet[8..20].try_into().unwrap();
            let address = client_addr.ip().to_string();
            let address: Ipv4Addr = address.parse().unwrap();
            let port = client_addr.port();
            let value = [
                0,
                1,
                port.to_be_bytes()[0],
                port.to_be_bytes()[1],
                address.octets()[0],
                address.octets()[1],
                address.octets()[2],
                address.octets()[3],
            ];
            let response_packet = response(transaction, MAPPED_ADDRESS, &value);
            server.send_to(&response_packet, source).await.unwrap();
            assert_eq!(length, HEADER_LEN);
        });
        assert_eq!(
            binding(&client, server_addr, Duration::from_secs(1))
                .await
                .unwrap(),
            client_addr
        );
        task.await.unwrap();
    }
}
