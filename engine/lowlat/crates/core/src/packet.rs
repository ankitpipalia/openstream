//! Cleartext packets: data, acknowledgements, and authenticated PMTU probes.
//!
//! See docs/01-protocol.md 5. Validation is deliberately strict and total: a
//! packet failing any check is discarded without touching session state, and
//! that is routine rather than exceptional.

use crate::error::{Error, Result};

/// First byte of every cleartext packet.
pub const MARKER: u8 = 0x01;
/// Fixed header ahead of a data packet's body.
pub const HEADER_LEN: usize = 7;
/// Group acknowledgements and keepalives are exactly this long.
pub const ACK_LEN: usize = 83;
/// Channels are indexed 0 to 18.
pub const CHANNEL_COUNT: usize = 19;

pub const FLAG_DATA: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
/// An authenticated, padded path-MTU probe. Its `seq` field is a probe ID,
/// not a data-channel sequence number.
pub const FLAG_PROBE: u8 = 0x04;
pub const FLAG_KEEPALIVE: u8 = 0x08;
pub const FLAG_NACK: u8 = 0x10;
/// Set on the **last** fragment of a message, clear on earlier ones.
///
/// Emit it correctly for a peer's validation, but never key reassembly on it;
/// reassembly is length-driven (docs/01-protocol.md 7).
pub const FLAG_LAST: u8 = 0x20;
/// Positive confirmation for an exact-size path-MTU probe.
pub const FLAG_PROBE_ACK: u8 = 0x40;

/// Bit 7 remains reserved. The other formerly reserved bits carry the
/// authenticated PMTU probe vocabulary.
const RESERVED_MASK: u8 = 0x80;
/// The bits that select which kind of packet this is.
const KIND_MASK: u8 = 0x0B;

/// A data packet carrying one fragment of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Data<'a> {
    pub channel: u8,
    pub seq: u32,
    /// True if this is the final fragment of its message.
    pub last: bool,
    pub body: &'a [u8],
}

/// A padded path-MTU probe. `size` is the expected encrypted UDP payload
/// length, including the envelope, and is echoed by the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub id: u32,
    pub size: usize,
}

/// A positive acknowledgement for one exact path-MTU probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeAck {
    pub id: u32,
    pub size: usize,
}

/// Acknowledgements and keepalives share a layout and differ only in kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckKind {
    Ack,
    Keepalive,
}

/// One packet acknowledging every channel at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub kind: AckKind,
    /// Requests fast retransmission below `trigger_seq`. Only valid with
    /// [`AckKind::Ack`].
    pub nack: bool,
    pub trigger_channel: u8,
    pub trigger_seq: u32,
    /// Next sequence expected per channel, so everything below is acknowledged.
    pub cumulative: [u32; CHANNEL_COUNT],
    /// How many of [`Ack::cumulative`] the sender actually reported.
    ///
    /// **A channel a peer did not report is not a channel it acknowledged
    /// nothing on**, and confusing the two would either do nothing or, near a
    /// sequence wrap, look like an acknowledgement that never happened.
    pub reported: usize,
}

/// The acknowledgement variant is much larger than the data variant, because
/// it carries one cumulative value per channel. Boxing it is not an option in
/// a crate with no allocator, and the whole packet is short-lived scratch, so
/// the size difference is accepted deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    Data(Data<'a>),
    Ack(Ack),
    Probe(Probe),
    ProbeAck(ProbeAck),
}

fn be32(src: &[u8], offset: usize) -> Result<u32> {
    src.get(offset..offset + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_be_bytes)
        .ok_or(Error::ShortPacket)
}

/// Parse a cleartext packet.
///
/// Checks run in the order given in docs/01-protocol.md 5.1. Every rejection
/// is an ordinary outcome; nothing here is a protocol error that should end a
/// session.
pub fn parse(cleartext: &[u8]) -> Result<Packet<'_>> {
    let &marker = cleartext.first().ok_or(Error::ShortPacket)?;
    let &flags = cleartext.get(1).ok_or(Error::ShortPacket)?;
    let &channel = cleartext.get(2).ok_or(Error::ShortPacket)?;
    if cleartext.len() < HEADER_LEN {
        return Err(Error::ShortPacket);
    }

    if flags & RESERVED_MASK != 0 {
        return Err(Error::Malformed);
    }
    let probe_kind = flags & (FLAG_PROBE | FLAG_PROBE_ACK);
    if probe_kind != 0 {
        // Probes are deliberately a separate vocabulary. They have no data
        // channel semantics, no NACK/last bit, and must carry an exact-size
        // two-byte echo value after the common header.
        if flags != FLAG_PROBE && flags != FLAG_PROBE_ACK {
            return Err(Error::Malformed);
        }
        if channel != 0 {
            return Err(Error::Malformed);
        }
        if marker != MARKER {
            return Err(Error::Malformed);
        }
        let id = be32(cleartext, 3)?;
        if id == u32::MAX {
            return Err(Error::Malformed);
        }
        let size = cleartext
            .get(HEADER_LEN..HEADER_LEN + 2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .ok_or(Error::ShortPacket)?;
        if !(crate::DEFAULT_DATAGRAM..=crate::MAX_DATAGRAM).contains(&size) {
            return Err(Error::Malformed);
        }
        if probe_kind == FLAG_PROBE {
            let expected_cleartext_len = size
                .checked_sub(crate::envelope::ENVELOPE_LEN)
                .ok_or(Error::Malformed)?;
            if cleartext.len() != expected_cleartext_len
                || cleartext
                    .get(HEADER_LEN + 2..)
                    .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
            {
                return Err(Error::Malformed);
            }
            return Ok(Packet::Probe(Probe { id, size }));
        }
        if cleartext.len() != HEADER_LEN + 2 {
            return Err(Error::Malformed);
        }
        return Ok(Packet::ProbeAck(ProbeAck { id, size }));
    }

    let kind = flags & KIND_MASK;
    if kind != FLAG_DATA && kind != FLAG_ACK && kind != FLAG_KEEPALIVE {
        return Err(Error::Malformed);
    }
    let nack = flags & FLAG_NACK != 0;
    if nack && kind != FLAG_ACK {
        return Err(Error::Malformed);
    }
    let last = flags & FLAG_LAST != 0;
    if last && (kind != FLAG_DATA || nack) {
        return Err(Error::Malformed);
    }
    if marker != MARKER {
        return Err(Error::Malformed);
    }
    if channel as usize >= CHANNEL_COUNT {
        return Err(Error::Malformed);
    }
    let seq = be32(cleartext, 3)?;
    if seq == u32::MAX {
        return Err(Error::Malformed);
    }

    if kind == FLAG_DATA {
        let body = cleartext.get(HEADER_LEN..).ok_or(Error::ShortPacket)?;
        return Ok(Packet::Data(Data {
            channel,
            seq,
            last,
            body,
        }));
    }

    // **A peer reports one cumulative value per channel it has, and peers do
    // not all have the same number of channels.** An older generation sends
    // four where the current one sends nineteen, so a fixed length refuses
    // every acknowledgement that generation sends -- and a peer whose
    // acknowledgements are all refused is indistinguishable from one that has
    // stopped receiving, which is the reading that ends the session.
    //
    // Read what is there and remember how much that was. Reading past the end
    // is the hazard the fixed length guarded against, and the bound below is
    // what actually prevents it.
    let reported = cleartext.len().saturating_sub(HEADER_LEN) / 4;
    if reported == 0 {
        return Err(Error::ShortAck);
    }
    let reported = reported.min(CHANNEL_COUNT);
    let mut cumulative = [0u32; CHANNEL_COUNT];
    for (index, slot) in cumulative.iter_mut().take(reported).enumerate() {
        *slot = be32(cleartext, HEADER_LEN + index * 4)?;
    }
    Ok(Packet::Ack(Ack {
        kind: if kind == FLAG_ACK {
            AckKind::Ack
        } else {
            AckKind::Keepalive
        },
        nack,
        trigger_channel: channel,
        trigger_seq: seq,
        cumulative,
        reported,
    }))
}

/// Write a data packet header followed by `body`. Returns bytes written.
pub fn encode_data(out: &mut [u8], data: &Data<'_>) -> Result<usize> {
    if data.channel as usize >= CHANNEL_COUNT || data.seq == u32::MAX {
        return Err(Error::Malformed);
    }
    let total = HEADER_LEN
        .checked_add(data.body.len())
        .ok_or(Error::BufferTooSmall)?;
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;

    let mut flags = FLAG_DATA;
    if data.last {
        flags |= FLAG_LAST;
    }
    let [s0, s1, s2, s3] = data.seq.to_be_bytes();
    let header = [MARKER, flags, data.channel, s0, s1, s2, s3];
    let (head, body) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&header);
    body.copy_from_slice(data.body);
    Ok(total)
}

/// Write a path-MTU probe and pad it to exactly `probe.size` encrypted wire
/// bytes. The envelope is added by [`crate::session::Session`], so this
/// function writes only the cleartext portion.
pub fn encode_probe(out: &mut [u8], probe: &Probe) -> Result<usize> {
    if probe.id == u32::MAX
        || !(crate::DEFAULT_DATAGRAM..=crate::MAX_DATAGRAM).contains(&probe.size)
    {
        return Err(Error::Malformed);
    }
    let cleartext_len = probe
        .size
        .checked_sub(crate::envelope::ENVELOPE_LEN)
        .ok_or(Error::BufferTooSmall)?;
    if cleartext_len < HEADER_LEN + 2 {
        return Err(Error::BufferTooSmall);
    }
    let out = out.get_mut(..cleartext_len).ok_or(Error::BufferTooSmall)?;
    let [s0, s1, s2, s3] = probe.id.to_be_bytes();
    let [m0, m1] = u16::try_from(probe.size)
        .map_err(|_| Error::BadLength)?
        .to_be_bytes();
    let (head, tail) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&[MARKER, FLAG_PROBE, 0, s0, s1, s2, s3]);
    let size_bytes = tail.get_mut(..2).ok_or(Error::BufferTooSmall)?;
    size_bytes.copy_from_slice(&[m0, m1]);
    for byte in tail.get_mut(2..).unwrap_or(&mut []) {
        *byte = 0;
    }
    Ok(cleartext_len)
}

/// Write a small positive acknowledgement for an exact path-MTU probe.
pub fn encode_probe_ack(out: &mut [u8], ack: &ProbeAck) -> Result<usize> {
    if ack.id == u32::MAX || !(crate::DEFAULT_DATAGRAM..=crate::MAX_DATAGRAM).contains(&ack.size) {
        return Err(Error::Malformed);
    }
    let out = out.get_mut(..HEADER_LEN + 2).ok_or(Error::BufferTooSmall)?;
    let [s0, s1, s2, s3] = ack.id.to_be_bytes();
    let [m0, m1] = u16::try_from(ack.size)
        .map_err(|_| Error::BadLength)?
        .to_be_bytes();
    let (head, tail) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&[MARKER, FLAG_PROBE_ACK, 0, s0, s1, s2, s3]);
    let size_bytes = tail.get_mut(..2).ok_or(Error::BufferTooSmall)?;
    size_bytes.copy_from_slice(&[m0, m1]);
    Ok(HEADER_LEN + 2)
}

/// Write a group acknowledgement or keepalive. Always [`ACK_LEN`] bytes.
pub fn encode_ack(out: &mut [u8], ack: &Ack) -> Result<usize> {
    if ack.trigger_channel as usize >= CHANNEL_COUNT {
        return Err(Error::Malformed);
    }
    if ack.nack && ack.kind != AckKind::Ack {
        return Err(Error::Malformed);
    }
    let out = out.get_mut(..ACK_LEN).ok_or(Error::BufferTooSmall)?;

    let mut flags = match ack.kind {
        AckKind::Ack => FLAG_ACK,
        AckKind::Keepalive => FLAG_KEEPALIVE,
    };
    if ack.nack {
        flags |= FLAG_NACK;
    }
    let [s0, s1, s2, s3] = ack.trigger_seq.to_be_bytes();
    let header = [MARKER, flags, ack.trigger_channel, s0, s1, s2, s3];
    let (head, tail) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&header);
    for (index, value) in ack.cumulative.iter().enumerate() {
        let Some(slot) = tail.get_mut(index * 4..index * 4 + 4) else {
            return Err(Error::BufferTooSmall);
        };
        slot.copy_from_slice(&value.to_be_bytes());
    }
    Ok(ACK_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ack() -> Ack {
        let mut cumulative = [0u32; CHANNEL_COUNT];
        for (index, slot) in cumulative.iter_mut().enumerate() {
            *slot = u32::try_from(index).unwrap_or(0) * 1000;
        }
        Ack {
            kind: AckKind::Ack,
            nack: true,
            trigger_channel: 5,
            trigger_seq: 0x1234_5678,
            cumulative,
            reported: CHANNEL_COUNT,
        }
    }

    #[test]
    fn data_round_trip_and_layout() {
        let body = [0xAAu8; 32];
        let data = Data {
            channel: 5,
            seq: 0x1234_5678,
            last: true,
            body: &body,
        };
        let mut buf = [0u8; 64];
        let n = encode_data(&mut buf, &data).unwrap();
        assert_eq!(n, HEADER_LEN + body.len());
        assert_eq!(buf[0], MARKER);
        assert_eq!(buf[1], FLAG_DATA | FLAG_LAST);
        assert_eq!(buf[2], 5);
        assert_eq!(&buf[3..7], &[0x12, 0x34, 0x56, 0x78]);

        let Packet::Data(got) = parse(&buf[..n]).unwrap() else {
            panic!("expected data");
        };
        assert_eq!(got, data);
    }

    #[test]
    fn a_path_probe_is_padded_to_its_declared_wire_size() {
        let probe = Probe {
            id: 0x1234_5678,
            size: crate::DEFAULT_DATAGRAM,
        };
        let mut buf = [0xA5u8; crate::DEFAULT_DATAGRAM];
        let cleartext_len = encode_probe(&mut buf, &probe).unwrap();
        assert_eq!(cleartext_len + crate::envelope::ENVELOPE_LEN, probe.size);
        assert_eq!(
            &buf[..HEADER_LEN],
            &[MARKER, FLAG_PROBE, 0, 0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(
            &buf[HEADER_LEN..HEADER_LEN + 2],
            &u16::try_from(probe.size).unwrap().to_be_bytes()
        );
        assert!(
            buf[HEADER_LEN + 2..cleartext_len]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(parse(&buf[..cleartext_len]), Ok(Packet::Probe(probe)));
    }

    #[test]
    fn a_probe_rejects_wrong_length_or_nonzero_padding() {
        let probe = Probe {
            id: 1,
            size: crate::DEFAULT_DATAGRAM,
        };
        let mut buf = [0u8; crate::DEFAULT_DATAGRAM];
        let cleartext_len = encode_probe(&mut buf, &probe).unwrap();
        assert_eq!(
            parse(&buf[..cleartext_len - 1]),
            Err(Error::Malformed),
            "declared size must describe the complete encrypted payload"
        );
        buf[cleartext_len - 1] = 1;
        assert_eq!(parse(&buf[..cleartext_len]), Err(Error::Malformed));
    }

    #[test]
    fn a_probe_ack_round_trips_with_the_exact_size_echo() {
        let ack = ProbeAck { id: 7, size: 1400 };
        let mut buf = [0u8; 64];
        let written = encode_probe_ack(&mut buf, &ack).unwrap();
        assert_eq!(written, HEADER_LEN + 2);
        assert_eq!(parse(&buf[..written]), Ok(Packet::ProbeAck(ack)));
    }

    #[test]
    fn probe_flags_cannot_be_combined_or_moved_to_another_channel() {
        let mut buf = [0u8; HEADER_LEN + 2];
        buf[0] = MARKER;
        buf[1] = FLAG_PROBE | FLAG_PROBE_ACK;
        buf[2] = 0;
        buf[3..7].copy_from_slice(&1u32.to_be_bytes());
        buf[HEADER_LEN..].copy_from_slice(&1280u16.to_be_bytes());
        assert_eq!(parse(&buf), Err(Error::Malformed));

        buf[1] = FLAG_PROBE;
        buf[2] = 1;
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn probes_require_the_canonical_marker_and_non_reserved_id() {
        let mut buf = [0u8; HEADER_LEN + 2];
        buf[0] = 0xFF;
        buf[1] = FLAG_PROBE;
        buf[2] = 0;
        buf[3..7].copy_from_slice(&1u32.to_be_bytes());
        buf[HEADER_LEN..].copy_from_slice(&1280u16.to_be_bytes());
        assert_eq!(parse(&buf), Err(Error::Malformed));

        buf[0] = MARKER;
        buf[3..7].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn probe_ack_does_not_accept_ambiguous_trailing_bytes() {
        let ack = ProbeAck { id: 7, size: 1400 };
        let mut buf = [0u8; HEADER_LEN + 3];
        let written = encode_probe_ack(&mut buf, &ack).unwrap();
        buf[written] = 1;
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn ack_round_trip_and_size() {
        let ack = sample_ack();
        let mut buf = [0u8; 128];
        assert_eq!(encode_ack(&mut buf, &ack).unwrap(), ACK_LEN);
        assert_eq!(buf[1], FLAG_ACK | FLAG_NACK);
        let Packet::Ack(got) = parse(&buf[..ACK_LEN]).unwrap() else {
            panic!("expected ack");
        };
        assert_eq!(got, ack);
    }

    #[test]
    fn keepalive_uses_the_acknowledgement_layout() {
        let mut ack = sample_ack();
        ack.kind = AckKind::Keepalive;
        ack.nack = false;
        let mut buf = [0u8; 128];
        encode_ack(&mut buf, &ack).unwrap();
        assert_eq!(buf[1], FLAG_KEEPALIVE);
        let Packet::Ack(got) = parse(&buf[..ACK_LEN]).unwrap() else {
            panic!("expected ack");
        };
        assert_eq!(got.kind, AckKind::Keepalive);
    }

    fn header_with_flags(flags: u8) -> [u8; ACK_LEN] {
        let mut buf = [0u8; ACK_LEN];
        buf[0] = MARKER;
        buf[1] = flags;
        buf[2] = 0;
        buf[3..7].copy_from_slice(&1u32.to_be_bytes());
        buf
    }

    #[test]
    fn rejects_reserved_flag_bits() {
        for bit in [0x04u8, 0x40, 0x80] {
            let buf = header_with_flags(FLAG_DATA | bit);
            assert_eq!(parse(&buf), Err(Error::Malformed), "bit {bit:#x}");
        }
    }

    #[test]
    fn rejects_ambiguous_or_absent_kind() {
        for flags in [
            0x00u8,
            FLAG_DATA | FLAG_ACK,
            FLAG_DATA | FLAG_KEEPALIVE,
            0x0B,
        ] {
            let buf = header_with_flags(flags);
            assert_eq!(parse(&buf), Err(Error::Malformed), "flags {flags:#x}");
        }
    }

    #[test]
    fn nack_requires_acknowledgement() {
        let buf = header_with_flags(FLAG_DATA | FLAG_NACK);
        assert_eq!(parse(&buf), Err(Error::Malformed));
        let buf = header_with_flags(FLAG_KEEPALIVE | FLAG_NACK);
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn last_requires_data_and_forbids_nack() {
        let buf = header_with_flags(FLAG_ACK | FLAG_LAST);
        assert_eq!(parse(&buf), Err(Error::Malformed));
        let buf = header_with_flags(FLAG_ACK | FLAG_NACK | FLAG_LAST);
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn rejects_bad_marker_channel_and_sequence() {
        let mut buf = header_with_flags(FLAG_DATA);
        buf[0] = 2;
        assert_eq!(parse(&buf), Err(Error::Malformed));

        let mut buf = header_with_flags(FLAG_DATA);
        buf[2] = u8::try_from(CHANNEL_COUNT).unwrap();
        assert_eq!(parse(&buf), Err(Error::Malformed));

        let mut buf = header_with_flags(FLAG_DATA);
        buf[3..7].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse(&buf), Err(Error::Malformed));
    }

    #[test]
    fn rejects_a_short_acknowledgement() {
        // Nothing to report at all is still refused: a header on its own says
        // nothing about any channel.
        let buf = header_with_flags(FLAG_ACK);
        for len in HEADER_LEN..HEADER_LEN + 4 {
            assert_eq!(parse(&buf[..len]), Err(Error::ShortAck), "len {len}");
        }
    }

    /// **An acknowledgement carrying fewer channels than we do is read, not
    /// refused.**
    ///
    /// A peer generation exists that carries four where this one carries
    /// nineteen, and its acknowledgement is 23 bytes: the seven-byte header
    /// and four cumulative values. Refusing it drops every acknowledgement
    /// that peer sends, which presents as a peer that has stopped receiving --
    /// a window that only grows, every fragment stale, and a session ended for
    /// undeliverability while the peer is decoding happily.
    #[test]
    fn an_acknowledgement_reporting_fewer_channels_is_read() {
        const LEGACY_CHANNELS: usize = 4;
        const LEGACY_LEN: usize = HEADER_LEN + LEGACY_CHANNELS * 4;
        assert_eq!(LEGACY_LEN, 23, "the length a peer generation really sends");

        let mut buf = header_with_flags(FLAG_ACK);
        for channel in 0..LEGACY_CHANNELS {
            let at = HEADER_LEN + channel * 4;
            let value = 0x0A00_0000u32 + channel as u32;
            buf[at..at + 4].copy_from_slice(&value.to_be_bytes());
        }

        let Ok(Packet::Ack(ack)) = parse(&buf[..LEGACY_LEN]) else {
            panic!("a 23-byte acknowledgement was refused");
        };
        assert_eq!(ack.reported, LEGACY_CHANNELS);
        for channel in 0..LEGACY_CHANNELS {
            assert_eq!(
                ack.cumulative[channel],
                0x0A00_0000u32 + channel as u32,
                "channel {channel} did not survive"
            );
        }
        // Everything past what it reported stays absent rather than reading as
        // an acknowledgement of nothing.
        for channel in LEGACY_CHANNELS..CHANNEL_COUNT {
            assert_eq!(ack.cumulative[channel], 0);
        }

        // And a full-length one still reports every channel.
        let full = header_with_flags(FLAG_ACK);
        let Ok(Packet::Ack(ack)) = parse(&full) else {
            panic!("a full acknowledgement was refused");
        };
        assert_eq!(ack.reported, CHANNEL_COUNT);
    }

    #[test]
    fn rejects_a_packet_shorter_than_a_header() {
        for len in 0..HEADER_LEN {
            let buf = header_with_flags(FLAG_DATA);
            assert!(parse(&buf[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn an_empty_data_body_is_valid() {
        let data = Data {
            channel: 0,
            seq: 1,
            last: false,
            body: &[],
        };
        let mut buf = [0u8; 16];
        let n = encode_data(&mut buf, &data).unwrap();
        assert_eq!(n, HEADER_LEN);
        let Packet::Data(got) = parse(&buf[..n]).unwrap() else {
            panic!("expected data");
        };
        assert!(got.body.is_empty());
    }
}
