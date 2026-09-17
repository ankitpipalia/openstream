//! Bounds-checked binary reader/writer for the broker protocol.
//!
//! The messages are small and fixed-shape, so they are hand-encoded rather than
//! pulling in a derive-based binary format: big-endian scalars and
//! length-prefixed byte strings, matching the rest of the project's wire code.
//! Every read is bounds-checked and [`Reader::finish`] rejects trailing bytes,
//! so a truncated or over-long frame is a clean [`DecodeError`] rather than a
//! panic or a silently accepted partial message.

/// Why decoding a message failed. Carries no attacker-influenced bytes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ended before a field that the message required.
    Truncated,
    /// A tag or enum discriminant that this version does not define.
    BadTag(u8),
    /// Bytes remained after the message was fully decoded.
    TrailingBytes,
    /// A length prefix exceeded the caller's sanity bound for that field.
    TooLong,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("message ended mid-field"),
            DecodeError::BadTag(tag) => write!(f, "unknown tag {tag}"),
            DecodeError::TrailingBytes => f.write_str("unexpected trailing bytes"),
            DecodeError::TooLong => f.write_str("length prefix exceeds the allowed bound"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// The largest byte string any single protocol field will accept. An encoded
/// access unit or input payload above this is rejected as malformed rather than
/// allocated, so a bad length prefix cannot drive an unbounded allocation. Two
/// megabytes comfortably holds a keyframe at the bitrates this host uses.
pub const MAX_FIELD_LEN: usize = 2 * 1024 * 1024;

/// Appends big-endian scalars and length-prefixed byte strings to a buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A writer that begins with the given one-byte message tag.
    #[must_use]
    pub fn tagged(tag: u8) -> Self {
        Self { buf: vec![tag] }
    }

    /// Append one byte.
    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Append a big-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u128` (used for 128-bit session token ids).
    pub fn u128(&mut self, value: u128) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a boolean as a single `0`/`1` byte.
    pub fn bool(&mut self, value: bool) {
        self.buf.push(u8::from(value));
    }

    /// Append a `u32` length prefix followed by the bytes.
    pub fn bytes(&mut self, value: &[u8]) {
        // A field longer than u32::MAX cannot arise from this host's frames;
        // clamp defensively so the prefix and the body cannot disagree.
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.u32(len);
        let take = (len as usize).min(value.len());
        self.buf.extend_from_slice(&value[..take]);
    }

    /// The finished message bytes (tag included), ready for the transport to
    /// length-prefix and send.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads big-endian scalars and length-prefixed byte strings, bounds-checked.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over a message body. Call [`Reader::tag`] first to take the
    /// leading message tag.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Take the leading one-byte message tag.
    pub fn tag(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Take one byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Take a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Take a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Take a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.take(8)?;
        let mut array = [0_u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(array))
    }

    /// Take a big-endian `u128`.
    pub fn u128(&mut self) -> Result<u128, DecodeError> {
        let bytes = self.take(16)?;
        let mut array = [0_u8; 16];
        array.copy_from_slice(bytes);
        Ok(u128::from_be_bytes(array))
    }

    /// Take a boolean, encoded as any non-zero byte for `true`.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    /// Take a `u32`-length-prefixed byte string, rejecting a prefix above
    /// [`MAX_FIELD_LEN`] before reading so a bad length cannot force a large
    /// read against a short buffer.
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_FIELD_LEN {
            return Err(DecodeError::TooLong);
        }
        self.take(len)
    }

    /// Assert the whole buffer was consumed. A well-formed message decodes to
    /// exactly its bytes; anything left over is a framing error.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_scalars_and_bytes() {
        let mut writer = Writer::tagged(7);
        writer.u8(0xAB);
        writer.u16(0x1234);
        writer.u32(0xDEAD_BEEF);
        writer.u64(0x0102_0304_0506_0708);
        writer.bytes(b"payload");
        let encoded = writer.finish();

        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.tag().unwrap(), 7);
        assert_eq!(reader.u8().unwrap(), 0xAB);
        assert_eq!(reader.u16().unwrap(), 0x1234);
        assert_eq!(reader.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(reader.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(reader.bytes().unwrap(), b"payload");
        reader.finish().unwrap();
    }

    #[test]
    fn truncated_reads_are_clean_errors() {
        let mut reader = Reader::new(&[0x00, 0x01]);
        assert_eq!(reader.u32(), Err(DecodeError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bytes = [1_u8, 2, 3];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 1);
        assert_eq!(reader.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn an_oversized_length_prefix_is_rejected_before_reading() {
        // len prefix = MAX_FIELD_LEN + 1, then no body: must be TooLong, not a
        // huge allocation or a truncated read.
        let mut writer = Writer::default();
        writer.u32(u32::try_from(MAX_FIELD_LEN + 1).unwrap());
        let encoded = writer.finish();
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.bytes(), Err(DecodeError::TooLong));
    }

    #[test]
    fn a_length_prefix_past_the_buffer_is_truncated() {
        // Valid-sized prefix but the body is not present.
        let mut writer = Writer::default();
        writer.u32(16);
        writer.buf.extend_from_slice(b"short");
        let encoded = writer.finish();
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.bytes(), Err(DecodeError::Truncated));
    }
}
