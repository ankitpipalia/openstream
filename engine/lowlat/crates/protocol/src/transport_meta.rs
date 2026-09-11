//! Authenticated transport metadata carried inside encrypted control packets.

/// Dedicated encrypted channel for transport metadata acknowledgements.
pub const TRANSPORT_META_CHANNEL: u8 = 254;
/// Maximum receiver-controlled delay represented by an acknowledgement.
pub const MAX_ACK_DELAY_US: u32 = 25_000;
/// Number of counters represented by the acknowledgement bitmap.
pub const ACK_BITMAP_BITS: usize = 64;

const VERSION: u8 = 1;
const ACK_RECORD_TYPE: u8 = 1;
const RESERVED_OFFSET: usize = 2;
const GENERATION_OFFSET: usize = 4;
const LARGEST_COUNTER_OFFSET: usize = 12;
const RECEIVED_MASK_OFFSET: usize = 20;
const ACK_DELAY_OFFSET: usize = 28;
const RECORD_LEN: usize = 32;

/// Acknowledgement of authenticated outer packet counters on one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportAck {
    pub generation: u64,
    pub largest_counter: u64,
    pub received_mask: u64,
    pub ack_delay_us: u32,
}

/// Failures while encoding or decoding a transport metadata record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMetaError {
    InvalidLength { expected: usize, actual: usize },
    UnsupportedVersion(u8),
    UnsupportedRecordType(u8),
    ReservedBytes,
    LargestNotAcknowledged,
    CounterUnderflow,
    AckDelayTooLarge(u32),
}

impl core::fmt::Display for TransportMetaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => write!(
                f,
                "transport metadata record has invalid length: expected {expected} bytes, got {actual}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported transport metadata version {version}")
            }
            Self::UnsupportedRecordType(record_type) => {
                write!(
                    f,
                    "unsupported transport metadata record type {record_type}"
                )
            }
            Self::ReservedBytes => f.write_str("transport metadata reserved bytes are non-zero"),
            Self::LargestNotAcknowledged => {
                f.write_str("transport metadata ACK must acknowledge its largest counter")
            }
            Self::CounterUnderflow => {
                f.write_str("transport metadata acknowledgement counter underflows")
            }
            Self::AckDelayTooLarge(delay_us) => {
                write!(
                    f,
                    "transport metadata acknowledgement delay is too large: {delay_us} us"
                )
            }
        }
    }
}

impl std::error::Error for TransportMetaError {}

impl TransportAck {
    /// Encode the fixed v1 acknowledgement record.
    pub fn encode(self) -> Result<[u8; RECORD_LEN], TransportMetaError> {
        if self.received_mask & 1 == 0 {
            return Err(TransportMetaError::LargestNotAcknowledged);
        }
        if self.ack_delay_us > MAX_ACK_DELAY_US {
            return Err(TransportMetaError::AckDelayTooLarge(self.ack_delay_us));
        }

        let mut bytes = [0_u8; RECORD_LEN];
        bytes[0] = VERSION;
        bytes[1] = ACK_RECORD_TYPE;
        bytes[GENERATION_OFFSET..LARGEST_COUNTER_OFFSET]
            .copy_from_slice(&self.generation.to_be_bytes());
        bytes[LARGEST_COUNTER_OFFSET..RECEIVED_MASK_OFFSET]
            .copy_from_slice(&self.largest_counter.to_be_bytes());
        bytes[RECEIVED_MASK_OFFSET..ACK_DELAY_OFFSET]
            .copy_from_slice(&self.received_mask.to_be_bytes());
        bytes[ACK_DELAY_OFFSET..RECORD_LEN].copy_from_slice(&self.ack_delay_us.to_be_bytes());
        Ok(bytes)
    }

    /// Decode and validate one fixed v1 acknowledgement record.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportMetaError> {
        if bytes.len() != RECORD_LEN {
            return Err(TransportMetaError::InvalidLength {
                expected: RECORD_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != VERSION {
            return Err(TransportMetaError::UnsupportedVersion(bytes[0]));
        }
        if bytes[1] != ACK_RECORD_TYPE {
            return Err(TransportMetaError::UnsupportedRecordType(bytes[1]));
        }
        if bytes[RESERVED_OFFSET] != 0 || bytes[RESERVED_OFFSET + 1] != 0 {
            return Err(TransportMetaError::ReservedBytes);
        }

        let generation = u64::from_be_bytes(
            bytes[GENERATION_OFFSET..LARGEST_COUNTER_OFFSET]
                .try_into()
                .expect("transport metadata length is checked"),
        );
        let largest_counter = u64::from_be_bytes(
            bytes[LARGEST_COUNTER_OFFSET..RECEIVED_MASK_OFFSET]
                .try_into()
                .expect("transport metadata length is checked"),
        );
        let received_mask = u64::from_be_bytes(
            bytes[RECEIVED_MASK_OFFSET..ACK_DELAY_OFFSET]
                .try_into()
                .expect("transport metadata length is checked"),
        );
        if received_mask & 1 == 0 {
            return Err(TransportMetaError::LargestNotAcknowledged);
        }
        let ack_delay_us = u32::from_be_bytes(
            bytes[ACK_DELAY_OFFSET..RECORD_LEN]
                .try_into()
                .expect("transport metadata length is checked"),
        );
        if ack_delay_us > MAX_ACK_DELAY_US {
            return Err(TransportMetaError::AckDelayTooLarge(ack_delay_us));
        }
        for bit in 1..ACK_BITMAP_BITS {
            if received_mask & (1_u64 << bit) != 0
                && u64::try_from(bit).expect("bitmap bit fits in u64") > largest_counter
            {
                return Err(TransportMetaError::CounterUnderflow);
            }
        }

        Ok(Self {
            generation,
            largest_counter,
            received_mask,
            ack_delay_us,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_ack() -> TransportAck {
        TransportAck {
            generation: 7,
            largest_counter: 100,
            received_mask: 0b101,
            ack_delay_us: 2_000,
        }
    }

    #[test]
    fn transport_ack_round_trips_exactly() {
        let ack = valid_ack();
        assert_eq!(TransportAck::decode(&ack.encode().unwrap()).unwrap(), ack);
    }

    #[test]
    fn transport_ack_uses_exact_big_endian_wire_layout() {
        let ack = TransportAck {
            generation: 0x0102_0304_0506_0708,
            largest_counter: 0x1112_1314_1516_1718,
            received_mask: 0x2122_2324_2526_2729,
            ack_delay_us: 0x0000_61A8,
        };
        assert_eq!(
            ack.encode().unwrap(),
            [
                1, 1, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x29, 0x00, 0x00,
                0x61, 0xA8,
            ]
        );
    }

    #[test]
    fn transport_ack_rejects_missing_largest_bit_and_accepts_maximum_counter() {
        let zero = TransportAck {
            generation: 0,
            largest_counter: 0,
            received_mask: 0,
            ack_delay_us: 0,
        };
        let maximum = TransportAck {
            generation: u64::MAX,
            largest_counter: u64::MAX,
            received_mask: u64::MAX,
            ack_delay_us: MAX_ACK_DELAY_US,
        };

        assert_eq!(
            zero.encode(),
            Err(TransportMetaError::LargestNotAcknowledged)
        );
        let mut missing_largest = valid_ack().encode().unwrap();
        missing_largest[RECEIVED_MASK_OFFSET..ACK_DELAY_OFFSET]
            .copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            TransportAck::decode(&missing_largest),
            Err(TransportMetaError::LargestNotAcknowledged)
        );
        assert_eq!(
            TransportAck::decode(&maximum.encode().unwrap()).unwrap(),
            maximum
        );
    }

    #[test]
    fn transport_ack_accepts_delay_bound_and_rejects_larger_delay() {
        let at_bound = TransportAck {
            ack_delay_us: MAX_ACK_DELAY_US,
            ..valid_ack()
        };
        assert_eq!(
            TransportAck::decode(&at_bound.encode().unwrap()).unwrap(),
            at_bound
        );

        let above_bound = TransportAck {
            ack_delay_us: MAX_ACK_DELAY_US + 1,
            ..valid_ack()
        };
        assert_eq!(
            above_bound.encode(),
            Err(TransportMetaError::AckDelayTooLarge(MAX_ACK_DELAY_US + 1))
        );

        let mut encoded = at_bound.encode().unwrap();
        encoded[28..32].copy_from_slice(&(MAX_ACK_DELAY_US + 1).to_be_bytes());
        assert_eq!(
            TransportAck::decode(&encoded),
            Err(TransportMetaError::AckDelayTooLarge(MAX_ACK_DELAY_US + 1))
        );
    }

    #[test]
    fn transport_ack_rejects_non_zero_reserved_bytes() {
        let mut encoded = valid_ack().encode().unwrap();
        encoded[2] = 1;
        assert_eq!(
            TransportAck::decode(&encoded),
            Err(TransportMetaError::ReservedBytes)
        );

        encoded[2] = 0;
        encoded[3] = 1;
        assert_eq!(
            TransportAck::decode(&encoded),
            Err(TransportMetaError::ReservedBytes)
        );
    }

    #[test]
    fn transport_ack_rejects_wrong_version_and_record_type() {
        let mut encoded = valid_ack().encode().unwrap();
        encoded[0] = 2;
        assert_eq!(
            TransportAck::decode(&encoded),
            Err(TransportMetaError::UnsupportedVersion(2))
        );

        encoded[0] = 1;
        encoded[1] = 2;
        assert_eq!(
            TransportAck::decode(&encoded),
            Err(TransportMetaError::UnsupportedRecordType(2))
        );
    }

    #[test]
    fn transport_ack_rejects_short_and_long_records() {
        let encoded = valid_ack().encode().unwrap();
        assert_eq!(
            TransportAck::decode(&encoded[..31]),
            Err(TransportMetaError::InvalidLength {
                expected: 32,
                actual: 31,
            })
        );

        let mut long = encoded.to_vec();
        long.push(0);
        assert_eq!(
            TransportAck::decode(&long),
            Err(TransportMetaError::InvalidLength {
                expected: 32,
                actual: 33,
            })
        );
    }

    #[test]
    fn an_ack_bit_that_underflows_largest_counter_is_rejected() {
        let ack = TransportAck {
            largest_counter: 1,
            received_mask: 1 | (1 << 2),
            ..valid_ack()
        };
        assert_eq!(
            TransportAck::decode(&ack.encode().unwrap()),
            Err(TransportMetaError::CounterUnderflow)
        );
    }
}
