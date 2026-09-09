//! Versioned, authenticated path migration control records.
//!
//! These records are payloads for the encrypted outer `Kind::Control`
//! datagram. They intentionally contain no routing addresses or credentials.

/// Current path-control record format version.
pub const VERSION: u8 = 1;
/// Maximum number of bytes in a single path-control record.
pub const MAX_PATH_CONTROL_BYTES: usize = 64;
/// Number of opaque, generation-scoped token bytes.
pub const PATH_TOKEN_BYTES: usize = 16;

const HEADER_LEN: usize = 4;
const REQUEST_LEN: usize = HEADER_LEN + 4;
const PREPARE_LEN: usize = HEADER_LEN + 8 + PATH_TOKEN_BYTES;
const TOKEN_RECORD_LEN: usize = HEADER_LEN + 8 + PATH_TOKEN_BYTES;
const READY_LEN: usize = TOKEN_RECORD_LEN + 2;
const ABORT_LEN: usize = HEADER_LEN + 8;

const REQUEST: u8 = 1;
const PREPARE: u8 = 2;
const PROBE: u8 = 3;
const PROBE_ACK: u8 = 4;
const READY: u8 = 5;
const COMMIT: u8 = 6;
const COMMIT_ACK: u8 = 7;
const ABORT: u8 = 8;

/// The type of path a peer is asked to prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    DirectUdp,
    OpaqueRelay,
    Ice,
}

/// Why a prepared path was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    Unsupported,
    Timeout,
    CandidateUnavailable,
    ProbeFailed,
    PmtuUnavailable,
    ResourceLimit,
    CommitUnconfirmed,
}

/// A bounded record for a generation-scoped path migration exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathControl {
    Request {
        request_id: u32,
        kind: PathKind,
    },
    Prepare {
        generation: u64,
        kind: PathKind,
        token: [u8; PATH_TOKEN_BYTES],
    },
    Probe {
        generation: u64,
        token: [u8; PATH_TOKEN_BYTES],
    },
    ProbeAck {
        generation: u64,
        token: [u8; PATH_TOKEN_BYTES],
    },
    Ready {
        generation: u64,
        token: [u8; PATH_TOKEN_BYTES],
        datagram_size: u16,
    },
    Commit {
        generation: u64,
        token: [u8; PATH_TOKEN_BYTES],
    },
    CommitAck {
        generation: u64,
        token: [u8; PATH_TOKEN_BYTES],
    },
    Abort {
        generation: u64,
        reason: AbortReason,
    },
}

/// Path-control codec failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Truncated { expected: usize, actual: usize },
    InvalidLength { expected: usize, actual: usize },
    UnsupportedVersion(u8),
    UnknownRecordType(u8),
    ReservedBits(u8),
    InvalidPathKind(u8),
    InvalidAbortReason(u8),
    ZeroGeneration,
    ZeroToken,
    InvalidDatagramSize(u16),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("path-control record is too large"),
            Self::Truncated { expected, actual } => write!(
                f,
                "path-control record is truncated: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidLength { expected, actual } => write!(
                f,
                "path-control record has invalid length: expected {expected} bytes, got {actual}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported path-control version {version}")
            }
            Self::UnknownRecordType(record_type) => {
                write!(f, "unknown path-control record type {record_type}")
            }
            Self::ReservedBits(bits) => write!(f, "path-control reserved bits are set: {bits:#x}"),
            Self::InvalidPathKind(kind) => write!(f, "invalid path kind {kind}"),
            Self::InvalidAbortReason(reason) => write!(f, "invalid abort reason {reason}"),
            Self::ZeroGeneration => f.write_str("path-control generation cannot be zero"),
            Self::ZeroToken => f.write_str("path-control token cannot be all zero"),
            Self::InvalidDatagramSize(size) => {
                write!(f, "invalid path-control datagram size {size}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl PathControl {
    /// Encode a fixed-format, bounded path-control record.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let out = match self {
            Self::Request { request_id, kind } => {
                let mut out = header(REQUEST, path_kind_code(*kind));
                out.extend_from_slice(&request_id.to_be_bytes());
                out
            }
            Self::Prepare {
                generation,
                kind,
                token,
            } => {
                validate_generation_and_token(*generation, token)?;
                let mut out = header(PREPARE, path_kind_code(*kind));
                append_generation_and_token(&mut out, *generation, token);
                out
            }
            Self::Probe { generation, token } => encode_token_record(PROBE, *generation, token)?,
            Self::ProbeAck { generation, token } => {
                encode_token_record(PROBE_ACK, *generation, token)?
            }
            Self::Ready {
                generation,
                token,
                datagram_size,
            } => {
                validate_generation_and_token(*generation, token)?;
                if *datagram_size == 0 {
                    return Err(Error::InvalidDatagramSize(*datagram_size));
                }
                let mut out = header(READY, 0);
                append_generation_and_token(&mut out, *generation, token);
                out.extend_from_slice(&datagram_size.to_be_bytes());
                out
            }
            Self::Commit { generation, token } => encode_token_record(COMMIT, *generation, token)?,
            Self::CommitAck { generation, token } => {
                encode_token_record(COMMIT_ACK, *generation, token)?
            }
            Self::Abort { generation, reason } => {
                if *generation == 0 {
                    return Err(Error::ZeroGeneration);
                }
                let mut out = header(ABORT, abort_reason_code(*reason));
                out.extend_from_slice(&generation.to_be_bytes());
                out
            }
        };
        debug_assert!(out.len() <= MAX_PATH_CONTROL_BYTES);
        Ok(out)
    }

    /// Decode a record after the outer packet's AES-GCM authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PATH_CONTROL_BYTES {
            return Err(Error::TooLarge);
        }
        require_at_least(bytes, HEADER_LEN)?;
        if bytes[0] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[0]));
        }
        let record_type = bytes[1];
        let field = bytes[2];
        if bytes[3] != 0 {
            return Err(Error::ReservedBits(bytes[3]));
        }
        match record_type {
            REQUEST => {
                require_exact(bytes, REQUEST_LEN)?;
                Ok(Self::Request {
                    request_id: u32::from_be_bytes(bytes[4..8].try_into().expect("length checked")),
                    kind: decode_path_kind(field)?,
                })
            }
            PREPARE => {
                require_exact(bytes, PREPARE_LEN)?;
                let (generation, token) = decode_generation_and_token(bytes)?;
                Ok(Self::Prepare {
                    generation,
                    kind: decode_path_kind(field)?,
                    token,
                })
            }
            PROBE => decode_token_record(bytes, field, PROBE, |generation, token| Self::Probe {
                generation,
                token,
            }),
            PROBE_ACK => decode_token_record(bytes, field, PROBE_ACK, |generation, token| {
                Self::ProbeAck { generation, token }
            }),
            READY => {
                require_exact(bytes, READY_LEN)?;
                require_zero_field(field)?;
                let (generation, token) = decode_generation_and_token(bytes)?;
                let datagram_size =
                    u16::from_be_bytes(bytes[28..30].try_into().expect("length checked"));
                if datagram_size == 0 {
                    return Err(Error::InvalidDatagramSize(datagram_size));
                }
                Ok(Self::Ready {
                    generation,
                    token,
                    datagram_size,
                })
            }
            COMMIT => decode_token_record(bytes, field, COMMIT, |generation, token| Self::Commit {
                generation,
                token,
            }),
            COMMIT_ACK => decode_token_record(bytes, field, COMMIT_ACK, |generation, token| {
                Self::CommitAck { generation, token }
            }),
            ABORT => {
                require_exact(bytes, ABORT_LEN)?;
                let generation = decode_generation(bytes)?;
                Ok(Self::Abort {
                    generation,
                    reason: decode_abort_reason(field)?,
                })
            }
            _ => Err(Error::UnknownRecordType(record_type)),
        }
    }
}

fn header(record_type: u8, field: u8) -> Vec<u8> {
    vec![VERSION, record_type, field, 0]
}

fn encode_token_record(
    record_type: u8,
    generation: u64,
    token: &[u8; PATH_TOKEN_BYTES],
) -> Result<Vec<u8>, Error> {
    validate_generation_and_token(generation, token)?;
    let mut out = header(record_type, 0);
    append_generation_and_token(&mut out, generation, token);
    Ok(out)
}

fn append_generation_and_token(out: &mut Vec<u8>, generation: u64, token: &[u8; PATH_TOKEN_BYTES]) {
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(token);
}

fn decode_token_record(
    bytes: &[u8],
    field: u8,
    expected_type: u8,
    build: impl FnOnce(u64, [u8; PATH_TOKEN_BYTES]) -> PathControl,
) -> Result<PathControl, Error> {
    debug_assert_eq!(bytes[1], expected_type);
    require_exact(bytes, TOKEN_RECORD_LEN)?;
    require_zero_field(field)?;
    let (generation, token) = decode_generation_and_token(bytes)?;
    Ok(build(generation, token))
}

fn decode_generation_and_token(bytes: &[u8]) -> Result<(u64, [u8; PATH_TOKEN_BYTES]), Error> {
    let generation = decode_generation(bytes)?;
    let token: [u8; PATH_TOKEN_BYTES] = bytes[12..28].try_into().expect("length checked");
    if token.iter().all(|byte| *byte == 0) {
        return Err(Error::ZeroToken);
    }
    Ok((generation, token))
}

fn decode_generation(bytes: &[u8]) -> Result<u64, Error> {
    let generation = u64::from_be_bytes(bytes[4..12].try_into().expect("length checked"));
    if generation == 0 {
        return Err(Error::ZeroGeneration);
    }
    Ok(generation)
}

fn require_at_least(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() < expected {
        return Err(Error::Truncated {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn require_exact(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() < expected {
        return Err(Error::Truncated {
            expected,
            actual: bytes.len(),
        });
    }
    if bytes.len() != expected {
        return Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn require_zero_field(field: u8) -> Result<(), Error> {
    if field != 0 {
        return Err(Error::ReservedBits(field));
    }
    Ok(())
}

fn validate_generation_and_token(
    generation: u64,
    token: &[u8; PATH_TOKEN_BYTES],
) -> Result<(), Error> {
    if generation == 0 {
        return Err(Error::ZeroGeneration);
    }
    if token.iter().all(|byte| *byte == 0) {
        return Err(Error::ZeroToken);
    }
    Ok(())
}

const fn path_kind_code(kind: PathKind) -> u8 {
    match kind {
        PathKind::DirectUdp => 1,
        PathKind::OpaqueRelay => 2,
        PathKind::Ice => 3,
    }
}

fn decode_path_kind(kind: u8) -> Result<PathKind, Error> {
    match kind {
        1 => Ok(PathKind::DirectUdp),
        2 => Ok(PathKind::OpaqueRelay),
        3 => Ok(PathKind::Ice),
        _ => Err(Error::InvalidPathKind(kind)),
    }
}

const fn abort_reason_code(reason: AbortReason) -> u8 {
    match reason {
        AbortReason::Unsupported => 1,
        AbortReason::Timeout => 2,
        AbortReason::CandidateUnavailable => 3,
        AbortReason::ProbeFailed => 4,
        AbortReason::PmtuUnavailable => 5,
        AbortReason::ResourceLimit => 6,
        AbortReason::CommitUnconfirmed => 7,
    }
}

fn decode_abort_reason(reason: u8) -> Result<AbortReason, Error> {
    match reason {
        1 => Ok(AbortReason::Unsupported),
        2 => Ok(AbortReason::Timeout),
        3 => Ok(AbortReason::CandidateUnavailable),
        4 => Ok(AbortReason::ProbeFailed),
        5 => Ok(AbortReason::PmtuUnavailable),
        6 => Ok(AbortReason::ResourceLimit),
        7 => Ok(AbortReason::CommitUnconfirmed),
        _ => Err(Error::InvalidAbortReason(reason)),
    }
}
