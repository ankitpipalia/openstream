//! Bounded clipboard text transfer over the reliable control channel.
//!
//! Clipboard contents are control data, not media. They therefore use the
//! ordered authenticated control channel and are split into small chunks
//! before transmission. Only UTF-8 text and an explicit clear operation are
//! defined in v1; platform adapters decide whether clipboard synchronization
//! is permitted. No host clipboard is touched by this module.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use openstream_protocol::control::MAX_PAYLOAD;

const MAGIC: [u8; 2] = *b"CB";
const VERSION: u8 = 1;
const TEXT: u8 = 1;
const CLEAR: u8 = 2;
const HEADER_LEN: usize = 16;
const MAX_TRANSFERS: usize = 4;
const MAX_TRANSFER_AGE: Duration = Duration::from_secs(10);

/// Maximum clipboard text size accepted for one transfer.
pub const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;
/// Maximum encoded clipboard chunk size, including its fixed header.
pub const MAX_CLIPBOARD_CHUNK: usize = MAX_PAYLOAD;
const MAX_CHUNK_BYTES: usize = MAX_CLIPBOARD_CHUNK - HEADER_LEN;

/// Clipboard operation encoded in a control chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClipboardKind {
    Text = TEXT,
    Clear = CLEAR,
}

impl TryFrom<u8> for ClipboardKind {
    type Error = ClipboardError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TEXT => Ok(Self::Text),
            CLEAR => Ok(Self::Clear),
            _ => Err(ClipboardError::UnknownKind(value)),
        }
    }
}

/// One authenticated, reliable clipboard chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardChunk {
    pub transfer_id: u32,
    pub kind: ClipboardKind,
    pub chunk_index: u16,
    pub chunk_count: u16,
    pub total_bytes: u32,
    pub payload: Vec<u8>,
}

impl ClipboardChunk {
    /// Encode a chunk. The returned bytes are intended for `Kind::Control`.
    pub fn encode(&self) -> Result<Vec<u8>, ClipboardError> {
        validate_metadata(
            self.transfer_id,
            self.kind,
            self.chunk_index,
            self.chunk_count,
            self.total_bytes,
        )?;
        if self.payload.len() > MAX_CHUNK_BYTES {
            return Err(ClipboardError::ChunkTooLarge);
        }
        if self.kind == ClipboardKind::Clear && (!self.payload.is_empty() || self.total_bytes != 0)
        {
            return Err(ClipboardError::ClearHasPayload);
        }
        if self.kind == ClipboardKind::Text
            && usize::try_from(self.total_bytes).map_err(|_| ClipboardError::TotalTooLarge)?
                > MAX_CLIPBOARD_BYTES
        {
            return Err(ClipboardError::TotalTooLarge);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.transfer_id.to_be_bytes());
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.total_bytes.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decode a chunk after the outer authenticated control frame is opened.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClipboardError> {
        if bytes.len() < HEADER_LEN {
            return Err(ClipboardError::ShortChunk);
        }
        if bytes[..2] != MAGIC {
            return Err(ClipboardError::BadMagic);
        }
        if bytes[2] != VERSION {
            return Err(ClipboardError::UnsupportedVersion(bytes[2]));
        }
        let kind = ClipboardKind::try_from(bytes[3])?;
        let transfer_id = u32::from_be_bytes(bytes[4..8].try_into().expect("header checked"));
        let chunk_index = u16::from_be_bytes(bytes[8..10].try_into().expect("header checked"));
        let chunk_count = u16::from_be_bytes(bytes[10..12].try_into().expect("header checked"));
        let total_bytes = u32::from_be_bytes(bytes[12..16].try_into().expect("header checked"));
        let chunk = Self {
            transfer_id,
            kind,
            chunk_index,
            chunk_count,
            total_bytes,
            payload: bytes[HEADER_LEN..].to_vec(),
        };
        chunk.encode()?;
        Ok(chunk)
    }
}

/// Clipboard framing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    ShortChunk,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    ZeroChunks,
    ChunkIndexOutOfRange,
    ChunkTooLarge,
    TotalTooLarge,
    TotalDoesNotMatch,
    ClearHasPayload,
    MetadataMismatch,
    Incomplete,
    InvalidUtf8,
}

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortChunk => f.write_str("clipboard chunk is shorter than its header"),
            Self::BadMagic => f.write_str("clipboard chunk magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported clipboard version {version}")
            }
            Self::UnknownKind(kind) => write!(f, "unknown clipboard kind {kind}"),
            Self::ZeroChunks => f.write_str("clipboard chunk count cannot be zero"),
            Self::ChunkIndexOutOfRange => f.write_str("clipboard chunk index is out of range"),
            Self::ChunkTooLarge => {
                f.write_str("clipboard chunk exceeds the control datagram limit")
            }
            Self::TotalTooLarge => f.write_str("clipboard transfer exceeds the size limit"),
            Self::TotalDoesNotMatch => f.write_str("clipboard transfer metadata does not match"),
            Self::ClearHasPayload => f.write_str("clipboard clear operation has a payload"),
            Self::MetadataMismatch => f.write_str("clipboard chunks disagree about metadata"),
            Self::Incomplete => f.write_str("clipboard transfer is incomplete"),
            Self::InvalidUtf8 => f.write_str("clipboard text is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ClipboardError {}

fn validate_metadata(
    _transfer_id: u32,
    kind: ClipboardKind,
    chunk_index: u16,
    chunk_count: u16,
    total_bytes: u32,
) -> Result<(), ClipboardError> {
    if chunk_count == 0 {
        return Err(ClipboardError::ZeroChunks);
    }
    if chunk_index >= chunk_count {
        return Err(ClipboardError::ChunkIndexOutOfRange);
    }
    let total = usize::try_from(total_bytes).map_err(|_| ClipboardError::TotalTooLarge)?;
    if total > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::TotalTooLarge);
    }
    if kind == ClipboardKind::Clear && total != 0 {
        return Err(ClipboardError::ClearHasPayload);
    }
    let expected = if total == 0 {
        1
    } else {
        total.div_ceil(MAX_CHUNK_BYTES)
    };
    if usize::from(chunk_count) != expected {
        return Err(ClipboardError::TotalDoesNotMatch);
    }
    Ok(())
}

/// Split UTF-8 clipboard text into bounded reliable-control chunks.
pub fn fragment_text(transfer_id: u32, text: &str) -> Result<Vec<Vec<u8>>, ClipboardError> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::TotalTooLarge);
    }
    let count = if bytes.is_empty() {
        1
    } else {
        bytes.len().div_ceil(MAX_CHUNK_BYTES)
    };
    let count = u16::try_from(count).map_err(|_| ClipboardError::TotalTooLarge)?;
    if bytes.is_empty() {
        return Ok(vec![
            ClipboardChunk {
                transfer_id,
                kind: ClipboardKind::Text,
                chunk_index: 0,
                chunk_count: count,
                total_bytes: 0,
                payload: Vec::new(),
            }
            .encode()?,
        ]);
    }
    bytes
        .chunks(MAX_CHUNK_BYTES)
        .enumerate()
        .map(|(index, payload)| {
            ClipboardChunk {
                transfer_id,
                kind: ClipboardKind::Text,
                chunk_index: u16::try_from(index).map_err(|_| ClipboardError::TotalTooLarge)?,
                chunk_count: count,
                total_bytes: u32::try_from(bytes.len())
                    .map_err(|_| ClipboardError::TotalTooLarge)?,
                payload: payload.to_vec(),
            }
            .encode()
        })
        .collect()
}

/// Encode a clipboard clear operation.
pub fn clear(transfer_id: u32) -> Result<Vec<u8>, ClipboardError> {
    ClipboardChunk {
        transfer_id,
        kind: ClipboardKind::Clear,
        chunk_index: 0,
        chunk_count: 1,
        total_bytes: 0,
        payload: Vec::new(),
    }
    .encode()
}

#[derive(Debug)]
struct Partial {
    kind: ClipboardKind,
    total_bytes: usize,
    chunks: Vec<Option<Vec<u8>>>,
    last_seen: Instant,
}

/// Bounded clipboard transfer assembler.
#[derive(Debug)]
pub struct Assembler {
    transfers: BTreeMap<u32, Partial>,
}

impl Assembler {
    /// Create an assembler limited to four simultaneous transfers.
    pub fn new() -> Self {
        Self {
            transfers: BTreeMap::new(),
        }
    }

    /// Add one chunk. Returns completed text/clear data when the transfer ends.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<CompletedClipboard>, ClipboardError> {
        self.expire_stale();
        let chunk = ClipboardChunk::decode(bytes)?;
        let total_bytes =
            usize::try_from(chunk.total_bytes).map_err(|_| ClipboardError::TotalTooLarge)?;
        if !self.transfers.contains_key(&chunk.transfer_id) {
            self.evict_oldest_if_full();
        }
        let mut metadata_mismatch = false;
        let incomplete = {
            let entry = self
                .transfers
                .entry(chunk.transfer_id)
                .or_insert_with(|| Partial {
                    kind: chunk.kind,
                    total_bytes,
                    chunks: vec![None; usize::from(chunk.chunk_count)],
                    last_seen: Instant::now(),
                });
            entry.last_seen = Instant::now();
            if entry.kind != chunk.kind
                || entry.total_bytes != total_bytes
                || entry.chunks.len() != usize::from(chunk.chunk_count)
            {
                metadata_mismatch = true;
                false
            } else {
                let slot = &mut entry.chunks[usize::from(chunk.chunk_index)];
                if let Some(existing) = slot.as_ref() {
                    if existing != &chunk.payload {
                        metadata_mismatch = true;
                    }
                } else {
                    *slot = Some(chunk.payload);
                }
                entry.chunks.iter().any(Option::is_none)
            }
        };
        if metadata_mismatch {
            self.transfers.remove(&chunk.transfer_id);
            return Err(ClipboardError::MetadataMismatch);
        }
        if incomplete {
            return Ok(None);
        }
        let partial = self
            .transfers
            .remove(&chunk.transfer_id)
            .expect("entry exists");
        let mut payload = Vec::with_capacity(partial.total_bytes);
        for part in partial.chunks {
            payload.extend(part.expect("complete transfer checked"));
        }
        if payload.len() != partial.total_bytes {
            return Err(ClipboardError::TotalDoesNotMatch);
        }
        match partial.kind {
            ClipboardKind::Text => {
                let text = String::from_utf8(payload).map_err(|_| ClipboardError::InvalidUtf8)?;
                Ok(Some(CompletedClipboard::Text(text)))
            }
            ClipboardKind::Clear => Ok(Some(CompletedClipboard::Clear)),
        }
    }

    /// Remove transfers that have not progressed recently. This is also run
    /// at the beginning of `push`, but is public so a quiet connection can be
    /// reaped by its event loop without waiting for another clipboard packet.
    pub fn expire_stale(&mut self) {
        let now = Instant::now();
        self.transfers.retain(|_, partial| {
            now.saturating_duration_since(partial.last_seen) <= MAX_TRANSFER_AGE
        });
    }

    fn evict_oldest_if_full(&mut self) {
        if self.transfers.len() < MAX_TRANSFERS {
            return;
        }
        if let Some((oldest, _)) = self
            .transfers
            .iter()
            .min_by_key(|(_, partial)| partial.last_seen)
            .map(|(id, partial)| (*id, partial.last_seen))
        {
            self.transfers.remove(&oldest);
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Completed clipboard operation ready for a platform adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletedClipboard {
    Text(String),
    Clear,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_chunks_round_trip_out_of_order() {
        let text = "hello ".repeat(400);
        let mut chunks = fragment_text(7, &text).expect("fragment text");
        assert!(chunks.len() > 1);
        chunks.reverse();
        let mut assembler = Assembler::new();
        let mut completed = None;
        for chunk in chunks {
            completed = assembler
                .push(&chunk)
                .expect("assemble chunk")
                .or(completed);
        }
        assert_eq!(completed, Some(CompletedClipboard::Text(text)));
    }

    #[test]
    fn clear_round_trips_and_malformed_metadata_is_rejected() {
        let clear_chunk = clear(9).expect("clear");
        let mut assembler = Assembler::new();
        assert_eq!(
            assembler.push(&clear_chunk).expect("assemble clear"),
            Some(CompletedClipboard::Clear)
        );
        let invalid = ClipboardChunk {
            transfer_id: 1,
            kind: ClipboardKind::Text,
            chunk_index: 0,
            chunk_count: 2,
            total_bytes: 1,
            payload: vec![b'x'],
        };
        assert_eq!(invalid.encode(), Err(ClipboardError::TotalDoesNotMatch));
    }

    #[test]
    fn conflicting_duplicate_chunk_is_rejected() {
        let mut chunks =
            fragment_text(11, &"z".repeat(MAX_CHUNK_BYTES + 1)).expect("fragment text");
        let first = chunks.remove(0);
        let mut altered = first.clone();
        *altered.last_mut().expect("non-empty payload") ^= 1;
        let mut assembler = Assembler::new();
        assert_eq!(assembler.push(&first).expect("first chunk"), None);
        assert_eq!(
            assembler.push(&altered),
            Err(ClipboardError::MetadataMismatch)
        );
    }

    #[test]
    fn clipboard_is_bounded_before_allocation() {
        assert_eq!(
            fragment_text(1, &"x".repeat(MAX_CLIPBOARD_BYTES + 1)),
            Err(ClipboardError::TotalTooLarge)
        );
        assert_eq!(fragment_text(2, "").expect("empty text").len(), 1);
        let oversized = ClipboardChunk {
            transfer_id: 1,
            kind: ClipboardKind::Text,
            chunk_index: 0,
            chunk_count: 1,
            total_bytes: u32::try_from(MAX_CLIPBOARD_BYTES + 1).expect("test bound fits"),
            payload: vec![b'x'],
        };
        assert_eq!(oversized.encode(), Err(ClipboardError::TotalTooLarge));
    }
}
