//! Bounded media packetization shared by host and client adapters.
//!
//! Video frames are commonly larger than a safe UDP datagram. This crate
//! keeps fragmentation/reassembly independent from capture, codec, and socket
//! implementations. Fragments may arrive out of order, duplicates are
//! ignored, incomplete frames are bounded, and a completed frame is returned
//! only once all fragments are present.

use std::collections::{BTreeMap, HashMap, VecDeque};

pub mod clipboard;
pub mod displays;
pub mod input;
pub mod metrics;

use openstream_protocol::MAX_PLAINTEXT;

pub mod adaptive;

pub use adaptive::{AdaptiveBitrate, BitrateDecision, BitrateReason};

const MAGIC: [u8; 2] = *b"VF";
const VERSION: u8 = 1;
const KEYFRAME: u8 = 1;
const MAX_FRAGMENTS_PER_FRAME: usize = 8192;

/// Bytes used by each cleartext fragment header inside an encrypted packet.
pub const FRAGMENT_HEADER_LEN: usize = 20;
/// Maximum encoded bytes carried by one fragment.
pub const MAX_FRAGMENT_BYTES: usize = MAX_PLAINTEXT - FRAGMENT_HEADER_LEN;
/// Control payload sent when a receiver detects a missing dependent frame.
pub const KEYFRAME_REQUEST: &[u8] = b"openstream/keyframe-request";
/// Bytes used by the audio frame header inside an encrypted packet.
pub const AUDIO_HEADER_LEN: usize = 16;
/// A conservative bound for one Opus access unit.
pub const MAX_AUDIO_BYTES: usize = MAX_PLAINTEXT - AUDIO_HEADER_LEN;
const FRAME_ACK_MAGIC: [u8; 2] = *b"FA";
const FRAME_ACK_VERSION: u8 = 1;
/// Fixed-size reliable acknowledgement for one assembled video frame.
pub const FRAME_ACK_LEN: usize = 12;

/// A client acknowledgement for a complete, decodable video frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAck {
    pub frame_id: u32,
    /// Number of frame IDs the client assembler observed missing before this
    /// frame. This keeps skipped redundant ACKs from looking like loss.
    pub lost_frames: u16,
}

impl FrameAck {
    /// Encode the acknowledgement for the reliable control channel.
    pub fn encode(self) -> [u8; FRAME_ACK_LEN] {
        let mut out = [0_u8; FRAME_ACK_LEN];
        out[0..2].copy_from_slice(&FRAME_ACK_MAGIC);
        out[2] = FRAME_ACK_VERSION;
        out[4..8].copy_from_slice(&self.frame_id.to_be_bytes());
        out[8..10].copy_from_slice(&self.lost_frames.to_be_bytes());
        out
    }

    /// Decode an acknowledgement after outer transport authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameAckError> {
        if bytes.len() != FRAME_ACK_LEN {
            return Err(FrameAckError::BadLength);
        }
        if bytes[..2] != FRAME_ACK_MAGIC {
            return Err(FrameAckError::BadMagic);
        }
        if bytes[2] != FRAME_ACK_VERSION {
            return Err(FrameAckError::UnsupportedVersion(bytes[2]));
        }
        if bytes[3] != 0 || bytes[10..12] != [0, 0] {
            return Err(FrameAckError::ReservedBits);
        }
        Ok(Self {
            frame_id: u32::from_be_bytes(bytes[4..8].try_into().expect("ack header checked")),
            lost_frames: u16::from_be_bytes(bytes[8..10].try_into().expect("ack header checked")),
        })
    }
}

/// Frame acknowledgement framing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAckError {
    BadLength,
    BadMagic,
    UnsupportedVersion(u8),
    ReservedBits,
}

impl std::fmt::Display for FrameAckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => f.write_str("frame acknowledgement length is not 12 bytes"),
            Self::BadMagic => f.write_str("frame acknowledgement magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported frame acknowledgement version {version}")
            }
            Self::ReservedBits => f.write_str("frame acknowledgement reserved bits are not zero"),
        }
    }
}

impl std::error::Error for FrameAckError {}

/// A decoded encoded-video fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub frame_id: u32,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub presentation_time_us: u64,
    pub keyframe: bool,
    pub payload: Vec<u8>,
}

/// A completed encoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    pub frame_id: u32,
    pub presentation_time_us: u64,
    pub keyframe: bool,
    pub payload: Vec<u8>,
}

/// Packetization/reassembly failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ShortFragment,
    BadMagic,
    UnsupportedVersion(u8),
    InvalidFlags(u8),
    ZeroFragments,
    FragmentIndexOutOfRange,
    BadLength,
    TooLarge,
    TooManyInflight,
    MetadataMismatch,
    ShortAudioFrame,
    BadAudioMagic,
    UnsupportedAudioVersion(u8),
    InvalidAudioFlags(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ShortFragment => f.write_str("video fragment is shorter than its header"),
            Self::BadMagic => f.write_str("video fragment magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported video fragment version {version}")
            }
            Self::InvalidFlags(flags) => write!(f, "unsupported video fragment flags {flags:#x}"),
            Self::ZeroFragments => f.write_str("video fragment count cannot be zero"),
            Self::FragmentIndexOutOfRange => f.write_str("video fragment index is out of range"),
            Self::BadLength => f.write_str("video fragment length is invalid"),
            Self::TooLarge => f.write_str("video frame exceeds the reassembly limit"),
            Self::TooManyInflight => f.write_str("video reassembly table is full"),
            Self::MetadataMismatch => f.write_str("video fragments disagree about frame metadata"),
            Self::ShortAudioFrame => f.write_str("audio frame is shorter than its header"),
            Self::BadAudioMagic => f.write_str("audio frame magic is invalid"),
            Self::UnsupportedAudioVersion(version) => {
                write!(f, "unsupported audio frame version {version}")
            }
            Self::InvalidAudioFlags(flags) => {
                write!(f, "unsupported audio frame flags {flags:#x}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Fragment {
    /// Encode a fragment header and payload for an encrypted protocol packet.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.fragment_count == 0 {
            return Err(Error::ZeroFragments);
        }
        if self.fragment_index >= self.fragment_count {
            return Err(Error::FragmentIndexOutOfRange);
        }
        if self.payload.len() > MAX_FRAGMENT_BYTES {
            return Err(Error::TooLarge);
        }
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(if self.keyframe { KEYFRAME } else { 0 });
        out.extend_from_slice(&self.frame_id.to_be_bytes());
        out.extend_from_slice(&self.fragment_index.to_be_bytes());
        out.extend_from_slice(&self.fragment_count.to_be_bytes());
        out.extend_from_slice(&self.presentation_time_us.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decode a fragment after it has been opened by the encrypted transport.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < FRAGMENT_HEADER_LEN {
            return Err(Error::ShortFragment);
        }
        if bytes[..2] != MAGIC {
            return Err(Error::BadMagic);
        }
        if bytes[2] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[2]));
        }
        if bytes[3] & !KEYFRAME != 0 {
            return Err(Error::InvalidFlags(bytes[3]));
        }
        let frame_id = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let fragment_index = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        let fragment_count = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        if fragment_count == 0 {
            return Err(Error::ZeroFragments);
        }
        if fragment_index >= fragment_count {
            return Err(Error::FragmentIndexOutOfRange);
        }
        if bytes.len() > FRAGMENT_HEADER_LEN + MAX_FRAGMENT_BYTES {
            return Err(Error::BadLength);
        }
        Ok(Self {
            frame_id,
            fragment_index,
            fragment_count,
            presentation_time_us: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
            keyframe: bytes[3] & KEYFRAME != 0,
            payload: bytes[FRAGMENT_HEADER_LEN..].to_vec(),
        })
    }
}

/// Split one encoded frame into bounded video fragments.
pub fn fragment_frame(
    frame_id: u32,
    presentation_time_us: u64,
    keyframe: bool,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, Error> {
    if payload.is_empty() {
        return Err(Error::BadLength);
    }
    let count = payload.len().div_ceil(MAX_FRAGMENT_BYTES);
    let fragment_count = u16::try_from(count).map_err(|_| Error::TooLarge)?;
    payload
        .chunks(MAX_FRAGMENT_BYTES)
        .enumerate()
        .map(|(index, part)| {
            Fragment {
                frame_id,
                fragment_index: u16::try_from(index).map_err(|_| Error::TooLarge)?,
                fragment_count,
                presentation_time_us,
                keyframe,
                payload: part.to_vec(),
            }
            .encode()
        })
        .collect()
}

/// One encoded audio access unit. The initial profile expects Opus at 48 kHz;
/// the framing is codec-neutral so negotiation can reject unsupported codecs
/// before a decoder sees a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    pub sequence: u32,
    pub presentation_time_us: u64,
    pub payload: Vec<u8>,
}

impl AudioFrame {
    /// Encode an audio frame for an encrypted `Kind::Audio` packet.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.payload.len() > MAX_AUDIO_BYTES {
            return Err(Error::TooLarge);
        }
        let mut out = Vec::with_capacity(AUDIO_HEADER_LEN + self.payload.len());
        out.extend_from_slice(b"AF");
        out.push(1);
        out.push(0);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.presentation_time_us.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decode an audio frame after authenticated transport has opened it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < AUDIO_HEADER_LEN {
            return Err(Error::ShortAudioFrame);
        }
        if bytes[..2] != *b"AF" {
            return Err(Error::BadAudioMagic);
        }
        if bytes[2] != 1 {
            return Err(Error::UnsupportedAudioVersion(bytes[2]));
        }
        if bytes[3] != 0 {
            return Err(Error::InvalidAudioFlags(bytes[3]));
        }
        if bytes.len() > AUDIO_HEADER_LEN + MAX_AUDIO_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            sequence: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            presentation_time_us: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            payload: bytes[AUDIO_HEADER_LEN..].to_vec(),
        })
    }
}

/// Output from a bounded audio jitter queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioEvent {
    Frame(AudioFrame),
    Missing(u32),
}

/// Small sequence-aware audio queue.
///
/// `poll` emits a missing sequence only after `max_depth` later frames have
/// accumulated. The caller can then ask the Opus decoder for packet-loss
/// concealment. No wall-clock is used here: the platform audio callback owns
/// the sample clock, which avoids mixing monotonic clocks from different OS
/// runtimes into the protocol crate.
#[derive(Debug)]
pub struct JitterBuffer {
    max_depth: usize,
    expected: Option<u32>,
    frames: BTreeMap<u32, AudioFrame>,
}

impl JitterBuffer {
    /// Create a queue with a fixed packet bound.
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth: max_depth.max(1),
            expected: None,
            frames: BTreeMap::new(),
        }
    }

    /// Insert an encoded frame, ignoring duplicates and late packets.
    pub fn push(&mut self, frame: AudioFrame) {
        if self
            .expected
            .is_some_and(|expected| sequence_before(frame.sequence, expected))
        {
            return;
        }
        self.expected.get_or_insert(frame.sequence);
        self.frames.entry(frame.sequence).or_insert(frame);
        while self.frames.len() > self.max_depth {
            let Some(expected) = self.expected else {
                break;
            };
            let Some(sequence) = self
                .frames
                .keys()
                .copied()
                .max_by_key(|sequence| expected.wrapping_sub(*sequence))
            else {
                break;
            };
            self.frames.remove(&sequence);
        }
    }

    /// Emit the next frame or, once the queue is deep enough, one concealment
    /// marker for a missing sequence.
    pub fn poll(&mut self) -> Option<AudioEvent> {
        let expected = self.expected?;
        if let Some(frame) = self.frames.remove(&expected) {
            self.expected = Some(expected.wrapping_add(1));
            return Some(AudioEvent::Frame(frame));
        }
        if self.frames.len() < self.max_depth {
            return None;
        }
        self.expected = Some(expected.wrapping_add(1));
        Some(AudioEvent::Missing(expected))
    }

    /// Drop queued samples and wait for the next received sequence.
    pub fn clear(&mut self) {
        self.expected = None;
        self.frames.clear();
    }

    /// Number of encoded frames retained.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the queue contains no encoded frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// Serial-number comparison from RFC 1982, valid for a receive window below
/// half the u32 sequence space. This keeps audio ordering correct when a long
/// running stream crosses `u32::MAX`.
fn sequence_before(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

#[derive(Debug)]
struct InProgress {
    presentation_time_us: u64,
    keyframe: bool,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    order: u64,
}

/// Bounded out-of-order video reassembler.
#[derive(Debug)]
pub struct Assembler {
    max_frame_bytes: usize,
    max_inflight: usize,
    order: u64,
    frames: HashMap<u32, InProgress>,
    completed: VecDeque<u32>,
    ready: HashMap<u32, EncodedFrame>,
    next_ready: Option<u32>,
    last_frame_id: Option<u32>,
    keyframe_request: bool,
    gap_frames: u16,
}

impl Assembler {
    /// Create a reassembler with explicit memory and concurrency limits.
    pub fn new(max_frame_bytes: usize, max_inflight: usize) -> Self {
        Self {
            max_frame_bytes,
            max_inflight: max_inflight.max(1),
            order: 0,
            frames: HashMap::new(),
            completed: VecDeque::new(),
            ready: HashMap::new(),
            next_ready: None,
            last_frame_id: None,
            keyframe_request: false,
            gap_frames: 0,
        }
    }

    /// Add one fragment. A complete frame is returned exactly once.
    pub fn push(&mut self, fragment: Fragment) -> Result<Option<EncodedFrame>, Error> {
        let count = usize::from(fragment.fragment_count);
        if count == 0 || usize::from(fragment.fragment_index) >= count {
            return Err(Error::FragmentIndexOutOfRange);
        }
        // Do not multiply the count by the maximum chunk size here: the last
        // fragment may be small, and callers may choose a smaller chunk size.
        // The slot bound prevents a forged count from allocating an
        // unbounded `Vec<Option<Vec<u8>>>`; the byte bound is enforced as
        // actual payloads arrive below.
        if count > MAX_FRAGMENTS_PER_FRAME {
            return Err(Error::TooLarge);
        }
        // A retransmission may have a new encrypted packet counter while
        // referring to the same logical frame. Retain a bounded completion
        // history so it cannot be emitted twice after the first assembly.
        if self.completed.contains(&fragment.frame_id) {
            return Ok(None);
        }
        if !self.frames.contains_key(&fragment.frame_id) {
            self.evict_if_needed();
            self.order = self.order.wrapping_add(1);
            self.frames.insert(
                fragment.frame_id,
                InProgress {
                    presentation_time_us: fragment.presentation_time_us,
                    keyframe: fragment.keyframe,
                    parts: vec![None; count],
                    bytes: 0,
                    order: self.order,
                },
            );
        }
        let frame = self
            .frames
            .get_mut(&fragment.frame_id)
            .ok_or(Error::TooManyInflight)?;
        if frame.parts.len() != count
            || frame.presentation_time_us != fragment.presentation_time_us
            || frame.keyframe != fragment.keyframe
        {
            self.frames.remove(&fragment.frame_id);
            return Err(Error::MetadataMismatch);
        }
        let slot = &mut frame.parts[usize::from(fragment.fragment_index)];
        if slot.is_some() {
            return Ok(None);
        }
        frame.bytes = frame.bytes.saturating_add(fragment.payload.len());
        if frame.bytes > self.max_frame_bytes {
            self.frames.remove(&fragment.frame_id);
            return Err(Error::TooLarge);
        }
        *slot = Some(fragment.payload);
        if frame.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let frame = self
            .frames
            .remove(&fragment.frame_id)
            .ok_or(Error::TooManyInflight)?;
        let mut payload = Vec::with_capacity(frame.bytes);
        for part in frame.parts {
            payload.extend(part.ok_or(Error::BadLength)?);
        }
        self.completed.push_back(fragment.frame_id);
        while self.completed.len() > self.max_inflight.saturating_mul(16) {
            self.completed.pop_front();
        }
        let encoded = EncodedFrame {
            frame_id: fragment.frame_id,
            presentation_time_us: frame.presentation_time_us,
            keyframe: frame.keyframe,
            payload,
        };
        // Once a newer frame has been selected as the next presentation point,
        // a completion from before it can never become decodable in order. Do
        // not retain such late frames in the reorder map until its eviction
        // limit happens to run; a delayed attacker could otherwise keep the
        // queue occupied indefinitely.
        if self
            .next_ready
            .is_some_and(|next| sequence_before(fragment.frame_id, next))
        {
            return Ok(None);
        }
        self.next_ready.get_or_insert(fragment.frame_id);
        self.ready.entry(fragment.frame_id).or_insert(encoded);
        self.evict_ready_if_needed();
        Ok(self.pop_ready())
    }

    /// Pop the next frame in presentation order. If a bounded reorder window
    /// fills while the expected frame is absent, the oldest missing IDs are
    /// declared lost and the next available frame is released. This gives
    /// out-of-order delivery a chance to settle without allowing a single
    /// lost frame to stall the decoder forever.
    pub fn pop_ready(&mut self) -> Option<EncodedFrame> {
        let expected = self.next_ready?;
        if !self.ready.contains_key(&expected) {
            if self.ready.len() < self.max_inflight.max(2) {
                return None;
            }
            let next = self
                .ready
                .keys()
                .copied()
                .filter(|id| !sequence_before(*id, expected))
                .min_by_key(|id| id.wrapping_sub(expected))?;
            let gap = next.wrapping_sub(expected);
            self.gap_frames = self
                .gap_frames
                .saturating_add(u16::try_from(gap).unwrap_or(u16::MAX));
            self.next_ready = Some(next);
        }
        let frame = self.ready.remove(&self.next_ready?)?;
        self.accept_ordered_frame(&frame);
        self.next_ready = Some(frame.frame_id.wrapping_add(1));
        Some(frame)
    }

    fn accept_ordered_frame(&mut self, frame: &EncodedFrame) {
        let discontinuity = match self.last_frame_id {
            Some(previous) => frame.frame_id != previous.wrapping_add(1),
            None => !frame.keyframe,
        };
        if discontinuity && !frame.keyframe {
            self.keyframe_request = true;
        }
        if frame.keyframe {
            // A keyframe restores decoder state only if it is not older than
            // the last emitted frame. Older late keyframes must not clear a
            // recovery request raised by a newer discontinuity.
            if self
                .last_frame_id
                .is_none_or(|last| !sequence_before(frame.frame_id, last))
            {
                self.keyframe_request = false;
            }
        }
        self.last_frame_id = Some(frame.frame_id);
    }

    /// Drop all incomplete frames, normally after a decoder reset/keyframe request.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.completed.clear();
        self.ready.clear();
        self.next_ready = None;
        self.last_frame_id = None;
        self.keyframe_request = false;
        self.gap_frames = 0;
    }

    /// Return and clear the request raised by a missing dependent frame.
    pub fn take_keyframe_request(&mut self) -> bool {
        core::mem::take(&mut self.keyframe_request)
    }

    /// Return and clear the count of frame IDs missing before the last
    /// completed frame. The count is explicit in `FrameAck`, so a skipped
    /// redundant ACK is not inferred as media loss by the host.
    pub fn take_frame_gap(&mut self) -> u16 {
        core::mem::take(&mut self.gap_frames)
    }

    /// Number of incomplete frames currently retained.
    pub fn inflight(&self) -> usize {
        self.frames.len()
    }

    fn evict_if_needed(&mut self) {
        while self.frames.len() >= self.max_inflight {
            let Some(oldest) = self
                .frames
                .iter()
                .min_by_key(|(_, frame)| frame.order)
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.frames.remove(&oldest);
        }
    }

    fn evict_ready_if_needed(&mut self) {
        let limit = self.max_inflight.saturating_mul(4).max(2);
        while self.ready.len() > limit {
            let Some(expected) = self.next_ready else {
                break;
            };
            let Some(farthest) = self
                .ready
                .keys()
                .copied()
                .max_by_key(|id| id.wrapping_sub(expected))
            else {
                break;
            };
            self.ready.remove(&farthest);
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new(8 * 1024 * 1024, 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_round_trip_in_reverse_order() {
        let source = vec![0x37; MAX_FRAGMENT_BYTES * 2 + 11];
        let encoded = fragment_frame(7, 1234, true, &source).expect("fragment");
        let mut assembler = Assembler::new(source.len(), 4);
        let mut complete = None;
        for bytes in encoded.into_iter().rev() {
            complete = assembler
                .push(Fragment::decode(&bytes).expect("decode"))
                .expect("assemble");
        }
        let frame = complete.expect("complete frame");
        assert_eq!(frame.frame_id, 7);
        assert!(frame.keyframe);
        assert_eq!(frame.payload, source);
        assert_eq!(assembler.inflight(), 0);
    }

    #[test]
    fn duplicate_fragments_do_not_duplicate_output() {
        let encoded =
            fragment_frame(1, 0, false, &[0x11; MAX_FRAGMENT_BYTES + 1]).expect("fragment");
        let fragment = Fragment::decode(&encoded[0]).expect("decode");
        let mut assembler = Assembler::new(4096, 2);
        assert_eq!(assembler.push(fragment.clone()).expect("first"), None);
        assert_eq!(assembler.push(fragment).expect("duplicate"), None);
        assert_eq!(
            assembler
                .push(Fragment::decode(&encoded[1]).expect("decode"))
                .expect("complete")
                .expect("frame"),
            EncodedFrame {
                frame_id: 1,
                presentation_time_us: 0,
                keyframe: false,
                payload: vec![0x11; MAX_FRAGMENT_BYTES + 1],
            }
        );
        assert_eq!(assembler.inflight(), 0);
        let duplicate = Fragment::decode(&encoded[0]).expect("decode duplicate");
        assert_eq!(assembler.push(duplicate).expect("late duplicate"), None);
    }

    #[test]
    fn incomplete_frames_are_evicted_at_the_bound() {
        let mut assembler = Assembler::new(1024, 2);
        for id in 0..3 {
            let bytes = fragment_frame(id, 0, false, b"frame").expect("fragment");
            let mut fragment = Fragment::decode(&bytes[0]).expect("decode");
            fragment.fragment_count = 2;
            assembler.push(fragment).expect("store");
        }
        assert_eq!(assembler.inflight(), 2);
    }

    #[test]
    fn a_completed_frame_gap_requests_a_keyframe_once() {
        let mut assembler = Assembler::new(4096, 4);
        let first = fragment_frame(10, 0, true, b"first").expect("fragment");
        assert!(
            assembler
                .push(Fragment::decode(&first[0]).expect("decode"))
                .expect("assemble")
                .is_some()
        );
        assert!(!assembler.take_keyframe_request());

        // A complete later frame is held briefly so an out-of-order frame 11
        // can still arrive. Once the bounded reorder window fills, frame 11
        // is declared lost and frame 12 is released in order.
        for id in 12..=15 {
            let later = fragment_frame(id, u64::from(id), false, b"later").expect("fragment");
            let _ = assembler
                .push(Fragment::decode(&later[0]).expect("decode"))
                .expect("assemble");
        }
        assert!(assembler.take_keyframe_request());
        assert_eq!(assembler.take_frame_gap(), 1);
        assert!(!assembler.take_keyframe_request());

        while assembler.pop_ready().is_some() {}
        let recovery = fragment_frame(16, 2, true, b"key").expect("fragment");
        assembler
            .push(Fragment::decode(&recovery[0]).expect("decode"))
            .expect("assemble");
        assert!(!assembler.take_keyframe_request());
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let mut assembler = Assembler::new(MAX_FRAGMENT_BYTES, 1);
        let bytes = fragment_frame(1, 0, false, &[0_u8; MAX_FRAGMENT_BYTES + 1]).expect("fragment");
        assert_eq!(
            assembler.push(Fragment::decode(&bytes[0]).expect("decode")),
            Ok(None)
        );
        assert_eq!(
            assembler.push(Fragment::decode(&bytes[1]).expect("decode")),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn invalid_flags_and_indices_are_rejected() {
        let mut bytes = fragment_frame(1, 0, false, b"x").expect("fragment")[0].clone();
        bytes[3] = 0x80;
        assert_eq!(Fragment::decode(&bytes), Err(Error::InvalidFlags(0x80)));
        bytes[3] = 0;
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            Fragment::decode(&bytes),
            Err(Error::FragmentIndexOutOfRange)
        );
    }

    #[test]
    fn audio_frame_round_trips_and_jitter_buffer_conceals_one_gap() {
        let frame = AudioFrame {
            sequence: 7,
            presentation_time_us: 20_000,
            payload: vec![0x42; 37],
        };
        let bytes = frame.encode().expect("encode audio");
        assert_eq!(AudioFrame::decode(&bytes).expect("decode audio"), frame);

        let mut jitter = JitterBuffer::new(2);
        jitter.push(AudioFrame {
            sequence: 10,
            presentation_time_us: 0,
            payload: vec![1],
        });
        jitter.push(AudioFrame {
            sequence: 12,
            presentation_time_us: 40_000,
            payload: vec![3],
        });
        assert_eq!(
            jitter.poll(),
            Some(AudioEvent::Frame(AudioFrame {
                sequence: 10,
                presentation_time_us: 0,
                payload: vec![1]
            }))
        );
        assert_eq!(jitter.poll(), None);
        jitter.push(AudioFrame {
            sequence: 13,
            presentation_time_us: 60_000,
            payload: vec![4],
        });
        assert_eq!(jitter.poll(), Some(AudioEvent::Missing(11)));
        assert_eq!(
            jitter.poll(),
            Some(AudioEvent::Frame(AudioFrame {
                sequence: 12,
                presentation_time_us: 40_000,
                payload: vec![3]
            }))
        );
    }

    #[test]
    fn audio_flags_and_size_are_bounded() {
        let mut bytes = AudioFrame {
            sequence: 1,
            presentation_time_us: 0,
            payload: vec![0],
        }
        .encode()
        .expect("encode audio");
        bytes[3] = 1;
        assert_eq!(AudioFrame::decode(&bytes), Err(Error::InvalidAudioFlags(1)));
        assert_eq!(
            AudioFrame {
                sequence: 1,
                presentation_time_us: 0,
                payload: vec![0; MAX_AUDIO_BYTES + 1],
            }
            .encode(),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn frame_ack_round_trips_and_rejects_reserved_bits() {
        let ack = FrameAck {
            frame_id: 0x1020_3040,
            lost_frames: 3,
        };
        let bytes = ack.encode();
        assert_eq!(FrameAck::decode(&bytes), Ok(ack));
        let mut invalid = bytes;
        invalid[3] = 1;
        assert_eq!(FrameAck::decode(&invalid), Err(FrameAckError::ReservedBits));
    }
}
