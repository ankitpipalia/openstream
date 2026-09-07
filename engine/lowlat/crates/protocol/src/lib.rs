//! OpenStream's project-owned encrypted datagram format.
//!
//! This is intentionally not presented as a BUD implementation. It is the
//! default wire format for the independent service and can be changed through
//! a versioned negotiation. The API keeps framing, authenticated encryption,
//! and media/control classification together so a caller cannot accidentally
//! send unauthenticated control traffic beside encrypted video.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};

/// Ordered control envelope carried inside an authenticated `Kind::Control`
/// datagram. The outer AES-GCM counter still authenticates every packet; this
/// inner sequence lets callers retransmit and deliver control messages in
/// order without coupling media sequencing to transport sequencing.
pub mod control {
    use super::BTreeMap;
    use super::MAX_PLAINTEXT;

    const MAGIC: [u8; 2] = *b"OC";
    const VERSION: u8 = 1;
    const ACK_PRESENT: u8 = 1;
    const ACK_ONLY: u8 = 2;

    /// Bytes used by the ordered control header.
    pub const HEADER_LEN: usize = 12;
    /// Maximum control payload inside one encrypted datagram.
    pub const MAX_PAYLOAD: usize = MAX_PLAINTEXT - HEADER_LEN;

    /// One ordered control message and its cumulative acknowledgement.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Frame {
        pub sequence: u32,
        pub acknowledgement: Option<u32>,
        pub ack_only: bool,
        pub payload: Vec<u8>,
    }

    /// Control framing failures.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        ShortFrame,
        BadMagic,
        UnsupportedVersion(u8),
        InvalidFlags(u8),
        InvalidAcknowledgement,
        EmptyMessage,
        TooLarge,
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::ShortFrame => f.write_str("control frame is shorter than its header"),
                Self::BadMagic => f.write_str("control frame magic is invalid"),
                Self::UnsupportedVersion(version) => {
                    write!(f, "unsupported control version {version}")
                }
                Self::InvalidFlags(flags) => write!(f, "invalid control flags {flags:#x}"),
                Self::InvalidAcknowledgement => {
                    f.write_str("ack-only control frame has no acknowledgement")
                }
                Self::EmptyMessage => f.write_str("ordered control message cannot be empty"),
                Self::TooLarge => f.write_str("ordered control payload is too large"),
            }
        }
    }

    impl std::error::Error for Error {}

    impl Frame {
        /// Encode one control envelope.
        pub fn encode(&self) -> Result<Vec<u8>, Error> {
            if self.ack_only && self.acknowledgement.is_none() {
                return Err(Error::InvalidAcknowledgement);
            }
            if !self.ack_only && self.payload.is_empty() {
                return Err(Error::EmptyMessage);
            }
            if self.payload.len() > MAX_PAYLOAD {
                return Err(Error::TooLarge);
            }
            let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
            out.extend_from_slice(&MAGIC);
            out.push(VERSION);
            let flags = if self.ack_only { ACK_ONLY } else { 0 }
                | if self.acknowledgement.is_some() {
                    ACK_PRESENT
                } else {
                    0
                };
            out.push(flags);
            out.extend_from_slice(&self.sequence.to_be_bytes());
            out.extend_from_slice(&self.acknowledgement.unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&self.payload);
            Ok(out)
        }

        /// Decode one control envelope after outer authentication.
        pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() < HEADER_LEN {
                return Err(Error::ShortFrame);
            }
            if bytes[..2] != MAGIC {
                return Err(Error::BadMagic);
            }
            if bytes[2] != VERSION {
                return Err(Error::UnsupportedVersion(bytes[2]));
            }
            let flags = bytes[3];
            if flags & !(ACK_PRESENT | ACK_ONLY) != 0 {
                return Err(Error::InvalidFlags(flags));
            }
            let ack_only = flags & ACK_ONLY != 0;
            let acknowledgement = (flags & ACK_PRESENT != 0).then(|| {
                u32::from_be_bytes(bytes[8..12].try_into().expect("control header is checked"))
            });
            if ack_only && acknowledgement.is_none() {
                return Err(Error::InvalidAcknowledgement);
            }
            let payload = bytes[HEADER_LEN..].to_vec();
            if ack_only && !payload.is_empty() {
                return Err(Error::InvalidFlags(flags));
            }
            if !ack_only && payload.is_empty() {
                return Err(Error::EmptyMessage);
            }
            if payload.len() > MAX_PAYLOAD {
                return Err(Error::TooLarge);
            }
            Ok(Self {
                sequence: u32::from_be_bytes(
                    bytes[4..8].try_into().expect("control header is checked"),
                ),
                acknowledgement,
                ack_only,
                payload,
            })
        }
    }

    /// Result of passing an ordered frame to a receive side.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Received {
        pub delivered: Vec<Vec<u8>>,
        pub acknowledgement: Option<u32>,
    }

    /// Bounded ordered control state.
    #[derive(Debug)]
    pub struct Channel {
        next_sequence: u32,
        expected_sequence: u32,
        received_any: bool,
        pending_ack: Option<u32>,
        outstanding: BTreeMap<u32, Vec<u8>>,
        waiting: BTreeMap<u32, Vec<u8>>,
        max_pending: usize,
    }

    impl Channel {
        /// Create a channel with a fixed outbound/inbound window.
        pub fn new(max_pending: usize) -> Self {
            Self {
                next_sequence: 0,
                expected_sequence: 0,
                received_any: false,
                pending_ack: None,
                outstanding: BTreeMap::new(),
                waiting: BTreeMap::new(),
                max_pending: max_pending.max(1),
            }
        }

        /// Queue a reliable message, returning its sequence number.
        pub fn queue(&mut self, payload: &[u8]) -> Result<u32, Error> {
            if payload.is_empty() {
                return Err(Error::EmptyMessage);
            }
            if payload.len() > MAX_PAYLOAD || self.outstanding.len() >= self.max_pending {
                return Err(Error::TooLarge);
            }
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            self.outstanding.insert(sequence, payload.to_vec());
            Ok(sequence)
        }

        /// Return the oldest outstanding frame for initial send or retry.
        pub fn next_frame(&self) -> Option<Frame> {
            let (&sequence, payload) = self
                .outstanding
                .iter()
                // The window is bounded far below half the sequence space;
                // distance from the next sequence is therefore an
                // unambiguous age even across u32::MAX -> 0.
                .max_by_key(|(sequence, _)| self.next_sequence.wrapping_sub(**sequence))?;
            Some(Frame {
                sequence,
                acknowledgement: self.pending_ack,
                ack_only: false,
                payload: payload.clone(),
            })
        }

        /// Return an acknowledgement-only frame when there is no data to piggyback.
        pub fn acknowledgement_frame(&self) -> Option<Frame> {
            self.pending_ack.map(|acknowledgement| Frame {
                sequence: 0,
                acknowledgement: Some(acknowledgement),
                ack_only: true,
                payload: Vec::new(),
            })
        }

        /// Mark every outbound sequence through a cumulative acknowledgement delivered.
        pub fn acknowledge(&mut self, acknowledgement: u32) {
            self.outstanding
                .retain(|&sequence, _| !sequence_at_or_before(sequence, acknowledgement));
        }

        /// Receive one frame, returning only newly deliverable messages.
        pub fn receive(&mut self, frame: Frame) -> Received {
            if let Some(acknowledgement) = frame.acknowledgement {
                self.acknowledge(acknowledgement);
            }
            if frame.ack_only {
                return Received {
                    delivered: Vec::new(),
                    acknowledgement: self.pending_ack,
                };
            }
            if sequence_at_or_before(frame.sequence, self.expected_sequence)
                && frame.sequence != self.expected_sequence
            {
                return Received {
                    delivered: Vec::new(),
                    acknowledgement: self.pending_ack,
                };
            }
            if frame.sequence != self.expected_sequence {
                if self.waiting.len() < self.max_pending {
                    self.waiting.entry(frame.sequence).or_insert(frame.payload);
                }
                return Received {
                    delivered: Vec::new(),
                    acknowledgement: self.pending_ack,
                };
            }

            let mut delivered = vec![frame.payload];
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
            while let Some(payload) = self.waiting.remove(&self.expected_sequence) {
                delivered.push(payload);
                self.expected_sequence = self.expected_sequence.wrapping_add(1);
            }
            let acknowledgement = self.expected_sequence.wrapping_sub(1);
            self.received_any = true;
            self.pending_ack = Some(acknowledgement);
            Received {
                delivered,
                acknowledgement: self.pending_ack,
            }
        }

        /// Number of messages awaiting acknowledgement.
        pub fn outstanding(&self) -> usize {
            self.outstanding.len()
        }

        /// Whether another outbound message fits in the bounded window.
        pub fn has_capacity(&self) -> bool {
            self.outstanding.len() < self.max_pending
        }

        /// Number of out-of-order messages retained.
        pub fn waiting(&self) -> usize {
            self.waiting.len()
        }

        /// Whether this channel has received at least one ordered message.
        pub fn received_any(&self) -> bool {
            self.received_any
        }
    }

    fn sequence_at_or_before(sequence: u32, reference: u32) -> bool {
        sequence == reference || reference.wrapping_sub(sequence) < 0x8000_0000
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn frames_round_trip_with_optional_acknowledgement() {
            let frame = Frame {
                sequence: 7,
                acknowledgement: Some(3),
                ack_only: false,
                payload: b"input".to_vec(),
            };
            assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
        }

        #[test]
        fn ordered_channel_buffers_reordering_and_ignores_duplicates() {
            let mut channel = Channel::new(4);
            let first = Frame {
                sequence: 0,
                acknowledgement: None,
                ack_only: false,
                payload: b"a".to_vec(),
            };
            let second = Frame {
                sequence: 1,
                acknowledgement: None,
                ack_only: false,
                payload: b"b".to_vec(),
            };
            assert!(channel.receive(second).delivered.is_empty());
            assert_eq!(channel.waiting(), 1);
            assert_eq!(
                channel.receive(first.clone()).delivered,
                vec![b"a".to_vec(), b"b".to_vec()]
            );
            assert!(channel.receive(first).delivered.is_empty());
            assert_eq!(channel.pending_ack, Some(1));
        }

        #[test]
        fn cumulative_acknowledgement_releases_outbound_window() {
            let mut channel = Channel::new(2);
            channel.queue(b"a").unwrap();
            channel.queue(b"b").unwrap();
            assert_eq!(channel.outstanding(), 2);
            channel.acknowledge(0);
            assert_eq!(channel.outstanding(), 1);
            channel.acknowledge(1);
            assert_eq!(channel.outstanding(), 0);
        }

        #[test]
        fn outbound_capacity_is_explicitly_bounded() {
            let mut channel = Channel::new(1);
            assert!(channel.has_capacity());
            channel.queue(b"one").unwrap();
            assert!(!channel.has_capacity());
            channel.acknowledge(0);
            assert!(channel.has_capacity());
        }
    }
}

/// Small registration envelope used only between an OpenStream peer and the
/// optional self-hosted UDP relay. The relay never receives or decrypts an
/// OpenStream data packet: after registration it forwards opaque datagrams
/// between the validated host and client addresses.
pub mod relay {
    const MAGIC: [u8; 2] = *b"OR";
    const VERSION: u8 = 1;
    const REGISTER: u8 = 1;

    /// Fixed bytes before the variable-length session and token fields.
    pub const HEADER_LEN: usize = 9;
    /// Maximum accepted session identifier length.
    pub const MAX_SESSION_ID: usize = 128;
    /// Maximum accepted role-token length.
    pub const MAX_TOKEN: usize = 256;

    /// The role whose source address is being registered at the relay.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Role {
        Host = 1,
        Client = 2,
    }

    impl Role {
        fn decode(value: u8) -> Result<Self, Error> {
            match value {
                1 => Ok(Self::Host),
                2 => Ok(Self::Client),
                _ => Err(Error::InvalidRole),
            }
        }
    }

    /// Relay registration failures.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Error {
        Short,
        BadMagic,
        UnsupportedVersion,
        InvalidType,
        InvalidRole,
        InvalidLength,
        InvalidUtf8,
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let message = match self {
                Self::Short => "relay registration is too short",
                Self::BadMagic => "relay registration magic is invalid",
                Self::UnsupportedVersion => "relay registration version is unsupported",
                Self::InvalidType => "relay packet type is invalid",
                Self::InvalidRole => "relay role is invalid",
                Self::InvalidLength => "relay registration length is invalid",
                Self::InvalidUtf8 => "relay registration contains invalid UTF-8",
            };
            f.write_str(message)
        }
    }

    impl std::error::Error for Error {}

    /// A validated, borrowed registration packet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Registration<'a> {
        pub role: Role,
        pub session_id: &'a str,
        pub token: &'a str,
    }

    /// Encode a role-token registration for the relay.
    pub fn encode_registration(
        session_id: &str,
        role: Role,
        token: &str,
    ) -> Result<Vec<u8>, Error> {
        let session_id = session_id.as_bytes();
        let token = token.as_bytes();
        if session_id.is_empty()
            || session_id.len() > MAX_SESSION_ID
            || token.is_empty()
            || token.len() > MAX_TOKEN
        {
            return Err(Error::InvalidLength);
        }
        let session_len = u16::try_from(session_id.len()).map_err(|_| Error::InvalidLength)?;
        let token_len = u16::try_from(token.len()).map_err(|_| Error::InvalidLength)?;
        let mut bytes = Vec::with_capacity(HEADER_LEN + session_id.len() + token.len());
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.push(REGISTER);
        bytes.push(role as u8);
        bytes.extend_from_slice(&session_len.to_be_bytes());
        bytes.extend_from_slice(&token_len.to_be_bytes());
        bytes.extend_from_slice(session_id);
        bytes.extend_from_slice(token);
        Ok(bytes)
    }

    /// Decode a relay registration without allocating attacker-controlled data.
    pub fn decode_registration(bytes: &[u8]) -> Result<Registration<'_>, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Short);
        }
        if bytes[..2] != MAGIC {
            return Err(Error::BadMagic);
        }
        if bytes[2] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if bytes[3] != REGISTER {
            return Err(Error::InvalidType);
        }
        let role = Role::decode(bytes[4])?;
        let session_len = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        let token_len = usize::from(u16::from_be_bytes([bytes[7], bytes[8]]));
        if session_len == 0
            || session_len > MAX_SESSION_ID
            || token_len == 0
            || token_len > MAX_TOKEN
            || HEADER_LEN
                .checked_add(session_len)
                .and_then(|length| length.checked_add(token_len))
                != Some(bytes.len())
        {
            return Err(Error::InvalidLength);
        }
        let session_start = HEADER_LEN;
        let token_start = session_start + session_len;
        let session_id = core::str::from_utf8(&bytes[session_start..token_start])
            .map_err(|_| Error::InvalidUtf8)?;
        let token = core::str::from_utf8(&bytes[token_start..]).map_err(|_| Error::InvalidUtf8)?;
        Ok(Registration {
            role,
            session_id,
            token,
        })
    }

    /// Encode a small response so a peer can distinguish registration from
    /// encrypted traffic while probing the relay path.
    pub fn encode_ack(role: Role) -> [u8; 5] {
        [MAGIC[0], MAGIC[1], VERSION, REGISTER + 1, role as u8]
    }

    /// Check the fixed-size acknowledgement for one role's registration.
    ///
    /// The relay ACK is deliberately not authenticated application data: it
    /// only confirms that the relay installed the already MAC-authenticated
    /// registration. The first encrypted path probe still proves that both
    /// peers selected the same end-to-end session keys.
    pub fn is_ack(bytes: &[u8], role: Role) -> bool {
        bytes == encode_ack(role)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn registration_round_trips_as_borrowed_fields() {
            let encoded = encode_registration("session-id", Role::Client, "client-token")
                .expect("encode registration");
            assert_eq!(
                decode_registration(&encoded).expect("decode registration"),
                Registration {
                    role: Role::Client,
                    session_id: "session-id",
                    token: "client-token",
                }
            );
        }

        #[test]
        fn malformed_registration_is_rejected_before_slicing() {
            assert_eq!(decode_registration(b"OR\x01\x01\x02"), Err(Error::Short));
            let mut encoded = encode_registration("session", Role::Host, "token").unwrap();
            encoded[5] = 0xff;
            assert_eq!(decode_registration(&encoded), Err(Error::InvalidLength));
        }

        #[test]
        fn acknowledgement_is_role_specific() {
            assert!(is_ack(&encode_ack(Role::Host), Role::Host));
            assert!(!is_ack(&encode_ack(Role::Host), Role::Client));
            assert!(!is_ack(b"OR\x01\x03\x01", Role::Host));
        }
    }
}

/// Maximum UDP payload emitted by the initial transport.
pub const MAX_DATAGRAM: usize = 1200;
/// Header bytes before ciphertext and the authentication tag.
pub const HEADER_LEN: usize = 16;
/// AES-GCM tag size.
pub const TAG_LEN: usize = 16;
/// Maximum plaintext that fits in one initial datagram.
pub const MAX_PLAINTEXT: usize = MAX_DATAGRAM - HEADER_LEN - TAG_LEN;
const REPLAY_WINDOW_BITS: u32 = 64;

const MAGIC: [u8; 2] = *b"OS";
const VERSION: u8 = 1;

/// Ephemeral X25519 key pair for one OpenStream session.
///
/// The private half never leaves this process. The public half may be sent in
/// the role-authenticated signaling channel; both peers then derive the same
/// AES-GCM key without placing a transport key in the pairing JSON.
pub struct KeyExchange {
    secret: StaticSecret,
    public: PublicKey,
}

/// A long-lived Ed25519 identity used to authenticate one ephemeral
/// X25519 exchange. The private key is kept by the caller and is never sent
/// over signaling. Applications should persist the PKCS#8 bytes in a
/// permission-restricted file or secret store and pin the peer's public-key
/// fingerprint out of band.
pub struct IdentityKey {
    pkcs8: Vec<u8>,
    public: [u8; 32],
}

impl core::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl IdentityKey {
    /// Generate a fresh Ed25519 identity using the operating-system RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| IdentityError::GenerationFailed)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Load an identity from Ed25519 PKCS#8 bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, IdentityError> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| IdentityError::InvalidKeyMaterial)?;
        let public = <[u8; 32]>::try_from(key_pair.public_key().as_ref())
            .map_err(|_| IdentityError::InvalidKeyMaterial)?;
        Ok(Self {
            pkcs8: bytes.to_vec(),
            public,
        })
    }

    /// Return the public identity key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Return a copy of the PKCS#8 bytes for secure persistence.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Sign the canonical ephemeral-key transcript.
    pub fn sign_key_exchange(
        &self,
        session_id: &str,
        role: u8,
        ephemeral_public: [u8; 32],
    ) -> Result<[u8; 64], IdentityError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8)
            .map_err(|_| IdentityError::InvalidKeyMaterial)?;
        let message = key_exchange_transcript(session_id, role, ephemeral_public);
        let signature = key_pair.sign(&message);
        <[u8; 64]>::try_from(signature.as_ref()).map_err(|_| IdentityError::SigningFailed)
    }

    /// Verify a peer's signature over its ephemeral-key transcript.
    pub fn verify_key_exchange(
        public: [u8; 32],
        signature_bytes: [u8; 64],
        session_id: &str,
        role: u8,
        ephemeral_public: [u8; 32],
    ) -> bool {
        let message = key_exchange_transcript(session_id, role, ephemeral_public);
        signature::UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(&message, &signature_bytes)
            .is_ok()
    }
}

/// Identity-key failures. The concrete ring error is intentionally not
/// exposed because it contains no useful operator-facing detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    GenerationFailed,
    InvalidKeyMaterial,
    SigningFailed,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::GenerationFailed => "identity key generation failed",
            Self::InvalidKeyMaterial => "identity key material is invalid",
            Self::SigningFailed => "identity signature generation failed",
        })
    }
}

impl std::error::Error for IdentityError {}

/// Build the unambiguous message signed by an identity key. The length prefix
/// prevents concatenation ambiguities if session identifiers are attacker
/// controlled, while role and the ephemeral public key bind the signature to
/// exactly one side of one session.
pub fn key_exchange_transcript(session_id: &str, role: u8, ephemeral_public: [u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 4 + session_id.len() + 1 + 32);
    message.extend_from_slice(b"OpenStream identity handshake v1\0");
    message.extend_from_slice(&(u32::try_from(session_id.len()).unwrap_or(u32::MAX)).to_be_bytes());
    message.extend_from_slice(session_id.as_bytes());
    message.push(role);
    message.extend_from_slice(&ephemeral_public);
    message
}

impl core::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyExchange")
            .field("public", &self.public.as_bytes())
            .finish_non_exhaustive()
    }
}

impl KeyExchange {
    /// Generate fresh session material using the operating system RNG.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Derive direction-separated AES keys on both peers.
    ///
    /// Returns `(tx, rx)`: the key this side seals with and the key it opens
    /// with. Both peers compute the same pair of keys with opposite
    /// assignment, so a (key, nonce) pair is never reused across directions
    /// (AES-GCM nonce reuse destroys confidentiality and integrity).
    ///
    /// The KDF binds the Diffie-Hellman shared secret and both public keys in
    /// canonical (lexicographic) order, so neither side can be tricked into a
    /// different key by reordering. Use [`KeyExchange::derive_session_keys`]
    /// when a session id is available so the keys are additionally bound to
    /// the session the handshake ran in.
    ///
    /// Returns [`Error::WeakPublicKey`] when the peer key is all zero or the
    /// resulting shared secret is all zero. The local secret is X25519-clamped
    /// (a multiple of 8), so any peer point of small order (dividing 8) maps
    /// to the all-zero shared secret and is rejected here.
    pub fn derive_keys(&self, peer_public: [u8; 32]) -> Result<DirectionalKeys, Error> {
        Self::derive_keys_inner(&self.secret, &self.public, peer_public, None)
    }

    /// Derive direction-separated keys additionally bound to a session id.
    ///
    /// Both peers must pass the same session id (the pairing's `session_id`);
    /// a key exchanged in one session cannot be replayed into another.
    pub fn derive_session_keys(
        &self,
        peer_public: [u8; 32],
        session_id: &str,
    ) -> Result<DirectionalKeys, Error> {
        Self::derive_keys_inner(&self.secret, &self.public, peer_public, Some(session_id))
    }

    fn derive_keys_inner(
        secret: &StaticSecret,
        own_public: &PublicKey,
        peer_public: [u8; 32],
        session_id: Option<&str>,
    ) -> Result<DirectionalKeys, Error> {
        if peer_public == [0_u8; 32] {
            return Err(Error::WeakPublicKey);
        }
        let shared = secret.diffie_hellman(&PublicKey::from(peer_public));
        if shared.as_bytes() == &[0_u8; 32] {
            // Covers every small-order peer point: with a clamped secret any
            // point of order dividing 8 maps to the identity element.
            return Err(Error::WeakPublicKey);
        }
        let own = own_public.as_bytes();
        let (lesser, greater) = if own <= &peer_public {
            (*own, peer_public)
        } else {
            (peer_public, *own)
        };
        let mut tx_label = b"OpenStream X25519 AES-256-GCM v2 lesser-to-greater\0".to_vec();
        let mut rx_label = b"OpenStream X25519 AES-256-GCM v2 greater-to-lesser\0".to_vec();
        if let Some(id) = session_id {
            tx_label.extend_from_slice(id.as_bytes());
            rx_label.extend_from_slice(id.as_bytes());
        }
        let key_lg = kdf_label(&tx_label, shared.as_bytes(), &lesser, &greater);
        let key_gl = kdf_label(&rx_label, shared.as_bytes(), &lesser, &greater);
        let own_is_lesser = own <= &peer_public;
        Ok(if own_is_lesser {
            DirectionalKeys {
                tx: key_lg,
                rx: key_gl,
            }
        } else {
            DirectionalKeys {
                tx: key_gl,
                rx: key_lg,
            }
        })
    }

    /// Return the public half for signaling.
    pub fn public_key(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Fingerprint of a public key for out-of-band verification.
    ///
    /// Both peers log this during establishment; operators comparing the two
    /// values over a trusted channel detect a signaling-service MITM.
    pub fn fingerprint(public: [u8; 32]) -> String {
        use core::fmt::Write as _;
        let mut digest = Sha256::new();
        digest.update(b"OpenStream X25519 fingerprint v1\0");
        digest.update(public);
        let bytes: [u8; 32] = digest.finalize().into();
        let mut out = String::with_capacity(64);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// Direction-separated traffic keys from one exchange.
///
/// `tx` seals this side's packets, `rx` opens the peer's. The two peers hold
/// mirrored pairs, so no (key, nonce) is ever reused across directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectionalKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

fn kdf_label(label: &[u8], shared: &[u8], lesser: &[u8; 32], greater: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update([0x00]);
    digest.update(shared);
    digest.update(lesser);
    digest.update(greater);
    digest.finalize().into()
}
/// Traffic class carried by a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Control = 1,
    Video = 2,
    Audio = 3,
    Input = 4,
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Video),
            3 => Ok(Self::Audio),
            4 => Ok(Self::Input),
            _ => Err(Error::UnknownKind(value)),
        }
    }
}

/// A cleartext message before it is sealed into a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub channel: u8,
    pub flags: u8,
    pub counter: u64,
    pub payload: Vec<u8>,
}

/// Packet parsing/sealing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ShortDatagram,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    BadLength,
    TooLarge,
    CounterOverflow,
    AuthenticationFailed,
    /// Peer public key is all zero or yields an all-zero shared secret
    /// (covers every small-order X25519 point against a clamped secret).
    WeakPublicKey,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ShortDatagram => f.write_str("datagram is shorter than its header"),
            Self::BadMagic => f.write_str("datagram magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version {version}")
            }
            Self::UnknownKind(kind) => write!(f, "unknown packet kind {kind}"),
            Self::BadLength => f.write_str("datagram length does not match its header"),
            Self::TooLarge => f.write_str("payload exceeds the datagram limit"),
            Self::CounterOverflow => f.write_str("session counter exhausted"),
            Self::AuthenticationFailed => f.write_str("packet authentication failed"),
            Self::WeakPublicKey => f.write_str("peer public key is weak or low-order"),
        }
    }
}

impl std::error::Error for Error {}

/// Stateful sender/receiver cipher for one session.
///
/// Holds separate transmit and receive keys: both peers seal counter 0 with
/// different keys, so AES-GCM (key, nonce) pairs are never reused across
/// directions. `Session` is deliberately not `Clone` -- duplicating `next_tx`
/// would reuse nonces with itself.
pub struct Session {
    tx_cipher: Aes256Gcm,
    rx_cipher: Aes256Gcm,
    next_tx: u64,
    highest_rx: Option<u64>,
    received_window: u64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("next_tx", &self.next_tx)
            .field("highest_rx", &self.highest_rx)
            .field("received_window", &self.received_window)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Create a session from direction-separated keys (see
    /// [`KeyExchange::derive_keys`]). `tx_key` seals, `rx_key` opens.
    pub fn new(tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self {
            tx_cipher: Aes256Gcm::new_from_slice(&tx_key).expect("AES-256 key has a fixed size"),
            rx_cipher: Aes256Gcm::new_from_slice(&rx_key).expect("AES-256 key has a fixed size"),
            next_tx: 0,
            highest_rx: None,
            received_window: 0,
        }
    }

    /// Create a loopback session using one key for both directions.
    ///
    /// Test-only: both directions share a key, so this must never carry
    /// bidirectional traffic in production.
    #[cfg(test)]
    fn new_loopback(key: [u8; 32]) -> Self {
        Self::new(key, key)
    }

    /// Seal one packet, assigning its next transmit counter.
    pub fn seal(
        &mut self,
        kind: Kind,
        channel: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if payload.len() > MAX_PLAINTEXT {
            return Err(Error::TooLarge);
        }
        let counter = self.next_tx;
        self.next_tx = self.next_tx.checked_add(1).ok_or(Error::CounterOverflow)?;
        let mut out = vec![0_u8; HEADER_LEN + payload.len() + TAG_LEN];
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = VERSION;
        out[3] = kind as u8;
        out[4] = channel;
        out[5] = flags;
        out[6..14].copy_from_slice(&counter.to_be_bytes());
        out[14..16].copy_from_slice(
            &(u16::try_from(payload.len()).map_err(|_| Error::TooLarge)?).to_be_bytes(),
        );
        out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

        let nonce_bytes = nonce(counter);
        let (header, rest) = out.split_at_mut(HEADER_LEN);
        let (ciphertext, tag_bytes) = rest.split_at_mut(payload.len());
        let tag = self
            .tx_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), header, ciphertext)
            .map_err(|_| Error::AuthenticationFailed)?;
        tag_bytes.copy_from_slice(&tag);
        Ok(out)
    }

    /// Open one datagram, accepting bounded reordering and rejecting replays.
    pub fn open(&mut self, datagram: &[u8]) -> Result<Packet, Error> {
        if datagram.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::ShortDatagram);
        }
        if datagram[0..2] != MAGIC {
            return Err(Error::BadMagic);
        }
        if datagram[2] != VERSION {
            return Err(Error::UnsupportedVersion(datagram[2]));
        }
        let kind = Kind::try_from(datagram[3])?;
        let counter = u64::from_be_bytes(
            datagram[6..14]
                .try_into()
                .map_err(|_| Error::ShortDatagram)?,
        );
        let payload_len = usize::from(u16::from_be_bytes(
            datagram[14..16]
                .try_into()
                .map_err(|_| Error::ShortDatagram)?,
        ));
        if payload_len > MAX_PLAINTEXT || datagram.len() != HEADER_LEN + payload_len + TAG_LEN {
            return Err(Error::BadLength);
        }
        if self.is_replay(counter) {
            return Err(Error::AuthenticationFailed);
        }
        let mut payload = datagram[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        let tag = &datagram[HEADER_LEN + payload_len..];
        let nonce_bytes = nonce(counter);
        self.rx_cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                &datagram[..HEADER_LEN],
                &mut payload,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        self.accept_counter(counter);
        Ok(Packet {
            kind,
            channel: datagram[4],
            flags: datagram[5],
            counter,
            payload,
        })
    }

    fn is_replay(&self, counter: u64) -> bool {
        let Some(highest) = self.highest_rx else {
            return false;
        };
        if counter > highest {
            return false;
        }
        let distance = highest - counter;
        distance >= u64::from(REPLAY_WINDOW_BITS) || self.received_window & (1_u64 << distance) != 0
    }

    fn accept_counter(&mut self, counter: u64) {
        let Some(highest) = self.highest_rx else {
            self.highest_rx = Some(counter);
            self.received_window = 1;
            return;
        };
        if counter > highest {
            let distance = counter - highest;
            self.received_window = if distance >= u64::from(REPLAY_WINDOW_BITS) {
                1
            } else {
                (self.received_window << distance) | 1
            };
            self.highest_rx = Some(counter);
        } else {
            self.received_window |= 1_u64 << (highest - counter);
        }
    }
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn encrypted_packet_round_trips() {
        let mut sender = Session::new_loopback(KEY);
        let mut receiver = Session::new_loopback(KEY);
        let sealed = sender.seal(Kind::Video, 1, 0, b"frame").expect("seal");
        let packet = receiver.open(&sealed).expect("open");
        assert_eq!(packet.kind, Kind::Video);
        assert_eq!(packet.channel, 1);
        assert_eq!(packet.payload, b"frame");
        assert_eq!(sealed.len(), HEADER_LEN + 5 + TAG_LEN);
    }

    #[test]
    fn ephemeral_key_exchange_agrees_without_exposing_private_material() {
        let left = KeyExchange::generate().expect("OS randomness");
        let right = KeyExchange::generate().expect("OS randomness");
        let left_keys = left.derive_keys(right.public_key()).expect("derive");
        let right_keys = right.derive_keys(left.public_key()).expect("derive");
        assert_eq!(left_keys.tx, right_keys.rx);
        assert_eq!(left_keys.rx, right_keys.tx);
        assert_ne!(left_keys.tx, left_keys.rx);
        assert_ne!(left.public_key(), right.public_key());
    }

    #[test]
    fn identity_signature_binds_session_role_and_ephemeral_key() {
        let identity = IdentityKey::generate().expect("identity generation");
        let ephemeral = KeyExchange::generate().expect("ephemeral generation");
        let public = identity.public_key();
        let signature = identity
            .sign_key_exchange("session-1", 1, ephemeral.public_key())
            .expect("identity signature");
        assert!(IdentityKey::verify_key_exchange(
            public,
            signature,
            "session-1",
            1,
            ephemeral.public_key()
        ));
        assert!(!IdentityKey::verify_key_exchange(
            public,
            signature,
            "session-2",
            1,
            ephemeral.public_key()
        ));
        assert!(!IdentityKey::verify_key_exchange(
            public,
            signature,
            "session-1",
            2,
            ephemeral.public_key()
        ));
    }

    #[test]
    fn header_tampering_is_rejected() {
        let mut sender = Session::new_loopback(KEY);
        let mut receiver = Session::new_loopback(KEY);
        let mut sealed = sender.seal(Kind::Control, 0, 0, b"hello").expect("seal");
        sealed[4] = 9;
        assert_eq!(receiver.open(&sealed), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn duplicate_counter_is_rejected() {
        let mut sender = Session::new_loopback(KEY);
        let mut receiver = Session::new_loopback(KEY);
        let sealed = sender.seal(Kind::Input, 0, 0, b"x").expect("seal");
        receiver.open(&sealed).expect("first open");
        assert_eq!(receiver.open(&sealed), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn bounded_reordering_is_accepted_but_replays_are_rejected() {
        let mut sender = Session::new_loopback(KEY);
        let mut receiver = Session::new_loopback(KEY);
        let first = sender.seal(Kind::Video, 0, 0, b"first").expect("seal");
        let second = sender.seal(Kind::Video, 0, 0, b"second").expect("seal");
        receiver.open(&second).expect("newest packet");
        receiver.open(&first).expect("reordered packet");
        assert_eq!(receiver.open(&first), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn oversized_payload_is_rejected_before_allocation() {
        let mut sender = Session::new_loopback(KEY);
        let payload = vec![0_u8; MAX_PLAINTEXT + 1];
        assert_eq!(
            sender.seal(Kind::Audio, 2, 0, &payload),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn directional_keys_never_reuse_nonce_across_directions() {
        let left_exchange = KeyExchange::generate().expect("OS randomness");
        let right_exchange = KeyExchange::generate().expect("OS randomness");
        let left_keys = left_exchange
            .derive_session_keys(right_exchange.public_key(), "session-1")
            .expect("derive");
        let right_keys = right_exchange
            .derive_session_keys(left_exchange.public_key(), "session-1")
            .expect("derive");
        let mut left = Session::new(left_keys.tx, left_keys.rx);
        let mut right = Session::new(right_keys.tx, right_keys.rx);
        // Both sides seal counter 0 with the same nonce value but different
        // keys: the wire bytes must differ (no keystream reuse).
        let left_wire = left.seal(Kind::Video, 0, 0, b"same").expect("seal");
        let right_wire = right.seal(Kind::Video, 0, 0, b"same").expect("seal");
        assert_ne!(left_wire, right_wire);
        // Cross-direction delivery works.
        let packet = right.open(&left_wire).expect("open left->right");
        assert_eq!(packet.payload, b"same");
        let packet = left.open(&right_wire).expect("open right->left");
        assert_eq!(packet.payload, b"same");
        // A side cannot open its own packet (wrong rx key).
        let own = left.seal(Kind::Video, 0, 0, b"own").expect("seal");
        assert_eq!(left.open(&own), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn weak_peer_keys_are_rejected() {
        let exchange = KeyExchange::generate().expect("OS randomness");
        assert_eq!(exchange.derive_keys([0_u8; 32]), Err(Error::WeakPublicKey));
        assert_eq!(
            exchange.derive_session_keys([0_u8; 32], "session-1"),
            Err(Error::WeakPublicKey)
        );
    }

    #[test]
    fn session_binding_changes_keys_and_agrees() {
        let left = KeyExchange::generate().expect("OS randomness");
        let right = KeyExchange::generate().expect("OS randomness");
        let plain = left.derive_keys(right.public_key()).expect("derive");
        let bound = left
            .derive_session_keys(right.public_key(), "session-1")
            .expect("derive");
        assert_ne!(plain.tx, bound.tx);
        let other = left
            .derive_session_keys(right.public_key(), "session-2")
            .expect("derive");
        assert_ne!(bound.tx, other.tx);
        let right_bound = right
            .derive_session_keys(left.public_key(), "session-1")
            .expect("derive");
        assert_eq!(bound.tx, right_bound.rx);
        assert_eq!(bound.rx, right_bound.tx);
    }

    #[test]
    fn fingerprint_is_stable_hex() {
        let exchange = KeyExchange::generate().expect("OS randomness");
        let first = KeyExchange::fingerprint(exchange.public_key());
        let second = KeyExchange::fingerprint(exchange.public_key());
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
