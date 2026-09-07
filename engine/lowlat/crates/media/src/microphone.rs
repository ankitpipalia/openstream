//! Guest-microphone intake shared by host adapters.
//!
//! Microphone controls are authenticated by the OpenStream session, but their
//! body is still peer-controlled input to a codec. This module keeps the
//! decoder and output buffer bounded, accepts only the lowlat microphone
//! selector, and treats malformed audio as a dropped media packet rather than
//! a reason to tear down an otherwise healthy session.

use std::fs::{File, OpenOptions};
use std::io::Write;

/// The largest verification sink size: 256 MiB of mono 48 kHz PCM, roughly
/// forty-five minutes of audio.
pub const MAX_SINK_BYTES: u64 = 256 * 1024 * 1024;

/// A host-side guest microphone decoder and optional raw PCM sink.
///
/// One value is created per host process. Opus state is intentionally kept
/// across packets because a voice decoder is stateful; the input message
/// itself identifies the guest microphone, so all packets reaching this sink
/// belong to the currently negotiated host session.
#[derive(Debug)]
pub struct GuestMicSink {
    decoder: Option<lowlat_audio::Decoder>,
    file: Option<File>,
    /// Reused output storage; a microphone packet may decode at most 960 mono
    /// samples.
    samples: Box<[i16; lowlat_core::microphone::SAMPLES_MAX]>,
    /// Reused little-endian output bytes for the optional verification sink.
    pcm: Vec<u8>,
    written: u64,
    /// Valid microphone packets decoded.
    pub frames: u64,
    /// Microphone-shaped packets refused by validation or the codec.
    pub refused: u64,
    /// Sink writes that failed. The sink is disabled after the first failure;
    /// a broken local file must not make the network worker fail repeatedly.
    pub sink_failures: u64,
}

impl GuestMicSink {
    /// Build the intake from the negotiated/policy decision and the optional
    /// `OPENSTREAM_MIC_SINK` path. A sink path is opened only after the
    /// microphone grant is true.
    pub fn from_env(enabled: bool) -> Self {
        let (decoder, file) = if enabled {
            let decoder = lowlat_audio::Decoder::new().ok();
            let file = std::env::var("OPENSTREAM_MIC_SINK")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .and_then(|path| {
                    match OpenOptions::new().create(true).append(true).open(&path) {
                        Ok(file) => Some(file),
                        Err(error) => {
                            eprintln!(
                                "OpenStream microphone sink could not be opened at {path:?}: {error}"
                            );
                            None
                        }
                    }
                });
            (decoder, file)
        } else {
            (None, None)
        };
        Self {
            decoder,
            file,
            samples: Box::new([0; lowlat_core::microphone::SAMPLES_MAX]),
            pcm: Vec::with_capacity(lowlat_core::microphone::SAMPLES_MAX * 2),
            written: 0,
            frames: 0,
            refused: 0,
            sink_failures: 0,
        }
    }

    /// Whether the host has a decoder and therefore accepts microphone-shaped
    /// controls. With no decoder, callers must leave the payload available to
    /// other control handlers.
    pub fn accepting(&self) -> bool {
        self.decoder.is_some()
    }

    /// Try to consume `payload` as one microphone control message.
    ///
    /// Returns `true` for every microphone-shaped payload, including one that
    /// is malformed after its virtual-device selector is recognized. This is
    /// important: rejected microphone bytes must never fall through into the
    /// keyboard/pointer injector.
    pub fn accept(&mut self, payload: &[u8]) -> bool {
        use lowlat_core::control::{self, CONTROL_HEADER_LEN};
        use lowlat_core::microphone;

        if self.decoder.is_none() || payload.len() < CONTROL_HEADER_LEN {
            return false;
        }
        let header = match control::parse(&payload[..CONTROL_HEADER_LEN]) {
            Ok(header) if header.opcode == control::op::VIRTUAL_DEVICE => header,
            _ => return false,
        };
        let packet = match microphone::parse(
            header.a0,
            header.a1,
            header.a2,
            &payload[CONTROL_HEADER_LEN..],
        ) {
            Ok(Some(packet)) => packet,
            Ok(None) => return false,
            Err(_) => {
                self.refused = self.refused.saturating_add(1);
                return true;
            }
        };
        let Some(decoder) = self.decoder.as_mut() else {
            return true;
        };
        let samples = match decoder.decode(&packet, self.samples.as_mut_slice()) {
            Ok(samples) => samples.min(self.samples.len()),
            Err(_) => {
                self.refused = self.refused.saturating_add(1);
                return true;
            }
        };
        self.frames = self.frames.saturating_add(1);
        if let Some(file) = self.file.as_mut() {
            self.pcm.clear();
            for sample in self.samples[..samples].iter().copied() {
                self.pcm.extend_from_slice(&sample.to_le_bytes());
            }
            let Some(next) = self
                .written
                .checked_add(u64::try_from(self.pcm.len()).unwrap_or(u64::MAX))
            else {
                return true;
            };
            if next <= MAX_SINK_BYTES {
                if file.write_all(&self.pcm).is_ok() {
                    self.written = next;
                } else {
                    self.sink_failures = self.sink_failures.saturating_add(1);
                    // Drop the file after a failed write so every subsequent
                    // packet remains a decode/count operation, not a tight
                    // loop of repeated filesystem errors.
                    self.file = None;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mic_message(payload: &[u8]) -> Vec<u8> {
        use lowlat_core::control::{self, Control};
        use lowlat_core::microphone;
        let mut body = vec![0_u8; microphone::BODY_LEN];
        microphone::encode(
            &mut body,
            &microphone::Packet {
                payload,
                encoding: microphone::Encoding::Raw,
            },
        )
        .expect("mic body");
        let control = Control {
            a0: u32::try_from(microphone::BODY_LEN).unwrap_or(u32::MAX),
            a1: microphone::MICROPHONE_ARGUMENT,
            a2: microphone::MICROPHONE_SELECTOR,
            opcode: control::op::VIRTUAL_DEVICE,
            body: &[],
        };
        let mut header = vec![0_u8; control::CONTROL_HEADER_LEN];
        control::encode_header(&mut header, &control).expect("mic header");
        header.extend_from_slice(&body);
        header
    }

    #[test]
    fn raw_microphone_frames_decode_without_allocating_per_packet() {
        let mut sink = GuestMicSink::from_env(false);
        assert!(!sink.accept(&mic_message(&[0; 960])));

        let mut sink = GuestMicSink {
            decoder: lowlat_audio::Decoder::new().ok(),
            file: None,
            samples: Box::new([0; lowlat_core::microphone::SAMPLES_MAX]),
            pcm: Vec::with_capacity(lowlat_core::microphone::SAMPLES_MAX * 2),
            written: 0,
            frames: 0,
            refused: 0,
            sink_failures: 0,
        };
        assert!(sink.accept(&mic_message(&[0; 960])));
        assert_eq!(sink.frames, 1);
        assert_eq!(sink.refused, 0);
    }

    #[test]
    fn malformed_microphone_is_consumed_and_never_falls_through() {
        let mut sink = GuestMicSink {
            decoder: lowlat_audio::Decoder::new().ok(),
            file: None,
            samples: Box::new([0; lowlat_core::microphone::SAMPLES_MAX]),
            pcm: Vec::with_capacity(lowlat_core::microphone::SAMPLES_MAX * 2),
            written: 0,
            frames: 0,
            refused: 0,
            sink_failures: 0,
        };
        let mut message = mic_message(&[1; 64]);
        message.truncate(100);
        assert!(sink.accept(&message));
        assert_eq!(sink.refused, 1);
    }

    #[test]
    fn non_microphone_controls_are_not_claimed() {
        let mut sink = GuestMicSink {
            decoder: lowlat_audio::Decoder::new().ok(),
            file: None,
            samples: Box::new([0; lowlat_core::microphone::SAMPLES_MAX]),
            pcm: Vec::with_capacity(lowlat_core::microphone::SAMPLES_MAX * 2),
            written: 0,
            frames: 0,
            refused: 0,
            sink_failures: 0,
        };
        assert!(!sink.accept(b"not a microphone control"));
    }
}
