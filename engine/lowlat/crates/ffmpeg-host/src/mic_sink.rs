//! Guest-microphone intake for the external FFmpeg host.
//!
//! The desktop client frames microphone Opus as the native virtual-device
//! microphone control message. This module accepts exactly those messages,
//! decodes them through the contained guest decoder, and appends verification
//! PCM (`s16le`, mono 48 kHz) to `OPENSTREAM_MIC_SINK` when set. Without a
//! sink path, frames are still validated and counted so operators can prove
//! the path works before wiring an OS virtual-microphone device. Routing
//! into a live OS virtual microphone remains open by design.

/// Maximum verification sink size (256 MiB of PCM, about 45 minutes of mono).
pub(crate) const MAX_SINK_BYTES: u64 = 256 * 1024 * 1024;

/// Contained microphone intake state for one host process.
pub(crate) struct MicSink {
    decoder: Option<lowlat_audio::Decoder>,
    file: Option<std::fs::File>,
    written: u64,
    /// Valid microphone packets decoded.
    pub(crate) frames: u64,
    /// Microphone-shaped packets that failed validation or decode.
    pub(crate) refused: u64,
}

impl MicSink {
    /// Build the intake. `enabled` is the negotiated-and-policy microphone
    /// grant; the sink file opens only when granted.
    pub(crate) fn from_env(enabled: bool) -> Self {
        let (decoder, file) = if enabled {
            let decoder = lowlat_audio::Decoder::new().ok();
            let file = std::env::var("OPENSTREAM_MIC_SINK")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .and_then(|path| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .ok()
                });
            (decoder, file)
        } else {
            (None, None)
        };
        Self {
            decoder,
            file,
            written: 0,
            frames: 0,
            refused: 0,
        }
    }

    /// Whether this host takes guest microphone packets at all.
    pub(crate) fn accepting(&self) -> bool {
        self.decoder.is_some()
    }

    /// Try to consume `payload` as a microphone control message.
    ///
    /// Returns `true` when the payload was microphone-shaped (accepted or
    /// refused after validation) so callers never hand it to input
    /// injection; `false` for anything else.
    pub(crate) fn accept(&mut self, payload: &[u8]) -> bool {
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
                self.refused += 1;
                return true;
            }
        };
        let Some(decoder) = self.decoder.as_mut() else {
            return true;
        };
        let mut scratch = vec![0_i16; microphone::SAMPLES_MAX];
        match decoder.decode(&packet, &mut scratch) {
            Ok(samples) => {
                self.frames += 1;
                if let Some(file) = self.file.as_mut() {
                    use std::io::Write;
                    let bytes: Vec<u8> = scratch[..samples.min(scratch.len())]
                        .iter()
                        .flat_map(|sample| sample.to_le_bytes())
                        .collect();
                    if self.written + bytes.len() as u64 <= MAX_SINK_BYTES
                        && file.write_all(&bytes).is_ok()
                    {
                        self.written += bytes.len() as u64;
                    }
                }
            }
            Err(_) => {
                self.refused += 1;
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
        let mut header = [0_u8; control::CONTROL_HEADER_LEN];
        control::encode_header(&mut header, &control).expect("mic header");
        let mut message = Vec::from(header);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn raw_mic_frames_decode_and_count() {
        // 480 mono samples of silence as little-endian pairs.
        let pcm = vec![0_u8; 960];
        let message = mic_message(&pcm);
        // Disabled intake ignores everything without touching the decoder.
        let mut off = MicSink::from_env(false);
        assert!(!off.accept(&message));
        // Enabled intake without a sink still validates and counts.
        let mut sink = MicSink {
            decoder: lowlat_audio::Decoder::new().ok(),
            file: None,
            written: 0,
            frames: 0,
            refused: 0,
        };
        assert!(sink.accept(&message));
        assert_eq!(sink.frames, 1);
        assert_eq!(sink.refused, 0);
    }

    #[test]
    fn non_microphone_payloads_pass_through_to_input() {
        let mut sink = MicSink {
            decoder: lowlat_audio::Decoder::new().ok(),
            file: None,
            written: 0,
            frames: 0,
            refused: 0,
        };
        assert!(!sink.accept(b"not a control message at all.............."));
        assert!(!sink.accept(&[0_u8; 4]));
        // A truncated microphone body is consumed and refused, never injected.
        let mut message = mic_message(&[1_u8; 64]);
        message.truncate(100);
        assert!(sink.accept(&message));
        assert_eq!(sink.refused, 1);
    }
}
