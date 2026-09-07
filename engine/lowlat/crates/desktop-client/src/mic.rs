//! Client microphone capture for passthrough to the host.
//!
//! The host only takes a guest microphone when both sides negotiate the
//! `microphone` capability and the host policy allows it. Capture itself is
//! an external FFmpeg process (no new audio dependency): mono 48 kHz
//! `s16le` piped in 10 ms chunks, Opus voice-encoded, and framed as the
//! native virtual-device microphone control message the lowlat host seat
//! already decodes. `OPENSTREAM_MIC_INPUT` names the device; without it no
//! process starts and nothing is sent.

use std::process::Stdio;
use tokio::process::{Child, Command};

/// Mono samples per 10 ms microphone chunk at 48 kHz.
pub(crate) const MIC_SAMPLES: usize = 480;
/// Bytes per chunk of mono 16-bit PCM.
pub(crate) const MIC_CHUNK_BYTES: usize = MIC_SAMPLES * 2;
/// Opus voice bitrate for the microphone path.
pub(crate) const MIC_BITRATE_BPS: i32 = 32_000;

/// Errors starting or framing microphone capture; all map to mic-off, never
/// to aborting the session.
#[derive(Debug)]
pub(crate) enum MicError {
    Disabled,
    Spawn(String),
    Encode(String),
    Frame(String),
}

impl std::fmt::Display for MicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("microphone capture is not configured"),
            Self::Spawn(detail) => write!(f, "could not start microphone capture: {detail}"),
            Self::Encode(detail) => write!(f, "microphone Opus encode failed: {detail}"),
            Self::Frame(detail) => write!(f, "microphone frame is invalid: {detail}"),
        }
    }
}

impl std::error::Error for MicError {}

/// Whether the operator configured a microphone input device.
pub(crate) fn mic_configured() -> bool {
    std::env::var("OPENSTREAM_MIC_INPUT")
        .ok()
        .is_some_and(|input| !input.trim().is_empty())
}

/// Spawn FFmpeg capturing mono 48 kHz PCM from the configured device.
///
/// `OPENSTREAM_MIC_FORMAT` overrides the per-OS default input format
/// (`alsa` on Linux, `avfoundation` on macOS, `dshow` on Windows).
/// No shell is involved: the device string is one argv element.
pub(crate) fn spawn_mic_capture() -> Result<Child, MicError> {
    let input = std::env::var("OPENSTREAM_MIC_INPUT").map_err(|_| MicError::Disabled)?;
    if input.trim().is_empty() {
        return Err(MicError::Disabled);
    }
    let format = std::env::var("OPENSTREAM_MIC_FORMAT").unwrap_or_else(|_| {
        match std::env::consts::OS {
            "macos" => "avfoundation",
            "windows" => "dshow",
            _ => "alsa",
        }
        .to_string()
    });
    let executable = std::env::var("OPENSTREAM_FFMPEG").unwrap_or_else(|_| "ffmpeg".to_string());
    Command::new(executable)
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            format.trim(),
            "-i",
            input.trim(),
            "-vn",
            "-sn",
            "-dn",
            "-ar",
            "48000",
            "-ac",
            "1",
            "-f",
            "s16le",
            "pipe:1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| MicError::Spawn(error.to_string()))
}

/// Mono Opus voice encoder state for 10 ms microphone chunks.
pub(crate) struct MicEncoder {
    opus: opus_rs::OpusEncoder,
    floats: Vec<f32>,
    packet: Vec<u8>,
}

impl MicEncoder {
    pub(crate) fn new() -> Result<Self, MicError> {
        let mut opus = opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip)
            .map_err(|error| MicError::Encode(error.to_string()))?;
        opus.bitrate_bps = MIC_BITRATE_BPS;
        Ok(Self {
            opus,
            floats: vec![0.0; MIC_SAMPLES],
            packet: vec![0_u8; 1024],
        })
    }

    /// Encode one 960-byte PCM chunk and frame it as a virtual-device
    /// microphone control message ready for the reliable control channel.
    pub(crate) fn encode_chunk(&mut self, pcm: &[u8]) -> Result<Vec<u8>, MicError> {
        if pcm.len() != MIC_CHUNK_BYTES {
            return Err(MicError::Frame(format!(
                "expected {MIC_CHUNK_BYTES} PCM bytes, got {}",
                pcm.len()
            )));
        }
        for (dst, pair) in self.floats.iter_mut().zip(pcm.chunks_exact(2)) {
            let sample = i16::from_le_bytes([pair[0], pair[1]]);
            *dst = f32::from(sample) / 32768.0;
        }
        let len = self
            .opus
            .encode(&self.floats, MIC_SAMPLES, &mut self.packet)
            .map_err(|error| MicError::Encode(error.to_string()))?;
        let payload = self.packet.get(..len).ok_or_else(|| {
            MicError::Encode("encoded microphone packet overran its buffer".into())
        })?;
        build_mic_control(payload)
    }
}

/// Frame one Opus voice payload as the native virtual-device microphone
/// control message (header plus fixed 1932-byte body).
pub(crate) fn build_mic_control(opus: &[u8]) -> Result<Vec<u8>, MicError> {
    use lowlat_core::control::{self, Control};
    use lowlat_core::microphone;
    if opus.len() > microphone::PAYLOAD_MAX {
        return Err(MicError::Frame(format!(
            "microphone payload {} exceeds {}",
            opus.len(),
            microphone::PAYLOAD_MAX
        )));
    }
    let mut body = vec![0_u8; microphone::BODY_LEN];
    microphone::encode(
        &mut body,
        &microphone::Packet {
            payload: opus,
            encoding: microphone::Encoding::Compressed,
        },
    )
    .map_err(|_| MicError::Frame("microphone body did not encode".into()))?;
    let control = Control {
        a0: u32::try_from(microphone::BODY_LEN).unwrap_or(u32::MAX),
        a1: microphone::MICROPHONE_ARGUMENT,
        a2: microphone::MICROPHONE_SELECTOR,
        opcode: control::op::VIRTUAL_DEVICE,
        body: &[],
    };
    let mut header = [0_u8; control::CONTROL_HEADER_LEN];
    control::encode_header(&mut header, &control)
        .map_err(|_| MicError::Frame("microphone header did not encode".into()))?;
    let mut message = Vec::with_capacity(header.len() + body.len());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mic_control_frames_decode_as_microphone_packets() {
        use lowlat_core::control;
        use lowlat_core::microphone;
        let message = build_mic_control(&[0x10, 0x20, 0x30]).expect("frame mic packet");
        assert_eq!(
            message.len(),
            control::CONTROL_HEADER_LEN + microphone::BODY_LEN
        );
        let header = control::parse(&message[..control::CONTROL_HEADER_LEN]).expect("parse header");
        assert_eq!(header.opcode, control::op::VIRTUAL_DEVICE);
        assert_eq!(header.a1, microphone::MICROPHONE_ARGUMENT);
        assert_eq!(header.a2, microphone::MICROPHONE_SELECTOR);
        let packet = microphone::parse(
            header.a0,
            header.a1,
            header.a2,
            &message[control::CONTROL_HEADER_LEN..],
        )
        .expect("parse mic body")
        .expect("is a microphone packet");
        assert_eq!(packet.payload, &[0x10, 0x20, 0x30]);
        assert_eq!(packet.encoding, microphone::Encoding::Compressed);
    }

    #[test]
    fn oversized_and_misaligned_chunks_are_rejected() {
        assert!(build_mic_control(&vec![0_u8; 1921]).is_err());
        let mut encoder = MicEncoder::new().expect("mic encoder");
        assert!(encoder.encode_chunk(&[0_u8; 959]).is_err());
        assert!(encoder.encode_chunk(&[0_u8; 961]).is_err());
    }

    #[test]
    fn silence_encodes_to_a_valid_control_message() {
        let mut encoder = MicEncoder::new().expect("mic encoder");
        let message = encoder
            .encode_chunk(&[0_u8; MIC_CHUNK_BYTES])
            .expect("encode silence");
        assert!(message.len() > lowlat_core::control::CONTROL_HEADER_LEN);
    }
}
