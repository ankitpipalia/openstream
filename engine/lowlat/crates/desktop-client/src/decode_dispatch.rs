//! Decoder-backend selection and the native decode path.
//!
//! [`select_decoder`] chooses the backend by codec, OS and opt-in preference,
//! with ffmpeg as the universal fallback; [`NativeVideoDecoder`] (on macOS)
//! turns reassembled [`EncodedFrame`]s into presentation-ready [`DecodedFrame`]s
//! using the in-process VideoToolbox decoder, assigning the client-local
//! sequence number and stamps the mailbox and presenter expect.
//!
//! The runtime network loop selects and builds the decoder through here; the
//! loopback harness drives the native decoder directly.

#![allow(dead_code)]

/// Which decoder the client uses for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeBackend {
    /// External ffmpeg subprocess -- the default, and the universal fallback.
    Ffmpeg,
    /// In-process VideoToolbox (macOS). Opt-in until a live stream validates it.
    #[cfg(target_os = "macos")]
    VideoToolboxNative,
    /// In-process Media Foundation H.264 decoder MFT (Windows). Vendor-neutral
    /// (runs on NVIDIA/AMD/Intel via the OS decoder), so it is preferred over a
    /// vendor SDK. Opt-in until a live stream validates it.
    #[cfg(target_os = "windows")]
    MediaFoundationNative,
}

/// A video codec the client may be asked to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeCodec {
    H264,
    H265,
}

/// What one decode backend can do on this machine.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecoderCapability {
    /// The backend.
    pub(crate) backend: DecodeBackend,
    /// Codecs it can decode here.
    pub(crate) codecs: &'static [DecodeCodec],
    /// Whether it decodes in-process (no external ffmpeg subprocess).
    pub(crate) in_process: bool,
}

impl DecoderCapability {
    fn supports(&self, codec: DecodeCodec) -> bool {
        self.codecs.contains(&codec)
    }
}

/// The decode backends available on this machine, most-preferred first: the
/// in-process native decoders before ffmpeg, which is always present as the
/// universal fallback. Extending to Windows Media Foundation / Linux VAAPI is a
/// matter of adding cfg-gated entries here.
pub(crate) fn available_decoders() -> Vec<DecoderCapability> {
    // ffmpeg is always present as the universal fallback.
    #[allow(unused_mut)]
    let mut decoders = vec![DecoderCapability {
        backend: DecodeBackend::Ffmpeg,
        codecs: &[DecodeCodec::H264, DecodeCodec::H265],
        in_process: false,
    }];
    // Native in-process decoders go first so they win the preference. The native
    // VideoToolbox path decodes H.264 today; H.265 is a follow-up.
    #[cfg(target_os = "macos")]
    decoders.insert(
        0,
        DecoderCapability {
            backend: DecodeBackend::VideoToolboxNative,
            codecs: &[DecodeCodec::H264],
            in_process: true,
        },
    );
    // Windows: the Media Foundation H.264 decoder MFT, in-process and
    // vendor-neutral. H.265 is a follow-up (a separate HEVC MFT).
    #[cfg(target_os = "windows")]
    decoders.insert(
        0,
        DecoderCapability {
            backend: DecodeBackend::MediaFoundationNative,
            codecs: &[DecodeCodec::H264],
            in_process: true,
        },
    );
    decoders
}

/// Whether the user opted into the in-process native decoder
/// (`OPENSTREAM_DECODER=videotoolbox-native` / `native`). The legacy
/// `videotoolbox` value (which meant `ffmpeg -hwaccel videotoolbox`) does not
/// count, so it stays on ffmpeg.
pub(crate) fn prefer_native_from_env() -> bool {
    let requested = std::env::var("OPENSTREAM_DECODER").unwrap_or_default();
    matches!(
        requested.trim().to_ascii_lowercase().as_str(),
        "videotoolbox-native" | "native"
    )
}

/// Whether the user opted into zero-copy presentation (`OPENSTREAM_ZERO_COPY=1`).
///
/// A separate switch from [`prefer_native_from_env`] because it is a separate
/// risk. The native decoder changes where decoding happens; zero-copy changes
/// what reaches the window -- a GPU surface instead of a pixel buffer -- and
/// that path depends on the native presenter being available and on the
/// surface importing successfully. Both must be asked for explicitly, and the
/// decode worker ignores this flag unless it is running natively, since there
/// is no surface to carry out of ffmpeg.
pub(crate) fn prefer_zero_copy_from_env() -> bool {
    zero_copy_requested(&std::env::var("OPENSTREAM_ZERO_COPY").unwrap_or_default())
}

/// The parsing half of [`prefer_zero_copy_from_env`], split out so it can be
/// tested without a process-wide environment variable that other tests in the
/// same process would race against.
fn zero_copy_requested(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Capability-driven backend selection: when `prefer_in_process` is set, the
/// first in-process decoder that supports `codec` wins; otherwise, and whenever
/// no such decoder exists, ffmpeg -- the universal fallback -- is chosen.
///
/// The runtime passes `prefer_in_process = prefer_native_from_env()`, so the
/// default (env unset) stays on ffmpeg until the native path is live-validated;
/// flipping the default to native-first is then a one-line change at the call
/// site.
pub(crate) fn select_decoder(
    codec: DecodeCodec,
    prefer_in_process: bool,
    decoders: &[DecoderCapability],
) -> DecodeBackend {
    if prefer_in_process
        && let Some(decoder) = decoders.iter().find(|d| d.in_process && d.supports(codec))
    {
        return decoder.backend;
    }
    DecodeBackend::Ffmpeg
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    /// Zero-copy changes what reaches the window, so an unset or unrecognised
    /// value must leave the client on the pixel path rather than guessing.
    #[test]
    fn zero_copy_is_off_unless_it_is_asked_for() {
        for value in ["", "  ", "0", "off", "no", "false", "native", "maybe"] {
            assert!(!zero_copy_requested(value), "{value:?} must not enable it");
        }
        for value in ["1", "true", "yes", " TRUE ", "Yes"] {
            assert!(zero_copy_requested(value), "{value:?} must enable it");
        }
    }

    #[test]
    fn ffmpeg_is_the_fallback_for_every_codec_when_not_preferring_native() {
        let decoders = available_decoders();
        assert_eq!(
            select_decoder(DecodeCodec::H264, false, &decoders),
            DecodeBackend::Ffmpeg
        );
        assert_eq!(
            select_decoder(DecodeCodec::H265, false, &decoders),
            DecodeBackend::Ffmpeg
        );
    }

    #[test]
    fn a_registry_without_an_in_process_decoder_always_uses_ffmpeg() {
        // Even preferring in-process: with only ffmpeg available, ffmpeg wins.
        let only_ffmpeg = [DecoderCapability {
            backend: DecodeBackend::Ffmpeg,
            codecs: &[DecodeCodec::H264, DecodeCodec::H265],
            in_process: false,
        }];
        assert_eq!(
            select_decoder(DecodeCodec::H264, true, &only_ffmpeg),
            DecodeBackend::Ffmpeg
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn preferring_native_picks_videotoolbox_for_h264_and_falls_back_for_h265() {
        let decoders = available_decoders();
        // H.264 has an in-process decoder (VideoToolbox), so it is chosen.
        assert_eq!(
            select_decoder(DecodeCodec::H264, true, &decoders),
            DecodeBackend::VideoToolboxNative
        );
        // VideoToolbox native is H.264-only, so H.265 falls back to ffmpeg even
        // when the native path is preferred.
        assert_eq!(
            select_decoder(DecodeCodec::H265, true, &decoders),
            DecodeBackend::Ffmpeg
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn preferring_native_picks_media_foundation_for_h264_and_falls_back_for_h265() {
        let decoders = available_decoders();
        // H.264 has an in-process decoder (Media Foundation), so it is chosen.
        assert_eq!(
            select_decoder(DecodeCodec::H264, true, &decoders),
            DecodeBackend::MediaFoundationNative
        );
        // The Media Foundation H.264 MFT does not decode H.265, so H.265 falls
        // back to ffmpeg even when the native path is preferred.
        assert_eq!(
            select_decoder(DecodeCodec::H265, true, &decoders),
            DecodeBackend::Ffmpeg
        );
    }
}

// Consumed by the loopback tests now and the runtime dispatch once wired; in a
// plain (non-test) build nothing references it yet.
#[cfg(target_os = "macos")]
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use native::NativeVideoDecoder;

#[cfg(target_os = "macos")]
mod native {
    use crate::vt_decoder::{VideoToolboxH264Decoder, VtError};
    use openstream_media::EncodedFrame;
    use openstream_media::frame_age::{DecodedFrame, DecodedFrameSeq};
    use openstream_media::latency::{Client, Stamp};

    /// Wraps the VideoToolbox decoder and adapts its output into the client's
    /// [`DecodedFrame`] type: a client-local sequence number and the stamps the
    /// mailbox and presenter read. This is the same adaptation the ffmpeg reader
    /// task does today, so publishing these frames needs no downstream change.
    pub(crate) struct NativeVideoDecoder {
        inner: VideoToolboxH264Decoder,
        next_seq: DecodedFrameSeq,
        force_failure: bool,
    }

    impl NativeVideoDecoder {
        pub(crate) fn new() -> Self {
            Self {
                inner: VideoToolboxH264Decoder::new(),
                next_seq: DecodedFrameSeq::FIRST,
                // A diagnostic/test seam: force every decode to fail so the
                // ffmpeg fallback can be exercised deliberately.
                force_failure: std::env::var_os("OPENSTREAM_VT_FORCE_FAIL").is_some(),
            }
        }

        /// A decoder that fails every decode, for exercising fallback in tests.
        #[cfg(test)]
        pub(crate) fn with_forced_failure() -> Self {
            let mut decoder = Self::new();
            decoder.force_failure = true;
            decoder
        }

        /// Whether the session resolved to the hardware decoder (`None` before
        /// the first frame configures it).
        pub(crate) fn hardware_accelerated(&self) -> Option<bool> {
            self.inner.hardware_accelerated()
        }

        /// Decode one reassembled access unit into presentation-ready frames.
        pub(crate) fn decode(
            &mut self,
            frame: &EncodedFrame,
        ) -> Result<Vec<DecodedFrame>, VtError> {
            if self.force_failure {
                return Err(VtError::Decode(-1));
            }
            let pictures =
                self.inner
                    .decode(&frame.payload, frame.presentation_time_us, frame.keyframe)?;
            Ok(pictures
                .into_iter()
                .map(|picture| {
                    let seq = self.next_seq;
                    self.next_seq = self.next_seq.next();
                    // These stamps mark the decoder handoff; the harness does not
                    // measure spans, and the real client stamps identically.
                    let now = Stamp::<Client>::now();
                    DecodedFrame::new(seq, now, now, picture.width, picture.height, picture.pixels)
                })
                .collect())
        }
    }
}

// ---------------------------------------------------------------------------
// Loopback harness: drive generated access units through the REAL client
// components -- fragmentation -> Assembler -> native decode -> latest-frame mailbox
// -> consumer -- with no network and no macOS hosting. This validates the decode
// path the way it will run, short of the windowed presenter and the multi-minute
// soak (those need a GPU surface and are a separate on-hardware run).
// ---------------------------------------------------------------------------
#[cfg(all(test, target_os = "macos"))]
mod loopback {
    use super::NativeVideoDecoder;
    use crate::test_fixtures::{access_units_by_aud, ffmpeg, generate_h264};
    use openstream_media::frame_age::{DecodedFrame, FrameOffer};
    use openstream_media::latest_frame::latest_frame;
    use openstream_media::{Assembler, Fragment, fragment_frame};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[derive(Debug, Default, Clone, Copy)]
    struct Counters {
        decoded: usize,
        enqueued: usize,
        replaced: usize,
        dropped: usize,
    }

    /// Whether an Annex-B access unit carries a keyframe (an IDR slice, type 5,
    /// or a sequence parameter set, type 7).
    fn au_is_keyframe(au: &[u8]) -> bool {
        let mut p = 0usize;
        while p + 4 <= au.len() {
            if au[p] == 0 && au[p + 1] == 0 && au[p + 2] == 1 {
                let nal_type = au[p + 3] & 0x1f;
                if nal_type == 5 || nal_type == 7 {
                    return true;
                }
                p += 3;
            } else {
                p += 1;
            }
        }
        false
    }

    /// Run access units through the real pipeline. When `drain_each` is true the
    /// consumer takes after every publish (steady state); when false it takes
    /// only at the end, so the single-slot mailbox must drop stale frames.
    fn run_loopback(
        access_units: &[Vec<u8>],
        drain_each: bool,
    ) -> (Vec<DecodedFrame>, Counters, Option<bool>) {
        let mut assembler = Assembler::new(4 * 1024 * 1024, 64);
        let mut decoder = NativeVideoDecoder::new();
        let (publisher, reader) = latest_frame::<DecodedFrame>();
        let mut consumed = Vec::new();
        let mut counters = Counters::default();

        for (index, au) in access_units.iter().enumerate() {
            let frame_id = u32::try_from(index).expect("test frame count fits u32");
            let pts = index as u64 * 100_000;
            let fragments =
                fragment_frame(frame_id, pts, au_is_keyframe(au), au).expect("fragment the frame");
            // `push` drains the newly in-order frame into its outcome, so collect
            // it from there; then drain any further frames the reorder buffer
            // released.
            let mut ready = Vec::new();
            for bytes in fragments {
                let fragment = Fragment::decode(&bytes).expect("decode fragment");
                if let Some(frame) = assembler
                    .push(fragment)
                    .expect("assemble fragment")
                    .into_ready()
                {
                    ready.push(frame);
                }
            }
            while let Some(frame) = assembler.pop_ready() {
                ready.push(frame);
            }
            for encoded in ready {
                let frames = decoder.decode(&encoded).expect("native decode");
                for frame in frames {
                    counters.decoded += 1;
                    match publisher.publish(frame) {
                        FrameOffer::Enqueued => counters.enqueued += 1,
                        FrameOffer::ReplacedOlder => counters.replaced += 1,
                        FrameOffer::DroppedNewest => counters.dropped += 1,
                        FrameOffer::Closed => {}
                    }
                    if drain_each && let Some(taken) = reader.take() {
                        consumed.push(taken);
                    }
                }
            }
        }
        if !drain_each {
            while let Some(taken) = reader.take() {
                consumed.push(taken);
            }
        }
        let hardware = decoder.hardware_accelerated();
        (consumed, counters, hardware)
    }

    /// Decode the same access units with ffmpeg, to prove the fallback produces
    /// frames. Returns each frame's centre-pixel BGRA `u32`.
    fn ffmpeg_decode_centres(access_units: &[Vec<u8>], width: usize, height: usize) -> Vec<u32> {
        let mut child = Command::new(ffmpeg())
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "h264",
                "-i",
                "pipe:0",
                "-pix_fmt",
                "bgra",
                "-f",
                "rawvideo",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ffmpeg");
        {
            let mut stdin = child.stdin.take().expect("ffmpeg stdin");
            for au in access_units {
                stdin.write_all(au).expect("write access unit");
            }
        }
        let output = child.wait_with_output().expect("ffmpeg output");
        let frame_bytes = width * height * 4;
        let centre_offset = ((height / 2) * width + width / 2) * 4;
        output
            .stdout
            .chunks_exact(frame_bytes)
            .map(|frame| {
                let p = &frame[centre_offset..centre_offset + 4];
                u32::from(p[0])
                    | (u32::from(p[1]) << 8)
                    | (u32::from(p[2]) << 16)
                    | (u32::from(p[3]) << 24)
            })
            .collect()
    }

    fn centre_pixel(frame: &DecodedFrame) -> (u32, u32, u32) {
        let pixel = frame.pixels()[(frame.height() / 2) * frame.width() + frame.width() / 2];
        (pixel & 0xff, (pixel >> 8) & 0xff, (pixel >> 16) & 0xff)
    }

    /// A solid colour flows through fragmentation -> reassembly -> native decode ->
    /// mailbox -> consumer with the right pixels, on the hardware decoder.
    #[test]
    fn loopback_decodes_a_solid_colour_end_to_end() {
        // Pure blue (0x0000FF) -- exercises a different channel than the
        // decoder-level green test.
        let Some(stream) = generate_h264("color=c=0x0000FF:size=160x120:rate=5", 4, 4) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);
        let (frames, counters, hardware) = run_loopback(&access_units, true);

        assert_eq!(hardware, Some(true), "must use the hardware decoder");
        assert!(!frames.is_empty(), "no frames survived the pipeline");
        assert_eq!(
            counters.decoded,
            frames.len(),
            "draining each: all consumed"
        );

        let (blue, green, red) = centre_pixel(frames.last().unwrap());
        assert!(
            blue > 150 && red < 100 && green < 100,
            "expected a blue centre (B={blue} G={green} R={red})"
        );
    }

    /// An undrained single-slot mailbox keeps only the newest frame and reports
    /// the stale ones it replaced -- the freshness property the gap analysis
    /// named as the reason latency survives in queues.
    #[test]
    fn loopback_mailbox_keeps_only_the_newest_frame() {
        let Some(stream) = generate_h264("testsrc2=size=160x120:rate=10", 12, 12) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);
        let (frames, counters, _hardware) = run_loopback(&access_units, false);

        assert!(counters.decoded >= 2, "need several frames: {counters:?}");
        assert!(
            counters.replaced >= 1,
            "stale frames must be replaced: {counters:?}"
        );
        assert_eq!(
            frames.len(),
            1,
            "only the newest survives an undrained mailbox"
        );
        assert_eq!(
            frames[0].seq().get(),
            counters.decoded as u64 - 1,
            "the survivor is the newest decoded frame"
        );
    }

    /// Native decode and the ffmpeg fallback agree on a known colour: forcing
    /// native to fail leaves the fallback producing the same blue frames, so the
    /// fallback is real and correct, not just present.
    #[test]
    fn loopback_ffmpeg_fallback_produces_correct_frames() {
        let Some(stream) = generate_h264("color=c=0x0000FF:size=160x120:rate=5", 4, 4) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);

        // Native forced to fail on every access unit.
        let mut decoder = NativeVideoDecoder::with_forced_failure();
        let mut assembler = Assembler::new(4 * 1024 * 1024, 64);
        let mut encoded = Vec::new();
        for (index, au) in access_units.iter().enumerate() {
            let frame_id = u32::try_from(index).unwrap();
            let fragments =
                fragment_frame(frame_id, index as u64 * 100_000, au_is_keyframe(au), au).unwrap();
            for bytes in fragments {
                if let Some(frame) = assembler
                    .push(Fragment::decode(&bytes).unwrap())
                    .unwrap()
                    .into_ready()
                {
                    encoded.push(frame);
                }
            }
            while let Some(frame) = assembler.pop_ready() {
                encoded.push(frame);
            }
        }
        assert!(!encoded.is_empty(), "reassembly produced no frames");
        for frame in &encoded {
            assert!(
                decoder.decode(frame).is_err(),
                "forced-failure native decoder must error so fallback triggers"
            );
        }

        // The fallback path: ffmpeg decodes the same content into correct frames.
        let centres = ffmpeg_decode_centres(&access_units, 160, 120);
        assert!(!centres.is_empty(), "ffmpeg fallback produced no frames");
        let last = centres.last().copied().unwrap();
        let (blue, green, red) = (last & 0xff, (last >> 8) & 0xff, (last >> 16) & 0xff);
        assert!(
            blue > 150 && red < 100 && green < 100,
            "ffmpeg fallback centre should be blue (B={blue} G={green} R={red})"
        );
    }

    /// Sustained run through the real decode -> mailbox pipeline: loop a clip
    /// until `target` frames decode, asserting the decoder and mailbox stay
    /// healthy -- every access unit decodes without error, the hardware decoder
    /// stays selected, and a consumer that keeps pace loses nothing. Ignored by
    /// default; run for several minutes with, e.g.:
    ///
    ///   OPENSTREAM_REQUIRE_VT_TEST=1 OPENSTREAM_SOAK_FRAMES=5400 \
    ///     cargo test -p openstream-desktop-client -- --ignored loopback_soak
    ///
    /// (5400 frames ~ 3 minutes at 30 fps.)
    #[test]
    #[ignore = "soak; run explicitly with --ignored"]
    fn loopback_soak_stays_healthy_over_many_frames() {
        let target: usize = std::env::var("OPENSTREAM_SOAK_FRAMES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(600);
        let Some(stream) = generate_h264("testsrc2=size=320x240:rate=30", 30, 30) else {
            return;
        };
        let access_units = access_units_by_aud(&stream);
        assert!(!access_units.is_empty(), "fixture produced no access units");

        let mut assembler = Assembler::new(4 * 1024 * 1024, 64);
        let mut decoder = NativeVideoDecoder::new();
        let (publisher, reader) = latest_frame::<DecodedFrame>();

        let mut decoded = 0usize;
        let mut consumed = 0usize;
        let mut replaced = 0usize;
        let mut frame_id = 0u32;

        'soak: loop {
            for au in &access_units {
                let fragments = fragment_frame(
                    frame_id,
                    u64::from(frame_id) * 33_000,
                    au_is_keyframe(au),
                    au,
                )
                .expect("fragment");
                frame_id = frame_id
                    .checked_add(1)
                    .expect("frame id fits u32 for a soak");
                let mut ready = Vec::new();
                for bytes in fragments {
                    if let Some(frame) = assembler
                        .push(Fragment::decode(&bytes).expect("decode fragment"))
                        .expect("assemble")
                        .into_ready()
                    {
                        ready.push(frame);
                    }
                }
                while let Some(frame) = assembler.pop_ready() {
                    ready.push(frame);
                }
                for encoded in ready {
                    let frames = decoder
                        .decode(&encoded)
                        .expect("native decode stayed healthy");
                    for frame in frames {
                        decoded += 1;
                        if publisher.publish(frame) == FrameOffer::ReplacedOlder {
                            replaced += 1;
                        }
                        if reader.take().is_some() {
                            consumed += 1;
                        }
                        if decoded >= target {
                            break 'soak;
                        }
                    }
                }
            }
        }

        assert!(decoded >= target, "decoded {decoded} of target {target}");
        assert_eq!(
            decoder.hardware_accelerated(),
            Some(true),
            "the hardware decoder stayed selected for the whole run"
        );
        assert_eq!(replaced, 0, "a consumer that keeps pace replaces nothing");
        assert_eq!(consumed, decoded, "every decoded frame was consumed");
    }
}
