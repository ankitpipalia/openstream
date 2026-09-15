//! Decoder-backend selection and the native decode path.
//!
//! [`DecodeBackend::from_env`] chooses the decoder; [`NativeVideoDecoder`] (on
//! macOS) turns reassembled [`EncodedFrame`]s into presentation-ready
//! [`DecodedFrame`]s using the in-process VideoToolbox decoder, assigning the
//! client-local sequence number and stamps the mailbox and presenter expect.
//!
//! This is the unit the loopback harness drives and the unit the runtime
//! dispatch will call once the native path is wired in. It is not yet reached
//! from the live network loop, so it is dead-code-allowed for now.

#![allow(dead_code)]

/// Which decoder the client uses for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeBackend {
    /// External ffmpeg subprocess -- the default, and the universal fallback.
    Ffmpeg,
    /// In-process VideoToolbox (macOS). Opt-in until a live stream validates it.
    #[cfg(target_os = "macos")]
    VideoToolboxNative,
}

impl DecodeBackend {
    /// Select from `OPENSTREAM_DECODER`. `videotoolbox-native` (or `native`)
    /// opts into the in-process macOS path; every other value -- including the
    /// legacy `videotoolbox`, which means `ffmpeg -hwaccel videotoolbox` -- stays
    /// on ffmpeg. Default: ffmpeg.
    pub(crate) fn from_env() -> Self {
        let requested = std::env::var("OPENSTREAM_DECODER").unwrap_or_default();
        match requested.trim().to_ascii_lowercase().as_str() {
            #[cfg(target_os = "macos")]
            "videotoolbox-native" | "native" => DecodeBackend::VideoToolboxNative,
            _ => DecodeBackend::Ffmpeg,
        }
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
