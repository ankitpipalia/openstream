//! In-process video source for the Windows host: no FFmpeg.
//!
//! Desktop Duplication captures the desktop, the frame is scaled to the
//! negotiated size and converted to NV12, and the Media Foundation H.264
//! encoder turns it into access units -- all inside this process on a
//! dedicated thread, the way Parsec-class hosts work. Selected with
//! `OPENSTREAM_CAPTURE_BACKEND=native`.
//!
//! The pipeline itself is Windows-only. Backend selection, scaling and
//! access-unit framing are pure and unit-tested on every target.

use std::borrow::Cow;

/// Backend names that select the in-process pipeline.
pub(crate) fn selects_native(backend: &str) -> bool {
    matches!(
        backend.trim().to_ascii_lowercase().as_str(),
        "native" | "desktop-duplication" | "dxgi"
    )
}

/// Annex-B access unit delimiter (NAL type 9), the boundary marker the FFmpeg
/// path inserts too, so clients see one stream shape from both sources.
const ACCESS_UNIT_DELIMITER: [u8; 6] = [0, 0, 0, 1, 0x09, 0xF0];

/// Frame one encoder access unit for the wire: delimiter, then on keyframes
/// the SPS/PPS (the encoder publishes them out of band, and a client must be
/// able to start at any keyframe), then the slices.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn frame_access_unit(
    data: &[u8],
    keyframe: bool,
    sequence_header: Option<&[u8]>,
) -> Vec<u8> {
    let header = if keyframe {
        sequence_header.unwrap_or(&[])
    } else {
        &[]
    };
    let mut unit = Vec::with_capacity(ACCESS_UNIT_DELIMITER.len() + header.len() + data.len());
    unit.extend_from_slice(&ACCESS_UNIT_DELIMITER);
    unit.extend_from_slice(header);
    unit.extend_from_slice(data);
    unit
}

/// Resize a tightly packed BGRA frame (4 bytes per pixel) to `dst_width` x
/// `dst_height`. The same size borrows the input; an exact 2:1 reduction
/// (capture at native resolution, stream at half) averages each 2x2 block;
/// anything else is nearest-neighbour, which is cheap and never reads out of
/// bounds.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn scale_bgra<'a>(
    src: &'a [u8],
    src_width: usize,
    src_height: usize,
    dst_width: usize,
    dst_height: usize,
) -> Cow<'a, [u8]> {
    if (src_width, src_height) == (dst_width, dst_height) {
        return Cow::Borrowed(&src[..src_width * src_height * 4]);
    }
    let mut dst = vec![0u8; dst_width * dst_height * 4];
    if src_width == dst_width * 2 && src_height == dst_height * 2 {
        for row in 0..dst_height {
            for col in 0..dst_width {
                let top = ((row * 2) * src_width + col * 2) * 4;
                let bottom = top + src_width * 4;
                let out = (row * dst_width + col) * 4;
                for channel in 0..3 {
                    let sum = u32::from(src[top + channel])
                        + u32::from(src[top + 4 + channel])
                        + u32::from(src[bottom + channel])
                        + u32::from(src[bottom + 4 + channel]);
                    dst[out + channel] = u8::try_from((sum + 2) / 4).unwrap_or(u8::MAX);
                }
                dst[out + 3] = 0xFF;
            }
        }
    } else {
        for row in 0..dst_height {
            let src_row = row * src_height / dst_height.max(1);
            for col in 0..dst_width {
                let src_col = col * src_width / dst_width.max(1);
                let from = (src_row * src_width + src_col) * 4;
                let to = (row * dst_width + col) * 4;
                dst[to..to + 4].copy_from_slice(&src[from..from + 4]);
            }
        }
    }
    Cow::Owned(dst)
}

#[cfg(windows)]
pub(crate) use pipeline::{NativeConfig, NativePipeline};

#[cfg(windows)]
mod pipeline {
    use std::sync::mpsc as std_mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use openstream_windows_host::capture::{CaptureError, DesktopDuplication};
    use openstream_windows_media::{
        MediaFoundationH264Encoder, bgra_bytes_to_nv12, prepare_media_thread,
    };
    use tokio::sync::{mpsc, oneshot};

    use super::{frame_access_unit, scale_bgra};

    /// How long a static desktop goes before the last frame is re-sent, so the
    /// client keeps receiving pictures and the host's frame counter advances.
    const KEEPALIVE: Duration = Duration::from_millis(1000);
    /// Complete access units queued for the streaming loop before capture
    /// backs off. Small on purpose: a deep queue is latency.
    const QUEUE_DEPTH: usize = 8;

    /// What the pipeline captures and encodes.
    #[derive(Debug, Clone)]
    pub(crate) struct NativeConfig {
        pub(crate) width: u32,
        pub(crate) height: u32,
        pub(crate) fps: u32,
        pub(crate) bitrate_bps: u32,
        /// DXGI output to duplicate; `None` is the first attached output.
        pub(crate) output_index: Option<usize>,
    }

    enum Control {
        Reconfigure {
            bitrate_bps: u32,
            force_keyframe: bool,
            reply: oneshot::Sender<Result<(), String>>,
        },
        Stop,
    }

    /// Handle to the capture/encode thread: access units come out of
    /// [`NativePipeline::next_unit`]; keyframe and bitrate changes go in
    /// through [`NativePipeline::reconfigure`].
    pub(crate) struct NativePipeline {
        units: mpsc::Receiver<Vec<u8>>,
        control: std_mpsc::Sender<Control>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl NativePipeline {
        /// Open capture and the encoder on the worker thread (which owns the
        /// COM objects) and start streaming. An open failure is returned here,
        /// synchronously, rather than logged from the thread.
        pub(crate) fn start(config: NativeConfig) -> Result<Self, String> {
            let (units_tx, units_rx) = mpsc::channel(QUEUE_DEPTH);
            let (control_tx, control_rx) = std_mpsc::channel();
            let (ready_tx, ready_rx) = std_mpsc::channel::<Result<String, String>>();
            let worker = thread::Builder::new()
                .name("openstream-native-video".into())
                .spawn(move || {
                    let worker = match Worker::open(config) {
                        Ok(worker) => {
                            let _ = ready_tx.send(Ok(worker.describe()));
                            worker
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    };
                    worker.run(&units_tx, &control_rx);
                })
                .map_err(|error| format!("could not start the native video thread: {error}"))?;
            match ready_rx.recv() {
                Ok(Ok(description)) => {
                    eprintln!("OpenStream native video: {description}");
                    Ok(Self {
                        units: units_rx,
                        control: control_tx,
                        worker: Some(worker),
                    })
                }
                Ok(Err(error)) => {
                    let _ = worker.join();
                    Err(error)
                }
                Err(_) => {
                    let _ = worker.join();
                    Err("the native video thread exited before it was ready".into())
                }
            }
        }

        /// The next complete access unit, or `None` once the thread is gone.
        pub(crate) async fn next_unit(&mut self) -> Option<Vec<u8>> {
            self.units.recv().await
        }

        /// Apply a new bitrate and/or force the next frame to be a keyframe.
        /// Resolves once the worker has applied it (or failed to).
        pub(crate) async fn reconfigure(
            &mut self,
            bitrate_bps: u32,
            force_keyframe: bool,
        ) -> Result<(), String> {
            let (reply, done) = oneshot::channel();
            self.control
                .send(Control::Reconfigure {
                    bitrate_bps,
                    force_keyframe,
                    reply,
                })
                .map_err(|_| "the native video thread is gone".to_string())?;
            done.await
                .map_err(|_| "the native video thread dropped a reconfigure request".to_string())?
        }

        /// Stop the thread and wait for it. Closing the unit queue first
        /// unblocks a worker waiting to hand over a frame.
        pub(crate) fn stop(&mut self) {
            self.units.close();
            let _ = self.control.send(Control::Stop);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    impl Drop for NativePipeline {
        fn drop(&mut self) {
            self.stop();
        }
    }

    struct Worker {
        config: NativeConfig,
        width_px: usize,
        height_px: usize,
        duplication: DesktopDuplication,
        encoder: MediaFoundationH264Encoder,
        sequence_header: Option<Vec<u8>>,
        epoch: Instant,
        interval: Duration,
        /// Latest captured frame, scaled, not yet encoded.
        pending: Option<Vec<u8>>,
        /// Last frame handed to the encoder, for keepalive and forced keyframes.
        last_frame: Option<Vec<u8>>,
        last_encode: Option<Instant>,
        conversion_threads: usize,
        encoded: u64,
    }

    impl Worker {
        fn open(config: NativeConfig) -> Result<Self, String> {
            prepare_media_thread().map_err(|error| format!("media foundation startup: {error}"))?;
            let duplication = DesktopDuplication::new(config.output_index)
                .map_err(|error| format!("desktop duplication: {error}"))?;
            let encoder = Self::create_encoder(&config)?;
            // Leave cores for the encoder's own threads.
            let conversion_threads =
                thread::available_parallelism().map_or(2, |count| (count.get() / 2).clamp(1, 6));
            Ok(Self {
                width_px: config.width as usize,
                height_px: config.height as usize,
                interval: Duration::from_micros(1_000_000 / u64::from(config.fps.max(1))),
                config,
                duplication,
                encoder,
                sequence_header: None,
                epoch: Instant::now(),
                pending: None,
                last_frame: None,
                last_encode: None,
                conversion_threads,
                encoded: 0,
            })
        }

        fn create_encoder(config: &NativeConfig) -> Result<MediaFoundationH264Encoder, String> {
            MediaFoundationH264Encoder::new(
                config.width,
                config.height,
                config.fps,
                config.bitrate_bps,
            )
            .map_err(|error| format!("media foundation h264 encoder: {error}"))
        }

        fn describe(&self) -> String {
            format!(
                "Desktop Duplication -> Media Foundation H.264, {}x{} @ {} fps, {:.2} Mbps, low-latency codec mode {}, {} conversion threads",
                self.config.width,
                self.config.height,
                self.config.fps,
                f64::from(self.config.bitrate_bps) / 1_000_000.0,
                if self.encoder.low_latency_configured() {
                    "on"
                } else {
                    "unavailable"
                },
                self.conversion_threads
            )
        }

        fn run(mut self, units: &mpsc::Sender<Vec<u8>>, control: &std_mpsc::Receiver<Control>) {
            self.stream(units, control);
            eprintln!(
                "OpenStream native video: stopped after {} access units",
                self.encoded
            );
        }

        fn stream(&mut self, units: &mpsc::Sender<Vec<u8>>, control: &std_mpsc::Receiver<Control>) {
            let timeout_ms = u32::try_from(self.interval.as_millis())
                .unwrap_or(16)
                .max(1);
            loop {
                while let Ok(command) = control.try_recv() {
                    match command {
                        Control::Stop => return,
                        Control::Reconfigure {
                            bitrate_bps,
                            force_keyframe,
                            reply,
                        } => {
                            let _ = reply.send(self.reconfigure(bitrate_bps, force_keyframe));
                        }
                    }
                }
                match self.duplication.capture(timeout_ms) {
                    Ok(frame) => {
                        let scaled = scale_bgra(
                            &frame.bgra,
                            frame.width,
                            frame.height,
                            self.width_px,
                            self.height_px,
                        )
                        .into_owned();
                        self.pending = Some(scaled);
                    }
                    // Nothing changed on the desktop within a frame interval.
                    Err(CaptureError::Timeout) => {}
                    Err(CaptureError::AccessLost) => {
                        if let Err(error) = self.duplication.recover() {
                            eprintln!("OpenStream native capture could not recover: {error}");
                            thread::sleep(Duration::from_millis(200));
                        }
                        continue;
                    }
                    Err(error) => {
                        eprintln!("OpenStream native capture failed: {error}; reopening");
                        thread::sleep(Duration::from_millis(250));
                        match DesktopDuplication::new(self.config.output_index) {
                            Ok(duplication) => self.duplication = duplication,
                            Err(error) => {
                                eprintln!("OpenStream native capture reopen failed: {error}");
                            }
                        }
                        continue;
                    }
                }
                let now = Instant::now();
                // Pace to the negotiated rate: the desktop may refresh faster
                // than the client asked for.
                let due = self
                    .last_encode
                    .is_none_or(|last| now.duration_since(last) >= self.interval.mul_f32(0.9));
                if !due {
                    continue;
                }
                if let Some(frame) = self.pending.take() {
                    if !self.encode(&frame, units) {
                        return;
                    }
                    self.last_frame = Some(frame);
                } else if self
                    .last_encode
                    .is_some_and(|last| now.duration_since(last) >= KEEPALIVE)
                    && let Some(frame) = self.last_frame.clone()
                    && !self.encode(&frame, units)
                {
                    return;
                }
            }
        }

        /// Convert and encode one frame, handing every access unit to the
        /// loop. Returns `false` once the loop has gone away.
        fn encode(&mut self, bgra: &[u8], units: &mpsc::Sender<Vec<u8>>) -> bool {
            let nv12 =
                bgra_bytes_to_nv12(bgra, self.width_px, self.height_px, self.conversion_threads);
            let pts_us = i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX);
            let encoded = match self.encoder.encode(&nv12, pts_us) {
                Ok(encoded) => encoded,
                Err(error) => {
                    eprintln!("OpenStream native encode failed: {error}; recreating the encoder");
                    if let Err(error) = self.recreate_encoder() {
                        eprintln!("OpenStream native encoder could not be recreated: {error}");
                        thread::sleep(Duration::from_millis(250));
                    }
                    return true;
                }
            };
            self.last_encode = Some(Instant::now());
            for unit in encoded {
                if unit.keyframe
                    && let Some(header) = self.encoder.sequence_header()
                {
                    self.sequence_header = Some(header);
                }
                let payload =
                    frame_access_unit(&unit.data, unit.keyframe, self.sequence_header.as_deref());
                if units.blocking_send(payload).is_err() {
                    return false;
                }
                self.encoded += 1;
            }
            true
        }

        fn reconfigure(&mut self, bitrate_bps: u32, force_keyframe: bool) -> Result<(), String> {
            let mut in_place = true;
            if bitrate_bps != self.config.bitrate_bps {
                in_place = self.encoder.set_bitrate(bitrate_bps).is_ok();
            }
            if in_place && force_keyframe {
                in_place = self.encoder.force_keyframe().is_ok();
            }
            self.config.bitrate_bps = bitrate_bps;
            if !in_place {
                // The codec API refused the live change; a fresh encoder
                // starts with a keyframe at the new rate.
                self.recreate_encoder()?;
            }
            if force_keyframe {
                // The client asked for a picture: send one now even if the
                // desktop is static.
                if self.pending.is_none() {
                    self.pending = self.last_frame.clone();
                }
                self.last_encode = None;
            }
            Ok(())
        }

        fn recreate_encoder(&mut self) -> Result<(), String> {
            self.encoder = Self::create_encoder(&self.config)?;
            self.sequence_header = None;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_backend_names_are_recognised_case_insensitively() {
        for name in ["native", " Native ", "desktop-duplication", "DXGI"] {
            assert!(selects_native(name), "{name:?}");
        }
        for name in ["", "gdigrab", "x11grab", "ffmpeg", "nativex"] {
            assert!(!selects_native(name), "{name:?}");
        }
    }

    #[test]
    fn keyframes_carry_the_delimiter_and_parameter_sets_before_the_slices() {
        let sps_pps = [0, 0, 0, 1, 0x67, 0xAA, 0, 0, 0, 1, 0x68, 0xBB];
        let idr = [0, 0, 0, 1, 0x65, 0x01, 0x02];
        let unit = frame_access_unit(&idr, true, Some(&sps_pps));
        let mut expected = ACCESS_UNIT_DELIMITER.to_vec();
        expected.extend_from_slice(&sps_pps);
        expected.extend_from_slice(&idr);
        assert_eq!(unit, expected);
    }

    #[test]
    fn non_keyframes_get_only_the_delimiter() {
        let slice = [0, 0, 0, 1, 0x41, 0x9A];
        let unit = frame_access_unit(&slice, false, Some(&[0, 0, 0, 1, 0x67]));
        let mut expected = ACCESS_UNIT_DELIMITER.to_vec();
        expected.extend_from_slice(&slice);
        assert_eq!(unit, expected);
    }

    #[test]
    fn a_keyframe_without_published_parameter_sets_is_still_framed() {
        let idr = [0, 0, 0, 1, 0x65];
        let unit = frame_access_unit(&idr, true, None);
        assert_eq!(unit.len(), ACCESS_UNIT_DELIMITER.len() + idr.len());
    }

    fn pixel(b: u8, g: u8, r: u8) -> [u8; 4] {
        [b, g, r, 0xFF]
    }

    #[test]
    fn same_size_scaling_borrows_the_input() {
        let src: Vec<u8> = [pixel(1, 2, 3), pixel(4, 5, 6)].concat();
        let out = scale_bgra(&src, 2, 1, 2, 1);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), src.as_slice());
    }

    #[test]
    fn exact_halving_averages_each_two_by_two_block() {
        // 4x2 source -> 2x1: left block is four different pixels, right block
        // is solid.
        let row0 = [
            pixel(0, 0, 0),
            pixel(40, 80, 120),
            pixel(9, 9, 9),
            pixel(9, 9, 9),
        ]
        .concat();
        let row1 = [
            pixel(80, 160, 240),
            pixel(120, 240, 0),
            pixel(9, 9, 9),
            pixel(9, 9, 9),
        ]
        .concat();
        let src = [row0, row1].concat();
        let out = scale_bgra(&src, 4, 2, 2, 1).into_owned();
        assert_eq!(out.len(), 2 * 4);
        // (0+40+80+120)/4 = 60, (0+80+160+240)/4 = 120, (0+120+240+0)/4 = 90.
        assert_eq!(&out[0..4], &pixel(60, 120, 90));
        assert_eq!(&out[4..8], &pixel(9, 9, 9));
    }

    #[test]
    fn other_ratios_use_nearest_neighbour_without_reading_out_of_bounds() {
        // 3x3 -> 2x2 picks source columns 0 and 1, rows 0 and 1.
        let mut src = Vec::new();
        for row in 0..3u8 {
            for col in 0..3u8 {
                src.extend_from_slice(&pixel(col, row, 0));
            }
        }
        let out = scale_bgra(&src, 3, 3, 2, 2).into_owned();
        assert_eq!(out.len(), 2 * 2 * 4);
        assert_eq!(&out[0..4], &pixel(0, 0, 0));
        assert_eq!(&out[4..8], &pixel(1, 0, 0));
        assert_eq!(&out[8..12], &pixel(0, 1, 0));
        assert_eq!(&out[12..16], &pixel(1, 1, 0));
        // Upscaling reads only valid source pixels too.
        let up = scale_bgra(&src, 3, 3, 7, 5).into_owned();
        assert_eq!(up.len(), 7 * 5 * 4);
    }
}
