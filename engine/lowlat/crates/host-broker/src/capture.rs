//! The Linux capture-and-encode [`FrameSource`], backed by the native
//! `lowlat` pipeline (DRM/KMS scanout -> GPU convert -> hardware H.264).
//!
//! `lowlat`'s `Stream` is synchronous and its `SeatHold` borrows the `Stream`,
//! so the two cannot be stored together in one value. The pipeline therefore
//! runs on its own thread -- exactly the model `lowlat` is built for -- and this
//! type is the handle to it: `open` spawns the thread, `next_frame` pulls
//! encoded access units it has queued, and the control methods send it commands.
//! Nothing raw crosses a thread or process boundary; only encoded bytes do.

#![cfg(target_os = "linux")]

use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lowlat::stream::{Codec, Config, Quality, Stream};
use lowlat_core::video::Rotation;
use lowlat_net::Wake;
use openstream_host_ipc::lifecycle::{CaptureKind, Seat};
use openstream_host_ipc::protocol::CaptureParams;

use crate::device::{CaptureFailure, EncodedFrame, FrameSource, OpenedCapture};

/// Reason codes for [`CaptureFailure`] originating in the capture thread.
mod fail {
    /// The lowlat pipeline had no free seat (commonly the DRM scanout is not
    /// reachable -- missing `CAP_SYS_ADMIN`, or nothing lit on the seat).
    pub(super) const NO_SEAT: u16 = 1;
    /// The wake primitive the seat needs could not be created.
    pub(super) const NO_WAKE: u16 = 2;
}

/// A command sent to the capture thread.
enum Command {
    SetBitrate(u32),
    Keyframe,
    Close,
}

/// The native capture source: a handle to a running (or idle) capture thread.
#[derive(Debug, Default)]
pub struct NativeFrameSource {
    running: Option<Running>,
}

struct Running {
    frames: Receiver<EncodedFrame>,
    commands: Sender<Command>,
    join: Option<JoinHandle<()>>,
    geometry: OpenedCapture,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("geometry", &self.geometry)
            .finish_non_exhaustive()
    }
}

impl NativeFrameSource {
    /// An idle source. Call [`FrameSource::open`] to start capturing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            // Ask the thread to stop, then drop the frame receiver so a thread
            // blocked on a send wakes, then join it so the DRM device and the
            // encoder are released before a possible re-open.
            let _ = running.commands.send(Command::Close);
            drop(running.frames);
            if let Some(join) = running.join.take() {
                let _ = join.join();
            }
        }
    }
}

impl FrameSource for NativeFrameSource {
    fn open(&mut self, params: CaptureParams) -> Result<OpenedCapture, CaptureFailure> {
        self.stop();
        let (frame_tx, frame_rx) = channel::<EncodedFrame>();
        let (command_tx, command_rx) = channel::<Command>();
        let (ready_tx, ready_rx) = channel::<Result<OpenedCapture, CaptureFailure>>();

        let join = std::thread::Builder::new()
            .name("openstream-capture".to_string())
            .spawn(move || capture_loop(params, &frame_tx, &command_rx, &ready_tx))
            .map_err(|error| {
                CaptureFailure::new(fail::NO_WAKE, format!("capture thread: {error}"))
            })?;

        // Wait for the thread to open the pipeline and report the real geometry
        // (or why it could not start).
        match ready_rx.recv() {
            Ok(Ok(geometry)) => {
                self.running = Some(Running {
                    frames: frame_rx,
                    commands: command_tx,
                    join: Some(join),
                    geometry,
                });
                Ok(geometry)
            }
            Ok(Err(failure)) => {
                let _ = join.join();
                Err(failure)
            }
            Err(_) => {
                let _ = join.join();
                Err(CaptureFailure::new(
                    fail::NO_SEAT,
                    "capture thread exited before reporting readiness",
                ))
            }
        }
    }

    fn switch(&mut self, seat: Seat, kind: CaptureKind) -> Result<OpenedCapture, CaptureFailure> {
        // v1 captures the DRM scanout, which already follows the active session
        // across a login, so a greeter<->user switch only needs a keyframe so
        // the client's decoder resets against the new content. A PipeWire switch
        // (the session-agent handoff) is not yet implemented, so it also stays
        // on the scanout for now rather than failing the session.
        let _ = (seat, kind);
        match &self.running {
            Some(running) => {
                let _ = running.commands.send(Command::Keyframe);
                Ok(running.geometry)
            }
            None => Err(CaptureFailure::new(
                fail::NO_SEAT,
                "switch requested with no capture open",
            )),
        }
    }

    fn set_bitrate(&mut self, kbps: u32) {
        if let Some(running) = &self.running {
            let _ = running.commands.send(Command::SetBitrate(kbps));
        }
    }

    fn request_keyframe(&mut self) {
        if let Some(running) = &self.running {
            let _ = running.commands.send(Command::Keyframe);
        }
    }

    fn next_frame(&mut self) -> Option<EncodedFrame> {
        let running = self.running.as_ref()?;
        match running.frames.try_recv() {
            Ok(frame) => Some(frame),
            Err(TryRecvError::Empty) => None,
            // The thread ended; surface nothing and let the next control call or
            // a later open notice. Dropping here keeps next_frame non-blocking.
            Err(TryRecvError::Disconnected) => None,
        }
    }

    fn close(&mut self) {
        self.stop();
    }
}

impl Drop for NativeFrameSource {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the lowlat `Config` for a video-only capture at the requested
/// geometry and bitrate. Mirrors the native host adapter's configuration, with
/// audio off (the broker streams video; audio can be added later).
fn build_config(params: CaptureParams) -> Config {
    let mbps = f64::from(params.bitrate_kbps) / 1000.0;
    Config {
        audio: None,
        accept_microphone: false,
        audio_on: false,
        audio_kbps: 128,
        allow_raw_audio: false,
        codec: Codec::H264,
        backend: None,
        prefer_vulkan: false,
        width: u32::from(params.width),
        height: u32::from(params.height),
        fps: u32::from(params.fps),
        configured_mbps: mbps,
        min_mbps: mbps,
        rotation: Rotation::None,
        detail_rows: 0,
        output: None,
        convert: None,
        display: true,
        full_fps: false,
        quality: Quality::default(),
        cg_level: 1,
    }
}

/// The capture thread body: start the pipeline, report readiness, then loop
/// applying commands and forwarding encoded frames until asked to stop or the
/// consumer goes away.
fn capture_loop(
    params: CaptureParams,
    frames: &Sender<EncodedFrame>,
    commands: &Receiver<Command>,
    ready: &Sender<Result<OpenedCapture, CaptureFailure>>,
) {
    let stream = Stream::start(build_config(params));
    let wake = match Wake::new() {
        Ok(wake) => wake,
        Err(error) => {
            let _ = ready.send(Err(CaptureFailure::new(
                fail::NO_WAKE,
                format!("wake: {error}"),
            )));
            return;
        }
    };
    let (video_wake, audio_wake) = match (wake.handle(), wake.handle()) {
        (Ok(video), Ok(audio)) => (video, audio),
        _ => {
            let _ = ready.send(Err(CaptureFailure::new(fail::NO_WAKE, "wake handle")));
            return;
        }
    };
    let seat = match stream.seats().take(video_wake, audio_wake) {
        Some(seat) => seat,
        None => {
            let _ = ready.send(Err(CaptureFailure::new(
                fail::NO_SEAT,
                "no free lowlat seat (is the DRM scanout reachable?)",
            )));
            return;
        }
    };

    let geometry = OpenedCapture {
        width: params.width,
        height: params.height,
    };
    if ready.send(Ok(geometry)).is_err() {
        return;
    }

    let started = Instant::now();
    let mut sequence = 0_u32;
    loop {
        // Apply every pending command first, so a bitrate change or a close is
        // acted on without waiting for the next frame.
        loop {
            match commands.try_recv() {
                Ok(Command::SetBitrate(kbps)) => {
                    let mut video = stream.video();
                    video.bitrate_mbps = f64::from(kbps) / 1000.0;
                    stream.set_video(video);
                }
                Ok(Command::Keyframe) => seat.request_refresh(),
                Ok(Command::Close) | Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }

        let mut idle = true;
        while let Some(frame) = seat.next_frame() {
            idle = false;
            let timestamp_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let encoded = EncodedFrame {
                sequence,
                timestamp_us,
                keyframe: frame.keyframe(),
                data: frame.bytes().to_vec(),
            };
            sequence = sequence.wrapping_add(1);
            if frames.send(encoded).is_err() {
                // The broker dropped the receiver: the connection is gone.
                return;
            }
        }
        if idle {
            // Nothing ready; yield briefly rather than spin. The pipeline paces
            // real frame production on its own threads.
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
