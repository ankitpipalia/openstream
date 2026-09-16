//! The two device abstractions the broker drives: a capture-and-encode
//! [`FrameSource`] and an [`InputSink`].
//!
//! The protocol-handling core ([`crate::session`]) is written entirely against
//! these traits, so it is exercised on any platform with the in-file fakes,
//! while the real implementations -- DRM scanout capture through `lowlat-host`
//! and `uinput` injection through `lowlat-inject` -- are Linux-only and live
//! behind the same traits. Both are synchronous, matching the `lowlat` data
//! path (polled worker threads, not `async`); the session loop polls them from
//! its own tick, exactly as the existing native host does.

use openstream_host_ipc::lifecycle::{CaptureKind, Seat};
use openstream_host_ipc::protocol::CaptureParams;
use openstream_host_ipc::token::Capabilities;

/// The geometry a capture actually started at (the source may not honour the
/// requested size exactly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedCapture {
    /// Actual encoded width in pixels.
    pub width: u16,
    /// Actual encoded height in pixels.
    pub height: u16,
}

/// One encoded access unit pulled from the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Monotonic sequence number.
    pub sequence: u32,
    /// Capture timestamp in microseconds since the stream began.
    pub timestamp_us: u64,
    /// Whether this is a keyframe (IDR).
    pub keyframe: bool,
    /// Annex-B access-unit bytes.
    pub data: Vec<u8>,
}

/// Force-feedback pulled from a captured gamepad, to forward to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RumbleOut {
    /// Which pad.
    pub device_id: u8,
    /// Strong (low-frequency) motor magnitude.
    pub strong: u16,
    /// Weak (high-frequency) motor magnitude.
    pub weak: u16,
}

/// Why a capture could not start or continue. `code` is a stable machine
/// reason carried to the service; `message` is short and secret-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFailure {
    /// Stable reason code (mirrors `BrokerEvent::CaptureError.code`).
    pub code: u16,
    /// Short human-readable detail, no secrets.
    pub message: String,
}

impl CaptureFailure {
    /// A failure with the given code and message.
    #[must_use]
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// A capture-and-encode source: the broker asks it to capture a seat and pulls
/// encoded frames from it. Implementations own the DRM device and the encoder;
/// the frames that come out are already H.264, so nothing raw crosses the IPC.
pub trait FrameSource {
    /// Start capturing and encoding the given seat at the given geometry.
    ///
    /// # Errors
    /// Returns a [`CaptureFailure`] if the seat cannot be captured or the
    /// encoder cannot start.
    fn open(&mut self, params: CaptureParams) -> Result<OpenedCapture, CaptureFailure>;

    /// Re-point the live capture to a new seat or source without tearing the
    /// encoder down harder than necessary, so the peer keeps receiving frames.
    ///
    /// # Errors
    /// Returns a [`CaptureFailure`] if the new source cannot be captured.
    fn switch(&mut self, seat: Seat, kind: CaptureKind) -> Result<OpenedCapture, CaptureFailure>;

    /// Change the encoder's target bitrate in kilobits per second.
    fn set_bitrate(&mut self, kbps: u32);

    /// Force the next frame to be a keyframe.
    fn request_keyframe(&mut self);

    /// Pull the next encoded frame if one is ready. Non-blocking: returns
    /// `None` when nothing is available yet.
    fn next_frame(&mut self) -> Option<EncodedFrame>;

    /// Stop capturing and release the encoder, keeping the source reusable for
    /// a later [`FrameSource::open`].
    fn close(&mut self);
}

/// An input destination: the broker hands it an already-encoded input payload
/// plus the session's granted capabilities, and it decodes, checks each event
/// against those capabilities, and injects the allowed ones.
pub trait InputSink {
    /// Inject the events in `payload` that `granted` permits. Events the grant
    /// does not cover are dropped, not injected.
    fn inject(&mut self, payload: &[u8], granted: Capabilities);

    /// Pull any pending force-feedback to forward to the peer. Non-blocking.
    fn take_rumble(&mut self) -> Option<RumbleOut>;
}

#[cfg(test)]
pub(crate) mod fakes {
    //! In-memory fakes so the session core is testable off a real device.

    use super::{
        Capabilities, CaptureFailure, CaptureKind, CaptureParams, EncodedFrame, FrameSource,
        InputSink, OpenedCapture, RumbleOut, Seat,
    };
    use std::collections::VecDeque;

    /// A recording [`FrameSource`]: it hands out queued frames and remembers
    /// every call, so a test can assert exactly what the session did.
    #[derive(Debug, Default)]
    pub(crate) struct FakeFrameSource {
        /// Frames [`FrameSource::next_frame`] will hand out, oldest first.
        pub(crate) queued: VecDeque<EncodedFrame>,
        /// If set, the next [`FrameSource::open`] fails with this.
        pub(crate) fail_open: Option<CaptureFailure>,
        pub(crate) opened: Vec<CaptureParams>,
        pub(crate) switched: Vec<(Seat, CaptureKind)>,
        pub(crate) bitrates: Vec<u32>,
        pub(crate) keyframes: u32,
        pub(crate) closes: u32,
        pub(crate) open: bool,
    }

    impl FrameSource for FakeFrameSource {
        fn open(&mut self, params: CaptureParams) -> Result<OpenedCapture, CaptureFailure> {
            if let Some(failure) = self.fail_open.take() {
                return Err(failure);
            }
            self.opened.push(params);
            self.open = true;
            Ok(OpenedCapture {
                width: params.width,
                height: params.height,
            })
        }

        fn switch(
            &mut self,
            seat: Seat,
            kind: CaptureKind,
        ) -> Result<OpenedCapture, CaptureFailure> {
            self.switched.push((seat, kind));
            Ok(OpenedCapture {
                width: 1920,
                height: 1080,
            })
        }

        fn set_bitrate(&mut self, kbps: u32) {
            self.bitrates.push(kbps);
        }

        fn request_keyframe(&mut self) {
            self.keyframes += 1;
        }

        fn next_frame(&mut self) -> Option<EncodedFrame> {
            if self.open {
                self.queued.pop_front()
            } else {
                None
            }
        }

        fn close(&mut self) {
            self.closes += 1;
            self.open = false;
        }
    }

    /// A recording [`InputSink`]: it remembers each injected payload with the
    /// grant it was given, and hands out any pre-loaded rumble.
    #[derive(Debug, Default)]
    pub(crate) struct FakeInputSink {
        pub(crate) injected: Vec<(Vec<u8>, Capabilities)>,
        pub(crate) rumble: VecDeque<RumbleOut>,
    }

    impl InputSink for FakeInputSink {
        fn inject(&mut self, payload: &[u8], granted: Capabilities) {
            self.injected.push((payload.to_vec(), granted));
        }

        fn take_rumble(&mut self) -> Option<RumbleOut> {
            self.rumble.pop_front()
        }
    }
}
