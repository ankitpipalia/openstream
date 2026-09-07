//! OpenStream media and input parsers.
//!
//! These parsers sit after authenticated transport but still consume peer
//! supplied lengths, indexes, flags, timestamps, and event kinds. Keep this
//! target independent of a real decoder: codec bitstreams are untrusted too,
//! while the framing layer must be total and bounded before a decoder sees
//! them.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openstream_media::input::InputEvent;
use openstream_media::{Assembler, AudioFrame, FrameAck, Fragment};

fuzz_target!(|data: &[u8]| {
    let _ = InputEvent::decode(data);
    let _ = AudioFrame::decode(data);
    let _ = FrameAck::decode(data);

    if let Ok(fragment) = Fragment::decode(data) {
        let mut assembler = Assembler::default();
        let _ = assembler.push(fragment);
        let _ = assembler.take_keyframe_request();
        let _ = assembler.take_frame_gap();
    }
});
