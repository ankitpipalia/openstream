//! OpenStream's unauthenticated datagram boundary.
//!
//! A packet is attacker-controlled until the AES-GCM tag verifies. The
//! parser must therefore reject arbitrary bytes without panicking or making
//! an allocation proportional to a forged length field.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openstream_protocol::control::Frame;
use openstream_protocol::relay::decode_registration;
use openstream_protocol::Session;

fuzz_target!(|data: &[u8]| {
    let mut session = Session::new([0x41; 32], [0x42; 32]);
    let _ = session.open(data);
    let _ = Frame::decode(data);
    let _ = decode_registration(data);
});
