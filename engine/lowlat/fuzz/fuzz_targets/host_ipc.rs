//! The broker protocol parsers, which decode untrusted bytes off the local
//! socket in both directions.
//!
//! Neither `ServiceRequest::decode` (broker side) nor `BrokerEvent::decode`
//! (service side) nor the low-level `wire::Reader` may panic on arbitrary input,
//! and any message that decodes must round-trip through its own type: encoding
//! it and decoding again reproduces the value. (The `CaptureError` message field
//! is decoded lossily from UTF-8, so this checks the value round trip, not the
//! raw bytes.)
#![no_main]

use libfuzzer_sys::fuzz_target;
use openstream_host_ipc::protocol::{BrokerEvent, ServiceRequest};
use openstream_host_ipc::wire::Reader;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = ServiceRequest::decode(data) {
        let reencoded = request.encode();
        assert_eq!(
            ServiceRequest::decode(&reencoded),
            Ok(request),
            "service request did not round trip through its type",
        );
    }
    if let Ok(event) = BrokerEvent::decode(data) {
        let reencoded = event.encode();
        assert_eq!(
            BrokerEvent::decode(&reencoded),
            Ok(event),
            "broker event did not round trip through its type",
        );
    }

    // The low-level reader must never panic on arbitrary bytes, whatever order
    // the fields are pulled in.
    let mut reader = Reader::new(data);
    let _ = reader.tag();
    let _ = reader.u8();
    let _ = reader.u16();
    let _ = reader.u32();
    let _ = reader.u64();
    let _ = reader.u128();
    let _ = reader.bool();
    let _ = reader.bytes();
    let _ = reader.finish();
});
