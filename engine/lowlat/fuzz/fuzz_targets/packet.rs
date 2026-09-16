//! Cleartext packet parsing, and the encoder fed back its own output.
//!
//! Re-encoding a parsed packet must reproduce the bytes exactly. A divergence
//! here is a wire bug that the corpus might not happen to cover.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lowlat_core::packet::{self, Packet};

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = packet::parse(data) else {
        return;
    };
    let mut out = [0u8; lowlat_core::MAX_CLEARTEXT];
    match parsed {
        Packet::Data(ref inner) => {
            if let Ok(written) = packet::encode_data(&mut out, inner) {
                assert_eq!(&out[..written], data, "data packet did not round trip");
            }
        }
        Packet::Ack(ref inner) => {
            // encode_ack canonicalises to the full ACK_LEN (all CHANNEL_COUNT
            // channels) regardless of how many the input reported, so it is
            // deliberately NOT byte-identical to a shorter acknowledgement --
            // comparing against `data[..written]` reads past a short Ack. The
            // canonical form must instead be a fixpoint: re-parsing it and
            // re-encoding reproduces exactly the same bytes.
            if let Ok(written) = packet::encode_ack(&mut out, inner) {
                let mut again = [0u8; lowlat_core::MAX_CLEARTEXT];
                if let Ok(Packet::Ack(ref reparsed)) = packet::parse(&out[..written])
                    && let Ok(again_written) = packet::encode_ack(&mut again, reparsed)
                {
                    assert_eq!(
                        &out[..written],
                        &again[..again_written],
                        "canonical acknowledgement is not a fixpoint",
                    );
                }
            }
        }
        Packet::Probe(ref inner) => {
            if let Ok(written) = packet::encode_probe(&mut out, inner) {
                assert_eq!(&out[..written], data, "probe did not round trip");
            }
        }
        Packet::ProbeAck(ref inner) => {
            if let Ok(written) = packet::encode_probe_ack(&mut out, inner) {
                assert_eq!(&out[..written], data, "probe acknowledgement did not round trip");
            }
        }
    }
});
