//! Lowlat host-local congestion-control compatibility exports.
//!
//! The policy state machine lives in `openstream-transport-policy` so it can
//! be reused by future transports without importing lowlat packet or socket
//! assumptions. Lowlat still owns the input orchestration: stale counts come
//! from [`crate::send::SendRing`], and there is no peer feedback message in
//! either direction.
//!
//! The re-exports below preserve the existing lowlat API and keep the
//! lowlat-specific relationship between the retransmission scan and this
//! controller explicit.

pub use openstream_transport_policy::{
    CongestionObservation, Controller, DEFAULT_LEVEL, LEVELS, Level, WINDOW_FLOOR, level,
};
