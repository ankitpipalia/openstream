//! The privileged device broker for OpenStream's pre-login host.
//!
//! The broker holds the two privileges that genuinely need elevation -- reading
//! the DRM/KMS scanout to capture and hardware-encode the screen, and injecting
//! input through `uinput` -- and nothing that faces the network. The
//! unprivileged machine service drives it over the [`openstream_host_ipc`]
//! protocol: the service authenticates by peer credentials, then asks the broker
//! to capture a seat and forwards approved input, while the broker streams back
//! encoded H.264.
//!
//! The protocol logic ([`session`]) is written against two device traits
//! ([`device`]) so it is unit-tested on any platform with fakes. The real
//! capture and injection are Linux-only and implemented behind the same traits
//! in the binary.

pub mod device;
pub mod session;
