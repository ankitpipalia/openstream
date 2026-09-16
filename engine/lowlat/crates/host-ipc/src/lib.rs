//! The shared contract between OpenStream's unprivileged machine service and
//! its privileged device broker.
//!
//! A machine-level host that is reachable at the login screen before anyone
//! logs in cannot be one big program running as root: the part that faces the
//! network (signaling, ICE, the peer connection, connection approval) must be
//! unprivileged, while a small, non-network-facing **broker** holds the two
//! privileges that actually need elevation -- reading the DRM/KMS scanout and
//! injecting input through `uinput`. This crate is what the two halves agree
//! on:
//!
//!   - [`lifecycle`]: the pure capture/login state machine -- what to capture
//!     as the seat moves greeter -> user, keeping an approved peer across the
//!     transition.
//!   - [`protocol`]: the message set the two exchange over the socket, and
//!     ([`wire`]) the bounds-checked binary codec that frames it. The data path
//!     is encoded H.264 access units, so the DMA-BUF and GPU import stay inside
//!     the privileged broker and the boundary carries only bytes.
//!   - [`token`]: the per-session capability grant the broker clamps to policy
//!     and enforces on every injected input event.
//!   - [`peercred`]: the peer-credential (`SO_PEERCRED`) authorisation each side
//!     applies -- the broker admits only the machine-service uid, the service
//!     obeys only a root broker.
//!
//! Everything here is pure and cross-platform apart from one Linux syscall
//! wrapper ([`peercred::read_peer_identity`]), so the whole contract is
//! unit-tested off-target. The DRM reader, the `uinput` sink, and the socket
//! transport live in the broker and service binaries that depend on this crate,
//! not here.

pub mod lifecycle;
pub mod peercred;
pub mod protocol;
pub mod token;
pub mod wire;
