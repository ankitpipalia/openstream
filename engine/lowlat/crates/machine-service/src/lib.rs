//! The unprivileged, network-facing machine service for OpenStream's pre-login
//! host.
//!
//! It owns everything that touches the network -- signaling, ICE, the peer
//! connection, and connection approval -- and none of the privileges that need
//! elevation. For capture and input it talks to the privileged broker over the
//! [`openstream_host_ipc`] socket, so the process an attacker can reach over the
//! network never runs as root. The peer loop that bridges the two lives in the
//! binary; this library holds the pieces that stand alone:
//!
//!   - [`broker_client`]: connecting to the broker, refusing a non-root one, and
//!     the version handshake;
//!   - [`session`]: reading the logind seat state to tell the broker whether it
//!     is capturing the greeter or a logged-in user.

pub mod broker_client;
pub mod session;
