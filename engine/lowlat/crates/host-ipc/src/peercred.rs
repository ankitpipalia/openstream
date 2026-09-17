//! Who is on the other end of the broker socket.
//!
//! The broker runs privileged and the machine service does not, so the two are
//! different users sharing one Unix socket. Filesystem permissions alone cannot
//! express "only the machine-service account may drive the devices, and the
//! service will only obey a broker that is actually root" -- for that each side
//! must check the *peer's* credentials on the connected socket. The repository
//! had no such check anywhere before this; this module is it.
//!
//! [`PeerIdentity`] is the uid/gid/pid the kernel vouches for (via `SO_PEERCRED`
//! on Linux); [`AllowedPeers`] is the pure allow-list policy both ends apply.
//! The policy is unit-tested off-target; only [`read_peer_identity`] touches a
//! real socket, and it is a thin, single-syscall wrapper.

/// The credentials the kernel attests for the process on the other end of a
/// connected Unix socket. Unforgeable by the peer: the kernel fills these in,
/// not the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's effective user id.
    pub uid: u32,
    /// The peer's effective group id.
    pub gid: u32,
    /// The peer's process id, for audit logging (never for authorisation: a pid
    /// can be reused, so it is not an identity).
    pub pid: i32,
}

impl PeerIdentity {
    /// Whether the peer is the superuser. The machine service uses this to
    /// refuse a broker socket that is not actually owned by a root process.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// A pure allow-list of user ids permitted to be on the other end. The broker
/// admits only the configured machine-service uid; the service admits only the
/// broker's uid (normally root). An empty list admits no one.
#[derive(Debug, Clone, Default)]
pub struct AllowedPeers {
    uids: Vec<u32>,
}

impl AllowedPeers {
    /// A policy admitting exactly one uid.
    #[must_use]
    pub fn only(uid: u32) -> Self {
        Self { uids: vec![uid] }
    }

    /// A policy admitting any uid in the list.
    #[must_use]
    pub fn any_of(uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            uids: uids.into_iter().collect(),
        }
    }

    /// Whether this peer's uid is on the list. gid and pid are deliberately not
    /// consulted: authorisation is by the account, and pid is not an identity.
    #[must_use]
    pub fn permits(&self, peer: &PeerIdentity) -> bool {
        self.uids.contains(&peer.uid)
    }
}

/// Read the connected peer's credentials from a Unix socket file descriptor via
/// `SO_PEERCRED`. Linux-only: `SO_PEERCRED` is a Linux interface, and the broker
/// is a Linux component. The caller passes the raw fd of a connected
/// `UnixStream` (`stream.as_raw_fd()`), from either the sync or the async stack.
///
/// # Errors
/// Returns the OS error if the socket is not a connected Unix stream socket or
/// the `getsockopt` call fails.
#[cfg(target_os = "linux")]
pub fn read_peer_identity(fd: std::os::unix::io::RawFd) -> std::io::Result<PeerIdentity> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred is far smaller than socklen_t's maximum");
    // SAFETY: getsockopt reads into `ucred` at most `len` bytes, and `len` is
    // exactly its size; `fd` is borrowed for the duration of the call only.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PeerIdentity {
        uid: ucred.uid,
        gid: ucred.gid,
        pid: ucred.pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> PeerIdentity {
        PeerIdentity {
            uid,
            gid: uid,
            pid: 1234,
        }
    }

    #[test]
    fn only_admits_the_named_uid() {
        let policy = AllowedPeers::only(1000);
        assert!(policy.permits(&peer(1000)));
        assert!(!policy.permits(&peer(0)));
        assert!(!policy.permits(&peer(1001)));
    }

    #[test]
    fn any_of_admits_any_listed_uid() {
        let policy = AllowedPeers::any_of([0, 1000]);
        assert!(policy.permits(&peer(0)));
        assert!(policy.permits(&peer(1000)));
        assert!(!policy.permits(&peer(1)));
    }

    #[test]
    fn an_empty_policy_admits_no_one() {
        let policy = AllowedPeers::default();
        assert!(!policy.permits(&peer(0)));
        assert!(!policy.permits(&peer(1000)));
    }

    #[test]
    fn root_is_recognised() {
        assert!(peer(0).is_root());
        assert!(!peer(1000).is_root());
    }

    #[test]
    fn authorisation_ignores_pid_and_gid() {
        // Same uid, wildly different pid/gid: still the same authorised peer.
        let policy = AllowedPeers::only(1000);
        let a = PeerIdentity {
            uid: 1000,
            gid: 5,
            pid: 10,
        };
        let b = PeerIdentity {
            uid: 1000,
            gid: 999,
            pid: 999_999,
        };
        assert!(policy.permits(&a));
        assert!(policy.permits(&b));
    }
}
