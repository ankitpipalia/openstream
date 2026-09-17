//! Which graphical session is on the seat right now, and what kind.
//!
//! A machine-level host that starts before login has to know whether the seat
//! is showing the display manager's greeter or a logged-in user's session, so
//! it can capture the right thing and hand off across a login without dropping
//! the remote session. `systemd-logind` already tracks exactly this, and
//! exposes it as plain key=value files under `/run/systemd`, so this reads
//! those rather than linking libsystemd or shelling out to `loginctl`:
//!
//! - `/run/systemd/seats/<seat>` names the `ACTIVE` session on that seat.
//! - `/run/systemd/sessions/<id>` gives that session's `CLASS`
//!   (`greeter`/`user`/`user-early`/...), `STATE` (`active`/`online`/...),
//!   `TYPE` (`wayland`/`x11`/`tty`) and `REMOTE`.
//!
//! The parsing is pure and unit-tested; only [`Seat::active`] touches the
//! filesystem, so the classification is verifiable without a live seat.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

/// What is currently shown on a seat, for choosing a capture mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionKind {
    /// The display manager's login greeter (no user logged in yet).
    Greeter,
    /// A logged-in user's graphical session.
    User,
    /// A session that is neither -- a bare TTY, or a class this does not model.
    Other,
}

impl SessionKind {
    /// `logind`'s `CLASS` value maps to one of these. `user-early` and
    /// `user-incomplete` are a user session mid-setup, so they count as `User`;
    /// everything unrecognised is `Other` rather than guessed.
    fn from_class(class: &str) -> Self {
        match class.trim() {
            "greeter" => SessionKind::Greeter,
            "user" | "user-early" | "user-incomplete" => SessionKind::User,
            _ => SessionKind::Other,
        }
    }
}

/// The active graphical session on a seat: what it is and enough to capture it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveSession {
    /// The logind session id, e.g. `c1` or `2`.
    pub(crate) id: String,
    /// Greeter, user, or other.
    pub(crate) kind: SessionKind,
    /// `wayland`, `x11`, `tty`, ... -- which capture path fits.
    pub(crate) session_type: String,
    /// Whether logind considers it active (foreground on the seat) vs merely
    /// online (a background session on a switched-away VT).
    pub(crate) active: bool,
    /// A remote (SSH) session is never the local screen; the host must not
    /// treat it as the thing to capture.
    pub(crate) remote: bool,
}

impl ActiveSession {
    /// Whether this is the local graphical session a host should capture: a
    /// local (not remote) greeter or user session on a graphical stack.
    pub(crate) fn is_capturable_local(&self) -> bool {
        !self.remote
            && matches!(self.kind, SessionKind::Greeter | SessionKind::User)
            && matches!(self.session_type.as_str(), "wayland" | "x11" | "mir")
    }
}

/// One seat's logind state, read from `/run/systemd`.
#[derive(Debug, Clone)]
pub(crate) struct Seat {
    run: PathBuf,
    seat: String,
}

impl Default for Seat {
    fn default() -> Self {
        Self::new("seat0")
    }
}

impl Seat {
    /// The named seat under the default `/run/systemd` root.
    pub(crate) fn new(seat: &str) -> Self {
        Self {
            run: PathBuf::from("/run/systemd"),
            seat: seat.to_string(),
        }
    }

    /// A seat rooted at a different `/run/systemd` directory, for tests.
    #[cfg(test)]
    pub(crate) fn with_root(run: impl Into<PathBuf>, seat: &str) -> Self {
        Self {
            run: run.into(),
            seat: seat.to_string(),
        }
    }

    /// The active session on this seat right now, or `None` when the seat file
    /// or the session it names is absent (no seat, or logind not running).
    pub(crate) fn active(&self) -> Option<ActiveSession> {
        let seat_file = self.run.join("seats").join(&self.seat);
        let session_id = active_session_id(&std::fs::read_to_string(seat_file).ok()?)?;
        let session_file = self.run.join("sessions").join(&session_id);
        let fields = std::fs::read_to_string(session_file).ok()?;
        Some(parse_session(&session_id, &fields))
    }
}

/// The `ACTIVE=` session id from a seat file's contents.
fn active_session_id(seat_file: &str) -> Option<String> {
    field(seat_file, "ACTIVE").map(str::to_string)
}

/// Build an [`ActiveSession`] from a session file's key=value contents.
fn parse_session(id: &str, session_file: &str) -> ActiveSession {
    ActiveSession {
        id: id.to_string(),
        kind: field(session_file, "CLASS").map_or(SessionKind::Other, SessionKind::from_class),
        session_type: field(session_file, "TYPE").unwrap_or("").to_string(),
        // logind writes ACTIVE as the string "1"/"0" in a session file.
        active: field(session_file, "ACTIVE") == Some("1")
            || field(session_file, "STATE") == Some("active"),
        remote: field(session_file, "REMOTE") == Some("1"),
    }
}

/// The value of one `KEY=value` line, trimmed. The first match wins.
fn field<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_active_session_id_from_a_seat_file() {
        let seat = "SEAT=seat0\nACTIVE=c2\nACTIVE_UID=1000\nSESSIONS=c2 c1\n";
        assert_eq!(active_session_id(seat).as_deref(), Some("c2"));
        assert_eq!(active_session_id("SEAT=seat0\n"), None);
    }

    #[test]
    fn classifies_a_greeter_session() {
        let session = "STATE=active\nACTIVE=1\nCLASS=greeter\nTYPE=wayland\nREMOTE=0\n";
        let parsed = parse_session("c1", session);
        assert_eq!(parsed.kind, SessionKind::Greeter);
        assert_eq!(parsed.session_type, "wayland");
        assert!(parsed.active);
        assert!(!parsed.remote);
        assert!(parsed.is_capturable_local());
    }

    #[test]
    fn classifies_a_user_wayland_session() {
        let session = "STATE=active\nACTIVE=1\nCLASS=user\nTYPE=wayland\nREMOTE=0\nDESKTOP=KDE\n";
        let parsed = parse_session("2", session);
        assert_eq!(parsed.kind, SessionKind::User);
        assert!(parsed.is_capturable_local());
    }

    #[test]
    fn user_early_counts_as_a_user_session() {
        assert_eq!(SessionKind::from_class("user-early"), SessionKind::User);
        assert_eq!(
            SessionKind::from_class("user-incomplete"),
            SessionKind::User
        );
    }

    #[test]
    fn a_remote_ssh_session_is_not_capturable_local() {
        let session = "STATE=active\nACTIVE=1\nCLASS=user\nTYPE=tty\nREMOTE=1\n";
        let parsed = parse_session("7", session);
        assert!(parsed.remote);
        assert!(!parsed.is_capturable_local());
    }

    #[test]
    fn a_tty_session_is_not_a_graphical_capture_target() {
        let session = "STATE=active\nACTIVE=1\nCLASS=user\nTYPE=tty\nREMOTE=0\n";
        assert!(!parse_session("3", session).is_capturable_local());
    }

    #[test]
    fn reads_a_seat_and_session_from_a_run_root() {
        let dir =
            std::env::temp_dir().join(format!("openstream-logind-test-{}", std::process::id()));
        let seats = dir.join("seats");
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&seats).unwrap();
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(seats.join("seat0"), "ACTIVE=c1\n").unwrap();
        std::fs::write(
            sessions.join("c1"),
            "CLASS=greeter\nTYPE=wayland\nACTIVE=1\nREMOTE=0\n",
        )
        .unwrap();

        let active = Seat::with_root(&dir, "seat0")
            .active()
            .expect("an active session");
        assert_eq!(active.id, "c1");
        assert_eq!(active.kind, SessionKind::Greeter);
        assert!(active.is_capturable_local());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_seat_file_means_no_active_session() {
        let missing = std::path::Path::new("/run/systemd-openstream-does-not-exist");
        assert!(Seat::with_root(missing, "seat0").active().is_none());
    }
}
