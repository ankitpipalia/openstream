//! Which seat state to report to the broker, read from `systemd-logind`.
//!
//! The machine service tells the broker whether it is capturing the greeter or a
//! logged-in user's session, because the broker narrows the capability grant on
//! the login screen. It reads the same plain `/run/systemd` key=value files the
//! host uses elsewhere rather than linking libsystemd, and maps the result onto
//! the protocol's [`Seat`]. The parsing is pure and unit-tested; only
//! [`current_seat`] touches the filesystem.

use std::path::Path;

use openstream_host_ipc::lifecycle::Seat;

/// The seat state to report right now: the greeter, a logged-in user, or empty
/// when there is no local graphical session (early boot, a remote-only session,
/// or a bare TTY). Reads the default `seat0` under `/run/systemd`.
#[must_use]
pub fn current_seat() -> Seat {
    seat_under(Path::new("/run/systemd"), "seat0")
}

/// [`current_seat`] against an explicit `/run/systemd` root, for tests.
#[must_use]
pub fn seat_under(run: &Path, seat: &str) -> Seat {
    let Ok(seat_file) = std::fs::read_to_string(run.join("seats").join(seat)) else {
        return Seat::Empty;
    };
    let Some(session_id) = field(&seat_file, "ACTIVE") else {
        return Seat::Empty;
    };
    let Ok(session_file) = std::fs::read_to_string(run.join("sessions").join(session_id)) else {
        return Seat::Empty;
    };
    classify(&session_file)
}

/// Map a session file's `CLASS`/`TYPE`/`REMOTE` onto a [`Seat`]. A remote or
/// non-graphical session is not the local screen, so it reports `Empty`.
fn classify(session_file: &str) -> Seat {
    let graphical = matches!(field(session_file, "TYPE"), Some("wayland" | "x11" | "mir"));
    let remote = field(session_file, "REMOTE") == Some("1");
    if remote || !graphical {
        return Seat::Empty;
    }
    match field(session_file, "CLASS") {
        Some("greeter") => Seat::Greeter,
        Some("user" | "user-early" | "user-incomplete") => Seat::User,
        _ => Seat::Empty,
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
    fn a_greeter_wayland_session_is_the_greeter() {
        let session = "CLASS=greeter\nTYPE=wayland\nREMOTE=0\n";
        assert_eq!(classify(session), Seat::Greeter);
    }

    #[test]
    fn a_user_wayland_session_is_a_user() {
        assert_eq!(classify("CLASS=user\nTYPE=wayland\nREMOTE=0\n"), Seat::User);
        assert_eq!(
            classify("CLASS=user-early\nTYPE=x11\nREMOTE=0\n"),
            Seat::User
        );
    }

    #[test]
    fn a_remote_session_is_not_a_local_seat() {
        assert_eq!(
            classify("CLASS=user\nTYPE=wayland\nREMOTE=1\n"),
            Seat::Empty
        );
    }

    #[test]
    fn a_tty_session_is_not_capturable() {
        assert_eq!(classify("CLASS=user\nTYPE=tty\nREMOTE=0\n"), Seat::Empty);
    }

    #[test]
    fn reads_a_seat_from_a_run_root() {
        let dir = std::env::temp_dir().join(format!("openstream-ms-seat-{}", std::process::id()));
        let seats = dir.join("seats");
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&seats).unwrap();
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(seats.join("seat0"), "ACTIVE=c1\n").unwrap();
        std::fs::write(
            sessions.join("c1"),
            "CLASS=greeter\nTYPE=wayland\nREMOTE=0\n",
        )
        .unwrap();
        assert_eq!(seat_under(&dir, "seat0"), Seat::Greeter);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_seat_file_is_empty() {
        let missing = Path::new("/run/systemd-openstream-ms-missing");
        assert_eq!(seat_under(missing, "seat0"), Seat::Empty);
    }
}
