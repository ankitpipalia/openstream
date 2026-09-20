//! Enrol this machine and provision its broker's grant key, in one step.
//!
//! This is the install-time command that turns a computer into a machine the
//! account owns and that its privileged broker can prove approvals against. It
//! runs once, as the broker's own user, and then never again.
//!
//! **Why one command and not two.** The grant key is returned exactly once, by
//! the enrolment that creates the device, and there is no endpoint that reads it
//! back. If enrolment and provisioning were separate steps the key would have to
//! cross between them -- through a terminal, a file, a pipe, an installer log --
//! and every one of those is a place it can be left behind. Here it goes from
//! the response straight into a 0600 file and is never printed.
//!
//! **What it prints.** The device id, and whether a key was written. Never the
//! key, on success or on failure.
//!
//! **Why the destination is opened before the request.** The key exists for
//! one instant: it is in the enrolment response and nowhere else, and no
//! endpoint reads it back. So the command proves it can store a key -- creates
//! the directory, checks it, creates the 0600 file -- *before* it asks for
//! one. And if storing still fails, it removes the device it just enrolled,
//! because a device id whose key was lost cannot be enrolled a second time.
//!
//! **Two windows remain, and they are the ones it cannot see.** If the server
//! commits the enrolment and the response is lost, or this process dies between
//! the server's commit and the local one, the device exists and its key does
//! not -- and nothing here knows a device was created, so nothing rolls it back.
//! The next run gets a 409 and the message tells the operator how to remove it.
//! Closing the windows properly needs an idempotent enrolment keyed by a durable
//! client-generated request id, so a retry re-reads its own outcome instead of
//! creating a second device. That is not built.
//!
//! ```text
//! OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key \
//!   openstream-enrol --origin https://signal.example.com \
//!                    --device-id "$(cat /etc/machine-id)" \
//!                    --name "Studio" \
//!                    --public-key "$KEY_HEX" < access-token.txt
//! ```
//!
//! The access token arrives on **stdin**, not as an argument: a command line is
//! visible in `ps` to every user on the machine.

use std::process::ExitCode;

/// What the command was asked to do.
struct Args {
    origin: String,
    device_id: String,
    name: String,
    platform: String,
    public_key: String,
}

const USAGE: &str = "\
usage: openstream-enrol --origin URL --device-id ID --public-key HEX [--name NAME] [--platform OS]

The account access token is read from stdin. The grant key is written to the
path in OPENSTREAM_BROKER_GRANT_KEY_FILE and is never printed.
";

fn parse_args() -> Result<Args, String> {
    let mut origin = None;
    let mut device_id = None;
    let mut name = None;
    let mut platform = None;
    let mut public_key = None;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut take = |target: &mut Option<String>| match args.next() {
            Some(value) => {
                *target = Some(value);
                Ok(())
            }
            None => Err(format!("{flag} needs a value")),
        };
        match flag.as_str() {
            "--origin" => take(&mut origin)?,
            "--device-id" => take(&mut device_id)?,
            "--name" => take(&mut name)?,
            "--platform" => take(&mut platform)?,
            "--public-key" => take(&mut public_key)?,
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }

    Ok(Args {
        origin: origin.ok_or("--origin is required")?,
        device_id: device_id.ok_or("--device-id is required")?,
        public_key: public_key.ok_or("--public-key is required")?,
        // A machine with no name shows up in the owner's device list as a blank
        // row, which is worse than a dull default.
        name: name.unwrap_or_else(|| "OpenStream host".to_string()),
        platform: platform.unwrap_or_else(|| std::env::consts::OS.to_string()),
    })
}

/// Undo an enrolment whose key could not be stored.
///
/// Enrolment mints the grant key once and `POST /v1/devices` refuses an id it
/// already holds, so a device enrolled without its key being written is a
/// machine that can neither be provisioned nor enrolled again. Removing the
/// record is what makes the next attempt possible.
///
/// If the removal itself fails there is nothing left to try automatically, and
/// the message has to be the one an operator can act on -- it names the device
/// and says plainly that the key is gone.
#[cfg(unix)]
async fn undo(origin: &str, access_token: &str, device_id: &str, why: &str) -> ExitCode {
    eprintln!("openstream-enrol: {why}");
    match openstream_client_core::enrolment::remove(origin, access_token, device_id).await {
        Ok(()) => eprintln!(
            "openstream-enrol: removed device {device_id} again. Nothing is left behind; fix the \
             problem above and run this command again."
        ),
        Err(error) => eprintln!(
            "openstream-enrol: device {device_id} is enrolled but its grant key was not stored \
             anywhere, and removing the device failed: {error}\n\
             openstream-enrol: the key cannot be re-issued for that id. Delete the device from \
             the account's device list, then enrol this machine again."
        ),
    }
    ExitCode::FAILURE
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> ExitCode {
    use openstream_client_core::enrolment::{EnrolmentError, MachineIdentity, enrol};
    use std::io::Read;

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    let key_path = match std::env::var("OPENSTREAM_BROKER_GRANT_KEY_FILE") {
        Ok(path) if !path.trim().is_empty() => path,
        _ => {
            eprintln!(
                "openstream-enrol: OPENSTREAM_BROKER_GRANT_KEY_FILE is not set. The grant key is \
                 returned once and cannot be fetched again, so this refuses to enrol before it \
                 knows where to put it."
            );
            return ExitCode::from(2);
        }
    };

    let mut access_token = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut access_token) {
        eprintln!("openstream-enrol: could not read the access token from stdin: {error}");
        return ExitCode::FAILURE;
    }
    let access_token = access_token.trim();
    if access_token.is_empty() {
        eprintln!("openstream-enrol: no access token on stdin");
        return ExitCode::from(2);
    }

    // Everything that can fail about *storing* the key, done before anything
    // issues one. A non-empty environment variable is not a destination: the
    // directory may not exist, may be unwritable, may be one the broker will
    // later refuse. Discovering any of that after enrolment means an enrolled
    // device whose one key no longer exists anywhere.
    //
    // What this leaves for later is a write to an open descriptor and a rename
    // inside one directory.
    let prepared = match openstream_host_broker::grant_key::prepare(&key_path) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!(
                "openstream-enrol: {key_path} cannot receive the grant key: {error}\n\
                 openstream-enrol: nothing was enrolled. The key is issued once, so this refuses \
                 to ask for one it could not store."
            );
            return ExitCode::from(2);
        }
    };

    let identity = MachineIdentity {
        device_id: args.device_id,
        name: args.name,
        platform: args.platform,
        public_key_hex: args.public_key,
    };
    let enrolment = match enrol(&args.origin, access_token, &identity).await {
        Ok(enrolment) => enrolment,
        // A conflict is the one refusal an operator can act on, and it is the
        // one they will actually hit: it means this machine is already enrolled
        // under this id. The generic message says "the control plane refused
        // enrolment (409): control-plane request failed", which describes
        // nothing and suggests nothing.
        Err(EnrolmentError::Rejected { status: 409, .. }) => {
            eprintln!(
                "openstream-enrol: {} is already enrolled on this account. Its grant key was \
                 issued once, at that enrolment, and cannot be re-read -- so if this machine no \
                 longer has it, the device has to be removed and enrolled again:\n\
                 \x20 curl -X DELETE {}/v1/devices/{} -H \"authorization: Bearer $TOKEN\"\n\
                 openstream-enrol: that invalidates the old key. Any broker still running with it \
                 will refuse every session until it is re-provisioned.",
                identity.device_id,
                args.origin.trim_end_matches('/'),
                identity.device_id
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("openstream-enrol: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Past this line the device exists and holds a key only this process has
    // seen. Every failure from here has to put the record back, or the machine
    // is stuck under an id that can never be provisioned and never re-enrolled.
    let device_id = enrolment.device_id.clone();
    let account_id = enrolment.account_id.clone();
    let Some(key_hex) = enrolment.into_grant_key() else {
        return undo(
            &args.origin,
            access_token,
            &device_id,
            "the control plane enrolled the device but returned no grant key, so its broker \
             could never be provisioned",
        )
        .await;
    };
    let key = match openstream_host_broker::grant_key::from_hex(&key_hex) {
        Ok(key) => key,
        Err(error) => {
            return undo(
                &args.origin,
                access_token,
                &device_id,
                &format!("the control plane's grant key is unusable: {error}"),
            )
            .await;
        }
    };
    if let Err(error) = prepared.commit(&key) {
        return undo(
            &args.origin,
            access_token,
            &device_id,
            &format!("could not store the grant key in {key_path}: {error}"),
        )
        .await;
    }

    println!("{device_id}");
    eprintln!("openstream-enrol: enrolled {device_id}; grant key written to {key_path}");

    // Record it where the broker reads from, if the installer said where.
    //
    // The alternative is what the package used to print: "now set these two
    // variables in the unit file". That is a device id copied by hand into a
    // file a package upgrade replaces, and both halves of that are avoidable.
    //
    // Deliberately not fatal. The key is already stored at this point, and the
    // enrolment is good; failing here would undo a device over a file that can
    // be edited in ten seconds. It says exactly what to write instead.
    match std::env::var("OPENSTREAM_BROKER_ENV_FILE") {
        Ok(env_path) if !env_path.trim().is_empty() => {
            match record_in_env_file(&env_path, &key_path, &device_id) {
                Ok(()) => {
                    eprintln!("openstream-enrol: recorded the key path and device id in {env_path}")
                }
                Err(error) => eprintln!(
                    "openstream-enrol: enrolled, but could not update {env_path}: {error}\n\
                     openstream-enrol: add these two lines to it by hand:\n\
                     \x20 OPENSTREAM_BROKER_GRANT_KEY_FILE={key_path}\n\
                     \x20 OPENSTREAM_BROKER_DEVICE_ID={device_id}"
                ),
            }
        }
        _ => eprintln!(
            "openstream-enrol: add these two lines to the broker's environment file:\n\
             \x20 OPENSTREAM_BROKER_GRANT_KEY_FILE={key_path}\n\
             \x20 OPENSTREAM_BROKER_DEVICE_ID={device_id}"
        ),
    }

    // Printed, not written. The account id is what the *machine service* needs
    // to authenticate -- a device proof names the (account, device) pair it is
    // good for -- and that service reads its own environment file, not the
    // broker's. Inventing a key for it here, in the file the broker reads,
    // would put it in the wrong place for the one process that will use it.
    eprintln!(
        "openstream-enrol: this machine is device {device_id} in account {account_id}. The \
         machine service needs both to authenticate; wiring that up is not done yet."
    );
    ExitCode::SUCCESS
}

/// Set `name` to `value` in an environment file's text.
///
/// Replaces an existing assignment in place, uncomments a commented-out one, or
/// appends. Kept as a string function so every one of those cases is testable
/// without a filesystem -- the commented-out case in particular is the one the
/// package ships, so it is the one that has to work.
#[cfg(unix)]
#[must_use]
fn set_env_line(contents: &str, name: &str, value: &str) -> String {
    let assignment = format!("{name}={value}");
    let mut replaced = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let bare = line.trim_start().trim_start_matches('#').trim_start();
            if !replaced && bare.starts_with(&format!("{name}=")) {
                replaced = true;
                assignment.clone()
            } else {
                line.to_string()
            }
        })
        .collect();
    if !replaced {
        lines.push(assignment);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Write the grant key path and device id into the broker's environment file.
///
/// Rewritten through a sibling temporary and renamed, so a failure partway
/// leaves the old file rather than half of a new one: the broker reads this at
/// every start, and a truncated line is a broker that will not start.
#[cfg(unix)]
fn record_in_env_file(path: &str, key_path: &str, device_id: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let existing = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    // Keep whatever mode the file already had; the package writes 0600 and an
    // upgrade must not loosen it.
    let mode = std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0o600);

    let updated = set_env_line(&existing, "OPENSTREAM_BROKER_GRANT_KEY_FILE", key_path);
    let updated = set_env_line(&updated, "OPENSTREAM_BROKER_DEVICE_ID", device_id);

    let staging = format!("{path}.{}.new", std::process::id());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&staging)?;
    let result = file
        .write_all(updated.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::set_env_line;

    #[test]
    fn a_commented_out_assignment_is_the_one_that_gets_set() {
        // Exactly what the package ships: the variable is present, commented
        // out, with its explanation above it. Appending a second copy would
        // work by luck -- later assignments win in a systemd environment file
        // -- and would leave the file saying two different things.
        let shipped = "\
# Written by `openstream-enrol`.
#OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key
#OPENSTREAM_BROKER_DEVICE_ID=
";
        let updated = set_env_line(shipped, "OPENSTREAM_BROKER_DEVICE_ID", "machine-one");
        assert_eq!(
            updated,
            "\
# Written by `openstream-enrol`.
#OPENSTREAM_BROKER_GRANT_KEY_FILE=/etc/openstream/grant.key
OPENSTREAM_BROKER_DEVICE_ID=machine-one
"
        );
        assert_eq!(
            updated.matches("OPENSTREAM_BROKER_DEVICE_ID=").count(),
            1,
            "the file must not end up with two answers"
        );
    }

    #[test]
    fn re_enrolling_replaces_the_old_device_id_rather_than_stacking() {
        let existing = "OPENSTREAM_BROKER_DEVICE_ID=old\nOPENSTREAM_BROKER_CEILING=capture\n";
        let updated = set_env_line(existing, "OPENSTREAM_BROKER_DEVICE_ID", "new");
        assert_eq!(
            updated,
            "OPENSTREAM_BROKER_DEVICE_ID=new\nOPENSTREAM_BROKER_CEILING=capture\n"
        );
    }

    #[test]
    fn a_variable_that_is_not_there_is_appended() {
        let updated = set_env_line("OPENSTREAM_BROKER_CEILING=capture\n", "NEW", "value");
        assert_eq!(updated, "OPENSTREAM_BROKER_CEILING=capture\nNEW=value\n");
    }

    #[test]
    fn an_empty_file_becomes_one_assignment_with_a_trailing_newline() {
        // systemd tolerates a missing final newline; leaving one off makes the
        // next append land on the same line, which is a different variable.
        assert_eq!(set_env_line("", "NAME", "value"), "NAME=value\n");
    }

    #[test]
    fn a_variable_whose_name_is_a_prefix_of_another_is_not_touched() {
        // OPENSTREAM_BROKER_SOCKET and OPENSTREAM_BROKER_SOCKET_GID both exist,
        // so matching on the name alone would rewrite the wrong line. The `=`
        // is what makes the match exact.
        let existing = "OPENSTREAM_BROKER_SOCKET_GID=1001\n";
        let updated = set_env_line(existing, "OPENSTREAM_BROKER_SOCKET", "/run/x.sock");
        assert_eq!(
            updated,
            "OPENSTREAM_BROKER_SOCKET_GID=1001\nOPENSTREAM_BROKER_SOCKET=/run/x.sock\n"
        );
    }
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("openstream-enrol provisions a Unix broker's grant key and runs only there");
    ExitCode::FAILURE
}
