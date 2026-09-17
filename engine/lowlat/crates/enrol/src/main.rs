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

#[cfg(unix)]
#[tokio::main]
async fn main() -> ExitCode {
    use openstream_client_core::enrolment::{MachineIdentity, enrol};
    use std::io::Read;

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    // Where the key will go, checked before the network call: enrolling and
    // then discovering there is nowhere to put the key would burn the one
    // chance to receive it.
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

    let identity = MachineIdentity {
        device_id: args.device_id,
        name: args.name,
        platform: args.platform,
        public_key_hex: args.public_key,
    };
    let enrolment = match enrol(&args.origin, access_token, &identity).await {
        Ok(enrolment) => enrolment,
        Err(error) => {
            eprintln!("openstream-enrol: {error}");
            return ExitCode::FAILURE;
        }
    };

    let device_id = enrolment.device_id.clone();
    let Some(key_hex) = enrolment.into_grant_key() else {
        eprintln!(
            "openstream-enrol: device {device_id} is enrolled, but the control plane returned no \
             grant key. That happens when the device was already enrolled: the key is issued once \
             and cannot be re-read. Remove the device and enrol it again to get a new one."
        );
        return ExitCode::FAILURE;
    };
    let key = match openstream_host_broker::grant_key::from_hex(&key_hex) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("openstream-enrol: the control plane's grant key is unusable: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = openstream_host_broker::grant_key::write(&key_path, &key) {
        eprintln!("openstream-enrol: could not write {key_path}: {error}");
        return ExitCode::FAILURE;
    }

    println!("{device_id}");
    eprintln!("openstream-enrol: enrolled {device_id}; grant key written to {key_path}");
    eprintln!(
        "openstream-enrol: set OPENSTREAM_BROKER_DEVICE_ID={device_id} in the broker's unit, \
         alongside OPENSTREAM_BROKER_GRANT_KEY_FILE={key_path}"
    );
    ExitCode::SUCCESS
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("openstream-enrol provisions a Unix broker's grant key and runs only there");
    ExitCode::FAILURE
}
