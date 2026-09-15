//! Keystore custody of the device identity, exercised as a whole.
//!
//! This lives in its own integration binary because it sets process-wide
//! environment variables; sharing a process with other tests would make the
//! result depend on scheduling.
//!
//! Ignored by default: it writes to the developer's login keychain. Run it
//! deliberately with `--ignored`.

#![cfg(target_os = "macos")]

use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("openstream-identity-{name}-{}", std::process::id()))
}

#[test]
#[ignore = "writes to the login keychain"]
fn a_fresh_identity_lives_only_in_the_keystore_and_is_stable_across_runs() {
    let directory = scratch("fresh");
    let store = directory.join("device-identity.pk8");
    let _ = std::fs::remove_dir_all(&directory);

    // SAFETY: this test binary runs alone, which is why it is its own file.
    unsafe {
        std::env::set_var("OPENSTREAM_IDENTITY_CUSTODY", "keystore");
        std::env::set_var("OPENSTREAM_IDENTITY_STORE", &store);
    }

    let first = openstream_client_core::local_identity_public_key().expect("first identity");

    // Keystore custody means the private key does not go to disk at all.
    assert!(
        !store.exists(),
        "a fresh identity under keystore custody must not be written to {}",
        store.display()
    );

    let second = openstream_client_core::local_identity_public_key().expect("second identity");
    assert_eq!(
        first, second,
        "the identity must be the same key on the next run, not a new one"
    );

    // Leave no residue in the developer's keychain. Deleting by service name
    // passes no secret on the command line, which is exactly why the CLI is
    // not used to *store* anything.
    let _ = std::process::Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            "com.openstream.device-identity",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::fs::remove_dir_all(&directory);
}
