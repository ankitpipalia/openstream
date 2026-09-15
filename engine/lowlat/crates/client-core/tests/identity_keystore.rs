//! Keystore custody of the device identity, exercised as a whole.
//!
//! This lives in its own integration binary because it sets process-wide
//! environment variables; sharing a process with other tests would make the
//! result depend on scheduling.
//!
//! macOS only, and deliberately. The account name is derived inside the crate
//! from the store path, so an integration test cannot compute it to clean up
//! afterwards; here the whole service can be cleared by name instead. The
//! Linux platform layer is covered by the round-trip test inside
//! `keystore.rs`, which knows its own account and removes it.
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

#[test]
#[ignore = "writes to the login keychain"]
fn a_lost_keystore_refuses_rather_than_enrolling_a_different_device() {
    let directory = scratch("lost");
    let store = directory.join("device-identity.pk8");
    let _ = std::fs::remove_dir_all(&directory);

    // SAFETY: this test binary runs alone, which is why it is its own file.
    unsafe {
        std::env::set_var("OPENSTREAM_IDENTITY_CUSTODY", "keystore");
        std::env::set_var("OPENSTREAM_IDENTITY_STORE", &store);
    }

    let first = openstream_client_core::local_identity_public_key().expect("identity in keystore");
    assert!(
        !store.exists(),
        "keystore custody must not write the key to disk"
    );

    // Take the keystore away, leaving the custody marker behind. This is a
    // locked or stopped keyring, and the only safe answer is to refuse: a new
    // identity here would silently enrol the machine as a different device.
    let cleared = std::process::Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            "com.openstream.device-identity",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    assert!(
        cleared.map(|s| s.success()).unwrap_or(false),
        "entry removed"
    );

    let after = openstream_client_core::local_identity_public_key();
    assert!(
        after.is_err(),
        "a lost keystore must refuse, not mint a replacement identity"
    );
    assert!(
        !store.exists(),
        "refusing must not leave a freshly generated key on disk"
    );
    let _ = first;

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
#[ignore = "writes to the login keychain"]
fn a_migrated_device_recovers_from_the_retained_file_when_the_keystore_is_lost() {
    let directory = scratch("migrated");
    let store = directory.join("device-identity.pk8");
    let _ = std::fs::remove_dir_all(&directory);

    // Start with a file-based identity so a real file exists to migrate. Default
    // custody is file, so the key is written to disk here.
    // SAFETY: this test binary runs alone, which is why it is its own file.
    unsafe {
        std::env::remove_var("OPENSTREAM_IDENTITY_CUSTODY");
        std::env::set_var("OPENSTREAM_IDENTITY_STORE", &store);
    }
    let original = openstream_client_core::local_identity_public_key().expect("file identity");
    assert!(store.exists(), "file custody writes the key to disk");

    // Migrate it into the keystore. The migration deliberately keeps the file as
    // a fallback and records a custody marker.
    unsafe {
        std::env::set_var("OPENSTREAM_IDENTITY_CUSTODY", "keystore");
    }
    let migrated = openstream_client_core::local_identity_public_key().expect("migrated identity");
    assert_eq!(original, migrated, "migration keeps the same identity");
    assert!(store.exists(), "migration keeps the file as a fallback");

    // Lose the keystore entry, leaving the marker and the retained file behind.
    let cleared = std::process::Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            "com.openstream.device-identity",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    assert!(
        cleared.map(|s| s.success()).unwrap_or(false),
        "entry removed"
    );

    // The retained file holds the same identity, so a migrated device must
    // recover from it rather than refusing. Recovery must never mint a
    // different device.
    let recovered = openstream_client_core::local_identity_public_key()
        .expect("a retained file fallback must let a migrated device recover, not refuse");
    assert_eq!(
        original, recovered,
        "recovery uses the retained identity, not a newly minted one"
    );

    let _ = std::process::Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            "com.openstream.device-identity",
        ])
        .status();
    let _ = std::fs::remove_dir_all(&directory);
}
