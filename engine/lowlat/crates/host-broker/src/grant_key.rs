//! Reading and writing the broker's grant key on disk.
//!
//! The key is the secret this machine shares with the control plane, pinned at
//! enrolment. The broker verifies every session approval against it, so the one
//! property that matters is that the unprivileged machine service cannot read
//! it -- a boundary the service can see through is not a boundary.
//!
//! That rules out the environment: `/proc/<pid>/environ` is readable by anyone
//! who can read the process, and a systemd unit's environment is not a secret.
//! So the key lives in a file owned by the broker's user with mode 0600, and
//! both halves of that are enforced here rather than documented and hoped for:
//! [`read`] refuses a file anybody else can read, and [`write`] creates one
//! that nobody else can.
//!
//! Not Linux-gated. The file handling is ordinary Unix and is tested on every
//! Unix CI runner, which is the point -- the Linux-only half of this crate
//! cannot be tested anywhere the maintainer usually works.

#![cfg(unix)]

use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Bits that must be clear: any access at all for group or other.
const OTHERS: u32 = 0o077;

/// Read the grant key, refusing one that is not private.
///
/// Trailing whitespace is stripped. A key written by `echo` or left by an
/// editor carries a newline, and a key that differs from the control plane's by
/// one byte fails every grant with nothing in the logs to say why.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if mode & OTHERS != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is readable or writable beyond its owner (mode {:o}); a grant key the \
                 machine service can read is not a boundary",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    let key = std::fs::read(path)?;
    let trimmed = key
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(&key[..0], |last| &key[..=last]);
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} is empty", path.display()),
        ));
    }
    Ok(trimmed.to_vec())
}

/// Write the grant key so only its owner can read it.
///
/// Created through a temporary file and renamed, so an interrupted write leaves
/// either the old key or none rather than a truncated one -- a half-written key
/// would fail every grant, and the failure would look like a control-plane
/// problem rather than a local one.
///
/// The mode is set on the temporary file *before* the key is written to it, so
/// there is no instant at which the secret exists in a world-readable file. A
/// `create` then `set_permissions` would leave exactly that window.
pub fn write(path: impl AsRef<Path>, key: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = path.as_ref();
    if key.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "refusing to write an empty grant key: it would authorise nothing and \
             the broker would report it as unconfigured",
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the grant key path has no parent directory",
        ));
    };
    std::fs::create_dir_all(parent)?;
    // The directory holds a secret, so it is the owner's too. Best effort: a
    // pre-existing directory may be owned by someone else, and the file's own
    // mode is what actually protects the key.
    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

    let staging = parent.join(format!(".grant-key.{}.new", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staging)?;
    // An existing staging file keeps its old mode, which `.mode()` does not
    // change. Set it explicitly before anything secret is written.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let result = file.write_all(key).and_then(|()| file.sync_all());
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

/// Decode a hex-encoded key.
///
/// The control plane hands the key out as hex, which is what survives being
/// pasted into an installer prompt or piped through a shell without a
/// transcoding step that could corrupt it silently.
pub fn from_hex(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "the key is empty"));
    }
    if hex.len() % 2 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the key has an odd number of hex digits, so it is truncated",
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "the key is not ASCII hex"))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "the key is not valid hex"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A directory that cleans itself up, so a failing test does not leave a
    /// key behind.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "openstream-grant-key-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_written_key_reads_back_exactly() {
        let dir = TempDir::new("roundtrip");
        let path = dir.join("grant.key");
        write(&path, b"\x00\x01\xfe\xffsecret").expect("write");
        assert_eq!(
            read(&path).expect("read"),
            b"\x00\x01\xfe\xffsecret",
            "the key must survive the round trip byte for byte; a key that \
             differs by one byte fails every grant with no diagnostic"
        );
    }

    #[test]
    fn a_written_key_is_private_to_its_owner() {
        let dir = TempDir::new("mode");
        let path = dir.join("grant.key");
        write(&path, b"secret").expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the whole point of the file is that the unprivileged machine \
             service cannot read it"
        );
    }

    #[test]
    fn a_key_anyone_can_read_is_refused() {
        let dir = TempDir::new("loose");
        let path = dir.join("grant.key");
        std::fs::write(&path, b"secret").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = read(&path).expect_err("a world-readable key must be refused");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_group_readable_key_is_refused() {
        // The machine service runs in a group of its own, so group-readable is
        // the mode that would actually leak in production -- not 0644.
        let dir = TempDir::new("group");
        let path = dir.join("grant.key");
        std::fs::write(&path, b"secret").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        let error = read(&path).expect_err("a group-readable key must be refused");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn rewriting_over_a_loose_file_makes_it_private() {
        // Provisioning has to repair a key someone previously created badly,
        // not inherit its mode. Renaming over the old file is what achieves
        // this, and this test is what notices if that becomes a plain write.
        let dir = TempDir::new("repair");
        let path = dir.join("grant.key");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write(&path, b"new").expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "provisioning must repair a loose mode");
        assert_eq!(read(&path).expect("read"), b"new");
    }

    #[test]
    fn trailing_whitespace_is_not_part_of_the_key() {
        let dir = TempDir::new("newline");
        let path = dir.join("grant.key");
        write(&path, b"secret\n").expect("write");
        assert_eq!(read(&path).expect("read"), b"secret");
    }

    #[test]
    fn an_empty_key_is_refused_on_write() {
        let dir = TempDir::new("empty-write");
        let error = write(dir.join("grant.key"), b"").expect_err("empty must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn an_empty_key_is_refused_on_read() {
        let dir = TempDir::new("empty-read");
        let path = dir.join("grant.key");
        std::fs::write(&path, b"   \n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let error = read(&path).expect_err("a whitespace-only key must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn hex_decodes_to_the_bytes_it_names() {
        assert_eq!(from_hex("00ff10").expect("decode"), vec![0x00, 0xff, 0x10]);
        assert_eq!(
            from_hex("  00ff10\n").expect("decode"),
            vec![0x00, 0xff, 0x10]
        );
    }

    #[test]
    fn a_truncated_or_malformed_key_is_refused_rather_than_guessed() {
        // Decoding "abc" as "ab" would install a key that is silently wrong,
        // and every session would then be refused for no visible reason.
        for bad in ["abc", "zz", "", "  "] {
            assert!(
                from_hex(bad).is_err(),
                "{bad:?} must be refused rather than partially decoded"
            );
        }
    }
}
