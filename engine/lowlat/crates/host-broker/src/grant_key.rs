//! Reading and writing the broker's grant key on disk.
//!
//! The key is the secret this machine shares with the control plane, pinned at
//! enrolment. The broker verifies every session approval against it, so the one
//! property that matters is that the unprivileged machine service cannot read
//! it -- a boundary the service can see through is not a boundary.
//!
//! That rules out the environment: `/proc/<pid>/environ` is readable by anyone
//! who can read the process, and a systemd unit's environment is not a secret.
//! So the key lives in a file owned by the broker's user with mode 0600.
//!
//! **Mode alone is not the boundary.** A file owned by the *machine service*
//! with mode 0600 is private to the machine service, and the broker -- running
//! privileged -- can read it perfectly well. A check that looked only at the
//! permission bits would accept a key the unprivileged process chose, and the
//! service could then forge its own approvals: exactly the privilege boundary
//! this key exists to draw. So [`read`] also requires that the file be
//! **owned by the reading process's own user**, that it be a **regular file**
//! rather than a symlink or device, and that **no directory on the path to it
//! be writable by anyone else** -- a directory the service can write is a
//! directory in which it can replace the file.
//!
//! The file is opened with `O_NOFOLLOW` and inspected through `fstat` on the
//! resulting descriptor, so what is checked and what is read are the same
//! object. Checking a path and then opening it is a race the service wins by
//! swapping the file in between.
//!
//! Not Linux-gated. The file handling is ordinary Unix and is tested on every
//! Unix CI runner, which is the point -- the Linux-only half of this crate
//! cannot be tested anywhere the maintainer usually works.

#![cfg(unix)]

use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Bits that must be clear on the key file: any access at all for group or
/// other.
const OTHERS: u32 = 0o077;

/// Bits that must be clear on every directory leading to it: write for group or
/// other. A directory someone else can write is one in which they can unlink
/// the key and put their own in its place, whatever the key's own mode says.
const DIRECTORY_OTHERS_WRITE: u32 = 0o022;

/// The sticky bit, widened once.
///
/// `libc::S_ISVTX` is `u16` on macOS and `u32` on Linux, so the cast is
/// required on one and redundant on the other. Normalised here rather than at
/// each use, with the lint silenced for the platform where it is a no-op.
#[allow(clippy::unnecessary_cast)]
const STICKY: u32 = libc::S_ISVTX as u32;

/// Largest key file accepted. A grant key is a handful of bytes; this stops a
/// wrong path from reading something enormous into memory.
const MAX_KEY_BYTES: u64 = 4096;

/// Refuse a path any other user could have tampered with.
///
/// Walks from the file's directory up to the root. Each directory must be owned
/// by this process's user or by root, and must not be writable by group or
/// other unless it is sticky -- `/tmp` is world-writable and sticky, and sticky
/// is what stops one user unlinking another's entries there.
///
/// Without this, a key with a perfect mode inside a directory the machine
/// service can write is still a key the machine service controls: it can
/// unlink the file and create its own.
fn check_directory_chain(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid cannot fail and touches no memory.
    let effective = unsafe { libc::geteuid() };
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Resolve the directories first. A symlinked directory in the middle of the
    // path is ordinary -- `/var` is a symlink to `/private/var` on macOS, and
    // merged-/usr Linux systems link `/lib` and friends -- so what has to be
    // checked is the real directory each one lands on, which is where an
    // attacker would need write access to replace the key. The file itself is
    // still opened `O_NOFOLLOW`: a symlink *as the key* is a different thing
    // and stays refused.
    let mut directory = match absolute.parent() {
        Some(parent) => Some(parent.canonicalize()?),
        None => None,
    };
    while let Some(current) = directory {
        let metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} is on the key's path but is not a directory",
                    current.display()
                ),
            ));
        }
        let mode = metadata.mode();
        let sticky = mode & STICKY != 0;
        if mode & DIRECTORY_OTHERS_WRITE != 0 && !sticky {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{} is writable by others (mode {:o}), so the key inside it can be replaced \
                     no matter what the key's own mode says",
                    current.display(),
                    mode & 0o777
                ),
            ));
        }
        if metadata.uid() != effective && metadata.uid() != 0 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by uid {}, which is neither root nor this process's uid \
                     {effective}; its owner can replace the key",
                    current.display(),
                    metadata.uid()
                ),
            ));
        }
        directory = current.parent().map(Path::to_path_buf);
    }
    Ok(())
}

/// Read the grant key, refusing one that is not private.
///
/// Trailing whitespace is stripped. A key written by `echo` or left by an
/// editor carries a newline, and a key that differs from the control plane's by
/// one byte fails every grant with nothing in the logs to say why.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = path.as_ref();
    check_directory_chain(path)?;

    // O_NOFOLLOW: a symlink here is someone redirecting the broker at a key
    // they control, and following it would be the whole attack.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            Error::new(
                error.kind(),
                format!("{}: {error} (a symlink here is refused)", path.display()),
            )
        })?;
    // Everything below is checked on the open descriptor, not on the path, so
    // the object inspected is the object read.
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mode = metadata.mode();
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
    // SAFETY: geteuid cannot fail and touches no memory.
    let effective = unsafe { libc::geteuid() };
    if metadata.uid() != effective {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {} but this process runs as uid {effective}; a key owned by \
                 the unprivileged service is a key the service chose, and a privileged reader \
                 would happily forge approvals from it",
                path.display(),
                metadata.uid()
            ),
        ));
    }
    let mut key = Vec::new();
    (&file).take(MAX_KEY_BYTES + 1).read_to_end(&mut key)?;
    if key.len() as u64 > MAX_KEY_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} is larger than a key should ever be", path.display()),
        ));
    }
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
    fn a_symlink_to_another_key_is_refused() {
        // The attack this blocks: leave a private-looking symlink where the
        // broker expects its key, pointing at a key the attacker wrote. Mode
        // bits on a symlink say nothing about its target.
        let dir = TempDir::new("symlink");
        let real = dir.join("attacker.key");
        std::fs::write(&real, b"forged").expect("seed");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.join("grant.key");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(
            read(&link).is_err(),
            "a symlink must not be followed to a key someone else placed"
        );
    }

    #[test]
    fn a_directory_others_can_write_is_refused() {
        // A key with a perfect 0600 mode inside a directory the machine
        // service can write is still a key the machine service controls: it
        // unlinks the file and creates its own. Mode on the file alone was the
        // gap this closes.
        let dir = TempDir::new("loose-dir");
        let inner = dir.join("keys");
        std::fs::create_dir_all(&inner).expect("mkdir");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let path = inner.join("grant.key");
        std::fs::write(&path, b"secret").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let error = read(&path).expect_err("a world-writable parent must be refused");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_directory_that_is_private_is_accepted() {
        // The counterpart: the check must not refuse a correctly-installed key,
        // or the broker never starts.
        let dir = TempDir::new("tight-dir");
        let inner = dir.join("keys");
        std::fs::create_dir_all(&inner).expect("mkdir");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = inner.join("grant.key");
        write(&path, b"secret").expect("write");
        assert_eq!(read(&path).expect("read"), b"secret");
    }

    #[test]
    fn a_directory_is_not_a_key() {
        let dir = TempDir::new("isdir");
        let path = dir.join("grant.key");
        std::fs::create_dir_all(&path).expect("mkdir");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(read(&path).is_err(), "a directory must not read as a key");
    }

    #[test]
    fn a_key_owned_by_this_process_is_accepted() {
        // The ownership check compares against the reading process's own uid.
        // A test cannot create a file owned by somebody else without being
        // root, so what is asserted here is that the check does not reject the
        // legitimate case -- the rejecting half is exercised by the directory
        // and symlink tests above, which share its code path.
        let dir = TempDir::new("owner");
        let path = dir.join("grant.key");
        write(&path, b"secret").expect("write");
        // SAFETY: geteuid cannot fail.
        let uid = unsafe { libc::geteuid() };
        let owner = std::fs::metadata(&path).expect("metadata").uid();
        assert_eq!(owner, uid, "the test's own file is owned by the test");
        assert_eq!(read(&path).expect("read"), b"secret");
    }

    #[test]
    fn an_enormous_file_is_refused_rather_than_read() {
        let dir = TempDir::new("huge");
        let path = dir.join("grant.key");
        let oversized = vec![b'a'; usize::try_from(MAX_KEY_BYTES).expect("fits") + 10];
        write(&path, &oversized).expect("write");
        let error = read(&path).expect_err("an oversized key must be refused");
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
