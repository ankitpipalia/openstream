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

/// A destination proved ready to receive the grant key.
///
/// The grant key is issued exactly once, by the enrolment that creates the
/// device, and no endpoint reads it back. So the order of operations around it
/// is not a detail: everything that can fail about *storing* the key has to
/// fail before the request that produces it, or a routine problem -- a
/// mistyped path, a directory owned by someone else, a full disk -- turns into
/// an enrolled device whose key no longer exists anywhere.
///
/// [`prepare`] does all of that work up front. It creates and checks the
/// directory and then *actually creates the file*, 0600, in the directory the
/// key will live in. What is left for [`PreparedKeyFile::commit`] is a write
/// to an open descriptor and a rename within one directory: the two operations
/// with nothing left to discover.
///
/// Dropping one without committing removes the empty staging file.
#[must_use = "a prepared destination that is never committed just removes itself"]
pub struct PreparedKeyFile {
    /// Where the key ends up.
    destination: std::path::PathBuf,
    /// The directory holding both, fsynced after the rename.
    parent: std::path::PathBuf,
    /// The open 0600 staging file, taken by `commit`.
    staging: Option<(std::path::PathBuf, std::fs::File)>,
}

impl std::fmt::Debug for PreparedKeyFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedKeyFile")
            .field("destination", &self.destination)
            .finish()
    }
}

impl Drop for PreparedKeyFile {
    fn drop(&mut self) {
        // An uncommitted staging file is an empty 0600 file with this
        // process's pid in its name. Harmless, but leaving it behind means the
        // next run has to reason about it.
        if let Some((staging, file)) = self.staging.take() {
            drop(file);
            let _ = std::fs::remove_file(staging);
        }
    }
}

impl PreparedKeyFile {
    /// Where the key will be written.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Write the key and put it in place.
    ///
    /// The mode was set when the staging file was created, before this is
    /// called, so there is no instant at which the secret exists in a
    /// world-readable file. A `create` then `set_permissions` would leave
    /// exactly that window.
    ///
    /// The rename is atomic, so an interrupted commit leaves either the old
    /// key or none rather than a truncated one -- a half-written key fails
    /// every grant, and the failure looks like a control-plane problem rather
    /// than a local one.
    pub fn commit(mut self, key: &[u8]) -> Result<()> {
        use std::io::Write;

        if key.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "refusing to write an empty grant key: it would authorise nothing and \
                 the broker would report it as unconfigured",
            ));
        }
        let Some((staging, mut file)) = self.staging.take() else {
            return Err(Error::other(
                "the prepared grant key file was already committed",
            ));
        };
        let written = file.write_all(key).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = std::fs::remove_file(&staging);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&staging, &self.destination) {
            let _ = std::fs::remove_file(&staging);
            return Err(error);
        }
        // The key's own bytes are on disk, but the directory entry naming them
        // may not be: after a power cut the rename can be lost and the key
        // with it. Syncing the parent is what makes the new name durable.
        sync_directory(&self.parent)
    }
}

/// Fsync a directory, tolerating filesystems that do not implement it.
///
/// Linux requires this to work and macOS implements it. Some network and
/// pseudo filesystems answer `EINVAL` instead, and there the rename is as
/// durable as it is going to get -- failing would roll back an enrolment whose
/// key is in fact perfectly readable.
fn sync_directory(parent: &Path) -> Result<()> {
    match std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => Ok(()),
        Err(error) => Err(Error::new(
            error.kind(),
            format!(
                "wrote the grant key but could not sync {}: {error}",
                parent.display()
            ),
        )),
    }
}

/// Prove the destination can hold the key, before anything issues one.
///
/// Creates the directory, tightens it, checks it is one [`read`] will accept,
/// and creates the 0600 file the key will be written into. Succeeding here
/// means the remaining work is a write to an open descriptor and a rename
/// between two names in the same directory.
///
/// The staging file is a sibling of the destination rather than something in
/// `/tmp`, which is what makes the rename a rename: across filesystems it
/// would be a copy, and a copy can fail halfway for all the reasons this is
/// trying to rule out.
pub fn prepare(path: impl AsRef<Path>) -> Result<PreparedKeyFile> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the grant key path is empty",
        ));
    }
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the grant key path has no parent directory",
        ));
    };
    // `create_dir_all` answers EEXIST when something on the path is a file,
    // and "File exists" is a baffling thing to read about a key that does not.
    if let Err(error) = std::fs::create_dir_all(parent) {
        let existing = std::fs::symlink_metadata(parent);
        return Err(match existing {
            Ok(metadata) if !metadata.is_dir() => Error::new(
                ErrorKind::NotADirectory,
                format!("{} is not a directory", parent.display()),
            ),
            _ => Error::new(
                error.kind(),
                format!("could not create {}: {error}", parent.display()),
            ),
        });
    }
    // The directory holds a secret, so it is the owner's too. Best effort: a
    // pre-existing directory may be owned by someone else, and the file's own
    // mode is what actually protects the key.
    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

    // Refuse to install into a directory `read` will later reject. Without
    // this, a key written somewhere others can write succeeds here and fails
    // at the far end of the chain, where the only symptom is the broker
    // refusing every session with nothing pointing at the directory.
    check_directory_chain(path)?;

    let staging = parent.join(format!(".grant-key.{}.new", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    // `create_new` is O_CREAT|O_EXCL, so a symlink planted at this name is an
    // error rather than a redirect, and two enrolments cannot share a file.
    options.write(true).create_new(true).mode(0o600);
    let file = match options.open(&staging) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            // Left by a run that died between creating this and renaming it.
            // Only this process's pid names it, and the directory was just
            // checked to be writable by nobody else, so removing it is safe.
            std::fs::remove_file(&staging)?;
            options.open(&staging)?
        }
        Err(error) => return Err(error),
    };
    // `open`'s mode argument is masked by the umask, which can only clear
    // bits -- so 0600 cannot widen, but an unusual umask can narrow it to
    // something the broker cannot open on a later run. Set it outright.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(PreparedKeyFile {
        destination: path.to_path_buf(),
        parent: parent.to_path_buf(),
        staging: Some((staging, file)),
    })
}

/// Write the grant key so only its owner can read it.
///
/// [`prepare`] then [`PreparedKeyFile::commit`], for callers that already hold
/// the key and so have nothing to gain from separating the two. Anything that
/// obtains the key over the network should prepare first: see [`prepare`].
pub fn write(path: impl AsRef<Path>, key: &[u8]) -> Result<()> {
    prepare(path)?.commit(key)
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
    fn writing_tightens_a_loose_directory_it_owns_and_the_key_reads_back() {
        // Installing has to leave a state `read` will accept, or the key lands
        // cleanly and then makes the broker refuse every session with nothing
        // naming the directory that caused it.
        //
        // A directory this process owns is repaired: 0777 becomes 0700. The
        // other case -- a directory owned by *someone else*, where the repair
        // fails and `check_directory_chain` refuses -- cannot be built in a
        // unit test without root, so what is pinned here is that install and
        // read agree. The refusing path is the same function the symlink and
        // world-writable read tests exercise.
        let dir = TempDir::new("write-loose-dir");
        let inner = dir.join("keys");
        std::fs::create_dir_all(&inner).expect("mkdir");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let path = inner.join("grant.key");
        write(&path, b"secret").expect("write");
        assert_eq!(
            std::fs::metadata(&inner)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the directory must be tightened, or the key is replaceable"
        );
        assert_eq!(
            read(&path).expect("a freshly installed key must read back"),
            b"secret"
        );
    }

    #[test]
    fn preparing_refuses_a_bad_destination_before_any_key_exists() {
        // The whole point of the split. Every one of these used to be
        // discovered *after* enrolment had already minted the one key the
        // control plane will ever issue for that device.
        let dir = TempDir::new("prepare-refuses");

        // A path whose parent is a file, not a directory.
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("seed");
        prepare(blocker.join("grant.key")).expect_err("a file cannot be a parent directory");

        // A directory owned by this user but writable by everyone, which
        // `read` refuses -- and which the repair cannot fix, because the test
        // makes it loose again underneath a parent that stays loose.
        let loose = dir.join("loose");
        std::fs::create_dir_all(&loose).expect("mkdir");
        let nested = loose.join("inner");
        std::fs::create_dir_all(&nested).expect("mkdir");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let error = prepare(nested.join("grant.key"))
            .expect_err("a chain with a world-writable directory must be refused");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        // An empty path: the shape an unset environment variable takes once it
        // has been through a systemd unit that sets it to nothing.
        prepare("").expect_err("an empty path must be refused");
    }

    #[test]
    fn preparing_creates_the_file_so_committing_only_writes_and_renames() {
        // What makes the ordering safe is that `prepare` leaves nothing to
        // discover: the file exists, 0600, in the directory the key will live
        // in, so the commit is a write to an open descriptor and a rename
        // between two names in one directory.
        let dir = TempDir::new("prepare-creates");
        let path = dir.join("keys").join("grant.key");
        let prepared = prepare(&path).expect("prepare");
        assert_eq!(prepared.destination(), path.as_path());

        let staging: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("readdir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(staging.len(), 1, "prepare must create exactly one file");
        assert_eq!(
            std::fs::metadata(&staging[0])
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the staging file must be private before the secret is written to it"
        );
        assert!(
            !path.exists(),
            "the destination must not exist until commit"
        );

        prepared.commit(b"secret").expect("commit");
        assert_eq!(read(&path).expect("read"), b"secret");
        let left: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("readdir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(left, vec![path], "the staging file must not be left behind");
    }

    #[test]
    fn dropping_a_prepared_file_without_committing_leaves_nothing() {
        // The enrolment path prepares first and then may never commit --
        // because enrolment failed, or because the device already existed. It
        // must not leave a stray file behind each time.
        let dir = TempDir::new("prepare-drop");
        let path = dir.join("keys").join("grant.key");
        drop(prepare(&path).expect("prepare"));
        let left: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("readdir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert!(left.is_empty(), "an abandoned preparation left {left:?}");
    }

    #[test]
    fn a_leftover_staging_file_does_not_block_a_retry() {
        // A run killed between prepare and commit leaves an empty staging file
        // named after its pid. A later run in the same process -- which is what
        // a retry looks like in a test, and what pid reuse looks like on a
        // machine -- must not fail on it.
        let dir = TempDir::new("prepare-leftover");
        let path = dir.join("grant.key");
        let name = format!(".grant-key.{}.new", std::process::id());
        let stale = dir.join(&name);
        std::fs::write(&stale, b"leftover").expect("seed");
        prepare(&path)
            .expect("prepare")
            .commit(b"secret")
            .expect("commit");
        assert_eq!(read(&path).expect("read"), b"secret");
    }

    #[test]
    fn an_empty_key_is_refused_after_preparing_too() {
        // `commit` is the last gate before a key file exists, and an empty one
        // reads back as "unconfigured" with nothing saying why.
        let dir = TempDir::new("prepare-empty-key");
        let path = dir.join("grant.key");
        let error = prepare(&path)
            .expect("prepare")
            .commit(b"")
            .expect_err("empty key");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(!path.exists(), "no file may be left for an empty key");
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
