//! Durable, secret-free device enrollment and trust records.
//!
//! This is the local half of the product trust model. It deliberately stores
//! public identity material and policy only; account credentials, refresh
//! tokens, session capabilities, TURN passwords, and private keys belong to a
//! platform secret provider or the control-plane service and never enter this
//! file.

use openstream_app_core::{DeviceEnrollment, DeviceTrustState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const STORE_SCHEMA_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 256 * 1024;
const MAX_DEVICES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDevice {
    pub enrollment: DeviceEnrollment,
    pub trust: DeviceTrustState,
    pub last_seen_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceStoreFile {
    schema_version: u32,
    devices: Vec<StoredDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedDeviceSnapshot {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub enrolled_at_ms: u64,
    pub trust: DeviceTrustState,
    pub last_seen_ms: Option<u64>,
    /// A display-safe fingerprint. It is intentionally not the raw key.
    pub public_key_fingerprint: String,
}

#[derive(Debug)]
pub enum DeviceStoreError {
    InvalidPath,
    InvalidRecord,
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for DeviceStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "device store path is invalid",
            Self::InvalidRecord => "device enrollment record is invalid",
            Self::Io(_) => "device store I/O failed",
            Self::Json(_) => "device store data is invalid",
        })
    }
}

impl std::error::Error for DeviceStoreError {}

impl From<io::Error> for DeviceStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for DeviceStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug)]
pub struct DeviceStore {
    path: PathBuf,
    devices: BTreeMap<String, StoredDevice>,
}

impl DeviceStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DeviceStoreError> {
        let path = path.into();
        validate_path(&path)?;
        let parent = path.parent().ok_or(DeviceStoreError::InvalidPath)?;
        ensure_private_dir(parent)?;

        let devices = match read_store(&path)? {
            Some(file) => {
                if file.schema_version != STORE_SCHEMA_VERSION || file.devices.len() > MAX_DEVICES {
                    return Err(DeviceStoreError::InvalidRecord);
                }
                file.devices
                    .into_iter()
                    .map(|device| {
                        validate_device(&device)?;
                        Ok((device.enrollment.device_id.clone(), device))
                    })
                    .collect::<Result<BTreeMap<_, _>, DeviceStoreError>>()?
            }
            None => BTreeMap::new(),
        };

        Ok(Self { path, devices })
    }

    #[cfg(test)]
    pub fn for_test(path: PathBuf) -> Result<Self, DeviceStoreError> {
        Self::open(path)
    }

    pub fn records(&self) -> Vec<StoredDevice> {
        self.devices.values().cloned().collect()
    }

    pub fn snapshots(&self) -> Vec<TrustedDeviceSnapshot> {
        self.devices.values().map(snapshot).collect()
    }

    pub fn enroll(
        &mut self,
        enrollment: DeviceEnrollment,
        trust: DeviceTrustState,
    ) -> Result<(), DeviceStoreError> {
        let record = StoredDevice {
            enrollment,
            trust,
            last_seen_ms: None,
        };
        validate_device(&record)?;
        if !self.devices.contains_key(&record.enrollment.device_id)
            && self.devices.len() >= MAX_DEVICES
        {
            return Err(DeviceStoreError::InvalidRecord);
        }
        self.devices
            .insert(record.enrollment.device_id.clone(), record);
        self.save()
    }

    pub fn set_trust(
        &mut self,
        device_id: &str,
        trust: DeviceTrustState,
        last_seen_ms: Option<u64>,
    ) -> Result<(), DeviceStoreError> {
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(DeviceStoreError::InvalidRecord)?;
        device.trust = trust;
        if last_seen_ms.is_some() {
            device.last_seen_ms = last_seen_ms;
        }
        self.save()
    }

    pub fn mark_seen(&mut self, device_id: &str, now_ms: u64) -> Result<(), DeviceStoreError> {
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(DeviceStoreError::InvalidRecord)?;
        device.last_seen_ms = Some(now_ms);
        self.save()
    }

    pub fn revoke(&mut self, device_id: &str, now_ms: u64) -> Result<(), DeviceStoreError> {
        self.set_trust(device_id, DeviceTrustState::Revoked, Some(now_ms))
    }

    fn save(&self) -> Result<(), DeviceStoreError> {
        let parent = self.path.parent().ok_or(DeviceStoreError::InvalidPath)?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(DeviceStoreError::InvalidPath)?,
            std::process::id(),
            now_nanos(),
        ));
        let bytes = serde_json::to_vec_pretty(&DeviceStoreFile {
            schema_version: STORE_SCHEMA_VERSION,
            devices: self.records(),
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STORE_BYTES {
            return Err(DeviceStoreError::InvalidRecord);
        }

        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_private_file(&mut options);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            replace_file(&temporary, &self.path)?;
            // The rename is the commit point. Directory sync is best-effort
            // because some supported filesystems reject it after commit.
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
            Ok::<(), io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(DeviceStoreError::Io)
    }
}

fn read_store(path: &Path) -> Result<Option<DeviceStoreFile>, DeviceStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_STORE_BYTES
    {
        return Err(DeviceStoreError::InvalidRecord);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.mode() & 0o400 == 0 {
            return Err(DeviceStoreError::InvalidRecord);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DeviceStoreError::InvalidRecord);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_STORE_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STORE_BYTES {
        return Err(DeviceStoreError::InvalidRecord);
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn validate_path(path: &Path) -> Result<(), DeviceStoreError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(DeviceStoreError::InvalidPath);
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(DeviceStoreError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(DeviceStoreError::InvalidPath);
            }
        }
    }
    Ok(())
}

fn validate_device(device: &StoredDevice) -> Result<(), DeviceStoreError> {
    let enrollment = &device.enrollment;
    if enrollment.device_id.is_empty()
        || enrollment.device_id.len() > 128
        || enrollment.name.is_empty()
        || enrollment.name.len() > 128
        || enrollment.platform.is_empty()
        || enrollment.platform.len() > 64
        || enrollment.device_id.chars().any(char::is_control)
        || enrollment.name.chars().any(char::is_control)
        || enrollment.platform.chars().any(char::is_control)
        || enrollment.public_key == [0; 32]
    {
        return Err(DeviceStoreError::InvalidRecord);
    }
    Ok(())
}

fn snapshot(device: &StoredDevice) -> TrustedDeviceSnapshot {
    let digest = Sha256::digest(device.enrollment.public_key);
    let mut fingerprint = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(fingerprint, "{byte:02x}");
    }
    TrustedDeviceSnapshot {
        device_id: device.enrollment.device_id.clone(),
        name: device.enrollment.name.clone(),
        platform: device.enrollment.platform.clone(),
        enrolled_at_ms: device.enrollment.enrolled_at_ms,
        trust: device.trust,
        last_seen_ms: device.last_seen_ms,
        public_key_fingerprint: fingerprint,
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn ensure_private_dir(path: &Path) -> Result<(), DeviceStoreError> {
    if !path.is_absolute() {
        return Err(DeviceStoreError::InvalidPath);
    }

    // The property that has to hold is that the trust database ends up in a
    // directory this user owns and nobody else can read.
    //
    // Refusing every symlinked ancestor would be a simpler rule and the wrong
    // one: on macOS `/var`, `/tmp` and `/etc` are all symlinks, so that rule
    // rejects every `TMPDIR`, and a user whose home directory sits behind one
    // would find the product unable to start at all.
    //
    // So the directory is created and then checked where it actually landed.
    // `symlink_metadata` declines to follow only the *final* component, so
    // the ownership and mode tests below already describe the real directory
    // at the end of whatever ancestors were traversed: an attacker who
    // redirects one into a location they own fails the uid check, and one who
    // redirects it somewhere this same user owns has not crossed a trust
    // boundary. The final component is still refused outright if it is itself
    // a link, because `set_permissions` would otherwise chmod the target.
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeviceStoreError::InvalidPath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DeviceStoreError::InvalidPath);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(DeviceStoreError::InvalidPath);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(not(unix))]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
        };

        let temporary_wide = windows_wide_path(temporary)?;
        let destination_wide = windows_wide_path(destination)?;
        let replaced = unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                temporary_wide.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if replaced != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(2 | 3)) {
            return Err(error);
        }
        let created = unsafe {
            MoveFileExW(
                temporary_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if created != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, destination)
    }
}

#[cfg(windows)]
fn windows_wide_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device store path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store path inside a directory of this test's own, mirroring the
    /// production layout of `<base>/OpenStream/devices.json`.
    ///
    /// The store takes ownership of its parent -- it chmods it to 0700 -- so
    /// the parent must never be a shared directory. Returning a path directly
    /// inside `TMPDIR` pointed that at the system temp directory itself, and
    /// the cleanup below would then have tried to remove it.
    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "openstream-device-store-{label}-{}-{}",
                std::process::id(),
                now_nanos()
            ))
            .join("devices.json")
    }

    fn enrollment(id: &str) -> DeviceEnrollment {
        DeviceEnrollment {
            device_id: id.to_string(),
            name: "MacBook Pro".to_string(),
            platform: "macos".to_string(),
            public_key: [7; 32],
            enrolled_at_ms: 10,
        }
    }

    #[test]
    fn enrollment_round_trips_without_private_material() {
        let path = test_path("round-trip");
        let mut store = DeviceStore::for_test(path.clone()).unwrap();
        store
            .enroll(enrollment("mac-1"), DeviceTrustState::Pending)
            .unwrap();
        assert_eq!(store.records().len(), 1);
        assert_eq!(store.snapshots()[0].trust, DeviceTrustState::Pending);
        let reopened = DeviceStore::for_test(path.clone()).unwrap();
        assert_eq!(reopened.records(), store.records());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn revocation_is_durable_and_fingerprint_is_display_safe() {
        let path = test_path("revoke");
        let mut store = DeviceStore::for_test(path.clone()).unwrap();
        store
            .enroll(enrollment("mac-1"), DeviceTrustState::Trusted)
            .unwrap();
        store.revoke("mac-1", 20).unwrap();
        let item = store.snapshots().pop().unwrap();
        assert_eq!(item.trust, DeviceTrustState::Revoked);
        assert_eq!(item.public_key_fingerprint.len(), 16);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
