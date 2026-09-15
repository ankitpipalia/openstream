//! OS-backed custody for the device identity key.
//!
//! The file-based store is sound as far as it goes: the key is `0600` inside a
//! `0700` directory and published atomically. What it cannot do is keep the key
//! away from other processes running as the same user, which is the whole point
//! of handing it to the platform instead.
//!
//! Only macOS is implemented. Everywhere else this reports itself unavailable
//! and the caller keeps the file, rather than pretending to a protection that
//! is not there.
//!
//! Note on what is deliberately *not* used here: `security add-generic-password`
//! and `secret-tool store` both take the secret as a command-line argument,
//! where any process on the machine can read it out of `ps`. Routing the
//! identity key through either would leave it more exposed than the file it
//! replaced. See docs/DEFERRED_FEATURES.md.

/// Whether this build can use a platform keystore at all.
pub(crate) fn available() -> bool {
    platform::AVAILABLE
}

/// Read the stored key, or `None` when there is no entry.
///
/// An error is not distinguished from a missing entry on purpose: both mean
/// "the keystore did not give a key", and the only safe response to either is
/// to fall back to the file.
pub(crate) fn load(account: &str) -> Option<Vec<u8>> {
    platform::load(account)
}

/// Store the key, replacing any existing entry for the account.
pub(crate) fn store(account: &str, secret: &[u8]) -> Result<(), String> {
    platform::store(account, secret)
}

/// Remove an entry. This exists so the round-trip test leaves no residue in
/// the developer's keychain; the product never deletes an identity.
#[cfg(test)]
pub(crate) fn remove(account: &str) -> Result<(), String> {
    platform::remove(account)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_void;

    pub(super) const AVAILABLE: bool = true;

    /// The item is scoped to this application and this device: it never syncs
    /// to iCloud and is not carried into a backup. `AfterFirstUnlock` rather
    /// than `WhenUnlocked` so a host that starts at login can reach its own
    /// identity without a human present.
    const SERVICE: &str = "com.openstream.device-identity";

    type CFTypeRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type OsStatus = i32;

    const ERR_SEC_SUCCESS: OsStatus = 0;
    const ERR_SEC_DUPLICATE_ITEM: OsStatus = -25299;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
        static kCFBooleanTrue: CFTypeRef;

        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external: u8,
        ) -> CFStringRef;
        fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: isize) -> CFDataRef;
        fn CFDataGetLength(data: CFDataRef) -> isize;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDictionaryCreate(
            alloc: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecAttrAccessible: CFStringRef;
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;

        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OsStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OsStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OsStatus;
    }

    /// A CoreFoundation object released when it goes out of scope. Every
    /// Create call below returns an owned reference, and the query paths have
    /// several early returns, so releasing by hand would leak on the first one
    /// that was missed.
    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: only constructed from a Create/Copy result, which is
                // an owned reference, and only dropped once.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn cf_string(value: &str) -> Option<Owned> {
        // SAFETY: the pointer and length describe `value`, which outlives the
        // call; CoreFoundation copies the bytes.
        let raw = unsafe {
            CFStringCreateWithBytes(
                kCFAllocatorDefault,
                value.as_ptr(),
                isize::try_from(value.len()).ok()?,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        (!raw.is_null()).then_some(Owned(raw))
    }

    fn cf_data(value: &[u8]) -> Option<Owned> {
        // SAFETY: as above; CoreFoundation copies the bytes.
        let raw = unsafe {
            CFDataCreate(
                kCFAllocatorDefault,
                value.as_ptr(),
                isize::try_from(value.len()).ok()?,
            )
        };
        (!raw.is_null()).then_some(Owned(raw))
    }

    fn cf_dictionary(pairs: &[(CFTypeRef, CFTypeRef)]) -> Option<Owned> {
        let keys: Vec<CFTypeRef> = pairs.iter().map(|(key, _)| *key).collect();
        let values: Vec<CFTypeRef> = pairs.iter().map(|(_, value)| *value).collect();
        // SAFETY: both slices have `pairs.len()` entries and outlive the call;
        // the type callbacks are the standard CoreFoundation ones.
        let raw = unsafe {
            CFDictionaryCreate(
                kCFAllocatorDefault,
                keys.as_ptr(),
                values.as_ptr(),
                isize::try_from(pairs.len()).ok()?,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            )
        };
        (!raw.is_null()).then_some(Owned(raw))
    }

    pub(super) fn load(account: &str) -> Option<Vec<u8>> {
        let service = cf_string(SERVICE)?;
        let account = cf_string(account)?;
        // SAFETY: reading framework string constants.
        let query = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account.0),
                (kSecReturnData, kCFBooleanTrue),
                (kSecMatchLimit, kSecMatchLimitOne),
            ])?
        };

        let mut found: CFTypeRef = std::ptr::null();
        // SAFETY: `query` is a valid dictionary; `found` receives an owned
        // reference only when the call succeeds.
        let status = unsafe { SecItemCopyMatching(query.0, &raw mut found) };
        if status != ERR_SEC_SUCCESS || found.is_null() {
            return None;
        }
        let data = Owned(found);
        // SAFETY: a successful kSecReturnData query yields a CFData.
        let length = unsafe { CFDataGetLength(data.0) };
        // SAFETY: as above; the pointer is valid for `length` bytes while
        // `data` is alive.
        let bytes = unsafe { CFDataGetBytePtr(data.0) };
        if bytes.is_null() || length <= 0 {
            return None;
        }
        let length = usize::try_from(length).ok()?;
        // SAFETY: `bytes` is valid for `length` bytes for the lifetime of
        // `data`, and the copy finishes before `data` is dropped.
        Some(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec())
    }

    #[cfg(test)]
    pub(super) fn remove(account: &str) -> Result<(), String> {
        let service = cf_string(SERVICE).ok_or("could not build the keychain service name")?;
        let account = cf_string(account).ok_or("could not build the keychain account")?;
        // SAFETY: reading framework string constants.
        let query = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account.0),
            ])
            .ok_or("could not build the keychain query")?
        };
        // SAFETY: `query` is a valid dictionary.
        let status = unsafe { SecItemDelete(query.0) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(format!(
                "the keychain refused the delete (OSStatus {status})"
            ))
        }
    }

    pub(super) fn store(account: &str, secret: &[u8]) -> Result<(), String> {
        let service = cf_string(SERVICE).ok_or("could not build the keychain service name")?;
        let account_string = cf_string(account).ok_or("could not build the keychain account")?;
        let value = cf_data(secret).ok_or("could not wrap the key for the keychain")?;

        // SAFETY: reading framework string constants.
        let attributes = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account_string.0),
                (kSecValueData, value.0),
                (
                    kSecAttrAccessible,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                ),
            ])
            .ok_or("could not build the keychain item")?
        };

        // SAFETY: `attributes` is a valid dictionary; no result is requested.
        let status = unsafe { SecItemAdd(attributes.0, std::ptr::null_mut()) };
        if status == ERR_SEC_SUCCESS {
            return Ok(());
        }
        if status != ERR_SEC_DUPLICATE_ITEM {
            return Err(format!("the keychain refused the item (OSStatus {status})"));
        }

        // Replace rather than update: an existing entry under this account is
        // either the same key or a stale one, and both are answered by writing
        // the current key.
        // SAFETY: reading framework string constants.
        let query = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account_string.0),
            ])
            .ok_or("could not build the keychain query")?
        };
        // SAFETY: `query` is a valid dictionary.
        let deleted = unsafe { SecItemDelete(query.0) };
        if deleted != ERR_SEC_SUCCESS {
            return Err(format!(
                "the keychain would not replace the item (OSStatus {deleted})"
            ));
        }
        // SAFETY: as above.
        let status = unsafe { SecItemAdd(attributes.0, std::ptr::null_mut()) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(format!("the keychain refused the item (OSStatus {status})"))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub(super) const AVAILABLE: bool = false;

    pub(super) fn load(_account: &str) -> Option<Vec<u8>> {
        None
    }

    pub(super) fn store(_account: &str, _secret: &[u8]) -> Result<(), String> {
        Err("no platform keystore is implemented for this target".into())
    }

    #[cfg(test)]
    pub(super) fn remove(_account: &str) -> Result<(), String> {
        Err("no platform keystore is implemented for this target".into())
    }
}

#[cfg(test)]
mod tests {
    /// A real keychain round trip. Ignored by default because it writes to
    /// the developer's own login keychain and can raise an authorization
    /// prompt; run it deliberately with `--ignored`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the login keychain"]
    fn a_stored_key_comes_back_byte_for_byte() {
        let account = format!("openstream-test-{}", std::process::id());
        let secret: Vec<u8> = (0..64_u8).collect();
        super::store(&account, &secret).expect("store");
        assert_eq!(super::load(&account).as_deref(), Some(secret.as_slice()));

        // Storing again must replace rather than fail or duplicate.
        let replacement: Vec<u8> = (64..128_u8).collect();
        super::store(&account, &replacement).expect("replace");
        assert_eq!(
            super::load(&account).as_deref(),
            Some(replacement.as_slice())
        );

        super::remove(&account).expect("clean up the test item");
        assert!(super::load(&account).is_none(), "the item must be gone");
    }

    #[test]
    fn an_account_with_no_entry_reads_as_absent() {
        let account = format!("openstream-absent-{}", std::process::id());
        assert!(super::load(&account).is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn targets_without_an_implementation_say_so_rather_than_pretending() {
        assert!(!super::available());
        assert!(super::store("account", b"secret").is_err());
    }
}
