//! OS-backed custody for the device identity key.
//!
//! The file-based store is sound as far as it goes: the key is `0600` inside a
//! `0700` directory and published atomically. What it cannot do is keep the key
//! away from other processes running as the same user, which is the whole point
//! of handing it to the platform instead.
//!
//! macOS uses the login keychain through Security.framework. Linux uses the
//! Secret Service through libsecret, resolved at runtime so nothing is linked
//! against it. Everywhere else, and on a Linux machine without libsecret or
//! without a reachable keyring, this reports itself unavailable and the caller
//! keeps the file, rather than pretending to a protection that is not there.
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

/// What a keystore read found.
#[derive(Debug)]
pub(crate) enum Lookup {
    /// The entry was there and came back.
    Found(Vec<u8>),
    /// The keystore answered, and has no entry for this account.
    Absent,
    /// The keystore could not be asked: no implementation, no library, or no
    /// running service. Distinct from `Absent` because the two call for
    /// opposite responses -- one may mint a new identity, the other must not.
    Unavailable(String),
}

/// Read the stored key.
pub(crate) fn load(account: &str) -> Lookup {
    platform::load(account)
}

/// Store the key, replacing any existing entry for the account.
pub(crate) fn store(account: &str, secret: &[u8]) -> Result<(), String> {
    platform::store(account, secret)
}

/// Remove an entry. This exists so the round-trip test leaves no residue in
/// the developer's keychain; the product never deletes an identity.
///
/// Gated on the platforms that implement a keystore as well as on test,
/// because the only caller is the round-trip test: elsewhere it would be dead
/// code, which this workspace treats as an error.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
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

    /// `errSecItemNotFound`: the keychain answered and holds no such item.
    const ERR_SEC_ITEM_NOT_FOUND: OsStatus = -25300;

    pub(super) fn load(account: &str) -> super::Lookup {
        let Some(service) = cf_string(SERVICE) else {
            return super::Lookup::Unavailable("could not build the keychain service name".into());
        };
        let Some(account) = cf_string(account) else {
            return super::Lookup::Unavailable("could not build the keychain account".into());
        };
        // SAFETY: reading framework string constants.
        let query = unsafe {
            cf_dictionary(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecAttrAccount, account.0),
                (kSecReturnData, kCFBooleanTrue),
                (kSecMatchLimit, kSecMatchLimitOne),
            ])
        };
        let Some(query) = query else {
            return super::Lookup::Unavailable("could not build the keychain query".into());
        };

        let mut found: CFTypeRef = std::ptr::null();
        // SAFETY: `query` is a valid dictionary; `found` receives an owned
        // reference only when the call succeeds.
        let status = unsafe { SecItemCopyMatching(query.0, &raw mut found) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return super::Lookup::Absent;
        }
        if status != ERR_SEC_SUCCESS || found.is_null() {
            return super::Lookup::Unavailable(format!(
                "the keychain refused the query (OSStatus {status})"
            ));
        }
        let data = Owned(found);
        // SAFETY: a successful kSecReturnData query yields a CFData.
        let length = unsafe { CFDataGetLength(data.0) };
        // SAFETY: as above; the pointer is valid for `length` bytes while
        // `data` is alive.
        let bytes = unsafe { CFDataGetBytePtr(data.0) };
        if bytes.is_null() || length <= 0 {
            return super::Lookup::Unavailable("the keychain returned an empty item".into());
        }
        let Ok(length) = usize::try_from(length) else {
            return super::Lookup::Unavailable("the keychain item is impossibly large".into());
        };
        // SAFETY: `bytes` is valid for `length` bytes for the lifetime of
        // `data`, and the copy finishes before `data` is dropped.
        super::Lookup::Found(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec())
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

#[cfg(target_os = "linux")]
mod platform {
    //! Secret Service through libsecret, resolved at runtime.
    //!
    //! libsecret is never linked. A machine without it -- a headless host, a
    //! container -- gets a keystore that reports itself unavailable and a
    //! caller that keeps the file, rather than a binary that will not start.
    //! That is the same rule the vendor codec runtimes follow.

    use std::ffi::{CStr, CString, c_char, c_int, c_void};
    use std::sync::OnceLock;

    use lowlat_common::dynlib::Library;

    pub(super) const AVAILABLE: bool = true;

    const SCHEMA_NAME: &CStr = c"com.openstream.DeviceIdentity";
    const ATTRIBUTE_ACCOUNT: &CStr = c"account";
    const LABEL: &CStr = c"OpenStream device identity";
    /// libsecret's `SECRET_COLLECTION_DEFAULT`.
    const COLLECTION_DEFAULT: &CStr = c"default";

    const SECRET_SCHEMA_NONE: c_int = 0;
    const SECRET_SCHEMA_ATTRIBUTE_STRING: c_int = 0;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SchemaAttribute {
        name: *const c_char,
        kind: c_int,
    }

    /// Mirrors `SecretSchema`. The trailing reserved fields are part of the
    /// published layout and have to be present even though nothing reads
    /// them: libsecret copies the struct by value.
    #[repr(C)]
    struct Schema {
        name: *const c_char,
        flags: c_int,
        attributes: [SchemaAttribute; 32],
        reserved: c_int,
        reserved1: *mut c_void,
        reserved2: *mut c_void,
        reserved3: *mut c_void,
        reserved4: *mut c_void,
        reserved5: *mut c_void,
        reserved6: *mut c_void,
        reserved7: *mut c_void,
    }

    // Declared variadic, because that is what these are. Calling a variadic
    // function through a non-variadic pointer is not the same ABI.
    type StoreSync = unsafe extern "C" fn(
        *const Schema,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut c_void,
        *mut c_void,
        ...
    ) -> c_int;
    type LookupSync =
        unsafe extern "C" fn(*const Schema, *mut c_void, *mut c_void, ...) -> *mut c_char;
    #[cfg(test)]
    type ClearSync = unsafe extern "C" fn(*const Schema, *mut c_void, *mut c_void, ...) -> c_int;
    type FreePassword = unsafe extern "C" fn(*mut c_char);
    /// From glib, reached through libsecret's own dependency graph: dlsym on a
    /// handle searches the library and everything it links.
    type ErrorFree = unsafe extern "C" fn(*mut c_void);

    struct Secret {
        /// Held so the library stays mapped. Dropping this would `dlclose`
        /// libsecret, and a later reload cannot re-register its GObject
        /// types; see `secret()`. Nothing in this module drops it.
        _library: Library,
        store: StoreSync,
        lookup: LookupSync,
        /// Only the round-trip test clears an entry; the product never
        /// deletes an identity, so outside test builds this is not resolved
        /// and the field is not carried.
        #[cfg(test)]
        clear: ClearSync,
        free: FreePassword,
        /// Optional: without it a failed call leaks one small GError, which is
        /// better than refusing to use the keystore at all.
        error_free: Option<ErrorFree>,
    }

    fn schema() -> Schema {
        let mut attributes = [SchemaAttribute {
            name: std::ptr::null(),
            kind: 0,
        }; 32];
        attributes[0] = SchemaAttribute {
            name: ATTRIBUTE_ACCOUNT.as_ptr(),
            kind: SECRET_SCHEMA_ATTRIBUTE_STRING,
        };
        Schema {
            name: SCHEMA_NAME.as_ptr(),
            flags: SECRET_SCHEMA_NONE,
            attributes,
            reserved: 0,
            reserved1: std::ptr::null_mut(),
            reserved2: std::ptr::null_mut(),
            reserved3: std::ptr::null_mut(),
            reserved4: std::ptr::null_mut(),
            reserved5: std::ptr::null_mut(),
            reserved6: std::ptr::null_mut(),
            reserved7: std::ptr::null_mut(),
        }
    }

    /// Resolve libsecret once for the life of the process.
    ///
    /// **The handle must never be closed.** libsecret registers GObject types
    /// on load, and GLib has no way to unregister them: a second `dlopen`
    /// after a `dlclose` aborts with "cannot register existing type
    /// 'SecretService'". Opening per call did exactly that -- the first
    /// lookup succeeded, the store that followed it failed, and every
    /// identity silently fell back to the file even with the Secret Service
    /// running. Caching here keeps one load alive for the process.
    fn secret() -> Option<&'static Secret> {
        static SECRET: OnceLock<Option<Secret>> = OnceLock::new();
        SECRET.get_or_init(open).as_ref()
    }

    fn open() -> Option<Secret> {
        // Versioned name first: the unversioned alias ships with the
        // development package, which a plain desktop does not have.
        let library = Library::open_first(&[c"libsecret-1.so.0", c"libsecret-1.so"])?;
        // SAFETY: each type matches the signature libsecret publishes for the
        // symbol of that name, and the pointers borrow `library`, which is
        // moved into the returned value and outlives every call.
        unsafe {
            Some(Secret {
                store: library.symbol(c"secret_password_store_sync")?,
                lookup: library.symbol(c"secret_password_lookup_sync")?,
                #[cfg(test)]
                clear: library.symbol(c"secret_password_clear_sync")?,
                free: library.symbol(c"secret_password_free")?,
                error_free: library.symbol(c"g_error_free"),
                _library: library,
            })
        }
    }

    pub(super) fn load(account: &str) -> super::Lookup {
        let Some(secret) = secret() else {
            return super::Lookup::Unavailable("libsecret is not available on this machine".into());
        };
        let Ok(account) = CString::new(account) else {
            return super::Lookup::Unavailable("the account name is not usable".into());
        };
        let schema = schema();
        let mut error: *mut c_void = std::ptr::null_mut();
        // SAFETY: the schema outlives the call; the variadic tail is one
        // attribute name/value pair terminated by NULL, as libsecret requires.
        // A null GError** means "report no detail", which is legal in GLib.
        let found = unsafe {
            (secret.lookup)(
                &raw const schema,
                std::ptr::null_mut(),
                &raw mut error,
                ATTRIBUTE_ACCOUNT.as_ptr(),
                account.as_ptr(),
                std::ptr::null::<c_char>(),
            )
        };
        if found.is_null() {
            // A null result with no GError is the service answering "I hold no
            // such entry". A null result *with* one means it could not answer
            // at all, which calls for the opposite response.
            if error.is_null() {
                return super::Lookup::Absent;
            }
            if let Some(free) = secret.error_free {
                // SAFETY: freeing exactly the GError libsecret allocated.
                unsafe { free(error) };
            }
            return super::Lookup::Unavailable("the Secret Service could not be reached".into());
        }
        // SAFETY: a non-null return is a NUL-terminated string owned by
        // libsecret, valid until freed below.
        let text = unsafe { CStr::from_ptr(found) }
            .to_str()
            .ok()
            .map(str::to_owned);
        // SAFETY: freeing exactly what libsecret returned, once.
        unsafe { (secret.free)(found) };
        match text.and_then(|text| hex::decode(text.trim()).ok()) {
            Some(bytes) => super::Lookup::Found(bytes),
            // The entry is there but is not what this code wrote.
            None => super::Lookup::Unavailable("the stored entry is not readable".into()),
        }
    }

    pub(super) fn store(account: &str, value: &[u8]) -> Result<(), String> {
        let secret = secret().ok_or("libsecret is not available on this machine")?;
        let account = CString::new(account).map_err(|_| "the account name is not usable")?;
        // The Secret Service carries a NUL-terminated string, so the key is
        // hex encoded rather than passed as raw bytes.
        let encoded = CString::new(hex::encode(value)).map_err(|_| "the key is not encodable")?;
        let schema = schema();
        // SAFETY: as in `load`; the variadic tail is one attribute pair
        // terminated by NULL.
        let stored = unsafe {
            (secret.store)(
                &raw const schema,
                COLLECTION_DEFAULT.as_ptr(),
                LABEL.as_ptr(),
                encoded.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                ATTRIBUTE_ACCOUNT.as_ptr(),
                account.as_ptr(),
                std::ptr::null::<c_char>(),
            )
        };
        if stored == 0 {
            return Err("the Secret Service refused the key".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn remove(account: &str) -> Result<(), String> {
        let secret = secret().ok_or("libsecret is not available on this machine")?;
        let account = CString::new(account).map_err(|_| "the account name is not usable")?;
        let schema = schema();
        // SAFETY: as in `load`.
        let cleared = unsafe {
            (secret.clear)(
                &raw const schema,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                ATTRIBUTE_ACCOUNT.as_ptr(),
                account.as_ptr(),
                std::ptr::null::<c_char>(),
            )
        };
        if cleared == 0 {
            return Err("the Secret Service refused the delete".into());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    pub(super) const AVAILABLE: bool = false;

    pub(super) fn load(_account: &str) -> super::Lookup {
        super::Lookup::Unavailable("no platform keystore is implemented for this target".into())
    }

    pub(super) fn store(_account: &str, _secret: &[u8]) -> Result<(), String> {
        Err("no platform keystore is implemented for this target".into())
    }
}

#[cfg(test)]
mod tests {
    /// A real keystore round trip. Ignored by default because it writes to
    /// the developer's own keychain or keyring and can raise an
    /// authorization prompt; run it deliberately with `--ignored`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    #[ignore = "writes to the login keychain"]
    fn a_stored_key_comes_back_byte_for_byte() {
        let account = format!("openstream-test-{}", std::process::id());
        let secret: Vec<u8> = (0..64_u8).collect();
        super::store(&account, &secret).expect("store");
        assert!(
            matches!(super::load(&account), super::Lookup::Found(found) if found == secret),
            "a stored key must come back byte for byte"
        );

        // Storing again must replace rather than fail or duplicate.
        let replacement: Vec<u8> = (64..128_u8).collect();
        super::store(&account, &replacement).expect("replace");
        assert!(
            matches!(super::load(&account), super::Lookup::Found(found) if found == replacement),
            "storing again must replace rather than duplicate"
        );

        super::remove(&account).expect("clean up the test item");
        // Absent, not Unavailable: the service answered and holds nothing.
        // Conflating the two is what let a lost entry mint a new identity.
        assert!(
            matches!(super::load(&account), super::Lookup::Absent),
            "a removed item must read as absent, not as an unavailable keystore"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    #[ignore = "needs a running Secret Service"]
    fn an_account_with_no_entry_reads_as_absent() {
        let account = format!("openstream-absent-{}", std::process::id());
        assert!(matches!(super::load(&account), super::Lookup::Absent));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn targets_without_an_implementation_say_so_rather_than_pretending() {
        assert!(!super::available());
        assert!(super::store("account", b"secret").is_err());
        // Unavailable, never Absent: a target with no keystore must not look
        // like a keystore that simply has no entry yet.
        assert!(matches!(
            super::load("account"),
            super::Lookup::Unavailable(_)
        ));
    }
}
