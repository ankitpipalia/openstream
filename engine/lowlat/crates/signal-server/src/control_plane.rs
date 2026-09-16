//! Durable account and device records for the self-hosted control plane.
//!
//! Signaling sessions, WebSocket senders, relay registrations, and access
//! tokens are intentionally not durable. Accounts, password verifiers,
//! enrolled public keys, trust decisions, and refresh-token hashes are. This
//! keeps a server restart from reviving a media path while still preserving
//! the identity and trust model users expect from a product.

use getrandom::getrandom;
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const STORE_SCHEMA_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 10_000;
const MAX_DEVICES_PER_ACCOUNT: usize = 256;
const MAX_REFRESH_TOKENS_PER_ACCOUNT: usize = 16;
/// Tombstones kept per account for replay detection.
///
/// Larger than the live allowance because one live token can be rotated many
/// times over its lifetime and every rotation leaves evidence behind. Still
/// bounded: an aggressive client must not be able to grow this without end.
const MAX_RETIRED_REFRESH_TOKENS_PER_ACCOUNT: usize = 256;
const PASSWORD_MIN_BYTES: usize = 12;
const PASSWORD_MAX_BYTES: usize = 256;
const USERNAME_MIN_BYTES: usize = 3;
const USERNAME_MAX_BYTES: usize = 128;
const DEVICE_ID_MAX_BYTES: usize = 128;
const DEVICE_NAME_MAX_BYTES: usize = 128;
const PLATFORM_MAX_BYTES: usize = 64;
const ACCESS_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// PBKDF2-HMAC-SHA256 cost for new and rehashed passwords.
///
/// Matches OWASP's current FIPS-oriented recommendation. It is a `u32` rather
/// than a `NonZeroU32` because it is also serialised into each account
/// record; the non-zero invariant is re-established at the one place that
/// derives.
const PBKDF2_ITERATIONS_CURRENT: u32 = 600_000;

/// What builds before [`PasswordScheme`] existed used, and therefore what a
/// record with no stored scheme must be verified with.
const PBKDF2_ITERATIONS_LEGACY: u32 = 600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeviceTrust {
    Pending,
    Trusted,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeviceRegistration {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicDevice {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub trust: DeviceTrust,
    pub enrolled_at_ms: u64,
    pub last_seen_ms: Option<u64>,
    pub public_key_fingerprint: String,
    /// Whether the Connect broker currently sees this device announcing
    /// presence. The account store does not know this -- presence is soft,
    /// per-process state with its own TTL -- so `public_device` leaves it
    /// `false` and the device-listing handler layers the live value on top.
    /// It is advisory for the owner's shell; the broker still enforces
    /// presence authoritatively when a session is actually requested.
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicUser {
    pub account_id: String,
    pub username: String,
    pub created_at_ms: u64,
}

/// Where a token sits in its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefreshFamily {
    family_id: String,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountPrincipal {
    pub account_id: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in_seconds: u64,
    pub refresh_expires_in_seconds: u64,
    pub user: PublicUser,
    pub device: Option<PublicDevice>,
}

#[derive(Debug)]
pub(crate) enum ControlPlaneError {
    InvalidInput(&'static str),
    AlreadyExists,
    NotFound,
    Unauthorized,
    /// A login was rejected because the device presented a different public key
    /// than the enrolled one, which auto-revoked the device. Client-facing this
    /// is indistinguishable from `Unauthorized` (same status, same body); it
    /// carries the owner internally so the caller can also end the device's live
    /// sessions, since a changed device identity signals a takeover.
    DeviceIdentityRevoked {
        account_id: String,
        device_id: String,
    },
    DevicePending,
    DeviceRevoked,
    InvalidStore,
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ControlPlaneError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput(reason) => reason,
            Self::AlreadyExists => "account or device already exists",
            Self::NotFound => "account or device was not found",
            Self::Unauthorized | Self::DeviceIdentityRevoked { .. } => "credentials were rejected",
            Self::DevicePending => "device enrollment is awaiting approval",
            Self::DeviceRevoked => "device has been revoked",
            Self::InvalidStore => "control-plane store is invalid",
            Self::Io(_) => "control-plane store I/O failed",
            Self::Json(_) => "control-plane store data is invalid",
        })
    }
}

impl std::error::Error for ControlPlaneError {
    /// Carry the underlying cause for an operator reading the service log.
    ///
    /// [`Display`](std::fmt::Display) deliberately stays coarse because that
    /// string is what a network client could otherwise infer state from; the
    /// detail belongs to whoever runs the service, and this is how they get
    /// it without it crossing the socket.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ControlPlaneError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ControlPlaneError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// How an account's password verifier was derived.
///
/// Stored per account rather than assumed globally. Without this the
/// iteration count is baked into every existing record: raising it locks out
/// every user, because their stored hash was produced with the old cost and
/// there is no way to tell which. A self-describing record makes the upgrade
/// mechanical -- derive with what the record says, and if that is not the
/// current recommendation, rehash on the next successful sign-in.
///
/// Serialised as a tagged enum so a future scheme -- Argon2id, which OWASP
/// prefers where FIPS is not a constraint -- is an added variant rather than
/// a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "kebab-case")]
pub(crate) enum PasswordScheme {
    Pbkdf2HmacSha256 { iterations: u32 },
}

impl PasswordScheme {
    /// What a new or rehashed password is derived with today.
    pub(crate) const fn current() -> Self {
        Self::Pbkdf2HmacSha256 {
            iterations: PBKDF2_ITERATIONS_CURRENT,
        }
    }

    /// Whether a record using this scheme should be upgraded.
    ///
    /// Only ever upgrades. A record derived with *more* work than the current
    /// recommendation is not weakened by staying where it is, and rehashing
    /// it down would be a downgrade performed automatically, which is the
    /// opposite of the point.
    pub(crate) const fn is_outdated(self) -> bool {
        match self {
            Self::Pbkdf2HmacSha256 { iterations } => iterations < PBKDF2_ITERATIONS_CURRENT,
        }
    }
}

impl Default for PasswordScheme {
    /// What a record written before schemes were stored must have used.
    ///
    /// Load-bearing for existing stores: an account saved by an earlier build
    /// has no `password_scheme` field, and guessing the current value for it
    /// would be wrong the moment the current value changes. This is the
    /// constant that build actually used.
    fn default() -> Self {
        Self::Pbkdf2HmacSha256 {
            iterations: PBKDF2_ITERATIONS_LEGACY,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountRecord {
    account_id: String,
    username: String,
    password_salt: [u8; 16],
    password_hash: [u8; 32],
    /// Absent in stores written before schemes were recorded; see
    /// [`PasswordScheme::default`].
    #[serde(default)]
    password_scheme: PasswordScheme,
    created_at_ms: u64,
    devices: BTreeMap<String, DeviceRecord>,
    refresh_tokens: Vec<RefreshTokenRecord>,
    /// Digests of refresh tokens that have been rotated away.
    ///
    /// Retained, not forgotten, because rotation alone detects nothing: if a
    /// stolen token is simply deleted on use, the thief's replay is
    /// indistinguishable from an unknown token and the legitimate client
    /// carries on unaware. Keeping the relationship is what turns a replay
    /// into evidence. See [`RetiredRefreshToken`].
    #[serde(default)]
    retired_refresh_tokens: Vec<RetiredRefreshToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRecord {
    registration: DeviceRegistration,
    trust: DeviceTrust,
    enrolled_at_ms: u64,
    last_seen_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenRecord {
    digest: [u8; 32],
    device_id: Option<String>,
    /// The chain this token belongs to.
    ///
    /// One sign-in starts one family; every rotation extends it. Reuse of any
    /// token in a family condemns the whole family, because the only two
    /// explanations are a stolen token and a client that replayed -- and a
    /// replayed token cannot be told apart from a stolen one, so the safe
    /// reading is the unsafe one.
    #[serde(default = "legacy_family_id")]
    family_id: String,
    #[serde(default)]
    generation: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

/// A refresh token that has been rotated away, kept as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetiredRefreshToken {
    digest: [u8; 32],
    family_id: String,
    /// When this tombstone may be forgotten.
    ///
    /// The family's own expiry, not the token's: forgetting a tombstone while
    /// its family is still live would reopen exactly the replay window it
    /// exists to close.
    expires_at_ms: u64,
}

/// Family id for records written before families existed.
///
/// Distinct per record rather than shared, so a store upgraded in place does
/// not treat every pre-existing token as one family that any single reuse
/// would condemn together.
fn legacy_family_id() -> String {
    format!("legacy-{}", Uuid::new_v4().simple())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreFile {
    schema_version: u32,
    accounts: BTreeMap<String, AccountRecord>,
}

#[derive(Debug)]
pub(crate) struct AccountStore {
    path: PathBuf,
    accounts: BTreeMap<String, AccountRecord>,
    /// Access tokens are intentionally memory-only. Restarting the service
    /// invalidates all active access tokens; refresh tokens are rotated and
    /// stored as hashes, never as bearer values.
    access_tokens: HashMap<[u8; 32], AccessTokenRecord>,
}

#[derive(Debug, Clone)]
struct AccessTokenRecord {
    principal: AccountPrincipal,
    /// The refresh family this access token was issued alongside.
    ///
    /// Without it, condemning a family has to fall back to revoking by
    /// device, which is wrong in both directions: it takes down unrelated
    /// families signed in on the same device, and it takes down nothing at
    /// all for a sign-in that has no device. Revocation has to reach exactly
    /// the credentials descended from the compromised sign-in.
    family_id: String,
    expires_at_ms: u64,
}

impl AccountStore {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self, ControlPlaneError> {
        let path = path.into();
        validate_store_path(&path)?;
        let parent = path.parent().ok_or(ControlPlaneError::InvalidStore)?;
        ensure_private_dir(parent)?;
        let accounts = match read_store(&path)? {
            Some(file) if file.schema_version == STORE_SCHEMA_VERSION => file.accounts,
            Some(_) => return Err(ControlPlaneError::InvalidStore),
            None => BTreeMap::new(),
        };
        if accounts.len() > MAX_ACCOUNTS {
            return Err(ControlPlaneError::InvalidStore);
        }
        for (key, account) in &accounts {
            validate_account(key, account)?;
        }
        Ok(Self {
            path,
            accounts,
            access_tokens: HashMap::new(),
        })
    }

    pub(crate) fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// The salt a caller must derive against before [`Self::login_derived`].
    ///
    /// Returned for an unknown username too, from a fixed decoy, so that
    /// obtaining a challenge reveals nothing about whether the account
    /// exists. The derivation the caller then performs costs the same either
    /// way, and it happens without this store's lock held -- which is the
    /// point: a 600,000-iteration PBKDF2 run must not serialize every other
    /// control-plane request behind it.
    /// The salt and scheme a sign-in attempt must derive with.
    ///
    /// The scheme travels with the salt because verification has to reproduce
    /// what the stored record was made with, not what the current build would
    /// choose. An unknown username gets the decoy salt and the *current*
    /// scheme, so a probe costs exactly the same work as a real account and
    /// leaves no cheaper path to measure.
    pub(crate) fn password_challenge_scheme(&self, username: &str) -> ([u8; 16], PasswordScheme) {
        self.accounts
            .values()
            .find(|account| account.username == username)
            .map_or_else(
                || (DECOY_PASSWORD_SALT, PasswordScheme::current()),
                |account| (account.password_salt, account.password_scheme),
            )
    }

    /// Whether this account's verifier should be rehashed after a successful
    /// sign-in.
    pub(crate) fn password_is_outdated(&self, username: &str) -> bool {
        self.accounts
            .values()
            .find(|account| account.username == username)
            .is_some_and(|account| account.password_scheme.is_outdated())
    }

    /// Replace an account's verifier with one derived under a new scheme.
    ///
    /// Called after the password has already been proven, so this does not
    /// re-authenticate; it re-encodes. Failing here is not a sign-in failure
    /// -- the user is already through -- so the caller is expected to ignore
    /// the outcome rather than turn a successful login into an error.
    pub(crate) fn rehash_password(
        &mut self,
        username: &str,
        salt: [u8; 16],
        derived: [u8; 32],
        scheme: PasswordScheme,
    ) -> Result<(), ControlPlaneError> {
        let Some(account) = self
            .accounts
            .values_mut()
            .find(|account| account.username == username)
        else {
            return Err(ControlPlaneError::NotFound);
        };
        account.password_salt = salt;
        account.password_hash = derived;
        account.password_scheme = scheme;
        self.save()
    }

    /// A salt for a new account, generated before the lock is taken.
    pub(crate) fn registration_salt() -> Result<[u8; 16], ControlPlaneError> {
        let mut salt = [0_u8; 16];
        getrandom(&mut salt).map_err(|_| ControlPlaneError::InvalidStore)?;
        Ok(salt)
    }

    /// Complete a registration whose key derivation has already been done.
    ///
    /// `require_empty` re-checks, under this lock, the condition the caller
    /// was authorized on. It exists because the authorization decision and
    /// this insertion cannot share a lock: the expensive derivation happens
    /// between them, deliberately. Without the re-check, two anonymous
    /// requests could both observe an empty store, both derive, and both
    /// register -- turning "only the first account may bootstrap" into "as
    /// many accounts as fit inside one derivation".
    pub(crate) fn register_derived(
        &mut self,
        username: &str,
        salt: [u8; 16],
        derived: [u8; 32],
        device: Option<DeviceRegistration>,
        require_empty: bool,
        now_ms: u64,
    ) -> Result<IssuedTokens, ControlPlaneError> {
        validate_username(username)?;
        if require_empty && !self.accounts.is_empty() {
            return Err(ControlPlaneError::Unauthorized);
        }
        if self
            .accounts
            .values()
            .any(|account| account.username == username)
        {
            return Err(ControlPlaneError::AlreadyExists);
        }
        if self.accounts.len() >= MAX_ACCOUNTS {
            return Err(ControlPlaneError::InvalidInput("account limit reached"));
        }
        let account_id = Uuid::new_v4().simple().to_string();
        let mut account = AccountRecord {
            password_scheme: PasswordScheme::current(),
            retired_refresh_tokens: Vec::new(),
            account_id: account_id.clone(),
            username: username.to_string(),
            password_salt: salt,
            password_hash: derived,
            created_at_ms: now_ms,
            devices: BTreeMap::new(),
            refresh_tokens: Vec::new(),
        };
        let device_id = if let Some(device) = device {
            let device_id = device.device_id.clone();
            validate_device_registration(&device)?;
            account.devices.insert(
                device_id.clone(),
                DeviceRecord {
                    registration: device,
                    trust: DeviceTrust::Trusted,
                    enrolled_at_ms: now_ms,
                    last_seen_ms: Some(now_ms),
                },
            );
            Some(device_id)
        } else {
            None
        };
        self.accounts.insert(account_id.clone(), account);
        self.save()?;
        self.issue_tokens(&account_id, device_id, now_ms)
    }

    /// Complete a sign-in whose key derivation has already been performed
    /// against [`Self::password_challenge`].
    ///
    /// The caller derived without this lock held. The salt is re-read here
    /// and must still match the one that was challenged: if a concurrent
    /// password change moved it, the derived value describes a verifier that
    /// no longer exists and the attempt fails closed rather than being
    /// compared against the wrong thing.
    pub(crate) fn login_derived(
        &mut self,
        username: &str,
        challenged_salt: [u8; 16],
        derived: [u8; 32],
        device: Option<DeviceRegistration>,
        now_ms: u64,
    ) -> Result<IssuedTokens, ControlPlaneError> {
        validate_username(username)?;
        let account_id = self
            .accounts
            .values()
            .find(|account| account.username == username)
            .map(|account| account.account_id.clone());
        let Some(account_id) = account_id else {
            // Compared against nothing, but compared: an unknown username and
            // a wrong password take the same path out of here, and the
            // expensive half already cost the caller the same either way.
            let _ = constant_time_eq(&derived, &[0_u8; 32]);
            return Err(ControlPlaneError::Unauthorized);
        };
        let account = self
            .accounts
            .get_mut(&account_id)
            .ok_or(ControlPlaneError::Unauthorized)?;
        if account.password_salt != challenged_salt {
            return Err(ControlPlaneError::Unauthorized);
        }
        if !constant_time_eq(&account.password_hash, &derived) {
            return Err(ControlPlaneError::Unauthorized);
        }
        let (device_id, identity_mismatch) = if let Some(registration) = device {
            validate_device_registration(&registration)?;
            let device_id = registration.device_id.clone();
            let mut identity_mismatch = false;
            match account.devices.get_mut(&device_id) {
                Some(existing) => {
                    if existing.trust == DeviceTrust::Revoked {
                        return Err(ControlPlaneError::DeviceRevoked);
                    }
                    if existing.registration.public_key != registration.public_key {
                        existing.trust = DeviceTrust::Revoked;
                        identity_mismatch = true;
                    } else {
                        existing.registration.name = registration.name;
                        existing.registration.platform = registration.platform;
                        existing.last_seen_ms = Some(now_ms);
                    }
                }
                None => {
                    let trust = if account.devices.is_empty() {
                        DeviceTrust::Trusted
                    } else {
                        DeviceTrust::Pending
                    };
                    if account.devices.len() >= MAX_DEVICES_PER_ACCOUNT {
                        return Err(ControlPlaneError::InvalidInput("device limit reached"));
                    }
                    account.devices.insert(
                        device_id.clone(),
                        DeviceRecord {
                            registration,
                            trust,
                            enrolled_at_ms: now_ms,
                            last_seen_ms: Some(now_ms),
                        },
                    );
                }
            }
            (Some(device_id), identity_mismatch)
        } else {
            (None, false)
        };
        if identity_mismatch {
            // Persist the revocation before returning. Otherwise a process
            // restart would restore the old trusted record and any refresh
            // token that was still on disk could become usable again.
            let device_id = device_id
                .as_deref()
                .expect("an identity mismatch always has a device id");
            self.invalidate_device_tokens(&account_id, device_id);
            self.save()?;
            // Client-facing this is identical to `Unauthorized`; the owner is
            // carried so the caller can also end the device's live sessions.
            return Err(ControlPlaneError::DeviceIdentityRevoked {
                account_id: account_id.clone(),
                device_id: device_id.to_string(),
            });
        }
        self.prune_refresh_tokens(&account_id, now_ms);
        self.save()?;
        self.issue_tokens(&account_id, device_id, now_ms)
    }

    pub(crate) fn refresh(
        &mut self,
        refresh_token: &str,
        now_ms: u64,
    ) -> Result<IssuedTokens, ControlPlaneError> {
        validate_token(refresh_token)?;
        let digest = token_digest(refresh_token);

        // Replay first, before anything else looks at the live tokens.
        //
        // A token presented here that has already been rotated away has two
        // explanations: it was stolen and the thief is using it, or the
        // legitimate client replayed one. Neither can be distinguished from
        // the other, and one of them is a compromise, so the whole family is
        // condemned -- every refresh token descended from that sign-in, and
        // every access token issued to the device. The legitimate client is
        // forced to sign in again, which is the cost of the only reading that
        // is safe to act on.
        if let Some((account_id, family_id)) = self.find_retired_family(&digest, now_ms) {
            self.revoke_refresh_family(&account_id, &family_id);
            self.save()?;
            return Err(ControlPlaneError::Unauthorized);
        }

        let mut principal = None;
        let mut expired = false;
        for account in self.accounts.values_mut() {
            if let Some(position) = account
                .refresh_tokens
                .iter()
                .position(|record| record.digest == digest)
            {
                let record = account.refresh_tokens.remove(position);
                if record.expires_at_ms <= now_ms {
                    expired = true;
                    break;
                }
                // The consumed token becomes a tombstone, kept for as long as
                // its family could still be presented. Deleting it instead --
                // which is what rotation alone does -- makes a later replay
                // indistinguishable from an unknown token, so the theft goes
                // unnoticed and the thief simply carries on.
                account.retired_refresh_tokens.push(RetiredRefreshToken {
                    digest: record.digest,
                    family_id: record.family_id.clone(),
                    expires_at_ms: record.expires_at_ms,
                });
                principal = Some((
                    account.account_id.clone(),
                    record.device_id,
                    RefreshFamily {
                        family_id: record.family_id,
                        generation: record.generation.saturating_add(1),
                    },
                ));
                break;
            }
        }
        if expired {
            self.save()?;
            return Err(ControlPlaneError::Unauthorized);
        }
        let (account_id, device_id, family) = principal.ok_or(ControlPlaneError::Unauthorized)?;
        if let Some(device_id) = device_id.as_deref() {
            let trust = self
                .accounts
                .get(&account_id)
                .and_then(|account| account.devices.get(device_id))
                .map(|device| device.trust)
                .ok_or(ControlPlaneError::Unauthorized)?;
            if trust != DeviceTrust::Trusted {
                // Consuming the presented refresh token and invalidating all
                // other device bearers makes revocation fail closed even if a
                // client retained a token issued before the trust decision.
                self.invalidate_device_tokens(&account_id, device_id);
                self.save()?;
                return Err(match trust {
                    DeviceTrust::Pending => ControlPlaneError::DevicePending,
                    DeviceTrust::Revoked => ControlPlaneError::DeviceRevoked,
                    DeviceTrust::Trusted => unreachable!(),
                });
            }
        }
        self.prune_retired_refresh_tokens(&account_id, now_ms);
        self.save()?;
        self.issue_tokens_in_family(&account_id, device_id, family, now_ms)
    }

    /// The family a retired token belonged to, if this digest is one.
    fn find_retired_family(&self, digest: &[u8; 32], now_ms: u64) -> Option<(String, String)> {
        self.accounts.values().find_map(|account| {
            account
                .retired_refresh_tokens
                .iter()
                .find(|retired| &retired.digest == digest && retired.expires_at_ms > now_ms)
                .map(|retired| (account.account_id.clone(), retired.family_id.clone()))
        })
    }

    /// Condemn every credential descended from one sign-in.
    ///
    /// Both halves matter. Dropping the refresh tokens stops the chain from
    /// being extended; dropping the access tokens stops the ones already
    /// issued from being used for the rest of their lifetime, which is the
    /// window an attacker would otherwise still hold.
    fn revoke_refresh_family(&mut self, account_id: &str, family_id: &str) {
        // By family, not by device. Revoking by device was wrong in both
        // directions: it took down unrelated families signed in on the same
        // device, and it took down nothing at all for a sign-in with no
        // device, leaving the condemned family's access token live for the
        // rest of its lifetime -- which is precisely the window an attacker
        // holding it would use.
        self.access_tokens.retain(|_, token| {
            token.principal.account_id != account_id || token.family_id != family_id
        });
        let Some(account) = self.accounts.get_mut(account_id) else {
            return;
        };
        account
            .refresh_tokens
            .retain(|record| record.family_id != family_id);
        account
            .retired_refresh_tokens
            .retain(|retired| retired.family_id != family_id);
    }

    /// Forget tombstones whose families can no longer be presented.
    ///
    /// Bounded as well as expiring: a client that rotates aggressively would
    /// otherwise grow this list for the token lifetime. The oldest go first,
    /// which are the ones least likely to still be held by anybody.
    fn prune_retired_refresh_tokens(&mut self, account_id: &str, now_ms: u64) {
        if let Some(account) = self.accounts.get_mut(account_id) {
            account
                .retired_refresh_tokens
                .retain(|retired| retired.expires_at_ms > now_ms);
            if account.retired_refresh_tokens.len() > MAX_RETIRED_REFRESH_TOKENS_PER_ACCOUNT {
                let remove =
                    account.retired_refresh_tokens.len() - MAX_RETIRED_REFRESH_TOKENS_PER_ACCOUNT;
                account.retired_refresh_tokens.drain(..remove);
            }
        }
    }

    pub(crate) fn authorize_access(
        &mut self,
        access_token: &str,
        now_ms: u64,
    ) -> Option<AccountPrincipal> {
        let digest = token_digest(access_token);
        let record = self.access_tokens.get(&digest)?.clone();
        if record.expires_at_ms <= now_ms {
            self.access_tokens.remove(&digest);
            return None;
        }
        if let Some(device_id) = record.principal.device_id.as_deref() {
            let trust = self
                .accounts
                .get(&record.principal.account_id)
                .and_then(|account| account.devices.get(device_id))
                .map(|device| device.trust);
            if matches!(trust, None | Some(DeviceTrust::Revoked)) {
                self.access_tokens.remove(&digest);
                if trust.is_some() {
                    self.invalidate_device_tokens(&record.principal.account_id, device_id);
                    // Access-token validation is a mutation when it discovers
                    // a revoked device: it also removes the durable refresh
                    // records. Persist that revocation boundary before the
                    // request is allowed to return.
                    let _ = self.save();
                }
                return None;
            }
        }
        Some(record.principal)
    }

    pub(crate) fn list_devices(
        &self,
        account_id: &str,
    ) -> Result<Vec<PublicDevice>, ControlPlaneError> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or(ControlPlaneError::NotFound)?;
        Ok(account.devices.values().map(public_device).collect())
    }

    pub(crate) fn enroll_device(
        &mut self,
        account_id: &str,
        registration: DeviceRegistration,
        now_ms: u64,
    ) -> Result<PublicDevice, ControlPlaneError> {
        validate_device_registration(&registration)?;
        let account = self
            .accounts
            .get_mut(account_id)
            .ok_or(ControlPlaneError::NotFound)?;
        if account.devices.contains_key(&registration.device_id) {
            return Err(ControlPlaneError::AlreadyExists);
        }
        if account.devices.len() >= MAX_DEVICES_PER_ACCOUNT {
            return Err(ControlPlaneError::InvalidInput("device limit reached"));
        }
        let device = DeviceRecord {
            registration,
            trust: DeviceTrust::Pending,
            enrolled_at_ms: now_ms,
            last_seen_ms: None,
        };
        let public = public_device(&device);
        account
            .devices
            .insert(device.registration.device_id.clone(), device);
        self.save()?;
        Ok(public)
    }

    pub(crate) fn set_device_trust(
        &mut self,
        account_id: &str,
        device_id: &str,
        trust: DeviceTrust,
        now_ms: u64,
    ) -> Result<PublicDevice, ControlPlaneError> {
        let public = {
            let account = self
                .accounts
                .get_mut(account_id)
                .ok_or(ControlPlaneError::NotFound)?;
            let device = account
                .devices
                .get_mut(device_id)
                .ok_or(ControlPlaneError::NotFound)?;
            device.trust = trust;
            device.last_seen_ms = Some(now_ms);
            public_device(device)
        };
        if trust != DeviceTrust::Trusted {
            self.invalidate_device_tokens(account_id, device_id);
        }
        self.save()?;
        Ok(public)
    }

    fn invalidate_device_tokens(&mut self, account_id: &str, device_id: &str) {
        self.access_tokens.retain(|_, token| {
            token.principal.account_id != account_id
                || token.principal.device_id.as_deref() != Some(device_id)
        });
        if let Some(account) = self.accounts.get_mut(account_id) {
            account
                .refresh_tokens
                .retain(|token| token.device_id.as_deref() != Some(device_id));
        }
    }

    pub(crate) fn can_create_session(
        &self,
        principal: &AccountPrincipal,
    ) -> Result<(), ControlPlaneError> {
        let account = self
            .accounts
            .get(&principal.account_id)
            .ok_or(ControlPlaneError::Unauthorized)?;
        let Some(device_id) = principal.device_id.as_deref() else {
            // Account authentication is sufficient for enrollment and device
            // management, but a session must always be created on behalf of a
            // concrete, trusted device.  Allowing a password-only principal
            // here would bypass the device-trust boundary.
            return Err(ControlPlaneError::Unauthorized);
        };
        let device = account
            .devices
            .get(device_id)
            .ok_or(ControlPlaneError::Unauthorized)?;
        match device.trust {
            DeviceTrust::Trusted => Ok(()),
            DeviceTrust::Pending => Err(ControlPlaneError::DevicePending),
            DeviceTrust::Revoked => Err(ControlPlaneError::DeviceRevoked),
        }
    }

    /// Device-management operations are allowed for an account principal or
    /// for a device that is already trusted. Pending and revoked devices must
    /// not be able to approve themselves or another device.
    pub(crate) fn can_manage_devices(
        &self,
        principal: &AccountPrincipal,
    ) -> Result<(), ControlPlaneError> {
        let account = self
            .accounts
            .get(&principal.account_id)
            .ok_or(ControlPlaneError::Unauthorized)?;
        let Some(device_id) = principal.device_id.as_deref() else {
            return Ok(());
        };
        let device = account
            .devices
            .get(device_id)
            .ok_or(ControlPlaneError::Unauthorized)?;
        if device.trust == DeviceTrust::Trusted {
            Ok(())
        } else {
            Err(match device.trust {
                DeviceTrust::Pending => ControlPlaneError::DevicePending,
                DeviceTrust::Revoked => ControlPlaneError::DeviceRevoked,
                DeviceTrust::Trusted => unreachable!(),
            })
        }
    }

    /// Issue a fresh token pair at the head of a new family.
    ///
    /// Used by sign-in and registration. Rotation goes through
    /// [`Self::issue_tokens_in_family`] so the chain is preserved.
    fn issue_tokens(
        &mut self,
        account_id: &str,
        device_id: Option<String>,
        now_ms: u64,
    ) -> Result<IssuedTokens, ControlPlaneError> {
        let family = RefreshFamily {
            family_id: Uuid::new_v4().simple().to_string(),
            generation: 0,
        };
        self.issue_tokens_in_family(account_id, device_id, family, now_ms)
    }

    fn issue_tokens_in_family(
        &mut self,
        account_id: &str,
        device_id: Option<String>,
        family: RefreshFamily,
        now_ms: u64,
    ) -> Result<IssuedTokens, ControlPlaneError> {
        let access_token = Uuid::new_v4().simple().to_string();
        let refresh_token = Uuid::new_v4().simple().to_string();
        let access_expires_at = now_ms.saturating_add(ACCESS_TOKEN_TTL_MS);
        let refresh_expires_at = now_ms.saturating_add(REFRESH_TOKEN_TTL_MS);
        self.access_tokens.insert(
            token_digest(&access_token),
            AccessTokenRecord {
                principal: AccountPrincipal {
                    account_id: account_id.to_string(),
                    device_id: device_id.clone(),
                },
                family_id: family.family_id.clone(),
                expires_at_ms: access_expires_at,
            },
        );
        let (user, device) = {
            let account = self
                .accounts
                .get_mut(account_id)
                .ok_or(ControlPlaneError::NotFound)?;
            account.refresh_tokens.push(RefreshTokenRecord {
                digest: token_digest(&refresh_token),
                device_id: device_id.clone(),
                family_id: family.family_id.clone(),
                generation: family.generation,
                issued_at_ms: now_ms,
                expires_at_ms: refresh_expires_at,
            });
            let user = PublicUser {
                account_id: account.account_id.clone(),
                username: account.username.clone(),
                created_at_ms: account.created_at_ms,
            };
            let device = device_id
                .as_deref()
                .and_then(|id| account.devices.get(id))
                .map(public_device);
            (user, device)
        };
        self.prune_refresh_tokens(account_id, now_ms);
        self.save()?;
        Ok(IssuedTokens {
            access_token,
            refresh_token,
            access_expires_in_seconds: ACCESS_TOKEN_TTL_MS / 1000,
            refresh_expires_in_seconds: REFRESH_TOKEN_TTL_MS / 1000,
            user,
            device,
        })
    }

    fn prune_refresh_tokens(&mut self, account_id: &str, now_ms: u64) {
        if let Some(account) = self.accounts.get_mut(account_id) {
            account
                .refresh_tokens
                .retain(|token| token.expires_at_ms > now_ms);
            if account.refresh_tokens.len() > MAX_REFRESH_TOKENS_PER_ACCOUNT {
                let remove = account.refresh_tokens.len() - MAX_REFRESH_TOKENS_PER_ACCOUNT;
                account.refresh_tokens.drain(..remove);
            }
        }
    }

    fn save(&self) -> Result<(), ControlPlaneError> {
        let parent = self.path.parent().ok_or(ControlPlaneError::InvalidStore)?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ControlPlaneError::InvalidStore)?,
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&StoreFile {
            schema_version: STORE_SCHEMA_VERSION,
            accounts: self.accounts.clone(),
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STORE_BYTES {
            return Err(ControlPlaneError::InvalidStore);
        }
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_private_file(&mut options);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            drop(file);
            replace_file(&temporary, &self.path)?;
            let _ = OpenOptions::new()
                .read(true)
                .open(parent)
                .and_then(|file| file.sync_all());
            Ok::<(), io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(ControlPlaneError::Io)
    }
}

#[cfg(unix)]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
    };

    let mut temporary_wide: Vec<u16> = temporary.as_os_str().encode_wide().collect();
    let mut destination_wide: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if temporary_wide.contains(&0) || destination_wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control-plane state path contains NUL",
        ));
    }
    temporary_wide.push(0);
    destination_wide.push(0);
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

#[cfg(not(any(unix, windows)))]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

pub(crate) fn default_store_path() -> PathBuf {
    if let Some(path) = std::env::var_os("OPENSTREAM_CONTROL_STATE_FILE") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("APPDATA") {
        return PathBuf::from(root)
            .join("OpenStream")
            .join("control-state.json");
    }
    if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(root)
            .join("openstream")
            .join("control-state.json");
    }
    if let Some(root) = std::env::var_os("HOME") {
        return PathBuf::from(root)
            .join(".local")
            .join("state")
            .join("openstream")
            .join("control-state.json");
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from(std::path::MAIN_SEPARATOR.to_string()))
        .join("openstream-control-state.json")
}

fn read_store(path: &Path) -> Result<Option<StoreFile>, ControlPlaneError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_STORE_BYTES
    {
        return Err(ControlPlaneError::InvalidStore);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.mode() & 0o400 == 0
        {
            return Err(ControlPlaneError::InvalidStore);
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
        return Err(ControlPlaneError::InvalidStore);
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn validate_store_path(path: &Path) -> Result<(), ControlPlaneError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ControlPlaneError::InvalidStore);
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(ControlPlaneError::InvalidStore);
    }
    Ok(())
}

/// Make the store's directory exist and confirm it is private to this user.
///
/// Refusing every symlinked ancestor would be a simpler rule and the wrong
/// one: on macOS `/var`, `/tmp` and `/etc` are all symlinks, and a deployment
/// whose state directory sits behind one would find the service unable to
/// start at all.
///
/// What has to hold is that the directory holding password verifiers and
/// refresh-token hashes is owned by this user and readable by nobody else.
/// `symlink_metadata` declines to follow only the *final* component, so the
/// checks below already describe the real directory at the end of whatever
/// ancestors were traversed: an attacker who redirects one into a location
/// they own fails the uid check. The final component is still refused if it
/// is itself a link, because `set_permissions` would follow it.
fn ensure_private_dir(path: &Path) -> Result<(), ControlPlaneError> {
    if !path.is_absolute() {
        return Err(ControlPlaneError::InvalidStore);
    }
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlPlaneError::InvalidStore);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ControlPlaneError::InvalidStore);
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

fn validate_account(key: &str, account: &AccountRecord) -> Result<(), ControlPlaneError> {
    if key != account.account_id {
        return Err(ControlPlaneError::InvalidStore);
    }
    validate_username(&account.username)?;
    if account.devices.len() > MAX_DEVICES_PER_ACCOUNT
        || account.refresh_tokens.len() > MAX_REFRESH_TOKENS_PER_ACCOUNT
    {
        return Err(ControlPlaneError::InvalidStore);
    }
    for (device_id, device) in &account.devices {
        if device_id != &device.registration.device_id {
            return Err(ControlPlaneError::InvalidStore);
        }
        validate_device_registration(&device.registration)?;
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), ControlPlaneError> {
    if !(USERNAME_MIN_BYTES..=USERNAME_MAX_BYTES).contains(&username.len())
        || username.chars().any(char::is_control)
        || username.chars().any(char::is_whitespace)
    {
        return Err(ControlPlaneError::InvalidInput("username is invalid"));
    }
    Ok(())
}

pub(crate) fn validate_password(password: &str) -> Result<(), ControlPlaneError> {
    if !(PASSWORD_MIN_BYTES..=PASSWORD_MAX_BYTES).contains(&password.len()) {
        return Err(ControlPlaneError::InvalidInput(
            "password length is invalid",
        ));
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), ControlPlaneError> {
    if token.is_empty() || token.len() > 128 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ControlPlaneError::Unauthorized);
    }
    Ok(())
}

fn validate_device_registration(device: &DeviceRegistration) -> Result<(), ControlPlaneError> {
    if device.device_id.is_empty()
        || device.device_id.len() > DEVICE_ID_MAX_BYTES
        || device.name.is_empty()
        || device.name.len() > DEVICE_NAME_MAX_BYTES
        || device.platform.is_empty()
        || device.platform.len() > PLATFORM_MAX_BYTES
        || device.device_id.chars().any(char::is_control)
        || device.name.chars().any(char::is_control)
        || device.platform.chars().any(char::is_control)
        || device.public_key == [0; 32]
    {
        return Err(ControlPlaneError::InvalidInput(
            "device registration is invalid",
        ));
    }
    Ok(())
}

/// Salt used when challenging an unknown username.
///
/// Fixed rather than random so that repeated probes for the same absent
/// account cost exactly the same work and produce no variance to measure.
const DECOY_PASSWORD_SALT: [u8; 16] = [0x5a; 16];

/// Derive a password verifier with the scheme a record actually used.
///
/// Deliberately expensive, and deliberately callable without the account
/// store's lock held. The scheme is a parameter rather than a constant
/// because verification must use whatever the stored record was made with,
/// while new and rehashed passwords use [`PasswordScheme::current`].
pub(crate) fn derive_password_with(
    password: &str,
    salt: &[u8; 16],
    scheme: PasswordScheme,
) -> [u8; 32] {
    let PasswordScheme::Pbkdf2HmacSha256 { iterations } = scheme;
    // A zero cost would be a stored record claiming no work at all. Clamped
    // rather than trusted: the record is on disk, and a file that has been
    // edited must not be able to turn verification into a plain digest.
    let iterations = NonZeroU32::new(iterations.max(1)).expect("clamped to at least one");
    let mut output = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut output,
    );
    output
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn public_device(device: &DeviceRecord) -> PublicDevice {
    let fingerprint = Sha256::digest(device.registration.public_key);
    let fingerprint = fingerprint
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    PublicDevice {
        device_id: device.registration.device_id.clone(),
        name: device.registration.name.clone(),
        platform: device.registration.platform.clone(),
        trust: device.trust,
        enrolled_at_ms: device.enrolled_at_ms,
        last_seen_ms: device.last_seen_ms,
        public_key_fingerprint: fingerprint,
        // Presence is not a property of the durable record; the listing
        // handler fills it in from the Connect broker.
        online: false,
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device(device_id: &str, key_byte: u8) -> DeviceRegistration {
        DeviceRegistration {
            device_id: device_id.to_string(),
            name: format!("{device_id} device"),
            platform: "test".to_string(),
            public_key: [key_byte; 32],
        }
    }

    fn test_store() -> (AccountStore, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "openstream-control-plane-test-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&directory).expect("unique test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private test directory");
        }
        let path = directory.join("control-state.json");
        let store = AccountStore::open(&path).expect("test store");
        (store, directory)
    }

    fn cleanup(directory: &Path) {
        let _ = fs::remove_dir_all(directory);
    }

    /// Register an account and return the store plus its first refresh token.
    fn registered(store: &mut AccountStore, now_ms: u64) -> String {
        let salt = AccountStore::registration_salt().expect("salt");
        let derived = derive_password_with(PASSWORD, &salt, PasswordScheme::current());
        store
            .register_derived(
                "operator",
                salt,
                derived,
                Some(test_device("device-1", 0x11)),
                false,
                now_ms,
            )
            .expect("register")
            .refresh_token
    }

    const PASSWORD: &str = "a-sufficiently-long-password";

    /// A login with the right password but a changed device key auto-revokes the
    /// device and reports the owner (so the caller can end its sessions), while a
    /// wrong password never reaches the device check -- so an unauthenticated
    /// caller cannot trigger the teardown.
    #[test]
    fn a_changed_device_key_reports_the_revoked_owner_but_stays_unauthorized_to_the_client() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        registered(&mut store, now);

        let (salt, scheme) = store.password_challenge_scheme("operator");

        // Correct password, different device public key.
        let correct = derive_password_with(PASSWORD, &salt, scheme);
        match store.login_derived(
            "operator",
            salt,
            correct,
            Some(test_device("device-1", 0x22)),
            now + 1,
        ) {
            Err(ControlPlaneError::DeviceIdentityRevoked {
                account_id,
                device_id,
            }) => {
                assert_eq!(device_id, "device-1");
                assert!(!account_id.is_empty());
            }
            other => panic!("expected an identity-revoked signal, got {other:?}"),
        }

        // A wrong password is rejected before the device check ever runs.
        let wrong = derive_password_with("the-wrong-password-entirely", &salt, scheme);
        assert!(matches!(
            store.login_derived(
                "operator",
                salt,
                wrong,
                Some(test_device("device-1", 0x33)),
                now + 2,
            ),
            Err(ControlPlaneError::Unauthorized)
        ));

        cleanup(&directory);
    }

    /// Replaying a rotated refresh token condemns the whole family.
    ///
    /// Rotation alone detects nothing: if the consumed token is simply
    /// deleted, a thief's replay is indistinguishable from an unknown token
    /// and the legitimate client carries on unaware. RFC 9700's model is
    /// rotation *with the relationship retained*, so a replay is evidence.
    #[test]
    fn replaying_a_rotated_refresh_token_revokes_the_family() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        let first = registered(&mut store, now);

        let second = store.refresh(&first, now).expect("rotate").refresh_token;
        let third = store
            .refresh(&second, now)
            .expect("rotate again")
            .refresh_token;

        // A stolen copy of the first token surfaces later.
        assert!(
            store.refresh(&first, now).is_err(),
            "a rotated token must not be accepted again"
        );

        // The whole chain is now dead, including the token the legitimate
        // client is holding. That is the intended cost: the two explanations
        // for a replay are theft and a client bug, and they cannot be told
        // apart, so the safe reading is the unsafe one.
        assert!(
            store.refresh(&third, now).is_err(),
            "the live token descended from the replayed one must also be revoked"
        );
        assert!(store.refresh(&second, now).is_err());
        cleanup(&directory);
    }

    /// Revoking a family also kills the access tokens already issued to it.
    #[test]
    fn a_revoked_family_takes_its_access_tokens_with_it() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        let first = registered(&mut store, now);
        let rotated = store.refresh(&first, now).expect("rotate");
        let access = rotated.access_token.clone();
        assert!(
            store.authorize_access(&access, now).is_some(),
            "the access token works before the replay"
        );

        store.refresh(&first, now).expect_err("replay is refused");
        assert!(
            store.authorize_access(&access, now).is_none(),
            "an access token outliving its condemned family is the window an \
             attacker would still hold"
        );
        cleanup(&directory);
    }

    /// One account's replay does not disturb another's sessions.
    #[test]
    fn revocation_is_confined_to_the_family_that_was_replayed() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        let first = registered(&mut store, now);

        // A second sign-in starts a second family on the same account.
        let (salt, scheme) = store.password_challenge_scheme("operator");
        let derived = derive_password_with(PASSWORD, &salt, scheme);
        let other = store
            .login_derived("operator", salt, derived, None, now)
            .expect("second sign-in")
            .refresh_token;

        let rotated = store.refresh(&first, now).expect("rotate").refresh_token;
        store.refresh(&first, now).expect_err("replay is refused");
        assert!(store.refresh(&rotated, now).is_err(), "family is condemned");
        assert!(
            store.refresh(&other, now).is_ok(),
            "an unrelated sign-in must survive another family's compromise"
        );
        cleanup(&directory);
    }

    /// Two sign-ins on one device are two families, and condemning one must
    /// not take the other down.
    ///
    /// Revocation used to fall back to "every credential on this device",
    /// which signed the user out of a session that had nothing to do with the
    /// compromise.
    #[test]
    fn a_replay_does_not_revoke_another_family_on_the_same_device() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        let compromised = registered(&mut store, now);

        // A second sign-in from the same device: same account, same device,
        // different family.
        let (salt, scheme) = store.password_challenge_scheme("operator");
        let derived = derive_password_with(PASSWORD, &salt, scheme);
        let innocent = store
            .login_derived(
                "operator",
                salt,
                derived,
                Some(test_device("device-1", 0x11)),
                now,
            )
            .expect("second sign-in on the same device");

        store.refresh(&compromised, now).expect("rotate");
        store
            .refresh(&compromised, now)
            .expect_err("replay is refused");

        assert!(
            store
                .authorize_access(&innocent.access_token, now)
                .is_some(),
            "the other family's access token must survive"
        );
        assert!(
            store.refresh(&innocent.refresh_token, now).is_ok(),
            "the other family's refresh token must survive"
        );
        cleanup(&directory);
    }

    /// A sign-in with no device still has its access token revoked.
    ///
    /// Device-scoped revocation could not reach these at all, so the
    /// condemned family's access token stayed live for its full lifetime --
    /// exactly the window an attacker holding it would use.
    #[test]
    fn a_device_less_family_still_loses_its_access_token() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        registered(&mut store, now);

        let (salt, scheme) = store.password_challenge_scheme("operator");
        let derived = derive_password_with(PASSWORD, &salt, scheme);
        let headless = store
            .login_derived("operator", salt, derived, None, now)
            .expect("sign-in with no device");
        assert!(headless.device.is_none());

        let rotated = store.refresh(&headless.refresh_token, now).expect("rotate");
        assert!(
            store.authorize_access(&rotated.access_token, now).is_some(),
            "the access token works before the replay"
        );

        store
            .refresh(&headless.refresh_token, now)
            .expect_err("replay is refused");
        assert!(
            store.authorize_access(&rotated.access_token, now).is_none(),
            "a device-less family's access token must be revoked too"
        );
        cleanup(&directory);
    }

    /// A tombstone does not outlive the family it protects.
    #[test]
    fn retired_token_evidence_expires_with_its_family() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        let first = registered(&mut store, now);
        store.refresh(&first, now).expect("rotate");

        let after = now + REFRESH_TOKEN_TTL_MS + 1;
        // Past the family's lifetime the replay is simply unknown rather than
        // evidence: nothing it could condemn is still live.
        assert!(store.refresh(&first, after).is_err());
        cleanup(&directory);
    }

    /// The stored scheme is what verification uses.
    ///
    /// Without this the iteration count is baked into every existing record,
    /// and raising it locks out every user.
    #[test]
    fn a_password_is_verified_with_the_scheme_its_record_was_written_under() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        registered(&mut store, now);

        // Rewrite the record as if an older build had made it, with a cost
        // this build no longer chooses.
        let legacy = PasswordScheme::Pbkdf2HmacSha256 { iterations: 1_000 };
        let salt = AccountStore::registration_salt().expect("salt");
        let derived = derive_password_with(PASSWORD, &salt, legacy);
        store
            .rehash_password("operator", salt, derived, legacy)
            .expect("rewrite as legacy");

        let (challenge_salt, challenge_scheme) = store.password_challenge_scheme("operator");
        assert_eq!(challenge_scheme, legacy, "the record describes itself");
        let verifier = derive_password_with(PASSWORD, &challenge_salt, challenge_scheme);
        assert!(
            store
                .login_derived("operator", challenge_salt, verifier, None, now)
                .is_ok(),
            "an account written under an older cost must still be able to sign in"
        );
        assert!(
            store.password_is_outdated("operator"),
            "and must be marked for upgrade"
        );
        cleanup(&directory);
    }

    /// An unknown username is challenged at the current cost.
    ///
    /// A cheaper decoy would be measurable, which is the leak the decoy salt
    /// exists to prevent.
    #[test]
    fn an_unknown_username_is_challenged_at_the_current_cost() {
        let (store, directory) = test_store();
        let (_, scheme) = store.password_challenge_scheme("nobody");
        assert_eq!(scheme, PasswordScheme::current());
        cleanup(&directory);
    }

    /// Rehashing replaces the verifier without changing who the account is.
    #[test]
    fn rehashing_upgrades_the_verifier_and_keeps_the_account() {
        let (mut store, directory) = test_store();
        let now = 1_000;
        registered(&mut store, now);
        let legacy = PasswordScheme::Pbkdf2HmacSha256 { iterations: 1_000 };
        let salt = AccountStore::registration_salt().expect("salt");
        store
            .rehash_password(
                "operator",
                salt,
                derive_password_with(PASSWORD, &salt, legacy),
                legacy,
            )
            .expect("downgrade for the test");
        assert!(store.password_is_outdated("operator"));

        let new_salt = AccountStore::registration_salt().expect("salt");
        let current = PasswordScheme::current();
        store
            .rehash_password(
                "operator",
                new_salt,
                derive_password_with(PASSWORD, &new_salt, current),
                current,
            )
            .expect("upgrade");
        assert!(!store.password_is_outdated("operator"));

        let (challenge_salt, challenge_scheme) = store.password_challenge_scheme("operator");
        assert_eq!(challenge_scheme, current);
        assert!(
            store
                .login_derived(
                    "operator",
                    challenge_salt,
                    derive_password_with(PASSWORD, &challenge_salt, challenge_scheme),
                    None,
                    now
                )
                .is_ok(),
            "the same password still works after the upgrade"
        );
        cleanup(&directory);
    }

    /// A record claiming zero work is not taken at its word.
    #[test]
    fn a_zero_cost_scheme_is_clamped_rather_than_trusted() {
        let salt = [0x22_u8; 16];
        let zero = PasswordScheme::Pbkdf2HmacSha256 { iterations: 0 };
        let one = PasswordScheme::Pbkdf2HmacSha256 { iterations: 1 };
        assert_eq!(
            derive_password_with(PASSWORD, &salt, zero),
            derive_password_with(PASSWORD, &salt, one),
            "an edited store must not be able to turn verification into a digest"
        );
    }

    /// Only upgrades are automatic.
    #[test]
    fn a_stronger_than_current_record_is_left_alone() {
        let stronger = PasswordScheme::Pbkdf2HmacSha256 {
            iterations: PBKDF2_ITERATIONS_CURRENT * 2,
        };
        assert!(
            !stronger.is_outdated(),
            "rehashing this down would be an automatic downgrade"
        );
    }

    /// The three steps a handler performs, in one call.
    ///
    /// Production derives between two short locked sections so a key
    /// derivation never serializes the account store; these wrappers keep the
    /// tests readable while exercising the same sequence.
    trait TestAuth {
        fn register(
            &mut self,
            username: &str,
            password: &str,
            device: Option<DeviceRegistration>,
            now_ms: u64,
        ) -> Result<IssuedTokens, ControlPlaneError>;

        fn login(
            &mut self,
            username: &str,
            password: &str,
            device: Option<DeviceRegistration>,
            now_ms: u64,
        ) -> Result<IssuedTokens, ControlPlaneError>;
    }

    impl TestAuth for AccountStore {
        fn register(
            &mut self,
            username: &str,
            password: &str,
            device: Option<DeviceRegistration>,
            now_ms: u64,
        ) -> Result<IssuedTokens, ControlPlaneError> {
            validate_password(password)?;
            let salt = AccountStore::registration_salt()?;
            let derived = derive_password_with(password, &salt, PasswordScheme::current());
            self.register_derived(username, salt, derived, device, false, now_ms)
        }

        fn login(
            &mut self,
            username: &str,
            password: &str,
            device: Option<DeviceRegistration>,
            now_ms: u64,
        ) -> Result<IssuedTokens, ControlPlaneError> {
            validate_password(password)?;
            let (salt, scheme) = self.password_challenge_scheme(username);
            let derived = derive_password_with(password, &salt, scheme);
            self.login_derived(username, salt, derived, device, now_ms)
        }
    }

    #[test]
    fn registration_and_identity_survive_store_reopen() {
        let (mut store, directory) = test_store();
        let device = test_device("macbook", 7);
        let tokens = store
            .register(
                "alice",
                "a sufficiently long password",
                Some(device.clone()),
                1,
            )
            .expect("registration");
        assert_eq!(store.account_count(), 1);
        assert_eq!(
            tokens.device.as_ref().map(|device| device.trust),
            Some(DeviceTrust::Trusted)
        );

        let mut reopened =
            AccountStore::open(directory.join("control-state.json")).expect("reopen durable store");
        let login = reopened
            .login("alice", "a sufficiently long password", Some(device), 2)
            .expect("login after reopen");
        assert_eq!(login.user.username, "alice");
        assert_eq!(reopened.account_count(), 1);
        cleanup(&directory);
    }

    /// An unknown username must cost the same work as a known one.
    ///
    /// The assertion is deliberately loose. This is a wall-clock comparison
    /// on a shared CI machine, so it cannot pin a tight ratio without being
    /// flaky; what it can catch is the regression that matters -- an early
    /// return that skips key derivation entirely and makes the two cases
    /// differ by orders of magnitude rather than by scheduling noise.
    #[test]
    fn an_unknown_username_costs_the_same_derivation_as_a_known_one() {
        let (mut store, directory) = test_store();
        store
            .register("alice", "a sufficiently long password", None, 1)
            .expect("registration");

        let known = std::time::Instant::now();
        assert!(matches!(
            store.login("alice", "the wrong password entirely", None, 2),
            Err(ControlPlaneError::Unauthorized)
        ));
        let known = known.elapsed();

        let unknown = std::time::Instant::now();
        assert!(matches!(
            store.login("mallory", "the wrong password entirely", None, 3),
            Err(ControlPlaneError::Unauthorized)
        ));
        let unknown = unknown.elapsed();

        assert!(
            unknown * 4 >= known,
            "an unknown username returned far faster than a known one \
             ({unknown:?} vs {known:?}), which is a username oracle"
        );
        cleanup(&directory);
    }

    #[test]
    fn refresh_tokens_rotate_and_replay_is_rejected() {
        let (mut store, directory) = test_store();
        let first = store
            .register("alice", "a sufficiently long password", None, 1)
            .expect("registration");
        let second = store
            .refresh(&first.refresh_token, 2)
            .expect("first refresh");
        assert_ne!(first.refresh_token, second.refresh_token);
        assert!(matches!(
            store.refresh(&first.refresh_token, 3),
            Err(ControlPlaneError::Unauthorized)
        ));
        cleanup(&directory);
    }

    #[test]
    fn revoking_a_device_invalidates_existing_access_and_refresh_tokens() {
        let (mut store, directory) = test_store();
        let device = test_device("macbook", 8);
        let tokens = store
            .register(
                "alice",
                "a sufficiently long password",
                Some(device.clone()),
                1,
            )
            .expect("registration");
        let principal = AccountPrincipal {
            account_id: tokens.user.account_id.clone(),
            device_id: Some(device.device_id.clone()),
        };
        assert!(store.authorize_access(&tokens.access_token, 2).is_some());
        store
            .set_device_trust(
                &tokens.user.account_id,
                &device.device_id,
                DeviceTrust::Revoked,
                3,
            )
            .expect("revoke device");
        assert!(store.authorize_access(&tokens.access_token, 4).is_none());
        assert!(matches!(
            store.refresh(&tokens.refresh_token, 4),
            Err(ControlPlaneError::Unauthorized)
        ));
        assert!(matches!(
            store.can_create_session(&principal),
            Err(ControlPlaneError::DeviceRevoked)
        ));
        cleanup(&directory);
    }

    #[test]
    fn pending_device_cannot_manage_devices_or_create_sessions() {
        let (mut store, directory) = test_store();
        let owner = test_device("owner", 9);
        let first = store
            .register("alice", "a sufficiently long password", Some(owner), 1)
            .expect("registration");
        let pending = test_device("phone", 10);
        let pending_public = store
            .enroll_device(&first.user.account_id, pending.clone(), 2)
            .expect("pending enrollment");
        assert_eq!(pending_public.trust, DeviceTrust::Pending);
        let pending_tokens = store
            .login(
                "alice",
                "a sufficiently long password",
                Some(pending.clone()),
                3,
            )
            .expect("pending device login");
        let principal = AccountPrincipal {
            account_id: first.user.account_id,
            device_id: Some(pending.device_id),
        };
        assert!(
            store
                .authorize_access(&pending_tokens.access_token, 4)
                .is_some()
        );
        assert!(matches!(
            store.can_manage_devices(&principal),
            Err(ControlPlaneError::DevicePending)
        ));
        assert!(matches!(
            store.can_create_session(&principal),
            Err(ControlPlaneError::DevicePending)
        ));
        cleanup(&directory);
    }

    #[test]
    fn account_only_principal_cannot_create_session() {
        let (mut store, directory) = test_store();
        let tokens = store
            .register("alice", "a sufficiently long password", None, 1)
            .expect("registration");
        let principal = AccountPrincipal {
            account_id: tokens.user.account_id,
            device_id: None,
        };
        assert!(matches!(
            store.can_create_session(&principal),
            Err(ControlPlaneError::Unauthorized)
        ));
        cleanup(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_symlinked_state_file() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "openstream-control-plane-symlink-test-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&directory).expect("unique test directory");
        let target = directory.join("real.json");
        fs::write(&target, b"{}").expect("target file");
        let link = directory.join("control-state.json");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            AccountStore::open(&link),
            Err(ControlPlaneError::InvalidStore)
        ));
        cleanup(&directory);
    }
}
