//! Session-scoped TURN credential issuance for the optional coturn path.
//!
//! The service never proxies media through TURN itself. When a deployment sets
//! `OPENSTREAM_TURN_SECRET` and `OPENSTREAM_TURN_URLS`, each session role can
//! fetch short-lived credentials minted with the classic TURN REST API
//! construction (`username = expiry:base`, `password =
//! base64(HMAC-SHA1(secret, username))`). Those credentials are accepted by
//! coturn configured with `use-auth-secret` and the same `static-auth-secret`.
//! The base embeds the session id and role so a leaked credential cannot be
//! reused for a different session, and the service logs only the username,
//! never the password.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Shortest TURN credential lifetime the service will mint, in seconds.
pub(crate) const MIN_TURN_TTL_SECONDS: u64 = 60;
/// Longest TURN credential lifetime the service will mint, in seconds.
pub(crate) const MAX_TURN_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Default TURN credential lifetime when the deployment does not set one.
pub(crate) const DEFAULT_TURN_TTL_SECONDS: u64 = 60 * 60;
const MAX_TURN_URLS: usize = 16;
const MAX_TURN_URL_BYTES: usize = 512;
const MAX_TURN_REALM_BYTES: usize = 128;
const MAX_TURN_SECRET_BYTES: usize = 4096;

/// Configuration read once at startup from the process environment.
#[derive(Clone)]
pub(crate) struct TurnConfig {
    secret: Vec<u8>,
    realm: String,
    urls: Vec<String>,
    ttl_seconds: u64,
}

impl core::fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TurnConfig")
            .field("secret", &"[redacted]")
            .field("realm", &self.realm)
            .field("urls", &self.urls)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl TurnConfig {
    /// Read the TURN configuration. Returns `None` when the deployment has
    /// not configured `OPENSTREAM_TURN_SECRET`/`OPENSTREAM_TURN_URLS`, in
    /// which case the `/turn` endpoint reports that TURN is unavailable
    /// instead of minting credentials.
    pub(crate) fn from_env() -> Option<Self> {
        let secret = match std::env::var("OPENSTREAM_TURN_SECRET") {
            Ok(secret) if (16..=MAX_TURN_SECRET_BYTES).contains(&secret.len()) => secret,
            Ok(_) => {
                eprintln!(
                    "OPENSTREAM_TURN_SECRET length is outside 16..={MAX_TURN_SECRET_BYTES} bytes; TURN issuance disabled"
                );
                return None;
            }
            Err(_) => return None,
        };
        let urls: Vec<String> = match std::env::var("OPENSTREAM_TURN_URLS") {
            Ok(spec) => spec
                .split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_string)
                .collect(),
            Err(_) => return None,
        };
        if urls.is_empty() {
            eprintln!("OPENSTREAM_TURN_URLS has no URLs; TURN issuance disabled");
            return None;
        }
        if urls.len() > MAX_TURN_URLS || urls.iter().any(|url| !valid_url(url)) {
            eprintln!(
                "OPENSTREAM_TURN_URLS contains an invalid URL or exceeds {MAX_TURN_URLS} entries; TURN issuance disabled"
            );
            return None;
        }
        let ttl_seconds = std::env::var("OPENSTREAM_TURN_TTL")
            .ok()
            .and_then(|value| {
                value.parse::<u64>().ok().or_else(|| {
                    eprintln!(
                        "OPENSTREAM_TURN_TTL={value:?} is not a number; using default {DEFAULT_TURN_TTL_SECONDS}s"
                    );
                    None
                })
            })
            .unwrap_or(DEFAULT_TURN_TTL_SECONDS)
            .clamp(MIN_TURN_TTL_SECONDS, MAX_TURN_TTL_SECONDS);
        let realm = std::env::var("OPENSTREAM_TURN_REALM")
            .ok()
            .filter(|realm| !realm.trim().is_empty())
            .unwrap_or_else(|| "openstream".to_string());
        if realm.len() > MAX_TURN_REALM_BYTES {
            eprintln!(
                "OPENSTREAM_TURN_REALM exceeds {MAX_TURN_REALM_BYTES} bytes; TURN issuance disabled"
            );
            return None;
        }
        Some(Self {
            secret: secret.into_bytes(),
            realm,
            urls,
            ttl_seconds,
        })
    }

    /// Mint credentials with an explicit TTL. This low-level helper keeps its
    /// historical minimum clamp; callers that bind credentials to a session
    /// lifetime must use [`TurnConfig::issue_for_session`] so a nearly expired
    /// session is rejected rather than extended past its own expiry.
    pub(crate) fn issue_with_ttl(
        &self,
        session_id: &str,
        role: &str,
        now_unix: u64,
        ttl_seconds: u64,
    ) -> TurnCredentials {
        let base = format!("{session_id}:{role}");
        let mut issued = issue_with_secret(&self.secret, &base, now_unix, ttl_seconds);
        issued.urls = self.urls.clone();
        issued.realm = self.realm.clone();
        issued
    }

    /// Mint a credential that cannot outlive the OpenStream session. TURN's
    /// classic REST format has a practical minimum lifetime in this service;
    /// returning `None` is safer than issuing a credential that survives a
    /// session which is about to expire.
    pub(crate) fn issue_for_session(
        &self,
        session_id: &str,
        role: &str,
        now_unix: u64,
        remaining_seconds: u64,
    ) -> Option<TurnCredentials> {
        if remaining_seconds < MIN_TURN_TTL_SECONDS {
            return None;
        }
        Some(self.issue_with_ttl(
            session_id,
            role,
            now_unix,
            self.ttl_seconds.min(remaining_seconds),
        ))
    }
}

/// Accept only the RFC 7064/7065 URL forms understood by the ICE client.
///
/// Credentials are deliberately rejected here: this service supplies the
/// short-lived REST username/password separately, and accepting userinfo in a
/// configured URL would put a long-lived secret into every pairing response.
fn valid_url(raw: &str) -> bool {
    raw.len() <= MAX_TURN_URL_BYTES
        && !raw.contains('@')
        && !raw.contains(['\r', '\n'])
        && webrtc_ice::url::Url::parse_url(raw).is_ok()
}

/// Short-lived TURN credentials handed to one session role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TurnCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) ttl_seconds: u64,
    pub(crate) urls: Vec<String>,
    pub(crate) realm: String,
}

/// Mint `expiry:base` credentials with an explicit secret and TTL. Kept free
/// of I/O so unit tests can pin the clock.
pub(crate) fn issue_with_secret(
    secret: &[u8],
    base: &str,
    now_unix: u64,
    ttl_seconds: u64,
) -> TurnCredentials {
    let ttl_seconds = ttl_seconds.clamp(MIN_TURN_TTL_SECONDS, MAX_TURN_TTL_SECONDS);
    let expiry = now_unix.saturating_add(ttl_seconds);
    let username = format!("{expiry}:{base}");
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let password = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        mac.finalize().into_bytes(),
    );
    TurnCredentials {
        username,
        password,
        ttl_seconds,
        urls: Vec::new(),
        realm: String::new(),
    }
}

/// Current Unix time in seconds; failures fall back to zero so issuance stays
/// total even with a broken platform clock (the credential simply expires).
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_is_deterministic_for_a_fixed_clock() {
        let first = issue_with_secret(
            b"test-secret-0123456789",
            "session:host",
            1_700_000_000,
            3600,
        );
        let second = issue_with_secret(
            b"test-secret-0123456789",
            "session:host",
            1_700_000_000,
            3600,
        );
        assert_eq!(first, second);
        assert_eq!(first.username, "1700003600:session:host");
        // 20-byte HMAC-SHA1 digest renders as 28 base64 characters.
        assert_eq!(first.password.len(), 28);
        assert_eq!(first.ttl_seconds, 3600);
    }

    #[test]
    fn different_roles_and_sessions_mint_different_credentials() {
        let host = issue_with_secret(
            b"test-secret-0123456789",
            "session:host",
            1_700_000_000,
            3600,
        );
        let client = issue_with_secret(
            b"test-secret-0123456789",
            "session:client",
            1_700_000_000,
            3600,
        );
        let other = issue_with_secret(b"test-secret-0123456789", "other:host", 1_700_000_000, 3600);
        assert_ne!(host.password, client.password);
        assert_ne!(host.password, other.password);
    }

    #[test]
    fn wrong_secret_does_not_verify() {
        let good = issue_with_secret(
            b"correct-secret-0123456789",
            "session:host",
            1_700_000_000,
            60,
        );
        let bad = issue_with_secret(
            b"wrong-secret-01234567890",
            "session:host",
            1_700_000_000,
            60,
        );
        assert_ne!(good.password, bad.password);
    }

    #[test]
    fn ttl_is_clamped_to_the_supported_range() {
        let short = issue_with_secret(b"test-secret-0123456789", "s:h", 1_000, 1);
        assert_eq!(short.ttl_seconds, MIN_TURN_TTL_SECONDS);
        assert!(short.username.starts_with("1060:"));
        let long = issue_with_secret(b"test-secret-0123456789", "s:h", 1_000, u64::MAX);
        assert_eq!(long.ttl_seconds, MAX_TURN_TTL_SECONDS);
    }

    #[test]
    fn config_requires_a_secret_and_at_least_one_url() {
        // Save and restore the process environment around the assertions so
        // parallel tests never observe a half-configured deployment.
        let saved: Vec<(&str, Option<String>)> = [
            "OPENSTREAM_TURN_SECRET",
            "OPENSTREAM_TURN_URLS",
            "OPENSTREAM_TURN_TTL",
            "OPENSTREAM_TURN_REALM",
        ]
        .iter()
        .map(|key| (*key, std::env::var(key).ok()))
        .collect();
        unsafe {
            std::env::remove_var("OPENSTREAM_TURN_SECRET");
            std::env::remove_var("OPENSTREAM_TURN_URLS");
        }
        assert!(TurnConfig::from_env().is_none());
        unsafe {
            std::env::set_var("OPENSTREAM_TURN_SECRET", "short");
            std::env::set_var("OPENSTREAM_TURN_URLS", "turn:turn.example:3478");
        }
        assert!(TurnConfig::from_env().is_none());
        unsafe {
            std::env::set_var("OPENSTREAM_TURN_SECRET", "a-long-enough-secret-for-tests");
        }
        let config = TurnConfig::from_env().expect("configured");
        assert_eq!(config.urls, vec!["turn:turn.example:3478".to_string()]);
        assert_eq!(config.realm, "openstream");
        unsafe {
            std::env::set_var(
                "OPENSTREAM_TURN_URLS",
                "turn:user:password@turn.example:3478",
            );
        }
        assert!(TurnConfig::from_env().is_none());
        unsafe {
            std::env::set_var("OPENSTREAM_TURN_URLS", "https://turn.example:3478");
        }
        assert!(TurnConfig::from_env().is_none());
        for (key, value) in saved {
            unsafe {
                match value {
                    Some(previous) => std::env::set_var(key, previous),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn session_scoped_credentials_never_outlive_the_session() {
        let config = TurnConfig {
            secret: b"test-secret-0123456789".to_vec(),
            realm: "openstream".into(),
            urls: vec!["turn:turn.example:3478".into()],
            ttl_seconds: 3600,
        };
        assert!(
            config
                .issue_for_session("session", "host", 1_700_000_000, 59)
                .is_none()
        );
        assert_eq!(
            config
                .issue_for_session("session", "host", 1_700_000_000, 60)
                .expect("minimum lifetime is usable")
                .ttl_seconds,
            60
        );
        assert_eq!(
            config
                .issue_for_session("session", "host", 1_700_000_000, 120)
                .expect("session lifetime caps the credential")
                .ttl_seconds,
            120
        );
    }

    #[test]
    fn session_credential_expiry_is_at_or_before_the_session_deadline() {
        let config = TurnConfig {
            secret: b"test-secret-0123456789".to_vec(),
            realm: "openstream".into(),
            urls: vec!["turn:turn.example:3478".into()],
            ttl_seconds: 3600,
        };
        let now = 1_700_000_000;
        let session_deadline = now + 120;
        let issued = config
            .issue_for_session("session", "client", now, session_deadline - now)
            .expect("credential fits inside the session");

        let expiry = issued
            .username
            .split_once(':')
            .expect("TURN username contains an expiry")
            .0
            .parse::<u64>()
            .expect("TURN expiry is numeric");
        assert_eq!(expiry, session_deadline);
    }
}
