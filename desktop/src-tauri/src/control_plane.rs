//! Small authenticated client for the OpenStream self-hosted control plane.
//!
//! The desktop shell owns this client, but it never exposes its bearer values
//! to React, diagnostics, command arguments, or persisted settings. Access
//! tokens live only in this process and refresh tokens live only in this
//! process for now; a platform secret-provider integration is a separate
//! release gate, so callers must not treat this as durable credential storage.

use openstream_client_core::{local_device_id, local_identity_public_key};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_USERNAME_BYTES: usize = 128;
const MAX_PASSWORD_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneError {
    InvalidOrigin,
    InvalidInput,
    IdentityUnavailable,
    Unauthorized,
    NotFound,
    Conflict,
    Forbidden,
    RateLimited,
    ServerUnavailable,
    InvalidResponse,
    Transport,
    NotAuthenticated,
}

impl fmt::Display for ControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOrigin => "control-plane origin is invalid",
            Self::InvalidInput => "account input is invalid",
            Self::IdentityUnavailable => "the local device identity is unavailable",
            Self::Unauthorized => "control-plane authentication failed",
            Self::NotFound => "the control-plane record was not found",
            Self::Conflict => "the control-plane request conflicts with existing state",
            Self::Forbidden => "the control-plane request is not permitted",
            Self::RateLimited => "the control plane is rate limiting requests",
            Self::ServerUnavailable => "the control plane is unavailable",
            Self::InvalidResponse => "the control-plane response was invalid",
            Self::Transport => "the control-plane request failed",
            Self::NotAuthenticated => "the desktop is not signed in",
        })
    }
}

impl std::error::Error for ControlPlaneError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrust {
    Pending,
    Trusted,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicUser {
    pub account_id: String,
    pub username: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicDevice {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub trust: DeviceTrust,
    pub enrolled_at_ms: u64,
    pub last_seen_ms: Option<u64>,
    pub public_key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedAccount {
    pub user: PublicUser,
    pub device: Option<PublicDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSignIn {
    pub account: AuthenticatedAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceRegistration {
    device_id: String,
    name: String,
    platform: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct AccountCredentials<'a> {
    username: &'a str,
    password: &'a str,
    device: DeviceRegistration,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    access_expires_in_seconds: u64,
    #[allow(dead_code)]
    refresh_expires_in_seconds: u64,
    user: PublicUser,
    device: Option<PublicDevice>,
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Debug, Serialize)]
struct ConnectRequestBody<'a> {
    target_device_id: &'a str,
}

/// What the service says about a request this device just made.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectRequested {
    pub request_id: String,
    pub state: ConnectState,
    pub expires_in_seconds: u64,
}

/// A request this device is being asked to answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingConnectRequest {
    pub request_id: String,
    pub requester_device_id: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectState {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// One end of an approved session: a session and exactly one role token.
///
/// There is deliberately no shape here carrying both roles. The service will
/// not return both to one caller, and a type that could hold them would be
/// the first step towards asking it to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConnectCredential {
    pub session_id: String,
    pub role: String,
    pub token: String,
    pub websocket_path: String,
    #[serde(default)]
    pub relay_address: Option<String>,
    pub relay_ticket: String,
}

/// Either a request that is still waiting, or the capability it produced.
///
/// Untagged because the service answers the same URL with one or the other:
/// a pending request has no credential to report, and an approved one has
/// nothing else worth saying.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ConnectObservation {
    Granted(Box<ConnectCredential>),
    Waiting { state: ConnectState },
}

#[derive(Debug, Serialize)]
struct TrustRequest {
    trust: DeviceTrust,
}

pub struct ControlPlaneClient {
    origin: String,
    http: reqwest::Client,
    access_token: Option<String>,
    refresh_token: Option<String>,
    access_expires_at: Option<std::time::Instant>,
    account: Option<AuthenticatedAccount>,
}

impl fmt::Debug for ControlPlaneClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneClient")
            .field("origin", &self.origin)
            .field("authenticated", &self.is_authenticated())
            .field("has_access_token", &self.access_token.is_some())
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("account", &self.account)
            .finish()
    }
}

impl ControlPlaneClient {
    pub fn new(origin: &str) -> Result<Self, ControlPlaneError> {
        validate_origin(origin)?;
        let http = reqwest::Client::builder()
            .connect_timeout(HTTP_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|_| ControlPlaneError::Transport)?;
        Ok(Self {
            origin: origin.trim_end_matches('/').to_string(),
            http,
            access_token: None,
            refresh_token: None,
            access_expires_at: None,
            account: None,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token.is_some() && self.account.is_some()
    }

    pub fn account(&self) -> Option<&AuthenticatedAccount> {
        self.account.as_ref()
    }

    /// Change the endpoint only as a Rust-owned settings outcome. Tokens are
    /// discarded because a bearer from one control plane must never be sent to
    /// another origin.
    pub fn reconfigure(&mut self, origin: &str) -> Result<(), ControlPlaneError> {
        validate_origin(origin)?;
        if self.origin != origin.trim_end_matches('/') {
            self.origin = origin.trim_end_matches('/').to_string();
            self.clear_credentials();
        }
        Ok(())
    }

    pub async fn register(
        &mut self,
        username: &str,
        password: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<AccountSignIn, ControlPlaneError> {
        validate_credentials(username, password)?;
        let registration = local_registration(device_name, platform)?;
        let response = self
            .http
            .post(self.endpoint("/v1/auth/register")?)
            .json(&AccountCredentials {
                username,
                password,
                device: registration,
            })
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        let response: AuthResponse = parse_response(response).await?;
        Ok(self.accept_auth(response))
    }

    pub async fn sign_in(
        &mut self,
        username: &str,
        password: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<AccountSignIn, ControlPlaneError> {
        validate_credentials(username, password)?;
        let registration = local_registration(device_name, platform)?;
        let response = self
            .http
            .post(self.endpoint("/v1/auth/login")?)
            .json(&AccountCredentials {
                username,
                password,
                device: registration,
            })
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        let response: AuthResponse = parse_response(response).await?;
        Ok(self.accept_auth(response))
    }

    pub async fn refresh(&mut self) -> Result<AccountSignIn, ControlPlaneError> {
        let refresh_token = self
            .refresh_token
            .clone()
            .ok_or(ControlPlaneError::NotAuthenticated)?;
        let response = self
            .http
            .post(self.endpoint("/v1/auth/refresh")?)
            .json(&RefreshRequest {
                refresh_token: &refresh_token,
            })
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        let response: AuthResponse = parse_response(response).await?;
        Ok(self.accept_auth(response))
    }

    pub async fn devices(&mut self) -> Result<Vec<PublicDevice>, ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.get(self.endpoint("/v1/devices")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport);
        match response {
            Ok(response) => parse_response(response).await,
            Err(error) => Err(error),
        }
    }

    pub async fn set_device_trust(
        &mut self,
        device_id: &str,
        trust: DeviceTrust,
    ) -> Result<PublicDevice, ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.patch(self.device_trust_endpoint(device_id)?))?
            .json(&TrustRequest { trust })
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport);
        match response {
            Ok(response) => parse_response(response).await,
            Err(error) => Err(error),
        }
    }

    // -----------------------------------------------------------------
    // Secure Connect
    // -----------------------------------------------------------------

    /// Tell the service this device is online and able to host.
    ///
    /// A heartbeat, not a registration: presence lapses on its own, so a
    /// machine that is switched off stops being offered rather than lingering
    /// in its owner's device list as connectable.
    pub async fn announce_presence(&mut self) -> Result<(), ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.post(self.endpoint("/v1/presence")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        expect_no_content(response)
    }

    /// Stop being offered as a host.
    pub async fn withdraw_presence(&mut self) -> Result<(), ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.delete(self.endpoint("/v1/presence")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        expect_no_content(response)
    }

    /// Ask one of this account's devices for a session.
    pub async fn request_connect(
        &mut self,
        target_device_id: &str,
    ) -> Result<ConnectRequested, ControlPlaneError> {
        if target_device_id.is_empty() || target_device_id.len() > 128 {
            return Err(ControlPlaneError::InvalidInput);
        }
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.post(self.endpoint("/v1/connect")?))?
            .json(&ConnectRequestBody { target_device_id })
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        parse_response(response).await
    }

    /// Requests this device is being asked to approve.
    pub async fn pending_connect_requests(
        &mut self,
    ) -> Result<Vec<PendingConnectRequest>, ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.get(self.endpoint("/v1/connect/pending")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        parse_response(response).await
    }

    /// Approve a request and receive the host capability.
    ///
    /// Safe to repeat. The service treats a second identical approval as the
    /// retry it is and returns the same credential, because approving is the
    /// only way a host receives one and a lost response would otherwise
    /// strand it outside its own session.
    pub async fn approve_connect(
        &mut self,
        request_id: &str,
    ) -> Result<ConnectCredential, ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(
                self.http
                    .post(self.connect_endpoint(request_id, "approve")?),
            )?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        parse_response(response).await
    }

    /// Refuse a request.
    pub async fn deny_connect(&mut self, request_id: &str) -> Result<(), ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.post(self.connect_endpoint(request_id, "deny")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        expect_no_content(response)
    }

    /// Poll a request this device made, collecting the client capability once
    /// it has been approved.
    ///
    /// Also safe to repeat, for the same reason.
    pub async fn observe_connect(
        &mut self,
        request_id: &str,
    ) -> Result<ConnectObservation, ControlPlaneError> {
        self.refresh_if_needed().await?;
        let response = self
            .authenticated_request(self.http.get(self.connect_endpoint(request_id, "")?))?
            .send()
            .await
            .map_err(|_| ControlPlaneError::Transport)?;
        parse_response(response).await
    }

    fn connect_endpoint(
        &self,
        request_id: &str,
        action: &str,
    ) -> Result<reqwest::Url, ControlPlaneError> {
        if request_id.is_empty() || request_id.len() > 128 {
            return Err(ControlPlaneError::InvalidInput);
        }
        let mut url = self.endpoint("/v1/connect")?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| ControlPlaneError::InvalidOrigin)?;
            segments.push(request_id);
            if !action.is_empty() {
                segments.push(action);
            }
        }
        Ok(url)
    }

    pub fn clear_credentials(&mut self) {
        self.access_token = None;
        self.refresh_token = None;
        self.access_expires_at = None;
        self.account = None;
    }

    fn accept_auth(&mut self, response: AuthResponse) -> AccountSignIn {
        let account = AuthenticatedAccount {
            user: response.user,
            device: response.device,
        };
        self.access_token = Some(response.access_token);
        self.refresh_token = Some(response.refresh_token);
        self.access_expires_at = Some(
            std::time::Instant::now()
                + Duration::from_secs(response.access_expires_in_seconds.max(1)),
        );
        self.account = Some(account.clone());
        AccountSignIn { account }
    }

    fn endpoint(&self, path: &str) -> Result<reqwest::Url, ControlPlaneError> {
        reqwest::Url::parse(&format!("{}{}", self.origin, path))
            .map_err(|_| ControlPlaneError::InvalidOrigin)
    }

    fn device_trust_endpoint(&self, device_id: &str) -> Result<reqwest::Url, ControlPlaneError> {
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(ControlPlaneError::InvalidInput);
        }
        let mut url = self.endpoint("/v1/devices")?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| ControlPlaneError::InvalidOrigin)?;
            segments.push(device_id).push("trust");
        }
        Ok(url)
    }

    async fn refresh_if_needed(&mut self) -> Result<(), ControlPlaneError> {
        if self
            .access_expires_at
            .is_some_and(|deadline| deadline <= std::time::Instant::now() + Duration::from_secs(5))
        {
            self.refresh().await?;
        }
        Ok(())
    }

    fn authenticated_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, ControlPlaneError> {
        let token = self
            .access_token
            .as_deref()
            .ok_or(ControlPlaneError::NotAuthenticated)?;
        Ok(request.bearer_auth(token))
    }
}

/// Accept a success that carries no body.
///
/// Separate from [`parse_response`] because a 204 has nothing to deserialise
/// and feeding an empty body to a JSON parser reports a transport fault for
/// a call that in fact succeeded.
fn expect_no_content(response: reqwest::Response) -> Result<(), ControlPlaneError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(status_error(status))
}

async fn parse_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ControlPlaneError> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(status));
    }
    response
        .json::<T>()
        .await
        .map_err(|_| ControlPlaneError::InvalidResponse)
}

/// One mapping from HTTP status to a typed error, shared by every call.
fn status_error(status: reqwest::StatusCode) -> ControlPlaneError {
    match status.as_u16() {
        401 => ControlPlaneError::Unauthorized,
        403 => ControlPlaneError::Forbidden,
        404 => ControlPlaneError::NotFound,
        409 => ControlPlaneError::Conflict,
        429 => ControlPlaneError::RateLimited,
        500..=599 => ControlPlaneError::ServerUnavailable,
        _ => ControlPlaneError::InvalidResponse,
    }
}

/// Accept only a loopback plaintext origin or an HTTPS one.
///
/// Stricter than the settings-level rule, which additionally allows a
/// private-LAN plaintext origin under `network.local_no_auth`. That is
/// deliberate: `local_no_auth` is the mode with no accounts at all, so this
/// client is not used there, and account credentials must never be the thing
/// that travels in the clear across a LAN.
fn validate_origin(origin: &str) -> Result<(), ControlPlaneError> {
    let url = reqwest::Url::parse(origin).map_err(|_| ControlPlaneError::InvalidOrigin)?;
    let Some(host) = url.host_str() else {
        return Err(ControlPlaneError::InvalidOrigin);
    };
    // `host_str` serializes an IPv6 literal in its URL form, brackets and
    // all, and `[::1]` does not parse as an address. Strip them before
    // asking, or a loopback origin is misread as remote and refused.
    let literal = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || literal
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (!url.path().is_empty() && url.path() != "/")
        || (url.scheme() == "http" && !loopback)
        || origin.len() > 2048
    {
        return Err(ControlPlaneError::InvalidOrigin);
    }
    Ok(())
}

fn validate_credentials(username: &str, password: &str) -> Result<(), ControlPlaneError> {
    if !(3..=MAX_USERNAME_BYTES).contains(&username.len())
        || username.chars().any(char::is_control)
        || username.chars().any(char::is_whitespace)
        || !(12..=MAX_PASSWORD_BYTES).contains(&password.len())
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    Ok(())
}

fn local_registration(name: &str, platform: &str) -> Result<DeviceRegistration, ControlPlaneError> {
    if name.is_empty()
        || name.len() > 128
        || platform.is_empty()
        || platform.len() > 64
        || name.chars().any(char::is_control)
        || platform.chars().any(char::is_control)
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    let public_key =
        local_identity_public_key().map_err(|_| ControlPlaneError::IdentityUnavailable)?;
    let device_id = local_device_id().map_err(|_| ControlPlaneError::IdentityUnavailable)?;
    Ok(DeviceRegistration {
        device_id,
        name: name.to_string(),
        platform: platform.to_string(),
        public_key: hex::encode(public_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_policy_allows_local_http_and_remote_https_only() {
        assert!(validate_origin("http://127.0.0.1:8080").is_ok());
        assert!(validate_origin("http://[::1]:8080/").is_ok());
        assert!(validate_origin("http://localhost:8080").is_ok());
        assert!(validate_origin("https://control.example").is_ok());
        assert!(matches!(
            validate_origin("http://control.example"),
            Err(ControlPlaneError::InvalidOrigin)
        ));
    }

    #[test]
    fn origin_policy_rejects_ambiguous_origins() {
        for origin in [
            "https://control.example/path",
            "https://control.example/?token=secret",
            "https://user:password@control.example",
            "ftp://control.example",
            "http://0.0.0.0:8080",
        ] {
            assert!(
                matches!(
                    validate_origin(origin),
                    Err(ControlPlaneError::InvalidOrigin)
                ),
                "origin should be rejected: {origin}"
            );
        }
    }

    #[test]
    fn debug_output_never_contains_bearer_values() {
        let mut client = ControlPlaneClient::new("https://control.example").expect("client");
        client.access_token = Some("access-sentinel".to_string());
        client.refresh_token = Some("refresh-sentinel".to_string());
        let debug = format!("{client:?}");
        assert!(!debug.contains("access-sentinel"));
        assert!(!debug.contains("refresh-sentinel"));
        assert!(debug.contains("has_access_token: true"));
        assert!(debug.contains("has_refresh_token: true"));
    }

    #[test]
    fn device_trust_endpoint_rejects_unbounded_ids() {
        let client = ControlPlaneClient::new("https://control.example").expect("client");
        assert!(matches!(
            client.device_trust_endpoint(""),
            Err(ControlPlaneError::InvalidInput)
        ));
        assert!(matches!(
            client.device_trust_endpoint(&"x".repeat(129)),
            Err(ControlPlaneError::InvalidInput)
        ));
    }
}
