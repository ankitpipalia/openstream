//! Client for the host agent's bounded local Unix IPC service.
//!
//! The desktop shell never spawns FFmpeg or touches the host child
//! directly; it only exchanges the same typed, length-prefixed frames the
//! host agent already defines for its control socket. The endpoint is
//! always the process default unless Rust test code asks for a different
//! one explicitly through [`HostAgentClient::with_endpoint`]; there is no
//! Tauri command parameter that lets the web UI choose a socket path.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openstream_host_agent::{
    AgentIpcCommand, AgentIpcRequest, AgentIpcResponse, HostAgentEvent, HostErrorCode, HostHealth,
    HOST_AGENT_PROTOCOL_VERSION,
};
use openstream_local_ipc::{read_frame, write_frame, Endpoint, IpcError, RequestId};
use serde::{Deserialize, Serialize};

/// Upper bound on one request/response round trip. Local Unix IPC normally
/// completes in well under a second; this only guards against a wedged or
/// unresponsive agent process.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors crossing the host-agent bridge boundary. Categories are stable
/// and never carry raw frame bytes, child process environment, or pairing
/// material; only a typed agent failure code and retry hint cross with
/// `AgentRejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostAgentBridgeError {
    ConnectionFailed,
    ProtocolMismatch,
    Timeout,
    InvalidResponse,
    UnsupportedPlatform,
    AgentRejected {
        code: HostErrorCode,
        retryable: bool,
    },
}

impl fmt::Display for HostAgentBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed => formatter.write_str("host agent connection failed"),
            Self::ProtocolMismatch => formatter.write_str("host agent protocol version mismatch"),
            Self::Timeout => formatter.write_str("host agent request timed out"),
            Self::InvalidResponse => formatter.write_str("host agent response was invalid"),
            Self::UnsupportedPlatform => {
                formatter.write_str("host agent IPC is not available on this target")
            }
            Self::AgentRejected { code, .. } => {
                write!(formatter, "host agent command rejected: {code:?}")
            }
        }
    }
}

impl std::error::Error for HostAgentBridgeError {}

/// Derive the same default socket path as the host agent's own
/// `socket_path()` in `main.rs`. That function is private to a bin target
/// and cannot be imported, so the derivation is intentionally duplicated
/// here rather than refactoring the host-agent crate.
fn default_socket_path() -> PathBuf {
    if let Some(path) = env::var_os("OPENSTREAM_HOST_AGENT_SOCKET") {
        return PathBuf::from(path);
    }
    let base = env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| {
            env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").into_os_string())
        })
        .unwrap_or_else(|| OsString::from("/tmp"));
    PathBuf::from(base)
        .join("openstream")
        .join("host-agent.sock")
}

fn default_endpoint() -> Result<Endpoint, HostAgentBridgeError> {
    Endpoint::new(default_socket_path()).map_err(|_| HostAgentBridgeError::ConnectionFailed)
}

/// Generate a bounded, non-secret identifier correlating one request. It
/// carries no user content and is unique within this process.
fn generate_request_id() -> RequestId {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let value = format!("desktop-host-agent-{nanos:x}-{sequence:x}");
    RequestId::new(value).expect("generated request id is bounded and control-character free")
}

/// Read the wire protocol version out of any response variant.
fn response_version(response: &AgentIpcResponse) -> u32 {
    match response {
        AgentIpcResponse::Accepted { version, .. }
        | AgentIpcResponse::Health { version, .. }
        | AgentIpcResponse::Error { version, .. } => *version,
    }
}

/// Read the request identifier out of any response variant, the same way
/// [`response_version`] reads the protocol version.
fn response_request_id(response: &AgentIpcResponse) -> &RequestId {
    match response {
        AgentIpcResponse::Accepted { request_id, .. }
        | AgentIpcResponse::Health { request_id, .. }
        | AgentIpcResponse::Error { request_id, .. } => request_id,
    }
}

/// Client for the host agent's control socket. Constructing one without an
/// explicit endpoint always targets the process-default socket; an
/// explicit endpoint is reachable only from Rust test code, never from a
/// Tauri command parameter.
#[derive(Debug)]
pub struct HostAgentClient {
    #[cfg_attr(not(unix), allow(dead_code))]
    endpoint: Endpoint,
}

impl HostAgentClient {
    /// Build a client targeting the default local host-agent endpoint.
    pub fn new() -> Result<Self, HostAgentBridgeError> {
        Ok(Self {
            endpoint: default_endpoint()?,
        })
    }

    /// Test-only construction against an explicit endpoint.
    #[cfg(test)]
    pub(crate) fn with_endpoint(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    pub async fn health(&self) -> Result<HostHealth, HostAgentBridgeError> {
        match self.call(AgentIpcCommand::Health).await? {
            AgentIpcResponse::Health { health, .. } => Ok(health),
            AgentIpcResponse::Error {
                code, retryable, ..
            } => Err(HostAgentBridgeError::AgentRejected { code, retryable }),
            AgentIpcResponse::Accepted { .. } => Err(HostAgentBridgeError::InvalidResponse),
        }
    }

    pub async fn start(&self) -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
        self.dispatch(AgentIpcCommand::Start).await
    }

    /// Start with the validated non-secret settings currently owned by the
    /// desktop runtime. The host agent resolves executable paths, probes the
    /// machine, and adds the protected pairing-file boundary itself.
    pub async fn start_with_settings(
        &self,
        settings: &openstream_settings::AppConfig,
    ) -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
        self.dispatch(AgentIpcCommand::StartWithSettings {
            settings: Box::new(settings.clone()),
        })
        .await
    }

    /// Start a session against a role capability the broker issued.
    ///
    /// Only the path crosses the socket. The agent opens it through the same
    /// protected-file check every other pairing goes through, so the
    /// capability itself never appears in an IPC frame, a log, or a crash
    /// dump of either process.
    pub async fn start_session(
        &self,
        pairing_file: &std::path::Path,
        settings: &openstream_settings::AppConfig,
    ) -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
        let pairing_file = pairing_file
            .to_str()
            .ok_or(HostAgentBridgeError::InvalidResponse)?
            .to_string();
        self.dispatch(AgentIpcCommand::StartSession {
            pairing_file,
            settings: Box::new(settings.clone()),
        })
        .await
    }

    pub async fn stop(&self) -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
        self.dispatch(AgentIpcCommand::Stop).await
    }

    async fn dispatch(
        &self,
        command: AgentIpcCommand,
    ) -> Result<Vec<HostAgentEvent>, HostAgentBridgeError> {
        match self.call(command).await? {
            AgentIpcResponse::Accepted { events, .. } => Ok(events),
            AgentIpcResponse::Error {
                code, retryable, ..
            } => Err(HostAgentBridgeError::AgentRejected { code, retryable }),
            AgentIpcResponse::Health { .. } => Err(HostAgentBridgeError::InvalidResponse),
        }
    }

    /// Send one request and validate the response's wire protocol version
    /// and request identifier before any caller inspects its contents. The
    /// identifier check matters as much as the version check: without it, a
    /// response intended for a different in-flight request would be
    /// silently accepted as this call's answer.
    async fn call(
        &self,
        command: AgentIpcCommand,
    ) -> Result<AgentIpcResponse, HostAgentBridgeError> {
        let request = AgentIpcRequest {
            version: HOST_AGENT_PROTOCOL_VERSION,
            request_id: generate_request_id(),
            command,
        };
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.round_trip(&request))
            .await
            .map_err(|_| HostAgentBridgeError::Timeout)??;
        if response_version(&response) != HOST_AGENT_PROTOCOL_VERSION {
            return Err(HostAgentBridgeError::ProtocolMismatch);
        }
        if response_request_id(&response) != &request.request_id {
            return Err(HostAgentBridgeError::InvalidResponse);
        }
        Ok(response)
    }

    /// Connect, write one request, and read one response. Only typed
    /// errors leave this function; raw frame contents are never logged.
    #[cfg(unix)]
    async fn round_trip(
        &self,
        request: &AgentIpcRequest,
    ) -> Result<AgentIpcResponse, HostAgentBridgeError> {
        let mut stream = self
            .endpoint
            .connect()
            .await
            .map_err(|_| HostAgentBridgeError::ConnectionFailed)?;
        write_frame(&mut stream, request)
            .await
            .map_err(|_| HostAgentBridgeError::ConnectionFailed)?;
        let response = read_frame::<_, AgentIpcResponse>(&mut stream)
            .await
            .map_err(|error| match error {
                IpcError::Io(_) => HostAgentBridgeError::ConnectionFailed,
                _ => HostAgentBridgeError::InvalidResponse,
            })?
            .ok_or(HostAgentBridgeError::ConnectionFailed)?;
        Ok(response)
    }

    /// The host agent's control socket is Unix-domain only, so a target
    /// without it reports the typed unsupported result rather than a
    /// connection failure it never attempted.
    #[cfg(not(unix))]
    async fn round_trip(
        &self,
        _request: &AgentIpcRequest,
    ) -> Result<AgentIpcResponse, HostAgentBridgeError> {
        Err(HostAgentBridgeError::UnsupportedPlatform)
    }
}

#[cfg(test)]
#[path = "host_agent_test.rs"]
mod host_agent_test;
