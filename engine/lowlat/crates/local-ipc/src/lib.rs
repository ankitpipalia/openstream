//! Bounded local control-plane IPC for the OpenStream shell and host agent.
//!
//! This crate deliberately contains no bearer tokens, pairing material,
//! private keys, or arbitrary runtime error strings. The wire messages are
//! adapters around the safe application-domain identifiers and state types;
//! secrets remain in the control/session boundary that owns them.

use openstream_app_core::{
    AppErrorCode, AppEvent, AppState, ConnectionRejectReason, DeviceSummary, DiagnosticSnapshot,
    HostStatus, PermissionSet,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Maximum JSON payload size, excluding the four-byte length prefix.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Maximum request identifier size in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;
/// Conservative maximum Unix-domain socket path length for portable systems.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// A bounded, non-secret identifier used to correlate one IPC request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RequestId(String);

impl RequestId {
    /// Validate and create an IPC request identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IpcError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REQUEST_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(IpcError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    /// Return the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid IPC request ID"))
    }
}

/// Commands accepted over local IPC. All secret-bearing or free-form error
/// fields from the application command model are intentionally omitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    GetSnapshot,
    BeginAuthentication,
    AuthenticationSucceeded,
    Connect {
        device_id: String,
        requested: PermissionSet,
        now_ms: u64,
    },
    ApproveRequest {
        request_id: RequestId,
        available: PermissionSet,
        now_ms: u64,
    },
    RejectRequest {
        request_id: RequestId,
        now_ms: u64,
    },
    Tick {
        now_ms: u64,
    },
    ConnectionNegotiating,
    ConnectionEstablished {
        session_id: String,
        generation: u64,
    },
    ConnectionLost {
        retryable: bool,
    },
    Disconnect,
    Disconnected,
    EnableHosting,
    DisableHosting,
    HostReady,
    /// Host failures cross IPC as a typed code; the original diagnostic text
    /// is kept inside the agent and must be redacted before export.
    HostFailed {
        code: AppErrorCode,
        retryable: bool,
    },
}

/// One request from a shell or other local controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcRequest {
    pub request_id: RequestId,
    pub command: IpcCommand,
}

/// Snapshot transferred to a local UI. It contains state and diagnostics, not
/// credentials or user content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpcSnapshot {
    pub state: AppState,
    pub host_status: HostStatus,
    pub devices: Vec<DeviceSummary>,
    pub diagnostics: DiagnosticSnapshot,
}

/// One response correlated to an [`IpcRequest`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum IpcResponse {
    Accepted {
        request_id: RequestId,
    },
    State {
        request_id: RequestId,
        snapshot: Box<IpcSnapshot>,
    },
    Error {
        request_id: RequestId,
        code: AppErrorCode,
        retryable: bool,
    },
}

/// Events broadcast by the application/host agent. Free-form failure text is
/// intentionally reduced to a typed code before it reaches this wire type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcEvent {
    AuthenticationStarted,
    AuthenticationRequired,
    ApprovalRequired {
        request_id: RequestId,
        device_id: String,
        requested: PermissionSet,
        expires_at_ms: u64,
    },
    ConnectionApproved {
        request_id: RequestId,
        permissions: PermissionSet,
    },
    ConnectionRejected {
        request_id: RequestId,
        reason: ConnectionRejectReason,
    },
    ConnectionNegotiationStarted,
    ConnectionReady {
        session_id: String,
        generation: u64,
    },
    ReconnectStarted,
    DisconnectRequested,
    Disconnected,
    HostStartRequested,
    HostReady,
    HostStopRequested,
    HostFailed {
        code: AppErrorCode,
        retryable: bool,
    },
}

/// Convert a safe application event into its IPC representation.
impl TryFrom<AppEvent> for IpcEvent {
    type Error = IpcError;

    fn try_from(event: AppEvent) -> Result<Self, Self::Error> {
        Ok(match event {
            AppEvent::AuthenticationStarted => Self::AuthenticationStarted,
            AppEvent::AuthenticationRequired => Self::AuthenticationRequired,
            AppEvent::ApprovalRequired(request) => Self::ApprovalRequired {
                request_id: RequestId::new(request.request_id)?,
                device_id: request.device_id,
                requested: request.requested,
                expires_at_ms: request.expires_at_ms,
            },
            AppEvent::ConnectionApproved {
                request_id,
                permissions,
            } => Self::ConnectionApproved {
                request_id: RequestId::new(request_id)?,
                permissions,
            },
            AppEvent::ConnectionRejected { request_id, reason } => Self::ConnectionRejected {
                request_id: RequestId::new(request_id)?,
                reason,
            },
            AppEvent::ConnectionNegotiationStarted => Self::ConnectionNegotiationStarted,
            AppEvent::ConnectionReady {
                session_id,
                generation,
            } => Self::ConnectionReady {
                session_id,
                generation,
            },
            AppEvent::ReconnectStarted => Self::ReconnectStarted,
            AppEvent::DisconnectRequested => Self::DisconnectRequested,
            AppEvent::Disconnected => Self::Disconnected,
            AppEvent::HostStartRequested => Self::HostStartRequested,
            AppEvent::HostReady => Self::HostReady,
            AppEvent::HostStopRequested => Self::HostStopRequested,
            AppEvent::HostFailed { code } => Self::HostFailed {
                retryable: code.retryable(),
                code,
            },
        })
    }
}

/// Framing and endpoint errors. Error values never include frame contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    InvalidRequestId,
    TooLarge { length: usize },
    Empty,
    Truncated,
    TrailingBytes { expected: usize, actual: usize },
    Json(String),
    Io(io::ErrorKind),
    InvalidEndpoint,
    InsecureParentPermissions,
    ExistingPath,
    SymlinkPath,
    SocketInUse,
    UnsupportedPlatform,
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => formatter.write_str("invalid IPC request ID"),
            Self::TooLarge { length } => {
                write!(formatter, "IPC frame is too large: {length} bytes")
            }
            Self::Empty => formatter.write_str("IPC frame is empty"),
            Self::Truncated => formatter.write_str("IPC frame is truncated"),
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "IPC frame has trailing bytes: expected {expected}, got {actual}"
            ),
            Self::Json(reason) => write!(formatter, "IPC JSON is invalid: {reason}"),
            Self::Io(kind) => write!(formatter, "IPC I/O failed: {kind}"),
            Self::InvalidEndpoint => formatter.write_str("invalid IPC endpoint path"),
            Self::InsecureParentPermissions => {
                formatter.write_str("IPC endpoint parent is not private")
            }
            Self::ExistingPath => formatter.write_str("IPC endpoint path is not a socket"),
            Self::SymlinkPath => formatter.write_str("IPC endpoint path may not be a symlink"),
            Self::SocketInUse => formatter.write_str("IPC endpoint socket is already in use"),
            Self::UnsupportedPlatform => formatter.write_str("Unix IPC is unavailable here"),
        }
    }
}

impl std::error::Error for IpcError {}

/// Alias retained for callers that want to name framing failures explicitly.
pub type FrameError = IpcError;

/// Encode one value with a four-byte big-endian length prefix.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value).map_err(|error| FrameError::Json(error.to_string()))?;
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            length: payload.len(),
        });
    }
    let length = u32::try_from(payload.len()).expect("MAX_FRAME_BYTES fits a u32");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one length-prefixed frame without allocating based on an
/// untrusted length above [`MAX_FRAME_BYTES`].
pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::Truncated);
    }
    let declared = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { length: declared });
    }
    let actual = frame.len() - 4;
    if actual < declared {
        return Err(FrameError::Truncated);
    }
    if actual > declared {
        return Err(FrameError::TrailingBytes {
            expected: declared,
            actual,
        });
    }
    serde_json::from_slice(&frame[4..]).map_err(|error| FrameError::Json(error.to_string()))
}

/// Read one framed value from an async stream. Clean EOF before a new frame is
/// represented by `Ok(None)`; a partial prefix or payload is a truncation.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: DeserializeOwned,
{
    use tokio::io::AsyncReadExt;

    let mut prefix = [0_u8; 4];
    let first = reader
        .read(&mut prefix[..1])
        .await
        .map_err(|error| FrameError::Io(error.kind()))?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut prefix[1..])
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            kind => FrameError::Io(kind),
        })?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { length: declared });
    }
    let mut payload = vec![0_u8; declared];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            kind => FrameError::Io(kind),
        })?;
    serde_json::from_slice(&payload).map_err(|error| FrameError::Json(error.to_string()))
}

/// Write one framed value to an async stream.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    use tokio::io::AsyncWriteExt;

    let frame = encode_frame(value)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|error| FrameError::Io(error.kind()))
}

/// Validated path for a local Unix-domain IPC endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    path: PathBuf,
}

impl Endpoint {
    /// Create an endpoint descriptor. Paths must be absolute, bounded, and
    /// have a final filename so callers cannot accidentally target a directory.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, IpcError> {
        let path = path.into();
        if !path.is_absolute()
            || path.as_os_str().is_empty()
            || path.file_name().is_none()
            || path.to_string_lossy().len() > MAX_SOCKET_PATH_BYTES
            || path.to_string_lossy().contains('\0')
        {
            return Err(IpcError::InvalidEndpoint);
        }
        Ok(Self { path })
    }

    /// Return the endpoint filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn ensure_private_parent(&self) -> Result<(), IpcError> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let parent = self.path.parent().ok_or(IpcError::InvalidEndpoint)?;
        let created = if parent.exists() {
            false
        } else {
            fs::create_dir_all(parent).map_err(|error| IpcError::Io(error.kind()))?;
            true
        };
        let metadata = fs::symlink_metadata(parent).map_err(|error| IpcError::Io(error.kind()))?;
        if !metadata.is_dir() {
            return Err(IpcError::ExistingPath);
        }
        let mode = metadata.permissions().mode() & 0o777;
        if !created && mode & 0o077 != 0 {
            return Err(IpcError::InsecureParentPermissions);
        }
        if created {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| IpcError::Io(error.kind()))?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_stale_socket(&self) -> Result<(), IpcError> {
        use std::fs;
        use std::os::unix::fs::FileTypeExt;

        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(IpcError::Io(error.kind())),
        };
        if metadata.file_type().is_symlink() {
            return Err(IpcError::SymlinkPath);
        }
        if !metadata.file_type().is_socket() {
            return Err(IpcError::ExistingPath);
        }
        Err(IpcError::SocketInUse)
    }

    /// Bind a private Unix listener. An existing socket is never unlinked
    /// blindly: callers must explicitly remove a stale endpoint first.
    #[cfg(unix)]
    pub async fn bind(&self) -> Result<tokio::net::UnixListener, IpcError> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        self.ensure_private_parent()?;
        self.remove_stale_socket()?;
        let listener = tokio::net::UnixListener::bind(&self.path)
            .map_err(|error| IpcError::Io(error.kind()))?;
        if let Err(error) = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&self.path);
            return Err(IpcError::Io(error.kind()));
        }
        Ok(listener)
    }

    /// Connect to an existing Unix listener.
    #[cfg(unix)]
    pub async fn connect(&self) -> Result<tokio::net::UnixStream, IpcError> {
        tokio::net::UnixStream::connect(&self.path)
            .await
            .map_err(|error| IpcError::Io(error.kind()))
    }

    /// Remove this endpoint if it is a socket. Cleanup is idempotent and
    /// refuses to remove a symlink or unrelated file.
    #[cfg(unix)]
    pub fn cleanup(&self) -> Result<(), IpcError> {
        use std::fs;
        use std::os::unix::fs::FileTypeExt;

        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(IpcError::Io(error.kind())),
        };
        if metadata.file_type().is_symlink() {
            return Err(IpcError::SymlinkPath);
        }
        if !metadata.file_type().is_socket() {
            return Err(IpcError::ExistingPath);
        }
        fs::remove_file(&self.path).map_err(|error| IpcError::Io(error.kind()))
    }
}

#[cfg(not(unix))]
impl Endpoint {
    /// Unix IPC is not available on this target yet.
    pub async fn bind(&self) -> Result<(), IpcError> {
        Err(IpcError::UnsupportedPlatform)
    }

    /// Unix IPC is not available on this target yet.
    pub async fn connect(&self) -> Result<(), IpcError> {
        Err(IpcError::UnsupportedPlatform)
    }

    /// Unix IPC is not available on this target yet.
    pub fn cleanup(&self) -> Result<(), IpcError> {
        Err(IpcError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Endpoint, FrameError, IpcCommand, IpcEvent, IpcRequest, IpcResponse, MAX_FRAME_BYTES,
        RequestId, decode_frame, encode_frame, read_frame, write_frame,
    };
    use openstream_app_core::{AppState, HostStatus, PermissionSet};

    #[test]
    fn request_id_is_bounded_and_round_trips() {
        let id = RequestId::new("request-1").expect("valid request id");
        let request = IpcRequest {
            request_id: id.clone(),
            command: super::IpcCommand::Tick { now_ms: 42 },
        };
        let encoded = encode_frame(&request).expect("request encodes");
        let decoded: IpcRequest = decode_frame(&encoded).expect("request decodes");
        assert_eq!(decoded, request);
        assert!(RequestId::new("x".repeat(129)).is_err());
        assert!(RequestId::new("bad\nrequest").is_err());
    }

    #[test]
    fn frames_use_a_big_endian_length_and_reject_empty_or_oversized_payloads() {
        let event = IpcEvent::HostReady;
        let encoded = encode_frame(&event).expect("event encodes");
        let declared = u32::from_be_bytes(encoded[..4].try_into().expect("length prefix"));
        assert_eq!(declared as usize, encoded.len() - 4);
        assert!(matches!(
            decode_frame::<IpcEvent>(&[0, 0, 0, 0]),
            Err(FrameError::Empty)
        ));

        let oversized_length = u32::try_from(MAX_FRAME_BYTES).expect("test size fits") + 1;
        let mut oversized = Vec::from(oversized_length.to_be_bytes());
        oversized.extend(std::iter::repeat_n(b'X', MAX_FRAME_BYTES + 1));
        assert!(matches!(
            decode_frame::<IpcEvent>(&oversized),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn malformed_truncated_trailing_and_invalid_json_frames_fail_closed() {
        assert!(matches!(
            decode_frame::<IpcEvent>(&[0, 0, 0]),
            Err(FrameError::Truncated)
        ));
        assert!(matches!(
            decode_frame::<IpcEvent>(&[0, 0, 0, 1]),
            Err(FrameError::Truncated)
        ));
        assert!(matches!(
            decode_frame::<IpcEvent>(&[0, 0, 0, 1, b'X', b'Y']),
            Err(FrameError::TrailingBytes { .. })
        ));
        assert!(matches!(
            decode_frame::<IpcEvent>(&[0, 0, 0, 1, b'X']),
            Err(FrameError::Json(_))
        ));
    }

    #[test]
    fn ipc_values_are_domain_only_and_serde_safe() {
        let response = IpcResponse::State {
            request_id: RequestId::new("status").expect("request id"),
            snapshot: Box::new(super::IpcSnapshot {
                state: AppState::Ready,
                host_status: HostStatus::Disabled,
                devices: Vec::new(),
                diagnostics: super::DiagnosticSnapshot::default(),
            }),
        };
        let text = serde_json::to_string(&response).expect("response serializes");
        assert!(!text.contains("token"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("pairing"));
        let _ = PermissionSet::view_only();
    }

    #[test]
    fn typed_connection_rejection_round_trips_over_ipc() {
        let event = IpcEvent::try_from(openstream_app_core::AppEvent::ConnectionRejected {
            request_id: "request-1".into(),
            reason: openstream_app_core::ConnectionRejectReason::Expired,
        })
        .expect("domain rejection maps to IPC");
        assert_eq!(
            event,
            IpcEvent::ConnectionRejected {
                request_id: RequestId::new("request-1").expect("request id"),
                reason: openstream_app_core::ConnectionRejectReason::Expired,
            }
        );

        let encoded = encode_frame(&event).expect("rejection encodes");
        let decoded: IpcEvent = decode_frame(&encoded).expect("rejection decodes");
        assert_eq!(decoded, event);
    }

    #[tokio::test]
    async fn async_reader_and_writer_preserve_frame_boundaries_and_clean_eof() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let event = IpcEvent::HostReady;
        write_frame(&mut writer, &event)
            .await
            .expect("event writes");
        let decoded: Option<IpcEvent> = read_frame(&mut reader).await.expect("event reads");
        assert_eq!(decoded, Some(event));
        drop(writer);
        let end: Option<IpcEvent> = read_frame(&mut reader).await.expect("clean EOF");
        assert_eq!(end, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn endpoint_creates_private_socket_and_cleans_up_idempotently() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("openstream-ipc-{unique}"));
        let path = root.join("agent.sock");
        let endpoint = Endpoint::new(&path).expect("endpoint");
        let listener = endpoint.bind().await.expect("bind endpoint");
        let parent_mode = std::fs::metadata(&root)
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777;
        let socket_mode = std::fs::symlink_metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(socket_mode, 0o600);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept endpoint client");
            let request: Option<IpcRequest> = read_frame(&mut stream).await.expect("read request");
            assert_eq!(
                request.expect("request frame").command,
                IpcCommand::GetSnapshot
            );
            let response = IpcResponse::Accepted {
                request_id: RequestId::new("request-1").expect("response request ID"),
            };
            write_frame(&mut stream, &response)
                .await
                .expect("write response");
        });
        let mut stream = endpoint.connect().await.expect("connect endpoint");
        let request = IpcRequest {
            request_id: RequestId::new("request-1").expect("request ID"),
            command: IpcCommand::GetSnapshot,
        };
        write_frame(&mut stream, &request)
            .await
            .expect("write request");
        let response: Option<IpcResponse> = read_frame(&mut stream).await.expect("read response");
        assert!(matches!(
            response,
            Some(IpcResponse::Accepted { request_id }) if request_id.as_str() == "request-1"
        ));
        server.await.expect("server task");
        endpoint.cleanup().expect("cleanup");
        endpoint.cleanup().expect("cleanup is idempotent");
        assert!(!path.exists());
        std::fs::remove_dir(&root).expect("remove test directory");
    }
}
