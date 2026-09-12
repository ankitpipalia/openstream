//! Tests for the host-agent IPC bridge.
//!
//! `TestAgentServer` is a minimal one-shot stand-in for the real host
//! agent process: it accepts a single connection, reads exactly one
//! `AgentIpcRequest`, writes back a canned `AgentIpcResponse`, and cleans
//! up its private socket. No production code is exercised on the server
//! side; only the client's framing, timeout, and error-mapping behavior is
//! under test here.

use super::{HostAgentBridgeError, HostAgentClient};
use openstream_host_agent::{
    AgentIpcRequest, AgentIpcResponse, ChildState, HostAgentEvent, HostErrorCode, HostHealth,
    HOST_AGENT_PROTOCOL_VERSION,
};
use openstream_local_ipc::{read_frame, write_frame, Endpoint, RequestId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

/// Build a private, bounded-length socket path unique to this call. Kept
/// short so it stays well under the local-ipc endpoint length limit even
/// on systems with a long default temporary directory.
fn unique_socket_path() -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("osa-{nanos:x}-{sequence:x}"))
        .join("s.sock")
}

fn sample_health() -> HostHealth {
    HostHealth {
        state: ChildState::Ready,
        backend: "ffmpeg-fallback".into(),
        pid: Some(42),
        restart_count: 0,
        next_restart_in_ms: None,
        last_exit: None,
        last_error: None,
    }
}

/// One-shot local IPC double for the host agent's control socket.
struct TestAgentServer {
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl TestAgentServer {
    async fn spawn(response: AgentIpcResponse) -> Self {
        let endpoint = Endpoint::new(unique_socket_path()).expect("valid test endpoint path");
        let listener = endpoint.bind().await.expect("bind test endpoint");
        let task = tokio::spawn(async move {
            if let Ok((mut stream, _address)) = listener.accept().await {
                let _request: Option<AgentIpcRequest> =
                    read_frame(&mut stream).await.unwrap_or(None);
                let _ = write_frame(&mut stream, &response).await;
            }
        });
        Self { endpoint, task }
    }

    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

impl Drop for TestAgentServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = self.endpoint.cleanup();
        if let Some(parent) = self.endpoint.path().parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

#[tokio::test]
async fn health_round_trip_uses_typed_ipc_without_secret_fields() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Health {
        version: HOST_AGENT_PROTOCOL_VERSION,
        request_id: RequestId::new("test-health").unwrap(),
        health: HostHealth {
            state: ChildState::Ready,
            backend: "ffmpeg-fallback".into(),
            pid: Some(42),
            restart_count: 0,
            next_restart_in_ms: None,
            last_exit: None,
            last_error: None,
        },
    })
    .await;
    let health = HostAgentClient::with_endpoint(server.endpoint())
        .health()
        .await
        .unwrap();
    assert_eq!(health.state, ChildState::Ready);
    assert!(!serde_json::to_string(&health).unwrap().contains("pairing"));
}

#[tokio::test]
async fn start_returns_typed_events() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Accepted {
        version: HOST_AGENT_PROTOCOL_VERSION,
        request_id: RequestId::new("test-start").unwrap(),
        events: vec![
            HostAgentEvent::Started { pid: Some(7) },
            HostAgentEvent::Ready,
        ],
    })
    .await;
    let events = HostAgentClient::with_endpoint(server.endpoint())
        .start()
        .await
        .unwrap();
    assert_eq!(
        events,
        vec![
            HostAgentEvent::Started { pid: Some(7) },
            HostAgentEvent::Ready
        ]
    );
}

#[tokio::test]
async fn stop_returns_typed_events() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Accepted {
        version: HOST_AGENT_PROTOCOL_VERSION,
        request_id: RequestId::new("test-stop").unwrap(),
        events: vec![HostAgentEvent::Stopped],
    })
    .await;
    let events = HostAgentClient::with_endpoint(server.endpoint())
        .stop()
        .await
        .unwrap();
    assert_eq!(events, vec![HostAgentEvent::Stopped]);
}

#[tokio::test]
async fn mismatched_protocol_version_is_a_typed_error() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Health {
        version: HOST_AGENT_PROTOCOL_VERSION + 1,
        request_id: RequestId::new("test-version").unwrap(),
        health: sample_health(),
    })
    .await;
    let result = HostAgentClient::with_endpoint(server.endpoint())
        .health()
        .await;
    assert_eq!(result, Err(HostAgentBridgeError::ProtocolMismatch));
}

#[tokio::test]
async fn connecting_with_no_listener_is_a_typed_connection_error() {
    let endpoint = Endpoint::new(unique_socket_path()).expect("valid endpoint path");
    let result = HostAgentClient::with_endpoint(endpoint).health().await;
    assert_eq!(result, Err(HostAgentBridgeError::ConnectionFailed));
}

#[tokio::test]
async fn agent_error_response_maps_to_typed_agent_failure() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Error {
        version: HOST_AGENT_PROTOCOL_VERSION,
        request_id: RequestId::new("test-error").unwrap(),
        code: HostErrorCode::ChildFailed,
        retryable: true,
    })
    .await;
    let result = HostAgentClient::with_endpoint(server.endpoint())
        .start()
        .await;
    assert_eq!(
        result,
        Err(HostAgentBridgeError::AgentRejected {
            code: HostErrorCode::ChildFailed,
            retryable: true,
        })
    );
}
