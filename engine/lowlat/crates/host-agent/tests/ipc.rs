#[cfg(unix)]
mod unix {
    use openstream_host_agent::{
        AgentIpcCommand, AgentIpcRequest, AgentIpcResponse, HOST_AGENT_PROTOCOL_VERSION,
    };
    use openstream_local_ipc::{Endpoint, RequestId, read_frame, write_frame};
    use std::fs;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::process::Command;

    #[tokio::test]
    async fn agent_process_serves_health_and_shutdown_over_private_socket() {
        let root =
            std::env::temp_dir().join(format!("openstream-host-agent-ipc-{}", std::process::id()));
        let socket_path = root.join("agent.sock");
        let endpoint = Endpoint::new(&socket_path).expect("valid endpoint");
        let binary = env!("CARGO_BIN_EXE_openstream-host-agent");
        let mut child = Command::new(binary)
            .env("OPENSTREAM_HOST_AGENT_SOCKET", &socket_path)
            .env("OPENSTREAM_HOST_CHILD", "yes")
            .env("OPENSTREAM_FFMPEG", "sh")
            .env("DISPLAY", ":0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn host agent");

        let mut stream = None;
        for _ in 0..100 {
            match endpoint.connect().await {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let mut stream = stream.expect("agent socket became available");

        write_frame(
            &mut stream,
            &AgentIpcRequest {
                version: HOST_AGENT_PROTOCOL_VERSION,
                request_id: RequestId::new("health").expect("request id"),
                command: AgentIpcCommand::Health,
            },
        )
        .await
        .expect("write health request");
        let response: AgentIpcResponse = read_frame(&mut stream)
            .await
            .expect("read health response")
            .expect("health response exists");
        assert!(matches!(response, AgentIpcResponse::Health { .. }));

        write_frame(
            &mut stream,
            &AgentIpcRequest {
                version: HOST_AGENT_PROTOCOL_VERSION,
                request_id: RequestId::new("shutdown").expect("request id"),
                command: AgentIpcCommand::Shutdown,
            },
        )
        .await
        .expect("write shutdown request");
        let response: AgentIpcResponse = read_frame(&mut stream)
            .await
            .expect("read shutdown response")
            .expect("shutdown response exists");
        assert!(matches!(response, AgentIpcResponse::Accepted { .. }));

        let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .expect("agent exits")
            .expect("wait for agent");
        assert!(status.success(), "agent exited with {status}");
        endpoint.cleanup().expect("cleanup is idempotent");
        let _ = fs::remove_dir_all(root);
    }
}
