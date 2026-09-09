use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use openstream_client_core::{
    Capabilities, ConnectionPath, Error, MigrationTarget, Pairing, PathMigrationError, PeerSession,
    Role,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

struct LoopbackIceEnv {
    previous: Option<String>,
}

impl LoopbackIceEnv {
    fn enable() -> Self {
        let previous = std::env::var("OPENSTREAM_ICE_INCLUDE_LOOPBACK").ok();
        // This test uses only loopback candidates. Rust 2024 makes process-wide
        // environment mutation explicit; the test is run with one test thread.
        unsafe { std::env::set_var("OPENSTREAM_ICE_INCLUDE_LOOPBACK", "1") };
        Self { previous }
    }
}

impl Drop for LoopbackIceEnv {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe { std::env::set_var("OPENSTREAM_ICE_INCLUDE_LOOPBACK", value) },
            None => unsafe { std::env::remove_var("OPENSTREAM_ICE_INCLUDE_LOOPBACK") },
        }
    }
}

async fn websocket_bridge() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback signaling bridge");
    let address = listener.local_addr().expect("bridge address");
    let task = tokio::spawn(async move {
        let (first, _) = listener.accept().await.expect("accept first peer");
        let first = accept_async(first).await.expect("upgrade first peer");
        let (second, _) = listener.accept().await.expect("accept second peer");
        let second = accept_async(second).await.expect("upgrade second peer");

        let (mut first_sink, mut first_source) = first.split();
        let (mut second_sink, mut second_source) = second.split();
        let (to_first, mut first_queue) = mpsc::channel::<Message>(128);
        let (to_second, mut second_queue) = mpsc::channel::<Message>(128);

        let first_writer = tokio::spawn(async move {
            while let Some(message) = first_queue.recv().await {
                if first_sink.send(message).await.is_err() {
                    break;
                }
            }
        });
        let second_writer = tokio::spawn(async move {
            while let Some(message) = second_queue.recv().await {
                if second_sink.send(message).await.is_err() {
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                message = first_source.next() => {
                    let Some(Ok(message)) = message else { break };
                    if to_second.send(message).await.is_err() { break; }
                }
                message = second_source.next() => {
                    let Some(Ok(message)) = message else { break };
                    if to_first.send(message).await.is_err() { break; }
                }
            }
        }
        first_writer.abort();
        second_writer.abort();
    });
    (format!("http://{address}"), task)
}

fn pairing() -> Pairing {
    Pairing {
        session_id: "ice-migration-test".into(),
        host_token: "host-token".into(),
        client_token: "client-token".into(),
        websocket_path: "/v1/signal/ice-migration-test/{host|client}".into(),
        expires_in_seconds: 60,
        relay_address: None,
        turn: None,
        turn_host: None,
        turn_client: None,
        relay_host_ticket: None,
        relay_client_ticket: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_migration_returns_typed_unsupported_without_reconnect() {
    let _loopback = LoopbackIceEnv::enable();
    let (origin, bridge) = websocket_bridge().await;
    let pairing = Arc::new(pairing());

    let host_pairing = Arc::clone(&pairing);
    let client_pairing = Arc::clone(&pairing);
    let (host_result, client_result) = tokio::join!(
        PeerSession::establish_with_ice(
            &origin,
            &host_pairing,
            Role::Host,
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            &[],
        ),
        PeerSession::establish_with_ice(
            &origin,
            &client_pairing,
            Role::Client,
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            &[],
        ),
    );
    let (mut host, mut client) = (
        host_result.expect("establish host"),
        client_result.expect("establish client"),
    );

    let (host_capabilities, client_capabilities) = tokio::join!(
        host.negotiate_host_with_capabilities(Capabilities::host_default().with_path_migration()),
        client.negotiate_client_with_capabilities(
            Capabilities::client_default().with_path_migration()
        ),
    );
    host_capabilities.expect("host capability negotiation");
    client_capabilities.expect("client capability negotiation");

    let generation = host.path_generation();
    let path = host.connection_path();
    let state = host.path_snapshot().state;
    let stats = host.stats();
    assert_eq!(path, ConnectionPath::Ice);
    assert!(matches!(
        host.migrate_to(MigrationTarget::Ice).await,
        Err(Error::PathMigration(
            PathMigrationError::UnsupportedIceRestart
        ))
    ));
    assert_eq!(host.path_generation(), generation);
    assert_eq!(host.connection_path(), path);
    assert_eq!(host.path_snapshot().state, state);
    assert_eq!(
        host.stats(),
        stats,
        "unsupported migration emitted no packets"
    );

    host.close().await.expect("close host");
    client.close().await.expect("close client");
    bridge.abort();
}
