use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use openstream_client_core::{Pairing, PeerSession, Role};
use openstream_protocol::{Kind, MAX_PLAINTEXT, Session as CipherSession};
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
        session_id: "portable-transport-test".into(),
        host_token: "host-token".into(),
        client_token: "client-token".into(),
        websocket_path: "/v1/signal/portable-transport-test/{host|client}".into(),
        expires_in_seconds: 60,
        relay_address: None,
        turn: None,
        turn_host: None,
        turn_client: None,
        relay_host_ticket: None,
        relay_client_ticket: None,
    }
}

async fn connected_test_sessions() -> (PeerSession, PeerSession, JoinHandle<()>, LoopbackIceEnv) {
    let loopback = LoopbackIceEnv::enable();
    let (origin, bridge) = websocket_bridge().await;
    let pairing = Arc::new(pairing());
    let (sender_result, receiver_result) = tokio::join!(
        PeerSession::establish_with_ice(
            &origin,
            &pairing,
            Role::Host,
            "127.0.0.1:0".parse::<SocketAddr>().expect("host bind"),
            &[],
        ),
        PeerSession::establish_with_ice(
            &origin,
            &pairing,
            Role::Client,
            "127.0.0.1:0".parse::<SocketAddr>().expect("client bind"),
            &[],
        ),
    );
    (
        sender_result.expect("establish sender"),
        receiver_result.expect("establish receiver"),
        bridge,
        loopback,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_video_waits_for_explicit_flush() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.queue(Kind::Video, 0, 0, b"frame").unwrap();
    assert_eq!(sender.stats().sent_packets, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err()
    );

    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_waits_for_its_own_identical_paced_video_item() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;
    let frame = vec![0; MAX_PLAINTEXT];

    sender.set_wire_pacing_rate(1.0).unwrap();
    sender.queue(Kind::Video, 0, 0, &frame).unwrap();
    sender.send(Kind::Video, 0, 0, &frame).await.unwrap();

    assert_eq!(sender.outbound_pending(), 0);
    assert_eq!(receiver.recv().await.unwrap().payload, frame);
    assert_eq!(receiver.recv().await.unwrap().payload, frame);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn critical_control_is_served_before_paced_video() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.set_wire_pacing_rate(1.0).unwrap();
    sender.queue(Kind::Video, 0, 0, b"video").unwrap();
    sender.queue(Kind::Control, 0, 0, b"control").unwrap();
    sender.flush_outbound().await.unwrap();

    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Control);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_ack_is_intercepted_and_ack_of_ack_is_suppressed() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.queue(Kind::Video, 0, 0, b"frame-1").unwrap();
    sender.queue(Kind::Video, 0, 0, b"frame-2").unwrap();
    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);

    assert!(sender.recv_step().await.unwrap().is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv_step())
            .await
            .is_err()
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_video_packet_gets_a_delayed_transport_ack() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.queue(Kind::Video, 0, 0, b"frame").unwrap();
    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);

    let (receiver_result, sender_result) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv_step()),
        tokio::time::timeout(Duration::from_millis(50), sender.recv_step()),
    );
    assert!(matches!(receiver_result, Ok(Ok(None))));
    assert!(matches!(sender_result, Ok(Ok(None))));
    assert!(
        sender
            .transport_delivery_snapshot(std::time::Instant::now())
            .video
            .acknowledged_bytes
            > 0
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_video_appears_in_the_delivery_snapshot() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.queue(Kind::Video, 0, 0, b"frame-1").unwrap();
    sender.queue(Kind::Video, 0, 0, b"frame-2").unwrap();
    sender.flush_outbound().await.unwrap();
    receiver.recv().await.unwrap();
    receiver.recv().await.unwrap();
    sender.recv_step().await.unwrap();

    let snapshot = sender.transport_delivery_snapshot(std::time::Instant::now());
    assert!(snapshot.video.acknowledged_bytes > 0);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[allow(dead_code)]
fn cipher_is_not_a_scheduler_escape_hatch() {
    let _ = CipherSession::new([0; 32], [0; 32]);
}
