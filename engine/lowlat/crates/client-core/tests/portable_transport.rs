use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use openstream_client_core::{
    DeliveryClassSnapshot, Pairing, PeerDeliverySnapshot, PeerSession, Role,
};
use openstream_media::{AdaptiveBitrate, PeerTelemetryAdapter};
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

fn delivery_class() -> DeliveryClassSnapshot {
    DeliveryClassSnapshot {
        sent_packets: 0,
        sent_bytes: 0,
        acknowledged_packets: 0,
        acknowledged_bytes: 0,
        delivery_rate_mbps: None,
        in_flight: 0,
        stale: 0,
        logical_reliable_retries: 0,
        outer_retransmissions: 0,
    }
}

fn delivery_snapshot(generation: u64) -> PeerDeliverySnapshot {
    PeerDeliverySnapshot {
        path_generation: generation,
        sample_interval_ms: 0.0,
        srtt_ms: None,
        aggregate: delivery_class(),
        video: delivery_class(),
        audio: delivery_class(),
        critical: delivery_class(),
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

#[test]
fn no_immediate_media_bypass_source_check() {
    let client_core_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let portable_source_roots = [
        (
            "ffmpeg-host",
            client_core_manifest.join("../ffmpeg-host/src"),
        ),
        (
            "reference-peer",
            client_core_manifest.join("../reference-peer/src"),
        ),
        ("client", client_core_manifest.join("../client/src")),
        (
            "desktop-client",
            client_core_manifest.join("../desktop-client/src"),
        ),
    ];
    let forbidden = [
        ("private immediate send", "send_immediate_on("),
        ("raw sealed write", "write_sealed_on("),
        ("raw sealed send", "send_sealed_on("),
        ("raw datagram send", "send_datagram("),
        ("direct high-rate video send", "session.send(Kind::Video"),
        ("direct high-rate audio send", "session.send(Kind::Audio"),
    ];
    let mut violations = Vec::new();

    for (crate_name, root) in portable_source_roots {
        for path in rust_source_paths(&root) {
            let source = fs::read_to_string(&path).expect("read portable consumer source");
            let compact_source: String = source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            let relative_path = path
                .strip_prefix(client_core_manifest)
                .unwrap_or(&path)
                .display();
            for (label, needle) in forbidden {
                if compact_source.contains(needle) {
                    let location = source.lines().enumerate().find_map(|(line_number, line)| {
                        line.contains(needle).then_some(line_number + 1)
                    });
                    match location {
                        Some(line_number) => violations.push(format!(
                            "{crate_name}:{relative_path}:{line_number}: {label}"
                        )),
                        None => violations.push(format!("{crate_name}:{relative_path}: {label}")),
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "portable outbound paths bypass the packet scheduler: {}",
        violations.join(", ")
    );
}

fn rust_source_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).expect("read portable consumer source directory") {
        let entry = entry.expect("read portable consumer source entry");
        let path = entry.path();
        if path.is_dir() {
            paths.extend(rust_source_paths(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_immediate_media_bypass_behavior() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;
    let frame = vec![0; MAX_PLAINTEXT];

    sender.set_wire_pacing_rate(1.0).unwrap();
    for _ in 0..5 {
        sender.queue(Kind::Video, 0, 0, &frame).unwrap();
    }

    assert_eq!(sender.stats().sent_packets, 0);
    assert_eq!(sender.outbound_pending(), 5);
    assert!(sender.next_outbound_wake().is_some());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err()
    );

    let report = sender.flush_outbound().await.unwrap();
    assert_eq!(report.sent_packets, 1);
    assert_eq!(report.pending_packets, 4);
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[test]
fn public_delivery_snapshot_is_serde_safe_and_has_no_socket_metadata() {
    let snapshot = delivery_snapshot(7);
    let encoded = serde_json::to_string(&snapshot).expect("serialize delivery snapshot");

    assert!(encoded.contains("\"path_generation\":7"));
    assert!(!encoded.contains("127.0.0.1"));
    assert!(!encoded.contains("credential"));
    assert_eq!(snapshot.video.delivery_rate_mbps, None);
}

#[test]
fn packet_delivery_observation_is_diagnostics_only_for_adaptive_bitrate() {
    let mut with_delivery = PeerTelemetryAdapter::new(AdaptiveBitrate::new(10.0, 1.0, 20.0), 1, 0);
    let mut without_delivery =
        PeerTelemetryAdapter::new(AdaptiveBitrate::new(10.0, 1.0, 20.0), 1, 0);
    for frame_id in 0..8 {
        with_delivery.frame_sent(frame_id, 1_024, 0);
        without_delivery.frame_sent(frame_id, 1_024, 0);
    }

    let delivery = delivery_snapshot(1);
    with_delivery.observe_delivery(&delivery);

    assert_eq!(
        with_delivery
            .latest_delivery_snapshot()
            .map(|snapshot| snapshot.path_generation),
        Some(delivery.path_generation)
    );
    assert_eq!(with_delivery.tick(500), without_delivery.tick(500));
    assert_eq!(
        with_delivery.bitrate_mbps().to_bits(),
        without_delivery.bitrate_mbps().to_bits()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_snapshot_keeps_aggregate_and_class_evidence_distinct() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.set_wire_pacing_rate(0.0).unwrap();
    sender.queue(Kind::Video, 0, 0, b"video").unwrap();
    sender.queue(Kind::Audio, 0, 0, b"audio").unwrap();
    sender.flush_outbound().await.unwrap();
    receiver.recv().await.unwrap();
    receiver.recv().await.unwrap();
    sender.recv_step().await.unwrap();

    let snapshot = sender.transport_delivery_snapshot(std::time::Instant::now());
    assert_eq!(snapshot.aggregate.acknowledged_packets, 2);
    assert_eq!(snapshot.video.acknowledged_packets, 1);
    assert_eq!(snapshot.audio.acknowledged_packets, 1);
    assert_eq!(snapshot.critical.acknowledged_packets, 0);
    assert_eq!(
        snapshot.aggregate.acknowledged_bytes,
        snapshot.video.acknowledged_bytes + snapshot.audio.acknowledged_bytes
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_snapshot_does_not_fabricate_acknowledgement_from_local_writes() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;

    sender.set_wire_pacing_rate(0.0).unwrap();
    sender
        .send(Kind::Video, 0, 0, b"locally-written")
        .await
        .unwrap();

    let snapshot = sender.transport_delivery_snapshot(std::time::Instant::now());
    assert_eq!(snapshot.aggregate.acknowledged_packets, 0);
    assert_eq!(snapshot.aggregate.delivery_rate_mbps, None);
    assert_eq!(snapshot.video.delivery_rate_mbps, None);
    assert!(snapshot.aggregate.sent_packets > 0);

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    bridge.abort();
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
