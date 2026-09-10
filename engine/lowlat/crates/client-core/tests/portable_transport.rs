use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use openstream_client_core::{
    Capabilities, DeliveryClassSnapshot, FlushOutcome, MigrationTarget, Pairing,
    PeerDeliverySnapshot, PeerSession, ReliableControl, Role,
};
use openstream_media::{AdaptiveBitrate, FrameAck, PeerTelemetryAdapter};
use openstream_protocol::{Kind, MAX_DATAGRAM, MAX_PLAINTEXT, Session as CipherSession, relay};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
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

const TEST_RELAY_HOST_TICKET: &str = "host-relay-ticket";
const TEST_RELAY_CLIENT_TICKET: &str = "client-relay-ticket";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayDirection {
    HostToClient,
    ClientToHost,
}

impl RelayDirection {
    fn index(self) -> usize {
        match self {
            Self::HostToClient => 0,
            Self::ClientToHost => 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RelayAction {
    DropTransportAck,
    DelayTransportAck(Duration),
    DuplicateTransportAck,
    HoldTransportAck,
    ReorderVideo { following: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RelayStats {
    host_to_client: usize,
    client_to_host: usize,
    transport_ack_host_to_client: usize,
    transport_ack_client_to_host: usize,
    video_host_to_client: usize,
    video_client_to_host: usize,
    dropped: usize,
    delayed: usize,
    duplicated: usize,
    held: usize,
    reordered: usize,
}

enum RelayCommand {
    Action {
        direction: RelayDirection,
        action: RelayAction,
        complete: oneshot::Sender<()>,
    },
    ReleaseHeld {
        direction: RelayDirection,
        complete: oneshot::Sender<bool>,
    },
    Quiesce {
        complete: oneshot::Sender<()>,
    },
    Shutdown {
        complete: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
struct RelayDatagram {
    destination: SocketAddr,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct RelayDirectionState {
    action: VecDeque<RelayAction>,
    held: Option<RelayDatagram>,
    reorder_remaining: usize,
}

struct RelayTask(Option<JoinHandle<()>>);

impl Drop for RelayTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

struct ControllableRelay {
    address: SocketAddr,
    commands: mpsc::Sender<RelayCommand>,
    stats: Arc<Mutex<RelayStats>>,
    task: RelayTask,
}

impl ControllableRelay {
    async fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind controllable loopback relay");
        let address = socket.local_addr().expect("controllable relay address");
        let (commands, command_rx) = mpsc::channel(16);
        let stats = Arc::new(Mutex::new(RelayStats::default()));
        let task = tokio::spawn(run_controllable_relay(
            socket,
            command_rx,
            Arc::clone(&stats),
        ));
        Self {
            address,
            commands,
            stats,
            task: RelayTask(Some(task)),
        }
    }

    fn pairing(&self) -> Pairing {
        let mut pairing = pairing();
        pairing.relay_address = Some(self.address.to_string());
        pairing.relay_host_ticket = Some(TEST_RELAY_HOST_TICKET.into());
        pairing.relay_client_ticket = Some(TEST_RELAY_CLIENT_TICKET.into());
        pairing
    }

    fn stats(&self) -> RelayStats {
        *self.stats.lock().expect("relay stats lock")
    }

    async fn install_action(&self, direction: RelayDirection, action: RelayAction) {
        let (complete, result) = oneshot::channel();
        self.commands
            .send(RelayCommand::Action {
                direction,
                action,
                complete,
            })
            .await
            .expect("controllable relay accepts action");
        result.await.expect("controllable relay installs action");
    }

    async fn drop_next(&self, direction: RelayDirection) {
        self.install_action(direction, RelayAction::DropTransportAck)
            .await;
    }

    async fn delay_next(&self, direction: RelayDirection, delay: Duration) {
        self.install_action(direction, RelayAction::DelayTransportAck(delay))
            .await;
    }

    async fn duplicate_next(&self, direction: RelayDirection) {
        self.install_action(direction, RelayAction::DuplicateTransportAck)
            .await;
    }

    async fn hold_next(&self, direction: RelayDirection) {
        self.install_action(direction, RelayAction::HoldTransportAck)
            .await;
    }

    async fn reorder_next(&self, direction: RelayDirection, following: usize) {
        self.install_action(direction, RelayAction::ReorderVideo { following })
            .await;
    }

    async fn release_held(&self, direction: RelayDirection) {
        let (complete, result) = oneshot::channel();
        self.commands
            .send(RelayCommand::ReleaseHeld {
                direction,
                complete,
            })
            .await
            .expect("controllable relay accepts release");
        assert!(
            result
                .await
                .expect("controllable relay releases held packet"),
            "controllable relay has no held packet"
        );
    }

    async fn quiesce(&self) {
        let (complete, result) = oneshot::channel();
        self.commands
            .send(RelayCommand::Quiesce { complete })
            .await
            .expect("controllable relay accepts quiesce");
        result.await.expect("controllable relay becomes quiescent");
    }

    async fn wait_for<F>(&self, label: &str, predicate: F) -> RelayStats
    where
        F: Fn(RelayStats) -> bool,
    {
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            let stats = self.stats();
            if predicate(stats) {
                return stats;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for relay {label}: {stats:?}"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn stop(mut self) {
        let (complete, result) = oneshot::channel();
        if self
            .commands
            .send(RelayCommand::Shutdown { complete })
            .await
            .is_ok()
        {
            let _ = result.await;
        }
        if let Some(task) = self.task.0.take() {
            let _ = task.await;
        }
    }
}

async fn connected_relay_test_sessions()
-> (PeerSession, PeerSession, ControllableRelay, JoinHandle<()>) {
    let relay = ControllableRelay::new().await;
    let force_relay = ForceRelayEnv::enable().await;
    let (origin, bridge) = websocket_bridge().await;
    let pairing = Arc::new(relay.pairing());
    let (sender_result, receiver_result) = tokio::join!(
        PeerSession::establish_with_stun(
            &origin,
            &pairing,
            Role::Host,
            "127.0.0.1:0".parse::<SocketAddr>().expect("host bind"),
            &[],
        ),
        PeerSession::establish_with_stun(
            &origin,
            &pairing,
            Role::Client,
            "127.0.0.1:0".parse::<SocketAddr>().expect("client bind"),
            &[],
        ),
    );
    drop(force_relay);
    relay.quiesce().await;
    let sender = sender_result.expect("establish relay sender");
    let receiver = receiver_result.expect("establish relay receiver");
    assert!(matches!(
        sender.connection_path(),
        openstream_client_core::ConnectionPath::DirectUdp {
            candidate: openstream_client_core::CandidateKind::Relay
        }
    ));
    assert!(matches!(
        receiver.connection_path(),
        openstream_client_core::ConnectionPath::DirectUdp {
            candidate: openstream_client_core::CandidateKind::Relay
        }
    ));
    (sender, receiver, relay, bridge)
}

struct ForceRelayEnv {
    previous: Option<String>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl ForceRelayEnv {
    async fn enable() -> Self {
        static ENV_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
        let guard = ENV_LOCK
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let previous = std::env::var("OPENSTREAM_FORCE_RELAY").ok();
        unsafe { std::env::set_var("OPENSTREAM_FORCE_RELAY", "1") };
        Self {
            previous,
            _guard: guard,
        }
    }
}

impl Drop for ForceRelayEnv {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe { std::env::set_var("OPENSTREAM_FORCE_RELAY", value) },
            None => unsafe { std::env::remove_var("OPENSTREAM_FORCE_RELAY") },
        }
    }
}

struct DelayedRelayDatagram {
    due: tokio::time::Instant,
    direction: RelayDirection,
    datagram: RelayDatagram,
}

async fn run_controllable_relay(
    socket: UdpSocket,
    mut commands: mpsc::Receiver<RelayCommand>,
    stats: Arc<Mutex<RelayStats>>,
) {
    let mut slots = [None, None];
    let mut directions = [
        RelayDirectionState::default(),
        RelayDirectionState::default(),
    ];
    let mut delayed: Vec<DelayedRelayDatagram> = Vec::new();
    let mut buffer = [0_u8; MAX_DATAGRAM + 256];

    loop {
        let next_delay = async {
            if let Some(due) = delayed.iter().map(|packet| packet.due).min() {
                tokio::time::sleep_until(due).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(RelayCommand::Action { direction, action, complete }) => {
                        directions[direction.index()].action.push_back(action);
                        let _ = complete.send(());
                    }
                    Some(RelayCommand::ReleaseHeld { direction, complete }) => {
                        let state = &mut directions[direction.index()];
                        let held = state.held.take();
                        if let Some(held) = held {
                            forward_datagram(&socket, &stats, direction, held).await;
                            let _ = complete.send(true);
                        } else {
                            let _ = complete.send(false);
                        }
                    }
                    Some(RelayCommand::Quiesce { complete }) => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        drain_quiescent_datagrams(&socket, &mut slots, &stats, &mut buffer).await;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        drain_quiescent_datagrams(&socket, &mut slots, &stats, &mut buffer).await;
                        let _ = complete.send(());
                    }
                    Some(RelayCommand::Shutdown { complete }) => {
                        let _ = complete.send(());
                        break;
                    }
                    None => break,
                }
            }
            result = socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = result else { break };
                let bytes = &buffer[..length];
                if let Ok(registration) = relay::decode_registration(bytes) {
                    handle_registration(&socket, &mut slots, source, registration).await;
                    continue;
                }
                if let Ok(unregister) = relay::decode_unregister(bytes) {
                    handle_unregister(&socket, &mut slots, source, unregister).await;
                    continue;
                }
                let Some(source_index) = slots.iter().position(|slot| *slot == Some(source)) else {
                    continue;
                };
                let Some(destination) = slots[1 - source_index] else {
                    continue;
                };
                let direction = if source_index == 0 {
                    RelayDirection::HostToClient
                } else {
                    RelayDirection::ClientToHost
                };
                let datagram = RelayDatagram {
                    destination,
                    bytes: bytes.to_vec(),
                };
                apply_relay_action(
                    &socket,
                    &stats,
                    &mut directions[direction.index()],
                    &mut delayed,
                    direction,
                    datagram,
                ).await;
            }
            () = next_delay, if !delayed.is_empty() => {
                flush_delayed(&socket, &stats, &mut delayed).await;
            }
        }
    }
}

async fn drain_quiescent_datagrams(
    socket: &UdpSocket,
    slots: &mut [Option<SocketAddr>; 2],
    stats: &Arc<Mutex<RelayStats>>,
    buffer: &mut [u8; MAX_DATAGRAM + 256],
) {
    loop {
        let Ok((length, source)) = socket.try_recv_from(buffer) else {
            break;
        };
        let bytes = buffer[..length].to_vec();
        if let Ok(registration) = relay::decode_registration(&bytes) {
            handle_registration(socket, slots, source, registration).await;
            continue;
        }
        if let Ok(unregister) = relay::decode_unregister(&bytes) {
            handle_unregister(socket, slots, source, unregister).await;
            continue;
        }
        let Some(source_index) = slots.iter().position(|slot| *slot == Some(source)) else {
            continue;
        };
        let Some(destination) = slots[1 - source_index] else {
            continue;
        };
        let direction = if source_index == 0 {
            RelayDirection::HostToClient
        } else {
            RelayDirection::ClientToHost
        };
        forward_datagram(
            socket,
            stats,
            direction,
            RelayDatagram { destination, bytes },
        )
        .await;
    }
}

async fn handle_registration(
    socket: &UdpSocket,
    slots: &mut [Option<SocketAddr>; 2],
    source: SocketAddr,
    registration: relay::Registration<'_>,
) {
    if registration.session_id != pairing_session_id()
        || registration.token != relay_ticket(registration.role)
    {
        return;
    }
    let index = match registration.role {
        relay::Role::Host => 0,
        relay::Role::Client => 1,
    };
    slots[index] = Some(source);
    let _ = socket
        .send_to(&relay::encode_ack(registration.role), source)
        .await;
}

async fn handle_unregister(
    socket: &UdpSocket,
    slots: &mut [Option<SocketAddr>; 2],
    source: SocketAddr,
    unregister: relay::Registration<'_>,
) {
    if unregister.session_id != pairing_session_id()
        || unregister.token != relay_ticket(unregister.role)
    {
        return;
    }
    let index = match unregister.role {
        relay::Role::Host => 0,
        relay::Role::Client => 1,
    };
    if slots[index] == Some(source) {
        slots[index] = None;
    }
    let _ = socket
        .send_to(&relay::encode_unregister_ack(unregister.role), source)
        .await;
}

fn pairing_session_id() -> &'static str {
    "portable-transport-test"
}

fn relay_ticket(role: relay::Role) -> &'static str {
    match role {
        relay::Role::Host => TEST_RELAY_HOST_TICKET,
        relay::Role::Client => TEST_RELAY_CLIENT_TICKET,
    }
}

async fn apply_relay_action(
    socket: &UdpSocket,
    stats: &Arc<Mutex<RelayStats>>,
    state: &mut RelayDirectionState,
    delayed: &mut Vec<DelayedRelayDatagram>,
    direction: RelayDirection,
    datagram: RelayDatagram,
) {
    if state.reorder_remaining > 0 {
        forward_datagram(socket, stats, direction, datagram).await;
        state.reorder_remaining -= 1;
        if state.reorder_remaining == 0 {
            if let Some(held) = state.held.take() {
                forward_datagram(socket, stats, direction, held).await;
            }
        }
        return;
    }

    let Some(action_index) = state
        .action
        .iter()
        .position(|action| action_matches(*action, &datagram.bytes))
    else {
        forward_datagram(socket, stats, direction, datagram).await;
        return;
    };
    let action = state
        .action
        .remove(action_index)
        .expect("matching relay action remains queued");
    match action {
        RelayAction::DropTransportAck => {
            stats.lock().expect("relay stats lock").dropped += 1;
        }
        RelayAction::DelayTransportAck(delay) => {
            stats.lock().expect("relay stats lock").delayed += 1;
            delayed.push(DelayedRelayDatagram {
                due: tokio::time::Instant::now() + delay,
                direction,
                datagram,
            });
        }
        RelayAction::DuplicateTransportAck => {
            stats.lock().expect("relay stats lock").duplicated += 1;
            let RelayDatagram { destination, bytes } = datagram;
            let first = RelayDatagram {
                destination,
                bytes: bytes.clone(),
            };
            let second = RelayDatagram { destination, bytes };
            forward_datagram(socket, stats, direction, first).await;
            forward_datagram(socket, stats, direction, second).await;
        }
        RelayAction::HoldTransportAck => {
            stats.lock().expect("relay stats lock").held += 1;
            state.held = Some(datagram);
        }
        RelayAction::ReorderVideo { following } if following == 0 => {
            forward_datagram(socket, stats, direction, datagram).await;
        }
        RelayAction::ReorderVideo { following } => {
            stats.lock().expect("relay stats lock").reordered += 1;
            stats.lock().expect("relay stats lock").held += 1;
            state.held = Some(datagram);
            state.reorder_remaining = following;
        }
    }
}

fn action_matches(action: RelayAction, bytes: &[u8]) -> bool {
    match action {
        RelayAction::DropTransportAck
        | RelayAction::DelayTransportAck(_)
        | RelayAction::DuplicateTransportAck
        | RelayAction::HoldTransportAck => is_transport_ack_datagram(bytes),
        RelayAction::ReorderVideo { .. } => is_video_datagram(bytes),
    }
}

fn is_transport_ack_datagram(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[3] == Kind::Control as u8 && bytes[4] == 254
}

fn is_video_datagram(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[3] == Kind::Video as u8
}

async fn flush_delayed(
    socket: &UdpSocket,
    stats: &Arc<Mutex<RelayStats>>,
    delayed: &mut Vec<DelayedRelayDatagram>,
) {
    let now = tokio::time::Instant::now();
    let mut ready = Vec::new();
    let mut waiting = Vec::with_capacity(delayed.len());
    for packet in delayed.drain(..) {
        if packet.due <= now {
            ready.push(packet);
        } else {
            waiting.push(packet);
        }
    }
    *delayed = waiting;
    for packet in ready {
        forward_datagram(socket, stats, packet.direction, packet.datagram).await;
    }
}

async fn forward_datagram(
    socket: &UdpSocket,
    stats: &Arc<Mutex<RelayStats>>,
    direction: RelayDirection,
    datagram: RelayDatagram,
) {
    if socket
        .send_to(&datagram.bytes, datagram.destination)
        .await
        .is_err()
    {
        return;
    }
    let mut stats = stats.lock().expect("relay stats lock");
    match direction {
        RelayDirection::HostToClient => stats.host_to_client += 1,
        RelayDirection::ClientToHost => stats.client_to_host += 1,
    }
    if is_transport_ack_datagram(&datagram.bytes) {
        match direction {
            RelayDirection::HostToClient => stats.transport_ack_host_to_client += 1,
            RelayDirection::ClientToHost => stats.transport_ack_client_to_host += 1,
        }
    }
    if is_video_datagram(&datagram.bytes) {
        match direction {
            RelayDirection::HostToClient => stats.video_host_to_client += 1,
            RelayDirection::ClientToHost => stats.video_client_to_host += 1,
        }
    }
}

#[test]
fn no_immediate_media_bypass_source_check() {
    let client_core_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    let allowed_client_core_file = client_core_manifest
        .join("src/lib.rs")
        .canonicalize()
        .expect("canonicalize allowlisted client-core internals");

    for (crate_name, root) in portable_source_roots(client_core_manifest) {
        let root = root
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize {crate_name} source root: {error}"));
        let source_paths = rust_source_paths(&root)
            .unwrap_or_else(|error| panic!("read {crate_name} source tree: {error}"));
        assert!(
            !source_paths.is_empty(),
            "{crate_name} source root contains no Rust files: {}",
            root.display()
        );
        for path in source_paths {
            let source = fs::read_to_string(&path).expect("read portable consumer source");
            if crate_name == "client-core" && path == allowed_client_core_file {
                continue;
            }
            let relative_path = path.strip_prefix(&root).unwrap_or(&path).display();
            for label in forbidden_send_calls(&source) {
                violations.push(format!("{crate_name}:{relative_path}: {label}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "portable outbound paths bypass the packet scheduler: {}",
        violations.join(", ")
    );
}

#[test]
fn no_bypass_source_scan_ignores_comments_and_literals() {
    let source = r###"
        // session.send(Kind::Video, 0, 0, payload)
        const TEXT: &str = "send_immediate_on(";
        let comment = r##"write_sealed_on("##;
    "###;

    assert!(forbidden_send_calls(source).is_empty());
}

#[test]
fn no_bypass_source_scan_reports_actual_send_calls() {
    let source = "session.send(Kind::Video, 0, 0, payload); self.send_immediate_on(payload);";

    assert_eq!(
        forbidden_send_calls(source),
        vec!["private immediate send", "direct high-rate video send"]
    );
}

const PORTABLE_CONSUMER_CRATES: &[&str] =
    &["ffmpeg-host", "reference-peer", "client", "desktop-client"];

const FORBIDDEN_SEND_CALLS: &[(&str, &str)] = &[
    ("private immediate send", "send_immediate_on("),
    ("private sealed write", "write_sealed_on("),
    ("private path-control immediate send", "send_path_control("),
    (
        "private transport-ack immediate send",
        "send_transport_ack(",
    ),
    ("private application send", "send_application_with_flag("),
    ("private scheduler flush", "flush_outbound_inner("),
    ("direct high-rate video send", ".send(Kind::Video,"),
    ("direct high-rate audio send", ".send(Kind::Audio,"),
];

fn portable_source_roots(client_core_manifest: &Path) -> Vec<(&'static str, PathBuf)> {
    let lowlat_root = client_core_manifest
        .parent()
        .expect("client-core manifest is nested under the lowlat workspace");
    let mut roots = vec![("client-core", client_core_manifest.join("src"))];
    roots.extend(
        PORTABLE_CONSUMER_CRATES
            .iter()
            .map(|crate_name| (*crate_name, lowlat_root.join(crate_name).join("src"))),
    );
    roots
}

fn forbidden_send_calls(source: &str) -> Vec<&'static str> {
    let compact_source = compact_rust_code(source);
    FORBIDDEN_SEND_CALLS
        .iter()
        .filter_map(|(label, needle)| compact_source.contains(needle).then_some(*label))
        .collect()
}

fn compact_rust_code(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut code = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            if index < bytes.len() {
                code.push('\n');
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = skip_block_comment(bytes, index, &mut code);
        } else if let Some(end) = raw_string_end(bytes, index) {
            code.push(' ');
            index = end;
        } else if bytes[index] == b'"' {
            code.push(' ');
            index = quoted_literal_end(bytes, index);
        } else if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"') {
            code.push(' ');
            index = quoted_literal_end(bytes, index + 1);
        } else if bytes[index] == b'\'' {
            if let Some(end) = char_literal_end(bytes, index) {
                code.push(' ');
                index = end;
            } else {
                code.push(char::from(bytes[index]));
                index += 1;
            }
        } else {
            code.push(char::from(bytes[index]));
            index += 1;
        }
    }
    code.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn skip_block_comment(bytes: &[u8], mut index: usize, code: &mut String) -> usize {
    let mut depth = 1;
    index += 2;
    while index < bytes.len() && depth > 0 {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
        } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth -= 1;
            index += 2;
        } else {
            if bytes[index] == b'\n' {
                code.push('\n');
            }
            index += 1;
        }
    }
    code.push(' ');
    index
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let raw_start = if bytes.get(index) == Some(&b'r') {
        index
    } else if bytes.get(index) == Some(&b'b') && bytes.get(index + 1) == Some(&b'r') {
        index + 1
    } else {
        return None;
    };
    let mut delimiter = raw_start + 1;
    let mut hashes = 0;
    while bytes.get(delimiter) == Some(&b'#') {
        hashes += 1;
        delimiter += 1;
    }
    if bytes.get(delimiter) != Some(&b'"') {
        return None;
    }
    let content_start = delimiter + 1;
    let mut cursor = content_start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && (0..hashes).all(|offset| bytes.get(cursor + 1 + offset) == Some(&b'#'))
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn quoted_literal_end(bytes: &[u8], quote: usize) -> usize {
    let mut index = quote + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = index.saturating_add(2);
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn char_literal_end(bytes: &[u8], quote: usize) -> Option<usize> {
    let mut index = quote + 1;
    if bytes.get(index) == Some(&b'\\') {
        index = index.checked_add(2)?;
    } else if bytes.get(index).is_some_and(|byte| *byte != b'\n') {
        index += 1;
    } else {
        return None;
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

fn rust_source_paths(root: &Path) -> io::Result<Vec<PathBuf>> {
    fn visit(root: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                visit(&path, paths)?;
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                paths.push(path);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    visit(root, &mut paths)?;
    paths.sort();
    Ok(paths)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_backpressure_keeps_receive_path_alive() {
    let (mut sender, mut receiver, bridge, _loopback) = connected_test_sessions().await;
    sender.set_wire_pacing_rate(0.0).unwrap();

    // Fill every delivery-history slot without letting the receiver process
    // the packets and return transport ACKs.
    for _ in 0..256 {
        sender.queue(Kind::Control, 0, 0, b"history").unwrap();
    }
    let report = sender.flush_outbound().await.unwrap();
    assert_eq!(report.sent_packets, 256);
    assert_eq!(sender.outbound_pending(), 0);

    sender.queue(Kind::Video, 0, 0, b"retained").unwrap();
    assert_eq!(
        sender.flush_outbound_recoverably().await.unwrap(),
        FlushOutcome::Backpressured
    );
    assert_eq!(sender.outbound_pending(), 1);

    for _ in 0..256 {
        assert_eq!(receiver.recv().await.unwrap().kind, Kind::Control);
    }

    for _ in 0..256 {
        if sender
            .transport_delivery_snapshot(Instant::now())
            .aggregate
            .in_flight
            == 0
        {
            break;
        }
        tokio::time::timeout(Duration::from_millis(100), sender.recv_step())
            .await
            .expect("sender receives a transport ACK")
            .expect("transport ACK is valid");
    }
    assert_eq!(
        sender
            .transport_delivery_snapshot(Instant::now())
            .aggregate
            .in_flight,
        0
    );

    assert!(matches!(
        sender.flush_outbound_recoverably().await.unwrap(),
        FlushOutcome::Flushed(report) if report.sent_packets == 1 && report.pending_packets == 0
    ));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_relay_drops_first_ack_and_delays_timer_recovery() {
    let (mut sender, mut receiver, relay, bridge) = connected_relay_test_sessions().await;
    sender.set_wire_pacing_rate(0.0).unwrap();
    let baseline = relay.stats();

    relay.drop_next(RelayDirection::ClientToHost).await;
    sender.queue(Kind::Video, 0, 0, b"first").unwrap();
    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);
    assert_eq!(
        sender
            .transport_delivery_snapshot(Instant::now())
            .video
            .in_flight,
        1
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    tokio::time::timeout(Duration::from_millis(100), receiver.recv_step())
        .await
        .expect("first ACK timer fires")
        .expect("first ACK timer remains healthy");
    relay
        .wait_for("dropped ACK", |stats| stats.dropped >= 1)
        .await;
    assert_eq!(
        sender
            .transport_delivery_snapshot(Instant::now())
            .video
            .in_flight,
        1,
        "dropped feedback leaves the packet outstanding"
    );

    relay
        .delay_next(RelayDirection::ClientToHost, Duration::from_millis(5))
        .await;
    sender.queue(Kind::Video, 0, 0, b"second").unwrap();
    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);
    tokio::time::sleep(Duration::from_millis(5)).await;
    tokio::time::timeout(Duration::from_millis(100), receiver.recv_step())
        .await
        .expect("recovery ACK timer fires")
        .expect("recovery ACK timer remains healthy");
    for _ in 0..16 {
        if sender
            .transport_delivery_snapshot(Instant::now())
            .video
            .acknowledged_packets
            == 2
        {
            break;
        }
        tokio::time::timeout(Duration::from_millis(100), sender.recv_step())
            .await
            .expect("delayed recovery ACK arrives")
            .expect("delayed recovery ACK is authenticated");
    }

    let snapshot = sender.transport_delivery_snapshot(Instant::now());
    assert_eq!(snapshot.video.acknowledged_packets, 2);
    assert_eq!(snapshot.video.in_flight, 0);
    let stats = relay
        .wait_for("delayed recovery ACK", |stats| {
            stats.delayed >= 1
                && stats.transport_ack_client_to_host >= baseline.transport_ack_client_to_host + 1
        })
        .await;
    assert_eq!(stats.dropped - baseline.dropped, 1);
    assert_eq!(stats.delayed - baseline.delayed, 1);
    assert_eq!(
        stats.video_host_to_client - baseline.video_host_to_client,
        2,
        "ACK recovery does not create an ACK-of-ACK loop"
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    relay.stop().await;
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_relay_reorders_first_packet_behind_sixty_four_followers() {
    let (mut sender, mut receiver, relay, bridge) = connected_relay_test_sessions().await;
    sender.set_wire_pacing_rate(0.0).unwrap();
    let baseline = relay.stats();

    relay.reorder_next(RelayDirection::HostToClient, 64).await;
    for _ in 0..65 {
        sender.queue(Kind::Video, 0, 0, b"reordered").unwrap();
    }
    let report = sender.flush_outbound().await.unwrap();
    assert_eq!(report.sent_packets, 65);

    let mut counters = Vec::with_capacity(64);
    for _ in 0..64 {
        let packet = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("reordered packet arrives")
            .expect("reordered packet is authenticated");
        counters.push(packet.counter);
    }
    let late = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
        .await
        .expect("late reordered packet reaches the session");
    assert!(matches!(
        late,
        Err(openstream_client_core::Error::Transport(
            openstream_transport::Error::Protocol(openstream_protocol::Error::AuthenticationFailed)
        ))
    ));
    assert!(counters[0] < counters[63]);
    assert_eq!(counters[63] - counters[0], 63);

    for _ in 0..64 {
        if sender
            .transport_delivery_snapshot(Instant::now())
            .aggregate
            .in_flight
            == 1
        {
            break;
        }
        tokio::time::timeout(Duration::from_millis(100), sender.recv_step())
            .await
            .expect("reordering ACK arrives")
            .expect("reordering ACK is authenticated");
    }
    let snapshot = sender.transport_delivery_snapshot(Instant::now());
    assert_eq!(snapshot.aggregate.acknowledged_packets, 64);
    assert_eq!(snapshot.aggregate.in_flight, 1);
    let stats = relay
        .wait_for("reordered video", |stats| {
            stats.video_host_to_client >= baseline.video_host_to_client + 65
        })
        .await;
    assert_eq!(stats.reordered - baseline.reordered, 1);
    assert_eq!(
        stats.video_host_to_client - baseline.video_host_to_client,
        65
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    relay.stop().await;
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_relay_duplicates_ack_without_ack_of_ack() {
    let (mut sender, mut receiver, relay, bridge) = connected_relay_test_sessions().await;
    sender.set_wire_pacing_rate(0.0).unwrap();
    let baseline = relay.stats();

    relay.duplicate_next(RelayDirection::ClientToHost).await;
    sender.queue(Kind::Video, 0, 0, b"duplicate-1").unwrap();
    sender.queue(Kind::Video, 0, 0, b"duplicate-2").unwrap();
    sender.flush_outbound().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);
    assert_eq!(receiver.recv().await.unwrap().kind, Kind::Video);

    let mut replay_rejected = false;
    let mut after_first = sender.transport_delivery_snapshot(Instant::now());
    for _ in 0..32 {
        let result = tokio::time::timeout(Duration::from_millis(100), sender.recv_step())
            .await
            .expect("second duplicate ACK arrives");
        match result {
            Ok(_) => {}
            Err(openstream_client_core::Error::Transport(
                openstream_transport::Error::Protocol(
                    openstream_protocol::Error::AuthenticationFailed,
                ),
            )) => {
                replay_rejected = true;
            }
            Err(error) => panic!("unexpected duplicate-ACK receive error: {error:?}"),
        }
        after_first = sender.transport_delivery_snapshot(Instant::now());
        if replay_rejected && after_first.video.acknowledged_packets == 2 {
            break;
        }
    }
    assert!(
        replay_rejected,
        "cipher rejects the duplicate encrypted ACK"
    );
    let after_second = sender.transport_delivery_snapshot(Instant::now());
    let stats = relay
        .wait_for("duplicated transport ACK", |stats| {
            stats.transport_ack_client_to_host >= baseline.transport_ack_client_to_host + 2
        })
        .await;

    assert_eq!(after_second.video.acknowledged_packets, 2);
    assert_eq!(
        after_second.video.acknowledged_bytes,
        after_first.video.acknowledged_bytes
    );
    assert_eq!(after_second.srtt_ms, after_first.srtt_ms);
    assert_eq!(stats.duplicated - baseline.duplicated, 1);
    assert_eq!(
        stats.transport_ack_client_to_host - baseline.transport_ack_client_to_host,
        2
    );
    assert_eq!(
        stats.transport_ack_host_to_client - baseline.transport_ack_host_to_client,
        0,
        "a transport ACK is not ACK-eliciting"
    );

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    relay.stop().await;
    bridge.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_relay_holds_old_ack_across_migration_and_preserves_frame_feedback() {
    let (mut sender, mut receiver, relay, bridge) = connected_relay_test_sessions().await;
    sender.set_wire_pacing_rate(0.0).unwrap();
    let negotiated = tokio::join!(
        sender.negotiate_host_with_capabilities(Capabilities::host_default().with_path_migration()),
        receiver.negotiate_client_with_capabilities(
            Capabilities::client_default().with_path_migration()
        )
    );
    assert!(negotiated.0.unwrap().path_migration);
    assert!(negotiated.1.unwrap().path_migration);
    assert!(matches!(
        sender.connection_path(),
        openstream_client_core::ConnectionPath::DirectUdp {
            candidate: openstream_client_core::CandidateKind::Relay
        }
    ));
    assert!(matches!(
        receiver.connection_path(),
        openstream_client_core::ConnectionPath::DirectUdp {
            candidate: openstream_client_core::CandidateKind::Relay
        }
    ));

    let initial_generation = sender.path_generation();
    let mut telemetry =
        PeerTelemetryAdapter::new(AdaptiveBitrate::new(10.0, 1.0, 20.0), initial_generation, 0);
    telemetry.frame_sent(41, 1_024, 0);

    relay.hold_next(RelayDirection::ClientToHost).await;
    sender
        .queue(Kind::Video, 0, 0, b"before-migration-1")
        .unwrap();
    sender.flush_outbound().await.unwrap();
    let before = receiver.recv().await.unwrap();
    tokio::time::timeout(Duration::from_millis(100), receiver.recv_step())
        .await
        .expect("old-generation ACK timer fires")
        .expect("old-generation ACK remains authenticated");
    let before_counter = before.counter;
    let held = relay
        .wait_for("held old-generation ACK", |stats| stats.held >= 1)
        .await;
    assert_eq!(held.held, 1);

    let migration = async {
        let host_migration = sender.migrate_to(MigrationTarget::DirectUdp);
        tokio::pin!(host_migration);
        let client_ready = async {
            while receiver.path_generation() == initial_generation {
                receiver.maintain_liveness().await?;
                if receiver.path_generation() != initial_generation {
                    break;
                }
                receiver.recv_step().await?;
            }
            Ok::<(), openstream_client_core::Error>(())
        };
        tokio::pin!(client_ready);
        tokio::select! {
            report = &mut host_migration => {
                let report = report?;
                client_ready.await?;
                Ok::<_, openstream_client_core::Error>(report)
            }
            result = &mut client_ready => {
                result?;
                Ok(host_migration.await?)
            }
        }
    };
    let report = tokio::time::timeout(Duration::from_secs(8), migration)
        .await
        .expect("migration completes without hanging")
        .expect("direct replacement path commits");
    assert_eq!(report.previous_generation, initial_generation);
    assert_eq!(report.active_generation, initial_generation + 1);
    assert_eq!(sender.path_generation(), initial_generation + 1);
    assert_eq!(receiver.path_generation(), initial_generation + 1);

    let reset_snapshot = sender.transport_delivery_snapshot(Instant::now());
    assert_eq!(reset_snapshot.path_generation, initial_generation + 1);
    assert_eq!(reset_snapshot.aggregate.in_flight, 0);
    assert_eq!(reset_snapshot.aggregate.acknowledged_packets, 0);

    relay.release_held(RelayDirection::ClientToHost).await;
    tokio::time::timeout(Duration::from_millis(100), sender.recv_step())
        .await
        .expect("late old-generation ACK reaches the draining path")
        .expect("late old-generation ACK remains authenticated");
    let after_late_ack = sender.transport_delivery_snapshot(Instant::now());
    assert_eq!(after_late_ack.path_generation, initial_generation + 1);
    assert_eq!(after_late_ack.aggregate.in_flight, 0);
    assert_eq!(after_late_ack.aggregate.acknowledged_packets, 0);

    sender.queue(Kind::Input, 1, 0, b"after-migration").unwrap();
    sender.flush_outbound().await.unwrap();
    let after = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
        .await
        .expect("post-migration packet arrives")
        .expect("post-migration packet is authenticated");
    assert!(after.counter > before_counter);

    let path_snapshot = sender.path_snapshot();
    telemetry.observe_path(&path_snapshot, 10);
    assert_eq!(telemetry.pending_frames(), 1);
    let mut client_control = ReliableControl::new(4);
    let mut host_control = ReliableControl::new(4);
    let frame_ack = FrameAck {
        frame_id: 41,
        lost_frames: 0,
    }
    .encode();
    client_control
        .send(&mut receiver, &frame_ack)
        .await
        .expect("post-migration FrameAck sends");
    let packet = tokio::time::timeout(Duration::from_millis(100), sender.recv())
        .await
        .expect("post-migration FrameAck arrives")
        .expect("post-migration FrameAck outer packet authenticates");
    let delivered = host_control
        .receive(&mut sender, &packet)
        .await
        .expect("reliable control packet is valid")
        .expect("FrameAck uses reliable control")
        .into_iter()
        .next()
        .expect("FrameAck is delivered once");
    assert_eq!(delivered, frame_ack);
    assert!(telemetry.accept_frame_ack_payload(&delivered, 20));
    assert_eq!(telemetry.pending_frames(), 0);

    while client_control.outstanding() != 0 {
        let packet = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("FrameAck reliable acknowledgement arrives")
            .expect("FrameAck reliable acknowledgement authenticates");
        let _ = client_control
            .receive(&mut receiver, &packet)
            .await
            .expect("FrameAck reliable acknowledgement is valid");
    }

    sender.close().await.unwrap();
    receiver.close().await.unwrap();
    relay.stop().await;
    bridge.abort();
}

#[allow(dead_code)]
fn cipher_is_not_a_scheduler_escape_hatch() {
    let _ = CipherSession::new([0; 32], [0; 32]);
}
