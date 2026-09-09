use openstream_media::{AdaptiveBitrate, FrameAck, PeerTelemetryAdapter};
use openstream_protocol::{Kind, Session, control::Frame as ControlFrame};
use openstream_transport::{
    FIRST_PATH_GENERATION, PathMtuState, PathState, PeerTransportSnapshot, TransportPathKind,
    TransportSample,
};

fn snapshot(generation: u64) -> PeerTransportSnapshot {
    PeerTransportSnapshot {
        path: TransportPathKind::DirectUdp,
        path_generation: generation,
        state: PathState::Active,
        path_age_ms: 10,
        datagram_size: Some(1200),
        path_mtu_state: PathMtuState::Unavailable,
        sample: Some(TransportSample {
            path_generation: generation,
            sent_packets: 1,
            sent_wire_bytes: 1_000,
            received_packets: 1,
            received_wire_bytes: 1_000,
            sample_interval_ms: 100,
            send_rate_mbps: 1.0,
            receive_rate_mbps: 1.0,
        }),
    }
}

#[test]
fn frame_ack_sent_before_migration_is_accepted_after_migration() {
    let mut telemetry = PeerTelemetryAdapter::new(
        AdaptiveBitrate::new(10.0, 1.0, 20.0),
        FIRST_PATH_GENERATION,
        0,
    );
    telemetry.frame_sent(41, 1_024, 0);
    telemetry.observe_path(&snapshot(FIRST_PATH_GENERATION), 10);
    telemetry.observe_path(&snapshot(FIRST_PATH_GENERATION + 1), 20);

    assert!(
        telemetry.accept_frame_ack_payload(
            &FrameAck {
                frame_id: 41,
                lost_frames: 0,
            }
            .encode(),
            30,
        )
    );
    assert_eq!(telemetry.pending_frames(), 0);
    assert_eq!(
        telemetry.snapshot().path_generation,
        FIRST_PATH_GENERATION + 1
    );
}

#[test]
fn generation_samples_never_subtract_across_paths() {
    let mut telemetry = PeerTelemetryAdapter::new(
        AdaptiveBitrate::new(10.0, 1.0, 20.0),
        FIRST_PATH_GENERATION,
        0,
    );
    telemetry.observe_path(&snapshot(FIRST_PATH_GENERATION), 10);
    telemetry.observe_path(&snapshot(FIRST_PATH_GENERATION + 1), 20);
    let state = telemetry.snapshot();
    assert_eq!(state.path_generation, FIRST_PATH_GENERATION + 1);
    assert_eq!(state.path_sample_baseline, None);
}

#[test]
fn replay_window_rejects_late_media_and_reliable_retransmit_delivers_once() {
    const KEY: [u8; 32] = [0x53; 32];
    let mut sender = Session::new(KEY, KEY);
    let mut receiver = Session::new(KEY, KEY);
    let old_media = sender
        .seal(Kind::Video, 0, 0, b"old-media")
        .expect("seal old media");
    let reliable = ControlFrame {
        sequence: 0,
        acknowledgement: None,
        ack_only: false,
        payload: b"reliable-control".to_vec(),
    }
    .encode()
    .expect("encode reliable control");
    let _first_control = sender
        .seal(Kind::Control, 0, 0, &reliable)
        .expect("seal first control");
    let mut newest = None;
    for _ in 0..65 {
        newest = Some(
            sender
                .seal(Kind::Control, 31, 0, b"path-control")
                .expect("seal path control"),
        );
    }
    receiver
        .open(&newest.expect("newest path control"))
        .expect("newest packet");
    assert_eq!(
        receiver.open(&old_media),
        Err(openstream_protocol::Error::AuthenticationFailed)
    );

    let retransmitted = sender
        .seal(Kind::Control, 0, 0, &reliable)
        .expect("seal fresh reliable retransmission");
    let packet = receiver.open(&retransmitted).expect("fresh outer counter");
    let mut channel = openstream_protocol::control::Channel::new(4);
    let frame = ControlFrame::decode(&packet.payload).expect("decode reliable control");
    assert_eq!(channel.receive(frame.clone()).delivered.len(), 1);
    assert!(channel.receive(frame).delivered.is_empty());
}
