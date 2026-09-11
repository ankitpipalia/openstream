//! A tiny end-to-end peer used to prove the independent control and data
//! planes. It is deliberately synthetic: it sends one text-labelled video
//! payload instead of pretending to be a desktop capture implementation.
//!
//! Start the signal server, create one pairing, then run this binary twice:
//!
//! ```text
//! OPENSTREAM_PAIRING_JSON='{"session_id":...}' \
//!   cargo run -p openstream-reference-peer -- host
//! OPENSTREAM_PAIRING_JSON='{"session_id":...}' \
//!   cargo run -p openstream-reference-peer -- client
//! ```

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use openstream_client_core::{
    CandidateKind, Capabilities, ConnectionPath, FlushOutcome, MigrationTarget, Pairing,
    PeerSession, QueueOutcome, Role, parse_stun_servers,
};
use openstream_media::{Assembler, Fragment, FrameAck, MAX_FRAGMENT_BYTES, fragment_frame};
use openstream_protocol::Kind;

const DEFAULT_SIGNAL_ORIGIN: &str = "http://127.0.0.1:8080";
const DEFAULT_UDP_BIND: &str = "127.0.0.1:0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let first = arguments.next();
    let (migration_mode, role_name) = match first.as_deref() {
        Some("--migration") => (true, arguments.next()),
        Some(role) => (false, Some(role.to_string())),
        None => (false, None),
    };
    if arguments.next().is_some() {
        eprintln!("usage: openstream-reference-peer [--migration] [host|client]");
        std::process::exit(2);
    }
    let role = match role_name.as_deref() {
        Some("host") => Role::Host,
        Some("client") => Role::Client,
        _ => {
            eprintln!("usage: openstream-reference-peer [--migration] [host|client]");
            std::process::exit(2);
        }
    };
    let origin =
        env::var("OPENSTREAM_SIGNAL_ORIGIN").unwrap_or_else(|_| DEFAULT_SIGNAL_ORIGIN.to_string());
    let pairing: Pairing = serde_json::from_str(
        &env::var("OPENSTREAM_PAIRING_JSON")
            .map_err(|_| "OPENSTREAM_PAIRING_JSON must contain the create-session response")?,
    )?;

    let bind = env::var("OPENSTREAM_UDP_BIND")
        .unwrap_or_else(|_| DEFAULT_UDP_BIND.to_string())
        .parse::<SocketAddr>()?;
    let stun_servers = match env::var("OPENSTREAM_STUN_SERVERS") {
        Ok(spec) => parse_stun_servers(&spec)?,
        Err(_) => Vec::new(),
    };
    let mut session =
        PeerSession::establish_configured(&origin, &pairing, role, bind, &stun_servers).await?;
    if migration_mode {
        run_migration(&mut session, role).await?;
    } else {
        run_legacy(&mut session, role).await?;
    }
    Ok(())
}

async fn run_legacy(
    session: &mut PeerSession,
    role: Role,
) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        Role::Host => {
            session.negotiate_host().await?;
            send_frame_and_wait_ack(session, 1).await?;
            session.send(Kind::Control, 0, 0, b"openstream/end").await?;
            println!("host sent an authenticated fragmented video frame and received its ack");
        }
        Role::Client => {
            session.negotiate_client().await?;
            receive_legacy_frames(session).await?;
        }
    }
    Ok(())
}

async fn run_migration(
    session: &mut PeerSession,
    role: Role,
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPENSTREAM_ICE_MIGRATION_PROBE").as_deref() == Ok("1") {
        return run_ice_migration_probe(session, role).await;
    }
    match role {
        Role::Host => {
            session
                .negotiate_host_with_capabilities(
                    Capabilities::host_default().with_path_migration(),
                )
                .await?;
            for frame_id in 1..=3 {
                send_frame_and_wait_ack(session, frame_id).await?;
                match frame_id {
                    1 => {
                        wait_for_drain(session).await?;
                        let report = session.migrate_to(MigrationTarget::OpaqueRelay).await?;
                        if report.active_generation != 2
                            || !matches!(
                                session.connection_path(),
                                ConnectionPath::DirectUdp {
                                    candidate: CandidateKind::Relay
                                }
                            )
                        {
                            return Err(
                                "opaque-relay migration committed an unexpected path".into()
                            );
                        }
                        println!("migration committed generation=2 path=opaque_relay");
                    }
                    2 => {
                        wait_for_drain(session).await?;
                        let report = session.migrate_to(MigrationTarget::DirectUdp).await?;
                        if report.active_generation != 3
                            || !matches!(
                                session.connection_path(),
                                ConnectionPath::DirectUdp {
                                    candidate: CandidateKind::Host
                                        | CandidateKind::Mapped
                                        | CandidateKind::ServerReflexive
                                }
                            )
                        {
                            return Err("direct migration committed an unexpected path".into());
                        }
                        println!("migration committed generation=3 path=direct_udp");
                    }
                    3 => {}
                    _ => unreachable!(),
                }
            }
            session.send(Kind::Control, 0, 0, b"openstream/end").await?;
            println!(
                "migration acceptance passed: one cipher session, three committed generations"
            );
        }
        Role::Client => {
            session
                .negotiate_client_with_capabilities(
                    Capabilities::client_default().with_path_migration(),
                )
                .await?;
            receive_migration_frames(session).await?;
        }
    }
    Ok(())
}

async fn run_ice_migration_probe(
    session: &mut PeerSession,
    role: Role,
) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        Role::Host => {
            session
                .negotiate_host_with_capabilities(
                    Capabilities::host_default().with_path_migration(),
                )
                .await?;
            if !matches!(
                session.migrate_to(MigrationTarget::Ice).await,
                Err(openstream_client_core::Error::PathMigration(
                    openstream_client_core::PathMigrationError::UnsupportedIceRestart
                ))
            ) {
                return Err("ICE migration did not return UnsupportedIceRestart".into());
            }
            println!("ice migration capability: UnsupportedIceRestart");
            session.send(Kind::Control, 0, 0, b"openstream/end").await?;
        }
        Role::Client => {
            session
                .negotiate_client_with_capabilities(
                    Capabilities::client_default().with_path_migration(),
                )
                .await?;
            receive_migration_frames(session).await?;
        }
    }
    Ok(())
}

async fn send_frame_and_wait_ack(
    session: &mut PeerSession,
    frame_id: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = vec![0x37 ^ u8::try_from(frame_id).unwrap_or(0); MAX_FRAGMENT_BYTES * 2 + 23];
    for fragment in fragment_frame(frame_id, 0, true, &source)? {
        queue_video_fragment(session, &fragment)?;
    }
    loop {
        let outbound_backpressured = matches!(
            session.flush_outbound_recoverably().await?,
            FlushOutcome::Backpressured
        );
        let outbound_wake = if outbound_backpressured {
            None
        } else {
            session.next_outbound_wake()
        };
        tokio::select! {
            packet = session.recv() => {
                let packet = packet?;
                if packet.kind == Kind::Control
                    && FrameAck::decode(&packet.payload).is_ok_and(|ack| ack.frame_id == frame_id)
                {
                    return Ok(());
                }
            }
            _ = wait_for_outbound_wake(outbound_wake) => {
                session.flush_outbound_recoverably().await?;
            }
        }
    }
}

async fn wait_for_outbound_wake(wake: Option<Duration>) {
    match wake {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}

fn queue_video_fragment(
    session: &mut PeerSession,
    fragment: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        session.queue(Kind::Video, 0, 0, fragment)?,
        QueueOutcome::DroppedOldest
    ) {
        eprintln!("reference peer dropped oldest queued video packet");
    }
    Ok(())
}

async fn wait_for_drain(session: &mut PeerSession) -> Result<(), Box<dyn std::error::Error>> {
    // The controller's minimum old-path drain is 250 ms. Let it expire, then
    // drive the event loop once so the next host migration can reserve the
    // following generation without treating the predecessor as busy.
    tokio::time::sleep(Duration::from_millis(300)).await;
    session.maintain_liveness().await?;
    Ok(())
}

async fn receive_legacy_frames(
    session: &mut PeerSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = Assembler::default();
    loop {
        let packet = session.recv().await?;
        if packet.kind == Kind::Control && packet.payload == b"openstream/end" {
            break;
        }
        if packet.kind != Kind::Video {
            continue;
        }
        let Ok(fragment) = Fragment::decode(&packet.payload) else {
            eprintln!("reference peer dropped malformed video fragment");
            continue;
        };
        let mut ready_frames = Vec::new();
        match assembler.push(fragment) {
            Ok(Some(frame)) => ready_frames.push(frame),
            Ok(None) => {}
            Err(error) => {
                eprintln!("reference peer dropped malformed video frame: {error}");
                continue;
            }
        }
        while let Some(frame) = assembler.pop_ready() {
            ready_frames.push(frame);
        }
        for frame in ready_frames {
            println!(
                "client received authenticated fragmented video payload: {} bytes",
                frame.payload.len()
            );
            let ack = FrameAck {
                frame_id: frame.frame_id,
                lost_frames: assembler.take_frame_gap(),
            }
            .encode();
            session.send(Kind::Control, 0, 0, &ack).await?;
        }
    }
    Ok(())
}

async fn receive_migration_frames(
    session: &mut PeerSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = Assembler::default();
    loop {
        let packet = session.recv().await?;
        if packet.kind == Kind::Control && packet.payload == b"openstream/end" {
            break;
        }
        if packet.kind != Kind::Video {
            continue;
        }
        let fragment = Fragment::decode(&packet.payload)?;
        let mut ready_frames = Vec::new();
        if let Some(frame) = assembler.push(fragment)? {
            ready_frames.push(frame);
        }
        while let Some(frame) = assembler.pop_ready() {
            ready_frames.push(frame);
        }
        for frame in ready_frames {
            let generation = session.path_snapshot().path_generation;
            let path = match session.connection_path() {
                ConnectionPath::DirectUdp { candidate } => match candidate {
                    openstream_client_core::CandidateKind::Relay => "opaque_relay",
                    _ => "direct_udp",
                },
                ConnectionPath::Ice => "ice",
            };
            let ack = FrameAck {
                frame_id: frame.frame_id,
                lost_frames: assembler.take_frame_gap(),
            }
            .encode();
            session.send(Kind::Control, 0, 0, &ack).await?;
            println!("client acknowledged frame at generation={generation}");
            println!("client path snapshot generation={generation} path={path}");
        }
    }
    Ok(())
}
