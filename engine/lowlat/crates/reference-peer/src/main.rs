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

use openstream_client_core::{Pairing, PeerSession, Role, parse_stun_servers};
use openstream_media::{Assembler, Fragment, FrameAck, MAX_FRAGMENT_BYTES, fragment_frame};
use openstream_protocol::Kind;

const DEFAULT_SIGNAL_ORIGIN: &str = "http://127.0.0.1:8080";
const DEFAULT_UDP_BIND: &str = "127.0.0.1:0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let role = match env::args().nth(1).as_deref() {
        Some("host") => Role::Host,
        Some("client") => Role::Client,
        _ => {
            eprintln!("usage: openstream-reference-peer [host|client]");
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
    match role {
        Role::Host => {
            session.negotiate_host().await?;
            let source = vec![0x37; MAX_FRAGMENT_BYTES * 2 + 23];
            for fragment in fragment_frame(1, 0, true, &source)? {
                session.send(Kind::Video, 0, 0, &fragment).await?;
            }
            let frame_ack = session.recv().await?;
            if frame_ack.kind != Kind::Control || FrameAck::decode(&frame_ack.payload).is_err() {
                return Err("unexpected client frame acknowledgement".into());
            }
            session.send(Kind::Control, 0, 0, b"openstream/end").await?;
            println!("host sent an authenticated fragmented video frame and received its ack");
        }
        Role::Client => {
            session.negotiate_client().await?;
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
        }
    }
    Ok(())
}
